#include "scanner/protocols/http_protocol.h"
#include "scanner/common/logger.h"
#include <boost/asio/write.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <sstream>
#include <algorithm>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

// 辅助函数：不区分大小写的前缀检查
static bool starts_with_ignore_case(const std::string& str, const std::string& prefix) {
    if (str.length() < prefix.length()) return false;
    return std::equal(prefix.begin(), prefix.end(), str.begin(),
                     [](char a, char b) { return std::tolower(a) == std::tolower(b); });
}

struct HttpProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    asio::streambuf buffer;
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    HttpProbeContext(boost::asio::any_io_executor exec, Timeout t, std::function<void(ProtocolResult&&)> cb)
        : socket(std::move(exec)), timer(socket.get_executor()), timeout(t), on_complete(std::move(cb)) {}

    void finish_success() {
        result.accessible = true;
        auto end = std::chrono::steady_clock::now();
        result.attrs.response_time_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start_time).count();
        complete();
    }

    void finish_error(const std::string& msg) {
        result.error = msg;
        complete();
    }

    void complete() {
        if (completed) return;
        completed = true;
        boost::system::error_code ec;
        (void)timer.cancel();
        socket.close(ec);
        if (on_complete) {
            on_complete(std::move(result));
        }
    }
};

void HttpProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete
) {
    auto ctx = std::make_shared<HttpProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = target;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

    ctx->timer.expires_after(timeout);
    ctx->timer.async_wait([ctx](const boost::system::error_code& ec) {
        if (!ec) {
            ctx->finish_error("HTTP probe timed out");
        }
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) {
        ctx->finish_error("Invalid address: " + ec.message());
        return;
    }

    tcp::endpoint endpoint(address, port);
    ctx->socket.async_connect(endpoint, [this, ctx, target](const boost::system::error_code& ec) {
        if (ec) {
            ctx->finish_error("Connection failed: " + ec.message());
            return;
        }

        // 使用完全伪装的 HEAD 请求（模仿 curl -I），使用 target 作为 Host 标识
        auto request = std::make_shared<std::string>(
            "HEAD / HTTP/1.1\r\n"
            "Host: " + target + "\r\n"
            "User-Agent: curl/8.7.1\r\n"
            "Accept: */*\r\n"
            "\r\n"
        );

        asio::async_write(ctx->socket, asio::buffer(*request),
            [this, ctx, request](const boost::system::error_code& ec, std::size_t /*bytes*/) {
                if (ec) {
                    ctx->finish_error("Write request failed: " + ec.message());
                    return;
                }

                // 读取响应头
                asio::async_read_until(ctx->socket, ctx->buffer, "\r\n\r\n",
                    [this, ctx](const boost::system::error_code& ec, std::size_t /*bytes*/) {
                        if (ec && ec != asio::error::eof) {
                            ctx->finish_error("Read response failed: " + ec.message());
                            return;
                        }

                        std::string full_response{
                            asio::buffers_begin(ctx->buffer.data()),
                            asio::buffers_end(ctx->buffer.data())
                        };
                        
                        // 提取状态行
                        auto first_line_end = full_response.find("\r\n");
                        std::string status_line = (first_line_end != std::string::npos) ? 
                                                 full_response.substr(0, first_line_end) : "";
                        
                        parse_capabilities(full_response, ctx->result.attrs);
                        
                        // 更新组合 Banner
                        std::string final_banner = status_line;
                        if (!ctx->result.attrs.http.server.empty()) {
                            final_banner += " [" + ctx->result.attrs.http.server + "]";
                        }
                        ctx->result.attrs.banner = final_banner;
                        
                        // 深度扫描：如果是错误码或者是通用的负载均衡器标识，则在 Body 中精确搜索
                        bool is_generic = (ctx->result.attrs.http.server.find("Lego") != std::string::npos ||
                                          ctx->result.attrs.http.server.find("NWS") != std::string::npos ||
                                          ctx->result.attrs.http.server.empty());

                        if (ctx->result.attrs.http.status_code >= 400 || is_generic) 
                        {
                            std::string lower_resp = full_response;
                            std::transform(lower_resp.begin(), lower_resp.end(), lower_resp.begin(), ::tolower);
                            
                            std::vector<std::string> signatures = {"nginx/", "apache/", "iis/", "litespeed"};
                            for (const auto& sig : signatures) {
                                auto pos = lower_resp.find(sig);
                                if (pos != std::string::npos) {
                                    // 提取版本号（到空格、换行、或 HTML 标签结束）
                                    auto end_pos = full_response.find_first_of(" \r\n<\"", pos);
                                    std::string found = full_response.substr(pos, end_pos - pos);
                                    ctx->result.attrs.banner += " (Detected: " + found + ")";
                                    break;
                                }
                            }
                        }

                        ctx->finish_success();
                    });
            });
    });
}

void HttpProtocol::parse_capabilities(
    const std::string& response,
    ProtocolAttributes& attrs
) {
    std::istringstream oss(response);
    std::string line;
    std::string status_line;

    while (std::getline(oss, line)) {
        if (line.back() == '\r') line.pop_back();
        if (line.empty()) {
            break;
        }

        if (status_line.empty() && starts_with_ignore_case(line, "HTTP/")) {
            status_line = line;
            auto space = line.find(' ');
            if (space != std::string::npos) {
                auto code_str = line.substr(space + 1, 3);
                try {
                    attrs.http.status_code = std::stoi(code_str);
                } catch (...) {}
            }
        } else if (starts_with_ignore_case(line, "Server: ")) {
            attrs.http.server = line.substr(8);
        } else if (starts_with_ignore_case(line, "Content-Type: ")) {
            attrs.http.content_type = line.substr(14);
        }
    }
}

} // namespace scanner
