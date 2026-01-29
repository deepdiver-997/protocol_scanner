#include "scanner/protocols/ftp_protocol.h"
#include "scanner/common/logger.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio/read.hpp>
#include <cstring>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

struct FtpProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    BufferPool::BufferHandle buffer;
    size_t bytes_read{0};
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    FtpProbeContext(boost::asio::any_io_executor exec, Timeout t, std::function<void(ProtocolResult&&)> cb)
        : socket(std::move(exec)), timer(socket.get_executor()), 
          buffer(get_global_buffer_pool().acquire()),
          timeout(t), on_complete(std::move(cb)) {}

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

void FtpProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete
) {
    auto ctx = std::make_shared<FtpProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = target;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

    // 允许端口重用，降低 TIME_WAIT/连接重用等待
    ctx->socket.open(tcp::v4());
    asio::socket_base::reuse_address reuse_opt(true);
    asio::socket_base::receive_buffer_size recv_buf(8 * 1024);   // 8 KB (sufficient for FTP banner)
    asio::socket_base::send_buffer_size send_buf(4 * 1024);      // 4 KB
    asio::ip::tcp::no_delay no_delay_opt(true);
    boost::system::error_code set_ec;
    ctx->socket.set_option(reuse_opt, set_ec);
    ctx->socket.set_option(recv_buf, set_ec);
    ctx->socket.set_option(send_buf, set_ec);
    ctx->socket.set_option(no_delay_opt, set_ec);

    ctx->timer.expires_after(timeout);
    ctx->timer.async_wait([ctx](const boost::system::error_code& ec) {
        if (!ec) {
            ctx->finish_error("FTP probe timed out");
        }
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) {
        ctx->finish_error("Invalid address: " + ec.message());
        return;
    }

    tcp::endpoint endpoint(address, port);
    ctx->socket.async_connect(endpoint, [this, ctx](const boost::system::error_code& ec) {
        if (ec) {
            ctx->finish_error("Connection failed: " + ec.message());
            return;
        }

        // FTP 服务通常会先返回 220 欢迎语，读取首行作为 banner。
        ctx->socket.async_read_some(
            asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
            [this, ctx](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                if (ec && ec != asio::error::eof) {
                    ctx->finish_error("Read banner failed: " + ec.message());
                    return;
                }

                ctx->bytes_read = bytes_transferred;
                auto* data = ctx->buffer->data();
                
                // 查找 \r\n 分隔符（兼容方式）
                std::string_view sv(data, bytes_transferred);
                auto pos = sv.find("\r\n");
                
                std::string line;
                if (pos != std::string_view::npos) {
                    line.assign(data, pos);
                } else {
                    // 查找单个 \n
                    auto* lf = static_cast<const char*>(std::memchr(data, '\n', bytes_transferred));
                    if (lf) {
                        line.assign(data, lf - data);
                        if (!line.empty() && line.back() == '\r') line.pop_back();
                    } else {
                        line.assign(data, bytes_transferred);
                    }
                }
                
                ctx->result.attrs.banner = line;
                parse_capabilities(line, ctx->result.attrs);
                ctx->finish_success();
            });
    });
}

void FtpProtocol::parse_capabilities(
    const std::string& response,
    ProtocolAttributes& attrs
) {
    // 目前仅提取 Banner，未来可扩展 FEAT/SYST 解析
    if (attrs.banner.empty()) {
        attrs.banner = response;
    }
}

} // namespace scanner
