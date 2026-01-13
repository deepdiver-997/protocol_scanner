#include "scanner/protocols/ftp_protocol.h"
#include "scanner/common/logger.h"
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

struct FtpProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    asio::streambuf buffer;
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    FtpProbeContext(boost::asio::any_io_executor exec, Timeout t, std::function<void(ProtocolResult&&)> cb)
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
        asio::async_read_until(ctx->socket, ctx->buffer, "\r\n",
            [this, ctx](const boost::system::error_code& ec, std::size_t /*bytes*/) {
                if (ec && ec != asio::error::eof) {
                    ctx->finish_error("Read banner failed: " + ec.message());
                    return;
                }

                std::istream is(&ctx->buffer);
                std::string line;
                if (std::getline(is, line)) {
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    ctx->result.attrs.banner = line;
                    parse_capabilities(line, ctx->result.attrs);
                }

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
