#include "scanner/protocols/telnet_protocol.h"
#include "scanner/common/logger.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio/read.hpp>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

struct TelnetProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    BufferPool::BufferHandle buffer;
    size_t bytes_read{0};
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    TelnetProbeContext(boost::asio::any_io_executor exec, Timeout t, std::function<void(ProtocolResult&&)> cb)
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

void TelnetProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete,
    const std::string& bind_ip
) {
    auto ctx = std::make_shared<TelnetProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = target;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

    ctx->socket.open(tcp::v4());
    asio::socket_base::reuse_address reuse_opt(true);
    asio::socket_base::receive_buffer_size recv_buf(8 * 1024);   // 8 KB (sufficient for Telnet banner)
    asio::socket_base::send_buffer_size send_buf(4 * 1024);      // 4 KB
    asio::ip::tcp::no_delay no_delay_opt(true);
    boost::system::error_code set_ec;
    ctx->socket.set_option(reuse_opt, set_ec);
    ctx->socket.set_option(recv_buf, set_ec);
    ctx->socket.set_option(send_buf, set_ec);
    ctx->socket.set_option(no_delay_opt, set_ec);

    // 绑定到指定本地 IP（多 IP 场景下分散临时端口池）
    if (!bind_ip.empty()) {
        boost::system::error_code bind_ec;
        ctx->socket.bind(tcp::endpoint(asio::ip::make_address(bind_ip, bind_ec), 0), bind_ec);
        if (bind_ec) {
            ctx->finish_error("Bind failed: " + bind_ec.message());
            return;
        }
    }

    ctx->timer.expires_after(timeout);
    ctx->timer.async_wait([ctx](const boost::system::error_code& ec) {
        if (!ec) {
            ctx->finish_error("Telnet probe timed out");
        }
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) {
        ctx->finish_error("Invalid address: " + ec.message());
        return;
    }

    tcp::endpoint endpoint(address, port);
    ctx->socket.async_connect(endpoint, [ctx](const boost::system::error_code& ec) {
        if (ec) {
            ctx->finish_error("Connection failed: " + ec.message());
            return;
        }

        // Telnet 连上后通常会有欢迎信息，或者什么都不发。
        // 我们尝试读取一点数据作为 banner。
        ctx->socket.async_read_some(
            asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
            [ctx](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                if (ec) {
                    // 即使没有读取到数据，只要连上了也算成功
                    ctx->finish_success();
                    return;
                }
                ctx->bytes_read = bytes_transferred;
                // 检查缓冲区是否被填满（可能被截断）
                if (bytes_transferred >= ctx->buffer->size()) {
                    ctx->result.attrs.banner_truncated = true;
                }
                // 只取前256字节作为banner（足够识别）
                size_t banner_len = std::min(bytes_transferred, size_t(256));
                std::string banner(ctx->buffer->data(), banner_len);
                ctx->result.attrs.banner = banner;
                ctx->finish_success();
            });
    });
}

void TelnetProtocol::parse_capabilities(const std::string&, ProtocolAttributes&) {}

} // namespace scanner
