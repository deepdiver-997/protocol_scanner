#include "scanner/protocols/sip_protocol.h"
#include "scanner/common/logger.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <cstring>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

struct SipProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    BufferPool::BufferHandle buffer;
    size_t bytes_read{0};
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    SipProbeContext(boost::asio::any_io_executor exec, Timeout t,
                    std::function<void(ProtocolResult&&)> cb)
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
        if (on_complete) on_complete(std::move(result));
    }
};

void SipProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete,
    const std::string& bind_ip
) {
    auto ctx = std::make_shared<SipProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = target;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

    ctx->socket.open(tcp::v4());
    asio::socket_base::reuse_address reuse_opt(true);
    asio::socket_base::receive_buffer_size recv_buf(8 * 1024);
    asio::socket_base::send_buffer_size send_buf(4 * 1024);
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
        if (!ec) ctx->finish_error("SIP probe timed out");
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) { ctx->finish_error("Invalid address"); return; }

    tcp::endpoint endpoint(address, port);
    ctx->socket.async_connect(endpoint, [ctx](const boost::system::error_code& ec) {
        if (ec) { ctx->finish_error("Connect failed: " + ec.message()); return; }

        static const std::string req =
            "OPTIONS sip:localhost SIP/2.0\r\n"
            "Via: SIP/2.0/TCP scanner.local;branch=z9hG4bK-test\r\n"
            "From: <sip:scanner@scanner.local>;tag=probe\r\n"
            "To: <sip:localhost>\r\n"
            "Call-ID: probe@scanner\r\n"
            "CSeq: 1 OPTIONS\r\n"
            "Max-Forwards: 70\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        asio::async_write(ctx->socket, asio::buffer(req),
            [ctx](const boost::system::error_code& wec, std::size_t) {
                if (wec) { ctx->finish_error("Write failed"); return; }

                ctx->socket.async_read_some(
                    asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
                    [ctx](const boost::system::error_code& ec, std::size_t n) {
                        if (ec) { ctx->finish_error("Read failed: " + ec.message()); return; }

                        ctx->bytes_read = n;
                        if (n >= ctx->buffer->size()) ctx->result.attrs.banner_truncated = true;

                        std::string resp(ctx->buffer->data(), n);

                        // Extract status line
                        auto crlf = resp.find("\r\n");
                        if (crlf != std::string::npos) {
                            ctx->result.attrs.banner = resp.substr(0, crlf);
                        }

                        // Parse Server header
                        auto server_pos = resp.find("Server:");
                        if (server_pos == std::string::npos) server_pos = resp.find("server:");
                        if (server_pos != std::string::npos) {
                            server_pos = resp.find(':', server_pos) + 1;
                            while (server_pos < resp.size() && resp[server_pos] == ' ') ++server_pos;
                            auto end = resp.find("\r\n", server_pos);
                            if (end == std::string::npos) end = resp.size();
                            ctx->result.attrs.http.server = resp.substr(server_pos, end - server_pos);
                        }

                        // Parse User-Agent (SIP servers often put version here)
                        if (ctx->result.attrs.http.server.empty()) {
                            auto ua_pos = resp.find("User-Agent:");
                            if (ua_pos == std::string::npos) ua_pos = resp.find("user-agent:");
                            if (ua_pos != std::string::npos) {
                                ua_pos = resp.find(':', ua_pos) + 1;
                                while (ua_pos < resp.size() && resp[ua_pos] == ' ') ++ua_pos;
                                auto end = resp.find("\r\n", ua_pos);
                                if (end == std::string::npos) end = resp.size();
                                ctx->result.attrs.http.server = resp.substr(ua_pos, end - ua_pos);
                            }
                        }

                        ctx->finish_success();
                    });
            });
    });
}

void SipProtocol::parse_capabilities(const std::string&, ProtocolAttributes&) {}

} // namespace scanner