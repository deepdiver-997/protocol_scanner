#include "scanner/protocols/pop3_protocol.h"
#include "scanner/common/logger.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <sstream>
#include <chrono>
#include <cstring>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

// =====================
// POP3 异步协议实现
// =====================

namespace {
struct Pop3ProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    BufferPool::BufferHandle buffer;
    size_t bytes_read{0};
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    Pop3ProbeContext(boost::asio::any_io_executor exec, Timeout t, std::function<void(ProtocolResult&&)> cb)
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
} // namespace

void Pop3Protocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete
) {
    auto ctx = std::make_shared<Pop3ProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = target;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

     ctx->socket.open(tcp::v4());
     asio::socket_base::reuse_address reuse_opt(true);
     asio::socket_base::receive_buffer_size recv_buf(8 * 1024);   // 8 KB (sufficient for POP3 banner)
     asio::socket_base::send_buffer_size send_buf(4 * 1024);      // 4 KB
     asio::ip::tcp::no_delay no_delay_opt(true);
     boost::system::error_code set_ec;
     ctx->socket.set_option(reuse_opt, set_ec);
     ctx->socket.set_option(recv_buf, set_ec);
     ctx->socket.set_option(send_buf, set_ec);
     ctx->socket.set_option(no_delay_opt, set_ec);

    // 超时处理
    ctx->timer.expires_after(timeout);
    ctx->timer.async_wait([ctx](const boost::system::error_code& ec) {
        if (!ec) {
            ctx->finish_error("POP3 probe timed out");
        }
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) {
        ctx->finish_error("Invalid address: " + ec.message());
        return;
    }

    tcp::endpoint endpoint(address, port);
    auto read_greeting = std::make_shared<std::function<void()>>();

    *read_greeting = [ctx]() {
        ctx->socket.async_read_some(
            asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
            [ctx](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                if (ec) {
                    ctx->finish_error("Read greeting failed: " + ec.message());
                    return;
                }

                ctx->bytes_read = bytes_transferred;
                auto* data = ctx->buffer->data();
                
                // 查找 \r\n
                std::string_view sv(data, bytes_transferred);
                auto pos = sv.find("\r\n");
                
                std::string line;
                if (pos != std::string_view::npos) {
                    line.assign(data, pos);
                } else {
                    // 查找单个 \n
                    auto lf_pos = sv.find('\n');
                    if (lf_pos != std::string_view::npos) {
                        line.assign(data, lf_pos);
                        if (!line.empty() && line.back() == '\r') line.pop_back();
                    } else {
                        line.assign(data, bytes_transferred);
                    }
                }

                if (line.find("OK") != std::string::npos || line.find("+OK") == 0) {
                    ctx->result.attrs.banner = line;
                    ctx->finish_success();
                } else {
                    ctx->finish_error("Invalid POP3 greeting: " + line);
                }
            });
    };

    ctx->socket.async_connect(endpoint, [ctx, read_greeting](const boost::system::error_code& connect_ec) {
        if (connect_ec) {
            ctx->finish_error("Connect failed: " + connect_ec.message());
            return;
        }
        ctx->start_time = std::chrono::steady_clock::now();
        (*read_greeting)();
    });
}

void Pop3Protocol::parse_capabilities(
    const std::string& response,
    ProtocolAttributes& attrs
) {
    std::istringstream iss(response);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("+OK") == 0) {
            attrs.banner = line;
            continue;
        }
        // Parse POP3 capabilities if needed
        if (line.find("USER") != std::string::npos) {
            attrs.pop3.user = true;
        }
        if (line.find("TOP") != std::string::npos) {
            attrs.pop3.top = true;
        }
        if (line.find("PIPELINING") != std::string::npos) {
            attrs.pop3.pipelining = true;
        }
        if (line.find("UIDL") != std::string::npos) {
            attrs.pop3.uidl = true;
        }
        if (line.find("STLS") != std::string::npos) {
            attrs.pop3.stls = true;
        }
    }
}

} // namespace scanner
