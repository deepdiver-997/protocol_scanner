#include "scanner/protocols/redis_protocol.h"
#include "scanner/common/logger.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <cstring>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

struct RedisProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    BufferPool::BufferHandle buffer;
    size_t bytes_read{0};
    size_t buffer_offset{0};
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    RedisProbeContext(boost::asio::any_io_executor exec, Timeout t,
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
        if (on_complete) {
            on_complete(std::move(result));
        }
    }
};

void RedisProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete,
    const std::string& bind_ip
) {
    auto ctx = std::make_shared<RedisProbeContext>(std::move(exec), timeout, std::move(on_complete));
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

    ctx->timer.expires_after(timeout);
    ctx->timer.async_wait([ctx](const boost::system::error_code& ec) {
        if (!ec) {
            ctx->finish_error("Redis probe timed out");
        }
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) {
        ctx->finish_error("Invalid address: " + ec.message());
        return;
    }

    // 主流程: connect → PING → 读 PONG → INFO server → 读 INFO → 提取版本 → finish
    tcp::endpoint endpoint(address, port);
    ctx->socket.async_connect(endpoint, [ctx](const boost::system::error_code& ec) {
        if (ec) {
            ctx->finish_error("Connection failed: " + ec.message());
            return;
        }

        // Step 1: 发送 PING
        static const std::string ping_cmd = "PING\r\n";
        asio::async_write(ctx->socket, asio::buffer(ping_cmd),
            [ctx](const boost::system::error_code& write_ec, std::size_t) {
                if (write_ec) {
                    ctx->finish_error("PING failed: " + write_ec.message());
                    return;
                }

                // Step 2: 读 PONG 响应
                ctx->socket.async_read_some(
                    asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
                    [ctx](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                        if (ec) {
                            ctx->finish_error("Read PONG failed: " + ec.message());
                            return;
                        }

                        std::string_view resp(ctx->buffer->data(), bytes_transferred);
                        if (resp.find("+PONG") == std::string::npos &&
                            resp.find("+pong") == std::string::npos &&
                            resp.find("+OK") == std::string::npos) {
                            ctx->finish_error("Not Redis: " + std::string(resp.substr(0, 32)));
                            return;
                        }

                        if (bytes_transferred >= ctx->buffer->size()) {
                            ctx->result.attrs.banner_truncated = true;
                        }

                        // Step 3: 发送 INFO server 获取版本
                        static const std::string info_cmd = "INFO server\r\n";
                        asio::async_write(ctx->socket, asio::buffer(info_cmd),
                            [ctx](const boost::system::error_code& write_ec, std::size_t) {
                                if (write_ec) {
                                    // INFO 失败也不影响——至少确认了是 Redis
                                    ctx->result.attrs.banner = "Redis (PONG OK)";
                                    ctx->finish_success();
                                    return;
                                }

                                // Step 4: 读 INFO 响应，提取版本
                                ctx->bytes_read = 0;
                                ctx->buffer_offset = 0;
                                ctx->socket.async_read_some(
                                    asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
                                    [ctx](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                        if (ec) {
                                            ctx->result.attrs.banner = "Redis (PONG OK)";
                                            ctx->finish_success();
                                            return;
                                        }

                                        ctx->bytes_read = bytes_transferred;
                                        std::string info(ctx->buffer->data(), bytes_transferred);
                                        ctx->result.attrs.banner = info;

                                        if (bytes_transferred >= ctx->buffer->size()) {
                                            ctx->result.attrs.banner_truncated = true;
                                        }

                                        // 从 INFO 中提取 redis_version
                                        auto pos = info.find("redis_version:");
                                        if (pos != std::string::npos) {
                                            pos += 14; // 跳过 "redis_version:"
                                            auto end = info.find("\r\n", pos);
                                            if (end == std::string::npos) end = info.find('\n', pos);
                                            if (end != std::string::npos) {
                                                ctx->result.attrs.vendor = "Redis " + info.substr(pos, end - pos);
                                            }
                                        }

                                        ctx->finish_success();
                                    });
                            });
                    });
            });
    });
}

void RedisProtocol::parse_capabilities(
    const std::string& response,
    ProtocolAttributes& attrs
) {
    // 已 inline 在 async_probe 中处理
    (void)response;
    (void)attrs;
}

} // namespace scanner