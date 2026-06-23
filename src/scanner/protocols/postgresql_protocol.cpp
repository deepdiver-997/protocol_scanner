#include "scanner/protocols/postgresql_protocol.h"
#include "scanner/common/logger.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <cstring>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

struct PgsqlProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    BufferPool::BufferHandle buffer;
    size_t bytes_read{0};
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    PgsqlProbeContext(boost::asio::any_io_executor exec, Timeout t,
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

// 构造 PostgreSQL StartupMessage（不含 TLS 请求）
// 格式: Int32 length | Int32 proto_ver (196608=3.0) | "user\0postgres\0\0"
static std::string build_startup_message() {
    const char* user   = "user";
    const char* value  = "scanner";
    uint32_t proto_ver = 196608;  // 3.0
    // length = 4 (self) + 4 (proto_ver) + strlen(user)+1 + strlen(value)+1 + 1 (terminator)
    uint32_t len = 4 + 4 + 5 + 8 + 1;  // "user\0" + "scanner\0" + "\0"

    std::string msg;
    msg.reserve(len);
    msg.append(reinterpret_cast<const char*>(&len), 4);
    msg.append(reinterpret_cast<const char*>(&proto_ver), 4);
    msg.append(user, 5);   // "user\0"
    msg.append(value, 8);  // "scanner\0"
    msg.push_back('\0');
    return msg;
}

void PgsqlProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete,
    const std::string& bind_ip
) {
    auto ctx = std::make_shared<PgsqlProbeContext>(std::move(exec), timeout, std::move(on_complete));
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
        if (!ec) ctx->finish_error("PGSQL probe timed out");
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) { ctx->finish_error("Invalid address"); return; }

    tcp::endpoint endpoint(address, port);
    ctx->socket.async_connect(endpoint, [ctx](const boost::system::error_code& ec) {
        if (ec) { ctx->finish_error("Connect failed: " + ec.message()); return; }

        // 发送 StartupMessage
        static const std::string startup = build_startup_message();
        asio::async_write(ctx->socket, asio::buffer(startup),
            [ctx](const boost::system::error_code& ec, std::size_t) {
                if (ec) { ctx->finish_error("Startup write failed: " + ec.message()); return; }

                // 读服务端响应
                ctx->socket.async_read_some(
                    asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
                    [ctx](const boost::system::error_code& ec, std::size_t n) {
                        if (ec) { ctx->finish_error("Read failed: " + ec.message()); return; }

                        ctx->bytes_read = n;
                        if (n < 5) { ctx->finish_error("Response too short"); return; }

                        char msg_type = ctx->buffer->data()[0];
                        uint32_t msg_len = 0;
                        std::memcpy(&msg_len, ctx->buffer->data() + 1, 4);
                        msg_len = ntohl(msg_len);

                        // PostgreSQL 后端消息类型
                        switch (msg_type) {
                        case 'R': { // AuthenticationX
                            uint32_t auth_type = 0;
                            if (msg_len >= 8) {
                                std::memcpy(&auth_type, ctx->buffer->data() + 5, 4);
                                auth_type = ntohl(auth_type);
                            }
                            ctx->result.attrs.pgsql.protocol_version = 196608;
                            if (auth_type == 0) {
                                ctx->result.attrs.banner = "AuthenticationOk";
                            } else {
                                ctx->result.attrs.banner = "Authentication" + std::to_string(auth_type);
                            }
                            ctx->finish_success();
                            return;
                        }
                        case 'E': { // ErrorResponse
                            // 错误消息可能包含版本线索，尝试提取
                            std::string err(ctx->buffer->data() + 5, std::min<size_t>(n - 5, 256));
                            ctx->result.attrs.banner = err;
                            ctx->result.attrs.pgsql.protocol_version = 196608;
                            ctx->finish_success();
                            return;
                        }
                        case 'S': // ParameterStatus
                        case 'K': // BackendKeyData
                        case 'Z': // ReadyForQuery
                        case 'N': // NoticeResponse
                            ctx->result.attrs.pgsql.protocol_version = 196608;
                            ctx->finish_success();
                            return;
                        default:
                            ctx->finish_error("Not PostgreSQL (msg_type="
                                + std::to_string(static_cast<int>(msg_type)) + ")");
                            return;
                        }
                    });
            });
    });
}

void PgsqlProtocol::parse_capabilities(const std::string&, ProtocolAttributes&) {
    // 解析在 async_probe 回调整合中完成
}

} // namespace scanner
