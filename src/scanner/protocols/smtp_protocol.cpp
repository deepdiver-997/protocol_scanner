#include "scanner/protocols/smtp_protocol.h"
#include "scanner/protocols/protocol_parsers.h"
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
// SMTP 异步协议实现
// =====================

namespace {
struct SmtpProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    BufferPool::BufferHandle buffer;
    size_t bytes_read{0};
    size_t buffer_offset{0};  // 当前已处理的偏移
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    SmtpProbeContext(boost::asio::any_io_executor exec, Timeout t, std::function<void(ProtocolResult&&)> cb)
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

void SmtpProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete,
    const std::string& bind_ip
) {
    auto ctx = std::make_shared<SmtpProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = target;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

    ctx->socket.open(tcp::v4());
    asio::socket_base::reuse_address reuse_opt(true);
    asio::socket_base::receive_buffer_size recv_buf(8 * 1024);   // 8 KB (sufficient for SMTP banner)
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

    // 超时处理
    ctx->timer.expires_after(timeout);
    ctx->timer.async_wait([ctx](const boost::system::error_code& ec) {
        if (!ec) {
            ctx->finish_error("SMTP probe timed out");
        }
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(ip, ec);
    if (ec) {
        ctx->finish_error("Invalid address: " + ec.message());
        return;
    }

    tcp::endpoint endpoint(address, port);
    auto read_ehlo = std::make_shared<std::function<void()>>();
    auto read_banner = std::make_shared<std::function<void()>>();

    *read_ehlo = [this, ctx, read_ehlo]() {
        // 如果缓冲区已满，完成
        if (ctx->buffer_offset >= ctx->bytes_read) {
            // 需要继续读取
            if (ctx->bytes_read >= ctx->buffer->size()) {
                ctx->finish_success();  // 缓冲区已满，结束
                return;
            }
            // 继续读取更多数据
            ctx->socket.async_read_some(
                asio::buffer(ctx->buffer->data() + ctx->bytes_read, 
                           ctx->buffer->size() - ctx->bytes_read),
                [ctx, read_ehlo](const boost::system::error_code& ec, std::size_t bytes) {
                    if (ec) {
                        if (ec == asio::error::eof) {
                            ctx->finish_success();
                        } else {
                            ctx->finish_error("Read EHLO failed: " + ec.message());
                        }
                        return;
                    }
                    ctx->bytes_read += bytes;
                    (*read_ehlo)();
                });
            return;
        }

        // 从buffer_offset开始查找一行
        auto* data = ctx->buffer->data() + ctx->buffer_offset;
        size_t remaining = ctx->bytes_read - ctx->buffer_offset;
        std::string_view sv(data, remaining);
        auto pos = sv.find("\r\n");
        
        if (pos == std::string_view::npos) {
            // 未找到完整行，继续读取
            if (ctx->bytes_read >= ctx->buffer->size()) {
                ctx->finish_success();  // 缓冲区已满
            } else {
                (*read_ehlo)();  // 递归继续
            }
            return;
        }

        std::string line(data, pos);
        ctx->buffer_offset += pos + 2;  // 跳过 \r\n
        parse_ehlo_line(line, ctx->result.attrs);

        if (line.find("250 ") == 0) {
            ctx->finish_success();
            return;
        }

        (*read_ehlo)();
    };

    *read_banner = [ctx, read_ehlo]() {
        ctx->socket.async_read_some(
            asio::buffer(ctx->buffer->data(), ctx->buffer->size()),
            [ctx, read_ehlo](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                if (ec) {
                    ctx->finish_error("Read banner failed: " + ec.message());
                    return;
                }

                ctx->bytes_read = bytes_transferred;
                auto* data = ctx->buffer->data();
                std::string_view sv(data, bytes_transferred);
                auto pos = sv.find("\r\n");
                
                std::string welcome;
                if (pos != std::string_view::npos) {
                    welcome.assign(data, pos);
                    ctx->buffer_offset = pos + 2;  // 记录已处理位置
                } else {
                    welcome.assign(data, bytes_transferred);
                    ctx->buffer_offset = bytes_transferred;
                }

                if (welcome.find("220") != 0) {
                    ctx->finish_error("Invalid welcome: " + welcome);
                    return;
                }

                ctx->result.attrs.banner = welcome;
                static const std::string ehlo_cmd = "EHLO scanner\r\n";
                asio::async_write(
                    ctx->socket,
                    asio::buffer(ehlo_cmd),
                    [ctx, read_ehlo](const boost::system::error_code& write_ec, std::size_t /*bytes*/) {
                        if (write_ec) {
                            ctx->finish_error("Write EHLO failed: " + write_ec.message());
                            return;
                        }
                        // 重置偏移，准备读取EHLO响应
                        ctx->buffer_offset = 0;
                        ctx->bytes_read = 0;
                        (*read_ehlo)();
                    });
            });
    };

    ctx->socket.async_connect(endpoint, [ctx, read_banner](const boost::system::error_code& connect_ec) {
        if (connect_ec) {
            ctx->finish_error("Connect failed: " + connect_ec.message());
            return;
        }
        ctx->start_time = std::chrono::steady_clock::now();
        (*read_banner)();
    });
}

void SmtpProtocol::parse_capabilities(
    const std::string& response,
    ProtocolAttributes& attrs
) {
    // Extract banner (first 220 line)
    auto crlf = response.find("\r\n");
    if (crlf != std::string::npos) {
        attrs.banner = response.substr(0, crlf);
    }
    // Use standalone parser
    auto info = parse_smtp_banner(response);
    attrs.smtp.pipelining = info.pipelining;
    attrs.smtp.starttls = info.starttls;
    attrs.smtp.size_supported = info.size_supported;
    attrs.smtp.size_limit = info.size_limit;
    attrs.smtp.utf8 = info.utf8;
    attrs.smtp._8bitmime = info._8bitmime;
    attrs.smtp.dsn = info.dsn;
    attrs.smtp.auth_methods = info.auth_methods;
}

void SmtpProtocol::parse_ehlo_line(
    const std::string& line,
    ProtocolAttributes& attrs
) {
    std::string capability;

    if (line.find("250-") == 0) {
        capability = line.substr(4);
    } else if (line.find("250 ") == 0) {
        capability = line.substr(4);
    } else {
        return;
    }

    if (capability == "PIPELINING") {
        attrs.smtp.pipelining = true;
    } else if (capability == "STARTTLS") {
        attrs.smtp.starttls = true;
    } else if (capability == "8BITMIME") {
        attrs.smtp._8bitmime = true;
    } else if (capability == "DSN") {
        attrs.smtp.dsn = true;
    } else if (capability == "SMTPUTF8") {
        attrs.smtp.utf8 = true;
    } else if (capability.find("SIZE") == 0) {
        parse_size(capability, attrs);
    } else if (capability.find("AUTH") == 0) {
        parse_auth(capability, attrs);
    }
}

void SmtpProtocol::parse_size(
    const std::string& value,
    ProtocolAttributes& attrs
) {
    if (value.find(" ") != std::string::npos) {
        std::string size_str = value.substr(value.find(" ") + 1);
        try {
            attrs.smtp.size_limit = stoull(size_str);
            attrs.smtp.size_supported = true;
        } catch (...) {
            LOG_SMTP_WARN("Failed to parse SIZE: {}", size_str);
        }
    }
}

void SmtpProtocol::parse_auth(
    const std::string& value,
    ProtocolAttributes& attrs
) {
    if (value.find(" ") != std::string::npos) {
        attrs.smtp.auth_methods = value.substr(value.find(" ") + 1);
    }
}

} // namespace scanner
