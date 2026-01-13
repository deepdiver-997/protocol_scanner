#include "scanner/protocols/smtp_protocol.h"
#include "scanner/common/logger.h"
#include <boost/asio/write.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <sstream>
#include <chrono>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using steady_timer = asio::steady_timer;

// =====================
// SMTP 异步协议实现
// =====================

// namespace {
struct ProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    asio::streambuf buffer;
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    bool completed{false};

    ProbeContext(boost::asio::any_io_executor exec, Timeout t, std::function<void(ProtocolResult&&)> cb)
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
// } // namespace

void SmtpProtocol::async_probe(
    const std::string& target,
    const std::string& ip,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete
) {
    auto ctx = std::make_shared<ProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = target;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

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
        asio::async_read_until(
            ctx->socket,
            ctx->buffer,
            "\r\n",
            [this, ctx, read_ehlo](const boost::system::error_code& ec, std::size_t /*bytes*/) {
                if (ec) {
                    ctx->finish_error("Read EHLO failed: " + ec.message());
                    return;
                }

                std::istream response_stream(&ctx->buffer);
                std::string line;
                if (!std::getline(response_stream, line)) {
                    ctx->finish_error("EHLO parsing error");
                    return;
                }

                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                parse_ehlo_line(line, ctx->result.attrs);

                if (line.find("250 ") == 0) {
                    ctx->finish_success();
                    return;
                }

                (*read_ehlo)();
            });
    };

    *read_banner = [ctx, read_ehlo]() {
        asio::async_read_until(
            ctx->socket,
            ctx->buffer,
            "\r\n",
            [ctx, read_ehlo](const boost::system::error_code& ec, std::size_t /*bytes*/) {
                if (ec) {
                    ctx->finish_error("Read banner failed: " + ec.message());
                    return;
                }

                std::istream response_stream(&ctx->buffer);
                std::string welcome;
                std::getline(response_stream, welcome);

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
    std::istringstream iss(response);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("220") == 0) {
            attrs.banner = line;
            continue;
        }
        if (line.find("250-") == 0 || line.find("250 ") == 0) {
            parse_ehlo_line(line, attrs);
        }
    }
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
