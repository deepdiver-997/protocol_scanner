#include "scanner/protocols/imap_protocol.h"
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
// IMAP 异步协议实现
// =====================

struct ProbeContext {
    ProtocolResult result;
    tcp::socket socket;
    steady_timer timer;
    asio::streambuf buffer;
    Timeout timeout;
    std::function<void(ProtocolResult&&)> on_complete;
    std::chrono::steady_clock::time_point start_time;
    std::string tag;
    bool completed{false};

    ProbeContext(boost::asio::any_io_executor exec, Timeout t, std::function<void(ProtocolResult&&)> cb)
        : socket(std::move(exec)), timer(socket.get_executor()), timeout(t), on_complete(std::move(cb)),
          tag("A001") {}

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

void ImapProtocol::async_probe(
    const std::string& host,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete
) {
    auto ctx = std::make_shared<ProbeContext>(std::move(exec), timeout, std::move(on_complete));
    ctx->result.protocol = name();
    ctx->result.host = host;
    ctx->result.port = port;
    ctx->start_time = std::chrono::steady_clock::now();

    // 超时处理
    ctx->timer.expires_after(timeout);
    ctx->timer.async_wait([ctx](const boost::system::error_code& ec) {
        if (!ec) {
            ctx->finish_error("IMAP probe timed out");
        }
    });

    boost::system::error_code ec;
    auto address = asio::ip::make_address(host, ec);
    if (ec) {
        ctx->finish_error("Invalid address: " + ec.message());
        return;
    }

    tcp::endpoint endpoint(address, port);
    auto read_capability = std::make_shared<std::function<void()>>();
    auto read_greeting = std::make_shared<std::function<void()>>();

    *read_capability = [ctx, read_capability]() {
        asio::async_read_until(
            ctx->socket,
            ctx->buffer,
            "\r\n",
            [ctx, read_capability](const boost::system::error_code& ec, std::size_t /*bytes*/) {
                if (ec) {
                    ctx->finish_error("Read capability failed: " + ec.message());
                    return;
                }

                std::istream response_stream(&ctx->buffer);
                std::string line;
                if (!std::getline(response_stream, line)) {
                    ctx->finish_error("Capability parsing error");
                    return;
                }

                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                // Parse capabilities
                if (line.find(ctx->tag) != std::string::npos) {
                    if (line.find("OK") != std::string::npos) {
                        ctx->finish_success();
                        return;
                    } else {
                        ctx->finish_error("CAPABILITY failed: " + line);
                        return;
                    }
                }

                (*read_capability)();
            });
    };

    *read_greeting = [ctx, read_capability]() {
        asio::async_read_until(
            ctx->socket,
            ctx->buffer,
            "\r\n",
            [ctx, read_capability](const boost::system::error_code& ec, std::size_t /*bytes*/) {
                if (ec) {
                    ctx->finish_error("Read greeting failed: " + ec.message());
                    return;
                }

                std::istream response_stream(&ctx->buffer);
                std::string line;
                if (!std::getline(response_stream, line)) {
                    ctx->finish_error("Greeting parsing error");
                    return;
                }

                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                if (line.find("* OK") == 0 || line.find("* PREAUTH") == 0) {
                    ctx->result.attrs.banner = line;
                    // Send CAPABILITY command
                    std::string cmd = ctx->tag + " CAPABILITY\r\n";
                    asio::async_write(
                        ctx->socket,
                        asio::buffer(cmd),
                        [ctx, read_capability](const boost::system::error_code& write_ec, std::size_t /*bytes*/) {
                            if (write_ec) {
                                ctx->finish_error("Write CAPABILITY failed: " + write_ec.message());
                                return;
                            }
                            (*read_capability)();
                        });
                } else {
                    ctx->finish_error("Invalid IMAP greeting: " + line);
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

void ImapProtocol::parse_capabilities(
    const std::string& response,
    ProtocolAttributes& attrs
) {
    std::istringstream iss(response);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("* OK") == 0 || line.find("* PREAUTH") == 0) {
            attrs.banner = line;
            continue;
        }
        if (line.find("* CAPABILITY") == 0) {
            // Parse capabilities
            if (line.find("IMAP4rev1") != std::string::npos) {
                attrs.imap.imap4rev1 = true;
            }
            if (line.find("STARTTLS") != std::string::npos) {
                attrs.imap.starttls = true;
            }
            if (line.find("AUTH=PLAIN") != std::string::npos) {
                attrs.imap.auth_plain = true;
            }
            if (line.find("AUTH=LOGIN") != std::string::npos) {
                attrs.imap.auth_login = true;
            }
            if (line.find("IDLE") != std::string::npos) {
                attrs.imap.idle = true;
            }
            if (line.find("UNSELECT") != std::string::npos) {
                attrs.imap.unselect = true;
            }
            if (line.find("UIDPLUS") != std::string::npos) {
                attrs.imap.uidplus = true;
            }
        }
    }
}

} // namespace scanner
