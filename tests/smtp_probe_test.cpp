// Minimal SMTP async probe test: prints results to terminal
#include "scanner/protocols/smtp_protocol.h"
#include <boost/asio.hpp>
#include <iostream>
#include <chrono>
#include <future>

using namespace scanner;

int main(int argc, char** argv) {
    std::string host = (argc > 1) ? argv[1] : std::string("127.0.0.1");
    Port port = (argc > 2) ? static_cast<Port>(std::stoi(argv[2])) : static_cast<Port>(25);
    Timeout timeout = Timeout(5000);

    std::cout << "SMTP Probe Test" << std::endl;
    std::cout << "Target: " << host << ":" << port << std::endl;

    boost::asio::io_context io;
    SmtpProtocol smtp;

    std::promise<ProtocolResult> promise;
    auto future = promise.get_future();

    smtp.async_probe(
        host,
        port,
        timeout,
        io.get_executor(),
        [&promise](ProtocolResult r) mutable { promise.set_value(std::move(r)); }
    );

    io.run();
    ProtocolResult res = future.get();

    std::cout << "Protocol: " << res.protocol << std::endl;
    std::cout << "Accessible: " << (res.accessible ? "Yes" : "No") << std::endl;
    if (res.accessible) {
        std::cout << "Banner: " << res.attrs.banner << std::endl;
        std::cout << "SMTP Features:" << std::endl;
        std::cout << "  PIPELINING: " << (res.attrs.smtp.pipelining ? "true" : "false") << std::endl;
        std::cout << "  STARTTLS: " << (res.attrs.smtp.starttls ? "true" : "false") << std::endl;
        std::cout << "  8BITMIME: " << (res.attrs.smtp._8bitmime ? "true" : "false") << std::endl;
        std::cout << "  DSN: " << (res.attrs.smtp.dsn ? "true" : "false") << std::endl;
        std::cout << "  SMTPUTF8: " << (res.attrs.smtp.utf8 ? "true" : "false") << std::endl;
        std::cout << "  SIZE: " << (res.attrs.smtp.size_supported ? std::to_string(res.attrs.smtp.size_limit) : std::string("unsupported")) << std::endl;
        std::cout << "  AUTH: " << (res.attrs.smtp.auth_methods.empty() ? std::string("-") : res.attrs.smtp.auth_methods) << std::endl;
    } else {
        std::cout << "Error: " << res.error << std::endl;
    }

    return 0;
}
