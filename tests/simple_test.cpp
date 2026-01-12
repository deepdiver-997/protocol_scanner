#include "scanner/protocols/protocol_base.h"
#include "scanner/protocols/smtp_protocol.h"
#include "scanner/common/logger.h"
#include <boost/asio.hpp>
#include <iostream>
#include <chrono>
#include <future>

using namespace scanner;

int main() {
    Logger::instance().set_level(LogLevel::INFO);
    Logger::instance().set_console_enabled(true);

    std::cout << "Protocol Scanner - Basic Test" << std::endl;
    std::cout << "===============================" << std::endl;

    // Test SMTP protocol
    SmtpProtocol smtp;
    std::cout << "\nTesting SMTP protocol..." << std::endl;
    std::cout << "Protocol: " << smtp.name() << std::endl;

    auto ports = smtp.default_ports();
    std::cout << "Default ports: ";
    for (auto port : ports) {
        std::cout << port << " ";
    }
    std::cout << std::endl;

    // Test protocol factory
    std::cout << "\nTesting ProtocolFactory..." << std::endl;
    auto protocols = ProtocolFactory::available_protocols();
    std::cout << "Available protocols: ";
    for (const auto& proto : protocols) {
        std::cout << proto << " ";
    }
    std::cout << std::endl;

    // Test SMTP probe on localhost (if available)
    std::cout << "\nTesting SMTP probe on 127.0.0.1:25..." << std::endl;
    boost::asio::io_context io;
    std::promise<ProtocolResult> promise;
    auto future = promise.get_future();
    smtp.async_probe(
        "127.0.0.1",
        25,
        std::chrono::milliseconds(5000),
        io.get_executor(),
        [&promise](ProtocolResult r) mutable { promise.set_value(std::move(r)); }
    );
    io.run();
    auto result = future.get();
    std::cout << "Accessible: " << (result.accessible ? "Yes" : "No") << std::endl;
    if (result.accessible) {
        std::cout << "Banner: " << result.attrs.banner << std::endl;
        std::cout << "Vendor: " << result.attrs.vendor << std::endl;
    } else {
        std::cout << "Error: " << result.error << std::endl;
    }

    std::cout << "\nTest completed!" << std::endl;
    return 0;
}
