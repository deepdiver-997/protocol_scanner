#include "scanner/protocols/http_protocol.h"
#include "scanner/protocols/ssh_protocol.h"
#include "scanner/protocols/ftp_protocol.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio.hpp>
#include <iostream>
#include <chrono>

using namespace scanner;
namespace asio = boost::asio;

void test_protocol(IProtocol& proto, const std::string& name,
                   const std::string& ip, uint16_t port) {
    std::cout << "\n=== Testing " << name << " @ " << ip << ":" << port << " ===" << std::endl;

    asio::io_context io;
    bool done = false;
    ProtocolResult result;

    proto.async_probe(
        ip, ip, port, Timeout(5000),
        io.get_executor(),
        [&](ProtocolResult&& r) {
            result = std::move(r);
            done = true;
        }
    );

    // Run with deadline
    auto start = std::chrono::steady_clock::now();
    while (!done) {
        io.run_one();
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(6)) {
            std::cout << "  TIMEOUT (no callback after 6s)" << std::endl;
            break;
        }
    }

    std::cout << "  Accessible: " << (result.accessible ? "YES" : "NO") << std::endl;
    if (!result.error.empty()) {
        std::cout << "  Error: " << result.error << std::endl;
    }
    if (!result.attrs.banner.empty()) {
        std::string banner_preview = result.attrs.banner.substr(0, 120);
        std::cout << "  Banner: " << banner_preview << std::endl;
    }
    if (result.attrs.banner_truncated) {
        std::cout << "  [TRUNCATED]" << std::endl;
    }

    // SSH specific
    if (!result.attrs.ssh.version_string.empty()) {
        std::cout << "  SSH Software: " << result.attrs.ssh.software << std::endl;
        std::cout << "  SSH Version: " << result.attrs.ssh.version << std::endl;
        std::cout << "  SSH Protocol: " << result.attrs.ssh.protocol_version << std::endl;
    }

    // HTTP specific
    if (!result.attrs.http.server.empty()) {
        std::cout << "  HTTP Server: " << result.attrs.http.server << std::endl;
    }
    if (result.attrs.http.status_code != 0) {
        std::cout << "  HTTP Status: " << result.attrs.http.status_code << std::endl;
    }

    // FTP specific
    if (!result.attrs.ftp.features.empty()) {
        std::cout << "  FTP Features: " << result.attrs.ftp.features << std::endl;
    }
    std::cout << "  Response time: " << result.attrs.response_time_ms << "ms" << std::endl;
    std::cout << "  ========================" << std::endl;
}

int main() {
    std::cout << "Protocol Scanner - Unit Test" << std::endl;
    std::cout << "Testing probes directly (bypassing scan pipeline)" << std::endl;
    std::cout << "================================================" << std::endl;

    // 先从最简单的开始：HTTP（example.com 应该总在线）
    HttpProtocol http;
    test_protocol(http, "HTTP", "93.184.216.34", 80);  // example.com IP

    // SSH（你的服务器）
    SshProtocol ssh;
    test_protocol(ssh, "SSH", "120.24.169.213", 22);

    // FTP
    FtpProtocol ftp;
    test_protocol(ftp, "FTP", "209.51.188.148", 21);   // ftp.gnu.org IP

    return 0;
}
