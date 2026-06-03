#include "scanner/deep_probe/deep_probe.h"
#include "scanner/common/logger.h"

#include <boost/asio.hpp>
#include <thread>
#include <chrono>
#include <vector>
#include <memory>
#include <atomic>
#include <cstring>

namespace scanner::deep_probe {
namespace asio = boost::asio;

// =====================
// vsftpd: max_clients
// =====================
// vsftpd 的 max_clients 限制并发连接数。
// 超过后新连接被直接拒绝（无 220 欢迎语，或连接 RST）。
// 探测：同时建大量连接，统计被接受的峰值。

std::string probe_vsftpd_max_clients(const std::string& ip, uint16_t port, int max_conn) {
    LOG_CORE_INFO("[deep_probe] vsftpd max_clients: connecting {} times to {}:{}", max_conn, ip, port);

    asio::io_context io_ctx;
    std::vector<std::unique_ptr<asio::ip::tcp::socket>> sockets;
    int accepted = 0;
    int refused = 0;

    for (int i = 0; i < max_conn; ++i) {
        auto sock = std::make_unique<asio::ip::tcp::socket>(io_ctx);
        boost::system::error_code ec;
        sock->open(asio::ip::tcp::v4());
        sock->connect(asio::ip::tcp::endpoint(
            asio::ip::make_address(ip), port), ec);

        if (!ec) {
            // Read banner to confirm connection is valid
            char buf[128] = {};
            size_t n = sock->read_some(asio::buffer(buf), ec);
            if (!ec && n > 0 && std::strstr(buf, "220") != nullptr) {
                accepted++;
                sockets.push_back(std::move(sock));
            } else {
                refused++;
                boost::system::error_code close_ec;
                sock->close(close_ec);
            }
        } else {
            refused++;
        }
    }

    // Cleanup
    for (auto& s : sockets) {
        boost::system::error_code ec;
        s->close(ec);
    }
    sockets.clear();

    LOG_CORE_INFO("[deep_probe] vsftpd max_clients: accepted={}, refused={}", accepted, refused);
    return "max_clients_accepted=" + std::to_string(accepted)
         + " max_clients_refused=" + std::to_string(refused);
}

// =====================
// telnetd: login delay
// =====================
// telnetd 自身无速率限制，但 /bin/login 或 PAM 可能引入延迟。
// 探测：连 → 等 login: → 输错误密码 → 测量到错误响应的间隔。

std::string probe_telnetd_login_delay(const std::string& ip, uint16_t port, int max_wait_ms) {
    LOG_CORE_INFO("[deep_probe] telnetd login_delay: connecting to {}:{}", ip, port);

    try {
        asio::io_context io_ctx;
        asio::ip::tcp::socket socket(io_ctx);
        socket.open(asio::ip::tcp::v4());
        socket.connect(asio::ip::tcp::endpoint(
            asio::ip::make_address(ip), port));

        // Wait for login prompt
        char buf[1024] = {};
        auto start = std::chrono::steady_clock::now();
        bool got_prompt = false;

        while (true) {
            auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed > std::chrono::milliseconds(max_wait_ms)) {
                return "error=no_login_prompt";
            }

            boost::system::error_code ec;
            size_t n = socket.read_some(asio::buffer(buf), ec);
            if (ec) return "error=disconnected_before_prompt";

            std::string_view data(buf, n);
            if (data.find("login:") != std::string::npos ||
                data.find("Login:") != std::string::npos ||
                data.find("User:") != std::string::npos) {
                got_prompt = true;
                break;
            }

            // Also check for IAC negotiation bytes and skip them
        }

        if (!got_prompt) return "error=no_login_prompt";

        // Send wrong username
        std::string wrong_user = "wronguser\r\n";
        boost::system::error_code ec;
        asio::write(socket, asio::buffer(wrong_user), ec);
        if (ec) return "error=write_failed";

        // Wait for password prompt
        auto prompt_start = std::chrono::steady_clock::now();
        while (true) {
            auto elapsed = std::chrono::steady_clock::now() - prompt_start;
            if (elapsed > std::chrono::milliseconds(max_wait_ms)) {
                return "error=no_password_prompt";
            }

            size_t n = socket.read_some(asio::buffer(buf), ec);
            if (ec) return "error=disconnected_before_password";

            std::string_view data(buf, n);
            if (data.find("password:") != std::string::npos ||
                data.find("Password:") != std::string::npos) {
                break;
            }
        }

        // Send wrong password and measure response time
        std::string wrong_pass = "wrongpass\r\n";
        asio::write(socket, asio::buffer(wrong_pass), ec);

        auto auth_start = std::chrono::steady_clock::now();
        while (true) {
            auto elapsed = std::chrono::steady_clock::now() - auth_start;
            if (elapsed > std::chrono::milliseconds(max_wait_ms)) {
                return "error=no_auth_response";
            }

            size_t n = socket.read_some(asio::buffer(buf), ec);
            if (ec) break;

            std::string_view data(buf, n);
            if (data.find("incorrect") != std::string::npos ||
                data.find("Invalid") != std::string::npos ||
                data.find("failed") != std::string::npos ||
                data.find("Login") != std::string::npos) {
                auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - auth_start).count();
                return "login_delay_ms=" + std::to_string(delay);
            }
        }

        auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - auth_start).count();
        return "login_delay_ms=" + std::to_string(delay);

    } catch (const std::exception& e) {
        return "error=" + std::string(e.what());
    }
}

} // namespace scanner::deep_probe