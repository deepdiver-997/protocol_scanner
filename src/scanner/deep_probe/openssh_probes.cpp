#include "scanner/deep_probe/deep_probe.h"
#include "scanner/common/logger.h"

#include <boost/asio.hpp>
#include <libssh2.h>
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>

namespace scanner::deep_probe {
namespace asio = boost::asio;

// =====================
// Helper: TCP connect + libssh2 session
// =====================

struct SshSession {
    asio::io_context& io;
    asio::ip::tcp::socket socket;
    LIBSSH2_SESSION* session = nullptr;
    bool connected = false;

    SshSession(asio::io_context& io_ctx) : io(io_ctx), socket(io_ctx) {}
    ~SshSession() { cleanup(); }

    bool connect(const std::string& ip, uint16_t port, int timeout_sec = 10) {
        try {
            auto addr = asio::ip::make_address(ip);
            socket.open(asio::ip::tcp::v4());
            socket.connect(asio::ip::tcp::endpoint(addr, port));

            session = libssh2_session_init();
            if (!session) return false;
            libssh2_session_set_blocking(session, 1);

            int sock = socket.native_handle();
            if (libssh2_session_handshake(session, sock) != 0) {
                cleanup();
                return false;
            }
            connected = true;
            return true;
        } catch (...) {
            cleanup();
            return false;
        }
    }

    void cleanup() {
        if (session) {
            libssh2_session_free(session);
            session = nullptr;
        }
        if (socket.is_open()) {
            boost::system::error_code ec;
            socket.close(ec);
        }
        connected = false;
    }
};

// =====================
// 1. MaxAuthTries
// =====================

std::string probe_openssh_max_auth_tries(const std::string& ip, uint16_t port, int max_probe) {
    LOG_CORE_INFO("[deep_probe] OpenSSH MaxAuthTries: connecting to {}:{}", ip, port);

    asio::io_context io_ctx;
    SshSession s(io_ctx);
    if (!s.connect(ip, port)) {
        return "error=connection_failed";
    }

    int tries = 0;
    for (int i = 1; i <= max_probe; ++i) {
        int rc = libssh2_userauth_password(s.session, "probe", "wrong_password_placeholder");
        if (rc == 0) {
            // Shouldn't happen — wrong password shouldn't authenticate
            return "error=unexpected_auth_success";
        }
        if (rc == LIBSSH2_ERROR_AUTHENTICATION_FAILED) {
            tries = i;
            continue;  // Normal auth failure, attempt counted
        }
        if (rc == LIBSSH2_ERROR_SOCKET_DISCONNECT || rc == LIBSSH2_ERROR_SOCKET_SEND) {
            // Server disconnected us — MaxAuthTries exceeded
            LOG_CORE_INFO("[deep_probe] OpenSSH MaxAuthTries: disconnected after {} attempts", i);
            return "max_auth_tries=" + std::to_string(i);
        }
        // Other error
        return "max_auth_tries=" + std::to_string(tries) + " (error=" + std::to_string(rc) + ")";
    }

    // Never exceeded within probe limit
    return "max_auth_tries=>" + std::to_string(max_probe);
}

// =====================
// 2. MaxStartups
// =====================

std::string probe_openssh_max_startups(const std::string& ip, uint16_t port, int max_conn) {
    LOG_CORE_INFO("[deep_probe] OpenSSH MaxStartups: connecting {} times to {}:{}", max_conn, ip, port);

    asio::io_context io_ctx;
    std::vector<std::unique_ptr<SshSession>> sessions;
    int accepted = 0;
    int refused = 0;

    for (int i = 0; i < max_conn; ++i) {
        auto s = std::make_unique<SshSession>(io_ctx);
        if (s->connect(ip, port, 5)) {
            accepted++;
            sessions.push_back(std::move(s));
        } else {
            refused++;
        }

        // Detect threshold: once refusals start, that's the begin limit
        if (refused > 0 && accepted >= refused) {
            // We're past the begin threshold, now try to find the full limit
        }
    }

    // Cleanup
    sessions.clear();

    LOG_CORE_INFO("[deep_probe] OpenSSH MaxStartups: accepted={}, refused={}", accepted, refused);

    std::string result = "max_startups_accepted=" + std::to_string(accepted)
                       + " max_startups_refused=" + std::to_string(refused);
    return result;
}

// =====================
// 3. LoginGraceTime
// =====================

std::string probe_openssh_login_grace_time(const std::string& ip, uint16_t port, int max_wait_sec) {
    LOG_CORE_INFO("[deep_probe] OpenSSH LoginGraceTime: connecting to {}:{}", ip, port);

    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    bool disconnected = false;

    try {
        auto addr = asio::ip::make_address(ip);
        socket.open(asio::ip::tcp::v4());
        socket.connect(asio::ip::tcp::endpoint(addr, port));

        // Read the SSH version banner (confirms connection is alive)
        char buf[256] = {};
        boost::system::error_code ec;
        size_t n = socket.read_some(asio::buffer(buf), ec);
        if (ec || n == 0) return "error=no_banner";

        // Now wait. Server will close the connection after LoginGraceTime
        auto start = std::chrono::steady_clock::now();
        while (true) {
            auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed >= std::chrono::seconds(max_wait_sec)) {
                // Server didn't disconnect within probe limit
                return "login_grace_time=>" + std::to_string(max_wait_sec) + "s";
            }

            // Try to read — if error, server disconnected us
            char tmp[1] = {};
            size_t r = socket.read_some(asio::buffer(tmp), ec);
            if (ec) {
                auto sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
                return "login_grace_time=" + std::to_string(sec) + "s";
            }
            (void)r;

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    } catch (const std::exception& e) {
        return "error=" + std::string(e.what());
    }
}

} // namespace scanner::deep_probe