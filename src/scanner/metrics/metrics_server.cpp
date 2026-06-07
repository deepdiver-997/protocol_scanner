#include "scanner/metrics/metrics_server.h"
#include "scanner/common/logger.h"

#include <boost/asio/ip/tcp.hpp>
#include <sstream>
#include <chrono>
#include <regex>
#include <cstring>

#include <unistd.h>

namespace scanner {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

MetricsServer::MetricsServer() = default;

MetricsServer::~MetricsServer() {
    stop();
}

void MetricsServer::start(uint16_t port) {
    if (running_.exchange(true)) return;

    thread_ = std::make_unique<std::thread>([this, port]() {
        try {
            acceptor_ = std::make_unique<tcp::acceptor>(
                io_ctx_, tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));
            acceptor_->set_option(asio::socket_base::reuse_address(true));
            LOG_CORE_INFO("[metrics] HTTP server listening on 127.0.0.1:{}", port);
            accept_loop();
        } catch (const std::exception& e) {
            LOG_CORE_ERROR("[metrics] Failed to start: {}", e.what());
            running_ = false;
        }
    });
}

void MetricsServer::stop() {
    running_ = false;
    if (acceptor_) {
        acceptor_->close();
    }
    io_ctx_.stop();
    if (thread_ && thread_->joinable()) {
        thread_->join();
    }
    thread_.reset();
    acceptor_.reset();
}

void MetricsServer::update_snapshot(const MetricsSnapshot& s) {
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_ = s;
}

std::string MetricsServer::build_json() {
    MetricsSnapshot s;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        s = snapshot_;
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"queues\":{";
    oss << "\"targets\":" << s.targets_queue_size << ",";
    oss << "\"results\":" << s.result_queue_size << ",";
    oss << "\"pending\":" << s.pending_reports_size;
    oss << "},";
    oss << "\"io_pool\":[";
    for (size_t i = 0; i < s.io_pool_loads.size(); ++i) {
        if (i) oss << ",";
        oss << s.io_pool_loads[i];
    }
    oss << "],";
    oss << "\"sessions\":{";
    oss << "\"active\":" << s.active_sessions << ",";
    oss << "\"total\":" << s.total_sessions;
    oss << "},";
    oss << "\"progress\":{";
    oss << "\"processed\":" << s.processed_count << ",";
    oss << "\"successful\":" << s.successful_count;
    oss << "},";
    oss << "\"rate\":{";
    oss << "\"targets_per_sec\":" << s.targets_per_sec;
    oss << "},";
    oss << "\"uptime_sec\":" << s.uptime_sec << ",";
    oss << "\"protocols\":{";
    bool first = true;
    for (const auto& [name, count] : s.protocol_success_counts) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << name << "\":" << count;
    }
    oss << "}";
    oss << "}\r\n";
    return oss.str();
}

void MetricsServer::accept_loop() {
    while (running_) {
        try {
            tcp::socket socket(io_ctx_);
            acceptor_->accept(socket);

            // 读取请求（简单 recv，最多 4KB）
            char buf[4096];
            ssize_t n = recv(socket.native_handle(), buf, sizeof(buf) - 1, 0);
            if (n <= 0) { socket.close(); continue; }
            buf[n] = '\0';
            std::string request(buf, n);

            // 只处理 GET /metrics
            static const std::regex metrics_re(R"(GET /metrics HTTP/\d\.\d)");
            std::string response;
            if (std::regex_search(request, metrics_re)) {
                std::string body = build_json();
                response = "HTTP/1.0 200 OK\r\n"
                           "Content-Type: application/json\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Connection: close\r\n"
                           "Content-Length: " + std::to_string(body.size()) + "\r\n"
                           "\r\n" + body;
            } else {
                response = "HTTP/1.0 404 Not Found\r\n"
                           "Content-Type: text/plain\r\n"
                           "Connection: close\r\n"
                           "Content-Length: 0\r\n\r\n";
            }

            send(socket.native_handle(), response.data(), response.size(), 0);
            socket.close();
        } catch (const std::exception&) {
            // accept 失败时继续
        }
    }
}

} // namespace scanner
