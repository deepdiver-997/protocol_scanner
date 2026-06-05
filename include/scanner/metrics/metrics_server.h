#pragma once

#include <string>
#include <functional>
#include <cstdint>
#include <atomic>
#include <thread>

#include <boost/asio/ip/tcp.hpp>

namespace scanner {

// 指标快照，由 scanner 定期更新，metrics 线程读取
struct MetricsSnapshot {
    // 队列
    size_t targets_queue_size    = 0;
    size_t result_queue_size     = 0;
    size_t pending_reports_size  = 0;

    // 会话
    size_t active_sessions  = 0;
    size_t total_sessions   = 0;

    // 进度
    uint64_t processed_count  = 0;
    uint64_t successful_count = 0;

    // 速率 (由服务器端计算 delta)
    double   targets_per_sec   = 0.0;

    // 运行时间
    uint64_t uptime_sec = 0;

    // 协议
    std::vector<std::pair<std::string, uint64_t>> protocol_success_counts;
};

// 极简 HTTP 服务，只响应 GET /metrics → JSON
class MetricsServer {
public:
    MetricsServer();
    ~MetricsServer();

    // 启动（在独立线程中运行）
    void start(uint16_t port = 9080);
    void stop();

    // 更新快照（由 scanner 主线程定期调用）
    void update_snapshot(const MetricsSnapshot& s);

private:
    void accept_loop();
    std::string build_json();

    boost::asio::io_context io_ctx_;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
    std::unique_ptr<std::thread> thread_;

    MetricsSnapshot snapshot_;
    mutable std::mutex mutex_;
    std::atomic<bool> running_{false};
};

} // namespace scanner
