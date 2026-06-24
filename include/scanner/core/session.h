#pragma once

#include "scanner/protocols/protocol_base.h"
#include "scanner/dns/dns_resolver.h"
#include "scanner/common/thread_pool.h"
#include "scanner/common/io_thread_pool.h"
#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <queue>
#include <mutex>
#include <string>
#include <functional>

namespace scanner {

namespace asio = boost::asio;

class ScanSession {
public:
    // session 完成当前 target 所有 probe 后回调，自行取新 target + 重启
    using RestartFunc = std::function<void(ScanSession*)>;

    enum class ProbeMode {
        AllAvailable,
        ProtocolDefaults
    };

    ScanSession(
        const ScanTarget& target,
        std::shared_ptr<class IDnsResolver> resolver,
        Timeout dns_timeout,
        Timeout probe_timeout,
        ProbeMode mode,
        const std::vector<std::unique_ptr<IProtocol>>& protocols,
        BlockingQueue<ScanReport>& result_queue
    );

    ~ScanSession() = default;

    // ====== 访问器 ======
    const ScanTarget& target() const { return target_; }
    bool idle() const { return tasks_total_.load(std::memory_order_relaxed) == 0; }
    bool ready_to_release() const {
        if (target_.ip_uint == 0 && !target_.domain.empty()) return true;
        return tasks_completed() >= initial_total;
    }
    // int io_context_idx() const { return io_context_idx_; }
    void set_io_context_idx(int idx) { io_context_idx_ = idx; }
    std::size_t tasks_total() const { return tasks_total_.load(std::memory_order_relaxed); }
    std::size_t tasks_completed() const { return tasks_completed_.load(std::memory_order_relaxed); }

    // ====== 复用 ======
    void reset(const ScanTarget& new_target, ProbeMode mode,
               const std::vector<std::unique_ptr<IProtocol>>& protocols);
    void reset(ScanTarget&& new_target, ProbeMode mode,
               const std::vector<std::unique_ptr<IProtocol>>& protocols);

    // ====== 端口 ======
    const std::vector<Port>& available_ports() const { return available_ports_; }
    void set_expected_tasks(std::size_t n) { tasks_total_.store(n, std::memory_order_relaxed); }
    void set_probe_mode(ProbeMode mode) { probe_mode_ = mode; }
    void set_error(const std::string& msg) { error_msg_ = msg; }
    std::string error_msg() const { return error_msg_; }

    // ====== 回调驱动重启 ======
    void set_on_restart(RestartFunc cb) { on_restart_ = std::move(cb); }

    // ====== 启动探测 ======
    int start_all_pending_probes(
        const std::vector<std::unique_ptr<IProtocol>>& protocols,
        IoThreadPool* io_pool_,
        Timeout timeout,
        int quota = INT_MAX,
        const std::string& bind_ip = ""
    );

private:
    void init_protocol_queues(const std::vector<std::unique_ptr<IProtocol>>& protocols);
    bool should_probe(const IProtocol& proto, Port port) const;

    ScanTarget target_;
    std::shared_ptr<class IDnsResolver> dns_resolver_;
    Timeout dns_timeout_;
    Timeout probe_timeout_;
    DnsResult dns_result_;
    BlockingQueue<ScanReport>* result_queue_;
    std::string error_msg_;

    std::vector<Port> available_ports_;
    ProbeMode probe_mode_{ProbeMode::AllAvailable};
    std::unordered_map<std::string, std::queue<Port>> protocol_port_queues_;

    std::vector<ProtocolResult> results_;
    std::mutex results_mutex_;

    std::atomic<std::size_t> tasks_total_{0};
    std::size_t initial_total;
    std::atomic<std::size_t> tasks_completed_{0};
    std::atomic<uint64_t> generation_{0};
    int io_context_idx_{-1};

    RestartFunc on_restart_;

    bool only_success_{false};
};

} // namespace scanner