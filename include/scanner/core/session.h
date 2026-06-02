#pragma once

#include "scanner/protocols/protocol_base.h"
#include "scanner/dns/dns_resolver.h"
#include "scanner/common/thread_pool.h"
#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <queue>
#include <mutex>
#include <string>

namespace scanner {

namespace asio = boost::asio;



class ScanSession {
public:
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
    bool is_done() const { return done_.load(std::memory_order_acquire); }
    std::size_t tasks_total() const { return tasks_total_.load(std::memory_order_relaxed); }

    // ====== 端口与协议 ======
    const std::vector<Port>& available_ports() const { return available_ports_; }
    void set_probe_mode(ProbeMode mode) { probe_mode_ = mode; }

    // ====== 启动探测 ======
    int start_all_pending_probes(
        const std::vector<std::unique_ptr<IProtocol>>& protocols,
        ThreadPool& scan_pool,
        const boost::asio::any_io_executor& exec,
        Timeout timeout,
        int quota = INT_MAX
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

    std::vector<Port> available_ports_;
    ProbeMode probe_mode_{ProbeMode::AllAvailable};
    std::unordered_map<std::string, std::queue<Port>> protocol_port_queues_;

    std::vector<ProtocolResult> results_;
    std::mutex results_mutex_;

    std::atomic<std::size_t> tasks_total_{0};
    std::atomic<std::size_t> tasks_completed_{0};
    std::atomic<bool> done_{false};

    bool only_success_{false};
};

} // namespace scanner