#pragma once

#include "scanner/protocols/protocol_base.h"
#include "scanner/dns/dns_resolver.h"
#include "scanner/common/thread_pool.h"
#include "scanner/core/task_queue.h"
#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <queue>
#include <functional>
#include <string>

namespace scanner {

namespace asio = boost::asio;

// =====================
// 扫描会话（Session）
// =====================
// 封装单次完整的域名探测生命周期：
// domain -> DNS -> 各协议探测 -> 完成
// 使用状态机与 asio 定时器管理整个周期的超时

class ScanSession {
public:
    // 探测端口选择策略
    enum class ProbeMode {
        AllAvailable,       // 对每个协议尝试所有可用端口
        ProtocolDefaults    // 仅尝试协议默认端口与可用端口的交集
    };
    enum class State {
        PENDING,        // 待 DNS 解析
        DNS_RUNNING,    // DNS 中
        PROBE_RUNNING,  // 协议探测中
        COMPLETED,      // 全部完成
        TIMEOUT,        // 超时
        FAILED          // 失败
    };


    // 构造：ScanTarget、dns 解析器、超时时间、探测模式、协议集、完成回调
    using Callback = std::function<void(ScanSession*)>;
    ScanSession(
        const ScanTarget& target,
        std::shared_ptr<class IDnsResolver> resolver,
        Timeout dns_timeout,
        Timeout probe_timeout,
        ProbeMode mode,
        const std::vector<std::unique_ptr<IProtocol>>& protocols
    );

    ~ScanSession() = default;
    // ====== 端口管理 ======
    const std::vector<Port>& available_ports() const { return available_ports_; }
    void set_available_ports(std::vector<Port> ports) { available_ports_ = std::move(ports); }
    void add_available_port(Port p) { available_ports_.push_back(p); }

    void set_probe_mode(ProbeMode mode) { probe_mode_ = mode; }
    ProbeMode probe_mode() const { return probe_mode_; }

    // 根据策略判断是否需要对某协议在某端口进行探测
    bool should_probe(const IProtocol& proto, Port port) const;

    // 记录协议使用的 available_ports 下标
    void record_protocol_port_index(const std::string& protocol_name, uint16_t index);
    // const std::unordered_map<std::string, std::vector<uint16_t>>& protocol_port_indices() const {
    //     return protocol_port_indices_;
    // }

    // ====== 任务计数 ======
    void set_expected_tasks(std::size_t n) { tasks_total_.store(n, std::memory_order_relaxed); }
    void mark_task_completed() { tasks_completed_.fetch_add(1, std::memory_order_relaxed); }
    std::size_t tasks_total() const { return tasks_total_.load(std::memory_order_relaxed); }
    std::size_t tasks_completed() const { return tasks_completed_.load(std::memory_order_relaxed); }
    bool ready_to_release() const { 
        // 如果没有 IP 且域名非空，说明域名解析失败，应该允许释放
        if (target_.ip.empty() && !target_.domain.empty()) return true;
        // 如果总任务数为 0，说明没有任何要扫的，也该释放
        if (tasks_total() == 0) return true;
        return tasks_completed() >= tasks_total(); 
    }

    // ====== 访问器 ======
    const std::string& domain() const { return target_.domain; }
    State state() const { return state_.load(); }
    
    const DnsResult& dns_result() const { return dns_result_; }
    DnsResult& dns_result() { return dns_result_; }

    // void set_callback(Callback cb) { on_complete_ = std::move(cb); }

    std::string error_msg() const { return error_msg_; }
    void set_error(const std::string& msg) { error_msg_ = msg; }

    // 启动一次探测任务；返回是否成功启动
    bool start_one_probe(
        const std::vector<std::unique_ptr<IProtocol>>& protocols,
        ThreadPool& scan_pool,
        const boost::asio::any_io_executor& exec,
        Timeout timeout
    );

    // ====== 状态转换 ======
    bool set_state(State from, State to);
    bool is_completed() const;

    // ====== 完成通知 ======
    void notify_complete();

    // ====== 协议端口队列与结果队列 ======
    // 初始化每个协议的待扫描端口队列（依据 probe_mode 与 available_ports）
    void init_protocol_queues(const std::vector<std::unique_ptr<IProtocol>>& protocols);
    bool has_pending_port(const std::string& protocol_name) const;
    bool next_port(const std::string& protocol_name, Port& out_port);

    // 每协议的结果队列（线程安全），用于异步回传结果与后续统一处理
    std::shared_ptr<TaskQueue<ProtocolResult>> result_queue(const std::string& protocol_name);
    void push_result(ProtocolResult&& r);

    // 获取所有协议结果
    std::vector<ProtocolResult> protocol_results();

    // 设置是否仅收集成功结果
    void set_only_success(bool only_success) { only_success_ = only_success; }

private:
    ScanTarget target_;
    std::shared_ptr<class IDnsResolver> dns_resolver_;
    Timeout dns_timeout_;
    Timeout probe_timeout_;
    DnsResult dns_result_;
    std::string error_msg_;
    std::atomic<State> state_{State::PENDING};
    Callback on_complete_;

    // 端口策略与映射
    std::vector<Port> available_ports_;
    ProbeMode probe_mode_{ProbeMode::AllAvailable};
    // std::unordered_map<std::string, std::vector<uint16_t>> protocol_port_indices_;

    // 每协议待扫描端口队列（顺序扫描，不并行同协议多端口）
    std::unordered_map<std::string, std::queue<Port>> protocol_port_queues_;
    // 每协议探测结果队列（线程安全，用于避免 if-else 分发）
    std::unordered_map<std::string, std::shared_ptr<TaskQueue<ProtocolResult>>> protocol_result_queues_;

    // 任务计数
    std::atomic<std::size_t> tasks_total_{0};
    std::atomic<std::size_t> tasks_completed_{0};

    // 过滤策略
    bool only_success_{false};
};

} // namespace scanner
