#include "scanner/core/session.h"
#include "scanner/dns/dns_resolver.h"
#include "scanner/common/logger.h"
#include "scanner/network/latency_manager.h"
#include <atomic>
#include <algorithm>
#include <unordered_map>

namespace scanner {

ScanSession::ScanSession(
    const ScanTarget& target,
    std::shared_ptr<class IDnsResolver> resolver,
    Timeout dns_timeout,
    Timeout probe_timeout,
    ProbeMode mode,
    const std::vector<std::unique_ptr<IProtocol>>& protocols
)
    : target_(target),
      dns_resolver_(std::move(resolver)),
      dns_timeout_(dns_timeout),
      probe_timeout_(probe_timeout) {
    reset(target, mode, protocols);
}

void ScanSession::set_new_target(const ScanTarget& new_target) {
    target_ = new_target;
    // 【优化】移除 idle_ 原子操作
}

void ScanSession::set_new_target(ScanTarget&& new_target) {
    target_ = std::move(new_target);
    // 【优化】移除 idle_ 原子操作
}

void ScanSession::reset(const ScanTarget& new_target, ProbeMode mode, const std::vector<std::unique_ptr<IProtocol>>& protocols) {
    target_ = new_target;
    error_msg_.clear();
    dns_result_ = DnsResult{};
    // 【优化】移除 state_ 原子操作（不再维护状态机）
    tasks_total_.store(0, std::memory_order_relaxed);
    tasks_completed_.store(0, std::memory_order_relaxed);
    // 【优化】移除 idle_ 原子操作
    available_ports_.clear();

    // 解析域名 -> IP
    std::string current_ip = target_.get_ip_string();
    if (!current_ip.empty() || target_.ip_uint != 0) {
        // 已经有IP，直接使用
        dns_result_.domain = target_.domain;
        dns_result_.ip = current_ip;
        dns_result_.success = true;
        LOG_DNS_DEBUG("Using pre-provided IP for {}: {}", target_.domain, current_ip);
    } else if (!target_.domain.empty() && dns_resolver_) {
        // 没有IP，需要DNS解析
        int max_retries = 2; // 默认尝试 2 次
        for (int i = 0; i <= max_retries; ++i) {
            DnsResult dr = dns_resolver_->resolve(target_.domain, dns_timeout_);
            dns_result_ = dr;
            if (dr.success && !dr.ip.empty()) {
                target_.set_ip(dr.ip);
                break;
            } else if (!dr.ip.empty()) {
                target_.set_ip(dr.ip);
                break;
            }
            if (i < max_retries) {
                LOG_DNS_WARN("DNS resolution failed for {}, retrying ({}/{})...", 
                            target_.domain, i + 1, max_retries);
            }
        }
        
        if (target_.get_ip_string().empty()) {
            LOG_CORE_ERROR("DNS resolution failed for {} after {} retries", target_.domain, max_retries + 1);
            // 【优化】移除 set_state 调用
            set_error("DNS Resolution Failed");
        }
    } else {
        // 既没有IP也没有有效的域名
        dns_result_.domain = target_.domain;
        dns_result_.ip = target_.get_ip_string();
        dns_result_.success = false;
    }

    probe_mode_ = mode;

    // 构建 available_ports_（占位：默认使用协议默认端口并集；全扫描未实现时也使用默认端口）
    for (const auto& p : protocols) {
        if (!p) continue;
        for (auto d : p->default_ports()) {
            if (std::find(available_ports_.begin(), available_ports_.end(), d) == available_ports_.end()) {
                available_ports_.push_back(d);
            }
        }
    }

    init_protocol_queues(protocols);

    // 预估任务总数
    std::size_t total_tasks = 0;
    for (const auto& p : protocols) {
        if (!p) continue;
        if (probe_mode_ == ProbeMode::ProtocolDefaults) {
            for (auto d : p->default_ports()) {
                if (should_probe(*p, d)) total_tasks++;
            }
        } else {
            for (auto ap : available_ports_) {
                if (should_probe(*p, ap)) total_tasks++;
            }
        }
    }
    set_expected_tasks(total_tasks);
}

void ScanSession::reset(ScanTarget&& new_target, ProbeMode mode, const std::vector<std::unique_ptr<IProtocol>>& protocols) {
    target_ = std::move(new_target);
    error_msg_.clear();
    dns_result_ = DnsResult{};
    // 【优化】移除 state_ 原子操作
    tasks_total_.store(0, std::memory_order_relaxed);
    tasks_completed_.store(0, std::memory_order_relaxed);
    // 【优化】移除 idle_ 原子操作
    available_ports_.clear();

    // 解析域名 -> IP
    std::string current_ip = target_.get_ip_string();
    if (!current_ip.empty() || target_.ip_uint != 0) {
        // 已经有IP，直接使用
        dns_result_.domain = target_.domain;
        dns_result_.ip = current_ip;
        dns_result_.success = true;
        LOG_DNS_DEBUG("Using pre-provided IP for {}: {}", target_.domain, current_ip);
    } else if (!target_.domain.empty() && dns_resolver_) {
        // 没有IP，需要DNS解析
        int max_retries = 2; // 默认尝试 2 次
        for (int i = 0; i <= max_retries; ++i) {
            DnsResult dr = dns_resolver_->resolve(target_.domain, dns_timeout_);
            dns_result_ = dr;
            if (dr.success && !dr.ip.empty()) {
                target_.set_ip(dr.ip);
                break;
            } else if (!dr.ip.empty()) {
                target_.set_ip(dr.ip);
                break;
            }
            if (i < max_retries) {
                LOG_DNS_WARN("DNS resolution failed for {}, retrying ({}/{})...", 
                            target_.domain, i + 1, max_retries);
            }
        }
        
        if (target_.get_ip_string().empty()) {
            LOG_CORE_ERROR("DNS resolution failed for {} after {} retries", target_.domain, max_retries + 1);
            // 【优化】移除 set_state 调用
            set_error("DNS Resolution Failed");
        }
    } else {
        // 既没有IP也没有有效的域名
        dns_result_.domain = target_.domain;
        dns_result_.ip = target_.get_ip_string();
        dns_result_.success = false;
    }

    probe_mode_ = mode;

    // 构建 available_ports_（占位：默认使用协议默认端口并集；全扫描未实现时也使用默认端口）
    for (const auto& p : protocols) {
        if (!p) continue;
        for (auto d : p->default_ports()) {
            if (std::find(available_ports_.begin(), available_ports_.end(), d) == available_ports_.end()) {
                available_ports_.push_back(d);
            }
        }
    }

    init_protocol_queues(protocols);

    // 预估任务总数
    std::size_t total_tasks = 0;
    for (const auto& p : protocols) {
        if (!p) continue;
        if (probe_mode_ == ProbeMode::ProtocolDefaults) {
            for (auto d : p->default_ports()) {
                if (should_probe(*p, d)) total_tasks++;
            }
        } else {
            for (auto ap : available_ports_) {
                if (should_probe(*p, ap)) total_tasks++;
            }
        }
    }
    set_expected_tasks(total_tasks);
}

bool ScanSession::start_one_probe(
    const std::vector<std::unique_ptr<IProtocol>>& protocols,
    ThreadPool& scan_pool,
    const boost::asio::any_io_executor& exec,
    Timeout timeout
) {
    std::string current_ip = target_.get_ip_string();
    if (current_ip.empty()) {
        return false;
    }

    // 找到第一个有待扫端口的协议
    std::string chosen_proto;
    Port chosen_port = 0;
    for (auto& kv : protocol_port_queues_) {
        if (!kv.second.empty()) {
            chosen_proto = kv.first;
            chosen_port = kv.second.front();
            kv.second.pop();
            break;
        }
    }

    if (chosen_proto.empty()) {
        return false; // 无待任务
    }

    // 定位协议实例
    IProtocol* proto_ptr = nullptr;
    for (const auto& p : protocols) {
        if (p && p->name() == chosen_proto) {
            proto_ptr = p.get();
            break;
        }
    }
    if (!proto_ptr) {
        LOG_CORE_WARN("Protocol instance not found for {}", chosen_proto);
        return false;
    }

    // 计算有效超时：优先考虑动态（当全局为0时），并与协议默认超时取最大值
    Timeout effective_timeout = timeout;
    if (effective_timeout.count() == 0) {
        effective_timeout = LatencyManager::instance().get_timeout(target_.get_ip_string());
    }
    // 按照约定：每个协议的最终超时 = max(协议默认超时, 全局/动态超时)
    Timeout proto_default = proto_ptr->default_timeout();
    if (proto_default > effective_timeout) {
        effective_timeout = proto_default;
    }

    // 提交任务到扫描线程池，实际 IO 在 exec 所属 io_context
    scan_pool.submit([this, proto_ptr, port = chosen_port, exec, timeout = effective_timeout]() {
        // 优先使用域名作为 target，如果没有域名则使用 IP
        const std::string& target = target_.domain.empty() ? target_.get_ip_string() : target_.domain;
        
        proto_ptr->async_probe(
            target,
            target_.get_ip_string(),
            port,
            timeout,
            exec,
            [this, proto_name = proto_ptr->name()](ProtocolResult&& r) {
                if (!r.accessible && !r.error.empty()) {
                     // 临时增加调试日志，采样打印错误
                     static int err_log_count = 0;
                     if (err_log_count++ < 10) {
                         LOG_CORE_WARN("Probe failed for {} {}: {}", target_.get_ip_string(), proto_name, r.error);
                     }
                }
                push_result(std::move(r));
                if (ready_to_release()) {
                    notify_complete();
                }
            }
        );
    });

    return true;
}

int ScanSession::start_all_pending_probes(
    const std::vector<std::unique_ptr<IProtocol>>& protocols,
    ThreadPool& scan_pool,
    const boost::asio::any_io_executor& exec,
    Timeout timeout,
    int quota
) {
    // 【优化】批量启动所有待扫描协议任务
    // 这样可以减少 start_one_probe 的调用频率（从 7 次/session → 1 次）
    // 从而降低 scan_loop 中的遍历和 start_one_probe 的 CPU 热点
    
    const std::string& ip = target_.get_ip_string();
    if (ip.empty() || quota <= 0) {
        return 0;
    }

    // 缓存 target 文本（域名优先，否则 IP）
    const std::string target_name = target_.domain.empty() ? ip : target_.domain;

    // 构建协议映射，避免每次循环线性查找
    std::unordered_map<std::string, IProtocol*> proto_map;
    proto_map.reserve(protocols.size());
    for (const auto& p : protocols) {
        if (p) {
            proto_map.emplace(p->name(), p.get());
        }
    }

    // 计算一次动态超时（如全局为0时），避免重复调用
    Timeout base_timeout = timeout;
    if (base_timeout.count() == 0) {
        base_timeout = LatencyManager::instance().get_timeout(ip);
    }

    int launched = 0;
    while (launched < quota) {
        // 找到第一个有待扫端口的协议
        std::string chosen_proto;
        Port chosen_port = 0;
        for (auto& kv : protocol_port_queues_) {
            if (!kv.second.empty()) {
                chosen_proto = kv.first;
                chosen_port = kv.second.front();
                kv.second.pop();
                break;
            }
        }

        if (chosen_proto.empty()) {
            break; // 无更多待任务
        }

        // 定位协议实例
        IProtocol* proto_ptr = nullptr;
        auto it = proto_map.find(chosen_proto);
        if (it != proto_map.end()) {
            proto_ptr = it->second;
        }
        if (!proto_ptr) {
            LOG_CORE_WARN("Protocol instance not found for {}", chosen_proto);
            break;
        }

        // 计算有效超时
        Timeout effective_timeout = base_timeout;
        Timeout proto_default = proto_ptr->default_timeout();
        if (proto_default > effective_timeout) {
            effective_timeout = proto_default;
        }

        // 提交任务到扫描线程池
        scan_pool.submit([this, proto_ptr, port = chosen_port, exec, timeout = effective_timeout, target_name, ip]() {
            proto_ptr->async_probe(
                target_name,
                ip,
                port,
                timeout,
                exec,
                [this, proto_name = proto_ptr->name()](ProtocolResult&& r) {
                    if (!r.accessible && !r.error.empty()) {
                        static int err_log_count = 0;
                        if (err_log_count++ < 10) {
                            LOG_CORE_WARN("Probe failed for {} {}: {}", target_.get_ip_string(), proto_name, r.error);
                        }
                    }
                    push_result(std::move(r));
                    if (ready_to_release()) {
                        notify_complete();
                    }
                }
            );
        });

        ++launched;
    }

    return launched;
}

// 【优化】移除 set_state 和 is_completed，不再需要状态机
/*
bool ScanSession::set_state(State from, State to) {
    State expected = from;
    return state_.compare_exchange_strong(expected, to);
}

bool ScanSession::is_completed() const {
    auto s = state_.load();
    return s == State::COMPLETED || s == State::TIMEOUT || s == State::FAILED;
}
*/

void ScanSession::notify_complete() {
    if (on_complete_) {
        try {
            on_complete_(this);
        } catch (const std::exception& e) {
            LOG_CORE_ERROR("Error in session callback: {}", e.what());
        }
    }
}

bool ScanSession::should_probe(const IProtocol& proto, Port port) const {
    if (available_ports_.empty()) return false;

    auto in_available = std::find(available_ports_.begin(), available_ports_.end(), port) != available_ports_.end();
    if (!in_available) return false;

    if (probe_mode_ == ProbeMode::ProtocolDefaults) {
        const auto defaults = proto.default_ports();
        return std::find(defaults.begin(), defaults.end(), port) != defaults.end();
    }
    return true; // AllAvailable
}

void ScanSession::init_protocol_queues(const std::vector<std::unique_ptr<IProtocol>>& protocols) {
    protocol_port_queues_.clear();
    protocol_result_queues_.clear();

    // 【优化】懒加载：不预先创建结果队列，改为按需创建
    // 只初始化端口队列
    for (const auto& p : protocols) {
        if (!p) continue;
        const std::string pname = p->name();
        protocol_port_queues_[pname] = std::queue<Port>();
        // protocol_result_queues_ 不再预先创建
    }

    if (available_ports_.empty()) {
        return; // 无可用端口，不入队
    }

    // 依据策略填充每协议的端口队列
    for (const auto& p : protocols) {
        if (!p) continue;
        const std::string pname = p->name();
        auto& q = protocol_port_queues_[pname];

        if (probe_mode_ == ProbeMode::ProtocolDefaults) {
            const auto defaults = p->default_ports();
            for (auto d : defaults) {
                if (std::find(available_ports_.begin(), available_ports_.end(), d) != available_ports_.end()) {
                    q.push(d);
                }
            }
        } else { // AllAvailable
            for (auto ap : available_ports_) {
                q.push(ap);
            }
        }
    }
}

bool ScanSession::has_pending_port(const std::string& protocol_name) const {
    auto it = protocol_port_queues_.find(protocol_name);
    if (it == protocol_port_queues_.end()) return false;
    return !it->second.empty();
}

bool ScanSession::next_port(const std::string& protocol_name, Port& out_port) {
    auto it = protocol_port_queues_.find(protocol_name);
    if (it == protocol_port_queues_.end()) return false;
    auto& q = it->second;
    if (q.empty()) return false;
    out_port = q.front();
    q.pop();
    return true;
}

std::shared_ptr<TaskQueue<ProtocolResult>> ScanSession::result_queue(const std::string& protocol_name) {
    auto it = protocol_result_queues_.find(protocol_name);
    if (it != protocol_result_queues_.end()) return it->second;
    
    // 【优化】懒加载：首次访问时才创建队列
    auto queue = std::make_shared<TaskQueue<ProtocolResult>>();
    protocol_result_queues_[protocol_name] = queue;
    return queue;
}

void ScanSession::push_result(ProtocolResult&& r) {
    mark_task_completed();
    
    // 动态超时统计：如果有响应且成功
    if (r.accessible && r.attrs.response_time_ms > 0) {
        LatencyManager::instance().update(
            target_.get_ip_string(), 
            std::chrono::milliseconds(static_cast<int64_t>(r.attrs.response_time_ms))
        );
    }
    
    // 如果设置了 only_success，过滤失败结果
    if (only_success_ && !r.accessible) {
        return;  // 丢弃失败结果，不推入队列
    }
    
    // 分发到对应协议的结果队列，避免 if-else
    auto rq = result_queue(r.protocol);
    if (rq) {
        rq->push(std::move(r));
    }
}

std::vector<ProtocolResult> ScanSession::protocol_results() {
    std::vector<ProtocolResult> results;
    for (auto& kv : protocol_result_queues_) {
        ProtocolResult r;
        while (kv.second->try_pop(r)) {
            results.push_back(std::move(r));
        }
    }
    return results;
}

} // namespace scanner
