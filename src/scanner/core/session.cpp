#include "scanner/core/session.h"
#include "scanner/common/logger.h"
#include <sstream>

namespace scanner {

ScanSession::ScanSession(
    const ScanTarget& target,
    std::shared_ptr<class IDnsResolver> resolver,
    Timeout dns_timeout,
    Timeout probe_timeout,
    ProbeMode mode,
    const std::vector<std::unique_ptr<IProtocol>>& protocols,
    BlockingQueue<ScanReport>& result_queue
)
    : target_(target)
    , dns_resolver_(std::move(resolver))
    , dns_timeout_(dns_timeout)
    , probe_timeout_(probe_timeout)
    , result_queue_(&result_queue)
{
    set_probe_mode(mode);
    results_.reserve(protocols.size());

    // DNS 解析（如果还没有 IP）
    if (target_.ip_uint == 0 && !target_.domain.empty() && dns_resolver_) {
        int max_retries = 2;
        for (int i = 0; i <= max_retries; ++i) {
            DnsResult dr = dns_resolver_->resolve(target_.domain, dns_timeout_);
            dns_result_ = dr;
            if (dr.success && !dr.ip.empty()) {
                target_.set_ip(dr.ip);
                LOG_DNS_DEBUG("DNS resolved {} -> {}", target_.domain, dr.ip);
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
    }

    // 构造 available_ports_（所有协议默认端口的并集）
    for (const auto& p : protocols) {
        if (!p) continue;
        for (auto d : p->default_ports()) {
            if (std::find(available_ports_.begin(), available_ports_.end(), d) == available_ports_.end()) {
                available_ports_.push_back(d);
            }
        }
    }

    // 初始化协议端口队列、计算任务总数
    init_protocol_queues(protocols);

    std::size_t total = 0;
    for (const auto& p : protocols) {
        if (!p) continue;
        if (probe_mode_ == ProbeMode::ProtocolDefaults) {
            for (auto d : p->default_ports()) {
                if (should_probe(*p, d)) total++;
            }
        } else {
            for (auto ap : available_ports_) {
                if (should_probe(*p, ap)) total++;
            }
        }
    }
    tasks_total_.store(total, std::memory_order_relaxed);
}

void ScanSession::init_protocol_queues(const std::vector<std::unique_ptr<IProtocol>>& protocols) {
    protocol_port_queues_.clear();
    for (const auto& p : protocols) {
        if (!p) continue;
        protocol_port_queues_[p->name()] = std::queue<Port>();
    }
    if (available_ports_.empty()) return;

    for (const auto& p : protocols) {
        if (!p) continue;
        auto& q = protocol_port_queues_[p->name()];
        if (probe_mode_ == ProbeMode::ProtocolDefaults) {
            for (auto d : p->default_ports()) {
                if (std::find(available_ports_.begin(), available_ports_.end(), d) != available_ports_.end()) {
                    q.push(d);
                }
            }
        } else {
            for (auto ap : available_ports_) {
                if (std::find(p->default_ports().begin(), p->default_ports().end(), ap) != p->default_ports().end()) {
                    q.push(ap);
                }
            }
        }
    }
}

bool ScanSession::should_probe(const IProtocol& proto, Port port) const {
    if (available_ports_.empty()) return false;
    bool in_available = std::find(available_ports_.begin(), available_ports_.end(), port) != available_ports_.end();
    if (!in_available) return false;
    if (probe_mode_ == ProbeMode::ProtocolDefaults) {
        const auto defaults = proto.default_ports();
        return std::find(defaults.begin(), defaults.end(), port) != defaults.end();
    }
    return true;
}

int ScanSession::start_all_pending_probes(
    const std::vector<std::unique_ptr<IProtocol>>& protocols,
    ThreadPool& scan_pool,
    const boost::asio::any_io_executor& exec,
    Timeout timeout,
    int quota
) {
    if (target_.ip_uint == 0) {
        LOG_CORE_DEBUG("[session] Skipped: empty IP for {}", target_.domain);
        // 没有 IP，标记为 done（失败）
        done_.store(true, std::memory_order_release);
        return 0;
    }

    const std::string& ip = target_.get_ip_string();
    const std::string target_name = target_.domain.empty() ? ip : target_.domain;

    std::unordered_map<std::string, IProtocol*> proto_map;
    for (const auto& p : protocols) {
        if (p) proto_map.emplace(p->name(), p.get());
    }

    Timeout base_timeout = timeout;
    if (base_timeout.count() == 0) {
        base_timeout = std::chrono::milliseconds(5000);
    }

    int launched = 0;
    while (launched < quota) {
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
        if (chosen_proto.empty()) break;

        IProtocol* proto_ptr = nullptr;
        auto it = proto_map.find(chosen_proto);
        if (it != proto_map.end()) proto_ptr = it->second;
        if (!proto_ptr) break;

        Timeout effective_timeout = base_timeout;
        Timeout proto_default = proto_ptr->default_timeout();
        if (proto_default > effective_timeout) effective_timeout = proto_default;

        auto grq = result_queue_;  // capture raw ptr (valid as long as session lives)

        scan_pool.submit([this, proto_ptr, port = chosen_port, exec, timeout = effective_timeout,
                          target_name, ip, proto_name = chosen_proto, grq]() {
            proto_ptr->async_probe(
                target_name, ip, port, timeout, exec,
                [this, proto_name, grq](ProtocolResult&& r) {
                    // 保存结果
                    {
                        std::lock_guard<std::mutex> lock(results_mutex_);
                        results_.push_back(std::move(r));
                    }

                    // 检查是否是最后一个任务
                    auto completed = tasks_completed_.fetch_add(1, std::memory_order_acq_rel) + 1;
                    auto total = tasks_total_.load(std::memory_order_acquire);

                    if (completed >= total) {
                        // 最后完成的任务负责聚合结果并推送到全局队列
                        ScanReport rep;
                        rep.target = target_;
                        rep.total_time = std::chrono::milliseconds(0);
                        {
                            std::lock_guard<std::mutex> lock(results_mutex_);
                            rep.protocols = std::move(results_);
                        }
                        grq->push(std::move(rep));
                        done_.store(true, std::memory_order_release);
                    }
                }
            );
        });

        ++launched;
    }

    // 如果没有启动任何任务，立即标记完成（避免僵尸 session）
    if (launched == 0 && tasks_total_.load() == 0) {
        done_.store(true, std::memory_order_release);
    }

    return launched;
}

} // namespace scanner