#include "scanner/core/session.h"
#include "scanner/common/logger.h"

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
    reset(target, mode, protocols);
}

void ScanSession::reset(const ScanTarget& new_target, ProbeMode mode,
                         const std::vector<std::unique_ptr<IProtocol>>& protocols) {
    target_ = new_target;
    generation_.fetch_add(1, std::memory_order_release);
    tasks_total_.store(0, std::memory_order_relaxed);
    tasks_completed_.store(0, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        results_.clear();
    }
    available_ports_.clear();

    // DNS 解析
    if (target_.ip_uint != 0) {
        dns_result_.domain = target_.domain;
        dns_result_.ip = target_.get_ip_string();
        dns_result_.success = true;
    } else if (!target_.domain.empty() && dns_resolver_) {
        for (int i = 0; i <= 2; ++i) {
            DnsResult dr = dns_resolver_->resolve(target_.domain, dns_timeout_);
            dns_result_ = dr;
            if (dr.success && !dr.ip.empty()) {
                target_.set_ip(dr.ip);
                break;
            } else if (!dr.ip.empty()) {
                target_.set_ip(dr.ip);
                break;
            }
        }
        if (target_.get_ip_string().empty()) {
            set_error("DNS Resolution Failed");
        }
    }

    probe_mode_ = mode;

    for (const auto& p : protocols) {
        if (!p) continue;
        for (auto d : p->default_ports()) {
            if (std::find(available_ports_.begin(), available_ports_.end(), d) == available_ports_.end()) {
                available_ports_.push_back(d);
            }
        }
    }

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
    initial_total = total;
}

void ScanSession::reset(ScanTarget&& new_target, ProbeMode mode,
                         const std::vector<std::unique_ptr<IProtocol>>& protocols) {
    ScanTarget copy = std::move(new_target);
    reset(copy, mode, protocols);
}

void ScanSession::init_protocol_queues(const std::vector<std::unique_ptr<IProtocol>>& protocols) {
    protocol_port_queues_.clear();
    for (const auto& p : protocols) {
        if (!p) continue;
        protocol_port_queues_[std::string(p->name())] = std::queue<Port>();
    }
    if (available_ports_.empty()) return;
    for (const auto& p : protocols) {
        if (!p) continue;
        auto& q = protocol_port_queues_[std::string(p->name())];
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
    IoThreadPool* io_pool_,
    Timeout timeout,
    int quota,
    const std::string& bind_ip
) {
    if (target_.ip_uint == 0) return 0;

    const std::string& ip = target_.get_ip_string();
    const std::string target_name = target_.domain.empty() ? ip : target_.domain;

    std::unordered_map<std::string, IProtocol*> proto_map;
    for (const auto& p : protocols) {
        if (p) proto_map.emplace(p->name(), p.get());
    }

    Timeout base_timeout = timeout;
    if (base_timeout.count() == 0) base_timeout = std::chrono::milliseconds(5000);

    auto gen = generation_.load(std::memory_order_acquire);
    auto grq = result_queue_;

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

        Timeout effective = timeout;
        Timeout proto_default = proto_ptr->default_timeout();
        if (proto_default > effective) effective = proto_default;

        int ctx_id = io_pool_->acquire_context();
        proto_ptr->async_probe(
            target_name, ip, chosen_port, effective, io_pool_->executor_for(ctx_id),
            [this, proto_name = chosen_proto, grq, gen, io_pool_, ctx_id](ProtocolResult&& r) {
                io_pool_->release_context(ctx_id);
                if (generation_.load(std::memory_order_acquire) != gen) return;

                {
                    std::lock_guard<std::mutex> lock(results_mutex_);
                    results_.push_back(std::move(r));
                }

                // 必须先快照 target_，再 fetch_add。否则 fetch_add 后
                // ready_to_release() 变 true，scan_loop 的 reset() 可能并发修改
                // target_（含 std::string），导致 double-free。
                ScanTarget target_snapshot = target_;
                bool is_last = (tasks_completed_.fetch_add(1, std::memory_order_acq_rel) + 1
                                >= initial_total);
                if (is_last) {
                    ScanReport rep;
                    rep.target = std::move(target_snapshot);
                    rep.total_time = std::chrono::milliseconds(0);
                    {
                        std::lock_guard<std::mutex> lock(results_mutex_);
                        rep.protocols = std::move(results_);
                    }
                    grq->push(std::move(rep));

                    // 回调驱动重启：session 自己取新 target 继续干活，不再等 scan_loop 来 poll
                    if (on_restart_) on_restart_(this);
                }
            },
            bind_ip
        );
        tasks_total_.fetch_sub(1, std::memory_order_relaxed);
        ++launched;
    }
    return launched;
}

} // namespace scanner