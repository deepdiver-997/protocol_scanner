#include "scanner/core/scanner.h"
#include "scanner/dns/dns_resolver.h"
#include "scanner/common/logger.h"
#include "scanner/common/io_thread_pool.h"
#include "scanner/protocols/smtp_protocol.h"
#include "scanner/protocols/pop3_protocol.h"
#include "scanner/protocols/imap_protocol.h"
#include "scanner/protocols/http_protocol.h"
#include <algorithm>
#include <thread>
#include <chrono>

namespace scanner {

Scanner::Scanner(const ScannerConfig& config)
    : config_(config) {
    // 优先使用新的分离配置，向后兼容旧的 thread_count
    int io_threads = config.io_thread_count > 0 ? config.io_thread_count : config.thread_count;
    int cpu_threads = config.cpu_thread_count > 0 ? config.cpu_thread_count : std::max(1, config.thread_count / 4);

    scan_pool_ = std::make_shared<ThreadPool>(std::max(1, cpu_threads));
    io_pool_ = std::make_shared<IoThreadPool>(std::max(1, io_threads));

    LOG_CORE_INFO("Thread pools initialized: IO={} CPU={}", io_threads, cpu_threads);
    
    dns_resolver_ = DnsResolverFactory::create(DnsResolverFactory::ResolverType::C_ARES);
    init_protocols();
}

Scanner::~Scanner() {
    if (scan_pool_) scan_pool_->shutdown();
    if (io_pool_) io_pool_->shutdown();
}

void Scanner::init_protocols() {
    protocols_.clear();
    if (config_.enable_smtp) protocols_.push_back(std::make_unique<SmtpProtocol>());
    if (config_.enable_pop3) protocols_.push_back(std::make_unique<Pop3Protocol>());
    if (config_.enable_imap) protocols_.push_back(std::make_unique<ImapProtocol>());
    if (config_.enable_http) protocols_.push_back(std::make_unique<HttpProtocol>());
}

bool Scanner::is_protocol_enabled(const std::string& name) const {
    if (name == "SMTP") return config_.enable_smtp;
    if (name == "POP3") return config_.enable_pop3;
    if (name == "IMAP") return config_.enable_imap;
    if (name == "HTTP") return config_.enable_http;
    return false;
}

std::vector<ScanReport> Scanner::scan_domains(const std::vector<std::string>& domains) {
    std::size_t expected = 0;
    {
        std::lock_guard<std::mutex> lock(targets_mutex_);
        for (const auto& d : domains) {
            ScanTarget t; t.domain = d;
            targets_.push_back(t);
            expected++;
        }
    }

    start();

    std::vector<ScanReport> reports;
    reports.reserve(expected);
    for (std::size_t i = 0; i < expected; ++i) {
        ScanReport rep;
        if (result_queue_.pop(rep)) {
            reports.push_back(std::move(rep));
        }
    }
    return reports;
}

void Scanner::start() {
    auto io_exec = io_pool_->get_tracking_executor().underlying_executor();

    auto estimate_quota = [this]() -> int {
        int base = std::max(1, config_.thread_count);
        int quota = base * 2;
        quota = std::min(quota, config_.batch_size);
        return quota;
    };

    while (!stop_) {
        int quota = estimate_quota();

        // 移除已完成的 session，并推送报告
        sessions_.erase(
            std::remove_if(
                sessions_.begin(),
                sessions_.end(),
                [this](const std::unique_ptr<ScanSession>& s) {
                    if (s && s->ready_to_release()) {
                        ScanReport rep;
                        rep.target = { s->domain(), s->dns_result().ip, {}, 0 };
                        rep.protocols = s->protocol_results();
                        rep.total_time = config_.probe_timeout;
                        result_queue_.push(rep);
                        return true;
                    }
                    return false;
                }
            ),
            sessions_.end()
        );

        // 先给现有 session 分配任务
        for (auto& s : sessions_) {
            if (!s) continue;
            while (quota > 0 && s->start_one_probe(protocols_, *scan_pool_, io_exec, config_.probe_timeout)) {
                --quota;
            }
            if (quota == 0) break;
        }

        // 创建新 session 并分配任务
        while (quota > 0) {
            ScanTarget t;
            {
                std::lock_guard<std::mutex> lock(targets_mutex_);
                if (targets_.empty()) break;
                t = targets_.back();
                targets_.pop_back();
            }

            auto sess = std::make_unique<ScanSession>(
                t,
                dns_resolver_ ? std::shared_ptr<IDnsResolver>(dns_resolver_.get(), [](IDnsResolver*){}) : nullptr,
                config_.dns_timeout,
                config_.probe_timeout,
                config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable : ScanSession::ProbeMode::ProtocolDefaults,
                protocols_,
                [](ScanSession* /*s*/) {}
            );

            while (quota > 0 && sess->start_one_probe(protocols_, *scan_pool_, io_exec, config_.probe_timeout)) {
                --quota;
            }

            sessions_.push_back(std::move(sess));
        }

        // 无任务可做且目标和会话都空 -> 结束
        if (quota > 0) {
            bool has_pending = false;
            for (auto& s : sessions_) {
                if (s && s->tasks_completed() < s->tasks_total()) { has_pending = true; break; }
            }
            if (!has_pending) {
                std::lock_guard<std::mutex> lock(targets_mutex_);
                if (targets_.empty() && sessions_.empty()) {
                    break;
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}
ScanReport Scanner::scan_target(const ScanTarget& target) {
    auto out = scan_domains({target.domain});
    return out.empty() ? ScanReport{} : out.front();
}
std::vector<ScanReport> Scanner::scan_targets(const std::vector<ScanTarget>& targets) {
    std::vector<std::string> domains;
    domains.reserve(targets.size());
    for (auto& t : targets) domains.push_back(t.domain);
    return scan_domains(domains);
}

} // namespace scanner
