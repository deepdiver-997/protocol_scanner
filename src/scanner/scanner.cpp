#include "scanner/core/scanner.h"
#include "scanner/dns/dns_resolver.h"
#include "scanner/common/logger.h"
#include "scanner/common/io_thread_pool.h"
#include "scanner/protocols/smtp_protocol.h"
#include "scanner/protocols/pop3_protocol.h"
#include "scanner/protocols/imap_protocol.h"
#include "scanner/protocols/http_protocol.h"
#include "scanner/protocols/ftp_protocol.h"
#include "scanner/protocols/telnet_protocol.h"
#include "scanner/protocols/ssh_protocol.h"
#include <algorithm>
#include <thread>
#include <chrono>
#include <filesystem>

namespace scanner {

namespace fs = std::filesystem;

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
    stop();
    if (input_thread_.joinable()) input_thread_.join();
    if (result_thread_.joinable()) result_thread_.join();
    if (scan_thread_.joinable()) scan_thread_.join();
    if (scan_pool_) scan_pool_->shutdown();
    if (io_pool_) io_pool_->shutdown();
}

Scanner::ScanStatistics Scanner::get_statistics() const {
    ScanStatistics stats;
    stats.total_targets = total_targets_.load();
    stats.successful_ips = successful_ips_.load();
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        for (const auto& [protocol, count] : protocol_success_counts_) {
            stats.protocol_counts[protocol] = count;
        }

        if (timing_started_.load()) {
            auto end = end_time_;
            if (end == std::chrono::steady_clock::time_point{}) {
                end = std::chrono::steady_clock::now();
            }
            stats.total_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start_time_);
        } else {
            stats.total_time = std::chrono::milliseconds(0);
        }
    }
    
    return stats;
}

void Scanner::init_protocols() {
    protocols_.clear();
    if (config_.enable_smtp) protocols_.push_back(std::make_unique<SmtpProtocol>());
    if (config_.enable_pop3) protocols_.push_back(std::make_unique<Pop3Protocol>());
    if (config_.enable_imap) protocols_.push_back(std::make_unique<ImapProtocol>());
    if (config_.enable_http) protocols_.push_back(std::make_unique<HttpProtocol>());
    if (config_.enable_ftp) protocols_.push_back(std::make_unique<FtpProtocol>());
    if (config_.enable_telnet) protocols_.push_back(std::make_unique<TelnetProtocol>());
    if (config_.enable_ssh) protocols_.push_back(std::make_unique<SshProtocol>());
}

bool Scanner::is_protocol_enabled(const std::string& name) const {
    if (name == "SMTP") return config_.enable_smtp;
    if (name == "POP3") return config_.enable_pop3;
    if (name == "IMAP") return config_.enable_imap;
    if (name == "HTTP") return config_.enable_http;
    if (name == "FTP") return config_.enable_ftp;
    if (name == "TELNET") return config_.enable_telnet;
    if (name == "SSH") return config_.enable_ssh;
    return false;
}

void Scanner::start(const std::string& source_path) {
    stop_ = false;
    input_done_ = false;
    input_source_path_ = source_path;
    
    // 初始化进度管理器
    progress_manager_ = std::make_unique<ProgressManager>(source_path, config_.output_dir);
    
    // 启动计时器
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        start_time_ = std::chrono::steady_clock::now();
        end_time_ = std::chrono::steady_clock::time_point{};
    }
    timing_started_ = true;
    
    // 启动三个线程
    input_thread_ = std::thread([this, source_path]() {
        try {
            size_t loaded_count = 0;
            
            // 加载断点信息
            CheckpointInfo checkpoint;
            bool has_checkpoint = progress_manager_->has_valid_checkpoint() && 
                                  progress_manager_->load_checkpoint(checkpoint);
            
            std::string skip_until_ip = has_checkpoint ? checkpoint.last_ip : "";
            bool skip_mode = !skip_until_ip.empty();
            size_t skipped_count = 0;

            auto enqueue_target = [this, &loaded_count, &skip_mode, &skip_until_ip, &skipped_count](const std::string& target_str) -> bool {
                if (stop_) return false;

                // 跳过已处理的 IP
                if (skip_mode) {
                    if (is_valid_ip_address(target_str)) {
                        if (target_str == skip_until_ip) {
                            skip_mode = false;  // 找到了断点，从下一个开始处理
                            LOG_CORE_INFO("Resumed from checkpoint: {}", skip_until_ip);
                        } else {
                            skipped_count++;
                            return true;  // 跳过
                        }
                    }
                }

                std::unique_lock<std::mutex> lock(targets_mutex_);
                targets_cv_.wait(lock, [this]() {
                    return targets_.size() < config_.targets_max_size || stop_;
                });

                if (stop_) return false;

                ScanTarget t;
                if (is_valid_ip_address(target_str)) {
                    t.domain = target_str;
                    t.ip = target_str;
                } else {
                    t.domain = target_str;
                }

                targets_.push_back(std::move(t));
                ++loaded_count;
                return true;
            };

            stream_domains(source_path, 0, enqueue_target);
            
            if (has_checkpoint) {
                LOG_CORE_INFO("Skipped {} already-processed targets", skipped_count);
                total_targets_ = loaded_count + checkpoint.processed_count;
                successful_ips_ = checkpoint.successful_count;
            } else {
                total_targets_ = loaded_count;
            }

            input_done_ = true;
            LOG_CORE_INFO("Input parsing completed: {} new targets loaded (total: {})", 
                         loaded_count, total_targets_.load());
        } catch (const std::exception& e) {
            LOG_CORE_ERROR("Error in input parser thread: {}", e.what());
            input_done_ = true;
        }
    });
    
    result_thread_ = std::thread([this]() { result_handler_thread(); });
    scan_thread_ = std::thread([this]() { scan_loop(); });
    
    LOG_CORE_INFO("Scanner started with input source: {}", source_path);
}

void Scanner::result_handler_thread() {
    const bool stream_mode = (config_.output_write_mode == "stream");
    auto last_flush = std::chrono::steady_clock::now();
    std::string last_successful_ip;  // 用于记录最后一个成功的 IP
    
    while (!stop_ || !result_queue_.empty()) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush);

        if (stream_mode) {
            if (!stop_ && elapsed < config_.result_flush_interval && result_queue_.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
        } else {
            if (result_queue_.empty()) {
                if (stop_) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
        }

        std::vector<ScanReport> batch;
        ScanReport rep;
        while (result_queue_.try_pop(rep)) {
            batch.push_back(std::move(rep));
        }

        if (batch.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        // 更新统计信息
        for (const auto& r : batch) {
            bool has_success = false;
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                for (const auto& pr : r.protocols) {
                    if (pr.accessible) {
                        has_success = true;
                        protocol_success_counts_[pr.protocol]++;
                    }
                }
            }
            if (has_success) {
                successful_ips_++;
            }
            
            // 记录最后的 IP（用于断点）
            last_successful_ip = r.target.ip;
            checkpoint_counter_++;
        }

        // 流式写入文件（在移动 batch 之前）
        if (stream_mode) {
            if (!report_ofs_.is_open()) {
                std::error_code ec;
                fs::create_directories(config_.output_dir, ec);
                std::string out_path = config_.output_dir;
                if (!out_path.empty() && out_path.back() != '/') out_path += "/";
                out_path += "scan_results.txt";
                report_ofs_.open(out_path, std::ios::app);
                if (report_ofs_.is_open() && !header_written_) {
                    report_ofs_ << "Scan Results\n";
                    report_ofs_ << "============\n";
                    header_written_ = true;
                }
            }

            if (report_ofs_.is_open()) {
                for (const auto& r : batch) {
                    // 跳过没有协议结果的报告（所有协议都失败时）
                    if (r.protocols.empty()) {
                        continue;
                    }
                    
                    report_ofs_ << r.target.domain << " (" << r.target.ip << ")\n";
                    for (const auto& pr : r.protocols) {
                        report_ofs_ << "  [" << pr.protocol << "] " << pr.host << ":" << pr.port;
                        if (pr.accessible) {
                            report_ofs_ << " -> OK\n";
                            if (!pr.attrs.banner.empty()) {
                                report_ofs_ << "    banner: " << pr.attrs.banner << "\n";
                            }
                        } else {
                            report_ofs_ << " -> FAIL\n";
                        }
                    }
                    report_ofs_ << "\n";
                }
                report_ofs_.flush();
            }
        }

        // 周期性保存进度（checkpoint）
        if (progress_manager_ && checkpoint_counter_ >= config_.checkpoint_interval) {
            CheckpointInfo checkpoint;
            checkpoint.last_ip = last_successful_ip;
            checkpoint.processed_count = total_targets_.load();
            checkpoint.successful_count = successful_ips_.load();
            
            auto now_time = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now_time);
            std::stringstream ss;
            ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S");
            checkpoint.timestamp = ss.str();
            
            progress_manager_->save_checkpoint(checkpoint);
            checkpoint_counter_ = 0;  // 重置计数器
        }

        reports_cv_.notify_one();

        last_flush = std::chrono::steady_clock::now();
    }
    
    if (stream_mode && report_ofs_.is_open()) {
        report_ofs_ << "\n================== 扫描统计 ==================\n";
        report_ofs_ << "总目标数: " << total_targets_.load() << "\n";
        report_ofs_ << "成功探测IP数: " << successful_ips_.load() << "\n";
        report_ofs_ << "\n各协议成功数:\n";
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            for (const auto& [protocol, count] : protocol_success_counts_) {
                report_ofs_ << "  " << protocol << ": " << count << "\n";
            }
        }
        if (timing_started_.load()) {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            auto end = end_time_;
            // 如果 end_time_ 还未设置（scan_loop 未完成），使用当前时间
            if (end == std::chrono::steady_clock::time_point{}) {
                end = std::chrono::steady_clock::now();
            }
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start_time_);
            report_ofs_ << "\n总耗时: " << duration.count() << " ms\n";
        }
        report_ofs_ << "============================================\n";
        report_ofs_.flush();
        report_ofs_.close();
        
        // 扫描完成，清除进度文件
        if (progress_manager_) {
            progress_manager_->clear_checkpoint();
        }
    }
    
    LOG_CORE_INFO("Result handler thread finished");
}

void Scanner::scan_loop() {
    auto io_exec = io_pool_->get_tracking_executor().underlying_executor();

    // 计算安全的任务配额：
    // - 每个 session 有 N 个协议探测（如 3 个：SSH, FTP, TELNET）
    // - 每个探测需要 1 个 socket (FD)
    // - 所以 max_work_count 个 session 最多需要 max_work_count * num_protocols 个 FD
    // - 我们需要确保 quota 不会一次性创建太多连接
    auto estimate_quota = [this]() -> int {
        // 每轮循环最多启动的任务数
        // 保守一点：最多启动 max_work_count / 2 个新任务
        int max_concurrent = static_cast<int>(config_.max_work_count);
        if (max_concurrent <= 0) max_concurrent = 1000; // 默认上限
        
        // 留出余量给已经在进行中的连接
        int active_sessions = static_cast<int>(sessions_.size());
        int available_slots = max_concurrent - active_sessions;
        
        // 每轮最多启动 batch_size 个新任务，但不能超过可用槽位
        int quota = std::min(config_.batch_size, std::max(1, available_slots));
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
            // 检查最大并发会话数（如果有配置）
            if (config_.max_work_count > 0 && sessions_.size() >= config_.max_work_count) {
                break;
            }

            ScanTarget t;
            {
                std::lock_guard<std::mutex> lock(targets_mutex_);
                if (targets_.empty()) {
                    // 唤醒输入线程，告知可以继续插入
                    targets_cv_.notify_one();
                    break;
                }
                t = targets_.back();
                targets_.pop_back();
            }

            auto sess = std::make_unique<ScanSession>(
                t,
                dns_resolver_ ? std::shared_ptr<IDnsResolver>(dns_resolver_.get(), [](IDnsResolver*){}) : nullptr,
                config_.dns_timeout,
                config_.probe_timeout,
                config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable : ScanSession::ProbeMode::ProtocolDefaults,
                protocols_
            );
            sess->set_only_success(config_.only_success);

            while (quota > 0 && sess->start_one_probe(protocols_, *scan_pool_, io_exec, config_.probe_timeout)) {
                --quota;
            }

            sessions_.push_back(std::move(sess));
        }

        // 检查是否完成
        bool has_pending = false;
        for (auto& s : sessions_) {
            if (s && s->tasks_completed() < s->tasks_total()) {
                has_pending = true;
                break;
            }
        }
        
        bool all_done = input_done_ && targets_.empty() && sessions_.empty() && !has_pending;
        if (all_done) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    
    LOG_CORE_INFO("Scan loop completed");
}

std::vector<ScanReport> Scanner::get_results(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(reports_mutex_);
    
    if (timeout.count() > 0) {
        reports_cv_.wait_for(lock, timeout, [this]() {
            return input_done_ && targets_.empty() && sessions_.empty();
        });
    } else if (timeout.count() == 0) {
        // 不等待，直接返回当前结果
    } else {
        // 无限等待
        reports_cv_.wait(lock, [this]() {
            return input_done_ && targets_.empty() && sessions_.empty();
        });
    }
    
    // 等待 result_thread_ 完成，确保所有结果已写入文件
    // 这样避免 result_thread_ 的周期性写入和最终写入冲突
    if (result_thread_.joinable()) {
        lock.unlock();  // 释放锁，避免死锁
        stop_ = true;  // 确保 result_handler_thread 退出
        result_thread_.join();
        lock.lock();   // 重新获取锁
    }
    
    return std::move(completed_reports_);
}

void Scanner::stop() {
    stop_ = true;
    targets_cv_.notify_all();
    reports_cv_.notify_all();
}

std::vector<ScanReport> Scanner::scan_domains(const std::vector<std::string>& domains) {
    std::size_t expected = 0;
    {
        std::lock_guard<std::mutex> lock(targets_mutex_);
        for (const auto& d : domains) {
            ScanTarget t;
            t.domain = d;
            targets_.push_back(t);
            expected++;
        }
    }

    // 创建虚拟输入（标记已完成）
    input_done_ = true;

    // 启动扫描线程
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
            // 检查最大并发会话数（如果有配置）
            if (config_.max_work_count > 0 && sessions_.size() >= config_.max_work_count) {
                break;
            }

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
                protocols_
            );            sess->set_only_success(config_.only_success);
            while (quota > 0 && sess->start_one_probe(protocols_, *scan_pool_, io_exec, config_.probe_timeout)) {
                --quota;
            }

            sessions_.push_back(std::move(sess));
        }

        // 无任务可做且目标和会话都空 -> 结束
        if (quota > 0) {
            bool has_pending = false;
            for (auto& s : sessions_) {
                if (s && s->tasks_completed() < s->tasks_total()) {
                    has_pending = true;
                    break;
                }
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

    // 停止计时器
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        end_time_ = std::chrono::steady_clock::now();
    }

    std::vector<ScanReport> reports;
    reports.reserve(expected);
    for (std::size_t i = 0; i < expected; ++i) {
        ScanReport rep;
        if (result_queue_.try_pop(rep)) {
            reports.push_back(std::move(rep));
        }
    }
    return reports;
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
