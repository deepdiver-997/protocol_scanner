#include "scanner/core/scanner.h"
#include "scanner/dns/dns_resolver.h"
#include "scanner/common/logger.h"
#include "scanner/common/io_thread_pool.h"
#include "scanner/common/buffer_pool.h"
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
#include <iostream>
#include <iomanip>
#include <sstream>
#include <functional>

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
    
    DnsResolverFactory::ResolverType rtype = DnsResolverFactory::ResolverType::C_ARES;
    const auto& rname = config_.dns_resolver_type;
    if (rname == "dig") {
        rtype = DnsResolverFactory::ResolverType::DIG;
    } else if (rname == "cares" || rname == "c-ares") {
        rtype = DnsResolverFactory::ResolverType::C_ARES;
    }
    dns_resolver_ = DnsResolverFactory::create(rtype);
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

    // 初始化厂商检测（内部封装，不再由 main 管理）
    vendor_detector_.reset();
    vendor_pattern_path_.clear();
    if (config_.enable_vendor) {
        vendor_detector_ = std::make_unique<VendorDetector>();
        vendor_pattern_path_ = config_.vendor_pattern_file.empty()
            ? (config_.output_dir + "/vendors.json")
            : config_.vendor_pattern_file;

        if (!vendor_detector_->load_patterns(vendor_pattern_path_)) {
            LOG_CORE_WARN("Failed to load vendor patterns from {}", vendor_pattern_path_);
            vendor_detector_.reset();
        }
    }
    
    // 初始化进度管理器
    progress_manager_ = std::make_unique<ProgressManager>(source_path, config_.output_dir);

    // 初始化结果处理器（用于流式写出自定义格式）
    result_handler_ = std::make_unique<ResultHandler>();
    if (result_handler_) {
        const std::string& fmt = config_.output_format;
        if (fmt == "json") result_handler_->set_format(OutputFormat::JSON);
        else if (fmt == "csv") result_handler_->set_format(OutputFormat::CSV);
        else if (fmt == "report") result_handler_->set_format(OutputFormat::REPORT);
        else if (fmt == "required_format") result_handler_->set_format(OutputFormat::REQUIRED);
        else result_handler_->set_format(OutputFormat::TEXT);
        result_handler_->set_only_success(config_.only_success);
    }
    
    // 启动计时器
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        start_time_ = std::chrono::steady_clock::now();
        end_time_ = std::chrono::steady_clock::time_point{};
    }
    timing_started_ = true;

    // must load checkpoint before starting input thread
    bool has_checkpoint = progress_manager_->has_valid_checkpoint() && progress_manager_->load_checkpoint(checkpoint_info_);
    std::cout << "Checkpoint loaded: " << (has_checkpoint ? "yes" : "no") << std::endl;
    if (has_checkpoint) {
        std::cout << "Resuming from last processed IP: " << checkpoint_info_.last_ip << std::endl;
        std::cout << "Last processed count: " << checkpoint_info_.processed_count << std::endl;
        std::cout << "Last successful count: " << checkpoint_info_.successful_count << std::endl;
        processed_count_ = checkpoint_info_.processed_count;
        successful_ips_ = checkpoint_info_.successful_count;
    }
    
    // 预分配 targets_ 以减少重分配开销
    {
        std::lock_guard<std::mutex> lock(targets_mutex_);
        targets_.reserve(std::min(config_.targets_max_size, size_t(10000)));
    }
    
    // 启动三个线程
    input_thread_ = std::thread([this, source_path, has_checkpoint]() {
        input_thread_func(source_path, has_checkpoint);
    });
    scan_thread_ = std::thread([this]() { scan_loop(); });
    result_thread_ = std::thread([this]() { result_handler_thread(); });
    
    LOG_CORE_INFO("Scanner started with input source: {}", source_path);
}

void Scanner::input_thread_func(const std::string& source_path, bool has_checkpoint) {
    try {
        size_t loaded_count = 0;
        size_t input_offset = has_checkpoint ? checkpoint_info_.input_file_offset : 0;

        std::string skip_until_ip = has_checkpoint ? checkpoint_info_.last_ip : "";
        bool skip_mode = !skip_until_ip.empty();
        size_t skipped_count = 0;

        auto enqueue_target = [this, &loaded_count, &skip_mode, &skip_until_ip, &skipped_count](const std::string& target_str, size_t source_offset) -> bool {
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
            t.source_offset = source_offset;

            targets_.push_back(std::move(t));
            ++loaded_count;
            return true;
        };

        // blocking call, will return after all targets are loaded
        stream_domains_with_offset(source_path, input_offset, enqueue_target);
        
        total_targets_ = loaded_count;

        input_done_ = true;
        LOG_CORE_INFO("Input parsing completed: {} new targets loaded (total: {})", 
                     loaded_count, total_targets_.load());
    } catch (const std::exception& e) {
        LOG_CORE_ERROR("Error in input parser thread: {}", e.what());
        input_done_ = true;
    }
}

void Scanner::result_handler_thread() {
    const bool stream_mode = (config_.output_write_mode == "stream");
    auto last_flush = std::chrono::steady_clock::now();
    std::string last_processed_ip;

    auto process_batch = [&](std::vector<ScanReport>& batch) {
        // 厂商识别
        if (vendor_detector_) {
            for (auto& r : batch) {
                for (auto& pr : r.protocols) {
                    if (!pr.accessible || pr.attrs.banner.empty()) continue;
                    int vendor_id = vendor_detector_->detect_vendor(pr.attrs.banner);
                    if (vendor_id > 0) {
                        pr.attrs.vendor = vendor_detector_->get_vendor_name(vendor_id);
                        const int server_id = static_cast<int>(std::hash<std::string>{}(pr.host + ":" + std::to_string(pr.port)));
                        vendor_detector_->update_matched_ids(vendor_id, server_id);
                    }
                }
            }
        }

        // 更新统计 & 保存结果
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

            processed_count_++;
            last_processed_ip = !r.target.ip.empty() ? r.target.ip : r.target.domain;
            checkpoint_info_.input_file_offset = r.target.source_offset;
        }

        // 保存进度（checkpoint）
        checkpoint_info_.last_ip = last_processed_ip;
        checkpoint_info_.processed_count = processed_count_.load();
        checkpoint_info_.successful_count = successful_ips_.load();
        checkpoint_info_.input_file_hash = ProgressManager::compute_file_hash(input_source_path_);

        auto now_time = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now_time);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S");
        checkpoint_info_.timestamp = ss.str();

        if (progress_manager_) {
            progress_manager_->save_checkpoint(checkpoint_info_);
        }

        reports_cv_.notify_one();
    };

    if (stream_mode) {
        while (true) {
            bool should_stop = stop_.load();
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush);

            if (!should_stop && elapsed < config_.result_flush_interval && result_queue_.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
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

            process_batch(batch);

            if (!report_ofs_.is_open()) {
                std::error_code ec;
                fs::create_directories(config_.output_dir, ec);
                std::string out_path = config_.output_dir;
                if (!out_path.empty() && out_path.back() != '/') out_path += "/";
                out_path += "scan_results.txt";
                report_ofs_.open(out_path, std::ios::app);
                if (checkpoint_info_.last_ip.empty() && report_ofs_.is_open() && !header_written_) {
                    report_ofs_ << "Scan Results\n";
                    report_ofs_ << "============\n";
                    header_written_ = true;
                }
            }

            if (report_ofs_.is_open()) {
                report_ofs_ << result_handler_->reports_to_string(batch);
                report_ofs_.flush();
            }

            last_flush = std::chrono::steady_clock::now();
            
            // 检查退出条件：stop 信号已发出 且 队列已清空
            if (should_stop && result_queue_.empty() && batch.empty()) {
                break;
            }
        }
    } else {
        std::cout << "Warning: Non-stream mode may consume large memory for storing results." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        while (true) {
            bool should_stop = stop_.load();
            std::vector<ScanReport> batch;
            ScanReport rep;
            while (result_queue_.try_pop(rep)) {
                batch.push_back(std::move(rep));
            }

            if (batch.empty()) {
                if (should_stop) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            process_batch(batch);

            std::lock_guard<std::mutex> lock(reports_mutex_);
            completed_reports_.insert(completed_reports_.end(), batch.begin(), batch.end());
        }
    }

    // 确保结束时间已记录
    if (timing_started_.load()) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        if (end_time_ == std::chrono::steady_clock::time_point{}) {
            end_time_ = std::chrono::steady_clock::now();
        }
    }

    // 最终输出
    auto stats = get_statistics();
    std::string summary_output;
    if (config_.output_to_console || !stream_mode) {
        summary_output = build_summary_output(result_handler_.get(), completed_reports_, stats, vendor_detector_.get());
    }

    if (stream_mode && report_ofs_.is_open()) {
        report_ofs_ << build_stats_block(stats);
        if (vendor_detector_) {
            report_ofs_ << "\nVendor Statistics:\n";
            auto stats_vec = vendor_detector_->get_statistics();
            for (const auto& s : stats_vec) {
                if (s.count > 0) {
                    report_ofs_ << s.name << ": " << s.count << " servers\n";
                }
            }
        }
        report_ofs_.flush();
        report_ofs_.close();
    }

    if (!stream_mode) {
        std::error_code ec;
        fs::create_directories(config_.output_dir, ec);
        if (ec) {
            LOG_CORE_WARN("Failed to create output dir '{}': {}", config_.output_dir, ec.message());
        }

        std::string ext = "txt";
        const std::string fmt = config_.output_format;
        if (fmt == "json") ext = "json";
        else if (fmt == "csv") ext = "csv";
        else if (fmt == "required_format") ext = "txt";

        std::string out_path = config_.output_dir;
        if (!out_path.empty() && out_path.back() != '/') out_path += "/";
        out_path += "scan_results." + ext;

        std::ofstream ofs(out_path);
        if (!ofs) {
            LOG_CORE_ERROR("Cannot open output file: {}", out_path);
        } else {
            ofs << summary_output;
            ofs.close();
            LOG_CORE_INFO("Results saved to {}", out_path);
        }
    }

    if (config_.output_to_console && !summary_output.empty()) {
        std::cout << summary_output;
    }

    if (vendor_detector_) {
        write_vendor_stats_file(vendor_detector_.get(), config_.output_dir);
        if (!vendor_pattern_path_.empty()) {
            vendor_detector_->save_patterns(vendor_pattern_path_);
        }
    }

    if (progress_manager_) {
        progress_manager_->clear_checkpoint();
    }

    LOG_CORE_INFO("Result handler thread finished");
}

void Scanner::scan_loop() {
    auto io_exec = io_pool_->get_tracking_executor().underlying_executor();

    // 预分配 sessions_ 以减少重分配开销
    sessions_.reserve(std::min(config_.max_work_count, size_t(1000)));

    // 内存监控：记录容器大小以便诊断内存问题
    auto last_mem_log = std::chrono::steady_clock::now();

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
        int active_sessions = 0;
        for (const auto& s : sessions_) {
            if (s && !s->is_idle()) {
                ++active_sessions;
            }
        }
        int available_slots = max_concurrent - active_sessions;
        
        // 每轮最多启动 batch_size 个新任务，但不能超过可用槽位
        int quota = std::min(config_.batch_size, std::max(1, available_slots));
        return quota;
    };

    auto wait_result_slot = [this]() {
        if (config_.result_queue_max_size == 0) return;
        while (!stop_ && result_queue_.size() >= config_.result_queue_max_size) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    };

    while (true) {
        bool should_stop = stop_.load();
        
        // 每10秒记录一次内存状态（用于诊断内存占用问题）
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_mem_log).count() >= 10) {
            size_t pending_sessions = 0;
            for (auto& s : sessions_) {
                if (s && !s->is_idle() && s->tasks_completed() < s->tasks_total()) {
                    pending_sessions++;
                }
            }
            
            // 获取内存池统计
            auto pool_stats = get_global_buffer_pool().get_stats();
            
            LOG_CORE_INFO(
                "[Memory] sessions_total={} sessions_pending={} targets_queue={} result_queue={} | "
                "[BufferPool] size={} available={} hit_rate={:.2f}%",
                sessions_.size(),
                pending_sessions,
                targets_.size(),
                result_queue_.size(),
                pool_stats.pool_size,
                pool_stats.available,
                pool_stats.hit_rate * 100.0
            );
            last_mem_log = now;
        }

        int quota = estimate_quota();

        auto fetch_target = [this](ScanTarget& out) -> bool {
            std::lock_guard<std::mutex> lock(targets_mutex_);
            if (targets_.empty()) {
                targets_cv_.notify_one();
                return false;
            }
            out = std::move(targets_.back());
            targets_.pop_back();
            return true;
        };

        // 复用已完成的 session，并推送报告
        for (auto& s : sessions_) {
            if (!s || s->is_idle()) continue;
            if (s->ready_to_release()) {
                ScanReport rep;
                rep.target = s->target();
                rep.protocols = s->protocol_results();
                rep.total_time = config_.probe_timeout;
                wait_result_slot();
                result_queue_.push(rep);

                ScanTarget next_target;
                if (fetch_target(next_target)) {
                    s->reset(
                        std::move(next_target),
                        config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable : ScanSession::ProbeMode::ProtocolDefaults,
                        protocols_
                    );
                    s->set_only_success(config_.only_success);
                } else {
                    s->mark_idle();
                }
            }
        }

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
            if (config_.max_work_count > 0) {
                int active_sessions = 0;
                for (const auto& s : sessions_) {
                    if (s && !s->is_idle()) {
                        ++active_sessions;
                    }
                }
                if (active_sessions >= static_cast<int>(config_.max_work_count)) {
                    break;
                }
            }

            ScanTarget t;
            if (!fetch_target(t)) {
                break;
            }

            ScanSession* idle_session = nullptr;
            for (auto& s : sessions_) {
                if (s && s->is_idle()) {
                    idle_session = s.get();
                    break;
                }
            }

            if (idle_session) {
                idle_session->reset(
                    std::move(t),
                    config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable : ScanSession::ProbeMode::ProtocolDefaults,
                    protocols_
                );
                idle_session->set_only_success(config_.only_success);

                while (quota > 0 && idle_session->start_one_probe(protocols_, *scan_pool_, io_exec, config_.probe_timeout)) {
                    --quota;
                }
            } else {
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
        }

        // 检查是否完成
        bool has_pending = false;
        bool has_active = false;
        for (auto& s : sessions_) {
            if (s && !s->is_idle()) {
                has_active = true;
            }
            if (s && !s->is_idle() && s->tasks_completed() < s->tasks_total()) {
                has_pending = true;
                break;
            }
        }
        
        bool all_done = input_done_ && targets_.empty() && !has_active && !has_pending;
        if (all_done) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        end_time_ = std::chrono::steady_clock::now();
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

    auto wait_result_slot = [this]() {
        if (config_.result_queue_max_size == 0) return;
        while (!stop_ && result_queue_.size() >= config_.result_queue_max_size) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    };
    
    auto estimate_quota = [this]() -> int {
        int base = std::max(1, config_.thread_count);
        int quota = base * 2;
        quota = std::min(quota, config_.batch_size);
        return quota;
    };

    while (!stop_) {
        int quota = estimate_quota();

        auto fetch_target = [this](ScanTarget& out) -> bool {
            std::lock_guard<std::mutex> lock(targets_mutex_);
            if (targets_.empty()) {
                return false;
            }
            out = std::move(targets_.back());
            targets_.pop_back();
            return true;
        };

        // 复用已完成的 session，并推送报告
        for (auto& s : sessions_) {
            if (!s || s->is_idle()) continue;
            if (s->ready_to_release()) {
                ScanReport rep;
                rep.target = s->target();
                rep.protocols = s->protocol_results();
                rep.total_time = config_.probe_timeout;
                wait_result_slot();
                result_queue_.push(rep);

                ScanTarget next_target;
                if (fetch_target(next_target)) {
                    s->reset(
                        std::move(next_target),
                        config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable : ScanSession::ProbeMode::ProtocolDefaults,
                        protocols_
                    );
                    s->set_only_success(config_.only_success);
                } else {
                    s->mark_idle();
                }
            }
        }

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
            if (config_.max_work_count > 0) {
                int active_sessions = 0;
                for (const auto& s : sessions_) {
                    if (s && !s->is_idle()) {
                        ++active_sessions;
                    }
                }
                if (active_sessions >= static_cast<int>(config_.max_work_count)) {
                    break;
                }
            }

            ScanTarget t;
            if (!fetch_target(t)) break;

            ScanSession* idle_session = nullptr;
            for (auto& s : sessions_) {
                if (s && s->is_idle()) {
                    idle_session = s.get();
                    break;
                }
            }

            if (idle_session) {
                idle_session->reset(
                    std::move(t),
                    config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable : ScanSession::ProbeMode::ProtocolDefaults,
                    protocols_
                );
                idle_session->set_only_success(config_.only_success);
                while (quota > 0 && idle_session->start_one_probe(protocols_, *scan_pool_, io_exec, config_.probe_timeout)) {
                    --quota;
                }
            } else {
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
        }

        // 无任务可做且目标和会话都空 -> 结束
        if (quota > 0) {
            bool has_pending = false;
            bool has_active = false;
            for (auto& s : sessions_) {
                if (s && !s->is_idle()) {
                    has_active = true;
                }
                if (s && !s->is_idle() && s->tasks_completed() < s->tasks_total()) {
                    has_pending = true;
                    break;
                }
            }
            if (!has_pending) {
                std::lock_guard<std::mutex> lock(targets_mutex_);
                if (targets_.empty() && !has_active) {
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
