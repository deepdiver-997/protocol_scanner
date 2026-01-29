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
        // 恢复累计值
        successful_ips_ = checkpoint_info_.successful_count;
        processed_count_ = checkpoint_info_.processed_count;
    }
    
    // 预分配 targets_ 以减少重分配开销
    // 【优化】按实际需要动态扩展，初始预留少一点
    {
        std::lock_guard<std::mutex> lock(targets_mutex_);
        targets_.reserve(std::min(static_cast<size_t>(config_.batch_size * 2), size_t(2000)));
    }
    
    // 启动三个线程
    input_thread_ = std::thread([this, source_path, has_checkpoint]() {
        input_thread_func(source_path, has_checkpoint);
    });
    
    // 【优化】等待 input_thread 至少加载一些 targets，但有超时防止卡住
    // 即使没有加载完，也要启动 scan_loop 开始消费，否则输入线程会因为 targets 满而阻塞
    if (has_checkpoint) {
        LOG_CORE_INFO("Waiting for input thread to load initial targets after checkpoint skip...");
        const size_t min_targets_before_start = 50;  // 至少等待50个target加载
        const auto start_wait = std::chrono::steady_clock::now();
        bool got_enough_targets = false;
        
        while (!input_done_ && !stop_ && !got_enough_targets) {
            std::unique_lock<std::mutex> lock(targets_mutex_);
            auto ready = targets_cv_.wait_for(lock, std::chrono::seconds(3), [this]() {
                return targets_.size() >= min_targets_before_start || input_done_ || stop_;
            });
            
            if (ready && targets_.size() >= min_targets_before_start) {
                LOG_CORE_INFO("Initial targets loaded ({}), starting scan threads", targets_.size());
                got_enough_targets = true;
                break;
            }
            
            // 超时 3 秒后强制启动，不然输入线程会因为 targets 满而阻塞，导致死锁
            auto elapsed = std::chrono::steady_clock::now() - start_wait;
            if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > 3) {
                LOG_CORE_WARN("Timeout waiting for {} targets (have {}), force starting scan threads",
                              min_targets_before_start, targets_.size());
                got_enough_targets = true;
                break;
            }
        }
    }
    std::cout << "Already have " << targets_.size() << " targets loaded, starting scan..." << std::endl;
    
    scan_thread_ = std::thread([this]() { scan_loop(); });
    result_thread_ = std::thread([this]() { result_handler_thread(); });
    
    LOG_CORE_INFO("Scanner started with input source: {}", source_path);
}

void Scanner::input_thread_func(const std::string& source_path, bool has_checkpoint) {
    try {
        size_t loaded_count = 0;
        size_t skipped_count = 0;  // 记录跳过的数量
        size_t input_offset = has_checkpoint ? checkpoint_info_.input_file_offset : 0;

        std::string skip_until_ip = has_checkpoint ? checkpoint_info_.last_ip : "";
        bool skip_mode = !skip_until_ip.empty();
        
        // 【优化】将断点 IP 转为数值，避免字符串比较和临时对象创建
        // 优先使用已保存的 uint32 值（如果可用）
        uint32_t skip_until_uint = 0;
        if (has_checkpoint && checkpoint_info_.last_processed_ip_uint > 0) {
            skip_until_uint = checkpoint_info_.last_processed_ip_uint;
            LOG_CORE_INFO("Using saved checkpoint IP uint32: {}", skip_until_uint);
        } else if (skip_mode && is_valid_ip_address(skip_until_ip)) {
            try {
                skip_until_uint = boost::asio::ip::make_address_v4(skip_until_ip).to_uint();
                LOG_CORE_INFO("Checkpoint IP {} converted to uint32: {}", skip_until_ip, skip_until_uint);
            } catch (...) {
                LOG_CORE_WARN("Failed to parse checkpoint IP {}, fallback to string compare", skip_until_ip);
            }
        }

        // 【优化】防止断点偏移错位：如果有偏移但没有last_ip（或processed_count=0），
        // 说明是文件偏移跳转但无需查找特定IP，直接从偏移位置开始处理
        if (has_checkpoint && input_offset > 0 && skip_until_ip.empty()) {
            skip_mode = false;  // 直接从偏移开始，无需跳过
            LOG_CORE_INFO("Resuming from file offset {} without IP skip", input_offset);
        }

        // 【关键优化】直接接受 uint32，完全避免字符串转换开销
        auto enqueue_target_uint = [this, &loaded_count, &skip_mode, &skip_until_uint, &skipped_count, &skip_until_ip](uint32_t ip_uint, size_t source_offset) -> bool {
            if (stop_) return false;

            // 【高速路径】使用纯数值比较，零字符串创建
            if (skip_mode) {
                if (skip_until_uint > 0) {
                    if (ip_uint == skip_until_uint) {
                        skip_mode = false;
                        LOG_CORE_INFO("Resumed from checkpoint: {} (skipped {} IPs)", skip_until_ip, skipped_count);
                    } else if (ip_uint < skip_until_uint) {
                        skipped_count++;
                        return true;  // 跳过，不创建字符串
                    } else {
                        LOG_CORE_WARN("IP uint {} exceeds checkpoint {}, starting from here", ip_uint, skip_until_uint);
                        skip_mode = false;
                    }
                }
            }

            // 【关键优化】直接存储 uint32，延迟字符串化到真正需要时
            std::unique_lock<std::mutex> lock(targets_mutex_);
            targets_cv_.wait(lock, [this]() {
                return targets_.size() < config_.targets_max_size || stop_;
            });

            if (stop_) return false;

            ScanTarget t;
            t.set_ip(ip_uint);  // 内部会设置 ip_uint 和 domain
            t.source_offset = source_offset;

            targets_.push_back(std::move(t));
            lock.unlock();
            targets_cv_.notify_one();
            ++loaded_count;
            return true;
        };

        // blocking call, will return after all targets are loaded
        // 使用新的 stream_domains_with_offset_uint 来直接传递 uint32
        stream_domains_with_offset_uint(source_path, input_offset, enqueue_target_uint, skip_until_uint);

        // 计算总目标数：如果是从断点恢复，总数 = 本轮加载 + 之前累计处理
        if (has_checkpoint) {
            total_targets_ = loaded_count + checkpoint_info_.processed_count;
            LOG_CORE_INFO("Input parsing completed: {} new targets loaded (total: {}, skipped: {})",
                         loaded_count, total_targets_.load(), skipped_count);
        } else {
            total_targets_ = loaded_count;
            LOG_CORE_INFO("Input parsing completed: {} targets loaded", total_targets_.load());
        }

        input_done_ = true;
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
            last_processed_ip = r.target.get_ip_string();  // 使用新的 ip() 方法
            if (last_processed_ip.empty()) last_processed_ip = r.target.domain;
            checkpoint_info_.input_file_offset = r.target.source_offset;
        }

        // 保存进度（checkpoint）
        checkpoint_info_.last_ip = last_processed_ip;
        checkpoint_info_.processed_count = processed_count_.load();
        checkpoint_info_.successful_count = successful_ips_.load();
        checkpoint_info_.input_file_hash = ProgressManager::compute_file_hash(input_source_path_);
        
        // 保存 IP 的 uint32 形式用于快速断点恢复
        if (!last_processed_ip.empty() && is_valid_ip_address(last_processed_ip)) {
            try {
                checkpoint_info_.last_processed_ip_uint = boost::asio::ip::make_address_v4(last_processed_ip).to_uint();
            } catch (...) {
                checkpoint_info_.last_processed_ip_uint = 0;
            }
        }

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
            // 【优化】集中获取时间，避免多次系统调用
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

            // 【优化】使用循环开头的 now，而不是重新获取时间
            last_flush = now;
            
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
    std::cout << "Scan loop started." << std::endl;
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

    // 【新优化】根据负载动态计算睡眠时间，避免固定 5ms 导致过多的 clock_nanosleep 调用
    auto calculate_adaptive_sleep = [](int active_sessions, int idle_count, int quota_used, int total_sessions, bool has_targets) -> std::chrono::milliseconds {
        // 策略：高负载 → 短睡眠（1-3ms），低负载 → 长睡眠（8-20ms）
        
        // 1. 活跃会话比率（0.0 - 1.0）
        double active_ratio = total_sessions > 0 ? static_cast<double>(active_sessions) / total_sessions : 0.0;
        
        // 2. 基于活跃率和任务状态动态调整
        int base_sleep_ms = 5;  // 默认基准
        
        if (active_ratio > 0.8 && has_targets) {
            // 高负载：80%+ 活跃 session 且有待扫描任务
            base_sleep_ms = 1;
        } else if (active_ratio > 0.5 && has_targets) {
            // 中高负载：50-80% 活跃
            base_sleep_ms = 2;
        } else if (active_ratio > 0.2) {
            // 中负载：20-50% 活跃
            base_sleep_ms = 5;
        } else if (active_sessions > 0) {
            // 低负载：还有活跃但很少
            base_sleep_ms = 8;
        } else {
            // 极低负载：无活跃 session（等待新任务或即将结束）
            base_sleep_ms = has_targets ? 10 : 15;
        }
        
        // 3. quota_used 修正（如果 quota 很快用完，说明任务提交很饱和）
        if (quota_used >= 50) {
            base_sleep_ms = std::max(1, base_sleep_ms - 2);  // 高提交率，缩短睡眠
        } else if (quota_used < 5) {
            base_sleep_ms = std::min(20, base_sleep_ms + 5);  // 低提交率，延长睡眠
        }
        
        return std::chrono::milliseconds(base_sleep_ms);
    };

    while (true) {
        // 【优化】在循环开头一次性获取当前时间，避免多次系统调用
        auto loop_now = std::chrono::steady_clock::now();
        
        // 每10秒记录一次内存状态（用于诊断内存占用问题）
        if (std::chrono::duration_cast<std::chrono::seconds>(loop_now - last_mem_log).count() >= 10) {
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
            last_mem_log = loop_now;
        }

        int quota = estimate_quota();
        int initial_quota = quota;  // 记录初始 quota 用于计算使用率

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

        // 单次遍历：复用已完成 + 分配任务 + 统计状态
        // 将原来的 4 次遍历合并为 1 次，减少缓存失效和循环开销
        int active_sessions = 0;
        int idle_count = 0;
        
        for (auto& s : sessions_) {
            if (!s) continue;
            
            bool is_idle = s->is_idle();
            if (is_idle) {
                idle_count++;
                continue;
            }
            
            active_sessions++;
            
            // 1️⃣ 检查是否完成，复用已完成的 session
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
                    // 【优化】一次性批量启动所有待扫协议，而不是多次循环
                    int started = s->start_all_pending_probes(protocols_, *scan_pool_, io_exec, config_.probe_timeout, quota);
                    quota -= started;
                } else {
                    // 【优化】mark_idle 无需调用，is_idle 由 tasks_total == 0 隐含表示
                    idle_count++;
                    active_sessions--;
                }
            } else {
                // 2️⃣ 为现有活跃 session 分配新任务【优化】批量启动所有待扫协议
                int started = s->start_all_pending_probes(protocols_, *scan_pool_, io_exec, config_.probe_timeout, quota);
                quota -= started;
            }
            
            if (quota == 0) break;
        }

        // 如果还有配额，查找 idle session 进行复用或创建新的
        int max_sessions = config_.max_work_count > 0
            ? static_cast<int>(config_.max_work_count)
            : std::max(1, config_.batch_size);

        while (quota > 0) {
            ScanTarget t;
            if (!fetch_target(t)) {
                break;
            }

            // 检查最大并发会话数
            if (active_sessions >= max_sessions) {
                // 放回这个 target，不创建新会话
                std::lock_guard<std::mutex> lock(targets_mutex_);
                targets_.push_back(std::move(t));
                break;
            }

            // 查找 idle session 进行复用
            ScanSession* idle_session = nullptr;
            if (idle_count > 0) {
                for (auto& s : sessions_) {
                    if (s && s->is_idle()) {
                        idle_session = s.get();
                        idle_count--;
                        active_sessions++;
                        break;
                    }
                }
            }

            if (idle_session) {
                idle_session->reset(
                    std::move(t),
                    config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable : ScanSession::ProbeMode::ProtocolDefaults,
                    protocols_
                );
                idle_session->set_only_success(config_.only_success);
                // 【优化】批量启动
                int started = idle_session->start_all_pending_probes(protocols_, *scan_pool_, io_exec, config_.probe_timeout, quota);
                quota -= started;
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
                int started = sess->start_all_pending_probes(protocols_, *scan_pool_, io_exec, config_.probe_timeout, quota);
                quota -= started;
                sessions_.push_back(std::move(sess));
                active_sessions++;
            }
        }

        // 检查是否完成（使用前面计算的统计信息）
        bool all_done = input_done_ && targets_.empty() && active_sessions == 0;
        if (all_done) {
            break;
        }

        // 【优化】动态睡眠时间：根据负载自适应调整，避免固定 5ms 导致过多 clock_nanosleep 开销
        int quota_used = initial_quota - quota;
        bool has_targets = false;
        {
            std::lock_guard<std::mutex> lock(targets_mutex_);
            has_targets = !targets_.empty();
        }
        
        auto sleep_duration = calculate_adaptive_sleep(
            active_sessions,
            idle_count,
            quota_used,
            static_cast<int>(sessions_.size()),
            has_targets
        );
        
        std::this_thread::sleep_for(sleep_duration);
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
                    // 【优化】mark_idle 无需调用
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
