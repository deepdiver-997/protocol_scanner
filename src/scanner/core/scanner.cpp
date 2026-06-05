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
#include "scanner/protocols/redis_protocol.h"
#include "scanner/protocols/rtsp_protocol.h"
#include "scanner/protocols/sip_protocol.h"
#include "scanner/protocols/mysql_protocol.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <thread>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <functional>
#include <iterator>

namespace scanner {

namespace fs = std::filesystem;

namespace {

std::string normalize_output_format(std::string fmt) {
    if (fmt == "txt") return "text";
    return fmt;
}

std::string output_extension_for(const std::string& fmt, bool stream_mode) {
    if (fmt == "json") return stream_mode ? "jsonl" : "json";
    if (fmt == "csv") return "csv";
    if (fmt == "required_format") return "txt";
    if (fmt == "report") return "txt";
    if (fmt == "text") return "txt";
    if (fmt == "fingerprint") return "jsonl";
    return "txt";
}

bool needs_text_header(const std::string& fmt) {
    return fmt == "text" || fmt == "report" || fmt == "required_format";
}


} // namespace

Scanner::Scanner(const ScannerConfig& config)
    : config_(config) {
    // 优先使用新的分离配置，向后兼容旧的 thread_count
    int io_threads = config.io_thread_count > 0 ? config.io_thread_count : config.thread_count;

    io_pool_ = std::make_shared<IoThreadPool>(std::max(1, io_threads));

    LOG_CORE_DEBUG("IO thread pool initialized: {} threads", io_threads);
    
    DnsResolverFactory::ResolverType rtype = DnsResolverFactory::ResolverType::C_ARES;
    const auto& rname = config_.dns_resolver_type;
    if (rname == "null" || rname == "none") {
        rtype = DnsResolverFactory::ResolverType::NULL_RESOLVER;
    } else if (rname == "dig") {
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
    if (config_.enable_redis) protocols_.push_back(std::make_unique<RedisProtocol>());
    if (config_.enable_rtsp) protocols_.push_back(std::make_unique<RtspProtocol>());
    if (config_.enable_sip) protocols_.push_back(std::make_unique<SipProtocol>());
    if (config_.enable_mysql) protocols_.push_back(std::make_unique<MysqlProtocol>());
}

bool Scanner::is_protocol_enabled(const std::string& name) const {
    if (name == "SMTP") return config_.enable_smtp;
    if (name == "POP3") return config_.enable_pop3;
    if (name == "IMAP") return config_.enable_imap;
    if (name == "HTTP") return config_.enable_http;
    if (name == "FTP") return config_.enable_ftp;
    if (name == "TELNET") return config_.enable_telnet;
    if (name == "SSH") return config_.enable_ssh;
    if (name == "REDIS") return config_.enable_redis;
    if (name == "RTSP") return config_.enable_rtsp;
    if (name == "SIP") return config_.enable_sip;
    if (name == "MYSQL") return config_.enable_mysql;
    return false;
}

void Scanner::start(const std::string& source_path) {
    stop_ = false;
    input_done_ = false;
    scan_done_ = false;
    input_source_path_ = source_path;

    // 【自动配置优化】配置值为0时，根据系统资源自动计算最优值
    // 此时配置文件和命令行参数都已合并完成
    if (config_.max_work_count == 0) {
        // 根据线程数估算：每个IO线程可维持250-500个并发连接
        int io_threads = config_.io_thread_count > 0 ? config_.io_thread_count : config_.thread_count;
        config_.max_work_count = std::max(500, io_threads * 300);
        // init_global_buffer_pool 需要这个值来初始化缓冲池大小
        get_global_buffer_pool(config_.max_work_count);
        LOG_CORE_DEBUG("Auto-configured max_work_count: {} (based on {} IO threads)", 
                     config_.max_work_count, io_threads);
    }
    
    if (config_.targets_max_size == 0) {
        // targets队列大小：至少是max_work_count的2倍，保证input线程不会被阻塞
        config_.targets_max_size = std::max(size_t(5000), config_.max_work_count * 3);
        LOG_CORE_DEBUG("Auto-configured targets_max_size: {}", config_.targets_max_size);
    }
    
    if (config_.result_queue_max_size == 0) {
        // 结果队列：通常max_work_count的一半即可
        config_.result_queue_max_size = std::max(size_t(500), config_.max_work_count / 2);
        LOG_CORE_DEBUG("Auto-configured result_queue_max_size: {}", config_.result_queue_max_size);
    }

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
    input_source_hash_ = ProgressManager::compute_file_hash(source_path);

    std::error_code output_dir_ec;
    fs::create_directories(config_.output_dir, output_dir_ec);
    if (output_dir_ec) {
        LOG_CORE_WARN("Failed to create output dir '{}': {}", config_.output_dir, output_dir_ec.message());
    }

    // 初始化结果处理器（用于流式写出自定义格式）
    result_handler_ = std::make_unique<ResultHandler>();
    if (result_handler_) {
        const std::string fmt = normalize_output_format(config_.output_format);
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
        if (!checkpoint_info_.input_file_hash.empty() && checkpoint_info_.input_file_hash != input_source_hash_) {
            LOG_CORE_WARN("Checkpoint hash mismatch, ignoring stale checkpoint for {}", source_path);
            checkpoint_info_ = CheckpointInfo{};
            has_checkpoint = false;
        }
    }
    if (has_checkpoint) {
        std::cout << "Resuming from committed seq: " << checkpoint_info_.processed_count << std::endl;
        std::cout << "Last processed count: " << checkpoint_info_.processed_count << std::endl;
        std::cout << "Last successful count: " << checkpoint_info_.successful_count << std::endl;
        // 恢复累计值
        successful_ips_ = checkpoint_info_.successful_count;
        processed_count_ = checkpoint_info_.processed_count;
    }
    
    // 预分配 targets_ 以减少重分配开销
    // 【优化】按实际需要动态扩展，初始预留少一点
    {
        std::lock_guard<SpinLock> lock(targets_lock_);
        // deque 不需要 reserve，自动按块分配
    }
    
    // 启动三个线程
    input_thread_ = std::thread([this, source_path, has_checkpoint]() {
        input_thread_func(source_path, has_checkpoint);
    });
    
    // 【优化】等待 input_thread 至少加载一些 targets，但有超时防止卡住
    // 即使没有加载完，也要启动 scan_loop 开始消费，否则输入线程会因为 targets 满而阻塞
    if (has_checkpoint) {
        LOG_CORE_DEBUG("Waiting for input thread to load initial targets after checkpoint skip...");
        const size_t min_targets_before_start = 50;  // 至少等待50个target加载
        const auto start_wait = std::chrono::steady_clock::now();
        bool got_enough_targets = false;
        
        while (!input_done_ && !stop_ && !got_enough_targets) {
            {
                std::lock_guard<SpinLock> lock(targets_lock_);
                if (targets_.size() >= min_targets_before_start) {
                    LOG_CORE_DEBUG("Initial targets loaded ({}), starting scan threads", targets_.size());
                    got_enough_targets = true;
                    break;
                }
            }
            // 自旋等待输入线程填充
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

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
        std::cout << "[input_thread] Starting to parse: " << source_path << std::endl;
        LOG_CORE_DEBUG("[input_thread] Starting to parse: {}", source_path);
        size_t loaded_count = 0;
        size_t skipped_count = 0;  // 记录跳过的数量
        size_t input_offset = has_checkpoint ? checkpoint_info_.input_file_offset : 0;
        const uint64_t committed_seq = has_checkpoint ? checkpoint_info_.processed_count : 0;
        const size_t resume_ordinal = has_checkpoint ? checkpoint_info_.input_offset_ordinal : 0;
        uint64_t current_seq = (committed_seq >= resume_ordinal) ? (committed_seq - resume_ordinal) : 0;
        size_t current_offset = static_cast<size_t>(-1);
        size_t current_offset_ordinal = 0;

        // 兼容域名 + IP + CIDR 混合输入
        auto enqueue_target = [this, &loaded_count, &skipped_count, committed_seq, &current_seq, &current_offset, &current_offset_ordinal](const std::string& target_value, size_t source_offset) -> bool {
            if (stop_) {
                LOG_CORE_ERROR("[enqueue_target_uint] stop_=true detected! loaded_count={}, this should NOT happen during normal scanning!", loaded_count);
                return false;
            }

            if (source_offset != current_offset) {
                current_offset = source_offset;
                current_offset_ordinal = 0;
            }
            ++current_offset_ordinal;
            ++current_seq;

            uint32_t ip_uint = 0;
            bool is_ip = false;
            try {
                ip_uint = boost::asio::ip::make_address_v4(target_value).to_uint();
                is_ip = true;
            } catch (...) {
                is_ip = false;
            }

            if (current_seq <= committed_seq) {
                ++skipped_count;
                if (skipped_count % 10000 == 0) {
                    LOG_CORE_DEBUG("Skipping committed targets: current_seq={} committed_seq={} skipped={}", current_seq, committed_seq, skipped_count);
                }
                return true;
            }

            // 【关键优化】直接存储 uint32，延迟字符串化到真正需要时
            {
                std::lock_guard<SpinLock> lock(targets_lock_);
                // 打印首次入队的诊断信息
                if (loaded_count == 0) {
                    std::cout << "[input_thread] First target enqueued, queue_size=" << targets_.size()
                              << ", max=" << config_.targets_max_size << std::endl;
                }
            }

            // 自旋等待直到有队列空间
            while (true) {
                {
                    std::lock_guard<SpinLock> lock(targets_lock_);
                    if (targets_.size() < config_.targets_max_size || stop_) break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (stop_) {
                LOG_CORE_WARN("[input_thread] Stop signal received during enqueue, loaded={} total", loaded_count);
                return false;
            }

            ScanTarget t;
            if (is_ip) {
                t.set_ip(ip_uint);
            } else {
                t.domain = target_value;
            }
            t.seq = current_seq;
            t.source_offset = source_offset;
            t.offset_ordinal = current_offset_ordinal;

            {
                std::lock_guard<SpinLock> lock(targets_lock_);
                targets_.push_back(std::move(t));
            }
            ++loaded_count;
            
            // 【诊断日志】每1000个IP打印一次进度
            if (loaded_count % 1000 == 0) {
                LOG_CORE_DEBUG("[input_thread] Loaded {} targets, queue_size={}", loaded_count, targets_.size());
            }
            
            return true;
        };

        // blocking call, will return after all targets are loaded
        // 使用字符串路径以支持域名/IP/CIDR 混合输入
        std::cout << "[input_thread] Calling stream_domains_with_offset..." << std::endl;
        LOG_CORE_DEBUG("[input_thread] Calling stream_domains_with_offset, offset={}, committed_seq={}, resume_ordinal={}", 
             input_offset, committed_seq, resume_ordinal);
        stream_domains_with_offset(source_path, input_offset, enqueue_target);
        std::cout << "[input_thread] Completed: loaded " << loaded_count << " targets" << std::endl;
        LOG_CORE_DEBUG("[input_thread] Completed: loaded {} targets", loaded_count);
        
        // 【诊断】检查是否完整读取了文件
        std::ifstream check_file(source_path);
        if (check_file) {
            check_file.seekg(0, std::ios::end);
            auto file_size = check_file.tellg();
            LOG_CORE_DEBUG("[input_thread] File size: {} bytes, final offset processed: {}", 
                         file_size, input_offset);
        }

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
        reports_cv_.notify_all();
    } catch (const std::exception& e) {
        LOG_CORE_ERROR("Error in input parser thread: {}", e.what());
        input_done_ = true;
        reports_cv_.notify_all();
    }
}

void Scanner::result_handler_thread() {
    std::cout << "[result_thread] Result handler thread started" << std::endl;
    const bool stream_mode = (config_.output_write_mode == "stream");
    auto last_flush = std::chrono::steady_clock::now();
    bool can_clear_checkpoint = true;
    std::unordered_map<uint64_t, ScanReport> pending_reports;
    pending_reports.reserve(std::max<size_t>(config_.max_work_count, size_t(1024)));
    uint64_t next_commit_seq = checkpoint_info_.processed_count + 1;

    // ==================== Lambda 函数定义（前置） ====================
    auto ensure_output_open = [&]() -> bool {
        if (!stream_mode || report_ofs_.is_open()) {
            return true;
        }

        std::error_code ec;
        fs::create_directories(config_.output_dir, ec);
        std::string out_path = config_.output_dir;
        if (!out_path.empty() && out_path.back() != '/') out_path += "/";
        const std::string fmt = normalize_output_format(config_.output_format);
        out_path += "scan_results." + output_extension_for(fmt, true);
        report_ofs_.open(out_path, std::ios::app);
        if (!report_ofs_.is_open()) {
            LOG_CORE_ERROR("Cannot open output file: {}", out_path);
            can_clear_checkpoint = false;
            return false;
        }
        if (!header_written_ && needs_text_header(fmt)) {
            report_ofs_ << "Scan Results\n";
            report_ofs_ << "============\n";
            header_written_ = true;
        }
        return true;
    };

    auto write_committed_reports = [&](const std::vector<ScanReport>& reports) -> bool {
        if (reports.empty()) return true;
        if (!stream_mode) return true;
        if (!ensure_output_open()) {
            return false;
        }

        const std::string fmt = normalize_output_format(config_.output_format);
        if (fmt == "json") {
            for (const auto& r : reports) {
                const std::string one = result_handler_->report_to_string(r);
                if (!one.empty()) {
                    report_ofs_ << one << '\n';
                }
            }
        } else if (fmt == "fingerprint") {
            // 每协议每行，扁平 JSONL，给 Python pipeline 用
            static std::atomic<uint64_t> fp_seq{0};
            for (const auto& r : reports) {
                for (const auto& pr : r.protocols) {
                    nlohmann::json j;
                    j["seq"] = fp_seq.fetch_add(1, std::memory_order_relaxed);
                    j["ip"] = r.target.get_ip_string();
                    j["port"] = pr.port;
                    j["protocol"] = pr.protocol;
                    j["banner"] = pr.attrs.banner;
                    j["time"] = std::chrono::system_clock::to_time_t(
                        std::chrono::system_clock::now());
                    report_ofs_ << j.dump() << '\n';
                }
            }
        } else {
            const std::string body = result_handler_->reports_to_string(reports);
            if (!body.empty()) {
                report_ofs_ << body;
            }
        }
        report_ofs_.flush();
        if (!report_ofs_) {
            LOG_CORE_ERROR("Failed to flush output stream for ordered result batch");
            can_clear_checkpoint = false;
            return false;
        }
        return true;
    };

    auto commit_ready_reports = [&]() {
        std::vector<ScanReport> committed_batch;
        while (true) {
            auto it = pending_reports.find(next_commit_seq);
            if (it == pending_reports.end()) {
                break;
            }
            committed_batch.push_back(std::move(it->second));
            pending_reports.erase(it);
            ++next_commit_seq;
        }

        if (committed_batch.empty()) {
            // 即使没有新结果可提交，也要刷新 checkpoint 时间戳
            if (progress_manager_) {
                auto now_time = std::chrono::system_clock::now();
                auto t = std::chrono::system_clock::to_time_t(now_time);
                std::ostringstream ss;
                ss << std::put_time(std::gmtime(&t), "%Y-%m-%d %H:%M:%S");
                checkpoint_info_.timestamp = ss.str();
                progress_manager_->save_checkpoint(checkpoint_info_);
            }
            return;
        }

        if (!write_committed_reports(committed_batch)) {
            for (auto& report : committed_batch) {
                pending_reports.emplace(report.target.seq, std::move(report));
            }
            return;
        }

        size_t committed_successes = 0;
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            for (const auto& r : committed_batch) {
                bool has_success = false;
                for (const auto& pr : r.protocols) {
                    if (pr.accessible) {
                        has_success = true;
                        protocol_success_counts_[pr.protocol]++;
                    }
                }
                if (has_success) {
                    ++committed_successes;
                }
            }
        }

        successful_ips_.fetch_add(committed_successes, std::memory_order_relaxed);
        processed_count_.store(next_commit_seq - 1, std::memory_order_relaxed);

        if (!stream_mode) {
            std::lock_guard<std::mutex> lock(reports_mutex_);
            completed_reports_.insert(
                completed_reports_.end(),
                std::make_move_iterator(committed_batch.begin()),
                std::make_move_iterator(committed_batch.end())
            );
        }

        const ScanReport& last_report = stream_mode ? committed_batch.back() : completed_reports_.back();
        checkpoint_info_.processed_count = processed_count_.load(std::memory_order_relaxed);
        checkpoint_info_.successful_count = successful_ips_.load(std::memory_order_relaxed);
        checkpoint_info_.input_file_hash = input_source_hash_;
        checkpoint_info_.input_file_offset = last_report.target.source_offset;
        checkpoint_info_.input_offset_ordinal = last_report.target.offset_ordinal;

        auto now_time = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now_time);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S");
        checkpoint_info_.timestamp = ss.str();

        if (progress_manager_ && !progress_manager_->save_checkpoint(checkpoint_info_)) {
            can_clear_checkpoint = false;
        }

        reports_cv_.notify_one();
    };
    
    // 处理一批扫描结果：厂商检测、统计更新、checkpoint保存
    // 注意：这个 lambda 同时用于流式和非流式模式
    auto process_batch = [&](std::vector<ScanReport>& batch) {
        if (batch.empty()) return;
        
        // Step 1: 厂商识别
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

        // Step 2: 按 seq 写入 pending，并推进连续提交前沿
        for (auto& r : batch) {
            pending_reports.insert_or_assign(r.target.seq, std::move(r));
        }
        commit_ready_reports();
    };

    // ==================== 主循环 ====================

    if (stream_mode) {
        // ========== 流式模式 ==========
        while (true) {
            bool should_stop = stop_.load();
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_flush);

            // 决定是否应该 flush：满足以下任一条件
            // 1. 收到停止信号
            // 2. 距离上次 flush 时间超过阈值
            // 3. 结果队列有数据
            static auto last_status = std::chrono::steady_clock::now();
            if (!should_stop && elapsed < config_.result_flush_interval && result_queue_.empty()) {
                auto since_status = std::chrono::duration_cast<std::chrono::seconds>(now - last_status).count();
                if (since_status >= 30) {
                    std::cout << "[result_thread] Waiting for results... idle="
                              << std::chrono::duration_cast<std::chrono::seconds>(elapsed).count()
                              << "s pending=" << pending_reports.size()
                              << " queue=" << result_queue_.size() << std::endl;
                    last_status = now;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            // Step 1: 从结果队列批量取出数据（限制批量大小）
            std::vector<ScanReport> batch;
            ScanReport rep;
            
            // 限制批量大小：避免一次性写入太多数据
            int max_batch = (config_.result_batch_size > 0) ? config_.result_batch_size : 1000;
            int count = 0;
            while (count < max_batch && result_queue_.try_pop(rep)) {
                batch.push_back(std::move(rep));
                count++;
            }

            // Step 2: 处理批次数据（厂商检测、按序提交、checkpoint）
            if (!batch.empty()) {
                process_batch(batch);
            }

            // Step 3: 更新 flush 时间
            last_flush = now;
            
            // Step 4: 检查退出条件：stop 信号已发出 且 队列已清空
            if (should_stop && result_queue_.empty() && batch.empty()) {
                LOG_CORE_DEBUG("[result_thread] Stream mode: stop signal with empty queue, exiting");
                break;
            }
        }
    } else {
        // ========== 非流式模式 ==========
        std::cout << "Warning: Non-stream mode may consume large memory for storing results." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        
        while (true) {
            bool should_stop = stop_.load();
            
            // 从结果队列批量取出数据
            std::vector<ScanReport> batch;
            ScanReport rep;
            while (result_queue_.try_pop(rep)) {
                batch.push_back(std::move(rep));
            }

            if (batch.empty()) {
                // 队列为空，检查是否应该停止
                if (should_stop) {
                    LOG_CORE_DEBUG("[result_thread] Non-stream mode: stop signal with empty batch, exiting");
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            // 处理一批数据
            process_batch(batch);
        }
    }

    if (!pending_reports.empty()) {
        LOG_CORE_WARN("Result handler exiting with {} uncommitted reports; checkpoint will be retained", pending_reports.size());
        can_clear_checkpoint = false;
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
        const std::string fmt = normalize_output_format(config_.output_format);
        if (needs_text_header(fmt)) {
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

        const std::string fmt = normalize_output_format(config_.output_format);
        const std::string ext = output_extension_for(fmt, false);

        std::string out_path = config_.output_dir;
        if (!out_path.empty() && out_path.back() != '/') out_path += "/";
        out_path += "scan_results." + ext;

        std::ofstream ofs(out_path);
        if (!ofs) {
            LOG_CORE_ERROR("Cannot open output file: {}", out_path);
            can_clear_checkpoint = false;
        } else {
            ofs << summary_output;
            if (!ofs) {
                LOG_CORE_ERROR("Failed while writing output file: {}", out_path);
                can_clear_checkpoint = false;
            }
            ofs.close();
            LOG_CORE_DEBUG("Results saved to {}", out_path);
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

    if (progress_manager_ && can_clear_checkpoint) {
        progress_manager_->clear_checkpoint();
    }

    LOG_CORE_DEBUG("Result handler thread finished");
}

void Scanner::scan_loop() {
    std::cout << "Scan loop started." << std::endl;
    auto io_exec = io_pool_->get_tracking_executor().underlying_executor();
    sessions_.reserve(std::min(config_.max_work_count, size_t(10000)));
    auto last_mem_log = std::chrono::steady_clock::now();

    auto estimate_quota = [this]() -> int {
        int max_concurrent = static_cast<int>(config_.max_work_count);
        if (max_concurrent <= 0) max_concurrent = 1000;
        int active = 0;
        for (const auto& s : sessions_) {
            if (s && !s->idle()) ++active;
        }
        return std::min(config_.batch_size, std::max(1, max_concurrent - active));
    };

    auto fetch_one_target = [this](ScanTarget& out) -> bool {
        std::lock_guard<SpinLock> lock(targets_lock_);
        if (targets_.empty()) return false;
        out = std::move(targets_.front());
        targets_.pop_front();
        return true;
    };

    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_mem_log).count() >= 10) {
            LOG_CORE_DEBUG("[scan_loop] sessions={} targets={} result_queue={}",
                sessions_.size(), targets_.size(), result_queue_.size());
            last_mem_log = now;
        }

        int quota = estimate_quota();
        int active_sessions = 0;
        int max_sessions = config_.max_work_count > 0
            ? static_cast<int>(config_.max_work_count) : std::max(1, config_.batch_size);

        // Step 1: iterate sessions, check completion + reuse
        for (auto& s : sessions_) {
            if (!s || s->idle()) continue;
            active_sessions++;

            if (s->ready_to_release()) {
                // Fetch ONE new target and reuse the session
                ScanTarget t;
                if (fetch_one_target(t)) {
                    s->reset(std::move(t),
                        config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable
                                               : ScanSession::ProbeMode::ProtocolDefaults,
                        protocols_);
                    int started = s->start_all_pending_probes(protocols_, io_exec, config_.probe_timeout, quota);
                    quota -= started;
                } else {
                    s->set_expected_tasks(0);
                    active_sessions--;
                }
            } else if (quota > 0) {
                int started = s->start_all_pending_probes(protocols_, io_exec, config_.probe_timeout, quota);
                quota -= started;
            }
            if (quota == 0) break;
        }

        // Step 2: create new sessions, one target at a time
        while (quota > 0 && active_sessions < max_sessions) {
            ScanTarget t;
            if (!fetch_one_target(t)) break;  // no more targets
            active_sessions++;
            auto sess = std::make_unique<ScanSession>(t,
                dns_resolver_ ? std::shared_ptr<IDnsResolver>(dns_resolver_.get(), [](IDnsResolver*){}) : nullptr,
                config_.dns_timeout, config_.probe_timeout,
                config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable
                                       : ScanSession::ProbeMode::ProtocolDefaults,
                protocols_, result_queue_);
            int started = sess->start_all_pending_probes(protocols_, io_exec, config_.probe_timeout, quota);
            quota -= started;
            sessions_.push_back(std::move(sess));
        }

        // Step 3: check exit condition
        if (input_done_ && targets_.empty() && active_sessions == 0) {
            LOG_CORE_DEBUG("Scan loop: all done, exiting");
            break;
        }

        std::this_thread::sleep_for(active_sessions > 0 ? std::chrono::milliseconds(3)
                                                        : std::chrono::milliseconds(10));
    }

    scan_done_ = true;
    reports_cv_.notify_all();
    LOG_CORE_INFO("Scan loop completed");
}


std::vector<ScanReport> Scanner::get_results(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(reports_mutex_);
    
    if (timeout.count() > 0) {
        reports_cv_.wait_for(lock, timeout, [this]() {
            return input_done_ && targets_.empty() && scan_done_.load();
        });
    } else if (timeout.count() == 0) {
        // 不等待，直接返回当前结果
    } else {
        // 无限等待
        reports_cv_.wait(lock, [this]() {
            return input_done_ && targets_.empty() && scan_done_.load();
        });
    }
    
    // 等待 result_thread_ 完成，确保所有结果已写入文件
    // 这样避免 result_thread_ 的周期性写入和最终写入冲突
    if (result_thread_.joinable()) {
        lock.unlock();  // 释放锁，避免死锁
        LOG_CORE_DEBUG("[get_results] Condition met, setting stop_=true to signal result_thread to exit. "
                      "input_done={}, targets_empty={}, scan_done={}", 
                      input_done_.load(), targets_.empty(), scan_done_.load());
        stop_ = true;  // 确保 result_handler_thread 退出
        result_thread_.join();
        lock.lock();   // 重新获取锁
    }
    
    return std::move(completed_reports_);
}

void Scanner::stop() {
    LOG_CORE_WARN("[Scanner::stop] Explicitly called, setting stop_=true");
    stop_ = true;
    reports_cv_.notify_all();
}

std::vector<ScanReport> Scanner::scan_domains(const std::vector<std::string>& domains) {
    // Synchronous scan — not used by --scan CLI, simplified stub
    for (const auto& d : domains) {
        ScanTarget t;
        t.domain = d;
        std::lock_guard<SpinLock> lock(targets_lock_);
        targets_.push_back(t);
    }
    input_done_ = true;
    
    auto io_exec = io_pool_->get_tracking_executor().underlying_executor();
    while (!targets_.empty()) {
        ScanTarget t;
        {
            std::lock_guard<SpinLock> lock(targets_lock_);
            if (targets_.empty()) break;
            t = std::move(targets_.front());
            targets_.pop_front();
        }
        auto resolver = dns_resolver_ 
            ? std::shared_ptr<IDnsResolver>(dns_resolver_.get(), [](IDnsResolver*){})
            : nullptr;
        auto session = std::make_unique<ScanSession>(
            t, resolver,
            config_.dns_timeout, config_.probe_timeout,
            config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable : ScanSession::ProbeMode::ProtocolDefaults,
            protocols_, result_queue_
        );
        session->start_all_pending_probes(protocols_, io_exec, config_.probe_timeout, 10);
        // Wait...
        for (int i = 0; i < 100 && !session->ready_to_release(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    std::vector<ScanReport> results;
    ScanReport r;
    while (result_queue_.try_pop(r)) {
        results.push_back(std::move(r));
    }
    return results;
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