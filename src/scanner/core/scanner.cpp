#include "scanner/core/scanner.h"
#include "scanner/dns/dns_resolver.h"
#include "scanner/common/logger.h"
#include "scanner/common/io_thread_pool.h"
#include "scanner/common/buffer_pool.h"
#include "scanner/core/resource_guard.h"
#include "scanner/protocols/protocol_all.h"
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

// protocol_registry_init.cpp 中定义，强制链接器保留所有协议 .o
void force_init_protocols();

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

    // 默认线程入口：本地文件I/O
    // start() 中根据 source_path/has_checkpoint 重新绑带参版本
    result_consumer_ = [this]() { result_handler_thread(); };
    
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
    metrics_server_.stop();
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
    force_init_protocols();  // 触发所有 REGISTER_PROTOCOL 静态注册
    for (auto& [name, enabled] : config_.protocol_enabled) {
        if (enabled) {
            auto proto = ProtocolFactory::create(name);
            if (proto) protocols_.push_back(std::move(proto));
        }
    }
}

bool Scanner::is_protocol_enabled(const std::string& name) const {
    auto it = config_.protocol_enabled.find(name);
    return it != config_.protocol_enabled.end() && it->second;
}

std::string Scanner::preprocess_zmap(const std::string& source_path) {
    if (!config_.enable_zmap_filter) return source_path;
    if (config_.zmap_port == 0) {
        std::cerr << "[zmap] zmap_port must be > 0 when enable_zmap_filter=true, skip filter" << std::endl;
        return source_path;
    }

    std::string out_dir = config_.output_dir;
    if (!out_dir.empty() && out_dir.back() != '/') out_dir += "/";
    std::string zmap_file = out_dir + "zmap_port" + std::to_string(config_.zmap_port) + ".txt";

    if (!fs::exists(zmap_file)) {
        std::string tmp_file = zmap_file + ".tmp";
        std::string cmd = "zmap -p " + std::to_string(config_.zmap_port)
                        + " -r 100000 -B 10M -o " + tmp_file
                        + " " + source_path + " 2>&1";
        std::cout << "[zmap] Running: " << cmd << std::endl;
        std::cout << "[zmap] Scanning 1.6B IPs at 100K pps ≈ 4.4 hours" << std::endl;
        int ret = std::system(cmd.c_str());
        if (ret != 0 || !fs::exists(tmp_file)) {
            std::cerr << "[zmap] zmap failed (exit " << ret << "), falling back to raw input" << std::endl;
            ::unlink(tmp_file.c_str());
            return source_path;
        }
        fs::rename(tmp_file, zmap_file);
        std::cout << "[zmap] Saved: " << zmap_file
                  << " (" << fs::file_size(zmap_file) / 1024 / 1024 << " MB)" << std::endl;
    }

    if (fs::exists(zmap_file)) {
        std::cout << "[zmap] Using filtered input: " << zmap_file << std::endl;
        return zmap_file;
    }
    return source_path;
}

void Scanner::set_input_producer(InputFunc fn)  { input_producer_ = std::move(fn); }
void Scanner::set_result_consumer(ResultFunc fn) { result_consumer_ = std::move(fn); }

void Scanner::push_targets_to_queue(ScanTarget t) {
    while (!stop_) {
        {
            std::lock_guard<SpinLock> lock(targets_lock_);
            if (targets_.size() < config_.targets_max_size) {
                targets_.push_back(std::move(t));
                return;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void Scanner::start(const std::string& source_path) {
    stop_ = false;
    input_done_ = false;
    scan_done_ = false;

    std::string actual_source = preprocess_zmap(source_path);
    input_source_path_ = actual_source;

    // 启动前安全检测：验证 max_work_count 不超过临时端口和可用内存的限制
    {
        size_t bind_ip_count = config_.bind_ips.empty() ? 1 : config_.bind_ips.size();
        auto limits = ResourceGuard::probe_limits(bind_ip_count);
        if (limits.ephemeral_ports > 0) {
            std::cout << "[guard] ephemeral ports: " << limits.ephemeral_ports
                      << " × " << bind_ip_count << " IP(s)"
                      << " → safe ≤ " << limits.max_safe_by_port << std::endl;
        }
        if (limits.avail_mem_mb > 0) {
            std::cout << "[guard] available memory: " << limits.avail_mem_mb
                      << " MB → safe ≤ " << limits.max_safe_by_mem << std::endl;
        }
        if (limits.conntrack_max > 0) {
            std::cout << "[guard] conntrack max: " << limits.conntrack_max
                      << " → safe ≤ " << limits.max_safe_by_conntrack << std::endl;
        }

        // 对外暴露 limits，方便外部脚本读取
        if (config_.max_work_count == 0) {
            // 自动计算：端口和内存约束取最严
            size_t safe = limits.max_safe_by_mem;
            if (limits.max_safe_by_port > 0) {
                safe = std::min(safe, limits.max_safe_by_port);
            }
            if (limits.max_safe_by_conntrack > 0) {
                safe = std::min(safe, limits.max_safe_by_conntrack);
            }
            if (safe == 0) {
                std::cerr << "FATAL: Cannot detect any system limits (ports/mem/conntrack). "
                          << "Refusing to start for safety. Set max_work_count explicitly." << std::endl;
                std::exit(1);
            }
            config_.max_work_count = safe;
            std::cout << "[guard] auto max_work_count=" << config_.max_work_count << std::endl;
        } else {
            // 显式配置值 → 做硬校验；超出上限则自动 cap（兼容 main.cpp 的 FD 级自动值）
            std::string err = ResourceGuard::validate(config_.max_work_count, bind_ip_count);
            if (!err.empty()) {
                std::cerr << "[guard] WARNING: " << err << std::endl;
                size_t safe = limits.max_safe_by_mem;
                if (limits.max_safe_by_port > 0) {
                    safe = std::min(safe, limits.max_safe_by_port);
                }
                if (limits.max_safe_by_conntrack > 0) {
                    safe = std::min(safe, limits.max_safe_by_conntrack);
                }
                if (safe == 0) {
                    std::cerr << "FATAL: Cannot detect any system limits to auto-cap. "
                              << "Refusing to start." << std::endl;
                    std::exit(1);
                }
                std::cerr << "[guard] Auto-capping to " << safe << std::endl;
                config_.max_work_count = safe;
            } else {
                std::cout << "[guard] max_work_count=" << config_.max_work_count << " passed safety check" << std::endl;
            }
        }
    }
    // 始终按 max_work_count 初始化缓冲池
    get_global_buffer_pool(std::max<size_t>(config_.max_work_count, 3000));
    
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

    // 厂商检测：硬编码禁用（存在 SEGV bug，暂不启用）
    // TODO: 修复 VendorDetector 并发安全后，可恢复 `if (config_.enable_vendor)` 分支
    vendor_detector_.reset();
    vendor_pattern_path_.clear();
    
    // 初始化进度管理器
    progress_manager_ = std::make_unique<ProgressManager>(actual_source, config_.output_dir);
    input_source_hash_ = ProgressManager::compute_file_hash(actual_source);

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

    // 校验：所有启用的协议都有对应的输出 formatter
    for (const auto& p : protocols_) {
        if (p && !result_handler_->has_protocol_formatter(p->name())) {
            std::cerr << "FATAL: No JSON formatter registered for protocol '"
                      << p->name() << "'. Add it to ResultHandler constructor." << std::endl;
            std::exit(1);
        }
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
            LOG_CORE_WARN("Checkpoint hash mismatch, ignoring stale checkpoint for {}", actual_source);
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
    
    // ===== preflight：配置合法性检查 =====
    if (!config_.bind_ips.empty()) {
        for (const auto& ip_str : config_.bind_ips) {
            boost::system::error_code ec;
            auto addr = asio::ip::make_address(ip_str, ec);
            if (ec) {
                std::cerr << "FATAL: bind_ip '" << ip_str << "' is not a valid IP address" << std::endl;
                input_done_ = true; scan_done_ = true;
                reports_cv_.notify_all();
                return;
            }
            // 直接尝试 bind 验证本机是否有此 IP
            asio::io_context tmp_ctx;
            asio::ip::tcp::socket sock(tmp_ctx);
            sock.open(asio::ip::tcp::v4(), ec);
            if (!ec) sock.bind(asio::ip::tcp::endpoint(addr, 0), ec);
            if (ec) {
                std::cerr << "FATAL: bind_ip '" << ip_str
                          << "' not available on this machine: " << ec.message() << std::endl;
                input_done_ = true; scan_done_ = true;
                reports_cv_.notify_all();
                return;
            }
            sock.close(ec);
        }
        LOG_CORE_INFO("[preflight] bind_ips validated: {} addresses", config_.bind_ips.size());
    }

    // 启动三个线程：生产者/消费者通过可注入回调执行
    //   本地模式 → 文件I/O（默认）
    //   分布式模式 → set_input_producer / set_result_consumer 替换
    if (!input_producer_) {
        input_producer_ = [this, actual_source, has_checkpoint]() {
            input_thread_func(actual_source, has_checkpoint);
        };
    }
    input_thread_ = std::thread([this]() { input_producer_(); });
    
    // 等待 input_thread 加载至少一批 targets 再启动 scan_loop
    // 大文件（如 22GB 纯 IP）首次读取需要时间，必须等待避免 scan_loop 创建 0 个 session
    // MCP 等自定义输入模式下跳过等待（target 按需到达）
    if (!actual_source.empty()) {
        const size_t min_targets = std::min<size_t>(config_.max_work_count, 100);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        int retries = 0;
        while (!input_done_ && !stop_) {
            {
                std::lock_guard<SpinLock> lock(targets_lock_);
                if (targets_.size() >= min_targets) break;
            }
            if (std::chrono::steady_clock::now() > deadline) {
                LOG_CORE_WARN("Timeout waiting for {} targets (have {}), starting anyway",
                              min_targets, targets_.size());
                break;
            }
            ++retries;
            std::this_thread::sleep_for(std::chrono::milliseconds(100 + std::min(retries, 20) * 50));
        }
    }
    std::cout << "Already have " << targets_.size() << " targets loaded, starting scan..." << std::endl;
    
    scan_thread_ = std::thread([this]() { scan_loop(); });
    result_thread_ = std::thread([this]() { result_consumer_(); });

    // 启动 metrics HTTP 服务 — 请求驱动采样，无专用轮询线程
    metrics_start_time_ = std::chrono::steady_clock::now();
    metrics_server_.start(config_.metrics_port);
    metrics_server_.set_snapshot_provider([this]() -> MetricsSnapshot {
        MetricsSnapshot snap;
        snap.targets_queue_size = targets_.size();
        snap.result_queue_size  = result_queue_.size();
        snap.pending_reports_size = pending_reports_count_.load();
        snap.io_pool_loads = io_pool_->io_loads();

        snap.total_sessions = sessions_.size();
        snap.active_sessions = static_cast<size_t>(
            active_session_count_.load(std::memory_order_relaxed));

        snap.processed_count  = processed_count_.load();
        snap.successful_count = successful_ips_.load();

        // 速率：基于实际时间间隔计算，避免波动
        auto now = std::chrono::steady_clock::now();
        uint64_t delta = snap.processed_count - metrics_last_processed_;
        double elapsed = std::chrono::duration<double>(now - metrics_last_sample_time_).count();
        if (elapsed > 0.5) {
            snap.targets_per_sec = static_cast<double>(delta) / elapsed;
        }
        metrics_last_processed_ = snap.processed_count;
        metrics_last_sample_time_ = now;

        snap.uptime_sec = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                now - metrics_start_time_).count());

        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            for (const auto& [name, count] : protocol_success_counts_) {
                snap.protocol_success_counts.emplace_back(name, count);
            }
        }
        return snap;
    });

    LOG_CORE_INFO("Scanner started with input source: {}", actual_source);
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

    uint64_t stalled_seq = 0;
    auto stall_since = std::chrono::steady_clock::now();
    static constexpr auto STALL_TIMEOUT = std::chrono::seconds(10);

    auto commit_ready_reports = [&]() {
        std::vector<ScanReport> committed_batch;
        while (true) {
            auto it = pending_reports.find(next_commit_seq);
            if (it == pending_reports.end()) {
                // 检测有序提交 stall：当前 seq 等太久就跳过（only_success 模式下失败不输出）
                auto now = std::chrono::steady_clock::now();
                if (stalled_seq != next_commit_seq) {
                    stalled_seq = next_commit_seq;
                    stall_since = now;
                } else if (now - stall_since > STALL_TIMEOUT) {
                    LOG_CORE_WARN("Skipping stalled seq {} after {}s wait (pending={})",
                        next_commit_seq,
                        std::chrono::duration_cast<std::chrono::seconds>(now - stall_since).count(),
                        pending_reports.size());
                    ++next_commit_seq;
                    stalled_seq = next_commit_seq;
                    stall_since = now;
                    continue;  // 尝试下一个 seq
                }
                break;
            }
            committed_batch.push_back(std::move(it->second));
            pending_reports.erase(it);
            ++next_commit_seq;
            stalled_seq = 0;  // reset stall tracker
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
        pending_reports_count_.store(pending_reports.size(), std::memory_order_relaxed);

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

        // Step 2: 按 seq 写入 pending（跳过已被 commit 前沿跨越的过期结果），并推进连续提交
        for (auto& r : batch) {
            if (r.target.seq < next_commit_seq) continue;  // 已被跳过，丢弃
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
            } else if (!pending_reports.empty()) {
                // 无新结果但有未提交的 pending，尝试推进 commit（检测 stall 跳过）
                commit_ready_reports();
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
                // 无新结果但有未提交的 pending，尝试推进 commit（检测 stall 跳过）
                if (!pending_reports.empty()) {
                    commit_ready_reports();
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
    // ===== 回调驱动架构：session 自己取 target + 重启，scan_loop 只负责等待 =====

    auto last_mem_log = std::chrono::steady_clock::now();

    // 计算 max_sessions
    int ports_per_session = 0;
    for (const auto& p : protocols_) {
        if (p) ports_per_session += static_cast<int>(p->default_ports().size());
    }
    if (ports_per_session == 0) ports_per_session = 1;
    int work_count = config_.max_work_count > 0
        ? static_cast<int>(config_.max_work_count) : std::max(1, config_.batch_size);
    int max_sessions = std::max(1, work_count / ports_per_session);
    sessions_.reserve(max_sessions);

    std::cout << "[scan_loop] ports_per_session=" << ports_per_session
              << " max_work=" << work_count << " max_sessions=" << max_sessions
              << " callback_driven" << std::endl;

    // 活跃 session 计数，用于检测扫描完成
    // session 完成回调：取新 target → 重启 probe
    // std::function 引用捕获支持递归——声明先于赋值，lambda 内通过引用调自己
    ScanSession::RestartFunc on_restart;
    on_restart = [this, &on_restart](ScanSession* s) {
        // is_last (session.cpp:fetch_add) 已保证本 session 只有最后一个
        // 完成的 probe 回调会进这里，不需要额外交替锁。

        if (stop_.load(std::memory_order_acquire)) {
            active_session_count_.fetch_sub(1, std::memory_order_relaxed);
            return;
        }

        ScanTarget t;
        {
            std::lock_guard<SpinLock> lock(targets_lock_);
            if (!targets_.empty()) {
                t = std::move(targets_.front());
                targets_.pop_front();
            }
        }
        if (t.ip_uint == 0 && t.domain.empty()) {
            if (input_done_) {
                active_session_count_.fetch_sub(1, std::memory_order_relaxed);
                return;
            }
            // 队列暂时空 → round-robin 选 context 重试
            int ctx = io_pool_->acquire_context();
            asio::post(io_pool_->executor_for(ctx),
                       [this, s, &on_restart, ctx, io_pool = io_pool_.get()]() {
                io_pool->release_context(ctx);
                on_restart(s);
            });
            return;
        }

        std::string bind_ip;
        if (!config_.bind_ips.empty()) {
            size_t idx = bind_ip_rr_.fetch_add(1, std::memory_order_relaxed) % config_.bind_ips.size();
            bind_ip = config_.bind_ips[idx];
        }

        s->reset(std::move(t),
            config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable
                                   : ScanSession::ProbeMode::ProtocolDefaults,
            protocols_);
        s->start_all_pending_probes(protocols_, io_pool_.get(),
            config_.probe_timeout, INT_MAX, bind_ip);
    };

    // 预创建全部 session + 立即启动
    for (int i = 0; i < max_sessions; ++i) {
        ScanTarget t;
        {
            std::lock_guard<SpinLock> lock(targets_lock_);
            if (targets_.empty()) break;
            t = std::move(targets_.front());
            targets_.pop_front();
        }
        std::string bind_ip;
        if (!config_.bind_ips.empty()) {
            size_t idx = bind_ip_rr_.fetch_add(1, std::memory_order_relaxed) % config_.bind_ips.size();
            bind_ip = config_.bind_ips[idx];
        }
        auto sess = std::make_unique<ScanSession>(t,
            dns_resolver_ ? std::shared_ptr<IDnsResolver>(dns_resolver_.get(), [](IDnsResolver*){}) : nullptr,
            config_.dns_timeout, config_.probe_timeout,
            config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable
                                   : ScanSession::ProbeMode::ProtocolDefaults,
            protocols_, result_queue_);
        sess->set_on_restart(on_restart);
        int launched = sess->start_all_pending_probes(protocols_,
            io_pool_.get(), config_.probe_timeout, INT_MAX, bind_ip);
        if (launched > 0) {
            active_session_count_.fetch_add(1, std::memory_order_relaxed);
            sessions_.push_back(std::move(sess));
        }
    }
    std::cout << "[scan_loop] Created " << sessions_.size()
              << " active sessions, callback-driven" << std::endl;

    // 等待 — probe 的回调链自己驱动 session 生命周期
    while (!stop_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // 懒创建：MCP 等按需模式 targets 在启动后才到达
        if (!input_done_ && static_cast<int>(sessions_.size()) < max_sessions) {
            ScanTarget t;
            {
                std::lock_guard<SpinLock> lock(targets_lock_);
                if (!targets_.empty()) {
                    t = std::move(targets_.front());
                    targets_.pop_front();
                }
            }
            if (t.ip_uint != 0 || !t.domain.empty()) {
                std::string bind_ip;
                if (!config_.bind_ips.empty()) {
                    size_t idx = bind_ip_rr_.fetch_add(1, std::memory_order_relaxed) % config_.bind_ips.size();
                    bind_ip = config_.bind_ips[idx];
                }
                auto sess = std::make_unique<ScanSession>(t,
                    dns_resolver_ ? std::shared_ptr<IDnsResolver>(dns_resolver_.get(), [](IDnsResolver*){}) : nullptr,
                    config_.dns_timeout, config_.probe_timeout,
                    config_.scan_all_ports ? ScanSession::ProbeMode::AllAvailable
                                           : ScanSession::ProbeMode::ProtocolDefaults,
                    protocols_, result_queue_);
                sess->set_on_restart(on_restart);
                int launched = sess->start_all_pending_probes(protocols_,
                    io_pool_.get(), config_.probe_timeout, INT_MAX, bind_ip);
                if (launched > 0) {
                    active_session_count_.fetch_add(1, std::memory_order_relaxed);
                    sessions_.push_back(std::move(sess));
                }
            }
        }

        // 定期日志
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_mem_log).count() >= 10) {
            LOG_CORE_DEBUG("[scan_loop] sessions={} targets={} active_session_count={}",
                sessions_.size(), targets_.size(), active_session_count_.load());
            last_mem_log = now;
        }

        if (input_done_ && active_session_count_.load(std::memory_order_acquire) == 0) {
            LOG_CORE_DEBUG("Scan loop: all done, exiting");
            break;
        }
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
        session->start_all_pending_probes(protocols_, io_pool_.get(), config_.probe_timeout, 10);
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