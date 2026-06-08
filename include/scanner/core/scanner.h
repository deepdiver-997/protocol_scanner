#pragma once

#include "scanner/protocols/protocol_base.h"
#include "scanner/common/spin_lock.h"
#include "scanner/common/thread_pool.h"
#include "scanner/metrics/metrics_server.h"
#include "scanner/common/io_thread_pool.h"
#include "scanner/core/session.h"
#include "scanner/core/progress_manager.h"
#include "scanner/vendor/vendor_detector.h"
#include "scanner/output/result_handler.h"
#include <deque>
#include <vector>
#include <memory>
#include <functional>
#include <fstream>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <boost/asio.hpp>

#include "scanner/scanner_config.h"
namespace scanner {

using boost::asio::io_context;
namespace asio = boost::asio;



// =====================
// 扫描器进度回调
// =====================

struct ProgressInfo {
    int total;          // 总数
    int completed;      // 已完成
    int failed;         // 失败数
    std::string current_domain; // 当前处理域名
};

// =====================
// 扫描器核心类
// =====================

class Scanner {
public:
    explicit Scanner(const ScannerConfig& config);
    ~Scanner();

    // 启动扫描，异步模式
    void start(const std::string& source_path);

    // 获取扫描结果（阻塞，直到扫描完成或超时）
    std::vector<ScanReport> get_results(std::chrono::milliseconds timeout = std::chrono::milliseconds(-1));

    // 停止扫描
    void stop();

    // 扫描单个目标（同步）
    ScanReport scan_target(const ScanTarget& target);

    // 批量扫描（同步）
    std::vector<ScanReport> scan_targets(
        const std::vector<ScanTarget>& targets
    );

    // 从域名列表扫描（同步，保留向后兼容）
    std::vector<ScanReport> scan_domains(
        const std::vector<std::string>& domains
    );

    // 获取配置
    const ScannerConfig& config() const { return config_; }

    // 获取统计信息
    struct ScanStatistics {
        size_t total_targets = 0;           // 总目标数
        size_t successful_ips = 0;          // 成功探测的 IP 数
        std::unordered_map<std::string, size_t> protocol_counts; // 各协议成功数
        std::chrono::milliseconds total_time{0}; // 总耗时
    };
    ScanStatistics get_statistics() const;

private:
    // 初始化协议
    void init_protocols();

    // 查询 DNS
    bool resolve_dns(ScanTarget& target);

    // 查询 MX 记录
    bool query_mx_records(ScanTarget& target);

    // 扫描目标的所有协议
    void scan_protocols(ScanReport& report);

    // 检查协议是否启用
    bool is_protocol_enabled(const std::string& name) const;

    // 结果处理线程
    void result_handler_thread();

    // 主扫描循环
    void scan_loop();

    // 输入线程函数
    void input_thread_func(const std::string& source_path, bool has_checkpoint);

    ScannerConfig config_;
    std::vector<std::unique_ptr<IProtocol>> protocols_;
    std::unique_ptr<class IDnsResolver> dns_resolver_;
    std::unique_ptr<class VendorDetector> vendor_detector_;
    std::unique_ptr<class ResultHandler> result_handler_;

    // 记录解析后的厂商模式文件路径，便于结果线程保存
    std::string vendor_pattern_path_;

    std::shared_ptr<IoThreadPool> io_pool_;

    // 已完成报告
    BlockingQueue<ScanReport> result_queue_;
    std::mutex reports_mutex_;
    std::condition_variable reports_cv_;
    std::vector<ScanReport> completed_reports_;

    std::deque<ScanTarget> targets_;  // FIFO: push_back + pop_front for in-order processing
    SpinLock targets_lock_;
    std::vector<std::unique_ptr<ScanSession>> sessions_;

    // 扫描状态
    std::atomic<bool> stop_{false};
    std::atomic<bool> input_done_{false};
    std::atomic<bool> scan_done_{false};
    std::ofstream report_ofs_;
    bool header_written_{false};

    std::thread input_thread_;
    std::thread result_thread_;
    std::thread scan_thread_;

    // metrics
    MetricsServer metrics_server_;
    std::unique_ptr<std::thread> metrics_thread_;
    std::chrono::steady_clock::time_point metrics_start_time_;
    uint64_t metrics_last_processed_{0};
    std::atomic<size_t> pending_reports_count_{0};  // updated by result_handler

    // 统计信息
    std::atomic<size_t> total_targets_{0};
    std::atomic<size_t> successful_ips_{0};
    std::unordered_map<std::string, size_t> protocol_success_counts_;
    mutable std::mutex stats_mutex_;

    // 计时器
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point end_time_;
    std::atomic<bool> timing_started_{false};
    
    // 进度管理
    std::unique_ptr<ProgressManager> progress_manager_;
    std::string input_source_path_;
    std::string input_source_hash_;
    std::atomic<size_t> processed_count_{0};  // 已处理（完成扫描）的目标数
    std::atomic<size_t> bind_ip_rr_{0};       // round-robin index for bind_ips
    CheckpointInfo checkpoint_info_;
};

// =====================
// 扫描器工具函数
// =====================

// 从文件加载域名列表
std::vector<std::string> load_domains(const std::string& filename, size_t offset = 0);

// 以流式方式处理域名列表，回调返回 false 时提前终止
size_t stream_domains(
    const std::string& path,
    size_t offset,
    const std::function<bool(const std::string&)>& handle_target
);

// 以流式方式处理域名列表（带输入文件偏移），回调返回 false 时提前终止
size_t stream_domains_with_offset(
    const std::string& path,
    size_t file_offset,
    const std::function<bool(const std::string&, size_t)>& handle_target
);

// 检查是否是有效的 IP 地址
bool is_valid_ip_address(const std::string& s);

// 保存报告到文件
void save_report(const ScanReport& report, const std::string& filename);
void save_reports(
    const std::vector<ScanReport>& reports,
    const std::string& filename
);
void save_reports(
    const std::vector<ScanReport>& reports,
    std::ofstream& ofs
);

// 构建汇总输出（含结果、厂商、统计）
std::string build_summary_output(
    const class ResultHandler* handler,
    const std::vector<ScanReport>& reports,
    const Scanner::ScanStatistics& stats,
    const class VendorDetector* vendor_detector
);

// 构建仅统计块（无单条结果）
std::string build_stats_block(const Scanner::ScanStatistics& stats);

// 写出厂商统计到独立文件
void write_vendor_stats_file(const class VendorDetector* vendor_detector, const std::string& output_dir);

// 导出 JSON 格式
std::string report_to_json(const ScanReport& report);
std::string reports_to_json(const std::vector<ScanReport>& reports);

} // namespace scanner
