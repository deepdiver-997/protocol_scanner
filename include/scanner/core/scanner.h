#pragma once

#include "scanner/protocols/protocol_base.h"
#include "scanner/common/thread_pool.h"
#include "scanner/common/io_thread_pool.h"
#include "scanner/core/session.h"
#include "scanner/vendor/vendor_detector.h"
#include "scanner/output/result_handler.h"
#include <vector>
#include <memory>
#include <functional>
#include <fstream>
#include <thread>
#include <chrono>
#include <boost/asio.hpp>

namespace scanner {

using boost::asio::io_context;
namespace asio = boost::asio;

// =====================
// 扫描器配置
// =====================

struct ScannerConfig {
    // 线程池配置
    int io_thread_count = 4;         // IO 线程数（网络 I/O，建议设置为 CPU 核心数 × 1.5）
    int cpu_thread_count = 2;         // CPU 线程数（协议解析等轻量任务，建议 2-4）
    
    // 兼容旧配置（如果未设置 io/cpu 线程数，则使用 thread_count）
    int thread_count = 4;              // 废弃：保留向后兼容
    
    int batch_size = 10000;           // 批处理大小
    size_t targets_max_size = 1000000; // 最大待处理目标数（默认 100 万）
    std::chrono::milliseconds dns_timeout = std::chrono::milliseconds(5000);  // DNS 超时
    std::chrono::milliseconds probe_timeout = std::chrono::milliseconds(60000); // 探测超时
    int retry_count = 1;               // 重试次数
    bool scan_all_ports = false;    // 扫描所有端口
    bool enable_smtp = true;          // 启用 SMTP
    bool enable_pop3 = true;          // 启用 POP3
    bool enable_imap = true;          // 启用 IMAP
    bool enable_http = false;          // 启用 HTTP
    bool enable_ftp = false;           // 启用 FTP
    bool enable_telnet = false;        // 启用 Telnet
    bool enable_ssh = false;           // 启用 SSH
    bool enable_vendor = true;         // 启用厂商识别
    std::string output_dir = "./result"; // 输出目录
    std::string output_format = "text";  // 输出格式
    bool only_success = false;        // 是否仅输出成功的结果
    std::vector<std::string> custom_protocols; // 自定义协议列表
    std::chrono::milliseconds result_flush_interval = std::chrono::milliseconds(5000); // 结果写入间隔
};

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

    ScannerConfig config_;
    std::vector<std::unique_ptr<IProtocol>> protocols_;
    std::unique_ptr<class IDnsResolver> dns_resolver_;
    std::unique_ptr<class VendorDetector> vendor_detector_;
    std::unique_ptr<class ResultHandler> result_handler_;

    std::shared_ptr<ThreadPool> scan_pool_;
    std::shared_ptr<IoThreadPool> io_pool_;

    BlockingQueue<ScanReport> result_queue_;
    std::vector<ScanTarget> targets_;
    std::mutex targets_mutex_;
    std::condition_variable targets_cv_;
    std::vector<std::unique_ptr<ScanSession>> sessions_;

    std::atomic<bool> stop_{false};
    std::atomic<bool> input_done_{false};
    std::ofstream report_ofs_;

    std::thread input_thread_;
    std::thread result_thread_;
    std::thread scan_thread_;

    std::vector<ScanReport> completed_reports_;
    std::mutex reports_mutex_;
    std::condition_variable reports_cv_;
};

// =====================
// 扫描器工具函数
// =====================

// 从文件加载域名列表
std::vector<std::string> load_domains(const std::string& filename, size_t offset = 0);

// 检查是否是有效的 IP 地址
bool is_valid_ip_address(const std::string& s);

// 从文件加载目标列表
std::vector<ScanTarget> load_targets(const std::string& filename);

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

// 导出 JSON 格式
std::string report_to_json(const ScanReport& report);
std::string reports_to_json(const std::vector<ScanReport>& reports);

} // namespace scanner
