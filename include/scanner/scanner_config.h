#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstddef>

namespace scanner {

// =====================
// 扫描器配置
// =====================

struct ScannerConfig {
    // Scanner 配置
    int io_thread_count = 4;         // IO 线程数（网络 I/O，建议设置为 CPU 核心数 × 1.5）
    int thread_count = 4;            // 废弃：保留向后兼容
    int batch_size = 100;            // 扫描任务配额：每轮循环最多启动的任务数
    int result_batch_size = 50;      // 结果写入批量：每次写入磁盘的最大结果数（0 表示不限制）
    size_t targets_max_size = 100000; // 最大待处理目标数（默认 10 万）
    size_t result_queue_max_size = 5000; // 结果队列上限，防止内存膨胀（0 表示不限制）
    std::chrono::milliseconds dns_timeout = std::chrono::milliseconds(1000);
    std::chrono::milliseconds probe_timeout = std::chrono::milliseconds(2000);
    int retry_count = 1;
    std::chrono::milliseconds result_flush_interval = std::chrono::milliseconds(5000);
    std::string output_write_mode = "stream";
    bool only_success = false;
    size_t max_work_count = 0;

    // Protocol 配置
    bool enable_smtp = false;
    bool enable_pop3 = false;
    bool enable_imap = false;
    bool enable_http = true;
    bool enable_ftp = true;
    bool enable_telnet = false;
    bool enable_ssh = true;
    bool enable_redis = false;
    bool enable_rtsp = false;
    bool enable_sip = false;
    bool enable_mysql = false;
    bool scan_all_ports = false;

    // DNS 配置
    std::string dns_resolver_type = "cares";
    int dns_max_mx_records = 16;
    std::chrono::milliseconds dns_config_timeout = std::chrono::milliseconds(5000);

    // Checkpoint 配置
    std::chrono::milliseconds checkpoint_interval = std::chrono::milliseconds(10000);

    // Output 配置
    std::vector<std::string> output_formats;
    std::string output_dir = "./result";
    bool output_enable_json = true;
    bool output_enable_csv = true;
    bool output_enable_report = false;
    bool output_to_console = false;
    std::string output_format = "required_format";

    // Diagnostics / recovery
    bool enable_crash_inspection = true;

    // Logging 配置
    std::string logging_level = "INFO";
    bool logging_console_enabled = false;
    bool logging_file_enabled = false;
    std::string logging_file_path = "./scanner.log";

    // Vendor 配置
    bool enable_vendor = true;
    std::string vendor_pattern_file = "./config/vendors.json";
    double vendor_similarity_threshold = 0.7;

    // 其他
    std::vector<std::string> custom_protocols;
};

} // namespace scanner