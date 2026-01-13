#pragma once

#include "../protocols/protocol_base.h"
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace scanner {

// =====================
// 输出格式枚举
// =====================

enum class OutputFormat {
    JSON,       // JSON 格式
    CSV,        // CSV 格式
    TEXT,       // 人类可读文本
    REPORT      // 详细报告
};

// =====================
// 结果处理器
// =====================

class ResultHandler {
public:
    ResultHandler() = default;
    ~ResultHandler() = default;

    // 设置输出格式
    void set_format(OutputFormat format) { format_ = format; }

    // 设置是否仅输出成功结果
    void set_only_success(bool only) { only_success_ = only; }

    // 保存单个报告
    void save_report(const ScanReport& report, const std::string& filename);

    // 保存多个报告
    void save_reports(
        const std::vector<ScanReport>& reports,
        const std::string& filename
    );

    // 导出到字符串
    std::string report_to_string(const ScanReport& report) const;
    std::string reports_to_string(const std::vector<ScanReport>& reports) const;

    // 输出到控制台
    void print_report(const ScanReport& report) const;
    void print_summary(const std::vector<ScanReport>& reports) const;

private:
    // JSON 格式化
    std::string to_json(const ScanReport& report) const;
    std::string to_json(const std::vector<ScanReport>& reports) const;

    // CSV 格式化
    std::string to_csv(const ScanReport& report) const;
    std::string to_csv(const std::vector<ScanReport>& reports) const;

    // 文本格式化
    std::string to_text(const ScanReport& report) const;

    // 报告格式化
    std::string to_report(const ScanReport& report) const;

    // 格式化协议属性
    std::string format_attributes(const ProtocolAttributes& attrs) const;

    // 格式化端口位掩码
    std::string format_port_mask(uint8_t mask) const;

    OutputFormat format_ = OutputFormat::TEXT;
    bool only_success_ = false;
};

// =====================
// 报告生成器
// =====================

class ReportGenerator {
public:
    ReportGenerator() = default;

    // 生成摘要报告
    std::string generate_summary(
        const std::vector<ScanReport>& reports
    ) const;

    // 生成统计报告
    std::string generate_statistics(
        const std::vector<ScanReport>& reports
    ) const;

    // 生成对比报告
    std::string generate_comparison(
        const std::vector<ScanReport>& old_reports,
        const std::vector<ScanReport>& new_reports
    ) const;

    // 生成 HTML 报告
    std::string generate_html(
        const std::vector<ScanReport>& reports
    ) const;

private:
    // 统计信息
    struct Statistics {
        int total_domains = 0;
        int total_protocols = 0;
        std::unordered_map<std::string, int> protocol_counts;
        std::unordered_map<std::string, int> vendor_counts;
        std::unordered_map<std::string, int> port_counts;
        double total_time_ms = 0.0;
    };

    Statistics calculate_statistics(
        const std::vector<ScanReport>& reports
    ) const;
};

} // namespace scanner
