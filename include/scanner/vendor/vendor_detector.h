#pragma once

#include "../protocols/protocol_base.h"
#include <unordered_map>
#include <regex>
#include <vector>

namespace scanner {

// =====================
// 服务商标识配置
// =====================

struct VendorPattern {
    int id;                      // 服务商 ID
    std::string name;             // 服务商名称
    std::string pattern;          // 正则表达式模式
    std::vector<int> matched_ids;  // 匹配的服务器 ID 列表
};

struct VendorStats {
    int id;
    std::string name;
    int count;                   // 匹配数量
};

// =====================
// 服务商检测器
// =====================

class VendorDetector {
public:
    VendorDetector() = default;
    ~VendorDetector() = default;

    // 加载服务商模式
    bool load_patterns(const std::string& filename);

    // 从欢迎消息检测服务商
    int detect_vendor(const std::string& banner) const;

    // 获取服务商名称
    std::string get_vendor_name(int vendor_id) const;

    // 更新匹配的服务器 ID
    void update_matched_ids(int vendor_id, int server_id);

    // 获取统计信息
    std::vector<VendorStats> get_statistics() const;

    // 保存更新后的模式文件
    bool save_patterns(const std::string& filename) const;

    // 添加新模式
    void add_pattern(const VendorPattern& pattern);

    // 查找相似消息
    std::vector<std::pair<int, double>> find_similar(
        const std::string& message,
        double threshold = 0.7
    ) const;

private:
    // 计算字符串相似度（编辑距离）
    double similarity(const std::string& s1, const std::string& s2) const;

    // 编译正则表达式
    bool compile_patterns();

    std::unordered_map<int, VendorPattern> patterns_;
    std::unordered_map<int, std::string> id_to_name_;
    std::unordered_map<int, int> match_counts_;
    std::unordered_map<int, std::regex> compiled_patterns_;
};

// =====================
// 服务商工具函数
// =====================

// 提取欢迎消息中的关键信息
std::string extract_banner_key(const std::string& banner);

// 标准化欢迎消息（去除时间戳、ID 等）
std::string normalize_banner(const std::string& banner);

// 检查是否为错误消息
bool is_error_message(const std::string& message);

// 从欢迎消息提取域名
std::string extract_domain_from_banner(const std::string& banner);

} // namespace scanner
