#include "scanner/vendor/vendor_detector.h"
#include "scanner/common/logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace scanner {

// =====================
// VendorDetector 实现
// =====================

bool VendorDetector::load_patterns(const std::string& filename) {
    std::ifstream ifs(filename);
    if (!ifs.is_open()) {
        LOG_CORE_ERROR("Failed to open vendor pattern file: {}", filename);
        return false;
    }

    try {
        nlohmann::json j = nlohmann::json::parse(ifs);
        ifs.close();

        if (!j.contains("vendors")) {
            LOG_CORE_ERROR("Invalid vendor file: missing 'vendors' array");
            return false;
        }

        for (const auto& v : j["vendors"]) {
            VendorPattern pattern;
            pattern.id = v["id"].get<int>();
            pattern.name = v["name"].get<std::string>();
            pattern.pattern = v["pattern"].get<std::string>();
            if (v.contains("matched_ids")) {
                pattern.matched_ids = v["matched_ids"].get<std::vector<int>>();
            }

            patterns_[pattern.id] = pattern;
            id_to_name_[pattern.id] = pattern.name;
            match_counts_[pattern.id] = 0;
        }

        LOG_CORE_INFO("Loaded {} vendor patterns from {}", patterns_.size(), filename);

        return compile_patterns();
    } catch (const nlohmann::json::exception& e) {
        LOG_CORE_ERROR("Failed to parse vendor file '{}': {}", filename, e.what());
        return false;
    }
}

bool VendorDetector::compile_patterns() {
    for (auto& [id, pattern] : patterns_) {
        try {
            compiled_patterns_[id] = std::regex(pattern.pattern);
        } catch (const std::regex_error& e) {
            LOG_CORE_WARN("Failed to compile regex for vendor {} ({}): {}",
                pattern.name, pattern.pattern, e.what());
            return false;
        }
    }
    return true;
}

int VendorDetector::detect_vendor(const std::string& banner) const {
    for (const auto& [id, pattern] : patterns_) {
        auto it = compiled_patterns_.find(id);
        if (it != compiled_patterns_.end()) {
            if (std::regex_search(banner, it->second)) {
                return id;
            }
        }
    }
    return 0; // No match
}

std::string VendorDetector::get_vendor_name(int vendor_id) const {
    auto it = id_to_name_.find(vendor_id);
    return it != id_to_name_.end() ? it->second : "Unknown";
}

void VendorDetector::update_matched_ids(int vendor_id, int server_id) {
    auto it = patterns_.find(vendor_id);
    if (it != patterns_.end()) {
        auto& ids = it->second.matched_ids;
        if (std::find(ids.begin(), ids.end(), server_id) == ids.end()) {
            ids.push_back(server_id);
        }
        match_counts_[vendor_id]++;
    }
}

std::vector<VendorStats> VendorDetector::get_statistics() const {
    std::vector<VendorStats> stats;
    for (const auto& [id, pattern] : patterns_) {
        VendorStats s;
        s.id = id;
        s.name = pattern.name;
        s.count = match_counts_.count(id) ? match_counts_.at(id) : 0;
        stats.push_back(s);
    }
    // Sort by count descending
    std::sort(stats.begin(), stats.end(),
        [](const VendorStats& a, const VendorStats& b) { return a.count > b.count; });
    return stats;
}

bool VendorDetector::save_patterns(const std::string& filename) const {
    nlohmann::json j;
    j["vendors"] = nlohmann::json::array();

    for (const auto& [id, pattern] : patterns_) {
        nlohmann::json vendor;
        vendor["id"] = id;
        vendor["name"] = pattern.name;
        vendor["pattern"] = pattern.pattern;
        vendor["matched_ids"] = pattern.matched_ids;
        j["vendors"].push_back(vendor);
    }

    std::ofstream ofs(filename);
    if (!ofs.is_open()) {
        LOG_CORE_ERROR("Failed to open vendor file for writing: {}", filename);
        return false;
    }

    ofs << j.dump(2);
    ofs.close();
    LOG_CORE_INFO("Saved {} vendor patterns to {}", patterns_.size(), filename);
    return true;
}

void VendorDetector::add_pattern(const VendorPattern& pattern) {
    patterns_[pattern.id] = pattern;
    id_to_name_[pattern.id] = pattern.name;
    match_counts_[pattern.id] = 0;
    try {
        compiled_patterns_[pattern.id] = std::regex(pattern.pattern);
    } catch (const std::regex_error& e) {
        LOG_CORE_WARN("Failed to compile regex for new pattern: {}", e.what());
    }
}

std::vector<std::pair<int, double>> VendorDetector::find_similar(
    const std::string& message,
    double threshold
) const {
    std::vector<std::pair<int, double>> results;

    for (const auto& [id, pattern] : patterns_) {
        double sim = similarity(message, pattern.pattern);
        if (sim >= threshold) {
            results.emplace_back(id, sim);
        }
    }

    std::sort(results.begin(), results.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    return results;
}

// 计算编辑距离
double VendorDetector::similarity(const std::string& s1, const std::string& s2) const {
    size_t len1 = s1.size();
    size_t len2 = s2.size();

    std::vector<std::vector<size_t>> dp(len1 + 1, std::vector<size_t>(len2 + 1));

    for (size_t i = 0; i <= len1; ++i) dp[i][0] = i;
    for (size_t j = 0; j <= len2; ++j) dp[0][j] = j;

    for (size_t i = 1; i <= len1; ++i) {
        for (size_t j = 1; j <= len2; ++j) {
            if (s1[i-1] == s2[j-1]) {
                dp[i][j] = dp[i-1][j-1];
            } else {
                dp[i][j] = std::min({dp[i-1][j], dp[i][j-1], dp[i-1][j-1]}) + 1;
            }
        }
    }

    size_t max_len = std::max(len1, len2);
    return max_len > 0 ? 1.0 - static_cast<double>(dp[len1][len2]) / max_len : 1.0;
}

// =====================
// 工具函数
// =====================

std::string extract_banner_key(const std::string& banner) {
    std::string result;
    for (char c : banner) {
        if (std::isalpha(c) || std::isdigit(c) || c == ' ' || c == '-') {
            result += c;
        } else if (c == '\r' || c == '\n') {
            break;
        }
    }
    return result;
}

std::string normalize_banner(const std::string& banner) {
    std::string normalized;
    for (char c : banner) {
        if (std::isalpha(c)) {
            normalized += std::tolower(c);
        } else if (std::isdigit(c) || c == ' ' || c == '-') {
            normalized += c;
        }
    }
    return normalized;
}

bool is_error_message(const std::string& message) {
    return message.find("4") == 0 || message.find("5") == 0 ||
           message.find("ERROR") != std::string::npos ||
           message.find("FAIL") != std::string::npos;
}

std::string extract_domain_from_banner(const std::string& banner) {
    size_t pos = banner.find('@');
    if (pos != std::string::npos) {
        size_t end = banner.find_first_of(" \r\n", pos);
        if (end != std::string::npos) {
            return banner.substr(pos + 1, end - pos - 1);
        } else {
            return banner.substr(pos + 1);
        }
    }
    return "";
}

} // namespace scanner
