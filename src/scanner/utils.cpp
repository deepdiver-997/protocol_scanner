#include "scanner/core/scanner.h"
#include "scanner/common/logger.h"
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <boost/asio/ip/address_v4.hpp>
#include <sstream>
#include <cmath>

namespace scanner {

namespace fs = std::filesystem;

// 辅助函数：检查是否是有效的 IP 地址（供内部使用）
static bool is_valid_ip_internal(const std::string& s) {
    try {
        auto addr = boost::asio::ip::make_address_v4(s);
        (void)addr;
        return true;
    } catch (...) {
        return false;
    }
}

static inline std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// 辅助函数：将 CIDR 记号扩展为单个 IP（如 192.168.1.0/24）
static std::vector<std::string> expand_cidr(const std::string& cidr_str) {
    std::vector<std::string> ips;
    try {
        std::string cidr_trimmed = trim(cidr_str);
        size_t slash_pos = cidr_trimmed.find('/');
        if (slash_pos == std::string::npos) {
            // 没有 /，尝试作为单个 IP 返回
            if (is_valid_ip_internal(cidr_trimmed)) {
                ips.push_back(cidr_trimmed);
            }
            return ips;
        }

        std::string ip_part = cidr_trimmed.substr(0, slash_pos);
        std::string prefix_part = cidr_trimmed.substr(slash_pos + 1);

        auto base_addr = boost::asio::ip::make_address_v4(trim(ip_part));
        int prefix_len = std::stoi(prefix_part);

        if (prefix_len < 0 || prefix_len > 32) {
            LOG_CORE_ERROR("Invalid CIDR prefix length: {}", prefix_len);
            return ips;
        }

        // 计算网络地址的主机位数
        int host_bits = 32 - prefix_len;
        uint32_t host_mask = (1UL << host_bits) - 1;  // 主机位掩码
        uint32_t base_uint = base_addr.to_uint();

        // 计算网络起始和结束地址
        uint32_t network_addr = base_uint & ~host_mask;
        uint32_t broadcast_addr = network_addr | host_mask;

        // 限制最大扩展数量，防止内存爆炸
        const uint32_t MAX_EXPANSION = 1048576; 
        uint32_t count = broadcast_addr - network_addr + 1;
        
        if (count > MAX_EXPANSION) {
            LOG_CORE_WARN("CIDR block {} too large ({} IPs), only expanding first {}", 
                          cidr_trimmed, count, MAX_EXPANSION);
            broadcast_addr = network_addr + MAX_EXPANSION - 1;
        }

        for (uint32_t i = network_addr; i <= broadcast_addr; ++i) {
            ips.push_back(boost::asio::ip::make_address_v4(i).to_string());
        }
    } catch (const std::exception& e) {
        LOG_CORE_ERROR("Failed to expand CIDR {}: {}", cidr_str, e.what());
    }
    return ips;
}

// 辅助函数：将 IP 段扩展为单个 IP
static std::vector<std::string> expand_ip_range(const std::string& start_ip_str, const std::string& end_ip_str) {
    std::vector<std::string> ips;
    try {
        auto start_addr = boost::asio::ip::make_address_v4(trim(start_ip_str));
        auto end_addr = boost::asio::ip::make_address_v4(trim(end_ip_str));
        
        uint32_t start_uint = start_addr.to_uint();
        uint32_t end_uint = end_addr.to_uint();
        
        if (start_uint > end_uint) std::swap(start_uint, end_uint);
        
        // 限制最大扩展数量，防止内存爆炸（例如 100万）
        const uint32_t MAX_EXPANSION = 1048576; 
        if (end_uint - start_uint > MAX_EXPANSION) {
            LOG_CORE_WARN("IP range too large: {}-{}, only expanding first {}", start_ip_str, end_ip_str, MAX_EXPANSION);
            end_uint = start_uint + MAX_EXPANSION;
        }

        for (uint32_t i = start_uint; i <= end_uint; ++i) {
            ips.push_back(boost::asio::ip::make_address_v4(i).to_string());
        }
    } catch (const std::exception& e) {
        LOG_CORE_ERROR("Failed to expand IP range {}-{}: {}", start_ip_str, end_ip_str, e.what());
    }
    return ips;
}

// 处理单个文件，尝试识别 CSV 格式（IP 段）
static std::vector<std::string> process_file(const std::string& filename) {
    std::vector<std::string> result;
    std::ifstream in(filename);
    if (!in) {
        LOG_FILE_IO_ERROR("Failed to open file: {}", filename);
        return result;
    }

    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        // 检查是否为 CIDR 记号（IP/PREFIX）
        if (line.find('/') != std::string::npos) {
            auto ips = expand_cidr(line);
            result.insert(result.end(), ips.begin(), ips.end());
            continue;
        }
        
        // 尝试判断是否为 IP 段 CSV (start_ip,end_ip,...)
        if (line.find(',') != std::string::npos) {
            std::stringstream ss(line);
            std::string start_ip, end_ip;
            if (std::getline(ss, start_ip, ',') && std::getline(ss, end_ip, ',')) {
                // 如果前两部分看起来像 IP，则进行扩展
                auto ips = expand_ip_range(start_ip, end_ip);
                result.insert(result.end(), ips.begin(), ips.end());
                continue;
            }
        }
        
        // 普通域名或 IP
        result.push_back(line);
    }
    return result;
}

std::vector<std::string> load_domains(const std::string& path, size_t offset) {
    std::vector<std::string> all_targets;
    
    try {
        if (fs::is_directory(path)) {
            LOG_FILE_IO_INFO("Loading targets from directory: {}", path);
            for (const auto& entry : fs::recursive_directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    auto targets = process_file(entry.path().string());
                    all_targets.insert(all_targets.end(), targets.begin(), targets.end());
                }
            }
        } else if (fs::is_regular_file(path)) {
            all_targets = process_file(path);
        } else {
            LOG_FILE_IO_ERROR("Path not found or invalid: {}", path);
        }
    } catch (const std::exception& e) {
        LOG_CORE_CRITICAL("Error during loading targets from {}: {}", path, e.what());
    }

    if (offset > 0 && offset < all_targets.size()) {
        all_targets.erase(all_targets.begin(), all_targets.begin() + offset);
    }

    LOG_FILE_IO_INFO("Total loaded {} targets from {}", all_targets.size(), path);
    return all_targets;
}

bool is_valid_ip_address(const std::string& s) {
    std::string trimmed = trim(s);
    
    // 检查是否为 CIDR 记号
    if (trimmed.find('/') != std::string::npos) {
        try {
            size_t slash_pos = trimmed.find('/');
            std::string ip_part = trimmed.substr(0, slash_pos);
            std::string prefix_part = trimmed.substr(slash_pos + 1);
            
            // 验证 IP 部分
            auto addr = boost::asio::ip::make_address_v4(ip_part);
            (void)addr;
            
            // 验证前缀长度
            int prefix_len = std::stoi(prefix_part);
            return prefix_len >= 0 && prefix_len <= 32;
        } catch (...) {
            return false;
        }
    }
    
    // 检查是否为单个 IP 地址
    try {
        auto addr = boost::asio::ip::make_address_v4(trimmed);
        (void)addr;
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace scanner
