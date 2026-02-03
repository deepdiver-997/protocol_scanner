#include "scanner/core/scanner.h"
#include "scanner/common/logger.h"
#include "scanner/vendor/vendor_detector.h"
#include "scanner/output/result_handler.h"
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <boost/asio/ip/address_v4.hpp>
#include <sstream>
#include <cmath>
#include <functional>
#include <sstream>

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

// 辅助函数：将 CIDR 记号扩展为单个 IP（流式输出 uint32，避免字符串创建）
static bool expand_cidr_stream_uint(const std::string& cidr_str,
                                    const std::function<bool(uint32_t)>& emit,
                                    uint32_t skip_until = 0) {
    try {
        std::string cidr_trimmed = trim(cidr_str);
        size_t slash_pos = cidr_trimmed.find('/');
        if (slash_pos == std::string::npos) {
            if (is_valid_ip_internal(cidr_trimmed)) {
                auto addr = boost::asio::ip::make_address_v4(cidr_trimmed);
                uint32_t ip_uint = addr.to_uint();
                // 快速跳过：如果这个IP小于断点IP，直接跳过
                if (skip_until > 0 && ip_uint < skip_until) {
                    return true;
                }
                return emit(ip_uint);
            }
            return true;
        }

        std::string ip_part = cidr_trimmed.substr(0, slash_pos);
        std::string prefix_part = cidr_trimmed.substr(slash_pos + 1);

        auto base_addr = boost::asio::ip::make_address_v4(trim(ip_part));
        int prefix_len = std::stoi(prefix_part);

        if (prefix_len < 0 || prefix_len > 32) {
            LOG_CORE_ERROR("Invalid CIDR prefix length: {}", prefix_len);
            return true;
        }

        int host_bits = 32 - prefix_len;
        uint32_t host_mask = (1UL << host_bits) - 1;
        uint32_t base_uint = base_addr.to_uint();

        uint32_t network_addr = base_uint & ~host_mask;
        uint32_t broadcast_addr = network_addr | host_mask;

        const uint32_t MAX_EXPANSION = 1048576;
        uint32_t count = broadcast_addr - network_addr + 1;
        if (count > MAX_EXPANSION) {
            // 静默截断，避免启动时打印大量警告日志拖慢速度
            broadcast_addr = network_addr + MAX_EXPANSION - 1;
        }

        // 快速跳过整个CIDR段或段内部分IP
        if (skip_until > 0) {
            if (broadcast_addr < skip_until) {
                // 整个段都要跳过，直接返回
                return true;
            }
            // 从断点IP开始（而不是从network_addr开始）
            if (network_addr < skip_until) {
                network_addr = skip_until;
            }
        }

        // 直接传递 uint32，完全避免字符串创建
        for (uint32_t i = network_addr; i <= broadcast_addr; ++i) {
            if (!emit(i)) {
                return false;
            }
        }
    } catch (const std::exception& e) {
        LOG_CORE_ERROR("Failed to expand CIDR {}: {}", cidr_str, e.what());
    }
    return true;
}

// 辅助函数：将 CIDR 记号扩展为单个 IP（字符串版本，供旧代码兼容）
static bool expand_cidr_stream(const std::string& cidr_str,
                               const std::function<bool(const std::string&)>& emit) {
    return expand_cidr_stream_uint(cidr_str, [&emit](uint32_t ip_uint) {
        // 在调用点直接转换字符串，而不是在lambda内重复转换
        return emit(boost::asio::ip::make_address_v4(ip_uint).to_string());
    });
}

// 辅助函数：将 IP 段扩展为单个 IP（流式输出 uint32，避免字符串创建）
static bool expand_ip_range_stream_uint(const std::string& start_ip_str,
                                        const std::string& end_ip_str,
                                        const std::function<bool(uint32_t)>& emit,
                                        uint32_t skip_until = 0) {
    try {
        auto start_addr = boost::asio::ip::make_address_v4(trim(start_ip_str));
        auto end_addr = boost::asio::ip::make_address_v4(trim(end_ip_str));

        uint32_t start_uint = start_addr.to_uint();
        uint32_t end_uint = end_addr.to_uint();

        if (start_uint > end_uint) std::swap(start_uint, end_uint);

        const uint32_t MAX_EXPANSION = 1048576;
        if (end_uint - start_uint > MAX_EXPANSION) {
            // 静默截断
            end_uint = start_uint + MAX_EXPANSION;
        }

        // 快速跳过整个段或段内部分IP
        if (skip_until > 0) {
            if (end_uint < skip_until) {
                // 整个段都要跳过，直接返回
                return true;
            }
            // 从断点IP开始（而不是从start_uint开始）
            if (start_uint < skip_until) {
                start_uint = skip_until;
            }
        }

        // 直接传递 uint32，完全避免字符串创建
        for (uint32_t i = start_uint; i <= end_uint; ++i) {
            if (!emit(i)) {
                return false;
            }
        }
    } catch (const std::exception& e) {
        LOG_CORE_ERROR("Failed to expand IP range {}-{}: {}", start_ip_str, end_ip_str, e.what());
    }
    return true;
}

// 辅助函数：将 IP 段扩展为单个 IP（字符串版本，供旧代码兼容）
static bool expand_ip_range_stream(const std::string& start_ip_str,
                                   const std::string& end_ip_str,
                                   const std::function<bool(const std::string&)>& emit) {
    return expand_ip_range_stream_uint(start_ip_str, end_ip_str, [&emit](uint32_t ip_uint) {
        // 在调用点直接转换字符串
        return emit(boost::asio::ip::make_address_v4(ip_uint).to_string());
    });
}

// 将单个文件流式解析为目标并交给处理器
static size_t process_file_stream(
    const std::string& filename,
    size_t offset,
    size_t& skipped,
    const std::function<bool(const std::string&)>& handle_target,
    bool& aborted
) {
    std::ifstream in(filename);
    if (!in) {
        LOG_FILE_IO_ERROR("Failed to open file: {}", filename);
        return 0;
    }

    auto dispatch = [&](const std::string& value, bool& delivered) -> bool {
        delivered = false;
        if (value.empty()) return true;
        if (skipped < offset) {
            ++skipped;
            return true;
        }
        if (!handle_target(value)) {
            aborted = true;
            return false;
        }
        delivered = true;
        return true;
    };

    size_t emitted = 0;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        // 检查是否为 CIDR 记号（IP/PREFIX）
        if (line.find('/') != std::string::npos) {
            bool ok = expand_cidr_stream(line, [&](const std::string& ip) {
                bool delivered = false;
                if (!dispatch(ip, delivered)) return false;
                if (delivered) ++emitted;
                return true;
            });
            if (!ok) return emitted;
            continue;
        }

        // 尝试判断是否为 IP 段 CSV (start_ip,end_ip,...)
        if (line.find(',') != std::string::npos) {
            std::stringstream ss(line);
            std::string start_ip, end_ip;
            if (std::getline(ss, start_ip, ',') && std::getline(ss, end_ip, ',')) {
                bool ok = expand_ip_range_stream(start_ip, end_ip, [&](const std::string& ip) {
                    bool delivered = false;
                    if (!dispatch(ip, delivered)) return false;
                    if (delivered) ++emitted;
                    return true;
                });
                if (!ok) return emitted;
                continue;
            }
        }

        bool delivered = false;
        if (!dispatch(line, delivered)) return emitted;
        if (delivered) ++emitted;
    }

    return emitted;
}

// 将单个文件流式解析为目标并交给处理器（按文件字节偏移定位）
static size_t process_file_stream_with_offset(
    const std::string& filename,
    size_t file_offset,
    const std::function<bool(const std::string&, size_t)>& handle_target,
    bool& aborted,
    uint32_t skip_until = 0  // 新增：跳过小于此值的所有IP
) {
    std::ifstream in(filename);
    if (!in) {
        LOG_FILE_IO_ERROR("Failed to open file: {}", filename);
        return 0;
    }

    if (file_offset > 0) {
        in.seekg(static_cast<std::streamoff>(file_offset), std::ios::beg);
        if (!in) {
            LOG_CORE_WARN("Failed to seek to offset {} in {}, fallback to start", file_offset, filename);
            in.clear();
            in.seekg(0, std::ios::beg);
            file_offset = 0;
        } else {
            // 如果不是行起始位置，则跳过当前残缺行
            in.seekg(static_cast<std::streamoff>(file_offset - 1), std::ios::beg);
            char prev = '\n';
            in.get(prev);
            if (prev != '\n' && prev != '\r') {
                std::string discard;
                std::getline(in, discard);
            }
        }
    }

    size_t emitted = 0;
    std::string line;
    while (true) {
        std::streampos line_pos = in.tellg();
        if (!std::getline(in, line)) break;
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        size_t line_offset = 0;
        if (line_pos != std::streampos(-1)) {
            line_offset = static_cast<size_t>(line_pos);
        }

        // 检查是否为 CIDR 记号（IP/PREFIX）
        if (line.find('/') != std::string::npos) {
            bool ok = expand_cidr_stream_uint(line, [&](uint32_t ip_uint) {
                std::string ip_str = boost::asio::ip::make_address_v4(ip_uint).to_string();
                if (!handle_target(ip_str, line_offset)) {
                    aborted = true;
                    return false;
                }
                ++emitted;
                return true;
            }, skip_until);  // 传递 skip_until 参数
            if (!ok) return emitted;
            continue;
        }

        // 尝试判断是否为 IP 段 CSV (start_ip,end_ip,...)
        if (line.find(',') != std::string::npos) {
            std::stringstream ss(line);
            std::string start_ip, end_ip;
            if (std::getline(ss, start_ip, ',') && std::getline(ss, end_ip, ',')) {
                bool ok = expand_ip_range_stream_uint(start_ip, end_ip, [&](uint32_t ip_uint) {
                    std::string ip_str = boost::asio::ip::make_address_v4(ip_uint).to_string();
                    if (!handle_target(ip_str, line_offset)) {
                        aborted = true;
                        return false;
                    }
                    ++emitted;
                    return true;
                }, skip_until);  // 传递 skip_until 参数
                if (!ok) return emitted;
                continue;
            }
        }

        if (!handle_target(line, line_offset)) {
            aborted = true;
            return emitted;
        }
        ++emitted;
    }

    return emitted;
}

// 【新增】完全uint32版本：从文件读取到CIDR展开全程避免字符串创建
static size_t process_file_stream_uint(
    const std::string& filename,
    size_t file_offset,
    const std::function<bool(uint32_t, size_t)>& handle_target_uint,
    bool& aborted,
    uint32_t skip_until = 0
) {
    std::ifstream in(filename);
    if (!in) {
        LOG_FILE_IO_ERROR("Failed to open file: {}", filename);
        return 0;
    }

    if (file_offset > 0) {
        in.seekg(static_cast<std::streamoff>(file_offset), std::ios::beg);
        if (!in) {
            LOG_CORE_WARN("Failed to seek to offset {} in {}, fallback to start", file_offset, filename);
            in.clear();
            in.seekg(0, std::ios::beg);
            file_offset = 0;
        } else {
            in.seekg(static_cast<std::streamoff>(file_offset - 1), std::ios::beg);
            char prev = '\n';
            in.get(prev);
            if (prev != '\n' && prev != '\r') {
                std::string discard;
                std::getline(in, discard);
            }
        }
    }

    size_t emitted = 0;
    std::string line;
    while (true) {
        std::streampos line_pos = in.tellg();
        if (!std::getline(in, line)) break;
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        size_t line_offset = 0;
        if (line_pos != std::streampos(-1)) {
            line_offset = static_cast<size_t>(line_pos);
        }

        // 检查是否为 CIDR 记号（IP/PREFIX）
        if (line.find('/') != std::string::npos) {
            bool ok = expand_cidr_stream_uint(line, [&](uint32_t ip_uint) {
                // 【关键优化】直接传递uint32，零字符串创建！
                if (!handle_target_uint(ip_uint, line_offset)) {
                    aborted = true;
                    LOG_CORE_WARN("[process_file_stream_uint] Handler returned false at line '{}', emitted={}", 
                                 line, emitted);
                    return false;
                }
                ++emitted;
                return true;
            }, skip_until);
            if (!ok) {
                LOG_CORE_WARN("[process_file_stream_uint] expand_cidr_stream_uint failed, aborted={}, emitted={}", 
                             aborted, emitted);
                return emitted;
            }
            continue;
        }

        // 尝试判断是否为 IP 段 CSV (start_ip,end_ip,...)
        if (line.find(',') != std::string::npos) {
            std::stringstream ss(line);
            std::string start_ip, end_ip;
            if (std::getline(ss, start_ip, ',') && std::getline(ss, end_ip, ',')) {
                bool ok = expand_ip_range_stream_uint(start_ip, end_ip, [&](uint32_t ip_uint) {
                    // 【关键优化】直接传递uint32
                    if (!handle_target_uint(ip_uint, line_offset)) {
                        aborted = true;
                        return false;
                    }
                    ++emitted;
                    return true;
                }, skip_until);
                if (!ok) return emitted;
                continue;
            }
        }

        // 单个IP或域名
        try {
            auto addr = boost::asio::ip::make_address_v4(line);
            if (!handle_target_uint(addr.to_uint(), line_offset)) {
                aborted = true;
                return emitted;
            }
        } catch (...) {
            // 非IP，跳过（或可以特殊处理域名）
        }
        ++emitted;
    }

    return emitted;
}

size_t stream_domains(
    const std::string& path,
    size_t offset,
    const std::function<bool(const std::string&)>& handle_target
) {
    size_t total = 0;
    size_t skipped = 0;
    bool aborted = false;

    try {
        if (fs::is_directory(path)) {
            LOG_FILE_IO_DEBUG("Loading targets from directory: {}", path);
            for (const auto& entry : fs::recursive_directory_iterator(path)) {
                if (!entry.is_regular_file()) continue;
                total += process_file_stream(entry.path().string(), offset, skipped, handle_target, aborted);
                if (aborted) break;
            }
        } else if (fs::is_regular_file(path)) {
            total = process_file_stream(path, offset, skipped, handle_target, aborted);
        } else {
            LOG_FILE_IO_ERROR("Path not found or invalid: {}", path);
        }
    } catch (const std::exception& e) {
        LOG_CORE_CRITICAL("Error during loading targets from {}: {}", path, e.what());
    }

    LOG_FILE_IO_DEBUG("Total loaded {} targets from {}", total, path);
    return total;
}

size_t stream_domains_with_offset(
    const std::string& path,
    size_t file_offset,
    const std::function<bool(const std::string&, size_t)>& handle_target
) {
    size_t total = 0;
    bool aborted = false;

    try {
        if (fs::is_directory(path)) {
            if (file_offset > 0) {
                LOG_CORE_WARN("Input path is directory; file_offset={} ignored", file_offset);
            }
            LOG_FILE_IO_DEBUG("Loading targets from directory: {}", path);
            for (const auto& entry : fs::recursive_directory_iterator(path)) {
                if (!entry.is_regular_file()) continue;
                total += process_file_stream_with_offset(entry.path().string(), 0, handle_target, aborted);
                if (aborted) break;
            }
        } else if (fs::is_regular_file(path)) {
            total = process_file_stream_with_offset(path, file_offset, handle_target, aborted);
        } else {
            LOG_FILE_IO_ERROR("Path not found or invalid: {}", path);
        }
    } catch (const std::exception& e) {
        LOG_CORE_CRITICAL("Error during loading targets from {}: {}", path, e.what());
    }

    LOG_FILE_IO_DEBUG("Total loaded {} targets from {}", total, path);
    return total;
}

// 【新增】uint32 版本：直接传递数值 IP，完全避免字符串转换
size_t stream_domains_with_offset_uint(
    const std::string& path,
    size_t file_offset,
    const std::function<bool(uint32_t, size_t)>& handle_target,
    uint32_t skip_until
) {
    size_t total = 0;
    bool aborted = false;

    // 【关键优化】直接使用uint32版本的process_file_stream_uint，零字符串创建
    try {
        if (fs::is_directory(path)) {
            if (file_offset > 0) {
                LOG_CORE_WARN("Input path is directory; file_offset={} ignored", file_offset);
            }
            LOG_FILE_IO_DEBUG("Loading targets from directory: {}", path);
            for (const auto& entry : fs::recursive_directory_iterator(path)) {
                if (!entry.is_regular_file()) continue;
                total += process_file_stream_uint(entry.path().string(), 0, handle_target, aborted, skip_until);
                if (aborted) break;
            }
        } else if (fs::is_regular_file(path)) {
            total = process_file_stream_uint(path, file_offset, handle_target, aborted, skip_until);
        } else {
            LOG_FILE_IO_ERROR("Path not found or invalid: {}", path);
        }
    } catch (const std::exception& e) {
        LOG_CORE_CRITICAL("Error during loading targets from {}: {}", path, e.what());
    }

    LOG_FILE_IO_DEBUG("Total loaded {} targets from {}", total, path);
    return total;
}

std::vector<std::string> load_domains(const std::string& path, size_t offset) {
    std::vector<std::string> all_targets;
    stream_domains(path, offset, [&](const std::string& target) {
        all_targets.push_back(target);
        return true;
    });
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

// =====================
// 输出/统计辅助
// =====================

static void append_vendor_stats(std::ostream& os, const VendorDetector* vendor_detector) {
    if (!vendor_detector) return;
    auto stats_vec = vendor_detector->get_statistics();
    for (const auto& s : stats_vec) {
        if (s.count > 0) {
            os << s.name << ": " << s.count << " servers\n";
        }
    }
}

std::string build_stats_block(const Scanner::ScanStatistics& stats) {
    std::ostringstream oss;
    oss << "\n================== Scan Statistics ==================\n";
    oss << "Total Targets: " << stats.total_targets << "\n";
    oss << "Successful IPs: " << stats.successful_ips << "\n";
    oss << "\nProtocol Success Counts:\n";
    for (const auto& [protocol, count] : stats.protocol_counts) {
        oss << "  " << protocol << ": " << count << "\n";
    }
    if (stats.total_time.count() > 0) {
        oss << "\nTotal Time: " << stats.total_time.count() << " ms\n";
    }
    oss << "====================================================\n";
    return oss.str();
}

std::string build_summary_output(
    const ResultHandler* handler,
    const std::vector<ScanReport>& reports,
    const Scanner::ScanStatistics& stats,
    const VendorDetector* vendor_detector
) {
    std::ostringstream oss;
    oss << "\nScan Results\n";
    oss << "============\n";
    if (handler) {
        oss << handler->reports_to_string(reports);
    }
    if (vendor_detector) {
        oss << "Vendor Statistics:\n";
        append_vendor_stats(oss, vendor_detector);
    }
    oss << build_stats_block(stats);
    return oss.str();
}

void write_vendor_stats_file(const VendorDetector* vendor_detector, const std::string& output_dir) {
    if (!vendor_detector) return;
    std::error_code ec;
    fs::create_directories(output_dir, ec);
    std::string out_path = output_dir;
    if (!out_path.empty() && out_path.back() != '/') out_path += "/";
    out_path += "vendor_stats.txt";

    std::ofstream ofs(out_path, std::ios::trunc);
    if (!ofs) {
        LOG_CORE_WARN("Failed to open vendor stats file: {}", out_path);
        return;
    }
    append_vendor_stats(ofs, vendor_detector);
    ofs.flush();
}

} // namespace scanner
