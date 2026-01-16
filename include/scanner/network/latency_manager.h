#pragma once

#include <atomic>
#include <shared_mutex>
#include <unordered_map>
#include <string>
#include <memory>
#include <chrono>

namespace scanner {

// 单个网段的统计信息
struct SubnetLatency {
    // 存储微秒级的平滑 RTT (Smoothed RTT)
    // 默认值设为 200ms (200000us)
    std::atomic<uint32_t> srtt_us{200000}; 
    
    // 偏差值 (RTT Variance)
    // 默认 50ms (50000us)
    std::atomic<uint32_t> rttvar_us{50000};

    void update(uint32_t sample_rtt_us) {
        // 使用原子操作加载当前值
        uint32_t old_srtt = srtt_us.load(std::memory_order_relaxed);
        uint32_t old_rttvar = rttvar_us.load(std::memory_order_relaxed);
        
        // Jacobson 算法简化版
        // 差值绝对值
        int32_t diff = static_cast<int32_t>(sample_rtt_us) - static_cast<int32_t>(old_srtt);
        uint32_t abs_diff = (diff < 0) ? -diff : diff;
        
        // RTTVAR = RTTVAR + (ABS_DIFF - RTTVAR) / 4
        uint32_t new_rttvar = old_rttvar + ((abs_diff > old_rttvar ? abs_diff - old_rttvar : -(old_rttvar - abs_diff)) >> 2);
        rttvar_us.store(new_rttvar, std::memory_order_relaxed);

        // SRTT = SRTT + (SAMPLE - SRTT) / 8
        uint32_t new_srtt = old_srtt + (diff >> 3); // 允许轻微误差，简单右移
        srtt_us.store(new_srtt, std::memory_order_relaxed);
    }

    // 获取建议的超时时间，带上下限钳制
    std::chrono::milliseconds get_suggested_timeout(uint32_t min_timeout_ms, uint32_t max_timeout_ms) const {
        uint32_t rtt = srtt_us.load(std::memory_order_relaxed);
        uint32_t var = rttvar_us.load(std::memory_order_relaxed);
        
        // Timeout = SRTT + 4 * RTTVAR
        uint32_t timeout_us = rtt + (var << 2);
        uint32_t timeout_ms = timeout_us / 1000;

        if (timeout_ms < min_timeout_ms) return std::chrono::milliseconds(min_timeout_ms);
        if (timeout_ms > max_timeout_ms) return std::chrono::milliseconds(max_timeout_ms);
        return std::chrono::milliseconds(timeout_ms);
    }
};

class LatencyManager {
public:
    static constexpr uint32_t kMinTimeoutMs = 800;
    static constexpr uint32_t kMaxTimeoutMs = 4000;

    static LatencyManager& instance() {
        static LatencyManager instance;
        return instance;
    }

    // 更新某个 IP 的扫描耗时
    void update(const std::string& ip_str, std::chrono::milliseconds rtt) {
        if (ip_str.empty()) return;
        auto subnet = get_subnet_key(ip_str);
        if (subnet.empty()) return; // 解析失败
        get_subnet_stats(subnet)->update(static_cast<uint32_t>(rtt.count() * 1000));
    }

    // 获取建议超时时间
    std::chrono::milliseconds get_timeout(const std::string& ip_str) {
        if (ip_str.empty()) return std::chrono::milliseconds(kMinTimeoutMs); // 默认兜底
        auto subnet = get_subnet_key(ip_str);
        if (subnet.empty()) return std::chrono::milliseconds(kMinTimeoutMs);
        return get_subnet_stats(subnet)->get_suggested_timeout(kMinTimeoutMs, kMaxTimeoutMs);
    }

private:
    std::string get_subnet_key(const std::string& ip_str) {
        // 简单实现：取前三个段作为 key (IPv4 C段) 
        // 192.168.1.100 -> 192.168.1
        size_t pos = 0;
        int dots = 0;
        for (size_t i = 0; i < ip_str.size(); ++i) {
            if (ip_str[i] == '.') {
                dots++;
                if (dots == 3) {
                    pos = i;
                    break;
                }
            }
        }
        // 如果是 IPv6 或者格式不对，简单处理：返回 "default" 或者整个 IP
        if (dots < 3) return "default"; 
        return ip_str.substr(0, pos);
    }

    std::shared_ptr<SubnetLatency> get_subnet_stats(const std::string& subnet) {
        // 1. 尝试读锁查找
        {
            std::shared_lock<std::shared_mutex> lock(map_mutex_);
            auto it = latencies_.find(subnet);
            if (it != latencies_.end()) {
                return it->second;
            }
        } // 读锁释放

        // 2. 没找到，加写锁插入
        {
            std::unique_lock<std::shared_mutex> lock(map_mutex_);
            // 双重检查
            auto it = latencies_.find(subnet);
            if (it != latencies_.end()) {
                return it->second;
            }
            auto stats = std::make_shared<SubnetLatency>();
            latencies_[subnet] = stats;
            return stats;
        }
    }

    std::shared_mutex map_mutex_;
    std::unordered_map<std::string, std::shared_ptr<SubnetLatency>> latencies_;
};

} // namespace scanner
