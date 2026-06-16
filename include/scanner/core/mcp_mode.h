#pragma once

#include "scanner/core/scanner.h"
#include <vector>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace scanner {

// MCP 模式的单个槽位：一个 IP → 一个扫描结果
struct MCPSlot {
    std::atomic<int> status{0};   // 0=free, 1=scanning, 2=done
    uint64_t seq = 0;
    std::string target_ip;
    ScanReport result;
    std::mutex result_mutex;      // 保护 result 写入
};

// MCP 模式上下文：槽位数组 + TCP 服务端 + 可注入回调工厂
class MCPContext {
public:
    // port: TCP 监听端口, num_slots: 最大并发槽位数(≤ max_work_count)
    MCPContext(uint16_t port, size_t num_slots);
    ~MCPContext();

    // 停止 TCP 服务
    void stop();

    // 生成可注入 Scanner 的线程回调
    Scanner::InputFunc  make_input_producer(Scanner* scanner);
    Scanner::ResultFunc make_result_consumer(Scanner* scanner);

private:
    int accept_loop(Scanner* scanner);
    std::string handle_request(const std::string& json_line, Scanner* scanner);

    uint16_t port_;
    size_t num_slots_;
    size_t last_stop_ = 0;
    std::vector<MCPSlot> slots_;
    std::atomic<bool> stop_{false};
    int listen_fd_ = -1;
};

} // namespace scanner
