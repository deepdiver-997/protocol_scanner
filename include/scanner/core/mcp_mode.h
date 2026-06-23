#pragma once

#include "scanner/core/scanner.h"
#include <boost/asio.hpp>
#include <vector>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <memory>
#include <unordered_map>

namespace scanner {

// MCP 模式的单个槽位：一个 IP → 一个扫描结果
struct MCPSlot {
    std::atomic<int> status{0};   // 0=free, 1=scanning, 2=done, 3=deep_probing
    uint64_t seq = 0;
    std::string target_ip;
    ScanReport result;
    std::mutex result_mutex;      // 保护 result 与 deep_probe_results 写入

    // 深度探测结果：probe_name -> result_string
    std::unordered_map<std::string, std::string> deep_probe_results;
    std::atomic<int> deep_probes_pending{0};
};

// MCP 模式上下文：槽位数组 + TCP 服务端 (Asio) + 可注入回调工厂
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
    void start_async_accept(Scanner* scanner);
    void do_session(boost::asio::ip::tcp::socket socket, Scanner* scanner);
    std::string handle_request(const std::string& json_line, Scanner* scanner);
    void maybe_start_deep_probes(size_t slot_id, class Scanner* scanner);

    uint16_t port_;
    size_t num_slots_;
    size_t last_stop_ = 0;
    std::vector<MCPSlot> slots_;
    std::atomic<bool> stop_{false};

    // Asio 成员 — MCP 自己有独立的 io_context，轻量不抢扫描池
    boost::asio::io_context mcp_io_ctx_;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
};

} // namespace scanner
