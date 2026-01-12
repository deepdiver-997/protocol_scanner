#pragma once

#include "../protocols/protocol_base.h"
#include <boost/asio.hpp>
#include <vector>

namespace scanner {

using boost::asio::ip::tcp;
using boost::asio::steady_timer;
namespace asio = boost::asio;

// =====================
// 端口扫描结果
// =====================

struct PortScanResult {
    Port port;
    bool open;
    std::string banner;
    double response_time_ms;
};

// =====================
// 端口扫描器
// =====================

class PortScanner {
public:
    explicit PortScanner(asio::io_context& io);
    ~PortScanner() = default;

    // 扫描单个端口
    PortScanResult scan(
        const std::string& host,
        Port port,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)
    );

    // 扫描多个端口
    std::vector<PortScanResult> scan(
        const std::string& host,
        const std::vector<Port>& ports,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)
    );

    // 异步扫描（返回 future）
    std::future<PortScanResult> async_scan(
        const std::string& host,
        Port port,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)
    );

private:
    // 同步连接检查
    bool connect_sync(
        const std::string& host,
        Port port,
        std::chrono::milliseconds timeout
    );

    // 异步连接检查
    struct AsyncScanContext {
        bool success = false;
        bool timeout = false;
        steady_timer timer;
        tcp::socket socket;
        asio::io_context& io;
    };

    void async_connect(
        const std::string& host,
        Port port,
        std::chrono::milliseconds timeout,
        std::function<void(bool)> callback
    );

    asio::io_context& io_;
};

} // namespace scanner
