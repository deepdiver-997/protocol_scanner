#pragma once

#include <boost/asio.hpp>
#include <functional>
#include <chrono>
#include <vector>
#include <memory>

namespace scanner {

// 协议探测上下文 - 所有协议共用
struct ProbeContext {
    boost::asio::ip::tcp::socket socket;
    std::function<void(class ProtocolResult&&)> callback;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::milliseconds timeout;
    std::shared_ptr<std::vector<char>> buffer;

    // 协议特定状态（部分协议可用）
    size_t bytes_read{0};
    size_t buffer_offset{0};

    ProbeContext(boost::asio::any_io_executor exec, 
                 std::chrono::milliseconds t,
                 std::function<void(ProtocolResult&&)> cb)
        : socket(exec), 
          callback(std::move(cb)), 
          timeout(t) {
        buffer = std::make_shared<std::vector<char>>(4096);
        start_time = std::chrono::steady_clock::now();
    }

    ~ProbeContext() = default;

    void finish_success() {
        // 由具体协议实现
    }

    void finish_error(const std::string& msg) {
        // 由具体协议实现
    }

    bool is_timeout() const {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time);
        return elapsed >= timeout;
    }
};

} // namespace scanner
