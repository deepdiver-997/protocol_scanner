#pragma once

#include <string>
#include <cstdint>

namespace scanner {

/// 深度探测抽象接口 — 同步调用，由调度层负责线程分配
class IDeepProbe {
public:
    virtual ~IDeepProbe() = default;

    /// 探测名称，例如 "max_auth_tries", "login_grace_time"
    virtual std::string name() const = 0;

    /// 关联的协议名称，例如 "SSH", "FTP", "TELNET"
    virtual std::string protocol_name() const = 0;

    /// 同步执行深度探测（可能阻塞，在 IO 线程池上执行）
    /// @return 探测结果字符串 (key=value 格式)
    virtual std::string probe(const std::string& ip, uint16_t port) = 0;
};

} // namespace scanner
