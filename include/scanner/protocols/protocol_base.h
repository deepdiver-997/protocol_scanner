#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <memory>
#include <unordered_map>
#include <functional>
#include <boost/asio/any_io_executor.hpp>

namespace scanner {

// =====================
// 基础类型定义
// =====================

using Port = uint16_t;

// 统一的超时类型别名
using Timeout = std::chrono::milliseconds;

// 协议属性
struct ProtocolAttributes {
    // SMTP/ESMTP 属性
    struct {
        bool pipelining = false;
        bool starttls = false;
        bool size_supported = false;
        size_t size_limit = 0;
        bool utf8 = false;
        bool _8bitmime = false;
        bool dsn = false;
        std::string auth_methods;
    } smtp;

    // POP3 属性
    struct {
        bool stls = false;
        bool sasl = false;
        bool user = false;
        bool top = false;
        bool pipelining = false;
        bool uidl = false;
        std::string capabilities;
    } pop3;

    // IMAP 属性
    struct {
        bool starttls = false;
        bool quota = false;
        bool acl = false;
        bool imap4rev1 = false;
        bool auth_plain = false;
        bool auth_login = false;
        bool idle = false;
        bool unselect = false;
        bool uidplus = false;
        std::string capabilities;
    } imap;

    // HTTP 属性
    struct {
        std::string server;
        std::string content_type;
        int status_code = 0;
    } http;

    // 通用属性
    std::string banner;           // 服务欢迎消息
    std::string vendor;          // 服务商标识
    double response_time_ms = 0.0; // 响应时间
};

// 协议探测结果
struct ProtocolResult {
    std::string protocol;        // 协议名称 (SMTP, POP3, IMAP, HTTP)
    std::string host;           // 主机地址
    Port port;                  // 端口号
    bool accessible = false;     // 是否可访问
    ProtocolAttributes attrs;    // 协议属性
    std::string error;          // 错误信息
};

// 扫描目标
struct ScanTarget {
    std::string domain;         // 域名
    std::string ip;            // IP 地址
    std::vector<std::string> mx_records; // MX 记录
    int priority = 0;          // 优先级
};

// 扫描报告
struct ScanReport {
    ScanTarget target;
    std::vector<ProtocolResult> protocols;
    std::chrono::milliseconds total_time;
};

// =====================
// 协议基类接口
// =====================

class IProtocol {
public:
    virtual ~IProtocol() = default;

    // 协议标识
    virtual std::string name() const = 0;

    // 默认端口列表
    virtual std::vector<Port> default_ports() const = 0;

    // 默认超时时间
    virtual Timeout default_timeout() const = 0;

    // 异步探测入口；实现负责持有自己的 socket 及 buffer 生命周期 通过回调传递结果到session中的队列
    virtual void async_probe(
        const std::string& host,
        Port port,
        Timeout timeout,
        boost::asio::any_io_executor exec,
        std::function<void(ProtocolResult&&)> on_complete
    ) = 0;

    // 解析特性
    virtual void parse_capabilities(
        const std::string& response,
        ProtocolAttributes& attrs
    ) = 0;

    // 是否需要加密连接
    virtual bool requires_tls(Port port) const {
        return (port == 465 || port == 587 || port == 993 || port == 995);
    }
};

// =====================
// 协议工厂
// =====================

class ProtocolFactory {
public:
    using ProtocolCreator = std::function<std::unique_ptr<IProtocol>()>;

    // 注册协议
    static void register_protocol(
        const std::string& name,
        ProtocolCreator creator
    );

    // 创建协议实例
    static std::unique_ptr<IProtocol> create(const std::string& name);

    // 获取所有可用协议
    static std::vector<std::string> available_protocols();

    // 检查协议是否可用
    static bool has_protocol(const std::string& name);

private:
    static std::unordered_map<std::string, ProtocolCreator> registry_;
};

// =====================
// 协议注册宏
// =====================

#define REGISTER_PROTOCOL(ProtocolClass, ProtocolName) \
    namespace { \
        struct ProtocolClass##Registrar { \
            ProtocolClass##Registrar() { \
                ProtocolFactory::register_protocol( \
                    ProtocolName, \
                    []() -> std::unique_ptr<IProtocol> { \
                        return std::make_unique<ProtocolClass>(); \
                    } \
                ); \
            } \
        }; \
        static ProtocolClass##Registrar g_##ProtocolClass##_registrar; \
    }

} // namespace scanner
