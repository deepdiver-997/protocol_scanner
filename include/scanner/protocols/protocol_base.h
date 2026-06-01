#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <memory>
#include <unordered_map>
#include <functional>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/address_v4.hpp>

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

    // FTP 属性
    struct {
        std::string features;       // FEAT 响应原始文本
        bool utf8 = false;          // UTF8 编码支持
        bool auth_tls = false;      // AUTH TLS
        bool auth_ssl = false;      // AUTH SSL
        bool size_cmd = false;      // SIZE 命令
        bool mdtm = false;          // MDTM 修改时间
        bool mldst = false;         // MLSD/MLST 目录列表
        bool tvfs = false;          // TVFS 虚拟文件系统
        bool xcrc = false;          // XCRC 校验
        bool xcup = false;          // XCUP 上级目录
    } ftp;

    // SSH 属性
    struct {
        std::string version_string;  // 完整版本标识，如 "SSH-2.0-OpenSSH_8.9p1"
        std::string software;        // 软件名，如 "OpenSSH"
        std::string version;         // 版本号，如 "8.9p1"
        std::string protocol_version; // 协议版本，如 "2.0"
    } ssh;

    // 通用属性
    std::string banner;           // 服务欢迎消息
    bool banner_truncated = false; // banner是否因缓冲区满而被截断
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

// 扫描目标（优化内存占用：IP 用 uint32 存储）
struct ScanTarget {
    uint32_t ip_uint = 0;      // IP 地址（uint32，节省内存）
    std::string domain;         // 原始输入域名（若输入是纯 IP，则等于该 IP 字符串）
    std::string resolved_ip;    // 实际用于连接的 IP 字符串（DNS 解析后写入）
    uint64_t seq = 0;          // 输入顺序序号（用于有序落盘/断点恢复）
    size_t source_offset = 0;  // 输入文件行起始偏移（用于断点恢复加速）
    size_t offset_ordinal = 0; // 同一 source_offset 下的第几个目标（用于行内恢复）
    
    // 直接返回解析后的 IP 字符串缓存。
    const std::string& get_ip_string() const {
        return resolved_ip;
    }
    
    // 设置 IP（更新连接 IP；仅当 domain 为空时回填 domain）
    void set_ip(uint32_t ip_value) {
        ip_uint = ip_value;
        resolved_ip = boost::asio::ip::make_address_v4(ip_value).to_string();
        if (domain.empty()) {
            domain = resolved_ip;
        }
    }
    
    void set_ip(const std::string& ip_str) {
        try {
            ip_uint = boost::asio::ip::make_address_v4(ip_str).to_uint();
            resolved_ip = ip_str;
            if (domain.empty()) {
                domain = ip_str;
            }
        } catch (...) {
            // 非 IP，当作域名
            ip_uint = 0;
            domain = ip_str;
            resolved_ip.clear();
        }
    }
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
        const std::string& target,  // 目标域名或IP（用于逻辑标识与 Header）
        const std::string& ip,      // 实际连接的 IP 地址
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
