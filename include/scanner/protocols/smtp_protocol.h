#pragma once

#include "protocol_base.h"
#include <boost/asio.hpp>
#include <string>

namespace scanner {

using boost::asio::ip::tcp;
using boost::asio::steady_timer;
namespace asio = boost::asio;

struct ProbeContext;
class SmtpProtocol : public IProtocol {
public:
    SmtpProtocol() = default;
    virtual ~SmtpProtocol() = default;

    // 协议标识
    std::string name() const override { return "SMTP"; }

    // 默认端口
    std::vector<Port> default_ports() const override {
        return {25, 465, 587, 2525};
    }

    // 默认超时
    std::chrono::milliseconds default_timeout() const override {
        return std::chrono::milliseconds(5000);
    }

    // 异步探测 SMTP 服务
    void async_probe(
        const std::string& host,
        Port port,
        Timeout timeout,
        boost::asio::any_io_executor exec,
        std::function<void(ProtocolResult&&)> on_complete
    ) override;

    // 解析 ESMTP 特性
    void parse_capabilities(
        const std::string& response,
        ProtocolAttributes& attrs
    ) override;

private:
    void parse_ehlo_line(const std::string& line, ProtocolAttributes& attrs);
    void parse_size(const std::string& value, ProtocolAttributes& attrs);
    void parse_auth(const std::string& value, ProtocolAttributes& attrs);
};

} // namespace scanner
