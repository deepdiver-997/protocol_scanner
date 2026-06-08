#pragma once

#include "protocol_base.h"
#include <boost/asio.hpp>

namespace scanner {

using boost::asio::ip::tcp;
namespace asio = boost::asio;

class MysqlProtocol : public IProtocol {
public:
    MysqlProtocol() = default;
    virtual ~MysqlProtocol() = default;

    std::string name() const override { return "MYSQL"; }

    std::vector<Port> default_ports() const override { return {3306}; }

    Timeout default_timeout() const override { return Timeout(3000); }

    void async_probe(
        const std::string& target,
        const std::string& ip,
        Port port,
        Timeout timeout,
        boost::asio::any_io_executor exec,
        std::function<void(ProtocolResult&&)> on_complete,
    const std::string& bind_ip = ""
    ) override;

    void parse_capabilities(const std::string& response, ProtocolAttributes& attrs) override;
};

} // namespace scanner