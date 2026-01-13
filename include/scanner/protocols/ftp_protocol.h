#pragma once

#include "protocol_base.h"
#include <boost/asio.hpp>

namespace scanner {

using boost::asio::ip::tcp;
namespace asio = boost::asio;

class FtpProtocol : public IProtocol {
public:
    FtpProtocol() = default;
    virtual ~FtpProtocol() = default;

    std::string name() const override { return "FTP"; }

    std::vector<Port> default_ports() const override {
        return {21, 990};
    }

    Timeout default_timeout() const override {
        return Timeout(3000);
    }

    bool requires_tls(Port port) const override {
        return port == 990;
    }

    void async_probe(
        const std::string& target,
        const std::string& ip,
        Port port,
        Timeout timeout,
        boost::asio::any_io_executor exec,
        std::function<void(ProtocolResult&&)> on_complete
    ) override;

    void parse_capabilities(
        const std::string& response,
        ProtocolAttributes& attrs
    ) override;
};

} // namespace scanner
