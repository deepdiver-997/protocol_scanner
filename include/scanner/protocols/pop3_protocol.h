#pragma once

#include "protocol_base.h"
#include <boost/asio.hpp>

namespace scanner {

using boost::asio::ip::tcp;
namespace asio = boost::asio;

class Pop3Protocol : public IProtocol {
public:
    Pop3Protocol() = default;
    virtual ~Pop3Protocol() = default;

    std::string name() const override { return "POP3"; }

    std::vector<Port> default_ports() const override {
        return {110, 995};
    }

    Timeout default_timeout() const override {
        return Timeout(3000);
    }

    void async_probe(
        const std::string& host,
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
