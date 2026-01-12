#pragma once

#include "protocol_base.h"
#include <boost/asio.hpp>

namespace scanner {

using boost::asio::ip::tcp;
namespace asio = boost::asio;

class ImapProtocol : public IProtocol {
public:
    ImapProtocol() = default;
    virtual ~ImapProtocol() = default;

    std::string name() const override { return "IMAP"; }

    std::vector<Port> default_ports() const override {
        return {143, 993};
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
