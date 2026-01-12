#pragma once

#include "protocol_base.h"
#include <boost/asio.hpp>

namespace scanner {

using boost::asio::ip::tcp;
namespace asio = boost::asio;

class HttpProtocol : public IProtocol {
public:
    HttpProtocol() = default;
    virtual ~HttpProtocol() = default;

    std::string name() const override { return "HTTP"; }

    std::vector<Port> default_ports() const override {
        return {80, 443, 8080, 8443};
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
