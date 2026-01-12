#include "scanner/protocols/http_protocol.h"
#include <boost/asio/post.hpp>

namespace scanner {

namespace asio = boost::asio;

void HttpProtocol::async_probe(
    const std::string& host,
    Port port,
    Timeout timeout,
    boost::asio::any_io_executor exec,
    std::function<void(ProtocolResult&&)> on_complete
) {
    ProtocolResult result;
    result.protocol = name();
    result.host = host;
    result.port = port;
    result.error = "HTTP async_probe not implemented";
    result.accessible = false;
    asio::post(std::move(exec), [cb = std::move(on_complete), res = std::move(result)]() mutable {
        if (cb) cb(std::move(res));
    });
}

void HttpProtocol::parse_capabilities(
    const std::string& response,
    ProtocolAttributes& attrs
) {
    (void)response;
    (void)attrs;
    // TODO: 解析 HTTP 响应头
}

} // namespace scanner
