#pragma once

#include "protocol_base.h"
#include <boost/asio.hpp>

namespace scanner {

class MongoProtocol : public IProtocol {
public:
    MongoProtocol() = default;
    virtual ~MongoProtocol() = default;

    std::string name() const override { return "MONGO"; }

    std::vector<Port> default_ports() const override { return {27017}; }

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

// 最简 BSON 解析：从 BSON 字节流中提取特定 key 的值
std::string bson_get_string(const char* data, size_t len, const std::string& key);
int         bson_get_int32(const char* data, size_t len, const std::string& key);

} // namespace scanner
