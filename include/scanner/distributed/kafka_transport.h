#pragma once

#include <string>
#include <vector>

namespace scanner::distributed {

class KafkaProducer {
public:
    KafkaProducer(std::string brokers, std::string topic, std::string client_id);
    bool init(std::string* err);
    bool produce(const std::string& payload, const std::string& key, std::string* err);

private:
    std::string brokers_;
    std::string topic_;
    std::string client_id_;

    void* rk_ = nullptr;
};

class KafkaConsumer {
public:
    KafkaConsumer(std::string brokers, std::string topic, std::string group_id, std::string client_id);
    ~KafkaConsumer();

    bool init(std::string* err);
    size_t poll_batch(size_t max_messages, int timeout_ms, std::vector<std::string>* payloads, std::string* err);

private:
    std::string brokers_;
    std::string topic_;
    std::string group_id_;
    std::string client_id_;

    void* rk_ = nullptr;
};

}  // namespace scanner::distributed
