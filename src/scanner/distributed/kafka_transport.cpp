#include "scanner/distributed/kafka_transport.h"

#include <memory>

#if defined(SCANNER_ENABLE_KAFKA) && SCANNER_ENABLE_KAFKA
#include <librdkafka/rdkafka.h>
#endif

namespace scanner::distributed {

KafkaProducer::KafkaProducer(std::string brokers, std::string topic, std::string client_id)
    : brokers_(std::move(brokers)), topic_(std::move(topic)), client_id_(std::move(client_id)) {}

bool KafkaProducer::init(std::string* err) {
#if defined(SCANNER_ENABLE_KAFKA) && SCANNER_ENABLE_KAFKA
    char errstr[512];
    rd_kafka_conf_t* conf = rd_kafka_conf_new();
    if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers_.c_str(), errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        if (err != nullptr) {
            *err = errstr;
        }
        rd_kafka_conf_destroy(conf);
        return false;
    }
    if (rd_kafka_conf_set(conf, "client.id", client_id_.c_str(), errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        if (err != nullptr) {
            *err = errstr;
        }
        rd_kafka_conf_destroy(conf);
        return false;
    }

    rd_kafka_t* rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (rk == nullptr) {
        if (err != nullptr) {
            *err = errstr;
        }
        rd_kafka_conf_destroy(conf);
        return false;
    }
    rk_ = rk;
    return true;
#else
    if (err != nullptr) {
        *err = "Kafka support is not enabled in this build";
    }
    return false;
#endif
}

bool KafkaProducer::produce(const std::string& payload, const std::string& key, std::string* err) {
#if defined(SCANNER_ENABLE_KAFKA) && SCANNER_ENABLE_KAFKA
    if (rk_ == nullptr) {
        if (err != nullptr) {
            *err = "Kafka producer not initialized";
        }
        return false;
    }

    rd_kafka_t* rk = static_cast<rd_kafka_t*>(rk_);
    const rd_kafka_resp_err_t rc = rd_kafka_producev(
        rk,
        RD_KAFKA_V_TOPIC(topic_.c_str()),
        RD_KAFKA_V_PARTITION(RD_KAFKA_PARTITION_UA),
        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
        RD_KAFKA_V_KEY(const_cast<char*>(key.data()), key.size()),
        RD_KAFKA_V_VALUE(const_cast<char*>(payload.data()), payload.size()),
        RD_KAFKA_V_END);

    if (rc != RD_KAFKA_RESP_ERR_NO_ERROR) {
        if (err != nullptr) {
            *err = rd_kafka_err2str(rc);
        }
        return false;
    }

    rd_kafka_poll(rk, 0);
    rd_kafka_flush(rk, 5000);
    return true;
#else
    (void)payload;
    (void)key;
    if (err != nullptr) {
        *err = "Kafka support is not enabled in this build";
    }
    return false;
#endif
}

KafkaConsumer::KafkaConsumer(std::string brokers, std::string topic, std::string group_id, std::string client_id)
    : brokers_(std::move(brokers)),
      topic_(std::move(topic)),
      group_id_(std::move(group_id)),
      client_id_(std::move(client_id)) {}

KafkaConsumer::~KafkaConsumer() {
#if defined(SCANNER_ENABLE_KAFKA) && SCANNER_ENABLE_KAFKA
    if (rk_ != nullptr) {
        rd_kafka_t* rk = static_cast<rd_kafka_t*>(rk_);
        rd_kafka_consumer_close(rk);
        rd_kafka_destroy(rk);
        rk_ = nullptr;
    }
#endif
}

bool KafkaConsumer::init(std::string* err) {
#if defined(SCANNER_ENABLE_KAFKA) && SCANNER_ENABLE_KAFKA
    char errstr[512];
    rd_kafka_conf_t* conf = rd_kafka_conf_new();

    if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers_.c_str(), errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
        rd_kafka_conf_set(conf, "group.id", group_id_.c_str(), errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
        rd_kafka_conf_set(conf, "client.id", client_id_.c_str(), errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
        rd_kafka_conf_set(conf, "auto.offset.reset", "earliest", errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK ||
        rd_kafka_conf_set(conf, "enable.auto.commit", "true", errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
        if (err != nullptr) {
            *err = errstr;
        }
        rd_kafka_conf_destroy(conf);
        return false;
    }

    rd_kafka_t* rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
    if (rk == nullptr) {
        if (err != nullptr) {
            *err = errstr;
        }
        rd_kafka_conf_destroy(conf);
        return false;
    }

    rd_kafka_poll_set_consumer(rk);

    rd_kafka_topic_partition_list_t* topics = rd_kafka_topic_partition_list_new(1);
    rd_kafka_topic_partition_list_add(topics, topic_.c_str(), RD_KAFKA_PARTITION_UA);
    const rd_kafka_resp_err_t sub_rc = rd_kafka_subscribe(rk, topics);
    rd_kafka_topic_partition_list_destroy(topics);

    if (sub_rc != RD_KAFKA_RESP_ERR_NO_ERROR) {
        if (err != nullptr) {
            *err = rd_kafka_err2str(sub_rc);
        }
        rd_kafka_destroy(rk);
        return false;
    }

    rk_ = rk;
    return true;
#else
    if (err != nullptr) {
        *err = "Kafka support is not enabled in this build";
    }
    return false;
#endif
}

size_t KafkaConsumer::poll_batch(size_t max_messages, int timeout_ms, std::vector<std::string>* payloads, std::string* err) {
#if defined(SCANNER_ENABLE_KAFKA) && SCANNER_ENABLE_KAFKA
    if (payloads == nullptr) {
        return 0;
    }
    payloads->clear();

    if (rk_ == nullptr) {
        if (err != nullptr) {
            *err = "Kafka consumer not initialized";
        }
        return 0;
    }

    rd_kafka_t* rk = static_cast<rd_kafka_t*>(rk_);
    const size_t to_take = max_messages == 0 ? 1 : max_messages;
    for (size_t i = 0; i < to_take; ++i) {
        rd_kafka_message_t* msg = rd_kafka_consumer_poll(rk, timeout_ms);
        if (msg == nullptr) {
            break;
        }

        if (msg->err == RD_KAFKA_RESP_ERR_NO_ERROR && msg->payload != nullptr && msg->len > 0) {
            payloads->emplace_back(static_cast<const char*>(msg->payload), msg->len);
        } else if (msg->err != RD_KAFKA_RESP_ERR__PARTITION_EOF && msg->err != RD_KAFKA_RESP_ERR__TIMED_OUT) {
            if (err != nullptr) {
                *err = rd_kafka_message_errstr(msg);
            }
        }

        rd_kafka_message_destroy(msg);
    }

    return payloads->size();
#else
    (void)max_messages;
    (void)timeout_ms;
    (void)payloads;
    if (err != nullptr) {
        *err = "Kafka support is not enabled in this build";
    }
    return 0;
#endif
}

}  // namespace scanner::distributed
