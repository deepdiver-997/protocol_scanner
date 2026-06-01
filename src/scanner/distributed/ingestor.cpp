#include "scanner/distributed/ingestor.h"

#include "scanner/common/logger.h"
#include "scanner/distributed/kafka_transport.h"
#include "scanner/distributed/task_codec.h"
#include "scanner/distributed/task_types.h"

#include <fstream>
#include <limits>
#include <memory>

namespace scanner::distributed {

namespace {

std::filesystem::path topic_path(const std::filesystem::path& state_dir) {
    return state_dir / "topic_tasks.jsonl";
}

std::filesystem::path chunk_dir(const std::filesystem::path& state_dir) {
    return state_dir / "chunks";
}

uint64_t find_last_batch_id(const std::filesystem::path& topic_file) {
    std::ifstream ifs(topic_file);
    if (!ifs.is_open()) {
        return 0;
    }

    uint64_t last_id = 0;
    std::string line;
    BatchTask task;
    while (std::getline(ifs, line)) {
        if (deserialize_batch_task(line, &task)) {
            last_id = task.batch_id;
        }
    }
    return last_id;
}

}  // namespace

DistributedIngestor::DistributedIngestor(IngestConfig cfg)
    : cfg_(std::move(cfg)) {}

int DistributedIngestor::run() {
    std::error_code ec;
    std::filesystem::create_directories(cfg_.state_dir, ec);
    if (ec) {
        LOG_CORE_ERROR("Failed to create state dir {}: {}", cfg_.state_dir.string(), ec.message());
        return 2;
    }
    std::filesystem::create_directories(chunk_dir(cfg_.state_dir), ec);
    if (ec) {
        LOG_CORE_ERROR("Failed to create chunk dir {}: {}", chunk_dir(cfg_.state_dir).string(), ec.message());
        return 2;
    }

    std::ifstream input(cfg_.input_path);
    if (!input.is_open()) {
        LOG_CORE_ERROR("Failed to open input file: {}", cfg_.input_path);
        return 2;
    }

    const std::filesystem::path task_topic = topic_path(cfg_.state_dir);
    uint64_t next_batch_id = 1;
    std::ios::openmode topic_mode = std::ios::out | std::ios::app;
    std::ofstream topic;
    std::unique_ptr<KafkaProducer> producer;

    const bool use_kafka = (cfg_.backend == "kafka");
    if (use_kafka) {
        producer = std::make_unique<KafkaProducer>(cfg_.kafka_brokers, cfg_.kafka_topic, cfg_.kafka_client_id);
        std::string err;
        if (!producer->init(&err)) {
            LOG_CORE_ERROR("Failed to init Kafka producer: {}", err);
            return 2;
        }
    } else {
        if (cfg_.truncate_topic) {
            topic_mode = std::ios::out | std::ios::trunc;
        } else {
            next_batch_id = find_last_batch_id(task_topic) + 1;
        }

        topic.open(task_topic, topic_mode);
        if (!topic.is_open()) {
            LOG_CORE_ERROR("Failed to open topic file: {}", task_topic.string());
            return 2;
        }
    }

    uint64_t chunk_index = 0;
    std::ofstream chunk;
    std::filesystem::path current_chunk_path;
    uint64_t current_chunk_lines = 0;

    BatchTask current_task;
    uint64_t current_cost = 0;
    uint64_t current_lines = 0;

    auto open_new_chunk = [&]() -> bool {
        if (chunk.is_open()) {
            chunk.close();
        }
        ++chunk_index;
        current_chunk_path = chunk_dir(cfg_.state_dir) / ("chunk_" + std::to_string(chunk_index) + ".txt");
        chunk.open(current_chunk_path, std::ios::out | std::ios::trunc);
        current_chunk_lines = 0;
        return chunk.is_open();
    };

    auto flush_task = [&]() {
        if (current_lines == 0) {
            return;
        }
        current_task.batch_id = next_batch_id++;
        current_task.max_attempts = 3;
        const std::string payload = serialize_batch_task(current_task);
        if (use_kafka) {
            std::string err;
            const std::string key = std::to_string(current_task.batch_id);
            if (!producer->produce(payload, key, &err)) {
                LOG_CORE_ERROR("Kafka produce failed for batch {}: {}", current_task.batch_id, err);
            }
        } else {
            topic << payload << '\n';
        }
        current_task = BatchTask{};
        current_cost = 0;
        current_lines = 0;
    };

    if (!open_new_chunk()) {
        LOG_CORE_ERROR("Failed to create first chunk file");
        return 2;
    }

    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }

        if (current_chunk_lines >= cfg_.max_chunk_lines) {
            flush_task();
            if (!open_new_chunk()) {
                LOG_CORE_ERROR("Failed to rotate chunk file");
                return 2;
            }
        }

        chunk << line << '\n';
        if (!chunk.good()) {
            LOG_CORE_ERROR("Failed writing chunk file: {}", current_chunk_path.string());
            return 2;
        }

        ++current_chunk_lines;

        if (current_lines == 0) {
            current_task.input_path = current_chunk_path.string();
            current_task.line_begin = current_chunk_lines;
            current_task.line_end = current_chunk_lines;
        } else {
            current_task.line_end = current_chunk_lines;
        }

        current_cost += estimate_line_cost(line);
        ++current_lines;

        if (current_cost >= cfg_.target_batch_cost || current_lines >= cfg_.max_batch_lines) {
            flush_task();
        }
    }

    flush_task();

    if (!use_kafka) {
        topic.flush();
        if (!topic.good()) {
            LOG_CORE_ERROR("Failed flushing topic file: {}", task_topic.string());
            return 2;
        }
    }

    if (use_kafka) {
        LOG_CORE_INFO("Ingest done: kafka_topic={}, chunks_dir={}", cfg_.kafka_topic, chunk_dir(cfg_.state_dir).string());
    } else {
        LOG_CORE_INFO("Ingest done: topic={}, chunks_dir={}", task_topic.string(), chunk_dir(cfg_.state_dir).string());
    }
    return 0;
}

uint64_t DistributedIngestor::estimate_line_cost(const std::string& line) const {
    const auto slash = line.find('/');
    if (slash == std::string::npos) {
        return 32;
    }

    int prefix = -1;
    try {
        prefix = std::stoi(line.substr(slash + 1));
    } catch (...) {
        return 32;
    }

    if (prefix < 0 || prefix > 32) {
        return 32;
    }

    const int host_bits = 32 - prefix;
    uint64_t hosts = 1;
    if (host_bits >= 20) {
        hosts = 1ULL << 20;
    } else {
        hosts = 1ULL << host_bits;
    }

    uint64_t cost = hosts / 256;
    if (cost == 0) {
        cost = 1;
    }
    return cost;
}

}  // namespace scanner::distributed
