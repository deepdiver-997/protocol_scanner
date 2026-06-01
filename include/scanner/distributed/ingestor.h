#pragma once

#include <filesystem>
#include <string>

namespace scanner::distributed {

struct IngestConfig {
    std::string input_path;
    std::filesystem::path state_dir = "./result/distributed_state";
    std::string backend = "file";  // file | kafka
    std::string kafka_brokers = "127.0.0.1:9092";
    std::string kafka_topic = "scanner.tasks";
    std::string kafka_client_id = "scanner-ingest";

    uint64_t target_batch_cost = 2000;
    uint64_t max_batch_lines = 20000;
    uint64_t max_chunk_lines = 200000;

    bool truncate_topic = true;
};

class DistributedIngestor {
public:
    explicit DistributedIngestor(IngestConfig cfg);

    // 切分输入并发布任务到本地 topic 文件（Kafka 模拟）。
    int run();

private:
    uint64_t estimate_line_cost(const std::string& line) const;

    IngestConfig cfg_;
};

}  // namespace scanner::distributed
