#pragma once

#include "scanner/core/scanner.h"
#include "scanner/distributed/distributed_queue.h"
#include "scanner/distributed/kafka_transport.h"
#include "scanner/distributed/progress_store.h"

#include <filesystem>
#include <memory>
#include <string>
#include <unordered_set>

namespace scanner::distributed {

struct OrchestratorConfig {
    std::filesystem::path state_dir = "./result/distributed_state";
    std::filesystem::path topic_file = "";
    std::string backend = "file";  // file | kafka
    std::string kafka_brokers = "127.0.0.1:9092";
    std::string kafka_topic = "scanner.tasks";
    std::string kafka_group_id = "scanner-workers";
    std::string kafka_client_id = "scanner-worker";
    uint32_t kafka_max_idle_polls = 200;

    size_t queue_max_size = 1000;
    size_t queue_low_watermark = 600;
    size_t queue_high_watermark = 900;

    uint64_t lease_ms = 5 * 60 * 1000;
    uint32_t max_attempts = 3;
    uint32_t simulate_sleep_seconds = 0;

    std::string worker_id = "worker-0";
};

class DistributedOrchestrator {
public:
    DistributedOrchestrator(const OrchestratorConfig& dist_cfg, scanner::ScannerConfig scan_cfg);

    // 单机模拟分布式调度：持续补货 -> 拉取任务 -> 写结果 -> ack/nack。
    int run_single_worker_until_empty();

private:
    bool load_tasks(size_t max_new_tasks);
    bool load_tasks_from_file_topic(size_t max_new_tasks);
    bool load_tasks_from_kafka_topic(size_t max_new_tasks);
    bool execute_batch_with_scanner(const BatchTask& task, std::string* err);
    void persist_watermark_from_queue();
    void restore_from_persisted_progress();
    void mark_batch_done(uint64_t batch_id);
    void advance_watermark();

    OrchestratorConfig dist_cfg_;
    scanner::ScannerConfig scan_cfg_;

    DistributedBatchQueue queue_;
    HdfsProgressStore progress_store_;

    uint64_t watermark_seq_minus_one_ = 0;
    std::unordered_set<uint64_t> done_batch_ids_;
    uint64_t topic_next_line_ = 1;
    bool kafka_consumer_initialized_ = false;
    std::unique_ptr<KafkaConsumer> kafka_consumer_;
    uint32_t kafka_idle_polls_ = 0;
    bool input_exhausted_ = false;
};

}  // namespace scanner::distributed
