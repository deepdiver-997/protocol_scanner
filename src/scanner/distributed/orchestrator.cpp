#include "scanner/distributed/orchestrator.h"

#include "scanner/common/logger.h"
#include "scanner/distributed/task_codec.h"

#include <chrono>
#include <fstream>
#include <thread>

namespace scanner::distributed {

DistributedOrchestrator::DistributedOrchestrator(const OrchestratorConfig& dist_cfg, scanner::ScannerConfig scan_cfg)
    : dist_cfg_(dist_cfg),
      scan_cfg_(std::move(scan_cfg)),
      queue_(dist_cfg.queue_max_size),
      progress_store_(dist_cfg.state_dir) {
    if (dist_cfg_.queue_low_watermark > dist_cfg_.queue_high_watermark) {
        dist_cfg_.queue_low_watermark = dist_cfg_.queue_high_watermark;
    }
    if (dist_cfg_.topic_file.empty()) {
        dist_cfg_.topic_file = dist_cfg_.state_dir / "topic_tasks.jsonl";
    }
    restore_from_persisted_progress();
}

int DistributedOrchestrator::run_single_worker_until_empty() {
    LOG_CORE_INFO("Distributed mode start: backend={}, queue_max={}",
                  dist_cfg_.backend, dist_cfg_.queue_max_size);

    while (true) {
        queue_.reclaim_expired_leases();

        if (queue_.ready_size() < dist_cfg_.queue_low_watermark && !input_exhausted_) {
            const size_t need = dist_cfg_.queue_high_watermark - queue_.ready_size();
            load_tasks(need);
        }

        auto lease = queue_.lease_one(dist_cfg_.worker_id, dist_cfg_.lease_ms);
        if (!lease.has_value()) {
            if (input_exhausted_ && queue_.inflight_size() == 0) {
                break;
            }
            continue;
        }

        std::string err;
        const bool ok = execute_batch_with_scanner(lease->task, &err);
        if (ok) {
            if (!queue_.ack(lease->batch_id, lease->lease_token, dist_cfg_.worker_id)) {
                LOG_CORE_WARN("Ack failed for batch_id={}", lease->batch_id);
            } else {
                mark_batch_done(lease->batch_id);
                advance_watermark();
            }
        } else {
            bool moved_to_failed = false;
            if (queue_.fail_and_requeue_or_mark_failed(
                    lease->batch_id,
                    lease->lease_token,
                    dist_cfg_.worker_id,
                    &moved_to_failed)) {
                if (moved_to_failed) {
                    auto failed = queue_.pop_failed_once();
                    if (failed.has_value()) {
                        progress_store_.append_failed_batch(*failed, err);
                    }
                }
            }
        }

        persist_watermark_from_queue();
    }

    persist_watermark_from_queue();
    LOG_CORE_INFO("Distributed mode done: failed_batches={}", queue_.failed_size());
    return 0;
}

bool DistributedOrchestrator::load_tasks(size_t max_new_tasks) {
    if (dist_cfg_.backend == "kafka") {
        return load_tasks_from_kafka_topic(max_new_tasks);
    }
    return load_tasks_from_file_topic(max_new_tasks);
}

bool DistributedOrchestrator::load_tasks_from_file_topic(size_t max_new_tasks) {
    if (input_exhausted_ || max_new_tasks == 0) {
        return false;
    }

    std::ifstream ifs(dist_cfg_.topic_file);
    if (!ifs.is_open()) {
        LOG_CORE_ERROR("Cannot open topic file: {}", dist_cfg_.topic_file.string());
        input_exhausted_ = true;
        return false;
    }

    std::string line;
    uint64_t topic_line = 0;
    size_t made = 0;

    while (std::getline(ifs, line)) {
        ++topic_line;
        if (topic_line < topic_next_line_) {
            continue;
        }

        BatchTask task;
        if (!deserialize_batch_task(line, &task)) {
            topic_next_line_ = topic_line + 1;
            continue;
        }

        if (task.batch_id <= watermark_seq_minus_one_) {
            topic_next_line_ = topic_line + 1;
            continue;
        }

        task.max_attempts = dist_cfg_.max_attempts;
        if (!queue_.enqueue(std::move(task))) {
            break;
        }

        topic_next_line_ = topic_line + 1;
        ++made;
        if (made >= max_new_tasks) {
            break;
        }
    }

    if (ifs.eof()) {
        input_exhausted_ = true;
    }

    LOG_CORE_INFO("Loaded {} tasks from topic, queue_ready={}", made, queue_.ready_size());
    return made > 0;
}

bool DistributedOrchestrator::load_tasks_from_kafka_topic(size_t max_new_tasks) {
    if (input_exhausted_ || max_new_tasks == 0) {
        return false;
    }

    if (!kafka_consumer_initialized_) {
        kafka_consumer_ = std::make_unique<KafkaConsumer>(
            dist_cfg_.kafka_brokers,
            dist_cfg_.kafka_topic,
            dist_cfg_.kafka_group_id,
            dist_cfg_.kafka_client_id + "-" + dist_cfg_.worker_id);
        std::string err;
        if (!kafka_consumer_->init(&err)) {
            LOG_CORE_ERROR("Kafka consumer init failed: {}", err);
            input_exhausted_ = true;
            return false;
        }
        kafka_consumer_initialized_ = true;
    }

    std::vector<std::string> payloads;
    std::string err;
    const size_t got = kafka_consumer_->poll_batch(max_new_tasks, 200, &payloads, &err);
    if (!err.empty()) {
        LOG_CORE_WARN("Kafka poll warning: {}", err);
    }

    size_t made = 0;
    for (const auto& payload : payloads) {
        BatchTask task;
        if (!deserialize_batch_task(payload, &task)) {
            continue;
        }
        if (task.batch_id <= watermark_seq_minus_one_) {
            continue;
        }

        task.max_attempts = dist_cfg_.max_attempts;
        if (!queue_.enqueue(std::move(task))) {
            break;
        }
        ++made;
    }

    if (got == 0) {
        ++kafka_idle_polls_;
        if (kafka_idle_polls_ >= dist_cfg_.kafka_max_idle_polls) {
            input_exhausted_ = true;
            LOG_CORE_INFO("Kafka source idle for {} polls, mark exhausted", kafka_idle_polls_);
        }
        return false;
    }

    kafka_idle_polls_ = 0;

    LOG_CORE_INFO("Loaded {} tasks from kafka, queue_ready={}", made, queue_.ready_size());
    return made > 0;
}

bool DistributedOrchestrator::execute_batch_with_scanner(const BatchTask& task, std::string* err) {
    if (dist_cfg_.simulate_sleep_seconds > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(dist_cfg_.simulate_sleep_seconds));
        return true;
    }

    std::error_code ec;
    const auto batch_dir = dist_cfg_.state_dir / "batch_inputs";
    std::filesystem::create_directories(batch_dir, ec);
    if (ec) {
        if (err != nullptr) {
            *err = "create batch_inputs dir failed";
        }
        return false;
    }

    const auto batch_file = batch_dir / ("batch_" + std::to_string(task.batch_id) + ".txt");

    std::ifstream ifs(task.input_path);
    if (!ifs.is_open()) {
        if (err != nullptr) {
            *err = "open input file failed";
        }
        return false;
    }

    std::ofstream ofs(batch_file, std::ios::trunc);
    if (!ofs.is_open()) {
        if (err != nullptr) {
            *err = "create batch file failed";
        }
        return false;
    }

    std::string line;
    uint64_t line_no = 0;
    while (std::getline(ifs, line)) {
        ++line_no;
        if (line_no < task.line_begin) {
            continue;
        }
        if (line_no > task.line_end) {
            break;
        }
        ofs << line << '\n';
    }

    ofs.flush();
    if (!ofs.good()) {
        if (err != nullptr) {
            *err = "write batch file failed";
        }
        return false;
    }

    scan_cfg_.output_dir = (dist_cfg_.state_dir / "scan_results").string();

    try {
        scanner::Scanner scanner(scan_cfg_);
        scanner.start(batch_file.string());
        scanner.get_results(std::chrono::milliseconds(-1));
    } catch (const std::exception& ex) {
        if (err != nullptr) {
            *err = ex.what();
        }
        return false;
    }

    return true;
}

void DistributedOrchestrator::persist_watermark_from_queue() {
    progress_store_.persist_watermark(watermark_seq_minus_one_);
}

void DistributedOrchestrator::restore_from_persisted_progress() {
    uint64_t persisted = 0;
    if (!progress_store_.load_watermark(&persisted)) {
        return;
    }

    watermark_seq_minus_one_ = persisted;
    topic_next_line_ = watermark_seq_minus_one_ + 1;

    LOG_CORE_INFO("Recovered progress: watermark={}, topic_next_line={}",
                  watermark_seq_minus_one_, topic_next_line_);
}

void DistributedOrchestrator::mark_batch_done(uint64_t batch_id) {
    if (batch_id <= watermark_seq_minus_one_) {
        return;
    }
    done_batch_ids_.insert(batch_id);
}

void DistributedOrchestrator::advance_watermark() {
    while (done_batch_ids_.contains(watermark_seq_minus_one_ + 1)) {
        done_batch_ids_.erase(watermark_seq_minus_one_ + 1);
        ++watermark_seq_minus_one_;
    }
}

}  // namespace scanner::distributed
