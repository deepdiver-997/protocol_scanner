#include "scanner/common/logger.h"
#include "scanner/core/scanner.h"
#include "scanner/distributed/orchestrator.h"

#include <boost/program_options.hpp>

#include <iostream>

namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    scanner::ScannerConfig scan_cfg;
    scanner::distributed::OrchestratorConfig dist_cfg;

    try {
        po::options_description desc("scanner_distributed options");
        desc.add_options()
            ("help,h", "show help")
            ("state-dir", po::value<std::string>()->default_value("./result/distributed_state"), "state dir (HDFS path placeholder)")
            ("backend", po::value<std::string>(&dist_cfg.backend)->default_value("file"), "task backend: file|kafka")
            ("topic-file", po::value<std::string>()->default_value(""), "task topic file path (default: <state-dir>/topic_tasks.jsonl)")
            ("kafka-brokers", po::value<std::string>(&dist_cfg.kafka_brokers)->default_value("127.0.0.1:9092"), "kafka brokers")
            ("kafka-topic", po::value<std::string>(&dist_cfg.kafka_topic)->default_value("scanner.tasks"), "kafka topic")
            ("kafka-group-id", po::value<std::string>(&dist_cfg.kafka_group_id)->default_value("scanner-workers"), "kafka group id")
            ("kafka-client-id", po::value<std::string>(&dist_cfg.kafka_client_id)->default_value("scanner-worker"), "kafka client id")
            ("kafka-max-idle-polls", po::value<uint32_t>(&dist_cfg.kafka_max_idle_polls)->default_value(200), "mark kafka exhausted after N empty polls")
            ("worker-id", po::value<std::string>(&dist_cfg.worker_id)->default_value("worker-0"), "worker id")
            ("queue-max", po::value<size_t>(&dist_cfg.queue_max_size)->default_value(1000), "queue max size")
            ("queue-low", po::value<size_t>(&dist_cfg.queue_low_watermark)->default_value(600), "queue refill low watermark")
            ("queue-high", po::value<size_t>(&dist_cfg.queue_high_watermark)->default_value(900), "queue refill high watermark")
            ("lease-ms", po::value<uint64_t>(&dist_cfg.lease_ms)->default_value(300000), "lease ttl ms")
            ("max-attempts", po::value<uint32_t>(&dist_cfg.max_attempts)->default_value(3), "max attempts per batch")
            ("simulate-sleep-seconds", po::value<uint32_t>(&dist_cfg.simulate_sleep_seconds)->default_value(0), "simulate task execution with sleep instead of scanning")
            ("output-dir,o", po::value<std::string>(&scan_cfg.output_dir)->default_value("./result"), "scanner output dir")
            ("scan-all-ports", po::bool_switch(&scan_cfg.scan_all_ports), "scan all protocol ports")
            ("only-success", po::bool_switch(&scan_cfg.only_success), "output only successful targets");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help") != 0U) {
            std::cout << desc << std::endl;
            return 0;
        }
        po::notify(vm);

        const auto state_dir_value = vm["state-dir"].as<std::string>();
        dist_cfg.state_dir = state_dir_value;
        const auto topic_file_value = vm["topic-file"].as<std::string>();
        if (!topic_file_value.empty()) {
            dist_cfg.topic_file = topic_file_value;
        }

        scanner::Logger::get_instance().init(
            scan_cfg.logging_file_path,
            5 * 1024 * 1024,
            3,
            spdlog::level::info,
            scan_cfg.logging_console_enabled,
            scan_cfg.logging_file_enabled);

        scanner::distributed::DistributedOrchestrator orchestrator(dist_cfg, scan_cfg);
        return orchestrator.run_single_worker_until_empty();
    } catch (const std::exception& ex) {
        std::cerr << "scanner_distributed failed: " << ex.what() << std::endl;
        return 2;
    }
}
