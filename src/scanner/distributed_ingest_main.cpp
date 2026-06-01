#include "scanner/common/logger.h"
#include "scanner/distributed/ingestor.h"

#include <boost/program_options.hpp>

#include <iostream>

namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    scanner::distributed::IngestConfig cfg;

    try {
        po::options_description desc("scanner_ingest options");
        desc.add_options()
            ("help,h", "show help")
            ("input,i", po::value<std::string>(&cfg.input_path)->required(), "input CIDR/domain file")
            ("state-dir", po::value<std::string>()->default_value("./result/distributed_state"), "state directory")
            ("backend", po::value<std::string>(&cfg.backend)->default_value("file"), "task backend: file|kafka")
            ("kafka-brokers", po::value<std::string>(&cfg.kafka_brokers)->default_value("127.0.0.1:9092"), "kafka brokers")
            ("kafka-topic", po::value<std::string>(&cfg.kafka_topic)->default_value("scanner.tasks"), "kafka topic")
            ("kafka-client-id", po::value<std::string>(&cfg.kafka_client_id)->default_value("scanner-ingest"), "kafka client id")
            ("target-batch-cost", po::value<uint64_t>(&cfg.target_batch_cost)->default_value(2000), "target estimated cost per batch")
            ("max-batch-lines", po::value<uint64_t>(&cfg.max_batch_lines)->default_value(20000), "max lines per batch")
            ("max-chunk-lines", po::value<uint64_t>(&cfg.max_chunk_lines)->default_value(200000), "max lines per chunk file")
            ("append-topic", po::bool_switch()->default_value(false), "append to existing topic file instead of truncating");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help") != 0U) {
            std::cout << desc << std::endl;
            return 0;
        }
        po::notify(vm);

        cfg.state_dir = vm["state-dir"].as<std::string>();
        cfg.truncate_topic = !vm["append-topic"].as<bool>();

        scanner::Logger::get_instance().init();
        scanner::distributed::DistributedIngestor ingestor(cfg);
        return ingestor.run();
    } catch (const std::exception& ex) {
        std::cerr << "scanner_ingest failed: " << ex.what() << std::endl;
        return 2;
    }
}
