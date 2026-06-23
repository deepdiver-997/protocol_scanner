#include "scanner/core/scanner.h"
#include "scanner/common/buffer_pool.h"
#include <boost/asio.hpp>
#include <iostream>
#include <chrono>
#include <thread>
#include <fstream>

using namespace scanner;

int main() {
    std::cout << "=== TEST 3: Full Scanner pipeline ===\n" << std::endl;

    // 创建模拟配置文件——只开 SSH
    ScannerConfig config;
    config.protocol_enabled["SSH"] = true;
    config.batch_size = 10;
    config.output_dir = "./result_test";
    config.output_format = "text";
    config.output_write_mode = "stream";
    config.probe_timeout = std::chrono::milliseconds(5000);
    config.dns_timeout = std::chrono::milliseconds(3000);
    config.only_success = false;
    config.max_work_count = 10;
    config.targets_max_size = 100;
    config.result_queue_max_size = 50;
    config.io_thread_count = 2;
    // cpu_thread_count removed (single IoThreadPool only)
    config.logging_level = "DEBUG";
    config.logging_console_enabled = true;

    // 创建测试输入文件（只有一条 SSH 目标）
    std::ofstream ofs("_test_single.txt");
    ofs << "120.24.169.213\n";
    ofs.close();

    // 创建 Scanner
    Scanner scanner(config);

    // 启动扫描
    std::cout << "Starting scan..." << std::endl;
    auto start = std::chrono::steady_clock::now();
    scanner.start("_test_single.txt");

    // 等待完成
    std::cout << "Waiting for results..." << std::endl;
    auto results = scanner.get_results(std::chrono::milliseconds(15000));

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start).count();

    std::cout << "Duration: " << elapsed << "s" << std::endl;
    std::cout << "Results count: " << results.size() << std::endl;

    for (const auto& r : results) {
        std::cout << "  Target: " << r.target.get_ip_string()
                  << " protocols=" << r.protocols.size() << std::endl;
        for (const auto& p : r.protocols) {
            std::cout << "    " << p.protocol << ":"
                      << " accessible=" << (p.accessible ? "YES" : "NO")
                      << (p.accessible ? "" : " error=" + p.error)
                      << std::endl;
            if (p.accessible) {
                std::cout << "    banner: " << p.attrs.banner.substr(0, 80) << std::endl;
            }
        }
    }

    auto stats = scanner.get_statistics();
    std::cout << "\nStatistics: targets=" << stats.total_targets
              << " successful=" << stats.successful_ips << std::endl;

    // 清理
    scanner.stop();
    std::remove("_test_single.txt");

    std::cout << "\nDone." << std::endl;
    return 0;
}
