#include "scanner/protocols/ssh_protocol.h"
#include "scanner/common/buffer_pool.h"
#include "scanner/core/session.h"
#include "scanner/common/thread_pool.h"
#include "scanner/common/io_thread_pool.h"
#include "scanner/dns/dns_resolver.h"
#include <boost/asio.hpp>
#include <iostream>
#include <chrono>
#include <atomic>

using namespace scanner;
namespace asio = boost::asio;

void test_direct_probe() {
    std::cout << "\n=== TEST 1: Direct async_probe call ===" << std::endl;

    asio::io_context io;
    bool done = false;
    ProtocolResult result;

    SshProtocol ssh;
    ssh.async_probe(
        "120.24.169.213", "120.24.169.213", 22, Timeout(5000),
        io.get_executor(),
        [&](ProtocolResult&& r) {
            result = std::move(r);
            done = true;
        }
    );

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(6);
    while (!done && std::chrono::steady_clock::now() < deadline) {
        io.run_one();
    }

    std::cout << "  Accessible: " << (result.accessible ? "YES" : "NO") << std::endl;
    if (result.accessible) {
        std::cout << "  Banner: " << result.attrs.banner.substr(0, 80) << std::endl;
        std::cout << "  SSH: " << result.attrs.ssh.software << " " << result.attrs.ssh.version << std::endl;
    } else {
        std::cout << "  Error: " << result.error << std::endl;
    }
}

void test_session_flow() {
    std::cout << "\n=== TEST 2: ScanSession lifecycle ===" << std::endl;

    // 基础设施
    IoThreadPool io_pool(1);
    ThreadPool cpu_pool(1);

    // 协议
    std::vector<std::unique_ptr<IProtocol>> protocols;
    protocols.push_back(std::make_unique<SshProtocol>());

    // DNS resolver (dummy — 我们不依赖DNS)
    auto resolver = DnsResolverFactory::create(DnsResolverFactory::ResolverType::C_ARES);

    // target: 直接指定IP
    ScanTarget target;
    target.set_ip("120.24.169.213");
    target.seq = 1;
    std::cout << "  Target IP: " << target.get_ip_string()
              << " (ip_uint=" << target.ip_uint << ")" << std::endl;

    // 创建Session
    auto session = std::make_shared<ScanSession>(
        target,
        std::shared_ptr<IDnsResolver>(resolver.get(), [](IDnsResolver*){}),
        Timeout(3000), Timeout(5000),
        ScanSession::ProbeMode::ProtocolDefaults,
        protocols
    );

    std::cout << "  Session created."
              << " idle=" << session->is_idle()
              << " tasks=" << session->tasks_total() << std::endl;

    // 启动 probes
    auto exec = io_pool.get_tracking_executor();
    int started = session->start_all_pending_probes(
        protocols, cpu_pool, exec.underlying_executor(), Timeout(5000), 10
    );
    std::cout << "  Probes started: " << started
              << " tasks_total=" << session->tasks_total() << std::endl;

    if (started == 0) {
        std::cout << "  ERROR: No probes started! Check session state." << std::endl;
        std::cout << "  available_ports: ";
        for (auto p : session->available_ports()) std::cout << p << " ";
        std::cout << std::endl;
    }

    // 等待完成（最多8秒）
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (!session->ready_to_release() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::cout << "  Completed: " << (session->ready_to_release() ? "YES" : "NO (timeout)")
              << " tasks_done=" << session->tasks_completed()
              << "/" << session->tasks_total() << std::endl;

    // 收集结果
    auto results = session->protocol_results();
    std::cout << "  Results: " << results.size() << " protocols" << std::endl;
    for (const auto& r : results) {
        std::cout << "    " << r.protocol << ":"
                  << " accessible=" << (r.accessible ? "YES" : "NO")
                  << (r.accessible ? "" : " error=" + r.error)
                  << std::endl;
        if (r.accessible && !r.attrs.banner.empty()) {
            std::cout << "    banner: " << r.attrs.banner.substr(0, 80) << std::endl;
        }
    }

    io_pool.shutdown();
    cpu_pool.shutdown();
}

int main() {
    std::cout << "Protocol Scanner - Diagnostic Tests" << std::endl;
    std::cout << "===================================" << std::endl;

    test_direct_probe();
    test_session_flow();

    std::cout << "\nDone." << std::endl;
    return 0;
}
