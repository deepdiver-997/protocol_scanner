/**
 * MCP 模式专用入口 — 按需单 IP 扫描
 *
 * 特点：
 *   - 无需配置文件，所有参数由命令行控制
 *   - 默认启用全部协议，默认低并发（节省资源）
 *   - 启动极简：./scanner_mcp [--port 9081]
 *
 * Usage:
 *   echo '{"target":"1.2.3.4"}' | nc localhost 9081
 *   echo '{"get":0}'            | nc localhost 9081
 */

#include "scanner/core/scanner.h"
#include "scanner/core/mcp_mode.h"
#include "scanner/common/logger.h"
#include <iostream>
#include <cstdlib>
#include <signal.h>

namespace {

volatile bool g_shutdown = false;

void on_signal(int) { g_shutdown = true; }

// ---- 小 helper：解析整数参数 ----
int parse_int(const char* arg, const char* name) {
    try {
        int v = std::stoi(arg);
        if (v <= 0) {
            std::cerr << "FATAL: " << name << " must be positive, got " << v << std::endl;
            std::exit(1);
        }
        return v;
    } catch (...) {
        std::cerr << "FATAL: " << name << " must be an integer, got '" << arg << "'\n";
        std::exit(1);
    }
}

void print_usage(const char* prog) {
    std::cout << "MCP Scanner — on-demand single-IP probe server\n\n"
              << "Usage: " << prog << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  -p, --port PORT      TCP listen port (default: 9081)\n"
              << "  -s, --slots N        Max concurrent slots (default: 20)\n"
              << "  -t, --timeout MS     Probe timeout in ms (default: 3000)\n"
              << "  -h, --help           Show this help\n\n"
              << "Protocol (JSON over TCP):\n"
              << "  Submit: echo '{\"target\":\"1.2.3.4\"}' | nc localhost PORT\n"
              << "  Query:  echo '{\"get\":0}' | nc localhost PORT\n"
              << std::endl;
}

} // namespace

int main(int argc, char* argv[]) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    // ---- 默认参数 ----
    uint16_t port = 9081;
    size_t   slots = 20;
    int      probe_ms = 3000;

    // ---- 命令行解析 ----
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        if (a == "-p" || a == "--port") {
            if (++i >= argc) { std::cerr << "FATAL: --port requires value\n"; return 1; }
            int v = parse_int(argv[i], "--port");
            if (v < 1 || v > 65535) { std::cerr << "FATAL: port out of range\n"; return 1; }
            port = static_cast<uint16_t>(v);
        } else if (a == "-s" || a == "--slots") {
            if (++i >= argc) { std::cerr << "FATAL: --slots requires value\n"; return 1; }
            slots = static_cast<size_t>(parse_int(argv[i], "--slots"));
        } else if (a == "-t" || a == "--timeout") {
            if (++i >= argc) { std::cerr << "FATAL: --timeout requires value\n"; return 1; }
            probe_ms = parse_int(argv[i], "--timeout");
        } else {
            std::cerr << "Unknown option: " << a << "\nUse --help\n";
            return 1;
        }
    }

    // ---- 构造硬编码 ScannerConfig ----
    scanner::ScannerConfig cfg;

    // 低并发：MCP 是单 IP 按需扫描，不需要大量并发
    cfg.io_thread_count    = 4;
    cfg.max_work_count     = slots * 2;       // slots × 2 更从容
    cfg.batch_size         = static_cast<int>(slots);
    cfg.result_batch_size  = static_cast<int>(slots);
    cfg.probe_timeout      = std::chrono::milliseconds(probe_ms);
    cfg.dns_timeout        = std::chrono::milliseconds(1000);
    cfg.retry_count        = 0;               // MCP 不需要重试
    cfg.only_success       = false;
    cfg.output_dir         = "/dev/null";
    cfg.output_format      = "json";
    cfg.output_to_console  = false;

    // 禁用不需要的功能
    cfg.enable_zmap_filter      = false;
    cfg.enable_crash_inspection = false;
    cfg.enable_vendor           = true;
    cfg.targets_max_size        = slots * 10;
    cfg.result_queue_max_size   = slots * 2;

    // 启用全部协议
    cfg.enable_smtp   = true;
    cfg.enable_pop3   = true;
    cfg.enable_imap   = true;
    cfg.enable_http   = true;
    cfg.enable_ftp    = true;
    cfg.enable_telnet = true;
    cfg.enable_ssh    = true;
    cfg.enable_redis  = true;
    cfg.enable_rtsp   = true;
    cfg.enable_sip    = true;
    cfg.enable_mysql  = true;

    // ---- 初始化 logger（精简：仅控制台 warn+） ----
    scanner::Logger::get_instance().init(
        "logs/mcp.log",
        1024 * 1024 * 2, 1,
        spdlog::level::warn,
        true,   // console
        false); // no file by default

    // ---- 启动 ----
    scanner::Scanner scanner(cfg);
    scanner::MCPContext mcp(port, slots);
    scanner.set_input_producer(mcp.make_input_producer(&scanner));
    scanner.set_result_consumer(mcp.make_result_consumer(&scanner));

    std::cout << "[mcp] TCP server on port " << port
              << ", slots=" << slots
              << ", timeout=" << probe_ms << "ms"
              << std::endl;
    std::cout << "[mcp] All 11 protocols enabled" << std::endl;
    std::cout << "[mcp] echo '{\"target\":\"1.2.3.4\"}' | nc localhost " << port << std::endl;

    scanner.start("");
    while (!g_shutdown) std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}
