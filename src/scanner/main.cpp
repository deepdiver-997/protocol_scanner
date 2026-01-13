// #include "scanner/core/scanner.h"  // TODO: 实现 scanner.cpp 后启用
// #include "scanner/vendor/vendor_detector.h"  // TODO: 实现 vendor_detector.cpp 后启用
#include "scanner/output/result_handler.h"
#include "scanner/protocols/protocol_base.h"
#include "scanner/core/scanner.h"
#include "scanner/dns/dns_resolver.h"
#include "scanner/common/logger.h"
#include <boost/program_options.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <chrono>
#include <filesystem>
#include <sstream>
#include <signal.h>

namespace po = boost::program_options;
namespace scanner {

using namespace std;
using namespace std::chrono;

// =====================
// 全局变量
// =====================

static volatile bool g_shutdown_requested = false;

// =====================
// 信号处理
// =====================

void signal_handler(int signum) {
    LOG_CORE_INFO("Received signal {}, shutting down gracefully...", signum);
    g_shutdown_requested = true;
}

void setup_signal_handlers() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
}

// =====================
// 配置加载器
// =====================

ScannerConfig load_config(const string& config_file) {
    ScannerConfig config;

    // 尝试从 JSON 文件加载配置
    std::ifstream ifs(config_file);
    if (ifs.is_open()) {
        try {
            nlohmann::json j = nlohmann::json::parse(ifs);
            ifs.close();

            // ===== Scanner 配置 =====
            if (j.contains("scanner")) {
                auto s = j["scanner"];
                if (s.contains("io_thread_count")) config.io_thread_count = s["io_thread_count"];
                if (s.contains("cpu_thread_count")) config.cpu_thread_count = s["cpu_thread_count"];
                if (s.contains("thread_count")) config.thread_count = s["thread_count"];
                if (s.contains("batch_size")) config.batch_size = s["batch_size"];
                if (s.contains("dns_timeout_ms")) config.dns_timeout = std::chrono::milliseconds(s["dns_timeout_ms"]);
                if (s.contains("probe_timeout_ms")) config.probe_timeout = std::chrono::milliseconds(s["probe_timeout_ms"]);
                if (s.contains("retry_count")) config.retry_count = s["retry_count"];
                if (s.contains("only_success")) config.only_success = s["only_success"];
                if (s.contains("max_work_count")) config.max_work_count = s["max_work_count"];
            }

            // ===== Protocols 配置 =====
            if (j.contains("protocols")) {
                auto p = j["protocols"];
                if (p.contains("SMTP") && p["SMTP"].contains("enabled")) config.enable_smtp = p["SMTP"]["enabled"];
                if (p.contains("POP3") && p["POP3"].contains("enabled")) config.enable_pop3 = p["POP3"]["enabled"];
                if (p.contains("IMAP") && p["IMAP"].contains("enabled")) config.enable_imap = p["IMAP"]["enabled"];
                if (p.contains("HTTP") && p["HTTP"].contains("enabled")) config.enable_http = p["HTTP"]["enabled"];
                if (p.contains("FTP") && p["FTP"].contains("enabled")) config.enable_ftp = p["FTP"]["enabled"];
                if (p.contains("TELNET") && p["TELNET"].contains("enabled")) config.enable_telnet = p["TELNET"]["enabled"];
                if (p.contains("SSH") && p["SSH"].contains("enabled")) config.enable_ssh = p["SSH"]["enabled"];
            }

            // ===== DNS 配置 =====
            if (j.contains("dns")) {
                auto d = j["dns"];
                if (d.contains("resolver_type")) config.dns_resolver_type = d["resolver_type"];
                if (d.contains("max_mx_records")) config.dns_max_mx_records = d["max_mx_records"];
                if (d.contains("timeout_ms")) config.dns_config_timeout = std::chrono::milliseconds(d["timeout_ms"]);
            }

            // ===== Output 配置 =====
            if (j.contains("output")) {
                auto o = j["output"];
                if (o.contains("format")) {
                    auto fmt = o["format"];
                    if (fmt.is_array()) {
                        config.output_formats.clear();
                        for (const auto& f : fmt) {
                            config.output_formats.push_back(f.get<std::string>());
                        }
                    } else if (fmt.is_string()) {
                        config.output_formats.clear();
                        config.output_formats.push_back(fmt.get<std::string>());
                    }
                }
                if (o.contains("directory")) config.output_dir = o["directory"];
                if (o.contains("write_mode")) {
                    auto mode = o["write_mode"].get<std::string>();
                    if (mode == "stream" || mode == "final") {
                        config.output_write_mode = mode;
                    } else {
                        LOG_CORE_WARN("Invalid write_mode '{}', fallback to 'stream'", mode);
                        config.output_write_mode = "stream";
                    }
                }
                if (o.contains("enable_json")) config.output_enable_json = o["enable_json"];
                if (o.contains("enable_csv")) config.output_enable_csv = o["enable_csv"];
                if (o.contains("enable_report")) config.output_enable_report = o["enable_report"];
                if (o.contains("to_console")) config.output_to_console = o["to_console"];
            }

            // ===== Logging 配置 =====
            if (j.contains("logging")) {
                auto l = j["logging"];
                if (l.contains("level")) config.logging_level = l["level"];
                if (l.contains("console_enabled")) config.logging_console_enabled = l["console_enabled"];
                if (l.contains("file_enabled")) config.logging_file_enabled = l["file_enabled"];
                if (l.contains("file_path")) config.logging_file_path = l["file_path"];
            }

            // ===== Vendor 配置 =====
            if (j.contains("vendor")) {
                auto v = j["vendor"];
                if (v.contains("enabled")) config.enable_vendor = v["enabled"];
                if (v.contains("pattern_file")) config.vendor_pattern_file = v["pattern_file"];
                if (v.contains("similarity_threshold")) config.vendor_similarity_threshold = v["similarity_threshold"];
            }

            LOG_CORE_INFO("Loaded config from {}", config_file);

        } catch (const nlohmann::json::exception& e) {
            LOG_CORE_WARN("Failed to parse config file '{}': {}", config_file, e.what());
            LOG_CORE_WARN("Using default configuration");
        }
    } else {
        LOG_CORE_WARN("Config file '{}' not found, using defaults", config_file);
    }

    return config;
}

// =====================
// 打印使用说明
// =====================

void print_usage(const char* program_name, const po::options_description& options) {
    cout << "Protocol Scanner v1.0.0" << endl;
    cout << "Multi-protocol network scanner for email services" << endl;
    cout << endl;
    cout << "Usage:" << endl;
    cout << "  " << program_name << " [OPTIONS] --domains <file>" << endl;
    cout << endl;
    cout << options << endl;
    cout << "Examples:" << endl;
    cout << "  # Scan with default config" << endl;
    cout << "  " << program_name << " --domains domains.txt --scan" << endl;
    cout << "  # Specify IO and CPU thread counts separately" << endl;
    cout << "  " << program_name << " --domains domains.txt --scan --io-threads 12 --cpu-threads 2" << endl;
    cout << "  # Legacy: single thread count" << endl;
    cout << "  " << program_name << " --domains domains.txt --threads 8" << endl;
    cout << endl;
    cout << "  # Scan with specific protocols" << endl;
    cout << "  " << program_name << " --domains domains.txt --protocols SMTP,IMAP" << endl;
    cout << endl;
    cout << "  # Output JSON format" << endl;
    cout << "  " << program_name << " --domains domains.txt --format json" << endl;
    cout << endl;
}

// =====================
// 主函数
// =====================

int main(int argc, char* argv[]) {
    // 设置信号处理
    setup_signal_handlers();

    try {
        // 命令行参数
        po::options_description options("Options");
        options.add_options()
            ("help,h", "Show help message")
            ("version,v", "Show version information")
            ("domains,d", po::value<string>(), "Input file containing domain names")
            ("dns-test", "Run DNS resolution test mode (temporary)")
            ("scan", "Run protocol scan and print results to stdout")
            ("output,o", po::value<string>(), "Output directory (default: ./result)")
            ("threads,t", po::value<int>()->default_value(4), "Number of threads (deprecated, use --io-threads)")
            ("io-threads", po::value<int>(), "IO thread pool size (network I/O)")
            ("cpu-threads", po::value<int>(), "CPU thread pool size (protocol processing)")
            ("config,c", po::value<string>(), "Configuration file")
            ("protocols,p", po::value<string>(),
             "Comma-separated list of protocols (SMTP,POP3,IMAP,HTTP,FTP,TELNET,SSH)")
            ("format,f", po::value<string>()->default_value("text"),
             "Output format (text,json,csv,report)")
            ("only-success", "Only output successful probes (hide failures)")
            ("no-smtp", "Disable SMTP scanning")
            ("no-pop3", "Disable POP3 scanning")
            ("no-imap", "Disable IMAP scanning")
            ("enable-http", "Enable HTTP scanning")
            ("enable-ftp", "Enable FTP scanning")
            ("enable-telnet", "Enable Telnet scanning")
            ("no-ftp", "Disable FTP scanning")
            ("enable-ssh", "Enable SSH scanning")
            ("scan-all-ports", "Scan all available ports instead of protocol defaults")
            ("vendor-file", po::value<string>(),
             "Vendor pattern file (default: ./config/vendors.json)")
            ("verbose", "Enable verbose output")
            ("quiet,q", "Suppress non-error output")
            ("timeout", po::value<int>()->default_value(60000),
             "Probe timeout in milliseconds")
            ("batch-size", po::value<int>()->default_value(10000),
             "Batch size for processing");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, options), vm);
        po::notify(vm);

        // 显示帮助
        if (vm.count("help")) {
            print_usage(argv[0], options);
            return 0;
        }

        // 显示版本
        if (vm.count("version")) {
            cout << "Protocol Scanner v1.0.0" << endl;
            cout << "Built with: C++20, Boost.Asio, OpenMP" << endl;
            return 0;
        }

        // 检查必需参数
        if (!vm.count("domains")) {
            cerr << "Error: --domains option is required" << endl;
            cerr << "Use --help for usage information" << endl;
            return 1;
        }

        // 临时 DNS 测试模式
        if (vm.count("dns-test")) {
            LOG_CORE_INFO("Running DNS test mode...");
            scanner::Logger::get_instance().init();
            scanner::Logger::get_instance().set_level(spdlog::level::info);

            string domains_file = vm["domains"].as<string>();
            auto domains = load_domains(domains_file);

            if (domains.empty()) {
                cerr << "No domains loaded from " << domains_file << endl;
                return 1;
            }

            DnsResolverFactory factory;
            auto resolver = factory.create(DnsResolverFactory::ResolverType::C_ARES);

            cout << "\nDNS Resolution Test Results:" << endl;
            cout << "============================" << endl;

            for (const auto& domain : domains) {
                auto result = resolver->resolve(domain);
                if (result.success) {
                    cout << domain << " -> " << result.ip;
                    if (!result.dns_records.empty()) {
                        cout << " (MX: " << result.dns_records.size() << ")";
                    }
                    cout << endl;
                } else {
                    cout << domain << " -> ERROR: " << result.error << endl;
                }
            }

            return 0;
        }

        // 加载配置：优先使用 --config 指定的文件，如果没有则使用默认路径
        string default_config_path = "./config/scanner_config.json";
        string config_file_to_load = "";

        if (vm.count("config")) {
            config_file_to_load = vm["config"].as<string>();
            if (!std::filesystem::exists(config_file_to_load)) {
                LOG_CORE_WARN("Specified config file '{}' not found, falling back to default '{}'", 
                             config_file_to_load, default_config_path);
                config_file_to_load = default_config_path;
            }
        } else {
            config_file_to_load = default_config_path;
        }

        ScannerConfig config = load_config(config_file_to_load);

        // 覆盖配置（命令行参数优先）
        if (vm.count("only-success")) {
            config.only_success = true;
        }
        
        bool has_io_threads = vm.count("io-threads");
        bool has_cpu_threads = vm.count("cpu-threads");

        if (has_io_threads) {
            config.io_thread_count = vm["io-threads"].as<int>();
        }
        if (has_cpu_threads) {
            config.cpu_thread_count = vm["cpu-threads"].as<int>();
        }

        // 如果显式传递 --threads 且没有分别指定 io/cpu 线程，使用向后兼容逻辑
        // 需要检查 --threads 的原始值是否为默认值
        const auto& threads_arg = vm["threads"];
        bool is_threads_explicit = !threads_arg.defaulted();

        if (is_threads_explicit && !has_io_threads && !has_cpu_threads) {
            // 向后兼容：--threads 同时设置 io 和 cpu 线程数
            int threads = vm["threads"].as<int>();
            config.thread_count = threads;
            config.io_thread_count = threads;
            config.cpu_thread_count = std::max(1, threads / 4);
            LOG_CORE_INFO("Using legacy --threads={} setting both IO and CPU pools", threads);
        }

        if (vm["timeout"].defaulted() == false) {
            config.probe_timeout = Timeout(vm["timeout"].as<int>());
        }
        if (vm["batch-size"].defaulted() == false) {
            config.batch_size = vm["batch-size"].as<int>();
        }
        if (vm.count("no-smtp")) config.enable_smtp = false;
        if (vm.count("no-pop3")) config.enable_pop3 = false;
        if (vm.count("no-imap")) config.enable_imap = false;
        if (vm.count("enable-http")) config.enable_http = true;
        if (vm.count("enable-telnet")) config.enable_telnet = true;
        if (vm.count("enable-ssh")) config.enable_ssh = true;
        if (vm.count("protocols")) {
            config.custom_protocols.clear();
            string protos = vm["protocols"].as<string>();
            size_t pos = 0;
            while ((pos = protos.find(',')) != string::npos) {
                config.custom_protocols.push_back(protos.substr(0, pos));
                protos.erase(0, pos + 1);
            }
            config.custom_protocols.push_back(protos);
            // 应用到启用开关：如指定协议则仅启用这些
            config.enable_smtp = false;
            config.enable_pop3 = false;
            config.enable_imap = false;
            config.enable_http = false;
            config.enable_telnet = false;
            config.enable_ssh = false;
            for (auto& p : config.custom_protocols) {
                if (p == "SMTP") config.enable_smtp = true;
                else if (p == "POP3") config.enable_pop3 = true;
                else if (p == "IMAP") config.enable_imap = true;
                else if (p == "HTTP") config.enable_http = true;
                else if (p == "TELNET") config.enable_telnet = true;
                else if (p == "SSH") config.enable_ssh = true;
            }
        }
        if (vm.count("scan-all-ports")) {
            config.scan_all_ports = true;
        }

        // 覆盖输出目录与格式
        if (vm.count("output")) {
            config.output_dir = vm["output"].as<string>();
        }
        if (vm.count("format")) {
            auto fmt = vm["format"].as<string>();
            // 兼容简写：txt -> text
            if (fmt == "txt") fmt = "text";
            config.output_format = fmt;
        }

        // 设置日志级别
        scanner::Logger::get_instance().init();
        if (vm.count("verbose")) {
            scanner::Logger::get_instance().set_level(spdlog::level::debug);
        } else if (vm.count("quiet")) {
            scanner::Logger::get_instance().set_level(spdlog::level::err);
        } else {
            scanner::Logger::get_instance().set_level(spdlog::level::info);
        }

        // 加载域名列表
        string domains_file = vm["domains"].as<string>();
        auto domains = load_domains(domains_file);

        if (domains.empty()) {
            LOG_CORE_ERROR("No domains loaded from {}", domains_file);
            return 1;
        }

        LOG_CORE_INFO("Loaded {} domains from {}", domains.size(), domains_file);

        // 显示最终配置（在命令行参数覆盖后）
        if (config.io_thread_count > 0 && config.cpu_thread_count > 0) {
            LOG_CORE_INFO("Thread pools: IO={}, CPU={}", config.io_thread_count, config.cpu_thread_count);
        } else {
            LOG_CORE_INFO("Thread count: {} (legacy mode)", config.thread_count);
        }

        // 初始化 Vendor Detector
        std::unique_ptr<VendorDetector> vendor_detector;
        // 默认使用配置文件指定的 pattern_file；未指定时回退到 output_dir/vendors.json
        string vendor_file = config.vendor_pattern_file.empty()
            ? (config.output_dir + "/vendors.json")
            : config.vendor_pattern_file;
        if (config.enable_vendor) {
            vendor_detector = std::make_unique<VendorDetector>();
            if (vm.count("vendor-file")) {
                vendor_file = vm["vendor-file"].as<string>();
            }
            if (!vendor_detector->load_patterns(vendor_file)) {
                LOG_CORE_WARN("Failed to load vendor patterns from {}", vendor_file);
                vendor_detector = nullptr;
            }
        }

        if (vm.count("scan")) {
            // 异步扫描模式
            LOG_CORE_INFO("Starting scan with input source: {}", domains_file);
            Scanner scanner(config);
            auto start_tp = std::chrono::steady_clock::now();
            const bool streaming_mode = (config.output_write_mode == "stream");
            
            // 启动扫描（异步）
            scanner.start(domains_file);
            
            // 等待完成并获取结果（最多等待 1 小时）
            auto reports = scanner.get_results(std::chrono::milliseconds(-1));
            
            auto end_tp = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_tp - start_tp);
            (void)duration; // silence unused when logging disabled
            LOG_CORE_INFO("Scan completed in {} seconds", duration.count());

            // Vendor 检测
            if (vendor_detector) {
                for (auto& rep : reports) {
                    for (auto& pr : rep.protocols) {
                        if (pr.accessible && !pr.attrs.banner.empty()) {
                            int vendor_id = vendor_detector->detect_vendor(pr.attrs.banner);
                            if (vendor_id > 0) {
                                pr.attrs.vendor = vendor_detector->get_vendor_name(vendor_id);
                                vendor_detector->update_matched_ids(vendor_id,
                                    std::hash<std::string>{}(pr.host + ":" + std::to_string(pr.port)));
                            }
                        }
                    }
                }
            }

            // 检查是否只输出成功结果
            bool only_success = config.only_success;

            // 使用 ResultHandler 生成结果
            ResultHandler rh;
            rh.set_format(config.output_format == "json" ? OutputFormat::JSON :
                         config.output_format == "csv" ? OutputFormat::CSV :
                         config.output_format == "report" ? OutputFormat::REPORT : OutputFormat::TEXT);
            rh.set_only_success(only_success);

            std::ostringstream oss;
            if (!streaming_mode || config.output_to_console) {
                oss << "\nScan Results\n";
                oss << "============\n";
                oss << rh.reports_to_string(reports);

                // 输出 vendor 统计
                if (vendor_detector) {
                    auto stats = vendor_detector->get_statistics();
                    if (!stats.empty()) {
                        for (const auto& s : stats) {
                            if (s.count > 0) {
                                oss << s.name << ": " << s.count << " servers\n";
                            }
                        }
                    }
                }

                if (!streaming_mode) {
                    auto stats = scanner.get_statistics();
                    oss << "\n================== Scan Statistics ==================\n";
                    oss << "Total Targets: " << stats.total_targets << "\n";
                    oss << "Successful IPs: " << stats.successful_ips << "\n";
                    oss << "\nProtocol Success Counts:\n";
                    for (const auto& [protocol, count] : stats.protocol_counts) {
                        oss << "  " << protocol << ": " << count << "\n";
                    }
                    oss << "\nTotal Time: " << stats.total_time.count() << " ms\n";
                    oss << "====================================================\n";
                }

                // 将结果写到控制台
                if (config.output_to_console) {
                    std::cout << oss.str();
                }
            }

            // 如果指定了输出目录，则保存到文件（仅 final 模式防止与流式输出冲突）
            if (!streaming_mode && vm.count("output")) {
                std::error_code ec;
                std::filesystem::create_directories(config.output_dir, ec);
                if (ec) {
                    LOG_CORE_WARN("Failed to create output dir '{}': {}", config.output_dir, ec.message());
                }

                std::string ext = "txt";
                if (config.output_format == "json") ext = "json";
                else if (config.output_format == "csv") ext = "csv";
                else ext = "txt";

                std::string out_path = config.output_dir;
                if (!out_path.empty() && out_path.back() != '/') out_path += "/";
                out_path += "scan_results." + ext;

                std::ofstream ofs(out_path);
                if (!ofs) {
                    LOG_CORE_ERROR("Cannot open output file: {}", out_path);
                } else {
                    ofs << oss.str();
                    ofs.close();
                    LOG_CORE_INFO("Results saved to {}", out_path);
                }
            } else if (streaming_mode) {
                LOG_CORE_INFO("Streaming output mode: results are written by the result handler thread to {}/scan_results.txt", config.output_dir);
            }

            if (vendor_detector) {
                vendor_detector->save_patterns(vendor_file);
            }

            return 0;
        }

        // 默认路径：当前仅支持 DNS 测试或 --scan
        LOG_CORE_WARN("No mode selected. Use --dns-test or --scan.");
        return 1;

    } catch (const std::exception& e) {
        LOG_CORE_CRITICAL("Fatal error: {}", e.what());
        return 1;
    }
}

} // namespace scanner

int main(int argc, char* argv[]) {
    return scanner::main(argc, argv);
}
