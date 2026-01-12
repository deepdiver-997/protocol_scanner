#ifndef scanner_LOGGER_H
#define scanner_LOGGER_H

#ifdef SCANNER_DISABLE_LOGGING

#include <memory>
#include <string>

namespace scanner {

enum class LogModule {
    CORE,
    DNS,
    NETWORK,
    SMTP,
    POP3,
    IMAP,
    HTTP,
    VENDOR,
    OUTPUT,
    PORT_SCAN,
    FILE_IO,
};

class Logger {
public:
    static Logger& get_instance() { static Logger inst; return inst; }
    void init(const std::string& = "", size_t = 0, size_t = 0, int = 0) {}
    void set_level(int) {}
    void set_module_level(LogModule, int) {}
    void flush() {}
    void shutdown() {}
};

inline std::shared_ptr<void> log(LogModule) { return nullptr; }
inline void set_log_level(int) {}
inline void set_module_log_level(LogModule, int) {}

} // namespace scanner

// 提供最小的 spdlog::level 定义以兼容调用方
namespace spdlog { namespace level {
    enum level_enum { trace, debug, info, warn, err, critical, off, n_levels };
} }

// 全量禁用日志输出宏
#define LOG_CORE_TRACE(...)
#define LOG_CORE_DEBUG(...)
#define LOG_CORE_INFO(...)
#define LOG_CORE_WARN(...)
#define LOG_CORE_ERROR(...)
#define LOG_CORE_CRITICAL(...)

#define LOG_DNS_TRACE(...)
#define LOG_DNS_DEBUG(...)
#define LOG_DNS_INFO(...)
#define LOG_DNS_WARN(...)
#define LOG_DNS_ERROR(...)
#define LOG_DNS_CRITICAL(...)

#define LOG_NETWORK_TRACE(...)
#define LOG_NETWORK_DEBUG(...)
#define LOG_NETWORK_INFO(...)
#define LOG_NETWORK_WARN(...)
#define LOG_NETWORK_ERROR(...)
#define LOG_NETWORK_CRITICAL(...)

#define LOG_SMTP_TRACE(...)
#define LOG_SMTP_DEBUG(...)
#define LOG_SMTP_INFO(...)
#define LOG_SMTP_WARN(...)
#define LOG_SMTP_ERROR(...)
#define LOG_SMTP_CRITICAL(...)

#define LOG_POP3_TRACE(...)
#define LOG_POP3_DEBUG(...)
#define LOG_POP3_INFO(...)
#define LOG_POP3_WARN(...)
#define LOG_POP3_ERROR(...)
#define LOG_POP3_CRITICAL(...)

#define LOG_IMAP_TRACE(...)
#define LOG_IMAP_DEBUG(...)
#define LOG_IMAP_INFO(...)
#define LOG_IMAP_WARN(...)
#define LOG_IMAP_ERROR(...)
#define LOG_IMAP_CRITICAL(...)

#define LOG_HTTP_TRACE(...)
#define LOG_HTTP_DEBUG(...)
#define LOG_HTTP_INFO(...)
#define LOG_HTTP_WARN(...)
#define LOG_HTTP_ERROR(...)
#define LOG_HTTP_CRITICAL(...)

#define LOG_VENDOR_TRACE(...)
#define LOG_VENDOR_DEBUG(...)
#define LOG_VENDOR_INFO(...)
#define LOG_VENDOR_WARN(...)
#define LOG_VENDOR_ERROR(...)
#define LOG_VENDOR_CRITICAL(...)

#define LOG_OUTPUT_TRACE(...)
#define LOG_OUTPUT_DEBUG(...)
#define LOG_OUTPUT_INFO(...)
#define LOG_OUTPUT_WARN(...)
#define LOG_OUTPUT_ERROR(...)
#define LOG_OUTPUT_CRITICAL(...)

#define LOG_PORT_SCAN_TRACE(...)
#define LOG_PORT_SCAN_DEBUG(...)
#define LOG_PORT_SCAN_INFO(...)
#define LOG_PORT_SCAN_WARN(...)
#define LOG_PORT_SCAN_ERROR(...)
#define LOG_PORT_SCAN_CRITICAL(...)

#define LOG_FILE_IO_TRACE(...)
#define LOG_FILE_IO_DEBUG(...)
#define LOG_FILE_IO_INFO(...)
#define LOG_FILE_IO_WARN(...)
#define LOG_FILE_IO_ERROR(...)
#define LOG_FILE_IO_CRITICAL(...)

#else // SCANNER_DISABLE_LOGGING

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <array>
#include <filesystem>

namespace scanner {

// 日志模块定义
enum class LogModule {
    CORE,          // 核心模块日志（Scanner 主逻辑）
    DNS,           // DNS 解析日志
    NETWORK,       // 网络连接日志
    SMTP,          // SMTP 协议日志
    POP3,          // POP3 协议日志
    IMAP,          // IMAP 协议日志
    HTTP,          // HTTP 协议日志
    VENDOR,        // 服务商标识日志
    OUTPUT,        // 结果输出日志
    PORT_SCAN,     // 端口扫描日志
    FILE_IO,       // 文件 I/O 日志
};

// 日志系统管理类
class Logger {
public:
    static Logger& get_instance() {
        static Logger instance;
        return instance;
    }

    // 初始化日志系统
    void init(const std::string& log_file = "logs/scanner.log",
              size_t max_file_size = 1024 * 1024 * 5,  // 5MB
              size_t max_files = 3,
              spdlog::level::level_enum level = spdlog::level::info) {
        if (m_initialized) {
            return;
        }

        try {
            // 确保日志目录存在
            std::filesystem::path log_dir(log_file);
            if (!std::filesystem::exists(log_dir.parent_path())) {
                std::filesystem::create_directories(log_dir.parent_path());
            }
            // 创建多 sink：终端 + 文件
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            console_sink->set_level(level);
            console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] [%n] %v");

            auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                log_file, max_file_size, max_files);
            file_sink->set_level(level);
            file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] [%n] %v");

            std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};

            // 创建各模块 logger
            m_loggers[static_cast<size_t>(LogModule::CORE)] =
                std::make_shared<spdlog::logger>("CORE", sinks.begin(), sinks.end());
            m_loggers[static_cast<size_t>(LogModule::DNS)] =
                std::make_shared<spdlog::logger>("DNS", sinks.begin(), sinks.end());
            m_loggers[static_cast<size_t>(LogModule::NETWORK)] =
                std::make_shared<spdlog::logger>("NETWORK", sinks.begin(), sinks.end());
            m_loggers[static_cast<size_t>(LogModule::SMTP)] =
                std::make_shared<spdlog::logger>("SMTP", sinks.begin(), sinks.end());
            m_loggers[static_cast<size_t>(LogModule::POP3)] =
                std::make_shared<spdlog::logger>("POP3", sinks.begin(), sinks.end());
            m_loggers[static_cast<size_t>(LogModule::IMAP)] =
                std::make_shared<spdlog::logger>("IMAP", sinks.begin(), sinks.end());
            m_loggers[static_cast<size_t>(LogModule::HTTP)] =
                std::make_shared<spdlog::logger>("HTTP", sinks.begin(), sinks.end());
            m_loggers[static_cast<size_t>(LogModule::VENDOR)] =
                std::make_shared<spdlog::logger>("VENDOR", sinks.begin(), sinks.end());
            m_loggers[static_cast<size_t>(LogModule::OUTPUT)] =
                std::make_shared<spdlog::logger>("OUTPUT", sinks.begin(), sinks.end());
            m_loggers[static_cast<size_t>(LogModule::PORT_SCAN)] =
                std::make_shared<spdlog::logger>("PORT_SCAN", sinks.begin(), sinks.end());
            m_loggers[static_cast<size_t>(LogModule::FILE_IO)] =
                std::make_shared<spdlog::logger>("FILE_IO", sinks.begin(), sinks.end());

            // 设置默认 logger
            spdlog::set_default_logger(m_loggers[static_cast<size_t>(LogModule::CORE)]);
            spdlog::set_level(level);

            m_initialized = true;
            spdlog::info("Logger initialized");
        } catch (const spdlog::spdlog_ex& ex) {
            std::cerr << "Log init failed: " << ex.what() << std::endl;
        }
    }

    // 获取指定模块的 logger
    std::shared_ptr<spdlog::logger> get_logger(LogModule module) {
        size_t index = static_cast<size_t>(module);
        if (index < m_loggers.size() && m_loggers[index]) {
            return m_loggers[index];
        }
        return spdlog::default_logger();
    }

    // 设置全局日志级别
    void set_level(spdlog::level::level_enum level) {
        spdlog::set_level(level);
        for (auto& logger : m_loggers) {
            if (logger) {
                logger->set_level(level);
            }
        }
    }

    // 设置指定模块的日志级别
    void set_module_level(LogModule module, spdlog::level::level_enum level) {
        size_t index = static_cast<size_t>(module);
        if (index < m_loggers.size() && m_loggers[index]) {
            m_loggers[index]->set_level(level);
        }
    }

    // 冲刷日志
    void flush() {
        for (auto& logger : m_loggers) {
            if (logger) {
                logger->flush();
            }
        }
        spdlog::default_logger()->flush();
    }

    // 关闭日志系统
    void shutdown() {
        flush();
        spdlog::shutdown();
    }

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    bool m_initialized = false;
    std::array<std::shared_ptr<spdlog::logger>, 11> m_loggers;
};

// 便捷函数：获取 logger
inline std::shared_ptr<spdlog::logger> log(LogModule module) {
    return Logger::get_instance().get_logger(module);
}

// 设置日志级别的便捷函数
inline void set_log_level(spdlog::level::level_enum level) {
    Logger::get_instance().set_level(level);
}

inline void set_module_log_level(LogModule module, spdlog::level::level_enum level) {
    Logger::get_instance().set_module_level(module, level);
}

} // namespace scanner

// ==================== 模块化日志宏控制 ====================

// 定义各模块是否启用调试日志的宏（默认都关闭，需要时开启）
#define ENABLE_CORE_DEBUG_LOG 0
#define ENABLE_DNS_DEBUG_LOG 0
#define ENABLE_NETWORK_DEBUG_LOG 0
#define ENABLE_SMTP_DEBUG_LOG 0
#define ENABLE_POP3_DEBUG_LOG 0
#define ENABLE_IMAP_DEBUG_LOG 0
#define ENABLE_HTTP_DEBUG_LOG 0
#define ENABLE_VENDOR_DEBUG_LOG 0
#define ENABLE_OUTPUT_DEBUG_LOG 0
#define ENABLE_PORT_SCAN_DEBUG_LOG 0
#define ENABLE_FILE_IO_DEBUG_LOG 0

// ==================== 模块化日志宏定义 ====================

// CORE 模块日志
#define LOG_CORE_TRACE(...) \
    if constexpr (ENABLE_CORE_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::CORE)->trace(__VA_ARGS__); \
    }
#define LOG_CORE_DEBUG(...) \
    if constexpr (ENABLE_CORE_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::CORE)->debug(__VA_ARGS__); \
    }
#define LOG_CORE_INFO(...) \
    scanner::log(scanner::LogModule::CORE)->info(__VA_ARGS__)
#define LOG_CORE_WARN(...) \
    scanner::log(scanner::LogModule::CORE)->warn(__VA_ARGS__)
#define LOG_CORE_ERROR(...) \
    scanner::log(scanner::LogModule::CORE)->error(__VA_ARGS__)
#define LOG_CORE_CRITICAL(...) \
    scanner::log(scanner::LogModule::CORE)->critical(__VA_ARGS__)

// DNS 模块日志
#define LOG_DNS_TRACE(...) \
    if constexpr (ENABLE_DNS_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::DNS)->trace(__VA_ARGS__); \
    }
#define LOG_DNS_DEBUG(...) \
    if constexpr (ENABLE_DNS_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::DNS)->debug(__VA_ARGS__); \
    }
#define LOG_DNS_INFO(...) \
    scanner::log(scanner::LogModule::DNS)->info(__VA_ARGS__)
#define LOG_DNS_WARN(...) \
    scanner::log(scanner::LogModule::DNS)->warn(__VA_ARGS__)
#define LOG_DNS_ERROR(...) \
    scanner::log(scanner::LogModule::DNS)->error(__VA_ARGS__)
#define LOG_DNS_CRITICAL(...) \
    scanner::log(scanner::LogModule::DNS)->critical(__VA_ARGS__)

// NETWORK 模块日志
#define LOG_NETWORK_TRACE(...) \
    if constexpr (ENABLE_NETWORK_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::NETWORK)->trace(__VA_ARGS__); \
    }
#define LOG_NETWORK_DEBUG(...) \
    if constexpr (ENABLE_NETWORK_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::NETWORK)->debug(__VA_ARGS__); \
    }
#define LOG_NETWORK_INFO(...) \
    scanner::log(scanner::LogModule::NETWORK)->info(__VA_ARGS__)
#define LOG_NETWORK_WARN(...) \
    scanner::log(scanner::LogModule::NETWORK)->warn(__VA_ARGS__)
#define LOG_NETWORK_ERROR(...) \
    scanner::log(scanner::LogModule::NETWORK)->error(__VA_ARGS__)
#define LOG_NETWORK_CRITICAL(...) \
    scanner::log(scanner::LogModule::NETWORK)->critical(__VA_ARGS__)

// SMTP 模块日志
#define LOG_SMTP_TRACE(...) \
    if constexpr (ENABLE_SMTP_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::SMTP)->trace(__VA_ARGS__); \
    }
#define LOG_SMTP_DEBUG(...) \
    if constexpr (ENABLE_SMTP_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::SMTP)->debug(__VA_ARGS__); \
    }
#define LOG_SMTP_INFO(...) \
    scanner::log(scanner::LogModule::SMTP)->info(__VA_ARGS__)
#define LOG_SMTP_WARN(...) \
    scanner::log(scanner::LogModule::SMTP)->warn(__VA_ARGS__)
#define LOG_SMTP_ERROR(...) \
    scanner::log(scanner::LogModule::SMTP)->error(__VA_ARGS__)
#define LOG_SMTP_CRITICAL(...) \
    scanner::log(scanner::LogModule::SMTP)->critical(__VA_ARGS__)

// POP3 模块日志
#define LOG_POP3_TRACE(...) \
    if constexpr (ENABLE_POP3_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::POP3)->trace(__VA_ARGS__); \
    }
#define LOG_POP3_DEBUG(...) \
    if constexpr (ENABLE_POP3_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::POP3)->debug(__VA_ARGS__); \
    }
#define LOG_POP3_INFO(...) \
    scanner::log(scanner::LogModule::POP3)->info(__VA_ARGS__)
#define LOG_POP3_WARN(...) \
    scanner::log(scanner::LogModule::POP3)->warn(__VA_ARGS__)
#define LOG_POP3_ERROR(...) \
    scanner::log(scanner::LogModule::POP3)->error(__VA_ARGS__)
#define LOG_POP3_CRITICAL(...) \
    scanner::log(scanner::LogModule::POP3)->critical(__VA_ARGS__)

// IMAP 模块日志
#define LOG_IMAP_TRACE(...) \
    if constexpr (ENABLE_IMAP_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::IMAP)->trace(__VA_ARGS__); \
    }
#define LOG_IMAP_DEBUG(...) \
    if constexpr (ENABLE_IMAP_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::IMAP)->debug(__VA_ARGS__); \
    }
#define LOG_IMAP_INFO(...) \
    scanner::log(scanner::LogModule::IMAP)->info(__VA_ARGS__)
#define LOG_IMAP_WARN(...) \
    scanner::log(scanner::LogModule::IMAP)->warn(__VA_ARGS__)
#define LOG_IMAP_ERROR(...) \
    scanner::log(scanner::LogModule::IMAP)->error(__VA_ARGS__)
#define LOG_IMAP_CRITICAL(...) \
    scanner::log(scanner::LogModule::IMAP)->critical(__VA_ARGS__)

// HTTP 模块日志
#define LOG_HTTP_TRACE(...) \
    if constexpr (ENABLE_HTTP_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::HTTP)->trace(__VA_ARGS__); \
    }
#define LOG_HTTP_DEBUG(...) \
    if constexpr (ENABLE_HTTP_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::HTTP)->debug(__VA_ARGS__); \
    }
#define LOG_HTTP_INFO(...) \
    scanner::log(scanner::LogModule::HTTP)->info(__VA_ARGS__)
#define LOG_HTTP_WARN(...) \
    scanner::log(scanner::LogModule::HTTP)->warn(__VA_ARGS__)
#define LOG_HTTP_ERROR(...) \
    scanner::log(scanner::LogModule::HTTP)->error(__VA_ARGS__)
#define LOG_HTTP_CRITICAL(...) \
    scanner::log(scanner::LogModule::HTTP)->critical(__VA_ARGS__)

// VENDOR 模块日志
#define LOG_VENDOR_TRACE(...) \
    if constexpr (ENABLE_VENDOR_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::VENDOR)->trace(__VA_ARGS__); \
    }
#define LOG_VENDOR_DEBUG(...) \
    if constexpr (ENABLE_VENDOR_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::VENDOR)->debug(__VA_ARGS__); \
    }
#define LOG_VENDOR_INFO(...) \
    scanner::log(scanner::LogModule::VENDOR)->info(__VA_ARGS__)
#define LOG_VENDOR_WARN(...) \
    scanner::log(scanner::LogModule::VENDOR)->warn(__VA_ARGS__)
#define LOG_VENDOR_ERROR(...) \
    scanner::log(scanner::LogModule::VENDOR)->error(__VA_ARGS__)
#define LOG_VENDOR_CRITICAL(...) \
    scanner::log(scanner::LogModule::VENDOR)->critical(__VA_ARGS__)

// OUTPUT 模块日志
#define LOG_OUTPUT_TRACE(...) \
    if constexpr (ENABLE_OUTPUT_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::OUTPUT)->trace(__VA_ARGS__); \
    }
#define LOG_OUTPUT_DEBUG(...) \
    if constexpr (ENABLE_OUTPUT_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::OUTPUT)->debug(__VA_ARGS__); \
    }
#define LOG_OUTPUT_INFO(...) \
    scanner::log(scanner::LogModule::OUTPUT)->info(__VA_ARGS__)
#define LOG_OUTPUT_WARN(...) \
    scanner::log(scanner::LogModule::OUTPUT)->warn(__VA_ARGS__)
#define LOG_OUTPUT_ERROR(...) \
    scanner::log(scanner::LogModule::OUTPUT)->error(__VA_ARGS__)
#define LOG_OUTPUT_CRITICAL(...) \
    scanner::log(scanner::LogModule::OUTPUT)->critical(__VA_ARGS__)

// PORT_SCAN 模块日志
#define LOG_PORT_SCAN_TRACE(...) \
    if constexpr (ENABLE_PORT_SCAN_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::PORT_SCAN)->trace(__VA_ARGS__); \
    }
#define LOG_PORT_SCAN_DEBUG(...) \
    if constexpr (ENABLE_PORT_SCAN_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::PORT_SCAN)->debug(__VA_ARGS__); \
    }
#define LOG_PORT_SCAN_INFO(...) \
    scanner::log(scanner::LogModule::PORT_SCAN)->info(__VA_ARGS__)
#define LOG_PORT_SCAN_WARN(...) \
    scanner::log(scanner::LogModule::PORT_SCAN)->warn(__VA_ARGS__)
#define LOG_PORT_SCAN_ERROR(...) \
    scanner::log(scanner::LogModule::PORT_SCAN)->error(__VA_ARGS__)
#define LOG_PORT_SCAN_CRITICAL(...) \
    scanner::log(scanner::LogModule::PORT_SCAN)->critical(__VA_ARGS__)

// FILE_IO 模块日志
#define LOG_FILE_IO_TRACE(...) \
    if constexpr (ENABLE_FILE_IO_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::FILE_IO)->trace(__VA_ARGS__); \
    }
#define LOG_FILE_IO_DEBUG(...) \
    if constexpr (ENABLE_FILE_IO_DEBUG_LOG) { \
        scanner::log(scanner::LogModule::FILE_IO)->debug(__VA_ARGS__); \
    }
#define LOG_FILE_IO_INFO(...) \
    scanner::log(scanner::LogModule::FILE_IO)->info(__VA_ARGS__)
#define LOG_FILE_IO_WARN(...) \
    scanner::log(scanner::LogModule::FILE_IO)->warn(__VA_ARGS__)
#define LOG_FILE_IO_ERROR(...) \
    scanner::log(scanner::LogModule::FILE_IO)->error(__VA_ARGS__)
#define LOG_FILE_IO_CRITICAL(...) \
    scanner::log(scanner::LogModule::FILE_IO)->critical(__VA_ARGS__)

#endif // SCANNER_LOGGER_H

#endif // SCANNER_DISABLE_LOGGING
