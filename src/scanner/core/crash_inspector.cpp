#include "scanner/core/crash_inspector.h"
#include "scanner/common/logger.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace scanner {
namespace fs = std::filesystem;

namespace {

std::string read_small_file(const std::string& path, std::size_t max_bytes = 16384) {
    std::ifstream ifs(path, std::ios::in | std::ios::binary);
    if (!ifs) return "";
    std::string buf;
    buf.resize(max_bytes);
    ifs.read(buf.data(), static_cast<std::streamsize>(max_bytes));
    buf.resize(static_cast<std::size_t>(ifs.gcount()));
    return buf;
}

std::string time_string_utc() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%d %H:%M:%S UTC");
    return ss.str();
}

} // namespace

#if defined(__linux__)

class LinuxCrashInspector final : public CrashInspector {
public:
    bool supported() const override { return true; }

    bool inspect(const std::string& progress_file,
                 const std::string& diag_output_file) override {
        if (!fs::exists(progress_file)) {
            return false;
        }

        std::error_code ec;
        fs::create_directories(fs::path(diag_output_file).parent_path(), ec);

        std::ofstream ofs(diag_output_file, std::ios::app);
        if (!ofs) {
            LOG_CORE_WARN("CrashInspector: cannot open diag file: {}", diag_output_file);
            return false;
        }

        ofs << "=== startup inspection ===\n";
        ofs << "time: " << time_string_utc() << "\n";
        ofs << "progress_file: " << progress_file << "\n";
        ofs << "progress_size: " << (fs::exists(progress_file) ? fs::file_size(progress_file) : 0) << " bytes\n";
        if (fs::exists(progress_file)) {
            auto mtime = fs::last_write_time(progress_file, ec);
            if (!ec) {
                auto s = std::chrono::duration_cast<std::chrono::seconds>(mtime.time_since_epoch()).count();
                ofs << "progress_mtime_epoch: " << s << "\n";
            }
        }

        auto limits = read_small_file("/proc/self/limits");
        auto status = read_small_file("/proc/self/status");
        auto meminfo = read_small_file("/proc/meminfo");
        auto cgroup = read_small_file("/proc/self/cgroup");
        auto oom_score = read_small_file("/proc/self/oom_score");
        auto oom_adj = read_small_file("/proc/self/oom_score_adj");

        if (!limits.empty()) ofs << "\n[proc/self/limits]\n" << limits << "\n";
        if (!status.empty()) ofs << "\n[proc/self/status]\n" << status << "\n";
        if (!meminfo.empty()) ofs << "\n[proc/meminfo]\n" << meminfo << "\n";
        if (!cgroup.empty()) ofs << "\n[proc/self/cgroup]\n" << cgroup << "\n";
        if (!oom_score.empty()) ofs << "oom_score=" << oom_score;
        if (!oom_adj.empty()) ofs << "oom_score_adj=" << oom_adj;
        ofs << "\n";

        ofs.flush();
        LOG_CORE_INFO("CrashInspector wrote diagnostics to {}", diag_output_file);
        return true;
    }
};

#elif defined(__APPLE__)

class MacCrashInspector final : public CrashInspector {
public:
    bool supported() const override { return true; }

    bool inspect(const std::string& progress_file,
                 const std::string& diag_output_file) override {
        if (!fs::exists(progress_file)) {
            return false;
        }
        std::ofstream ofs(diag_output_file, std::ios::app);
        if (!ofs) return false;
        ofs << "=== startup inspection ===\n";
        ofs << "time: " << time_string_utc() << "\n";
        ofs << "progress_file: " << progress_file << "\n";
        ofs << "note: macOS inspection is minimal; run 'sysctl vm.swapusage' and 'ulimit -a' manually if needed.\n";
        ofs.flush();
        LOG_CORE_INFO("CrashInspector wrote diagnostics to {} (macOS)", diag_output_file);
        return true;
    }
};

#endif

std::unique_ptr<CrashInspector> CrashInspector::create() {
#if defined(__linux__)
    return std::make_unique<LinuxCrashInspector>();
#elif defined(__APPLE__)
    return std::make_unique<MacCrashInspector>();
#else
    return nullptr;
#endif
}

} // namespace scanner
