#include "scanner/core/crash_inspector.h"
#include "scanner/common/logger.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#if defined(__linux__)
#include <unistd.h>
#endif

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

// Execute a shell command and capture its stdout, limiting output size.
// Returns empty string on failure or timeout.
std::string exec_command(const std::string& cmd, std::size_t max_output = 8192) {
    // Redirect stderr to /dev/null to avoid noise; add timeout wrapper if available
    std::string wrapped_cmd = "timeout 2s sh -c '" + cmd + "' 2>/dev/null";
    FILE* pipe = popen(wrapped_cmd.c_str(), "r");
    if (!pipe) {
        return "";
    }

    std::string result;
    result.reserve(std::min(max_output, std::size_t(4096)));
    char buffer[512];
    while (!feof(pipe) && result.size() < max_output) {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result.append(buffer);
        }
    }
    pclose(pipe);

    if (result.size() > max_output) {
        result.resize(max_output);
        result.append("\n... (output truncated)\n");
    }
    return result;
}

// Get current process name from /proc/self/comm
std::string get_process_name() {
    auto comm = read_small_file("/proc/self/comm", 256);
    // Trim trailing newline
    while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) {
        comm.pop_back();
    }
    return comm;
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

        // --- Extended diagnostics via shell commands ---

        // a. OOM Killer history from dmesg
        {
            auto oom_events = exec_command("dmesg -T | grep -iE '(killed process|out of memory|oom_reaper)' | tail -20");
            if (!oom_events.empty()) {
                ofs << "\n[Recent OOM Events from dmesg]\n" << oom_events << "\n";
            }
        }

        // b. Systemd service exit history
        {
            std::string service_name = get_process_name();
            std::string journal_output;
            if (!service_name.empty()) {
                // Try with service name first (common pattern: <name>.service)
                std::string cmd = "journalctl -u " + service_name + ".service -n 30 --no-pager --output=short-precise 2>/dev/null | grep -E '(exit|killed|stopped|signal|code=)'";
                journal_output = exec_command(cmd);
                // If empty, try without .service suffix
                if (journal_output.empty()) {
                    cmd = "journalctl -u " + service_name + " -n 30 --no-pager --output=short-precise 2>/dev/null | grep -E '(exit|killed|stopped|signal|code=)'";
                    journal_output = exec_command(cmd);
                }
            }
            // Fallback: query by current PID (won't find previous incarnation, but may help)
            if (journal_output.empty()) {
                std::string pid_str = std::to_string(getpid());
                std::string cmd = "journalctl _PID=" + pid_str + " -n 20 --no-pager 2>/dev/null";
                journal_output = exec_command(cmd);
            }
            if (!journal_output.empty()) {
                ofs << "\n[Systemd Service Exit History]\n" << journal_output << "\n";
            }
        }

        // c. Coredump history (coredumpctl may not be installed)
        {
            auto coredumps = exec_command("coredumpctl list --no-pager --no-legend 2>/dev/null | tail -10");
            if (!coredumps.empty()) {
                ofs << "\n[Recent Coredumps (system-wide)]\n" << coredumps << "\n";
            }
        }

        // d. Memory pressure (PSI) - Linux 4.20+
        {
            if (fs::exists("/proc/pressure/memory")) {
                auto psi = read_small_file("/proc/pressure/memory", 512);
                if (!psi.empty()) {
                    ofs << "\n[Memory Pressure (PSI)]\n" << psi << "\n";
                }
            }
        }

        // e. Recent system reboots
        {
            auto reboots = exec_command("last reboot 2>/dev/null | head -5");
            if (!reboots.empty()) {
                ofs << "\n[Recent System Reboots]\n" << reboots << "\n";
            }
        }

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
