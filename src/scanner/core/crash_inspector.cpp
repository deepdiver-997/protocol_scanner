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
#include <memory>

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

}  // namespace

#if defined(__linux__)

// Linux-specific utilities for extended diagnostics
namespace {

// Execute a shell command and capture its stdout, limiting output size.
std::string exec_command(const std::string& cmd, std::size_t max_output = 8192) {
    std::string escaped_cmd = cmd;
    size_t pos = 0;
    while ((pos = escaped_cmd.find('"', pos)) != std::string::npos) {
        escaped_cmd.replace(pos, 1, "\\\"");
        pos += 2;
    }
    
    std::string wrapped_cmd = "timeout 2s bash -c \"" + escaped_cmd + "\" 2>/dev/null";
    FILE* pipe = popen(wrapped_cmd.c_str(), "r");
    if (!pipe) return "";

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
    while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) {
        comm.pop_back();
    }
    return comm;
}

// Try to extract systemd unit name from /proc/self/cgroup
std::string get_systemd_unit_from_cgroup() {
    auto cgroup = read_small_file("/proc/self/cgroup", 1024);
    if (cgroup.empty()) return "";
    const std::string suffix = ".service";
    auto pos = cgroup.find(suffix);
    if (pos == std::string::npos) return "";
    auto start = cgroup.rfind('/', pos);
    if (start == std::string::npos) {
        start = 0;
    } else {
        start += 1;
    }
    return cgroup.substr(start, pos - start + suffix.size());
}

std::string get_systemd_unit_name() {
    auto unit = get_systemd_unit_from_cgroup();
    if (!unit.empty()) return unit;
    auto comm = get_process_name();
    if (comm.empty()) return "";
    return comm + ".service";
}

std::string trim(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) {
        s.pop_back();
    }
    std::size_t start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r')) {
        ++start;
    }
    if (start > 0) s.erase(0, start);
    return s;
}

std::string get_value_from_systemctl_show(const std::string& output, const std::string& key) {
    std::string prefix = key + "=";
    std::size_t pos = output.find(prefix);
    if (pos == std::string::npos) return "";
    std::size_t end = output.find('\n', pos);
    if (end == std::string::npos) end = output.size();
    return trim(output.substr(pos + prefix.size(), end - (pos + prefix.size())));
}

std::string classify_stop_reason(const std::string& status_output, const std::string& recent_journal) {
    auto result = get_value_from_systemctl_show(status_output, "Result");
    auto code = get_value_from_systemctl_show(status_output, "ExecMainCode");
    auto status = get_value_from_systemctl_show(status_output, "ExecMainStatus");
    auto restarts = get_value_from_systemctl_show(status_output, "NRestarts");
    bool has_restart = (!restarts.empty() && restarts != "0");

    if (recent_journal.find("Stopped ") != std::string::npos ||
        recent_journal.find("Stopping ") != std::string::npos) {
        if (result == "success" && (code == "exited" || code == "0") && (status == "0" || status == "")) {
            return "manual-stop likely";
        }
    }

    if (recent_journal.find("Restarting") != std::string::npos ||
        recent_journal.find("Scheduled restart job") != std::string::npos ||
        recent_journal.find("restart job") != std::string::npos ||
        (result == "watchdog" || result == "timeout" || result == "signal")) {
        return "systemd-auto-restart likely";
    }

    if (has_restart) {
        return "systemd-auto-restart likely (NRestarts>0)";
    }

    if (result == "success" && (code == "exited" || code == "0") && (status == "0" || status == "")) {
        return "graceful-exit likely";
    }

    if (!result.empty() || !code.empty() || !status.empty()) {
        return "abnormal-exit possible";
    }
    return "unknown";
}

}  // namespace

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

        // OOM Killer history from dmesg
        {
            auto oom_events = exec_command("dmesg -T | grep -iE '(killed process|out of memory|oom_reaper)' | tail -20");
            if (!oom_events.empty()) {
                ofs << "\n[Recent OOM Events from dmesg]\n" << oom_events << "\n";
            }
        }

        // Systemd service exit history
        {
            std::string service_name = get_process_name();
            std::string journal_output;
            if (!service_name.empty()) {
                std::string cmd = "journalctl -u " + service_name + ".service -n 30 --no-pager --output=short-precise 2>/dev/null | grep -E '(exit|killed|stopped|signal|code=)'";
                journal_output = exec_command(cmd);
                if (journal_output.empty()) {
                    cmd = "journalctl -u " + service_name + " -n 30 --no-pager --output=short-precise 2>/dev/null | grep -E '(exit|killed|stopped|signal|code=)'";
                    journal_output = exec_command(cmd);
                }
            }
            if (journal_output.empty()) {
                std::string pid_str = std::to_string(getpid());
                std::string cmd = "journalctl _PID=" + pid_str + " -n 20 --no-pager 2>/dev/null";
                journal_output = exec_command(cmd);
            }
            if (!journal_output.empty()) {
                ofs << "\n[Systemd Service Exit History]\n" << journal_output << "\n";
            }
        }

        // Systemd unit status and restart/stop reasons
        {
            std::string unit = get_systemd_unit_name();
            if (!unit.empty()) {
                std::string status_cmd =
                    "systemctl show " + unit +
                    " --no-pager -p Id -p Description -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus "
                    "-p ExecMainPID -p ExecMainStartTimestamp -p ExecMainExitTimestamp -p InactiveExitTimestamp "
                    "-p Restart -p NRestarts -p RestartUSec -p FragmentPath";
                auto status_output = exec_command(status_cmd);

                std::string reason_cmd =
                    "journalctl -u " + unit +
                    " -n 40 --no-pager --output=short-precise 2>/dev/null | "
                    "grep -E '(Stopped|Stopping|Starting|Started|Restarting|restart job|code=|signal=|failed|killed)'";
                auto reason_output = exec_command(reason_cmd);

                if (!status_output.empty()) {
                    ofs << "\n[Systemd Unit Status]\n" << status_output << "\n";
                }
                if (!reason_output.empty()) {
                    ofs << "\n[Systemd Restart/Stop Reasons]\n" << reason_output << "\n";
                }

                if (!status_output.empty()) {
                    std::string summary = classify_stop_reason(status_output, reason_output);
                    ofs << "\n[Systemd Stop Reason Summary]\n" << summary << "\n";
                }
            }
        }

        // Coredump history
        {
            auto coredumps = exec_command("coredumpctl list --no-pager --no-legend 2>/dev/null | tail -10");
            if (!coredumps.empty()) {
                ofs << "\n[Recent Coredumps (system-wide)]\n" << coredumps << "\n";
            }
        }

        // Memory pressure (PSI) - Linux 4.20+
        {
            if (fs::exists("/proc/pressure/memory")) {
                auto psi = read_small_file("/proc/pressure/memory", 512);
                if (!psi.empty()) {
                    ofs << "\n[Memory Pressure (PSI)]\n" << psi << "\n";
                }
            }
        }

        // Recent system reboots
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

#else  // macOS and other platforms

class MacCrashInspector final : public CrashInspector {
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
            return false;
        }
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
#else
    return std::make_unique<MacCrashInspector>();
#endif
}

} // namespace scanner
