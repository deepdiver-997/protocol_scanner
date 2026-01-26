#pragma once

#include <memory>
#include <string>

namespace scanner {

// CrashInspector is a small pluggable diagnostic helper.
// Implementations can be selected via compile-time platform detection.
class CrashInspector {
public:
    virtual ~CrashInspector() = default;

    // Whether this inspector can run on the current platform.
    virtual bool supported() const = 0;

    // Run a lightweight inspection when a checkpoint file exists.
    // progress_file: path to the checkpoint/progress JSON.
    // diag_output_file: destination file to append diagnostic information.
    // Returns true if inspection executed (even if partial), false otherwise.
    virtual bool inspect(const std::string& progress_file,
                         const std::string& diag_output_file) = 0;

    // Factory: returns a platform-specific inspector when available.
    static std::unique_ptr<CrashInspector> create();
};

} // namespace scanner
