#include "scanner/distributed/task_codec.h"

#include <nlohmann/json.hpp>

namespace scanner::distributed {

std::string serialize_batch_task(const BatchTask& task) {
    nlohmann::json j;
    j["batch_id"] = task.batch_id;
    j["input_path"] = task.input_path;
    j["line_begin"] = task.line_begin;
    j["line_end"] = task.line_end;
    j["attempt"] = task.attempt;
    j["max_attempts"] = task.max_attempts;
    return j.dump();
}

bool deserialize_batch_task(const std::string& line, BatchTask* task) {
    if (task == nullptr) {
        return false;
    }

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(line);
    } catch (...) {
        return false;
    }

    if (!j.contains("batch_id") || !j.contains("input_path") || !j.contains("line_begin") || !j.contains("line_end")) {
        return false;
    }

    task->batch_id = j["batch_id"].get<uint64_t>();
    task->input_path = j["input_path"].get<std::string>();
    task->line_begin = j["line_begin"].get<uint64_t>();
    task->line_end = j["line_end"].get<uint64_t>();
    task->attempt = j.value("attempt", 0U);
    task->max_attempts = j.value("max_attempts", 3U);
    return true;
}

}  // namespace scanner::distributed
