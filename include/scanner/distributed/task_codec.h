#pragma once

#include "scanner/distributed/task_types.h"

#include <string>

namespace scanner::distributed {

std::string serialize_batch_task(const BatchTask& task);
bool deserialize_batch_task(const std::string& line, BatchTask* task);

}  // namespace scanner::distributed
