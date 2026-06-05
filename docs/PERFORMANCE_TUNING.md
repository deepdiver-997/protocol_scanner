# 性能调优记录

## 环境

- 服务器: 6核 Xeon E5-2683 v4 / 8GB RAM / Ubuntu 24.04
- 扫描: 单协议 SSH（端口 22），纯 IP 列表输入（2.9 亿 IP）
- 编译: `-DUSE_CARES=OFF`（无 c-ares 依赖，用 null resolver）

## 发现的问题与修复

### 1. LIFO 队列导致有序提交死锁

**现象**: 扫描启动后输出文件始终为空，`pending_reports` 积压千万级结果不提交，内存冲到 540MB。

**根因**: `targets_` 使用 `std::vector` + `pop_back()`（后进先出）。输入线程按 seq 1→N 顺序 push，扫描线程反向 consume（seq N 先处理）。有序提交机制 `commit_ready_reports` 从 seq=1 开始等待，但 seq=1 的结果在队列底部最后才被处理。大批量扫描时所有结果卡在 `pending_reports` 中无法提交。

**修复**: `std::vector` → `std::deque`，`pop_back()` → `pop_front()`，保证 FIFO 处理顺序。同时进度文件在空批次时也更新时间戳。

**效果**: 输出文件秒级开始写入，内存从 540MB 降至 100MB。

### 2. `estimate_quota` 把已完成 session 算作 active

**现象**: 修复 FIFO 后吞吐只有 200/s，`scan_loop` 占 56% CPU，大量时间空转。

**根因**: `estimate_quota()` 遍历所有 session 统计 active 数，但 `ready_to_release()` 的 session（探针已完成等重用）也被算入 active。当 20000 个 session 同时完成时，`max_concurrent - active = 0`，quota 被强制设为 1 (max)，每 3ms 只重用 1 个 session。20000 个 session 要 60 秒才能轮完一圈。

**修复**: 排除 `ready_to_release()` 的 session，只统计真正在探测中的。

```
- if (s && !s->idle()) ++active;
+ if (s && !s->idle() && !s->ready_to_release()) ++active;
```

**效果**: 吞吐从 200/s → 6,324/s（31 倍）。

### 3. 缓冲池未按配置初始化

**现象**: `max_work_count=20000` 显式配置时，BufferPool 只分配默认 3000 个缓冲区，17000 个 session 每次 `acquire()` 都走 malloc，`return_buffer()` 时池已满直接 free。malloc/free 开销 + mutex 竞争。

**根因**: `get_global_buffer_pool()` 是 static 局部变量，初始化逻辑在 `if (max_work_count == 0)` 分支内，显式配置时被跳过。

**修复**: 将 buffer pool 初始化移到分支外，始终按 `max_work_count` 分配。

```cpp
// 始终按 max_work_count 初始化缓冲池
get_global_buffer_pool(std::max<size_t>(config_.max_work_count, 3000));
```

### 4. c-ares 依赖与 DNS 解析器拆分

**背景**: 原项目 c-ares 是硬依赖，交叉编译/无 c-ares 环境无法构建。

**修复**:
- `CMakeLists.txt`: 添加 `USE_CARES` option，未找到时不报错而是定义 `SCANNER_NO_CARES`
- DNS 解析器拆分为独立文件: `null_resolver.h`, `dig_resolver.h`, `cares_resolver.h` + 对应 `.cpp`
- `dns_resolver.h` 只保留接口和工厂，`cares_resolver.h` 只在 `USE_CARES=ON` 时编译
- 生产配置使用 `"resolver_type": "null"`（全 IP 输入无需 DNS）

### 5. 队列锁优化

**背景**: `targets_` 和 `result_queue_`（BlockingQueue）使用 `std::mutex`，高并发下有一定开销。

**修复**:
- 实现 `SpinLock`（`atomic_flag` 自旋锁）
- `targets_lock_` 和 `BlockingQueue` 内部 mutex 都换为 `SpinLock`
- 移除 `targets_cv_`（condition_variable），等待逻辑改为自旋 + sleep
- `BufferPool` 内部 mutex 也换为 `SpinLock`

**效果**: `pthread_mutex_lock` 从 perf 中消失。

### 6. CIDR 展开瓶颈

**现象**: 输入文件包含 `3.0.0.0/8`、`4.0.0.0/8` 等巨型 CIDR，每个 1600 万 IP。输入线程单线程展开 CIDR，CPU-bound 每秒只能产出 ~250 个 IP，扫描线程严重饥饿。

**修复**: 用 Python 预处理，将 CIDR 提前展开为纯 IP 文件（跳过 >100 万 IP 的超大范围）。2.9 万个 CIDR 行展开为 2.9 亿行纯 IP。

**效果**: 输入线程不再瓶颈，吞吐达 17000/s。

### 7. `max_work_count` 逐步调优

| 阶段 | max_work_count | 吞吐 | 内存 |
|------|:---:|:---:|:---:|
| 初始 | 5,000 | 200/s | 540MB (LIFO 积压) |
| FIFO修复 | 5,000 | 250/s | 140MB |
| 提升并发 | 20,000 | 6,324/s | 1.2GB |
| quota修复+SpinLock | 80,000 | 17,273/s | ~4GB |

单协议扫描每个 session 只需 1 个探针 + 1KB buffer，内存开销 ~50-60KB/session。8GB 服务器理论可支持 12 万+ 并发。

## 最终配置 (`scanner_config_prod.json`)

```json
{
  "scanner": {
    "io_thread_count": 6,
    "batch_size": 80000,
    "result_batch_size": 2000,
    "dns_timeout_ms": 2000,
    "probe_timeout_ms": 3000,
    "retry_count": 1,
    "only_success": false,
    "max_work_count": 80000,
    "targets_max_size": 0,
    "metrics_port": 9080
  },
  "dns": {
    "resolver_type": "null"
  }
}
```

## 监控

内嵌 HTTP metrics 端点 `curl 127.0.0.1:9080/metrics` 返回实时 JSON:

```json
{
  "queues": {"targets": 195483, "results": 0, "pending": 9},
  "sessions": {"active": 80000, "total": 80000},
  "progress": {"processed": 11157969, "successful": 85761},
  "rate": {"targets_per_sec": 17273},
  "uptime_sec": 29,
  "protocols": {"SSH": 85761}
}
```
