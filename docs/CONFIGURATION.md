# 配置说明文档

## 概述

协议扫描器支持通过三种方式配置线程池：

1. **JSON 配置文件**（推荐）
2. **命令行参数**（覆盖 JSON 配置）
3. **旧版单线程数模式**（向后兼容）

---

## 线程池架构

```
┌─────────────────────────────────────────────────┐
│           Protocol Scanner                      │
├─────────────────────────────────────────────────┤
│  ScanThreadPool (CPU 密集型)                 │
│  - 协议封装                                │
│  - 任务调度                                  │
│  - 结果收集                                  │
│  建议配置: 2-4 线程                        │
├─────────────────────────────────────────────────┤
│  IoThreadPool (I/O 密集型)                   │
│  - 网络连接                                  │
│  - 数据读写                                  │
│  - 超时管理                                  │
│  建议配置: CPU 核心数 × 1.5                │
└─────────────────────────────────────────────────┘
```

---

## 配置方式

### 方式 1: JSON 配置文件（推荐）

编辑 `config/scanner_config.json`：

```json
{
  "scanner": {
    "io_thread_count": 12,
    "cpu_thread_count": 2,
    "batch_size": 100,
    "probe_timeout_ms": 3000
  }
}
```

**参数说明：**
- `io_thread_count`: IO 线程池大小，处理网络 I/O
  - 推荐值: CPU 核心数 × 1.5
  - 例如: 8 核 CPU → 12 线程
- `cpu_thread_count`: CPU 线程池大小，处理协议封装等轻量任务
  - 推荐值: 2-4 线程
  - 不建议超过 8 线程
- `thread_count`: 废弃参数，保留向后兼容
- `batch_size`: 每批次任务数，建议 100-1000
- `probe_timeout_ms`: 单次探测超时（毫秒），建议 3000-5000

---

### 方式 2: 命令行参数（覆盖 JSON）

```bash
# 分别指定 IO 和 CPU 线程数
./build/scanner --domains domains.txt --scan \
    --io-threads 12 \
    --cpu-threads 2

# 只指定 IO 线程，CPU 使用默认
./build/scanner --domains domains.txt --scan \
    --io-threads 8
```

---

### 方式 3: 旧版单线程数模式（向后兼容）

```bash
# 使用旧版 --threads 参数（同时设置 IO 和 CPU 线程）
./build/scanner --domains domains.txt --scan --threads 8

# 实际效果:
#   io_thread_count = 8
#   cpu_thread_count = max(1, 8 / 4) = 2
```

---

## 推荐配置

### 小规模扫描（< 100 域名）

```json
{
  "scanner": {
    "io_thread_count": 4,
    "cpu_thread_count": 2,
    "batch_size": 100,
    "probe_timeout_ms": 3000
  }
}
```

### 中等规模（100 - 10,000 域名）

```json
{
  "scanner": {
    "io_thread_count": 12,
    "cpu_thread_count": 2,
    "batch_size": 500,
    "probe_timeout_ms": 3000
  }
}
```

### 大规模扫描（> 10,000 域名）

```json
{
  "scanner": {
    "io_thread_count": 24,
    "cpu_thread_count": 4,
    "batch_size": 1000,
    "probe_timeout_ms": 5000
  }
}
```

---

## 性能调优指南

### 1. 如何确定最佳 IO 线程数

```bash
# 查看 CPU 核心数
sysctl -n hw.ncpu  # macOS
lscpu | grep "CPU(s)"  # Linux

# IO 线程数 = CPU 核心数 × 1.5
# 8 核 CPU → 12 个 IO 线程
```

**原因：**
- 网络等待期间 CPU 可以处理其他连接
- 1.5 倍因子在测试中表现最佳
- 过多线程会导致上下文切换开销

### 2. 如何确定最佳 CPU 线程数

```bash
# 固定值: 2-4 线程
# CPU 线程只处理轻量任务（协议封装），不需要太多
```

**原因：**
- ScanThreadPool 只是包装器，实际 I/O 在 IoThreadPool
- 协议解析（字符串处理）非常快（< 0.1ms）
- 过多线程造成资源浪费

### 3. 调整 batch_size

```bash
# batch_size = io_thread_count × 预期并发连接数
# 示例: 12 IO 线程 × 100 并发连接 = 1200 batch_size
```

**注意事项：**
- 过大会增加内存占用
- 过小会降低吞吐量
- 建议从 100 开始，逐步增加

### 4. 调整 probe_timeout_ms

```bash
# 超时设置影响:
#   - 太短: 慢速服务器被误判为失败
#   - 太长: 浪费时间等待响应
# 推荐值: 3000-5000ms
```

---

## 故障排查

### 问题 1: 扫描速度慢

**症状：** 扫描 1000 域名需要 > 10 分钟

**解决方案：**
```bash
# 增加 IO 线程数
./build/scanner --domains domains.txt --scan --io-threads 24

# 检查是否有瓶颈
# 查看日志中的连接成功率
```

### 问题 2: 内存占用过高

**症状：** 内存占用 > 2GB

**解决方案：**
```json
{
  "scanner": {
    "batch_size": 100,  // 减少 batch_size
    "io_thread_count": 8   // 减少 IO 线程数
  }
}
```

### 问题 3: 误报率高

**症状：** 大量连接超时

**解决方案：**
```json
{
  "scanner": {
    "probe_timeout_ms": 5000  // 增加超时时间
  }
}
```

---

## 配置优先级

1. **命令行参数**（最高优先级）
   - `--io-threads`
   - `--cpu-threads`
   - `--threads`（旧版）

2. **JSON 配置文件**
   - `config/scanner_config.json`

3. **代码默认值**（最低优先级）
   - `io_thread_count = 4`
   - `cpu_thread_count = 2`

---

## 监控和日志

查看线程池使用情况：

```bash
# 启动扫描，观察日志
./build/scanner --domains domains.txt --scan

# 日志输出:
# [info] Thread pools: IO=12, CPU=2
# [info] Thread pools initialized: IO=12 CPU=2
# [info] Scan completed in 15 seconds
```

---

## 向后兼容性

| 旧版命令 | 新版等效命令 | 说明 |
|----------|------------|------|
| `--threads 8` | `--io-threads 8 --cpu-threads 2` | 自动分配 IO=8, CPU=2 |
| `--threads 4` | `--io-threads 4 --cpu-threads 1` | 自动分配 IO=4, CPU=1 |

**注意：** 旧版 `--threads` 参数仍可使用，但推荐迁移到新版参数。
