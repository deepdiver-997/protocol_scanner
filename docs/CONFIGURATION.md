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
    "io_thread_count": 24,
    "cpu_thread_count": 4,
    "thread_count": 8,
    "batch_size": 100,
    "dns_timeout_ms": 1000,
    "probe_timeout_ms": 2000,
    "retry_count": 1,
    "only_success": true,
    "max_work_count": 100
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
- `dns_timeout_ms`: DNS 查询超时
- `retry_count`: 探测重试次数
- `only_success`: 仅输出成功结果
- `max_work_count`: 批次/工作量上限（预留防护）

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

### 输出、日志与厂商识别配置

**Output**
```json
"output": {
  "format": ["text", "csv"],   // 主输出 + 附加格式
  "write_mode": "stream",      // stream: 边扫边写；final: 扫描结束一次写
  "directory": "./result",
  "enable_json": true,
  "enable_csv": true,
  "enable_report": false,
  "to_console": false
}
```

**Logging**
```json
"logging": {
  "level": "INFO",
  "console_enabled": false,
  "file_enabled": false,
  "file_path": "./scanner.log"
}
```

**Vendor**
```json
"vendor": {
  "enabled": true,
  "pattern_file": "./config/vendors.json",  // 可通过 --vendor-file 覆盖
  "similarity_threshold": 0.7
}
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
    "probe_timeout_ms": 3000,
    "only_success": true
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
    "probe_timeout_ms": 3000,
    "only_success": true
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
    "probe_timeout_ms": 5000,
    "only_success": true
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

## DNS 优化配置

### 自动 IP 地址检测

扫描器会自动检测输入中的有效 IPv4 地址，**跳过 DNS 解析**，直接进行协议探测：

```json
{
  "dns": {
    "resolver_type": "cares",
    "timeout_ms": 5000,
    "max_mx_records": 16
  }
}
```

**工作原理**：

1. **输入**：`192.168.1.1` → 检测为 IP 地址
2. **跳过** DNS 查询
3. **直接** 进行协议探测（SMTP、HTTP 等）

相比于域名输入节省了 DNS 查询时间（通常 100-500ms）。

### 大规模扫描优化

对于 1M+ 规模的 IP 列表扫描：

```json
{
  "scanner": {
    "targets_max_size": 1000000,      // 最大目标队列大小
    "batch_size": 100,                 // 单次批处理数量
    "thread_count": 8                  // CPU 线程数
  }
}
```

**特性**：

- **生产者-消费者模式**：输入线程异步加载，扫描线程异步探测
- **背压机制**：当 targets 队列达到 `targets_max_size` 时，输入线程暂停
- **结果缓冲**：结果线程定期（每 5 秒）将完成的报告写入磁盘

这种设计避免了一次性加载所有目标到内存的问题。

---

## 输入文件格式

### 支持的输入格式

#### 1. 域名列表（每行一个）

```
gmail.com
outlook.com
baidu.com
```

#### 2. IP 地址列表（自动检测，无需 DNS）

```
8.8.8.8
114.114.114.114
1.1.1.1
```

#### 3. IP 范围（CSV 格式：start_ip,end_ip）

```
192.168.1.0,192.168.1.255
10.0.0.0,10.0.0.10
172.16.0.0,172.16.0.255
```

**自动扩展范围**，上限 1M 条 IP（防止内存爆炸）

#### 4. 混合格式（域名 + IP）

```
# 注释行（以 # 或 ; 开头）
gmail.com
8.8.8.8

baidu.com
114.114.114.114
```

### 最佳实践

- **预先解析 IP**：使用 IP 地址而非域名可节省 DNS 时间
- **使用 IP 范围**：对于 CIDR 块可用 CSV 格式自动扩展
- **注释行**：以 `#` 或 `;` 开头的行会被自动忽略
- **空行处理**：自动跳过空行和仅有空白的行

---

## 向后兼容性

| 旧版命令 | 新版等效命令 | 说明 |
|----------|------------|------|
| `--threads 8` | `--io-threads 8 --cpu-threads 2` | 自动分配 IO=8, CPU=2 |
| `--threads 4` | `--io-threads 4 --cpu-threads 1` | 自动分配 IO=4, CPU=1 |

**注意：** 旧版 `--threads` 参数仍可使用，但推荐迁移到新版参数。
