# 服务器 Perf 分析 & 优化方案

## 📊 Perf 结果分析

### 主要瓶颈排序

| 瓶颈 | 占比 | 原因 |
|------|------|------|
| `do_epoll_ctl` | ~2.5% | 频繁修改 epoll fd |
| `_copy_from_user` | 1.36% | 内核↔用户空间拷贝 |
| `syscall return` | 高% | 系统调用开销 |
| `malloc/free` | ~1.7% | 内存分配 |

**结论**: CPU 主要消耗在**系统调用和上下文切换**，而非应用逻辑

---

## 🔍 根本原因

### 问题 1：Socket 接收缓冲区未优化

**当前代码** (`src/scanner/protocols/*.cpp`):
```cpp
ctx->socket.open(tcp::v4());
asio::socket_base::reuse_address reuse_opt(true);
ctx->socket.set_option(reuse_opt, set_ec);
// ← 没有设置 SO_RCVBUF 或 SO_SNDBUF
```

**影响**:
- 使用系统默认值（通常 128KB 左右，但可能更小）
- 频繁的 `async_read_some(buffer<1KB>)` 调用
- 1KB 缓冲 + 默认接收缓冲 = **多次系统调用**才能读取一条完整响应
- 每次读取 → `copy_from_user` → epoll 更新

### 问题 2：IO Context 负载均衡低效

**当前代码** (`src/scanner/common/io_thread_pool.cpp`):
```cpp
asio::io_context& IoThreadPool::get_context() {
    // 返回任务数最少的 context
    // 但没有考虑 socket 缓冲区大小和系统调用成本
}
```

### 问题 3：协议缓冲区 1KB 的限制

**当前** (`include/scanner/common/buffer_pool.h`):
```cpp
constexpr size_t PROTOCOL_BUFFER_SIZE = 1024;  // 1KB
```

**理由**: HTTP 响应、SMTP 多行回复等通常 < 2KB
**问题**: 如果某些协议返回较大响应，会导致多次读取

---

## ✅ 优化方案

### 方案 1：设置 Socket 缓冲区（立即实施，预期提升 15-25%）

在每个协议的 `socket.open()` 后添加：

```cpp
// 设置接收和发送缓冲区大小（256KB，可根据内存调整）
asio::socket_base::receive_buffer_size recv_buf(256 * 1024);
asio::socket_base::send_buffer_size send_buf(64 * 1024);
ctx->socket.set_option(recv_buf, set_ec);
ctx->socket.set_option(send_buf, set_ec);

// 禁用 Nagle 算法，减少延迟
asio::ip::tcp::no_delay no_delay_opt(true);
ctx->socket.set_option(no_delay_opt, set_ec);
```

**效果**:
- 减少 `async_read_some()` 调用次数（缓冲区能容纳整个响应）
- 减少系统调用频率 → `copy_from_user` 下降
- `do_epoll_ctl` 修改减少 → 上下文切换降低

### 方案 2：调整协议缓冲区（可选，预期提升 5-10%）

**可选**：从 1KB 增加到 4KB 或 8KB

```cpp
// include/scanner/common/buffer_pool.h
constexpr size_t PROTOCOL_BUFFER_SIZE = 4096;  // 4KB
```

**权衡**:
- ✅ 减少读取次数
- ✅ 单次缓冲更大，覆盖更多协议响应
- ❌ 内存占用增加（5-10MB 级别，可接受）

### 方案 3：使用 epoll 等级触发而非边缘触发（可选）

Boost ASIO 默认使用**级别触发** (level-triggered)，这已经是最优的。
不需要改动。

### 方案 4：减少 DNS 查询频率（如果适用）

检查是否有不必要的 DNS 查询：
```bash
perf stat -e syscalls:sys_enter_getaddrinfo ./build/scanner ...
```

---

## 🚀 执行优化步骤

### 第一步：为所有协议添加 Socket 缓冲区设置

需要修改的文件：
- `src/scanner/protocols/smtp_protocol.cpp`
- `src/scanner/protocols/pop3_protocol.cpp`
- `src/scanner/protocols/imap_protocol.cpp`
- `src/scanner/protocols/http_protocol.cpp`
- `src/scanner/protocols/ftp_protocol.cpp`
- `src/scanner/protocols/telnet_protocol.cpp`
- `src/scanner/protocols/ssh_protocol.cpp`

每个文件中，在 `socket.open()` 之后添加缓冲区设置。

### 第二步：测试性能差异

编译后运行相同的测试：
```bash
./build.sh Release clean
time ./build/scanner -d JP_ip.txt -c config/scanner_config_2gb_optimized.json --scan --time-limit 300s
```

记录：
- CPU 使用率（top 或 perf stat）
- 内存占用
- 完成时间

### 第三步：对比 perf 输出

优化后应该看到：
- `do_epoll_ctl` 占比下降（期望 < 1.5%）
- `_copy_from_user` 占比下降（期望 < 0.8%）
- `syscall return` 占比下降

---

## 预期收益

- **CPU 占用**: 35-40% → 25-30%（内核态）
- **吞吐量**: +15-25%（相同时间内扫描更多 IP）
- **延迟**: 略微降低
- **内存**: +50-100MB（可接受）

---

## 风险分析

| 风险 | 概率 | 缓解方案 |
|------|------|--------|
| 内存占用过高 | 低 | 监控，必要时调整缓冲区大小 |
| 某些协议不兼容 | 极低 | 充分测试不同的 banner 大小 |
| 旧系统兼容性 | 低 | 缓冲区大小不会导致兼容性问题 |

---

## 后续进阶优化（如果还有性能空间）

1. **使用 SO_REUSEPORT**: 多 epoll 线程（需要改变架构）
2. **Protocol Buffers**: 替换当前的文本协议（高风险）
3. **零拷贝**: 使用 `sendfile` 或 `splice`（协议不适用）
4. **NUMA 感知调度**: 在大型服务器上（可选）

