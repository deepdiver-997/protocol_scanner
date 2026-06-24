# 架构演变与重大重构

> 从 2026 年 1 月初版到当前架构，历时 5 个月（实际活跃开发约 3 个月），
> 137 个提交，经历了轮询架构的长期统治、2.5 个月的沉寂期、以及 6 月的爆发式重构。

---

## 时间线概览

```
1/13 ────── 1/29 ──── 3/16 ──── 6/2 ─────────────────── 6/25
 密集开发    修bug     空白期     爆发重构（~100 commits）
 (29次)     (12次)   (2.5月)    新协议+并发修复+架构重写
```

---

## 第一阶段：轮询架构的诞生（1/13 - 1/29，29 次提交）

### 1.1 核心搭建

```
1/13  Initial commit: Multi-protocol scanner implementation
1/14  Updates some configures stuff.
1/15  Adding dynamic timeout strategy
1/16  Adding breakpoint continuation ability.     ← checkpoint 机制
1/18  Adding a new type of output format, fixed few bugs about dns.
1/19  fixed checkpoint might fail when fast restart twice in short time.
1/20  refactored some llm generated codes.        ← 第一次清理 AI 生成的代码
1/20  fixed dns might cause seg fault
1/26  support port reuse, added startup diagnostics
1/28  adding memory monitor, using pool to allocate sockets buffer
1/28  replace deletion of session with reuse       ← session 复用机制诞生
1/28  batch start, reduce loop times.              ← 轮询优化开始
1/28  adding dynamic scan_loop sleep time...       ← 动态 sleep
1/28  remove some atomic operation.                ← 性能微优化
1/28  fixed steady_clock hot point                 ← 时钟热点修复
1/29  fixed checkpoint.
1/29  Implement high and medium priority performance optimizations
1/29  find out why memory occupation is stably unbelievable high
      — one left behind function call loading all domains into memory
```

12 天内从零搭出了：多协议扫描、流式输入、checkpoint 断点续扫、session 复用、批量启动、动态 sleep、内存池。轮询架构已经成形且**一开始就遇到了性能问题**——1 月 28 日一天 8 个提交全部是 scan_loop 的优化。

### 1.2 轮询架构的本质

```cpp
while (true) {
    for (auto& s : sessions_) {          // O(N)
        if (s->ready_to_release()) {
            fetch_target() → reset() → start_one_probe()
        }
    }
    sleep(dynamic_ms);                   // batch_start / dynamic_sleep 在这里调
}
```

直观、单线程、容易理解。问题是 session 数大时遍历本身就是瓶颈，但当时并发量还不大，问题不明显。

---

## 第二阶段：修补期（1/30 - 3/16，12 次提交）

```
1/30  Staged reconstruction, cleared unused files
1/30  fixed memory leakage.
1/31  improve the systemd crash inspector.
2/3   fixed scan_loop might exit and left result thread cycling forever.
2/3   fixed count growing too fast error.
3/15  fix: 修复断点恢复顺序提交与缺漏风险
3/16  fixed struct name conflict.
```

主要是修 bug。项目逐渐稳定，然后进入了 2.5 个月的沉寂。

---

## 第三阶段：爆发重构（6/2 - 6/25，95 次提交）

### 3.1 协议大爆炸（6/2-6/5）

6 月 2 日一天 22 次提交，6 月 5 日 18 次提交。新增了 SSH/FTP/TELNET/REDIS/RTSP/SIP 协议、FTP FEAT 命令、SSH 版本解析、Redis PING/INFO、RTSP/SIP OPTIONS。

### 3.2 并发战争（6/5-6/10）

轮询架构在高并发下的问题集中爆发：

| 提交 | 问题 | 修复 |
|------|------|------|
| `61711a8` | mutex 竞争 | SpinLock 替代 std::mutex |
| `f2b195c` | 吞吐瓶颈 | max_work_count 提到 20000 + timeout 降到 3s |
| `d73ab3c` | 缓冲区池初始化 | 针对显式 max_work_count 调整 |
| `ff354a3` | BufferPool 锁竞争 | SpinLock 保护 |
| `d03ba3b` | 动态扩容重分配 | 预创建全部 session |
| `f302c57` | 系统打满 | ResourceGuard 检查 + systemd 资源限制 |
| `9472c55` | **全部 probe 钉在 context 0** | round-robin 替代 least_loaded |
| `f64a93f` | atomic 不可移动 | vector<unique_ptr<atomic>> |
| `77b20fe` | round-robin 仍不均 | 纯轮询 |
| `209a883` | 负载不可见 | acquire/release 实时计数 |

最关键的是 `9472c55`：6 个 io_context 的池子，`choose_least_loaded_index()` 在无负载时总返回 0——**所有 probe 跑在同一个 context 上**，另外 5 个完全空转。改了纯 round-robin。

### 3.3 部署与运维（6/10-6/18）

```
6/10  zmap 预过滤、心跳监控、watchdog
6/17  per-probe io_context 分配优化
6/18  signedness 警告修复、watchdog 阈值调大
```

### 3.4 架构总决战（6/23-6/25）

```
6/23  MCP专用入口 + Asio网络 + bind_ip全协议覆盖 + MySQL握手解析修复
6/24  map协议注册 + PGSQL/MONGO + auth_plugin offset修复
6/25  回调驱动 scan_loop ← 轮询架构在此终结
6/25  metrics采样改为请求驱动 + preflight
```

**轮询架构从 1 月 13 日存活到 6 月 24 日——5 个月。**

---

## 4. AI 参与开发的边界

AI 参与了大量开发，但有几个特征：

### 4.1 AI 擅长的事

- 对称模式复制：给 SSH 加 `bind_ip`，把同样逻辑加到其他 10 个协议——机械工作，AI 批量完成
- 单元测试编写：MySQL 握手包的 11 个测试场景
- 协议实现：PGSQL StartupMessage 构造、MongoDB BSON 解析

### 4.2 AI 不擅长的事

- **架构判断**：在轮询架构内反复打补丁（加动态 sleep、改配额计算、加 lazy creation），从没建议"推倒这个循环"
- **并发安全**：倾向于"多加一层保护"——`restarting_` CAS 门就是例子，`fetch_add` 已经保证了单回调，AI 还要加 CAS，且某些路径忘了释放导致死锁
- **偏移量计算**：MySQL 握手包的 auth_plugin offset 从旧代码一路错到新代码，AI 写的手工偏移量很难验证

### 4.3 关键教训

- 1 月 20 日就有 `refactored some llm generated codes`——AI 生成的代码从一开始就需要清理
- AI 给出的修复总是在问题所在的**同一层抽象**里——轮询慢了优化轮询，而不是质疑轮询这个抽象本身
- 根本性架构改变（回调驱动）需要人来做决策

---

## 5. 典型 bug 调查链：bind_ips 漏洞

**现象**：MySQL 1w 并发 SSH 卡死，Redis 2w 并发正常。

**假设 1** — conntrack 打满 → `max=524K`，峰值 67K → 排除

**假设 2** — 带宽打满 → 逐步提高 max_work_count（2000→5000→10000→20000）对照实验，网络恒定 ~7Mbps → 排除

**假设 3** — MySQL 协议更快，连接更替率更高 → 不对，IO 池是瓶颈

**真因**：只有 SSH 实现了 `bind_ip`。其余 10 个协议接受参数但从未 `socket.bind()`。单 IP 端口池 28K，ResourceGuard 按双 IP 56K 算。加上进程不退出 TIME_WAIT 累积。

**修复**：全部 13 个协议补 bind_ip。本地加 preflight 逐个 bind 验证。

---

## 6. MySQL 握手解析两连 bug

- **4 字节包头偏移**：解析器把包头当协议版本，只有包长恰好以 10 结尾的才过，42 万真 MySQL 只检出 37 个
- **auth_plugin offset**：跳过 filler 时把 1 字节当 2 字节，全体错位，42 万结果全显示 `_password`
- **单元测试跟着错**：`make_handshake` 没构造包头，测的是去掉包头的 payload，恰好和 bug 对齐

---

## 7. 其他关键事件

- **有序提交死锁**：缺失 seq 堵死整条管线，10s 超时跳过
- **double-free**：`results_.clear()` 无锁，ASan 捕获加 `lock_guard`
- **X-macro 妥协**：`#pragma once` 阻止二次 include，X-macro 退回手动注册
- **watchdog 误杀**：跨国网络波动 7 分钟未更新心跳，阈值 300s→600s
- **preflight 退出卡死**：`start()` 里 return 后 `get_results(-1)` 死等，补设置 `input_done_`/`scan_done_`

---

## 8. 当前架构（6/25）

```
Scanner::start()
 ├── preflight: bind_ip 逐个 bind() 验证
 ├── init_protocols: 遍历 protocol_enabled map
 ├── input_thread: 流式加载 targets_
 ├── scan_loop: 预创建 session → 回调驱动 → wait
 └── result_thread: commit_ready_reports + 写文件

scan_loop 内部（回调驱动，无轮询）:
 ├── on_restart callback: fetch → reset → start_all → 递归重试
 └── while(!stop_) sleep(100ms) + 懒创建 + 检查计数归零

metrics: GET /metrics → SnapshotProvider() → 2s 冷却 → JSON
ResourceGuard: min(ports×0.75×IPs, mem/80KB, (ct-1000)/4) 封顶
```
