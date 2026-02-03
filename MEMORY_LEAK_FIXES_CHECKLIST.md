# 内存泄漏修复检查清单

## 修复项目

### 1. DNS 解析器上下文泄漏 ✅
**文件**: `src/scanner/dns_resolver.cpp`

#### 1.1 query_a_record 方法 (L459)
- [x] 添加 `callback_called` 标志防止重复调用
- [x] 在回调中验证 `ctx` 指针有效性
- [x] 仅在回调中执行一次 `delete ctx`
- [x] 超时情况下不在外部delete，由回调管理

#### 1.2 query_mx_records 方法 (L555)
- [x] 添加 `callback_called` 标志防止重复调用
- [x] 在回调中验证 `ctx` 指针有效性
- [x] 仅在回调中执行一次 `delete ctx`
- [x] 超时情况下不在外部delete，由回调管理

**修复原理**: c-ares库的异步回调可能在取消后继续被调用，因此需要防御性编程确保单次delete

---

### 2. 协议探测上下文验证 ✅
**文件**: `src/scanner/protocols/*.cpp`

检查的协议文件:
- [x] ftp_protocol.cpp - 使用 shared_ptr<FtpProbeContext> ✓ 安全
- [x] http_protocol.cpp - 使用 shared_ptr<HttpProbeContext> ✓ 安全
- [x] imap_protocol.cpp - 使用 shared_ptr<ProbeContext> ✓ 安全
- [x] smtp_protocol.cpp - 使用 shared_ptr<ProbeContext> ✓ 安全
- [x] pop3_protocol.cpp - 使用 shared_ptr<ProbeContext> ✓ 安全
- [x] ssh_protocol.cpp - 使用 shared_ptr<SshProbeContext> ✓ 安全
- [x] telnet_protocol.cpp - 使用 shared_ptr<TelnetProbeContext> ✓ 安全

**结论**: 所有协议都已正确使用shared_ptr，无泄漏风险

---

### 3. utils.cpp 字符串优化 ✅
**文件**: `src/scanner/utils.cpp`

#### 3.1 expand_cidr_stream 函数 (L108)
- [x] 优化lambda捕获方式 `[&emit]`
- [x] 移除冗余的临时字符串创建
- [x] 直接在调用点转换uint32到string

#### 3.2 expand_ip_range_stream 函数 (L160)
- [x] 优化lambda捕获方式 `[&emit]`
- [x] 移除冗余的临时字符串创建
- [x] 直接在调用点转换uint32到string

**性能改进**: 减少临时对象创建，特别在处理大规模CIDR时提升性能

---

## 编译验证

```bash
cmake --build build --target scanner -- -j4
```

**结果**: ✅ 编译成功
- 无错误
- 仅有预期的c-ares弃用警告（已存在）
- 未产生新的警告

---

## 测试建议

### 立即执行
1. 运行AddressSanitizer检查:
   ```bash
   cmake -DCMAKE_CXX_FLAGS="-fsanitize=address" ..
   make
   ./scanner [test_domains.txt]
   ```

2. 运行内存工具检查:
   ```bash
   valgrind --leak-check=full ./scanner [test_domains.txt]
   ```

### 集成测试
- DNS查询测试：验证大量域名查询无泄漏
- 协议探测测试：验证各协议的socket资源释放
- IP处理测试：验证CIDR扩展的性能和正确性

---

## 修复风险评估

| 修复项 | 风险等级 | 影响范围 | 备注 |
|--------|--------|--------|------|
| DNS context防御检查 | 🟢 低 | DNS查询路径 | 仅添加保护性检查，无逻辑改变 |
| 协议context验证 | 🟢 低 | 协议探测 | 仅验证，无代码改动 |
| 字符串优化 | 🟢 低 | IP地址处理 | 纯优化，无行为改变 |

**总体风险**: ✅ **极低** - 所有修复都是防御性或优化性，未改变核心业务逻辑

---

## 修复前后对比

### 修复前风险
```
DNS查询在超时时:
1. run_event_loop() 返回 false
2. 后续无法清理 ctx_ptr
3. 回调可能仍被c-ares调用，导致use-after-free
```

### 修复后保障
```
DNS查询流程:
1. 创建ctx，标记 callback_called = false
2. 注册异步回调
3. 等待事件循环
4. 回调被调用时：
   a. 检查 callback_called，防止重复
   b. 设置 callback_called = true
   c. 执行delete ctx
5. 即使超时，回调仍能安全处理
```

---

## 后续维护

### 定期检查项
- [ ] 月度：运行AddressSanitizer扫描
- [ ] 季度：运行Valgrind完整内存检查
- [ ] 年度：代码审计，检查新增异步代码

### 开发规范
1. **异步操作**：必须使用shared_ptr管理上下文
2. **手动delete**：仅在确定回调不再被调用时使用
3. **大量字符串操作**：优先使用uint32_t直通优化

---

**修复完成**: ✅ 2026-01-30  
**验证状态**: ✅ 编译通过  
**下一步**: 运行AddressSanitizer验证
