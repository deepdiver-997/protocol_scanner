# 交叉编译指南 - Mac 到 Linux x64

本文档介绍如何在 Mac 上交叉编译项目，并在 Ubuntu x64 服务器上完成最终链接。

## 概述

这种方案的优势：
- ✅ 在本地 Mac 上进行大部分编译工作（速度快）
- ✅ 最终链接在目标服务器上完成（确保二进制兼容性）
- ✅ 生成的二进制文件与直接在服务器编译完全一致
- ✅ 无需手动设置 LD_LIBRARY_PATH 或 RPATH

## 工作流程

```
Mac 本地              服务器
  ↓                    ↓
编译源文件 → 上传 → 链接生成可执行文件
(.o 文件)            (scanner 二进制)
```

---

## 第一步：在 Mac 上安装交叉编译工具链

### 方案 1：使用 Homebrew（推荐）✅

已验证可用的完整工具链包含 gcc/g++：

```bash
brew tap messense/macos-cross-toolchains
brew install x86_64-unknown-linux-gnu

# 如果之前安装过 x86_64-linux-gnu-binutils，需要解决冲突
brew unlink x86_64-linux-gnu-binutils
brew link --overwrite x86_64-unknown-linux-gnu

# 验证安装
x86_64-linux-gnu-g++ --version
# 应显示: x86_64-linux-gnu-g++ (GCC) 13.3.0
```

---

## 第二步：在 Mac 上进行交叉编译

### 2.1 编译（仅生成目标文件）

由于在 Mac 上没有 Linux 版的依赖库，我们只进行编译，不进行链接。CMake 工具链已配置为支持这种模式。

```bash
# Mac 上只生成目标文件 (.o)
CROSS_COMPILE=linux-x64 ./build.sh Release

# 成功标志：
# - 所有 .cpp 文件都被编译成 .o 文件
# - 最后会在链接阶段报错（这是预期的，因为 Mac 上没有 Linux 库）
# - 构建目录在: build-linux-x64/
```

### 2.2 预期的编译输出

编译会成功完成直到链接阶段：

```
[ 10%] Building CXX object CMakeFiles/scanner.dir/src/scanner/main.cpp.o
...
[ 95%] Linking CXX executable scanner
/opt/homebrew/lib/libboost_program_options.dylib: file not recognized: file format not recognized
collect2: error: ld returned 1 exit status
```

这个错误是预期的 - 说明编译已成功，但链接失败（因为 Mac 库与 Linux 目标不兼容）。

### 2.3 查看生成的目标文件

```bash
# 查看目标文件是否已生成
ls -la build-linux-x64/CMakeFiles/scanner.dir/src/scanner/*.o

# 验证是 Linux x64 格式
file build-linux-x64/CMakeFiles/scanner.dir/src/scanner/main.cpp.o
# 应显示: ELF 64-bit LSB relocatable, x86-64, ...
```

---

## 第二步原文档已移除

旧的 sysroot 方案已简化。现在工作流更简洁：仅在 Mac 上编译，在 Ubuntu 上完成链接。

---

## 第三步：上传到服务器

```bash
# 打包构建目录
tar czf build-linux-x64.tar.gz build-linux-x64/

# 上传到服务器
scp build-linux-x64.tar.gz user@server:~/protocol-scanner/

# 或使用 rsync（更快，支持增量）
rsync -avz --progress build-linux-x64/ user@server:~/protocol-scanner/build-linux-x64/
```

---

## 第四步：在服务器上完成链接

在 Ubuntu 服务器上：

```bash
# 解压（如果使用 scp）
cd ~/protocol-scanner
tar xzf build-linux-x64.tar.gz

# 确保依赖已安装
sudo apt-get update
sudo apt-get install libboost-all-dev libc-ares-dev libfmt-dev \
    nlohmann-json3-dev libspdlog-dev

# 执行服务器端链接脚本
./link_on_server.sh

# 测试运行
./build-linux-x64/scanner --help
```

### 工作原理

`link_on_server.sh` 脚本会：
1. 检查所有必需的依赖库
2. 重新运行 CMake 配置（使用服务器本地的编译器和库）
3. 只执行链接步骤（目标文件已存在）
4. 生成最终的可执行文件

生成的二进制文件将：
- 使用服务器上的动态库（标准路径）
- RPATH 已正确设置，无需手动配置 LD_LIBRARY_PATH
- 与直接在服务器上编译的结果完全一致

---

## 验证二进制文件

```bash
# 检查文件类型
file build-linux-x64/scanner
# 应显示: ELF 64-bit LSB executable, x86-64, ... dynamically linked

# 检查动态库依赖
ldd build-linux-x64/scanner
# 应显示所有库都能找到（不应有 "not found"）

# 检查 RPATH
readelf -d build-linux-x64/scanner | grep RPATH
# 或
objdump -x build-linux-x64/scanner | grep RPATH

# 运行测试
./build-linux-x64/scanner --version
```

---

## 故障排除

### 问题 1：交叉编译器未找到

```
Error: CMAKE_CXX_COMPILER not set or not found
```

**解决**：确保交叉编译工具链已安装并在 PATH 中：

```bash
which x86_64-linux-gnu-g++
# 如果没有输出，需要安装工具链
```

### 问题 2：找不到头文件

```
fatal error: boost/asio.hpp: No such file or directory
```

**解决**：
1. 从服务器复制头文件到 sysroot
2. 或使用选项 B（仅编译不链接）

### 问题 3：服务器链接失败

```
undefined reference to `boost::system::...`
```

**解决**：确保服务器上安装了开发库：

```bash
sudo apt-get install libboost-all-dev libc-ares-dev libfmt-dev \
    nlohmann-json3-dev libspdlog-dev
```

### 问题 4：运行时找不到动态库

```
error while loading shared libraries: libboost_system.so.1.74.0
```

**解决**：
1. 检查库是否安装：`ldconfig -p | grep libboost`
2. 如果库存在但版本不同，安装运行时库：
   ```bash
   sudo apt-get install libboost-system1.74.0 libcares2 libfmt8
   ```

---

## 性能优化建议

### 增量编译

第一次编译后，后续修改只需：

```bash
# Mac 上
CROSS_COMPILE=linux-x64 ./build.sh Release

# 只同步修改的文件
rsync -avz --delete build-linux-x64/*.o user@server:~/protocol-scanner/build-linux-x64/

# 服务器上
./link_on_server.sh
```

### 并行编译

```bash
# 使用所有 CPU 核心
cmake --build build-linux-x64 -- -j$(sysctl -n hw.ncpu)
```

---

## 完整示例工作流

```bash
# === Mac 本地 ===

# 1. 安装工具链（首次）
brew tap messense/macos-cross-toolchains
brew install x86_64-unknown-linux-gnu

# 处理可能的冲突（如果之前安装过 x86_64-linux-gnu-binutils）
brew unlink x86_64-linux-gnu-binutils 2>/dev/null || true
brew link --overwrite x86_64-unknown-linux-gnu

# 验证安装
x86_64-linux-gnu-g++ --version

# 2. 交叉编译（只生成目标文件）
CROSS_COMPILE=linux-x64 ./build.sh Release

# 3. 检查目标文件是否生成
file build-linux-x64/CMakeFiles/scanner.dir/src/scanner/main.cpp.o
# 应显示: ELF 64-bit LSB relocatable, x86-64

# 4. 同步到服务器
rsync -avz --progress build-linux-x64/ user@server:~/protocol-scanner/build-linux-x64/
rsync -avz link_on_server.sh user@server:~/protocol-scanner/

# === Ubuntu 服务器 ===

# 5. 安装依赖（首次）
sudo apt-get update
sudo apt-get install -y build-essential cmake \
    libboost-all-dev libc-ares-dev libfmt-dev \
    nlohmann-json3-dev libspdlog-dev

# 6. 完成链接
cd ~/protocol-scanner
./link_on_server.sh

# 7. 验证和运行
./build-linux-x64/scanner --version
./build-linux-x64/scanner --help
```

---

## 与直接编译的对比

| 方面 | 交叉编译 + 服务器链接 | 直接在服务器编译 |
|------|---------------------|-----------------|
| 编译速度 | Mac 本地（快） | 服务器（可能较慢） |
| 二进制兼容性 | ✅ 完全一致 | ✅ 完全一致 |
| RPATH 设置 | ✅ 自动正确 | ✅ 自动正确 |
| 依赖管理 | 需要两边都有 | 只需服务器 |
| 设置复杂度 | 中等 | 简单 |
| 增量编译 | ✅ 支持 | ✅ 支持 |

---

## 参考资料

- [CMake Cross Compiling](https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html#cross-compiling)
- [osxcross](https://github.com/tpoechtrager/osxcross)
- [RPATH and RUNPATH](https://amir.rachum.com/blog/2016/09/17/shared-libraries/)

---

## 联系与支持

如有问题，请查看：
- [README.md](README.md) - 项目说明
- [PRODUCTION_BUILD.md](PRODUCTION_BUILD.md) - 生产环境构建
