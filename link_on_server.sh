#!/usr/bin/env bash
# 服务器端链接脚本 - 在 Ubuntu x64 服务器上完成最终链接
# 使用从 Mac 上交叉编译生成的目标文件

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD_DIR=${BUILD_DIR:-${SCRIPT_DIR}/build-linux-x64}
FINAL_BINARY=${1:-scanner}

echo "========================================="
echo "Protocol Scanner - Server-side Linking"
echo "========================================="
echo "Build Dir: $BUILD_DIR"
echo "Output Binary: $FINAL_BINARY"
echo ""

# 检查必要的依赖库
check_dependencies() {
    local missing=()
    
    echo "Checking dependencies..."
    
    # 检查开发库
    for lib in libboost-system libboost-program-options libboost-filesystem libc-ares libfmt nlohmann-json3-dev libspdlog; do
        if ! dpkg -l | grep -q "^ii.*$lib"; then
            missing+=("$lib")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Error: Missing dependencies: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  sudo apt-get update"
        echo "  sudo apt-get install libboost-all-dev libc-ares-dev libfmt-dev nlohmann-json3-dev libspdlog-dev"
        exit 1
    fi
    
    echo "✓ All dependencies found"
}

# 检查构建目录
if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: Build directory not found: $BUILD_DIR"
    echo "Please upload the cross-compiled build directory from Mac first."
    exit 1
fi

cd "$BUILD_DIR"

# 检查是否有 CMake 构建文件
if [ ! -f "CMakeCache.txt" ]; then
    echo "Error: CMakeCache.txt not found. Invalid build directory."
    exit 1
fi

check_dependencies

echo ""
echo "Performing final link on server..."

# 重新运行 CMake 配置（使用本地编译器和库）
cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER=/usr/bin/g++ \
    -DCMAKE_C_COMPILER=/usr/bin/gcc \
    "$SCRIPT_DIR"

# 只执行链接步骤
cmake --build . --target scanner -- -j$(nproc)

# 检查生成的二进制文件
if [ -f "scanner" ]; then
    echo ""
    echo "========================================="
    echo "Linking completed successfully!"
    echo "========================================="
    echo "Binary: $BUILD_DIR/scanner"
    echo ""
    
    # 显示二进制信息
    echo "Binary info:"
    file scanner
    echo ""
    
    echo "Shared library dependencies:"
    ldd scanner || true
    echo ""
    
    # 可选：复制到指定位置
    if [ "$FINAL_BINARY" != "scanner" ]; then
        cp scanner "$SCRIPT_DIR/$FINAL_BINARY"
        echo "Copied to: $SCRIPT_DIR/$FINAL_BINARY"
    fi
    
    echo "Done! You can now run: $BUILD_DIR/scanner --help"
else
    echo "Error: Failed to generate scanner binary"
    exit 1
fi
