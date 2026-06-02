#!/usr/bin/env bash
# Protocol Scanner 通用构建脚本（依赖提示 + CMake 驱动）
# 支持模式：Debug / Release（无日志）/ InfoRelease（仅INFO/ERROR日志）
# 支持交叉编译：CROSS_COMPILE=linux-x64 ./build.sh

set -euo pipefail

BUILD_TYPE=${1:-Release}
CLEAN_BUILD=${2:-false}
EXTRA_CMAKE_ARGS=${EXTRA_CMAKE_ARGS:-}
GENERATOR=${CMAKE_GENERATOR:-}
CROSS_COMPILE=${CROSS_COMPILE:-}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# 根据交叉编译模式选择构建目录
if [ -n "$CROSS_COMPILE" ]; then
    BUILD_DIR=${BUILD_DIR:-${SCRIPT_DIR}/build-${CROSS_COMPILE}}
else
    BUILD_DIR=${BUILD_DIR:-${SCRIPT_DIR}/build}
fi

# 验证构建类型
if [[ ! "$BUILD_TYPE" =~ ^(Debug|Release|InfoRelease)$ ]]; then
    echo "Error: BUILD_TYPE must be Debug, Release, or InfoRelease"
    exit 1
fi

cpu_count() {
    if command -v getconf >/dev/null 2>&1; then
        getconf _NPROCESSORS_ONLN
    elif command -v sysctl >/dev/null 2>&1; then
        sysctl -n hw.ncpu
    else
        echo 4
    fi
}

platform_hint() {
    local msg="Missing dependencies."
    case "$(uname -s)" in
        Darwin)
            msg+=" macOS install: brew install boost c-ares fmt nlohmann-json spdlog";;
        Linux)
            if command -v apt-get >/dev/null 2>&1; then
                msg+=" Ubuntu/Debian: sudo apt-get install libboost-all-dev libc-ares-dev libfmt-dev nlohmann-json3-dev libspdlog-dev";
            elif command -v yum >/dev/null 2>&1; then
                msg+=" RHEL/CentOS: sudo yum install boost-devel c-ares-devel fmt-devel nlohmann-json-devel spdlog-devel";
            elif command -v dnf >/dev/null 2>&1; then
                msg+=" Fedora: sudo dnf install boost-devel c-ares-devel fmt-devel nlohmann-json-devel spdlog-devel";
            elif command -v pacman >/dev/null 2>&1; then
                msg+=" Arch: sudo pacman -S boost c-ares fmt nlohmann-json spdlog";
            fi;;
    esac
    echo "$msg"
}

echo "========================================="
echo "Protocol Scanner Build Script"
echo "========================================="
echo "Build Type: $BUILD_TYPE"
echo "Clean Build: $CLEAN_BUILD"
echo "Build Dir: $BUILD_DIR"
echo "Generator: ${GENERATOR:-auto}"
echo "Cross Compile: ${CROSS_COMPILE:-native}"
echo ""

# 为 InfoRelease 设置额外参数
if [ "$BUILD_TYPE" = "InfoRelease" ]; then
    EXTRA_CMAKE_ARGS="${EXTRA_CMAKE_ARGS} -DENABLE_LOGGING=ON"
    # 【修复】不再把 BUILD_TYPE 改成 Release，直接使用 InfoRelease
    # 这样 CMake 会使用 CMAKE_CXX_FLAGS_INFORELEASE（包含 -DENABLE_LOGGING_INFO）
    echo "Note: InfoRelease builds with Release optimizations and INFO/ERROR logging enabled"
    echo ""
elif [ "$BUILD_TYPE" = "Release" ]; then
    # 默认 Release 关闭日志
    EXTRA_CMAKE_ARGS="${EXTRA_CMAKE_ARGS} -DENABLE_LOGGING=OFF"
fi

if [ "$CLEAN_BUILD" = "true" ] || [ "$CLEAN_BUILD" = "clean" ]; then
    echo "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"

if ! command -v cmake >/dev/null 2>&1; then
    echo "cmake not found. $(platform_hint)"
    exit 1
fi

if ! command -v pkg-config >/dev/null 2>&1; then
    echo "Warning: pkg-config not found; dependency discovery may be slower. $(platform_hint)"
fi

# 设置交叉编译工具链
if [ -n "$CROSS_COMPILE" ]; then
    case "$CROSS_COMPILE" in
        linux-x64|linux-x86_64)
            TOOLCHAIN_FILE="$SCRIPT_DIR/cmake/linux-x64-toolchain.cmake"
            if [ ! -f "$TOOLCHAIN_FILE" ]; then
                echo "Error: Toolchain file not found: $TOOLCHAIN_FILE"
                exit 1
            fi
            EXTRA_CMAKE_ARGS="${EXTRA_CMAKE_ARGS} -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE"
            echo "Using cross-compilation toolchain: linux-x64"
            echo "Note: Ensure x86_64-linux-gnu-gcc/g++ is installed"
            echo "  macOS: See CROSS_COMPILE.md for installation instructions"
            ;;
        *)
            echo "Error: Unknown cross-compile target: $CROSS_COMPILE"
            echo "Supported targets: linux-x64"
            exit 1
            ;;
    esac
    echo ""
fi

echo "Configuring with CMake..."
cmake \
    -S "$SCRIPT_DIR" \
    -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    ${GENERATOR:+-G "$GENERATOR"} \
    $EXTRA_CMAKE_ARGS

echo "Building..."
cmake --build "$BUILD_DIR" -- -j"$(cpu_count)" 2>&1 | tee "$BUILD_DIR"/build.log

echo ""
echo "========================================="
echo "Build completed"
echo "========================================="
echo "Executable: $BUILD_DIR/scanner"
echo "Unit tests: $BUILD_DIR/unit_test"
echo ""
echo "Usage:"
echo "  $BUILD_DIR/scanner --help"
echo "  $BUILD_DIR/scanner --domains domains.txt --scan"
echo "  $BUILD_DIR/unit_test                                          # 运行单元测试"
echo ""
echo "Tip: disable logging at build time with:"
echo "  EXTRA_CMAKE_ARGS=\"-DENABLE_LOGGING=OFF\" ./build.sh"
