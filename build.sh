#!/usr/bin/env bash
# Protocol Scanner 通用构建脚本（依赖提示 + CMake 驱动）

set -euo pipefail

BUILD_TYPE=${1:-Release}
CLEAN_BUILD=${2:-false}
EXTRA_CMAKE_ARGS=${EXTRA_CMAKE_ARGS:-}
GENERATOR=${CMAKE_GENERATOR:-}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD_DIR=${BUILD_DIR:-${SCRIPT_DIR}/build}

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
echo ""

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
echo ""
echo "Usage:"
echo "  $BUILD_DIR/scanner --help"
echo "  $BUILD_DIR/scanner --domains domains.txt --scan"
echo ""
echo "Tip: disable logging at build time with:"
echo "  EXTRA_CMAKE_ARGS=\"-DENABLE_LOGGING=OFF\" ./build.sh"
