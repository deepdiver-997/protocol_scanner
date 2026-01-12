#!/bin/bash
# 简单测试脚本

echo "Protocol Scanner - Quick Test"
echo "================================"

cd /Users/zhuhongrui/Desktop/code/c++/protocol-scanner

# 检查依赖
echo "Checking dependencies..."

if ! command -v cmake &> /dev/null; then
    echo "ERROR: cmake not found"
    exit 1
fi

if ! command -v brew &> /dev/null; then
    if ! dpkg -l | grep -q cmake; then
        echo "ERROR: Neither brew nor apt found"
        exit 1
    fi
fi

echo "✓ cmake found"

# 检查 Boost
if [ -d "/opt/homebrew/opt/boost" ] || [ -d "/usr/local/opt/boost" ]; then
    echo "✓ Boost found"
else
    echo "WARNING: Boost not found, may need installation"
fi

# 检查 OpenMP
if [ -f "/opt/homebrew/opt/libomp/lib/libomp.dylib" ] || [ -f "/usr/local/lib/libomp.dylib" ]; then
    echo "✓ OpenMP found"
else
    echo "WARNING: OpenMP not found, run: brew install libomp"
fi

echo ""
echo "Building project..."
./build.sh Release

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Build successful!"
    echo ""
    echo "Running simple test..."
    cd build
    ctest --verbose 2>&1 | head -20
    
    echo ""
    echo "Testing scanner --help..."
    ./scanner --help
else
    echo ""
    echo "✗ Build failed!"
    exit 1
fi

echo ""
echo "Test completed!"
