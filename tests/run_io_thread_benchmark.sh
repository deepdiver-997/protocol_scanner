#!/bin/bash

# IO Thread Count Benchmarking Script
# Tests different IO thread counts to find optimal configuration

set -e

cd "$(dirname "$0")/.."

INPUT_FILE="tests/test_cidr_input.txt"
OUTPUT_DIR="tests/output/benchmark"
CONFIG_FILE="config/scanner_config.json"
SCANNER="./build/scanner"

SUMMARY_FILE="$OUTPUT_DIR/io_thread_benchmark_summary.txt"
TOTAL_IPS=20480

# Create output directory and summary file
mkdir -p "$OUTPUT_DIR"
echo "IO Thread Count Benchmark" > "$SUMMARY_FILE"
echo "Generated: $(date)" >> "$SUMMARY_FILE"
echo "Input: $INPUT_FILE" >> "$SUMMARY_FILE"
echo "Config: $CONFIG_FILE (default settings, only io_thread_count overridden)" >> "$SUMMARY_FILE"
echo "Protocols: FTP, SSH, TELNET" >> "$SUMMARY_FILE"
echo "Total IPs: $TOTAL_IPS" >> "$SUMMARY_FILE"
echo "Output directory (per run): $OUTPUT_DIR" >> "$SUMMARY_FILE"
echo "=========================================" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

echo "========================================="
echo "IO Thread Count Benchmark"
echo "========================================="
echo "Input: $INPUT_FILE"
echo "Output: $OUTPUT_DIR"
echo "Total IPs: $TOTAL_IPS (1.0.16.0/20 + 1.0.64.0/18)"
echo "Protocols: FTP, SSH, TELNET"
echo "Using config: $CONFIG_FILE (default settings, only io_thread_count overridden)"
echo ""
echo "========================================="

# Test different IO thread counts
# Format: io_threads -> result_file
declare -a THREADS=(4 8 12 16)

echo ""
echo "Starting benchmark..."
echo "Testing ${#THREADS[@]} different thread configurations..."
echo ""

printf "%-12s %-15s %-15s %-10s\n" "IO Threads" "Time (s)" "Throughput (IP/s)" "Results" | tee -a "$SUMMARY_FILE"
echo "-----------------------------------------------------------" | tee -a "$SUMMARY_FILE"

for threads in "${THREADS[@]}"; do
    run_dir="$OUTPUT_DIR/io_${threads}_threads"
    result_file="$run_dir/scan_results.txt"
    log_file="$run_dir/run.log"

    echo "-----------------------------------------"
    echo "Testing IO threads: $threads"
    echo "-----------------------------------------"

    rm -rf "$run_dir"
    mkdir -p "$run_dir"

    if command -v gtime >/dev/null 2>&1; then
        gtime -v "$SCANNER" \
            --config "$CONFIG_FILE" \
            --domains "$INPUT_FILE" \
            --scan \
            --io-threads "$threads" \
            --protocols FTP,SSH,TELNET \
            --output "$run_dir" \
            --quiet \
            > "$log_file" 2>&1 || true
        elapsed=$(grep "Elapsed" "$log_file" | awk '{print $2}' || echo "N/A")
    else
        start=$(date +%s.%N)
        "$SCANNER" \
            --config "$CONFIG_FILE" \
            --domains "$INPUT_FILE" \
            --scan \
            --io-threads "$threads" \
            --protocols FTP,SSH,TELNET \
            --output "$run_dir" \
            --quiet \
            > "$log_file" 2>&1 || true
        end=$(date +%s.%N)
        elapsed=$(echo "$end - $start" | bc)
        echo "Elapsed $elapsed" >> "$log_file"
    fi

    result_count=0
    if [ -f "$result_file" ]; then
        result_count=$(wc -l < "$result_file" 2>/dev/null || echo 0)
    fi

    if [ "$elapsed" != "N/A" ] && [ "$elapsed" != "0" ]; then
        throughput=$(echo "scale=2; $TOTAL_IPS / $elapsed" | bc)
    else
        throughput="N/A"
    fi

    printf "%-12s %-15s %-15s %-10s\n" "$threads" "$elapsed" "$throughput" "$result_count" | tee -a "$SUMMARY_FILE"

    echo "" >> "$SUMMARY_FILE"
    echo "[IO $threads] Log tail" >> "$SUMMARY_FILE"
    echo "-----------------------------------------" >> "$SUMMARY_FILE"
    tail -n 10 "$log_file" >> "$SUMMARY_FILE" 2>/dev/null || true
    echo "" >> "$SUMMARY_FILE"

    echo ""
done

echo "========================================="
echo "Benchmark Complete"
echo "========================================="
echo "Results saved to: $SUMMARY_FILE"
echo "Detailed per-run logs: $OUTPUT_DIR/io_<threads>_threads/run.log"
echo "Per-run scanner outputs: $OUTPUT_DIR/io_<threads>_threads/scan_results.txt"
