#!/usr/bin/env bash
# /opt/scanner/bin/run_scan.sh
# Wrapper for single-protocol scan
# Usage: run_scan.sh <PROTOCOL> [input_file]
#
# Environment variables:
#   SCANNER_INPUT    - input file path (default: /opt/scanner/input/targets.txt)
#   SCANNER_CONFIG   - config file path (default: /opt/scanner/config/scanner_config.json)
#   EXTRA_ARGS       - additional scanner arguments

set -euo pipefail

PROTOCOL="${1:?Usage: $0 <PROTOCOL> [input_file]}"
INPUT_FILE="${2:-${SCANNER_INPUT:-/opt/scanner/input/targets.txt}}"
CONFIG_FILE="${SCANNER_CONFIG:-/opt/scanner/config/scanner_config.json}"

SCANNER_BIN="/opt/scanner/bin/scanner"
BASE_DIR="/opt/scanner"

# 按协议分输出目录，防止结果混杂
export OUTPUT_DIR="${BASE_DIR}/output/${PROTOCOL}"

cd "$BASE_DIR"
mkdir -p "$OUTPUT_DIR" logs

exec "$SCANNER_BIN" \
    --config "$CONFIG_FILE" \
    --domains "$INPUT_FILE" \
    --protocols "$PROTOCOL" \
    --output "$OUTPUT_DIR" \
    --scan \
    ${EXTRA_ARGS:-}
