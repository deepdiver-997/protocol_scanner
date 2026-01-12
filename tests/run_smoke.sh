#!/usr/bin/env bash
# Simple smoke test: runs scanner with a small domain list and captures JSON output under tests/output

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCANNER_BIN=${SCANNER_BIN:-"${ROOT_DIR}/build/scanner"}
DOMAINS_FILE="${ROOT_DIR}/tests/data/domains_smoke.txt"
OUTPUT_FILE="${ROOT_DIR}/tests/output/smoke_result.json"

if [ ! -x "$SCANNER_BIN" ]; then
    echo "Scanner binary not found at $SCANNER_BIN"
    echo "Build first: ./build.sh Release"
    exit 1
fi

mkdir -p "${ROOT_DIR}/tests/output"

# Run from project root so default config paths resolve (./config/...)
pushd "$ROOT_DIR" >/dev/null
"$SCANNER_BIN" --domains "$DOMAINS_FILE" --scan --format json > "$OUTPUT_FILE"
popd >/dev/null

echo "Smoke test complete. Output saved to: $OUTPUT_FILE"
