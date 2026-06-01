#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

INPUT_FILE="$ROOT_DIR/result/chaos_test_cidr_input.txt"
STATE_DIR="$ROOT_DIR/result/distributed_state_chaos"

rm -rf "$STATE_DIR"
mkdir -p "$STATE_DIR"

rm -f "$INPUT_FILE"
for i in $(seq 1 60); do
  echo "10.$((i / 256)).$((i % 256)).0/24" >> "$INPUT_FILE"
done

cmake -S . -B build >/dev/null
cmake --build build --target scanner_ingest --target scanner_distributed -- -j4 >/dev/null

echo "[0/4] run ingest to build chunks + topic"
./build/scanner_ingest \
  --input "$INPUT_FILE" \
  --state-dir "$STATE_DIR" \
  --target-batch-cost 12 \
  --max-batch-lines 6 \
  --max-chunk-lines 40 \
  >"$STATE_DIR/ingest.log" 2>&1

echo "[1/4] start worker-A"
./build/scanner_distributed \
  --state-dir "$STATE_DIR" \
  --worker-id worker-A \
  --queue-max 20 \
  --queue-low 8 \
  --queue-high 16 \
  --lease-ms 10000 \
  --max-attempts 3 \
  --simulate-sleep-seconds 3 \
  >"$STATE_DIR/worker-A.log" 2>&1 &
PID_A=$!

echo "worker-A pid=$PID_A"
sleep 4

echo "[2/4] kill worker-A (simulate crash)"
if ps -p "$PID_A" >/dev/null 2>&1; then
  kill -9 "$PID_A" || true
else
  echo "worker-A already exited before kill"
fi
sleep 1

echo "[3/4] restart worker-B from persisted state"
./build/scanner_distributed \
  --state-dir "$STATE_DIR" \
  --worker-id worker-B \
  --queue-max 20 \
  --queue-low 8 \
  --queue-high 16 \
  --lease-ms 10000 \
  --max-attempts 3 \
  --simulate-sleep-seconds 1 \
  >"$STATE_DIR/worker-B.log" 2>&1

echo "[4/4] done, inspect state files"
ls -lh "$STATE_DIR" || true

if [[ -f "$STATE_DIR/queue_progress.json" ]]; then
  echo "queue_progress.json:"
  cat "$STATE_DIR/queue_progress.json"
fi

if [[ -f "$STATE_DIR/failed_batches.jsonl" ]]; then
  echo "failed_batches.jsonl:"
  cat "$STATE_DIR/failed_batches.jsonl"
fi

echo "logs:"
echo "  $STATE_DIR/ingest.log"
echo "  $STATE_DIR/worker-A.log"
echo "  $STATE_DIR/worker-B.log"
