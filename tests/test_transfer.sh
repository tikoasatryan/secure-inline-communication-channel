#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

make all

mkdir -p sender receiver
printf 'TCP file transfer test from the secure-inline-channel project.\n' > sender/test-input.txt
rm -f receiver/test-output.txt

./build/receiver 19090 receiver/test-output.txt &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

sleep 1
./build/sender 127.0.0.1 19090 sender/test-input.txt

wait "$SERVER_PID" || true
cmp sender/test-input.txt receiver/test-output.txt
echo "PASS: TCP file transfer contents match."
