#!/usr/bin/env bash
# Alpha Blockchain node — Linux / macOS
cd "$(dirname "$0")"
echo "=== Alpha node — leave running (Ctrl+C to stop) ==="
./alphad --chain main --datadir ./data
