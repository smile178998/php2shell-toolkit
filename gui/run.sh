#!/usr/bin/env bash
# Batch web vulnerability scanning GUI launcher
#   ./gui/run.sh                # 127.0.0.1:8899
#   ./gui/run.sh 9100           # change port
#   ./gui/run.sh 9100 0.0.0.0   # listen on all interfaces (controlled intranet only)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${1:-8899}"
HOST="${2:-127.0.0.1}"
echo "Starting GUI: http://${HOST}:${PORT}/  (Ctrl+C to stop)"
exec python3 gui/server.py --host "${HOST}" --port "${PORT}"
