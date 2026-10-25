#!/usr/bin/env bash
# 批量 Web 漏洞扫描 GUI 启动器
#   ./gui/run.sh                # 127.0.0.1:8899
#   ./gui/run.sh 9100           # 换端口
#   ./gui/run.sh 9100 0.0.0.0   # 对外监听（仅限受控内网）
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${1:-8899}"
HOST="${2:-127.0.0.1}"
echo "启动 GUI: http://${HOST}:${PORT}/  （Ctrl+C 结束）"
exec python3 gui/server.py --host "${HOST}" --port "${PORT}"
