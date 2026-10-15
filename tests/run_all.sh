#!/bin/bash
# NextBastion 发版回归门禁（R13）
# 用法: ./run_all.sh <目标服务器IP>
#   API:  服务器本机跑（需 /opt/nextbastion/venv/bin/python）
#   前端: 本地 Playwright 跑（需 NODE_TLS_REJECT_UNAUTHORIZED=0 + chromium）
set -euo pipefail
HOST=${1:-127.0.0.1}
echo "===== 1/2 API 回归（$HOST）====="
/opt/nextbastion/venv/bin/python tests/api_regression.py
echo "===== 2/2 前端回归 ====="
NODE_TLS_REJECT_UNAUTHORIZED=0 node tests/frontend_regression.js
echo "===== 回归完成 ====="
