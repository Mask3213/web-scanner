#!/usr/bin/env bash
# Web 安全扫描器 —— 生产启动脚本（Linux 云服务器用）
cd "$(dirname "$0")"
source .venv/bin/activate
uvicorn api:app --host 0.0.0.0 --port 8000
