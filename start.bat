@echo off
rem Web 安全扫描器 —— 生产启动脚本（对外可访问，绑定 0.0.0.0）
cd /d %~dp0
call .venv\Scripts\activate.bat
uvicorn api:app --host 0.0.0.0 --port 8000
