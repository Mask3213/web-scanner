@echo off
cd /d %~dp0
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] virtual env activate failed
    pause
    exit /b 1
)
uvicorn api:app --host 0.0.0.0 --port 8000
pause
