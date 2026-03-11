@echo off
REM Campus Network Monitor - Backend Startup Script for Windows

echo ==========================================
echo Campus Network Traffic Analyzer
echo Starting Backend...
echo ==========================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed
    pause
    exit /b 1
)

REM Navigate to backend directory
cd /d "%~dp0backend"

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing/updating dependencies...
pip install -r requirements.txt -q

echo.
echo ==========================================
echo Starting Backend Server...
echo API will be available at: http://localhost:8000
echo API Docs: http://localhost:8000/docs
echo ==========================================
echo.
echo Note: Packet capture requires Administrator privileges
echo If you see permission errors, run this script as Administrator
echo.

REM Start the backend
python main.py

pause
