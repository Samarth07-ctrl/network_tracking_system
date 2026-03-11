@echo off
REM Campus Network Monitor - Frontend Startup Script for Windows

echo ==========================================
echo Campus Network Traffic Analyzer
echo Starting Frontend...
echo ==========================================

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo Error: Node.js is not installed
    pause
    exit /b 1
)

REM Navigate to frontend directory
cd /d "%~dp0frontend"

REM Check if node_modules exists
if not exist "node_modules" (
    echo Installing dependencies (this may take a few minutes)...
    call npm install
)

echo.
echo ==========================================
echo Starting Frontend Development Server...
echo Dashboard will be available at: http://localhost:3000
echo ==========================================
echo.

REM Start the frontend
call npm start

pause
