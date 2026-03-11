#!/bin/bash
# Campus Network Monitor - Backend Startup Script

echo "=========================================="
echo "Campus Network Traffic Analyzer"
echo "Starting Backend..."
echo "=========================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Check if MySQL is running
if ! pgrep -x "mysqld" > /dev/null; then
    echo "Warning: MySQL doesn't appear to be running"
    echo "Start MySQL first: sudo systemctl start mysql"
fi

# Navigate to backend directory
cd "$(dirname "$0")/backend"

# Check if dependencies are installed
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing/updating dependencies..."
pip install -r requirements.txt -q

echo ""
echo "=========================================="
echo "Starting Backend Server..."
echo "API will be available at: http://localhost:8000"
echo "API Docs: http://localhost:8000/docs"
echo "=========================================="
echo ""
echo "Note: Packet capture requires root privileges"
echo "If you see permission errors, run with: sudo ./start_backend.sh"
echo ""

# Start the backend
python3 main.py
