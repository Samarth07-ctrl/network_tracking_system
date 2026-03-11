#!/bin/bash
# Campus Network Monitor - Frontend Startup Script

echo "=========================================="
echo "Campus Network Traffic Analyzer"
echo "Starting Frontend..."
echo "=========================================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Error: Node.js is not installed"
    exit 1
fi

# Navigate to frontend directory
cd "$(dirname "$0")/frontend"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies (this may take a few minutes)..."
    npm install
fi

echo ""
echo "=========================================="
echo "Starting Frontend Development Server..."
echo "Dashboard will be available at: http://localhost:3000"
echo "=========================================="
echo ""

# Start the frontend
npm start
