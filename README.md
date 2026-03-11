# Campus Network Traffic Analyzer and Security Monitor

A production-ready academic project for monitoring and analyzing WiFi networks across a college campus. The system captures and analyzes network packets in real time, detects abnormal activity, and visualizes network traffic through an administrative dashboard.

## 🚀 Quick Start

### For the Impatient (5 Minutes)

See **[QUICKSTART.md](QUICKSTART.md)** for the fastest setup.

### For Detailed Instructions

See **[SETUP_GUIDE.md](SETUP_GUIDE.md)** for complete step-by-step instructions.

## Features

- **Real-time Packet Capture**: Monitor multiple campus WiFi networks simultaneously using Scapy
- **Traffic Analysis**: Analyze protocols (TCP, UDP, ICMP, DNS, HTTP, HTTPS), bandwidth usage, and traffic patterns
- **Device Tracking**: Identify and track all connected devices by MAC/IP address
- **Intrusion Detection**: Detect port scanning, DDoS attempts, brute force attacks, high bandwidth usage
- **DNS Monitoring**: Block and alert on prohibited website access
- **Admin Dashboard**: Real-time visualization with charts, graphs, and live packet feed
- **Performance Metrics**: Track throughput, packet rate, and network health

## System Architecture

```
Campus WiFi Access Points
         ↓
Packet Capture Module (Scapy)
         ↓
Traffic Analyzer
         ↓
Intrusion Detection Engine
         ↓
Database (MySQL)
         ↓
Backend API (FastAPI)
         ↓
Admin Dashboard (React)
```

## Tech Stack

- **Backend**: Python 3.9+, FastAPI, Scapy
- **Database**: MySQL 8.0+
- **Frontend**: React 18, Recharts
- **Packet Capture**: Scapy library

## Prerequisites

- Python 3.9 or higher
- Node.js 16 or higher
- MySQL 8.0 or higher
- Administrator/root privileges (for packet capture)

## Installation

### Method 1: Using Startup Scripts (Recommended)

#### Windows:
1. Double-click `start_backend.bat` (run as Administrator for packet capture)
2. Double-click `start_frontend.bat`

#### Linux/Mac:
```bash
# Make scripts executable (first time only)
chmod +x start_backend.sh start_frontend.sh

# Start backend (use sudo for packet capture)
./start_backend.sh

# In a new terminal, start frontend
./start_frontend.sh
```

### Method 2: Manual Setup

#### 1. Set Up Database

```bash
# Login to MySQL
mysql -u root -p

# Create database and user
CREATE DATABASE campus_network_monitor;
CREATE USER 'campus_monitor'@'localhost' IDENTIFIED BY 'changeme';
GRANT ALL PRIVILEGES ON campus_network_monitor.* TO 'campus_monitor'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Initialize schema
mysql -u campus_monitor -p campus_network_monitor < backend/schema.sql
```

#### 2. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

#### 3. Install Frontend Dependencies

```bash
cd frontend
npm install
```

## Running the System

### Using Startup Scripts

**Windows:**
- Run `start_backend.bat` (as Administrator)
- Run `start_frontend.bat`

**Linux/Mac:**
```bash
sudo ./start_backend.sh  # Terminal 1
./start_frontend.sh      # Terminal 2
```

### Manual Start

**Backend:**
```bash
cd backend
# With packet capture (requires sudo/admin)
sudo python main.py

# Without packet capture (for testing)
python main.py
```

**Frontend:**
```bash
cd frontend
npm start
```

### Access the Application

- **Dashboard**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **API Health Check**: http://localhost:8000

## Testing Without Packet Capture

If you can't run with admin privileges, you can still test the system by adding sample data to the database. See [QUICKSTART.md](QUICKSTART.md) for SQL commands to insert test data.

## Project Structure

```
campus-network-traffic-analyzer/
├── backend/
│   ├── main.py                 # Application entry point
│   ├── config.yaml             # System configuration
│   ├── requirements.txt        # Python dependencies
│   ├── schema.sql              # Database schema
│   ├── modules/
│   │   ├── packet_capture.py   # Packet capture module
│   │   ├── traffic_analyzer.py # Traffic analysis
│   │   ├── intrusion_detection.py # IDS engine
│   │   ├── database.py         # Database access layer
│   │   └── config_loader.py    # Configuration parser
│   └── api/
│       └── routes.py           # FastAPI endpoints
├── frontend/
│   ├── package.json
│   ├── public/
│   └── src/
│       ├── App.js
│       ├── components/
│       └── services/
└── README.md
```

## API Documentation

Once the backend is running, visit `http://localhost:8000/docs` for interactive API documentation.

## Security Considerations

- Packet capture requires root/administrator privileges
- Store database credentials securely (use environment variables in production)
- Configure firewall rules to restrict API access
- Use HTTPS in production environments

## License

Academic Project - For Educational Purposes

## Contributors

Network Security Team
