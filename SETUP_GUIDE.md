# Campus Network Traffic Analyzer - Complete Setup Guide

This guide will walk you through setting up and running the Campus Network Traffic Analyzer system step by step.

## Prerequisites

Before starting, ensure you have:
- **Python 3.9+** installed
- **Node.js 16+** and npm installed
- **MySQL 8.0+** installed and running
- **Administrator/root privileges** (for packet capture)

## Step 1: Install Prerequisites

### Windows

1. **Install Python**:
   - Download from https://www.python.org/downloads/
   - During installation, check "Add Python to PATH"

2. **Install Node.js**:
   - Download from https://nodejs.org/
   - Install with default settings

3. **Install MySQL**:
   - Download MySQL Installer from https://dev.mysql.com/downloads/installer/
   - Choose "Developer Default" installation
   - Set root password during installation

4. **Install Npcap** (required for Scapy on Windows):
   - Download from https://npcap.com/#download
   - Install with "WinPcap API-compatible Mode" checked

### Linux (Ubuntu/Debian)

```bash
# Update package list
sudo apt update

# Install Python 3 and pip
sudo apt install python3 python3-pip

# Install Node.js and npm
sudo apt install nodejs npm

# Install MySQL
sudo apt install mysql-server

# Install libpcap (required for Scapy)
sudo apt install libpcap-dev

# Start MySQL service
sudo systemctl start mysql
sudo systemctl enable mysql
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python

# Install Node.js
brew install node

# Install MySQL
brew install mysql

# Start MySQL service
brew services start mysql
```

## Step 2: Set Up MySQL Database

### 2.1 Login to MySQL

```bash
# Linux/Mac
mysql -u root -p

# Windows (use MySQL Command Line Client or)
mysql -u root -p
```

### 2.2 Create Database and User

```sql
-- Create database
CREATE DATABASE campus_network_monitor;

-- Create user (change 'changeme' to a secure password)
CREATE USER 'campus_monitor'@'localhost' IDENTIFIED BY 'changeme';

-- Grant privileges
GRANT ALL PRIVILEGES ON campus_network_monitor.* TO 'campus_monitor'@'localhost';
FLUSH PRIVILEGES;

-- Exit MySQL
EXIT;
```

### 2.3 Initialize Database Schema

```bash
# Navigate to backend directory
cd backend

# Import schema
mysql -u campus_monitor -p campus_network_monitor < schema.sql
# Enter password: changeme (or your chosen password)
```

## Step 3: Configure the System

### 3.1 Update Database Credentials

Edit `backend/config.yaml`:

```yaml
database:
  host: localhost
  port: 3306
  user: campus_monitor
  password: changeme  # Change this to your password
  database: campus_network_monitor
```

### 3.2 Configure Network Interfaces

**Important**: You need to identify your network interfaces.

#### Find Your Network Interfaces:

**Windows**:
```bash
ipconfig
# Look for "Ethernet adapter" or "Wireless LAN adapter"
# Interface names might be: "Ethernet", "Wi-Fi", "Local Area Connection"
```

**Linux**:
```bash
ip link show
# or
ifconfig
# Look for interfaces like: eth0, wlan0, enp0s3, etc.
```

**macOS**:
```bash
ifconfig
# Look for interfaces like: en0, en1, etc.
```

#### Update config.yaml:

Edit `backend/config.yaml` and update the `capture_interface` for each network:

```yaml
wifi_networks:
  - ssid: "Lab-WiFi"
    subnet: "192.168.1.0/24"
    location: "Computer Lab"
    capture_interface: "eth0"  # Change to your interface
    bandwidth_capacity_mbps: 100
```

**For testing without packet capture**, you can leave the default interfaces. The system will show an error but the API and dashboard will still work.

## Step 4: Install Backend Dependencies

```bash
# Navigate to backend directory
cd backend

# Install Python packages
pip install -r requirements.txt

# On Linux/Mac, you might need:
pip3 install -r requirements.txt
```

## Step 5: Install Frontend Dependencies

```bash
# Navigate to frontend directory
cd frontend

# Install Node.js packages
npm install
```

This will take a few minutes to download all dependencies.

## Step 6: Run the Backend

### Option A: With Packet Capture (Requires Admin/Root)

**Windows** (Run PowerShell or CMD as Administrator):
```bash
cd backend
python main.py
```

**Linux/Mac**:
```bash
cd backend
sudo python3 main.py
```

You should see:
```
============================================================
Campus Network Traffic Analyzer and Security Monitor
============================================================
Loading configuration...
Connecting to database...
Database connection established
...
Starting API server on 0.0.0.0:8000
```

### Option B: Without Packet Capture (For Testing)

If you don't have admin privileges or just want to test the API:

```bash
cd backend
python main.py
```

You'll see permission errors for packet capture, but the API will still work.

**Keep this terminal window open** - the backend is now running.

## Step 7: Run the Frontend

Open a **new terminal window**:

```bash
cd frontend
npm start
```

This will:
- Start the React development server
- Automatically open your browser to http://localhost:3000

You should see the Campus Network Monitor dashboard!

## Step 8: Verify Everything Works

### Check Backend API

Open your browser and visit:
- **API Health Check**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

You should see the API documentation with all available endpoints.

### Check Frontend Dashboard

The dashboard at http://localhost:3000 should show:
- Campus overview with statistics
- List of WiFi networks
- Click on a network to see details

## Troubleshooting

### Problem: "Permission denied" for packet capture

**Solution**: Run backend with sudo/administrator privileges:
```bash
# Linux/Mac
sudo python3 main.py

# Windows: Run terminal as Administrator
```

### Problem: "Can't connect to MySQL server"

**Solution**: 
1. Check if MySQL is running:
   ```bash
   # Linux
   sudo systemctl status mysql
   
   # Mac
   brew services list
   
   # Windows: Check Services app for "MySQL" service
   ```

2. Verify credentials in `backend/config.yaml`

3. Test MySQL connection:
   ```bash
   mysql -u campus_monitor -p campus_network_monitor
   ```

### Problem: "Module not found" errors

**Solution**: Reinstall dependencies:
```bash
# Backend
cd backend
pip install -r requirements.txt --force-reinstall

# Frontend
cd frontend
rm -rf node_modules
npm install
```

### Problem: Frontend shows "Failed to load data"

**Solution**:
1. Make sure backend is running (check http://localhost:8000)
2. Check browser console for errors (F12 → Console tab)
3. Verify CORS is enabled in backend

### Problem: No packets being captured

**Solution**:
1. Verify you're running with admin/root privileges
2. Check network interface names in `config.yaml`
3. Make sure the interface is active and connected
4. On Windows, ensure Npcap is installed

### Problem: "Address already in use" error

**Solution**: Another process is using port 8000 or 3000:
```bash
# Linux/Mac - Find and kill process
sudo lsof -i :8000
sudo kill -9 <PID>

# Windows - Find and kill process
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

## Testing Without Live Packet Capture

If you can't capture live packets, you can still test the system:

### 1. Insert Test Data Manually

```sql
-- Connect to MySQL
mysql -u campus_monitor -p campus_network_monitor

-- Insert test packet logs
INSERT INTO packet_logs (timestamp, source_ip, dest_ip, source_mac, protocol, source_port, dest_port, packet_size, wifi_network_id)
VALUES 
(NOW(), '192.168.1.100', '8.8.8.8', '00:11:22:33:44:55', 'TCP', 54321, 443, 1500, 1),
(NOW(), '192.168.1.101', '1.1.1.1', '00:11:22:33:44:56', 'UDP', 12345, 53, 512, 1),
(NOW(), '192.168.1.102', '8.8.4.4', '00:11:22:33:44:57', 'DNS', 54322, 53, 256, 1);

-- Insert test devices
INSERT INTO connected_devices (mac_address, ip_address, wifi_network_id, total_bytes_sent, total_bytes_received)
VALUES 
('00:11:22:33:44:55', '192.168.1.100', 1, 1048576, 2097152),
('00:11:22:33:44:56', '192.168.1.101', 1, 524288, 1048576);

-- Insert test alerts
INSERT INTO security_alerts (alert_type, severity, source_ip, source_mac, target_ip, metadata, wifi_network_id)
VALUES 
('PORT_SCAN', 'HIGH', '192.168.1.100', '00:11:22:33:44:55', '192.168.1.1', '{"ports_accessed": 25}', 1),
('PROHIBITED_WEBSITE', 'MEDIUM', '192.168.1.101', '00:11:22:33:44:56', NULL, '{"domain": "gambling-site.com"}', 1);
```

### 2. View Test Data in Dashboard

Refresh the dashboard at http://localhost:3000 to see the test data.

## Next Steps

Once everything is running:

1. **Explore the Dashboard**: Navigate through different WiFi networks
2. **View Security Alerts**: Check the Security panel
3. **Add Prohibited Websites**: Test the website blocking feature
4. **Monitor Real-time Traffic**: If packet capture is working, watch live packets

## Stopping the System

To stop the system:

1. **Stop Frontend**: Press `Ctrl+C` in the frontend terminal
2. **Stop Backend**: Press `Ctrl+C` in the backend terminal
3. **Stop MySQL** (optional):
   ```bash
   # Linux
   sudo systemctl stop mysql
   
   # Mac
   brew services stop mysql
   ```

## Production Deployment Notes

For production deployment:

1. **Use environment variables** for sensitive data (database passwords)
2. **Configure CORS** properly in FastAPI (restrict origins)
3. **Use HTTPS** for the API
4. **Set up proper logging** and monitoring
5. **Configure firewall rules** to restrict API access
6. **Use a production WSGI server** like Gunicorn instead of Uvicorn
7. **Build React for production**: `npm run build`

## Getting Help

If you encounter issues:

1. Check the logs in `backend/campus_monitor.log`
2. Check browser console (F12) for frontend errors
3. Verify all prerequisites are installed correctly
4. Make sure all services (MySQL, backend, frontend) are running

## Summary of Commands

```bash
# Terminal 1 - Backend
cd backend
sudo python3 main.py  # or python main.py on Windows as Admin

# Terminal 2 - Frontend
cd frontend
npm start

# Access Points
# Dashboard: http://localhost:3000
# API Docs: http://localhost:8000/docs
```

Enjoy monitoring your campus network! 🎓🔒📊
