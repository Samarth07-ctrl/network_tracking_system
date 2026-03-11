# Quick Start Guide - 5 Minutes Setup

This is the fastest way to get the system running for demonstration purposes.

## Prerequisites Check

Make sure you have:
- ✅ Python 3.9+ (`python --version`)
- ✅ Node.js 16+ (`node --version`)
- ✅ MySQL 8.0+ (`mysql --version`)

## 1. Database Setup (2 minutes)

```bash
# Login to MySQL
mysql -u root -p

# Run these commands in MySQL:
CREATE DATABASE campus_network_monitor;
CREATE USER 'campus_monitor'@'localhost' IDENTIFIED BY 'changeme';
GRANT ALL PRIVILEGES ON campus_network_monitor.* TO 'campus_monitor'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Import schema
cd backend
mysql -u campus_monitor -p campus_network_monitor < schema.sql
# Password: changeme
```

## 2. Install Dependencies (2 minutes)

```bash
# Backend dependencies
cd backend
pip install -r requirements.txt

# Frontend dependencies
cd ../frontend
npm install
```

## 3. Run the System (1 minute)

### Terminal 1 - Start Backend:
```bash
cd backend
python main.py
```

**Note**: You'll see packet capture errors if not running as admin - that's OK for testing!

### Terminal 2 - Start Frontend:
```bash
cd frontend
npm start
```

## 4. Access the Dashboard

Your browser should automatically open to:
**http://localhost:3000**

If not, manually open: http://localhost:3000

## 5. Add Test Data (Optional)

Since packet capture requires admin privileges, add some test data:

```bash
# In a new terminal
mysql -u campus_monitor -p campus_network_monitor

# Paste this SQL:
INSERT INTO packet_logs (timestamp, source_ip, dest_ip, source_mac, protocol, source_port, dest_port, packet_size, wifi_network_id)
VALUES 
(NOW(), '192.168.1.100', '8.8.8.8', '00:11:22:33:44:55', 'TCP', 54321, 443, 1500, 1),
(NOW(), '192.168.1.101', '1.1.1.1', '00:11:22:33:44:56', 'UDP', 12345, 53, 512, 1),
(NOW(), '192.168.1.102', '8.8.4.4', '00:11:22:33:44:57', 'HTTP', 54322, 80, 2048, 2),
(NOW(), '192.168.2.100', '8.8.8.8', '00:11:22:33:44:58', 'HTTPS', 54323, 443, 1024, 2),
(NOW(), '192.168.3.100', '1.1.1.1', '00:11:22:33:44:59', 'DNS', 54324, 53, 256, 3);

INSERT INTO connected_devices (mac_address, ip_address, wifi_network_id, total_bytes_sent, total_bytes_received, is_active)
VALUES 
('00:11:22:33:44:55', '192.168.1.100', 1, 10485760, 20971520, TRUE),
('00:11:22:33:44:56', '192.168.1.101', 1, 5242880, 10485760, TRUE),
('00:11:22:33:44:57', '192.168.1.102', 2, 15728640, 31457280, TRUE),
('00:11:22:33:44:58', '192.168.2.100', 2, 20971520, 41943040, TRUE),
('00:11:22:33:44:59', '192.168.3.100', 3, 52428800, 104857600, TRUE);

INSERT INTO security_alerts (alert_type, severity, source_ip, source_mac, target_ip, metadata, wifi_network_id)
VALUES 
('PORT_SCAN', 'HIGH', '192.168.1.100', '00:11:22:33:44:55', '192.168.1.1', '{"ports_accessed": 25, "port_list": [22, 23, 80, 443, 3389]}', 1),
('BRUTE_FORCE', 'HIGH', '192.168.2.100', '00:11:22:33:44:58', '192.168.2.1', '{"target_port": 22, "port_name": "SSH", "attempt_count": 15}', 2),
('PROHIBITED_WEBSITE', 'MEDIUM', '192.168.1.101', '00:11:22:33:44:56', NULL, '{"domain": "gambling-site.com", "category": "gambling"}', 1),
('HIGH_BANDWIDTH', 'MEDIUM', '192.168.3.100', '00:11:22:33:44:59', NULL, '{"bytes_transferred": 5368709120, "gb_transferred": 5.0}', 3),
('DDOS', 'CRITICAL', NULL, NULL, '192.168.1.1', '{"packet_rate": 1500, "source_count": 10, "source_ips": ["192.168.1.50", "192.168.1.51"]}', 1);

INSERT INTO performance_metrics (wifi_network_id, throughput_bps, packet_rate, avg_packet_size, active_devices)
VALUES 
(1, 1048576, 850, 1234, 2),
(2, 2097152, 1200, 1746, 2),
(3, 5242880, 3000, 1748, 1);

EXIT;
```

Refresh the dashboard to see the test data!

## What You'll See

1. **Dashboard**: Overview of 3 WiFi networks (Lab, Library, Hostel)
2. **Network Details**: Click any network to see:
   - Live packet feed
   - Protocol distribution chart
   - Performance graphs
   - Connected devices
   - Top bandwidth consumers
3. **Security Panel**: View security alerts and manage prohibited websites

## For Live Packet Capture

To capture real network traffic:

### Windows:
1. Install Npcap from https://npcap.com/#download
2. Run PowerShell as Administrator
3. Run: `python main.py`

### Linux/Mac:
```bash
sudo python3 main.py
```

## Troubleshooting

**Problem**: Can't connect to database
- **Fix**: Check MySQL is running: `sudo systemctl status mysql` (Linux) or check Services (Windows)

**Problem**: Port already in use
- **Fix**: Kill the process using the port or change port in config.yaml

**Problem**: Frontend shows "Failed to load data"
- **Fix**: Make sure backend is running at http://localhost:8000

## Stop the System

Press `Ctrl+C` in both terminal windows (backend and frontend)

## Full Documentation

For detailed setup instructions, see `SETUP_GUIDE.md`

---

**That's it! You now have a fully functional Campus Network Traffic Analyzer running! 🎉**
