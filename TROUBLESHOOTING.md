# Troubleshooting Guide

Common issues and their solutions for the Campus Network Traffic Analyzer.

## Database Issues

### Problem: "Can't connect to MySQL server"

**Symptoms**: Backend fails to start with database connection error

**Solutions**:

1. **Check if MySQL is running**:
   ```bash
   # Linux
   sudo systemctl status mysql
   sudo systemctl start mysql
   
   # Mac
   brew services list
   brew services start mysql
   
   # Windows
   # Open Services app and check "MySQL" service status
   ```

2. **Verify credentials**:
   ```bash
   mysql -u campus_monitor -p campus_network_monitor
   # If this fails, recreate the user
   ```

3. **Check config.yaml**:
   - Verify host, port, user, password, database name
   - Default password is "changeme"

### Problem: "Access denied for user"

**Solution**: Recreate database user with correct privileges:
```sql
mysql -u root -p
DROP USER 'campus_monitor'@'localhost';
CREATE USER 'campus_monitor'@'localhost' IDENTIFIED BY 'changeme';
GRANT ALL PRIVILEGES ON campus_network_monitor.* TO 'campus_monitor'@'localhost';
FLUSH PRIVILEGES;
```

### Problem: "Unknown database 'campus_network_monitor'"

**Solution**: Create and initialize database:
```bash
mysql -u root -p
CREATE DATABASE campus_network_monitor;
EXIT;

cd backend
mysql -u campus_monitor -p campus_network_monitor < schema.sql
```

## Packet Capture Issues

### Problem: "Permission denied" when capturing packets

**Symptoms**: Backend shows "PermissionError" for packet capture

**Solutions**:

**Linux/Mac**:
```bash
# Run with sudo
sudo python3 main.py

# OR give Python capabilities (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
python3 main.py
```

**Windows**:
1. Right-click PowerShell/CMD
2. Select "Run as Administrator"
3. Run `python main.py`

### Problem: "No such device" or interface not found

**Symptoms**: Error about network interface not existing

**Solutions**:

1. **List available interfaces**:
   ```bash
   # Linux/Mac
   ip link show
   # or
   ifconfig
   
   # Windows
   ipconfig
   ```

2. **Update config.yaml** with correct interface names:
   ```yaml
   wifi_networks:
     - capture_interface: "eth0"  # Change to your interface
   ```

3. **Common interface names**:
   - Linux: eth0, wlan0, enp0s3, wlp2s0
   - Mac: en0, en1
   - Windows: Ethernet, Wi-Fi, "Local Area Connection"

### Problem: No packets being captured (Windows)

**Solution**: Install Npcap:
1. Download from https://npcap.com/#download
2. Install with "WinPcap API-compatible Mode" checked
3. Restart computer
4. Run backend as Administrator

## Backend Issues

### Problem: "Module not found" errors

**Symptoms**: ImportError or ModuleNotFoundError

**Solutions**:

1. **Reinstall dependencies**:
   ```bash
   cd backend
   pip install -r requirements.txt --force-reinstall
   ```

2. **Check Python version**:
   ```bash
   python --version  # Should be 3.9+
   ```

3. **Use virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   pip install -r requirements.txt
   ```

### Problem: "Address already in use" (Port 8000)

**Symptoms**: Backend fails to start, port 8000 already in use

**Solutions**:

**Linux/Mac**:
```bash
# Find process using port 8000
sudo lsof -i :8000

# Kill the process
sudo kill -9 <PID>
```

**Windows**:
```bash
# Find process
netstat -ano | findstr :8000

# Kill process
taskkill /PID <PID> /F
```

**Alternative**: Change port in `config.yaml`:
```yaml
system:
  api_port: 8001  # Use different port
```

### Problem: Backend starts but shows errors

**Solution**: Check logs:
```bash
# View log file
cat backend/campus_monitor.log

# Or run with verbose logging
cd backend
python main.py  # Watch console output
```

## Frontend Issues

### Problem: "Failed to load data" in dashboard

**Symptoms**: Dashboard shows error message, no data displayed

**Solutions**:

1. **Check if backend is running**:
   - Open http://localhost:8000 in browser
   - Should see: `{"status":"ok","service":"Campus Network Traffic Analyzer"}`

2. **Check browser console**:
   - Press F12 → Console tab
   - Look for CORS or network errors

3. **Verify API URL**:
   - Check `frontend/src/services/api.js`
   - Default: `http://localhost:8000`

4. **Check CORS settings**:
   - Backend should allow frontend origin
   - Check `backend/api/routes.py` CORS configuration

### Problem: "npm install" fails

**Symptoms**: Errors during `npm install`

**Solutions**:

1. **Clear npm cache**:
   ```bash
   npm cache clean --force
   rm -rf node_modules package-lock.json
   npm install
   ```

2. **Update npm**:
   ```bash
   npm install -g npm@latest
   ```

3. **Use different registry** (if behind firewall):
   ```bash
   npm config set registry https://registry.npmjs.org/
   ```

### Problem: "Port 3000 already in use"

**Solutions**:

**Option 1 - Kill process**:
```bash
# Linux/Mac
lsof -i :3000
kill -9 <PID>

# Windows
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

**Option 2 - Use different port**:
```bash
# Set PORT environment variable
PORT=3001 npm start
```

### Problem: Charts not displaying

**Symptoms**: Dashboard loads but charts are empty

**Solutions**:

1. **Check if data exists**:
   - Visit http://localhost:8000/api/networks
   - Should return network data

2. **Add test data** (see QUICKSTART.md for SQL commands)

3. **Check browser console** for JavaScript errors

## General Issues

### Problem: System runs but no data appears

**Cause**: No packets being captured or no test data

**Solutions**:

1. **If packet capture is working**:
   - Wait a few seconds for packets to be captured
   - Check if network interface has traffic

2. **If packet capture isn't working**:
   - Add test data manually (see QUICKSTART.md)
   - Or run with sudo/admin privileges

3. **Verify data in database**:
   ```sql
   mysql -u campus_monitor -p campus_network_monitor
   SELECT COUNT(*) FROM packet_logs;
   SELECT COUNT(*) FROM connected_devices;
   ```

### Problem: High CPU usage

**Symptoms**: System becomes slow, high CPU usage

**Solutions**:

1. **Reduce packet capture rate**:
   - Capture from fewer interfaces
   - Add BPF filter to capture specific traffic only

2. **Increase processing interval**:
   - Edit `traffic_analyzer.py`
   - Increase sleep time in metrics loop

3. **Limit database writes**:
   - Batch insert packets instead of individual inserts

### Problem: High memory usage

**Symptoms**: System uses too much RAM

**Solutions**:

1. **Clear old packet logs**:
   ```sql
   DELETE FROM packet_logs WHERE timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY);
   ```

2. **Reduce queue size**:
   - Edit `packet_capture.py`
   - Reduce `max_queue_size` parameter

3. **Restart services periodically**

## Platform-Specific Issues

### Windows-Specific

**Problem**: Scapy doesn't work

**Solution**: Install Npcap (see above)

**Problem**: Scripts don't run

**Solution**: 
```bash
# Enable script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Linux-Specific

**Problem**: MySQL socket error

**Solution**:
```bash
# Check MySQL socket location
mysql_config --socket

# Update config.yaml if needed
```

### Mac-Specific

**Problem**: Homebrew services not starting

**Solution**:
```bash
# Restart services
brew services restart mysql

# Check logs
brew services list
```

## Testing Without Packet Capture

If you can't get packet capture working, you can still demonstrate the system:

### 1. Add Test Data

See QUICKSTART.md for complete SQL commands to insert:
- Packet logs
- Connected devices
- Security alerts
- Performance metrics

### 2. Use Mock Data

Create a script to generate random data:
```python
# backend/generate_test_data.py
import random
from modules.database import DatabaseManager
from datetime import datetime

db = DatabaseManager(config['database'])

# Generate random packets
for i in range(100):
    db.insert_packet_log(
        timestamp=datetime.now(),
        source_ip=f"192.168.1.{random.randint(1,254)}",
        dest_ip=f"8.8.{random.randint(1,8)}.{random.randint(1,8)}",
        source_mac=f"00:11:22:33:44:{random.randint(0,255):02x}",
        protocol=random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS']),
        source_port=random.randint(1024, 65535),
        dest_port=random.choice([80, 443, 53, 22, 3389]),
        packet_size=random.randint(64, 1500),
        wifi_network_id=random.randint(1, 3)
    )
```

## Getting More Help

If you're still stuck:

1. **Check logs**:
   - Backend: `backend/campus_monitor.log`
   - Browser console: F12 → Console tab

2. **Verify prerequisites**:
   - Python 3.9+
   - Node.js 16+
   - MySQL 8.0+

3. **Test components individually**:
   - Database: `mysql -u campus_monitor -p`
   - Backend API: http://localhost:8000/docs
   - Frontend: http://localhost:3000

4. **Review documentation**:
   - SETUP_GUIDE.md for detailed setup
   - ARCHITECTURE.md for system design
   - Code comments for implementation details

## Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `PermissionError: [Errno 1] Operation not permitted` | No admin privileges | Run with sudo/admin |
| `mysql.connector.errors.ProgrammingError: 1045` | Wrong database password | Check config.yaml |
| `ModuleNotFoundError: No module named 'scapy'` | Missing dependencies | Run `pip install -r requirements.txt` |
| `Error: listen EADDRINUSE: address already in use :::3000` | Port in use | Kill process or use different port |
| `Failed to fetch` in browser | Backend not running | Start backend first |
| `CORS policy` error | CORS not configured | Check backend CORS settings |

## Prevention Tips

1. **Always start backend before frontend**
2. **Check MySQL is running before starting backend**
3. **Use virtual environment for Python dependencies**
4. **Keep dependencies updated**
5. **Run with appropriate privileges for packet capture**
6. **Monitor logs for early warning signs**
7. **Test with sample data first**

---

Still having issues? Check the code comments or review the architecture documentation for more details.
