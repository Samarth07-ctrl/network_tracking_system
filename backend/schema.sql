-- Campus Network Traffic Analyzer Database Schema
-- This schema implements the data model for packet logging, device tracking,
-- security alerts, and network performance metrics

-- WiFi Networks Table
-- Stores configuration for each monitored WiFi network on campus
CREATE TABLE IF NOT EXISTS wifi_networks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ssid VARCHAR(255) NOT NULL,
    subnet_range VARCHAR(50) NOT NULL COMMENT 'CIDR notation e.g. 192.168.1.0/24',
    location VARCHAR(255) NOT NULL COMMENT 'Campus location e.g. Lab, Library, Hostel',
    capture_interface VARCHAR(50) COMMENT 'Network interface for packet capture',
    bandwidth_capacity_mbps INT DEFAULT 100 COMMENT 'Maximum bandwidth in Mbps',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_ssid (ssid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='WiFi network configurations';

-- Connected Devices Table
-- Tracks all devices that have connected to campus WiFi networks
CREATE TABLE IF NOT EXISTS connected_devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mac_address VARCHAR(17) NOT NULL COMMENT 'MAC address in format XX:XX:XX:XX:XX:XX',
    ip_address VARCHAR(45) NOT NULL COMMENT 'IPv4 or IPv6 address',
    wifi_network_id INT NOT NULL,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'First time device was detected',
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Most recent packet from device',
    is_active BOOLEAN DEFAULT TRUE COMMENT 'Active if seen within last 300 seconds',
    total_bytes_sent BIGINT DEFAULT 0 COMMENT 'Total bytes transmitted by device',
    total_bytes_received BIGINT DEFAULT 0 COMMENT 'Total bytes received by device',
    FOREIGN KEY (wifi_network_id) REFERENCES wifi_networks(id) ON DELETE CASCADE,
    INDEX idx_mac_address (mac_address),
    INDEX idx_ip_address (ip_address),
    INDEX idx_wifi_network (wifi_network_id),
    INDEX idx_last_seen (last_seen),
    UNIQUE KEY unique_device (mac_address, wifi_network_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Connected device registry';

-- Packet Logs Table
-- Stores metadata for captured network packets
-- Implements 30-day retention policy (see data_retention module)
CREATE TABLE IF NOT EXISTS packet_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP(3) COMMENT 'Packet capture time with millisecond precision',
    source_ip VARCHAR(45) NOT NULL COMMENT 'Source IP address',
    dest_ip VARCHAR(45) NOT NULL COMMENT 'Destination IP address',
    source_mac VARCHAR(17) COMMENT 'Source MAC address',
    protocol VARCHAR(20) NOT NULL COMMENT 'Protocol: TCP, UDP, ICMP, DNS, HTTP, HTTPS',
    source_port INT COMMENT 'Source port number for TCP/UDP',
    dest_port INT COMMENT 'Destination port number for TCP/UDP',
    packet_size INT NOT NULL COMMENT 'Packet size in bytes',
    wifi_network_id INT NOT NULL,
    dns_query VARCHAR(255) COMMENT 'DNS query domain if protocol is DNS',
    FOREIGN KEY (wifi_network_id) REFERENCES wifi_networks(id) ON DELETE CASCADE,
    INDEX idx_timestamp (timestamp),
    INDEX idx_wifi_network (wifi_network_id),
    INDEX idx_source_ip (source_ip),
    INDEX idx_dest_ip (dest_ip),
    INDEX idx_protocol (protocol)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Network packet metadata logs';

-- Security Alerts Table
-- Stores intrusion detection alerts and security events
-- Implements 365-day retention policy
CREATE TABLE IF NOT EXISTS security_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Alert generation time',
    alert_type VARCHAR(50) NOT NULL COMMENT 'PORT_SCAN, DDOS, BRUTE_FORCE, PROHIBITED_WEBSITE, HIGH_BANDWIDTH',
    severity VARCHAR(20) NOT NULL COMMENT 'LOW, MEDIUM, HIGH, CRITICAL',
    source_ip VARCHAR(45) COMMENT 'Source IP address of threat',
    source_mac VARCHAR(17) COMMENT 'Source MAC address of threat',
    target_ip VARCHAR(45) COMMENT 'Target IP address',
    metadata JSON COMMENT 'Additional alert details (port range, packet rate, domain, etc.)',
    wifi_network_id INT,
    resolved BOOLEAN DEFAULT FALSE COMMENT 'Whether alert has been acknowledged',
    FOREIGN KEY (wifi_network_id) REFERENCES wifi_networks(id) ON DELETE SET NULL,
    INDEX idx_timestamp (timestamp),
    INDEX idx_alert_type (alert_type),
    INDEX idx_severity (severity),
    INDEX idx_wifi_network (wifi_network_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Security alerts and intrusion detection events';

-- Performance Metrics Table
-- Stores network performance statistics calculated every 10-60 seconds
CREATE TABLE IF NOT EXISTS performance_metrics (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Metric calculation time',
    wifi_network_id INT NOT NULL,
    throughput_bps BIGINT NOT NULL COMMENT 'Network throughput in bytes per second',
    packet_rate INT NOT NULL COMMENT 'Packets per second',
    avg_packet_size INT COMMENT 'Average packet size in bytes',
    active_devices INT DEFAULT 0 COMMENT 'Number of active connected devices',
    FOREIGN KEY (wifi_network_id) REFERENCES wifi_networks(id) ON DELETE CASCADE,
    INDEX idx_timestamp (timestamp),
    INDEX idx_wifi_network (wifi_network_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Network performance metrics';

-- Prohibited Websites Table
-- Stores list of domains that trigger security alerts when accessed
CREATE TABLE IF NOT EXISTS prohibited_websites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE COMMENT 'Domain name to block',
    category VARCHAR(100) COMMENT 'Category: gambling, malware, adult, social_media, etc.',
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_domain (domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Prohibited website domains';

-- Insert sample prohibited websites
INSERT INTO prohibited_websites (domain, category) VALUES
('gambling-site.com', 'gambling'),
('malware-domain.net', 'malware'),
('phishing-site.org', 'phishing')
ON DUPLICATE KEY UPDATE domain=domain;

-- Insert sample WiFi networks (will be overwritten by config.yaml on startup)
INSERT INTO wifi_networks (ssid, subnet_range, location, capture_interface, bandwidth_capacity_mbps) VALUES
('Lab-WiFi', '192.168.1.0/24', 'Computer Lab', 'eth0', 100),
('Library-WiFi', '192.168.2.0/24', 'Library', 'eth1', 200),
('Hostel-WiFi', '192.168.3.0/24', 'Student Hostel', 'eth2', 500)
ON DUPLICATE KEY UPDATE ssid=ssid;
