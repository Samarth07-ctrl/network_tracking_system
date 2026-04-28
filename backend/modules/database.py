"""
Database Access Layer Module

This module provides a centralized interface for all database operations.
It implements connection pooling for efficient database access and handles
all CRUD operations for packet logs, security alerts, device tracking, and
network performance metrics.

Networking Concepts:
- Data persistence for network traffic analysis
- Time-series data storage for performance metrics
- Relational data model for network topology
"""

import mysql.connector
from mysql.connector import pooling, Error
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import json
import logging

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Manages database connections and provides methods for all data operations.
    Uses connection pooling to handle concurrent access from multiple modules.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize database manager with connection pooling.
        
        Args:
            config: Database configuration dict with host, port, user, password, database
        """
        self.config = config
        self.pool = None
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Create connection pool for efficient database access."""
        try:
            self.pool = pooling.MySQLConnectionPool(
                pool_name="campus_monitor_pool",
                pool_size=32,
                pool_reset_session=True,
                host=self.config['host'],
                port=self.config['port'],
                user=self.config['user'],
                password=self.config['password'],
                database=self.config['database']
            )
            logger.info("Database connection pool initialized successfully")
        except Error as e:
            logger.error(f"Failed to create connection pool: {e}")
            raise
    
    def _get_connection(self):
        """Get a connection from the pool."""
        try:
            return self.pool.get_connection()
        except Error as e:
            logger.error(f"Failed to get connection from pool: {e}")
            raise
    
    # WiFi Network Operations
    
    def get_wifi_networks(self) -> List[Dict[str, Any]]:
        """
        Retrieve all configured WiFi networks.
        
        Returns:
            List of WiFi network dictionaries
        """
        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT id, ssid, subnet_range, location, capture_interface, 
                       bandwidth_capacity_mbps, created_at
                FROM wifi_networks
                ORDER BY location
            """)
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    
    def get_wifi_network_by_id(self, network_id: int) -> Optional[Dict[str, Any]]:
        """Get specific WiFi network by ID."""
        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT id, ssid, subnet_range, location, capture_interface,
                       bandwidth_capacity_mbps, created_at
                FROM wifi_networks
                WHERE id = %s
            """, (network_id,))
            return cursor.fetchone()
        finally:
            cursor.close()
            conn.close()
    
    def insert_wifi_network(self, ssid: str, subnet_range: str, location: str,
                           capture_interface: str, bandwidth_capacity_mbps: int) -> int:
        """Insert new WiFi network configuration."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO wifi_networks 
                (ssid, subnet_range, location, capture_interface, bandwidth_capacity_mbps)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                subnet_range = VALUES(subnet_range),
                location = VALUES(location),
                capture_interface = VALUES(capture_interface),
                bandwidth_capacity_mbps = VALUES(bandwidth_capacity_mbps)
            """, (ssid, subnet_range, location, capture_interface, bandwidth_capacity_mbps))
            conn.commit()
            return cursor.lastrowid
        finally:
            cursor.close()
            conn.close()
    
    # Packet Log Operations
    
    def insert_packet_log(self, timestamp: datetime, source_ip: str, dest_ip: str,
                         source_mac: str, protocol: str, source_port: Optional[int],
                         dest_port: Optional[int], packet_size: int, wifi_network_id: int,
                         dns_query: Optional[str] = None):
        """
        Insert packet log record.
        
        Args:
            timestamp: Packet capture timestamp
            source_ip: Source IP address
            dest_ip: Destination IP address
            source_mac: Source MAC address
            protocol: Protocol name (TCP, UDP, ICMP, DNS, etc.)
            source_port: Source port number (TCP/UDP only)
            dest_port: Destination port number (TCP/UDP only)
            packet_size: Packet size in bytes
            wifi_network_id: WiFi network identifier
            dns_query: DNS query domain (DNS packets only)
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO packet_logs
                (timestamp, source_ip, dest_ip, source_mac, protocol, source_port,
                 dest_port, packet_size, wifi_network_id, dns_query)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (timestamp, source_ip, dest_ip, source_mac, protocol, source_port,
                  dest_port, packet_size, wifi_network_id, dns_query))
            conn.commit()
        finally:
            cursor.close()
            conn.close()
    
    def get_packet_logs(self, wifi_network_id: Optional[int] = None,
                       start_time: Optional[datetime] = None,
                       end_time: Optional[datetime] = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve packet logs with optional filtering.
        
        Args:
            wifi_network_id: Filter by WiFi network
            start_time: Filter by start timestamp
            end_time: Filter by end timestamp
            limit: Maximum number of records to return
        
        Returns:
            List of packet log dictionaries
        """
        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            query = """
                SELECT id, timestamp, source_ip, dest_ip, source_mac, protocol,
                       source_port, dest_port, packet_size, wifi_network_id, dns_query
                FROM packet_logs
                WHERE 1=1
            """
            params = []
            
            if wifi_network_id:
                query += " AND wifi_network_id = %s"
                params.append(wifi_network_id)
            
            if start_time:
                query += " AND timestamp >= %s"
                params.append(start_time)
            
            if end_time:
                query += " AND timestamp <= %s"
                params.append(end_time)
            
            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    
    def delete_old_packet_logs(self, days: int):
        """Delete packet logs older than specified days (data retention)."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            cursor.execute("""
                DELETE FROM packet_logs
                WHERE timestamp < %s
            """, (cutoff_date,))
            conn.commit()
            deleted_count = cursor.rowcount
            logger.info(f"Deleted {deleted_count} old packet logs")
            return deleted_count
        finally:
            cursor.close()
            conn.close()
    
    # Connected Device Operations
    
    def upsert_connected_device(self, mac_address: str, ip_address: str,
                               wifi_network_id: int, bytes_sent: int = 0,
                               bytes_received: int = 0):
        """
        Insert or update connected device record.
        Updates last_seen timestamp and bandwidth counters.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO connected_devices
                (mac_address, ip_address, wifi_network_id, total_bytes_sent, total_bytes_received)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                ip_address = VALUES(ip_address),
                last_seen = CURRENT_TIMESTAMP,
                is_active = TRUE,
                total_bytes_sent = total_bytes_sent + VALUES(total_bytes_sent),
                total_bytes_received = total_bytes_received + VALUES(total_bytes_received)
            """, (mac_address, ip_address, wifi_network_id, bytes_sent, bytes_received))
            conn.commit()
        finally:
            cursor.close()
            conn.close()
    
    def get_connected_devices(self, wifi_network_id: Optional[int] = None,
                             active_only: bool = True) -> List[Dict[str, Any]]:
        """
        Retrieve connected devices.
        
        Args:
            wifi_network_id: Filter by WiFi network
            active_only: Only return active devices (seen within 300 seconds)
        
        Returns:
            List of connected device dictionaries
        """
        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            query = """
                SELECT id, mac_address, ip_address, wifi_network_id, first_seen,
                       last_seen, is_active, total_bytes_sent, total_bytes_received,
                       (total_bytes_sent + total_bytes_received) as total_bandwidth
                FROM connected_devices
                WHERE 1=1
            """
            params = []
            
            if wifi_network_id:
                query += " AND wifi_network_id = %s"
                params.append(wifi_network_id)
            
            if active_only:
                query += " AND is_active = TRUE"
            
            query += " ORDER BY total_bandwidth DESC"
            
            cursor.execute(query, params)
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    
    def mark_inactive_devices(self, timeout_seconds: int = 300):
        """Mark devices as inactive if not seen within timeout period."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cutoff_time = datetime.now() - timedelta(seconds=timeout_seconds)
            cursor.execute("""
                UPDATE connected_devices
                SET is_active = FALSE
                WHERE last_seen < %s AND is_active = TRUE
            """, (cutoff_time,))
            conn.commit()
            updated_count = cursor.rowcount
            if updated_count > 0:
                logger.info(f"Marked {updated_count} devices as inactive")
            return updated_count
        finally:
            cursor.close()
            conn.close()
    
    # Security Alert Operations
    
    def insert_security_alert(self, alert_type: str, severity: str,
                             source_ip: Optional[str], source_mac: Optional[str],
                             target_ip: Optional[str], metadata: Dict[str, Any],
                             wifi_network_id: Optional[int]) -> int:
        """
        Insert security alert record.
        
        Args:
            alert_type: PORT_SCAN, DDOS, BRUTE_FORCE, PROHIBITED_WEBSITE, HIGH_BANDWIDTH
            severity: LOW, MEDIUM, HIGH, CRITICAL
            source_ip: Source IP address of threat
            source_mac: Source MAC address of threat
            target_ip: Target IP address
            metadata: Additional alert details as dictionary
            wifi_network_id: WiFi network identifier
        
        Returns:
            Alert ID
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO security_alerts
                (alert_type, severity, source_ip, source_mac, target_ip, metadata, wifi_network_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (alert_type, severity, source_ip, source_mac, target_ip,
                  json.dumps(metadata), wifi_network_id))
            conn.commit()
            return cursor.lastrowid
        finally:
            cursor.close()
            conn.close()
    
    def get_security_alerts(self, wifi_network_id: Optional[int] = None,
                           severity: Optional[str] = None,
                           start_time: Optional[datetime] = None,
                           end_time: Optional[datetime] = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve security alerts with optional filtering."""
        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            query = """
                SELECT id, timestamp, alert_type, severity, source_ip, source_mac,
                       target_ip, metadata, wifi_network_id, resolved
                FROM security_alerts
                WHERE 1=1
            """
            params = []
            
            if wifi_network_id:
                query += " AND wifi_network_id = %s"
                params.append(wifi_network_id)
            
            if severity:
                query += " AND severity = %s"
                params.append(severity)
            
            if start_time:
                query += " AND timestamp >= %s"
                params.append(start_time)
            
            if end_time:
                query += " AND timestamp <= %s"
                params.append(end_time)
            
            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            # Parse JSON metadata
            for result in results:
                if result['metadata']:
                    result['metadata'] = json.loads(result['metadata'])
            
            return results
        finally:
            cursor.close()
            conn.close()
    
    # Performance Metrics Operations
    
    def insert_performance_metric(self, wifi_network_id: int, throughput_bps: int,
                                  packet_rate: int, avg_packet_size: int,
                                  active_devices: int):
        """Insert network performance metric record."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO performance_metrics
                (wifi_network_id, throughput_bps, packet_rate, avg_packet_size, active_devices)
                VALUES (%s, %s, %s, %s, %s)
            """, (wifi_network_id, throughput_bps, packet_rate, avg_packet_size, active_devices))
            conn.commit()
        finally:
            cursor.close()
            conn.close()
    
    def get_performance_metrics(self, wifi_network_id: int,
                               start_time: Optional[datetime] = None,
                               end_time: Optional[datetime] = None,
                               limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve performance metrics for a WiFi network."""
        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            query = """
                SELECT id, timestamp, wifi_network_id, throughput_bps, packet_rate,
                       avg_packet_size, active_devices
                FROM performance_metrics
                WHERE wifi_network_id = %s
            """
            params = [wifi_network_id]
            
            if start_time:
                query += " AND timestamp >= %s"
                params.append(start_time)
            
            if end_time:
                query += " AND timestamp <= %s"
                params.append(end_time)
            
            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    
    # Prohibited Website Operations
    
    def get_prohibited_websites(self) -> List[Dict[str, Any]]:
        """Retrieve all prohibited website domains."""
        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT id, domain, category, added_at
                FROM prohibited_websites
                ORDER BY domain
            """)
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    
    def insert_prohibited_website(self, domain: str, category: str) -> int:
        """Add a prohibited website domain."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO prohibited_websites (domain, category)
                VALUES (%s, %s)
            """, (domain, category))
            conn.commit()
            return cursor.lastrowid
        finally:
            cursor.close()
            conn.close()
    
    def delete_prohibited_website(self, website_id: int):
        """Remove a prohibited website domain."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                DELETE FROM prohibited_websites
                WHERE id = %s
            """, (website_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            cursor.close()
            conn.close()
    
    def clear_all_alerts(self) -> int:
        """
        Truncate the security_alerts table, removing all rows.

        Uses TRUNCATE for performance (faster than DELETE, resets AUTO_INCREMENT).
        This is intended as a maintenance / testing utility to clear out
        false-positive spam so PCAP files can be tested on a clean slate.

        Returns:
            Number of rows that existed before truncation.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            # Get current row count for the response message
            cursor.execute("SELECT COUNT(*) FROM security_alerts")
            row_count = cursor.fetchone()[0]

            cursor.execute("TRUNCATE TABLE security_alerts")
            conn.commit()
            logger.info(f"Cleared all {row_count} security alerts from database")
            return row_count
        finally:
            cursor.close()
            conn.close()

    def close(self):
        """Close all connections in the pool."""
        if self.pool:
            # Connection pools don't have a direct close method
            # Connections are closed when they're returned to the pool
            logger.info("Database manager closed")
