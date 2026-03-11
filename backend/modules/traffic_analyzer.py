"""
Traffic Analyzer Module

Processes captured packets to extract traffic patterns, calculate bandwidth metrics,
track connected devices, and compute network performance statistics.

Networking Concepts Implemented:
- Protocol Classification: Identifying TCP, UDP, ICMP, DNS, HTTP, HTTPS
- Bandwidth Calculation: Measuring data transfer rates (bytes/sec)
- Throughput Analysis: Network capacity utilization
- Packet Rate: Packets per second metric
- Device Tracking: Maintaining active device registry by MAC/IP
"""

from typing import Dict, List, Optional, Callable
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import time
import logging
import queue
from .packet_capture import PacketLog
from .database import DatabaseManager

logger = logging.getLogger(__name__)


class DeviceInfo:
    """Tracks information about a connected device."""
    def __init__(self, mac_address: str, ip_address: str, wifi_network_id: int):
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.wifi_network_id = wifi_network_id
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.is_active = True


class NetworkStats:
    """Tracks statistics for a WiFi network."""
    def __init__(self, wifi_network_id: int):
        self.wifi_network_id = wifi_network_id
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.protocol_bytes = defaultdict(int)
        self.start_time = datetime.now()
        self.last_reset = datetime.now()
    
    def add_packet(self, packet_log: PacketLog):
        """Add packet to statistics."""
        self.total_packets += 1
        self.total_bytes += packet_log.packet_size
        self.protocol_counts[packet_log.protocol] += 1
        self.protocol_bytes[packet_log.protocol] += packet_log.packet_size
    
    def get_throughput_bps(self) -> int:
        """Calculate throughput in bytes per second."""
        elapsed = (datetime.now() - self.last_reset).total_seconds()
        if elapsed > 0:
            return int(self.total_bytes / elapsed)
        return 0
    
    def get_packet_rate(self) -> int:
        """Calculate packet rate in packets per second."""
        elapsed = (datetime.now() - self.last_reset).total_seconds()
        if elapsed > 0:
            return int(self.total_packets / elapsed)
        return 0
    
    def get_avg_packet_size(self) -> int:
        """Calculate average packet size."""
        if self.total_packets > 0:
            return int(self.total_bytes / self.total_packets)
        return 0
    
    def reset(self):
        """Reset counters for next measurement period."""
        self.total_packets = 0
        self.total_bytes = 0
        self.last_reset = datetime.now()


class TrafficAnalyzer:
    """
    Analyzes network traffic patterns and maintains device registry.
    
    Responsibilities:
    - Protocol classification
    - Bandwidth calculation per device and network
    - Device tracking and activity monitoring
    - Performance metrics calculation
    """
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        
        # Database write queue
        self.db_queue = queue.Queue(maxsize=50000)
        
        # Device registry: {(mac_address, wifi_network_id): DeviceInfo}
        self.devices: Dict[tuple, DeviceInfo] = {}
        self.devices_lock = threading.Lock()
        
        # Network statistics: {wifi_network_id: NetworkStats}
        self.network_stats: Dict[int, NetworkStats] = {}
        self.stats_lock = threading.Lock()
        
        # Callbacks for other modules (e.g., IDS)
        self.packet_callbacks: List[Callable[[PacketLog], None]] = []
        
        # Background tasks
        self.is_running = False
        self.metrics_thread = None
        self.device_cleanup_thread = None
        self.db_worker_thread = None
    
    def start(self):
        """Start background tasks for metrics calculation and device cleanup."""
        self.is_running = True
        
        # Start DB worker thread
        self.db_worker_thread = threading.Thread(
            target=self._db_worker_loop,
            name="DBWorker",
            daemon=True
        )
        self.db_worker_thread.start()
        
        # Start metrics calculation thread (every 10 seconds)
        self.metrics_thread = threading.Thread(
            target=self._metrics_loop,
            name="MetricsCalculator",
            daemon=True
        )
        self.metrics_thread.start()
        
        # Start device cleanup thread (every 60 seconds)
        self.device_cleanup_thread = threading.Thread(
            target=self._device_cleanup_loop,
            name="DeviceCleanup",
            daemon=True
        )
        self.device_cleanup_thread.start()
        
        logger.info("Traffic Analyzer started")
    
    def stop(self):
        """Stop background tasks."""
        self.is_running = False
        if self.metrics_thread:
            self.metrics_thread.join(timeout=5)
        if self.device_cleanup_thread:
            self.device_cleanup_thread.join(timeout=5)
        if self.db_worker_thread:
            self.db_worker_thread.join(timeout=5)
        logger.info("Traffic Analyzer stopped")
    
    def register_callback(self, callback: Callable[[PacketLog], None]):
        """Register callback to receive all packets (for IDS, etc.)."""
        self.packet_callbacks.append(callback)
    
    def process_packet(self, packet_log: PacketLog):
        """
        Process a captured packet.
        This is the main entry point called by PacketCaptureModule.
        
        Processing steps:
        1. Update device registry
        2. Update network statistics
        3. Queue packet log for database storage
        4. Notify registered callbacks (IDS)
        """
        try:
            # Update device tracking
            self._update_device(packet_log)
            
            # Update network statistics
            self._update_network_stats(packet_log)
            
            # Queue for database storage
            try:
                self.db_queue.put_nowait(packet_log)
            except queue.Full:
                logger.warning("DB write queue full, dropping packet log")
            
            # Notify callbacks (e.g., Intrusion Detection Engine)
            for callback in self.packet_callbacks:
                try:
                    callback(packet_log)
                except Exception as e:
                    logger.error(f"Error in packet callback: {e}")
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _update_device(self, packet_log: PacketLog):
        """
        Update device registry with packet information.
        Tracks bandwidth consumption per device.
        """
        with self.devices_lock:
            device_key = (packet_log.source_mac, packet_log.wifi_network_id)
            
            if device_key not in self.devices:
                # New device detected
                device = DeviceInfo(
                    packet_log.source_mac,
                    packet_log.source_ip,
                    packet_log.wifi_network_id
                )
                self.devices[device_key] = device
                logger.info(f"New device detected: {packet_log.source_mac} ({packet_log.source_ip})")
            else:
                device = self.devices[device_key]
            
            # Update device information
            device.last_seen = packet_log.timestamp
            device.ip_address = packet_log.source_ip  # Update in case of DHCP change
            device.bytes_sent += packet_log.packet_size
            device.is_active = True
    
    def _update_network_stats(self, packet_log: PacketLog):
        """Update network-level statistics."""
        with self.stats_lock:
            if packet_log.wifi_network_id not in self.network_stats:
                self.network_stats[packet_log.wifi_network_id] = NetworkStats(packet_log.wifi_network_id)
            
            self.network_stats[packet_log.wifi_network_id].add_packet(packet_log)
    
    def _db_worker_loop(self):
        """Background worker for database writes."""
        # Create a dedicated connection for the worker to avoid pool exhaustion
        import mysql.connector
        
        # Keep retrying connection if it fails or disconnects
        db_conn = None
        db_cursor = None
        
        while self.is_running:
            try:
                # Ensure connection is alive
                if not db_conn or not db_conn.is_connected():
                    if db_conn:
                        try: db_conn.close() 
                        except: pass
                    
                    db_conn = mysql.connector.connect(
                        host=self.db_manager.config['host'],
                        port=self.db_manager.config['port'],
                        user=self.db_manager.config['user'],
                        password=self.db_manager.config['password'],
                        database=self.db_manager.config['database']
                    )
                    db_cursor = db_conn.cursor()
                
                # Get packet from queue with timeout
                try:
                    packet_log = self.db_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Store to database using dedicated cursor
                db_cursor.execute("""
                    INSERT INTO packet_logs
                    (timestamp, source_ip, dest_ip, source_mac, protocol, source_port,
                     dest_port, packet_size, wifi_network_id, dns_query)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (packet_log.timestamp, packet_log.source_ip, packet_log.dest_ip,
                      packet_log.source_mac, packet_log.protocol, packet_log.source_port,
                      packet_log.dest_port, packet_log.packet_size, packet_log.wifi_network_id,
                      packet_log.dns_query))
                db_conn.commit()
                
                self.db_queue.task_done()
            
            except Exception as e:
                # Let it reconnect on next iteration
                if db_conn:
                    try: db_conn.close()
                    except: pass
                    db_conn = None
                    db_cursor = None
                
                if self.is_running:
                    logger.error(f"Error in DB worker: {e}")
                    import time
                    time.sleep(1) # Backoff before reconnect
    
    def _metrics_loop(self):
        """
        Background task to calculate and store performance metrics every 10 seconds.
        
        Metrics calculated:
        - Throughput (bytes per second)
        - Packet rate (packets per second)
        - Average packet size
        - Active device count
        """
        while self.is_running:
            try:
                time.sleep(10)  # Calculate metrics every 10 seconds
                
                with self.stats_lock:
                    for wifi_network_id, stats in self.network_stats.items():
                        # Calculate metrics
                        throughput_bps = stats.get_throughput_bps()
                        packet_rate = stats.get_packet_rate()
                        avg_packet_size = stats.get_avg_packet_size()
                        
                        # Count active devices for this network
                        active_devices = sum(
                            1 for device in self.devices.values()
                            if device.wifi_network_id == wifi_network_id and device.is_active
                        )
                        
                        # Store metrics to database
                        if stats.total_packets > 0:  # Only store if there was traffic
                            self.db_manager.insert_performance_metric(
                                wifi_network_id=wifi_network_id,
                                throughput_bps=throughput_bps,
                                packet_rate=packet_rate,
                                avg_packet_size=avg_packet_size,
                                active_devices=active_devices
                            )
                            
                            logger.debug(f"Network {wifi_network_id}: {throughput_bps} Bps, {packet_rate} pps, {active_devices} devices")
                        
                        # Reset counters for next period
                        stats.reset()
            
            except Exception as e:
                logger.error(f"Error in metrics loop: {e}")
    
    def _device_cleanup_loop(self):
        """
        Background task to mark inactive devices and sync to database.
        Runs every 60 seconds.
        
        A device is considered inactive if not seen for 300 seconds (5 minutes).
        """
        while self.is_running:
            try:
                time.sleep(60)  # Check every 60 seconds
                
                current_time = datetime.now()
                inactive_threshold = timedelta(seconds=300)
                
                with self.devices_lock:
                    for device in self.devices.values():
                        # Check if device is inactive
                        if current_time - device.last_seen > inactive_threshold:
                            if device.is_active:
                                device.is_active = False
                                logger.info(f"Device {device.mac_address} marked inactive")
                        
                        # Sync device to database
                        self.db_manager.upsert_connected_device(
                            mac_address=device.mac_address,
                            ip_address=device.ip_address,
                            wifi_network_id=device.wifi_network_id,
                            bytes_sent=device.bytes_sent,
                            bytes_received=device.bytes_received
                        )
                
                # Also update database inactive status
                self.db_manager.mark_inactive_devices(timeout_seconds=300)
            
            except Exception as e:
                logger.error(f"Error in device cleanup loop: {e}")
    
    def get_network_stats(self, wifi_network_id: int) -> Optional[Dict]:
        """Get current statistics for a WiFi network."""
        with self.stats_lock:
            if wifi_network_id in self.network_stats:
                stats = self.network_stats[wifi_network_id]
                return {
                    'throughput_bps': stats.get_throughput_bps(),
                    'packet_rate': stats.get_packet_rate(),
                    'avg_packet_size': stats.get_avg_packet_size(),
                    'total_packets': stats.total_packets,
                    'total_bytes': stats.total_bytes,
                    'protocol_distribution': dict(stats.protocol_counts)
                }
        return None
    
    def get_top_bandwidth_consumers(self, wifi_network_id: int, limit: int = 10) -> List[Dict]:
        """Get top bandwidth consuming devices for a network."""
        with self.devices_lock:
            network_devices = [
                device for device in self.devices.values()
                if device.wifi_network_id == wifi_network_id
            ]
            
            # Sort by total bandwidth (sent + received)
            sorted_devices = sorted(
                network_devices,
                key=lambda d: d.bytes_sent + d.bytes_received,
                reverse=True
            )[:limit]
            
            return [
                {
                    'mac_address': device.mac_address,
                    'ip_address': device.ip_address,
                    'bytes_sent': device.bytes_sent,
                    'bytes_received': device.bytes_received,
                    'total_bandwidth': device.bytes_sent + device.bytes_received,
                    'is_active': device.is_active,
                    'last_seen': device.last_seen.isoformat()
                }
                for device in sorted_devices
            ]
    
    def get_protocol_distribution(self, wifi_network_id: int) -> Dict[str, int]:
        """Get protocol distribution for a network."""
        with self.stats_lock:
            if wifi_network_id in self.network_stats:
                return dict(self.network_stats[wifi_network_id].protocol_counts)
        return {}
