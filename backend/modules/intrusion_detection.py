"""
Intrusion Detection Engine

Rule-based IDS that detects suspicious network activities including:
- Port scanning
- DDoS attacks
- Brute force login attempts
- Prohibited website access
- High bandwidth usage

Networking Concepts Implemented:
- Port Scanning Detection: Monitoring connection attempts to multiple ports
- DDoS Detection: Identifying high packet rates from multiple sources
- Brute Force Detection: Tracking failed authentication attempts
- DNS Monitoring: Inspecting DNS queries for prohibited domains
"""

from typing import Dict, List, Set, Optional
from collections import defaultdict
from datetime import datetime, timedelta
import re
import threading
import logging
from .packet_capture import PacketLog
from .database import DatabaseManager

logger = logging.getLogger(__name__)


class ThreatTracker:
    """Tracks potential threats over time windows."""
    def __init__(self, time_window_seconds: int):
        self.time_window = timedelta(seconds=time_window_seconds)
        self.events: List[datetime] = []
    
    def add_event(self, timestamp: datetime):
        """Add an event and clean old events outside time window."""
        self.events.append(timestamp)
        cutoff = timestamp - self.time_window
        self.events = [t for t in self.events if t > cutoff]
    
    def get_count(self) -> int:
        """Get number of events in current time window."""
        return len(self.events)
    
    def clear(self):
        """Clear all events."""
        self.events.clear()


class IntrusionDetectionEngine:
    """
    Rule-based intrusion detection system.
    
    Detection Rules:
    1. Port Scan: >20 ports accessed from single source within 60s
    2. DDoS: >1000 packets/sec to single target from 5+ sources within 30s
    3. Brute Force: >10 failed auth attempts to SSH/RDP/HTTP within 120s
    4. Prohibited Website: DNS query for blacklisted domain
    5. High Bandwidth: >5GB data transfer from single device within 1 hour
    """
    
    def __init__(self, db_manager: DatabaseManager, config: Dict):
        self.db_manager = db_manager
        self.config = config
        
        # Port scan tracking: {(source_ip, target_ip): {ports_accessed, tracker}}
        self.port_scan_tracking: Dict[tuple, Dict] = {}
        
        # DDoS tracking: {target_ip: {source_ips, packet_tracker}}
        self.ddos_tracking: Dict[str, Dict] = {}
        
        # Brute force tracking: {(source_ip, target_ip, port): tracker}
        self.brute_force_tracking: Dict[tuple, ThreatTracker] = {}
        
        # High bandwidth tracking: {(mac_address, wifi_network_id): {bytes, start_time}}
        self.bandwidth_tracking: Dict[tuple, Dict] = {}
        
        # Prohibited websites cache
        self.prohibited_domains: Set[str] = set()
        self.prohibited_domains_lock = threading.Lock()
        
        # Load prohibited websites
        self._load_prohibited_websites()
        
        # Background cleanup thread
        self.is_running = False
        self.cleanup_thread = None
    
    def start(self):
        """Start background tasks."""
        self.is_running = True
        
        # Start cleanup thread to prevent memory leaks
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="IDSCleanup",
            daemon=True
        )
        self.cleanup_thread.start()
        
        logger.info("Intrusion Detection Engine started")
    
    def stop(self):
        """Stop background tasks."""
        self.is_running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        logger.info("Intrusion Detection Engine stopped")
    
    def _load_prohibited_websites(self):
        """Load prohibited website domains from database."""
        try:
            websites = self.db_manager.get_prohibited_websites()
            with self.prohibited_domains_lock:
                self.prohibited_domains = {w['domain'] for w in websites}
            logger.info(f"Loaded {len(self.prohibited_domains)} prohibited domains")
        except Exception as e:
            logger.error(f"Failed to load prohibited websites: {e}")
    
    def reload_prohibited_websites(self):
        """Reload prohibited websites from database."""
        self._load_prohibited_websites()
    
    def analyze_packet(self, packet_log: PacketLog):
        """
        Analyze packet for suspicious activity.
        This is called for every captured packet.
        """
        try:
            # Check for port scanning
            if packet_log.protocol == "TCP" and packet_log.dest_port:
                self._check_port_scan(packet_log)
            
            # Check for DDoS
            self._check_ddos(packet_log)
            
            # Check for brute force on authentication ports
            if packet_log.dest_port in self.config['intrusion_detection']['brute_force']['monitored_ports']:
                self._check_brute_force(packet_log)
            
            # Check for prohibited website access
            if packet_log.protocol == "DNS" and packet_log.dns_query:
                self._check_prohibited_website(packet_log)
            
            # Check for clear-text credential transmission on HTTP (80) and FTP (21)
            if packet_log.dest_port in (80, 21) and packet_log.raw_payload is not None:
                self._check_cleartext_credentials(packet_log)
            
            # Track bandwidth for high usage detection
            self._track_bandwidth(packet_log)
        
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
    
    def _check_port_scan(self, packet_log: PacketLog):
        """
        Detect port scanning activity.
        
        Port Scan Definition:
        - Single source IP accessing >20 distinct ports on a target within 60 seconds
        - Typically uses TCP SYN packets (connection attempts)
        """
        key = (packet_log.source_ip, packet_log.dest_ip)
        
        if key not in self.port_scan_tracking:
            self.port_scan_tracking[key] = {
                'ports': set(),
                'tracker': ThreatTracker(self.config['intrusion_detection']['port_scan']['time_window_seconds'])
            }
        
        tracking = self.port_scan_tracking[key]
        tracking['ports'].add(packet_log.dest_port)
        tracking['tracker'].add_event(packet_log.timestamp)
        
        # Check threshold
        port_threshold = self.config['intrusion_detection']['port_scan']['port_threshold']
        if len(tracking['ports']) > port_threshold:
            # Port scan detected!
            self._generate_alert(
                alert_type="PORT_SCAN",
                severity="CRITICAL",
                source_ip=packet_log.source_ip,
                source_mac=packet_log.source_mac,
                target_ip=packet_log.dest_ip,
                metadata={
                    'ports_accessed': len(tracking['ports']),
                    'port_list': sorted(list(tracking['ports']))[:50],  # Limit to first 50
                    'time_window_seconds': self.config['intrusion_detection']['port_scan']['time_window_seconds']
                },
                wifi_network_id=packet_log.wifi_network_id
            )
            
            # Clear tracking to avoid duplicate alerts
            tracking['ports'].clear()
            tracking['tracker'].clear()
    
    def _check_ddos(self, packet_log: PacketLog):
        """
        Detect DDoS (Distributed Denial of Service) attacks.
        
        DDoS Definition:
        - Single target IP receiving >1000 packets/sec from 5+ distinct sources within 30s
        """
        target_ip = packet_log.dest_ip
        
        if target_ip not in self.ddos_tracking:
            self.ddos_tracking[target_ip] = {
                'source_ips': set(),
                'packet_tracker': ThreatTracker(self.config['intrusion_detection']['ddos']['time_window_seconds'])
            }
        
        tracking = self.ddos_tracking[target_ip]
        tracking['source_ips'].add(packet_log.source_ip)
        tracking['packet_tracker'].add_event(packet_log.timestamp)
        
        # Check thresholds
        packet_count = tracking['packet_tracker'].get_count()
        source_count = len(tracking['source_ips'])
        time_window = self.config['intrusion_detection']['ddos']['time_window_seconds']
        packet_rate = packet_count / time_window if time_window > 0 else 0
        
        packet_threshold = self.config['intrusion_detection']['ddos']['packet_rate_threshold']
        source_threshold = self.config['intrusion_detection']['ddos']['source_count_threshold']
        
        if packet_rate > packet_threshold and source_count >= source_threshold:
            # DDoS detected!
            self._generate_alert(
                alert_type="DDOS",
                severity="CRITICAL",
                source_ip=None,  # Multiple sources
                source_mac=None,
                target_ip=target_ip,
                metadata={
                    'packet_rate': int(packet_rate),
                    'source_count': source_count,
                    'source_ips': list(tracking['source_ips'])[:20],  # Limit to first 20
                    'time_window_seconds': time_window
                },
                wifi_network_id=packet_log.wifi_network_id
            )
            
            # Clear tracking to avoid duplicate alerts
            tracking['source_ips'].clear()
            tracking['packet_tracker'].clear()
    
    def _check_brute_force(self, packet_log: PacketLog):
        """
        Detect brute force authentication attempts.
        
        Brute Force Definition:
        - >10 connection attempts to SSH (22), RDP (3389), or HTTP auth (80/443) within 120s
        - Indicates password guessing attack
        """
        key = (packet_log.source_ip, packet_log.dest_ip, packet_log.dest_port)
        
        if key not in self.brute_force_tracking:
            self.brute_force_tracking[key] = ThreatTracker(
                self.config['intrusion_detection']['brute_force']['time_window_seconds']
            )
        
        tracker = self.brute_force_tracking[key]
        tracker.add_event(packet_log.timestamp)
        
        # Check threshold
        attempt_threshold = self.config['intrusion_detection']['brute_force']['attempt_threshold']
        if tracker.get_count() > attempt_threshold:
            # Brute force detected!
            port_names = {22: 'SSH', 3389: 'RDP', 80: 'HTTP', 443: 'HTTPS'}
            port_name = port_names.get(packet_log.dest_port, str(packet_log.dest_port))
            
            self._generate_alert(
                alert_type="BRUTE_FORCE",
                severity="HIGH",
                source_ip=packet_log.source_ip,
                source_mac=packet_log.source_mac,
                target_ip=packet_log.dest_ip,
                metadata={
                    'target_port': packet_log.dest_port,
                    'port_name': port_name,
                    'attempt_count': tracker.get_count(),
                    'time_window_seconds': self.config['intrusion_detection']['brute_force']['time_window_seconds']
                },
                wifi_network_id=packet_log.wifi_network_id
            )
            
            # Clear tracking
            tracker.clear()
    
    def _check_prohibited_website(self, packet_log: PacketLog):
        """
        Detect access to prohibited websites via DNS monitoring.
        
        DNS Monitoring:
        - Inspect DNS queries for blacklisted domains
        - Enforce acceptable use policies
        """
        if not packet_log.dns_query:
            return
        
        domain = packet_log.dns_query.lower()
        
        with self.prohibited_domains_lock:
            # Check exact match or subdomain match
            is_prohibited = domain in self.prohibited_domains
            if not is_prohibited:
                # Check if any prohibited domain is a suffix (e.g., example.com matches sub.example.com)
                for prohibited in self.prohibited_domains:
                    if domain.endswith('.' + prohibited) or domain == prohibited:
                        is_prohibited = True
                        break
        
        if is_prohibited:
            # Prohibited website access detected!
            self._generate_alert(
                alert_type="PROHIBITED_WEBSITE",
                severity="MEDIUM",
                source_ip=packet_log.source_ip,
                source_mac=packet_log.source_mac,
                target_ip=None,
                metadata={
                    'domain': domain,
                    'category': 'prohibited'
                },
                wifi_network_id=packet_log.wifi_network_id
            )
    
    def _track_bandwidth(self, packet_log: PacketLog):
        """
        Track bandwidth usage per device for high usage detection.
        
        High Bandwidth Definition:
        - Single device transferring >5GB within 1 hour
        """
        key = (packet_log.source_mac, packet_log.wifi_network_id)
        
        if key not in self.bandwidth_tracking:
            self.bandwidth_tracking[key] = {
                'bytes': 0,
                'start_time': packet_log.timestamp
            }
        
        tracking = self.bandwidth_tracking[key]
        tracking['bytes'] += packet_log.packet_size
        
        # Check if time window has passed
        elapsed = (packet_log.timestamp - tracking['start_time']).total_seconds()
        time_window = self.config['intrusion_detection']['high_bandwidth']['time_window_seconds']
        
        if elapsed > time_window:
            # Reset tracking for new window
            tracking['bytes'] = packet_log.packet_size
            tracking['start_time'] = packet_log.timestamp
        else:
            # Check threshold
            threshold_bytes = self.config['intrusion_detection']['high_bandwidth']['threshold_gb'] * 1024 * 1024 * 1024
            if tracking['bytes'] > threshold_bytes:
                # High bandwidth usage detected!
                self._generate_alert(
                    alert_type="HIGH_BANDWIDTH",
                    severity="MEDIUM",
                    source_ip=packet_log.source_ip,
                    source_mac=packet_log.source_mac,
                    target_ip=None,
                    metadata={
                        'bytes_transferred': tracking['bytes'],
                        'gb_transferred': round(tracking['bytes'] / (1024**3), 2),
                        'time_window_seconds': time_window
                    },
                    wifi_network_id=packet_log.wifi_network_id
                )
                
                # Reset tracking
                tracking['bytes'] = 0
                tracking['start_time'] = packet_log.timestamp
    
    def _check_cleartext_credentials(self, packet_log: PacketLog):
        """
        Inspect TCP payload on HTTP (port 80) and FTP (port 21) for clear-text
        credential patterns using Layer 7 (Application layer) inspection.

        HTTP detection: regex search for 'user=', 'login=', 'username=', 'password='
        FTP detection: literal prefix check for 'USER ' and 'PASS ' commands

        IMPORTANT: Only the parameter name / command keyword is stored in the alert
        metadata — the actual credential value is NEVER saved anywhere.

        Args:
            packet_log: PacketLog with raw_payload populated (guaranteed non-None by caller)
        """
        try:
            # Decode the raw TCP payload as UTF-8.
            # If the payload contains non-UTF-8 bytes (binary data), skip silently.
            try:
                payload_text = packet_log.raw_payload.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                logger.debug(
                    f"Non-UTF-8 payload from {packet_log.source_ip} on port "
                    f"{packet_log.dest_port} — skipping credential check"
                )
                return

            if packet_log.dest_port == 80:
                # --- HTTP credential detection ---
                # Regex matches any of the four common form-field names followed by '='.
                # We capture only the parameter name (group 1), never the value after '='.
                # Pattern breakdown:
                #   (?i)          — case-insensitive (handles Password=, PASSWORD=, etc.)
                #   (user|login|username|password)  — the parameter name to capture
                #   =             — the assignment operator that confirms it's a key=value pair
                http_pattern = re.compile(
                    r'(?i)(user|login|username|password)=',
                    re.IGNORECASE
                )
                match = http_pattern.search(payload_text)
                if match:
                    # Extract only the matched keyword, not the value that follows '='
                    matched_param = match.group(1).lower()
                    logger.warning(
                        f"Clear-text credential detected: '{matched_param}=' in HTTP traffic "
                        f"from {packet_log.source_ip}"
                    )
                    self._generate_alert(
                        alert_type="CLEARTEXT_CREDENTIAL",
                        severity="CRITICAL",
                        source_ip=packet_log.source_ip,
                        source_mac=packet_log.source_mac,
                        target_ip=packet_log.dest_ip,
                        metadata={
                            # Protocol identifier for the alert display
                            "protocol": "HTTP",
                            # Only the parameter name — value is intentionally omitted
                            "matched_parameter": matched_param,
                            "description": (
                                f"Clear-text credential transmission detected on "
                                f"{packet_log.source_ip} via HTTP"
                            )
                        },
                        wifi_network_id=packet_log.wifi_network_id
                    )

            elif packet_log.dest_port == 21:
                # --- FTP credential detection ---
                # FTP authentication uses plain-text commands:
                #   'USER <username>\r\n'  — sent to identify the user
                #   'PASS <password>\r\n'  — sent to authenticate
                # We check only the command keyword prefix, never the argument value.
                ftp_command = None
                upper_payload = payload_text.upper()

                if upper_payload.startswith("USER "):
                    # FTP USER command — username is being transmitted in clear text
                    ftp_command = "USER"
                elif upper_payload.startswith("PASS "):
                    # FTP PASS command — password is being transmitted in clear text
                    ftp_command = "PASS"

                if ftp_command:
                    logger.warning(
                        f"Clear-text FTP credential detected: '{ftp_command}' command "
                        f"from {packet_log.source_ip}"
                    )
                    self._generate_alert(
                        alert_type="CLEARTEXT_CREDENTIAL",
                        severity="CRITICAL",
                        source_ip=packet_log.source_ip,
                        source_mac=packet_log.source_mac,
                        target_ip=packet_log.dest_ip,
                        metadata={
                            # Protocol identifier for the alert display
                            "protocol": "FTP",
                            # Only the command keyword — the argument value is intentionally omitted
                            "matched_parameter": ftp_command,
                            "description": (
                                f"Clear-text credential transmission detected on "
                                f"{packet_log.source_ip} via FTP"
                            )
                        },
                        wifi_network_id=packet_log.wifi_network_id
                    )

        except Exception as e:
            # Catch-all: credential check must never crash the main analyze_packet() flow
            logger.error(f"Error in cleartext credential check for {packet_log.source_ip}: {e}")

    def _generate_alert(self, alert_type: str, severity: str,
                       source_ip: Optional[str], source_mac: Optional[str],
                       target_ip: Optional[str], metadata: Dict,
                       wifi_network_id: int):
        """
        Generate and store security alert.
        
        Args:
            alert_type: PORT_SCAN, DDOS, BRUTE_FORCE, PROHIBITED_WEBSITE, HIGH_BANDWIDTH
            severity: LOW, MEDIUM, HIGH, CRITICAL
            source_ip: Source IP of threat
            source_mac: Source MAC of threat
            target_ip: Target IP
            metadata: Additional alert details
            wifi_network_id: WiFi network ID
        """
        try:
            alert_id = self.db_manager.insert_security_alert(
                alert_type=alert_type,
                severity=severity,
                source_ip=source_ip,
                source_mac=source_mac,
                target_ip=target_ip,
                metadata=metadata,
                wifi_network_id=wifi_network_id
            )
            
            logger.warning(f"Security Alert [{severity}] {alert_type}: {metadata}")
        
        except Exception as e:
            logger.error(f"Failed to generate alert: {e}")
    
    def _cleanup_loop(self):
        """
        Background task to clean up old tracking data.
        Prevents memory leaks from accumulating tracking dictionaries.
        """
        import time
        
        while self.is_running:
            try:
                time.sleep(300)  # Cleanup every 5 minutes
                
                current_time = datetime.now()
                
                # Clean port scan tracking
                old_keys = [
                    key for key, data in self.port_scan_tracking.items()
                    if len(data['tracker'].events) == 0
                ]
                for key in old_keys:
                    del self.port_scan_tracking[key]
                
                # Clean DDoS tracking
                old_keys = [
                    key for key, data in self.ddos_tracking.items()
                    if len(data['packet_tracker'].events) == 0
                ]
                for key in old_keys:
                    del self.ddos_tracking[key]
                
                # Clean brute force tracking
                old_keys = [
                    key for key, tracker in self.brute_force_tracking.items()
                    if len(tracker.events) == 0
                ]
                for key in old_keys:
                    del self.brute_force_tracking[key]
                
                # Clean bandwidth tracking (older than 2 hours)
                old_keys = [
                    key for key, data in self.bandwidth_tracking.items()
                    if (current_time - data['start_time']).total_seconds() > 7200
                ]
                for key in old_keys:
                    del self.bandwidth_tracking[key]
                
                logger.debug("IDS tracking data cleaned up")
            
            except Exception as e:
                logger.error(f"Error in IDS cleanup loop: {e}")
