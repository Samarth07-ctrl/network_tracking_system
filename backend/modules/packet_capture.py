"""
Packet Capture Module

This module implements packet sniffing using Scapy to capture network traffic
from multiple WiFi access points concurrently. It extracts packet headers and
metadata for analysis by the Traffic Analyzer module.

Networking Concepts Implemented:
- Packet Sniffing: Capturing raw network packets from interfaces
- Protocol Analysis: Parsing IP, TCP, UDP, ICMP, DNS headers
- MAC Address Extraction: Identifying devices by hardware address
- Asynchronous I/O: Non-blocking packet capture for high throughput
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Ether, ARP
from scapy.error import Scapy_Exception
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Callable, Dict, Any
import asyncio
import threading
import logging
import queue
from queue import Queue, Full

logger = logging.getLogger(__name__)


@dataclass
class PacketLog:
    """
    Data structure representing captured packet metadata.
    This is the core data model passed between capture, analysis, and storage modules.
    """
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_mac: str
    protocol: str
    source_port: Optional[int]
    dest_port: Optional[int]
    packet_size: int
    wifi_network_id: int
    dns_query: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'source_mac': self.source_mac,
            'protocol': self.protocol,
            'source_port': self.source_port,
            'dest_port': self.dest_port,
            'packet_size': self.packet_size,
            'wifi_network_id': self.wifi_network_id,
            'dns_query': self.dns_query
        }


class PacketCaptureModule:
    """
    Captures network packets from configured interfaces using Scapy.
    Supports concurrent capture from multiple WiFi networks.
    
    Networking Concepts:
    - Promiscuous Mode: Captures all packets on the network segment
    - BPF Filters: Berkeley Packet Filter for efficient packet filtering
    - Packet Queuing: Buffering packets for asynchronous processing
    """
    
    def __init__(self, wifi_network_id: int, interface: str, 
                 packet_callback: Callable[[PacketLog], None],
                 max_queue_size: int = 10000):
        """
        Initialize packet capture for a specific WiFi network.
        
        Args:
            wifi_network_id: Database ID of the WiFi network
            interface: Network interface name (e.g., 'eth0', 'wlan0')
            packet_callback: Function to call with each captured packet
            max_queue_size: Maximum packets in processing queue
        """
        self.wifi_network_id = wifi_network_id
        self.interface = interface
        self.packet_callback = packet_callback
        self.max_queue_size = max_queue_size
        
        self.packet_queue = Queue(maxsize=max_queue_size)
        self.is_running = False
        self.capture_thread = None
        self.process_thread = None
        
        self.packets_captured = 0
        self.packets_dropped = 0
    
    def start(self):
        """Start packet capture and processing threads."""
        if self.is_running:
            logger.warning(f"Capture already running for network {self.wifi_network_id}")
            return
        
        self.is_running = True
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            name=f"Capture-{self.wifi_network_id}",
            daemon=True
        )
        self.capture_thread.start()
        
        # Start processing thread
        self.process_thread = threading.Thread(
            target=self._process_loop,
            name=f"Process-{self.wifi_network_id}",
            daemon=True
        )
        self.process_thread.start()
        
        logger.info(f"Started packet capture for network {self.wifi_network_id} on {self.interface}")
    
    def stop(self):
        """Stop packet capture and processing."""
        self.is_running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        if self.process_thread:
            self.process_thread.join(timeout=5)
        
        logger.info(f"Stopped packet capture for network {self.wifi_network_id}")
    
    def _capture_loop(self):
        """
        Main capture loop using Scapy's sniff function.
        Runs in separate thread to avoid blocking.
        """
        try:
            # Scapy sniff parameters:
            # - iface: Network interface to capture from
            # - prn: Callback function for each packet
            # - store: Don't store packets in memory (we process immediately)
            # - stop_filter: Function to determine when to stop
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except Scapy_Exception as e:
            logger.error(f"Scapy capture error on {self.interface}: {e}")
        except PermissionError:
            logger.error(f"Permission denied for packet capture on {self.interface}. Run with sudo/admin privileges.")
        except Exception as e:
            logger.error(f"Unexpected error in capture loop: {e}")
    
    def _packet_handler(self, packet):
        """
        Handle each captured packet.
        Parses packet headers and queues for processing.
        
        Networking Concepts:
        - Layer 2 (Data Link): Ethernet frame with MAC addresses
        - Layer 3 (Network): IP packet with source/dest addresses
        - Layer 4 (Transport): TCP/UDP with port numbers
        - Layer 7 (Application): DNS queries
        """
        try:
            # Parse packet into PacketLog structure
            packet_log = self._parse_packet(packet)
            
            if packet_log:
                # Add to processing queue
                try:
                    self.packet_queue.put_nowait(packet_log)
                    self.packets_captured += 1
                    
                    # Monitor queue capacity (QoS concept)
                    queue_usage = self.packet_queue.qsize() / self.max_queue_size
                    if queue_usage > 0.8:
                        logger.warning(f"Packet queue at {queue_usage*100:.1f}% capacity for network {self.wifi_network_id}")
                
                except Full:
                    self.packets_dropped += 1
                    if self.packets_dropped % 100 == 0:
                        logger.error(f"Dropped {self.packets_dropped} packets due to full queue")
        
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
    
    def _parse_packet(self, packet) -> Optional[PacketLog]:
        """
        Parse raw packet into structured PacketLog object.
        Extracts headers from multiple protocol layers.
        
        Args:
            packet: Scapy packet object
        
        Returns:
            PacketLog object or None if packet cannot be parsed
        """
        try:
            # Skip non-IP packets (ARP, etc.)
            if not packet.haslayer(IP):
                return None
            
            # Extract Layer 3 (IP) information
            ip_layer = packet[IP]
            source_ip = ip_layer.src
            dest_ip = ip_layer.dst
            packet_size = len(packet)
            
            # Extract Layer 2 (Ethernet) MAC address
            source_mac = packet[Ether].src if packet.haslayer(Ether) else "00:00:00:00:00:00"
            
            # Determine protocol and extract Layer 4 (Transport) information
            protocol = "UNKNOWN"
            source_port = None
            dest_port = None
            dns_query = None
            
            if packet.haslayer(TCP):
                protocol = "TCP"
                source_port = packet[TCP].sport
                dest_port = packet[TCP].dport
                
                # Identify HTTP/HTTPS by port
                if dest_port == 80:
                    protocol = "HTTP"
                elif dest_port == 443:
                    protocol = "HTTPS"
            
            elif packet.haslayer(UDP):
                protocol = "UDP"
                source_port = packet[UDP].sport
                dest_port = packet[UDP].dport
                
                # Check for DNS (port 53)
                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    protocol = "DNS"
                    dns_query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            
            # Create PacketLog object
            return PacketLog(
                timestamp=datetime.now(),
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_mac=source_mac,
                protocol=protocol,
                source_port=source_port,
                dest_port=dest_port,
                packet_size=packet_size,
                wifi_network_id=self.wifi_network_id,
                dns_query=dns_query
            )
        
        except Exception as e:
            logger.debug(f"Failed to parse packet: {e}")
            return None
    
    def _process_loop(self):
        """
        Process packets from queue.
        Calls the callback function for each packet.
        """
        while self.is_running:
            try:
                # Get packet from queue with timeout
                try:
                    packet_log = self.packet_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Call the callback function (typically Traffic Analyzer)
                self.packet_callback(packet_log)
                
                self.packet_queue.task_done()
            
            except Exception as e:
                if self.is_running:  # Only log if not shutting down
                    logger.error(f"Error processing packet: {e}", exc_info=True)
    
    def get_stats(self) -> Dict[str, int]:
        """Get capture statistics."""
        return {
            'packets_captured': self.packets_captured,
            'packets_dropped': self.packets_dropped,
            'queue_size': self.packet_queue.qsize(),
            'queue_capacity': self.max_queue_size
        }


class PacketCaptureManager:
    """
    Manages multiple PacketCaptureModule instances for concurrent
    capture from multiple WiFi networks.
    """
    
    def __init__(self):
        self.capture_modules: Dict[int, PacketCaptureModule] = {}
    
    def add_network(self, wifi_network_id: int, interface: str,
                   packet_callback: Callable[[PacketLog], None]):
        """
        Add a WiFi network for packet capture.
        
        Args:
            wifi_network_id: Database ID of the WiFi network
            interface: Network interface name
            packet_callback: Function to call with captured packets
        """
        if wifi_network_id in self.capture_modules:
            logger.warning(f"Network {wifi_network_id} already being captured")
            return
        
        module = PacketCaptureModule(wifi_network_id, interface, packet_callback)
        self.capture_modules[wifi_network_id] = module
        module.start()
    
    def remove_network(self, wifi_network_id: int):
        """Stop capturing from a WiFi network."""
        if wifi_network_id in self.capture_modules:
            self.capture_modules[wifi_network_id].stop()
            del self.capture_modules[wifi_network_id]
    
    def stop_all(self):
        """Stop all packet capture modules."""
        for module in self.capture_modules.values():
            module.stop()
        self.capture_modules.clear()
    
    def get_all_stats(self) -> Dict[int, Dict[str, int]]:
        """Get statistics for all capture modules."""
        return {
            network_id: module.get_stats()
            for network_id, module in self.capture_modules.items()
        }
