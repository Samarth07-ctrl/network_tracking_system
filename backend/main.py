"""
Campus Network Traffic Analyzer - Main Application

This is the entry point for the system. It orchestrates all modules:
- Loads configuration
- Initializes database
- Starts packet capture for all WiFi networks
- Starts traffic analyzer
- Starts intrusion detection engine
- Starts FastAPI server

Usage:
    sudo python main.py                    # Run with live packet capture
    python main.py --pcap-file sample.pcap # Run with PCAP file for testing
"""

import sys
import signal
import logging
import argparse
import uvicorn
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.config_loader import ConfigLoader
from modules.database import DatabaseManager
from modules.packet_capture import PacketCaptureManager
from modules.traffic_analyzer import TrafficAnalyzer
from modules.intrusion_detection import IntrusionDetectionEngine
from modules.pcap_processor import PcapProcessor
from modules.pdf_generator import PdfGenerator
from api.routes import create_app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('campus_monitor.log')
    ]
)
logger = logging.getLogger(__name__)


class CampusNetworkMonitor:
    """
    Main application class that orchestrates all system components.
    
    Architecture:
    1. Configuration: Load system settings from config.yaml
    2. Database: Initialize MySQL connection pool
    3. Packet Capture: Start capturing from all configured WiFi networks
    4. Traffic Analyzer: Process packets and calculate metrics
    5. Intrusion Detection: Analyze packets for security threats
    6. API Server: Provide REST API for dashboard
    """
    
    def __init__(self, config_path: str = 'config.yaml'):
        self.config_path = config_path
        self.config = None
        self.db_manager = None
        self.capture_manager = None
        self.traffic_analyzer = None
        self.ids_engine = None
        self.pcap_processor = None
        self.pdf_generator = None
        self.app = None
    
    def initialize(self):
        """Initialize all system components."""
        logger.info("=" * 60)
        logger.info("Campus Network Traffic Analyzer and Security Monitor")
        logger.info("=" * 60)
        
        # Load configuration
        logger.info("Loading configuration...")
        self.config = ConfigLoader.load(self.config_path)
        logger.info(f"Loaded {len(self.config['wifi_networks'])} WiFi network configurations")
        
        # Initialize database
        logger.info("Connecting to database...")
        self.db_manager = DatabaseManager(self.config['database'])
        logger.info("Database connection established")
        
        # Sync WiFi networks from config to database
        logger.info("Syncing WiFi network configurations...")
        for network in self.config['wifi_networks']:
            self.db_manager.insert_wifi_network(
                ssid=network['ssid'],
                subnet_range=network['subnet'],
                location=network['location'],
                capture_interface=network['capture_interface'],
                bandwidth_capacity_mbps=network.get('bandwidth_capacity_mbps', 100)
            )
        
        # Initialize traffic analyzer
        logger.info("Initializing Traffic Analyzer...")
        self.traffic_analyzer = TrafficAnalyzer(self.db_manager)
        self.traffic_analyzer.start()
        
        # Initialize intrusion detection engine
        logger.info("Initializing Intrusion Detection Engine...")
        self.ids_engine = IntrusionDetectionEngine(self.db_manager, self.config)
        self.ids_engine.start()
        
        # Register IDS as callback for traffic analyzer
        self.traffic_analyzer.register_callback(self.ids_engine.analyze_packet)
        
        # Initialize packet capture manager
        logger.info("Initializing Packet Capture...")
        self.capture_manager = PacketCaptureManager()
        
        # Start capturing from all configured networks
        networks = self.db_manager.get_wifi_networks()
        for network in networks:
            logger.info(f"Starting capture for {network['ssid']} on {network['capture_interface']}")
            self.capture_manager.add_network(
                wifi_network_id=network['id'],
                interface=network['capture_interface'],
                packet_callback=self.traffic_analyzer.process_packet
            )
        
        # Create FastAPI application
        logger.info("Creating API server...")
        self.pcap_processor = PcapProcessor(self.traffic_analyzer)
        self.pdf_generator = PdfGenerator(self.db_manager)
        self.app = create_app(
            self.db_manager,
            self.traffic_analyzer,
            self.ids_engine,
            pcap_processor=self.pcap_processor,
            pdf_generator=self.pdf_generator,
        )
        
        logger.info("=" * 60)
        logger.info("System initialized successfully!")
        logger.info("=" * 60)
    
    def run(self):
        """Start the API server."""
        host = self.config['system']['api_host']
        port = self.config['system']['api_port']
        
        logger.info(f"Starting API server on {host}:{port}")
        logger.info(f"API documentation available at http://{host}:{port}/docs")
        logger.info("Press Ctrl+C to stop")
        
        # Run FastAPI server
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level="info"
        )
    
    def shutdown(self):
        """Gracefully shutdown all components."""
        logger.info("Shutting down...")
        
        if self.capture_manager:
            logger.info("Stopping packet capture...")
            self.capture_manager.stop_all()
        
        if self.traffic_analyzer:
            logger.info("Stopping traffic analyzer...")
            self.traffic_analyzer.stop()
        
        if self.ids_engine:
            logger.info("Stopping intrusion detection engine...")
            self.ids_engine.stop()
        
        if self.db_manager:
            logger.info("Closing database connections...")
            self.db_manager.close()
        
        logger.info("Shutdown complete")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Campus Network Traffic Analyzer and Security Monitor"
    )
    parser.add_argument(
        '--config',
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    parser.add_argument(
        '--pcap-file',
        help='Read packets from PCAP file instead of live capture (for testing)'
    )
    
    args = parser.parse_args()
    
    # Check for root privileges (required for packet capture)
    if not args.pcap_file:
        import os
        is_admin = False
        if sys.platform == 'win32':
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                is_admin = False
        else:
            is_admin = os.geteuid() == 0
        
        if not is_admin:
            logger.warning("Packet capture may require elevated privileges.")
            logger.info("For testing without admin, use: python main.py --pcap-file sample.pcap")
            logger.info("Continuing anyway...")
    
    # Create monitor instance
    monitor = CampusNetworkMonitor(config_path=args.config)
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("\nReceived shutdown signal")
        monitor.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Initialize and run
        monitor.initialize()
        monitor.run()
    
    except KeyboardInterrupt:
        logger.info("\nShutdown requested")
        monitor.shutdown()
    
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        monitor.shutdown()
        sys.exit(1)


if __name__ == "__main__":
    main()
