"""
PCAP File Processor Module

Reads a .pcap file using Scapy's rdpcap() and replays every packet through
the existing TrafficAnalyzer pipeline — identical to live capture but sourced
from a file.  This enables "Demo Mode" for forensic analysis and jury
demonstrations without requiring a live network interface.

Key design decisions:
- Runs synchronously inside a background thread (caller is responsible for
  threading) so the FastAPI endpoint can return immediately.
- Processes packets in configurable batches with a rate-limit sleep to avoid
  overwhelming the TrafficAnalyzer queue (max 10 000 pps by default).
- Deletes the temporary file after processing unless test_mode=True.
- A module-level threading.Semaphore(2) is managed by the API layer to cap
  concurrent uploads at 2; this module itself is stateless w.r.t. concurrency.
"""

import os
import time
import logging
from datetime import datetime
from typing import Optional

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, Ether, Raw
from scapy.error import Scapy_Exception

from .packet_capture import PacketLog

logger = logging.getLogger(__name__)


class PcapReadError(Exception):
    """Raised when Scapy cannot parse the uploaded PCAP file."""


class PcapProcessor:
    """
    Processes an uploaded .pcap file through the existing traffic analysis
    and intrusion detection pipeline.

    Usage::

        processor = PcapProcessor(traffic_analyzer, wifi_network_id=1)
        summary = processor.process_file("/tmp/upload_abc123.pcap")
        # summary == {"packets_processed": 1500, "duration_seconds": 0.42, "errors": 3}

    Args:
        traffic_analyzer: TrafficAnalyzer instance whose process_packet()
            method is called for every parsed packet.
        wifi_network_id: The database WiFi network ID to tag packets with.
            Defaults to 1 (first network).
        batch_size: Number of packets to process before sleeping to enforce
            the rate limit.  Defaults to 1000.
        rate_limit_pps: Maximum packets per second to feed into the pipeline.
            Defaults to 10 000.  Set to 0 to disable rate limiting.
        test_mode: When True the temporary file is NOT deleted after processing,
            allowing inspection in automated tests.
    """

    def __init__(
        self,
        traffic_analyzer,
        wifi_network_id: int = 1,
        batch_size: int = 1000,
        rate_limit_pps: int = 10000,
        test_mode: bool = False,
    ):
        self.traffic_analyzer = traffic_analyzer
        self.wifi_network_id = wifi_network_id
        self.batch_size = batch_size
        self.rate_limit_pps = rate_limit_pps
        self.test_mode = test_mode

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_file(self, file_path: str) -> dict:
        """
        Read a PCAP file and push every IP packet through the traffic
        analysis pipeline.

        Args:
            file_path: Absolute (or relative) path to the .pcap file.

        Returns:
            A summary dict::

                {
                    "packets_processed": int,   # packets successfully sent to pipeline
                    "duration_seconds": float,  # wall-clock time for the whole run
                    "errors": int,              # packets that failed to parse
                }

        Raises:
            PcapReadError: If Scapy cannot open or parse the file.
        """
        logger.info(f"Starting PCAP processing: {file_path}")
        start_time = time.monotonic()

        # --- Step 1: Read the PCAP file ---
        try:
            packets = rdpcap(file_path)
        except Scapy_Exception as exc:
            raise PcapReadError(f"Failed to read PCAP file '{file_path}': {exc}") from exc
        except FileNotFoundError as exc:
            raise PcapReadError(f"PCAP file not found: '{file_path}'") from exc

        total = len(packets)
        logger.info(f"Loaded {total} packets from {file_path}")

        # --- Step 2: Process packets in rate-limited batches ---
        packets_processed = 0
        errors = 0

        for batch_start in range(0, total, self.batch_size):
            batch = packets[batch_start: batch_start + self.batch_size]
            batch_start_time = time.monotonic()

            for raw_packet in batch:
                packet_log = self._parse_packet(raw_packet)
                if packet_log is None:
                    # Non-IP or malformed packet — skip silently
                    continue
                try:
                    self.traffic_analyzer.process_packet(packet_log)
                    packets_processed += 1
                except Exception as exc:
                    errors += 1
                    logger.error(
                        f"Pipeline error for packet from {getattr(packet_log, 'source_ip', '?')}: {exc}"
                    )

            # Enforce rate limit: sleep for the remaining time in the batch window
            if self.rate_limit_pps > 0:
                batch_duration = time.monotonic() - batch_start_time
                expected_duration = len(batch) / self.rate_limit_pps
                sleep_time = expected_duration - batch_duration
                if sleep_time > 0:
                    time.sleep(sleep_time)

        duration = time.monotonic() - start_time

        # --- Step 3: Clean up the temporary file ---
        if not self.test_mode:
            try:
                os.remove(file_path)
                logger.info(f"Deleted temporary PCAP file: {file_path}")
            except OSError as exc:
                logger.warning(f"Could not delete temporary file '{file_path}': {exc}")

        summary = {
            "packets_processed": packets_processed,
            "duration_seconds": round(duration, 3),
            "errors": errors,
        }
        logger.info(f"PCAP processing complete: {summary}")
        return summary

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_packet(self, packet) -> Optional[PacketLog]:
        """
        Convert a raw Scapy packet into a PacketLog object using the same
        logic as PacketCaptureModule._parse_packet().

        Returns None for non-IP packets (ARP, etc.) or on parse failure.

        Args:
            packet: A Scapy packet object from rdpcap().

        Returns:
            PacketLog instance, or None if the packet should be skipped.
        """
        try:
            # Only process IP packets (skip ARP, etc.)
            if not packet.haslayer(IP):
                return None

            ip_layer = packet[IP]
            source_ip: str = ip_layer.src
            dest_ip: str = ip_layer.dst
            packet_size: int = len(packet)

            # Layer 2 — MAC address (may be absent in some PCAP formats)
            source_mac: str = (
                packet[Ether].src if packet.haslayer(Ether) else "00:00:00:00:00:00"
            )

            # Layer 4 — Transport protocol and ports
            protocol = "UNKNOWN"
            source_port: Optional[int] = None
            dest_port: Optional[int] = None
            dns_query: Optional[str] = None
            raw_payload: Optional[bytes] = None

            if packet.haslayer(TCP):
                protocol = "TCP"
                source_port = packet[TCP].sport
                dest_port = packet[TCP].dport

                # Classify well-known application protocols by destination port
                if dest_port == 80:
                    protocol = "HTTP"
                elif dest_port == 443:
                    protocol = "HTTPS"

            elif packet.haslayer(UDP):
                protocol = "UDP"
                source_port = packet[UDP].sport
                dest_port = packet[UDP].dport

                # DNS runs over UDP port 53
                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    protocol = "DNS"
                    dns_query = (
                        packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                    )

            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            # Layer 7 — Raw application payload (used by credential sniffer)
            if packet.haslayer(Raw):
                raw_payload = bytes(packet[Raw].load)

            return PacketLog(
                # Use current wall-clock time so metrics appear as "live" in the dashboard
                timestamp=datetime.now(),
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_mac=source_mac,
                protocol=protocol,
                source_port=source_port,
                dest_port=dest_port,
                packet_size=packet_size,
                wifi_network_id=self.wifi_network_id,
                dns_query=dns_query,
                raw_payload=raw_payload,
            )

        except Exception as exc:
            logger.debug(f"Failed to parse PCAP packet: {exc}")
            return None
