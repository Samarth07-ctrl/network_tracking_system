"""
FastAPI REST API Routes

Provides HTTP endpoints for the admin dashboard to access network data.

Endpoints:
- GET  /api/networks                    - List all WiFi networks
- GET  /api/networks/{id}               - Get network details
- GET  /api/networks/{id}/devices       - Get connected devices
- GET  /api/networks/{id}/metrics       - Get performance metrics
- GET  /api/packets                     - Get packet logs
- GET  /api/protocols/{network_id}      - Get protocol distribution
- GET  /api/bandwidth/{network_id}      - Get top bandwidth consumers
- GET  /api/alerts                      - Get security alerts
- DELETE /api/alerts/clear-all          - Truncate all security alerts (DB reset utility)
- POST /api/prohibited-websites         - Add prohibited domain
- DELETE /api/prohibited-websites/{id}  - Remove prohibited domain
- POST /api/upload-pcap/                - Upload .pcap file for demo/forensic analysis
- GET  /api/report/generate-pdf         - Generate and download security audit PDF
- GET  /api/test/upload-pcap            - Test PCAP processing without storing results
"""

import io
import os
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime, timedelta
from typing import List, Optional

import aiofiles
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Concurrency guard: at most 2 PCAP uploads processed simultaneously.
# The semaphore is acquired before starting background processing and released
# inside the background task's finally block.
# ---------------------------------------------------------------------------
_upload_semaphore = threading.Semaphore(2)


# Pydantic models for request/response validation
class ProhibitedWebsiteCreate(BaseModel):
    domain: str
    category: str


class ProhibitedWebsiteResponse(BaseModel):
    id: int
    domain: str
    category: str
    added_at: datetime


def create_app(db_manager, traffic_analyzer, ids_engine, pcap_processor=None, pdf_generator=None):
    """
    Create FastAPI application with all routes.

    Args:
        db_manager: DatabaseManager instance
        traffic_analyzer: TrafficAnalyzer instance
        ids_engine: IntrusionDetectionEngine instance
        pcap_processor: PcapProcessor instance (Feature 1 — PCAP Demo Mode)
        pdf_generator: PdfGenerator instance (Feature 3 — PDF Audit Report)

    Returns:
        FastAPI application
    """
    app = FastAPI(
        title="Campus Network Traffic Analyzer API",
        description="REST API for campus network monitoring and security",
        version="1.0.0"
    )
    
    # Enable CORS for frontend access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, specify exact origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    @app.get("/")
    def root():
        """Health check endpoint."""
        return {"status": "ok", "service": "Campus Network Traffic Analyzer"}
    
    @app.get("/api/networks")
    def get_networks():
        """Get list of all WiFi networks."""
        try:
            networks = db_manager.get_wifi_networks()
            
            # Enrich with current stats
            for network in networks:
                stats = traffic_analyzer.get_network_stats(network['id'])
                if stats:
                    network['current_throughput_bps'] = stats['throughput_bps']
                    network['current_packet_rate'] = stats['packet_rate']
                else:
                    network['current_throughput_bps'] = 0
                    network['current_packet_rate'] = 0
                
                # Get active device count
                devices = db_manager.get_connected_devices(network['id'], active_only=True)
                network['active_devices'] = len(devices)
            
            return {"networks": networks}
        except Exception as e:
            logger.error(f"Error getting networks: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/networks/{network_id}")
    def get_network(network_id: int):
        """Get specific network details."""
        try:
            network = db_manager.get_wifi_network_by_id(network_id)
            if not network:
                raise HTTPException(status_code=404, detail="Network not found")
            
            # Add current stats
            stats = traffic_analyzer.get_network_stats(network_id)
            if stats:
                network['current_stats'] = stats
            
            return network
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error getting network {network_id}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/networks/{network_id}/devices")
    def get_network_devices(network_id: int, active_only: bool = True):
        """Get connected devices for a network."""
        try:
            devices = db_manager.get_connected_devices(network_id, active_only)
            return {"devices": devices}
        except Exception as e:
            logger.error(f"Error getting devices for network {network_id}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/networks/{network_id}/metrics")
    def get_network_metrics(
        network_id: int,
        hours: int = Query(1, ge=1, le=24, description="Hours of historical data")
    ):
        """Get performance metrics for a network."""
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            metrics = db_manager.get_performance_metrics(network_id, start_time=start_time)
            return {"metrics": metrics}
        except Exception as e:
            logger.error(f"Error getting metrics for network {network_id}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/packets")
    def get_packets(
        network_id: Optional[int] = None,
        limit: int = Query(100, ge=1, le=1000)
    ):
        """Get recent packet logs."""
        try:
            packets = db_manager.get_packet_logs(
                wifi_network_id=network_id,
                limit=limit
            )
            return {"packets": packets}
        except Exception as e:
            logger.error(f"Error getting packets: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/protocols/{network_id}")
    def get_protocol_distribution(network_id: int):
        """Get protocol distribution for a network."""
        try:
            distribution = traffic_analyzer.get_protocol_distribution(network_id)
            
            # Calculate percentages
            total = sum(distribution.values())
            if total > 0:
                percentages = {
                    protocol: (count / total) * 100
                    for protocol, count in distribution.items()
                }
            else:
                percentages = {}
            
            return {
                "distribution": distribution,
                "percentages": percentages
            }
        except Exception as e:
            logger.error(f"Error getting protocol distribution: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/bandwidth/{network_id}")
    def get_top_bandwidth_consumers(network_id: int, limit: int = Query(10, ge=1, le=50)):
        """Get top bandwidth consuming devices."""
        try:
            consumers = traffic_analyzer.get_top_bandwidth_consumers(network_id, limit)
            return {"consumers": consumers}
        except Exception as e:
            logger.error(f"Error getting bandwidth consumers: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/alerts")
    def get_alerts(
        network_id: Optional[int] = None,
        severity: Optional[str] = None,
        hours: int = Query(24, ge=1, le=168, description="Hours of historical alerts"),
        limit: int = Query(100, ge=1, le=500)
    ):
        """Get security alerts."""
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            alerts = db_manager.get_security_alerts(
                wifi_network_id=network_id,
                severity=severity,
                start_time=start_time,
                limit=limit
            )
            return {"alerts": alerts}
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    # -------------------------------------------------------------------
    # Database Reset Utility: Clear all security alerts
    # -------------------------------------------------------------------

    @app.delete("/api/alerts/clear-all")
    def clear_all_alerts():
        """
        Truncate the security_alerts table.

        This is a maintenance / testing utility designed to wipe the
        thousands of false-positive spam alerts generated when the sniffer
        was capturing its own management traffic, so that PCAP files can
        be tested on a clean slate.

        Returns:
            JSON with the number of deleted rows.
        """
        try:
            deleted_count = db_manager.clear_all_alerts()
            return {
                "message": "All security alerts have been cleared",
                "deleted_count": deleted_count,
            }
        except Exception as e:
            logger.error(f"Error clearing alerts: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/prohibited-websites")
    def get_prohibited_websites():
        """Get list of prohibited websites."""
        try:
            websites = db_manager.get_prohibited_websites()
            return {"websites": websites}
        except Exception as e:
            logger.error(f"Error getting prohibited websites: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/prohibited-websites", status_code=201)
    def add_prohibited_website(website: ProhibitedWebsiteCreate):
        """Add a prohibited website domain."""
        try:
            website_id = db_manager.insert_prohibited_website(website.domain, website.category)
            
            # Reload IDS prohibited domains
            ids_engine.reload_prohibited_websites()
            
            return {"id": website_id, "domain": website.domain, "category": website.category}
        except Exception as e:
            logger.error(f"Error adding prohibited website: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.delete("/api/prohibited-websites/{website_id}")
    def delete_prohibited_website(website_id: int):
        """Remove a prohibited website domain."""
        try:
            success = db_manager.delete_prohibited_website(website_id)
            if not success:
                raise HTTPException(status_code=404, detail="Website not found")
            
            # Reload IDS prohibited domains
            ids_engine.reload_prohibited_websites()
            
            return {"message": "Website deleted successfully"}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error deleting prohibited website: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/stats/overview")
    def get_overview_stats():
        """Get campus-wide overview statistics."""
        try:
            networks = db_manager.get_wifi_networks()
            
            total_networks = len(networks)
            total_devices = 0
            total_throughput = 0
            
            for network in networks:
                devices = db_manager.get_connected_devices(network['id'], active_only=True)
                total_devices += len(devices)
                
                stats = traffic_analyzer.get_network_stats(network['id'])
                if stats:
                    total_throughput += stats['throughput_bps']
            
            # Get recent alerts (last 24 hours)
            start_time = datetime.now() - timedelta(hours=24)
            alerts = db_manager.get_security_alerts(start_time=start_time, limit=1000)
            alert_count = len(alerts)
            
            return {
                "total_networks": total_networks,
                "total_active_devices": total_devices,
                "total_throughput_bps": total_throughput,
                "alerts_24h": alert_count
            }
        except Exception as e:
            logger.error(f"Error getting overview stats: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    # -----------------------------------------------------------------------
    # Feature 1: PCAP File Demo Mode
    # -----------------------------------------------------------------------

    @app.post("/api/upload-pcap/", status_code=202)
    async def upload_pcap(
        background_tasks: BackgroundTasks,
        file: UploadFile = File(...),
    ):
        """
        Accept a .pcap or .pcapng file and process it through the existing
        traffic analysis and IDS pipeline in the background.

        - Validates file extension (.pcap / .pcapng) and size (≤ 500 MB).
        - Limits concurrent uploads to 2 (returns 429 if both slots are busy).
        - Returns 202 Accepted immediately; processing happens asynchronously.
        """
        # --- Validate file extension ---
        filename = file.filename or ""
        if not (filename.lower().endswith(".pcap") or filename.lower().endswith(".pcapng")):
            raise HTTPException(status_code=400, detail="Invalid PCAP format")

        # --- Read file content and validate size (max 500 MB) ---
        MAX_SIZE = 500 * 1024 * 1024  # 500 MB in bytes
        content = await file.read()
        file_size = len(content)

        logger.info(f"PCAP upload attempt: filename={filename}, size={file_size} bytes")

        if file_size > MAX_SIZE:
            raise HTTPException(status_code=413, detail="File too large")

        # --- Check concurrency limit ---
        acquired = _upload_semaphore.acquire(blocking=False)
        if not acquired:
            raise HTTPException(status_code=429, detail="Too many concurrent uploads")

        # --- Save to a temporary file ---
        try:
            tmp_dir = tempfile.mkdtemp()
            task_id = str(uuid.uuid4())
            tmp_path = os.path.join(tmp_dir, f"{task_id}.pcap")

            async with aiofiles.open(tmp_path, "wb") as f:
                await f.write(content)

        except Exception as exc:
            _upload_semaphore.release()
            logger.error(f"Failed to save uploaded PCAP file: {exc}")
            raise HTTPException(status_code=500, detail="Internal server error")

        # --- Enqueue background processing ---
        def _process_and_release():
            """Run PCAP processing and always release the semaphore."""
            try:
                if pcap_processor is not None:
                    summary = pcap_processor.process_file(tmp_path)
                    logger.info(f"PCAP task {task_id} complete: {summary}")
                else:
                    logger.warning("pcap_processor not configured — skipping PCAP processing")
            except Exception as exc:
                logger.error(f"PCAP processing error for task {task_id}: {exc}")
            finally:
                _upload_semaphore.release()

        background_tasks.add_task(_process_and_release)

        return {
            "task_id": task_id,
            "message": "PCAP file accepted for processing",
            "filename": filename,
            "size_bytes": file_size,
        }

    # -----------------------------------------------------------------------
    # Feature 3: Automated Weekly Audit PDF Generator
    # -----------------------------------------------------------------------

    @app.get("/api/report/generate-pdf")
    def generate_pdf_report():
        """
        Generate and stream a Campus Network Security Audit PDF report.

        Queries the database for:
        - Top 5 bandwidth consumers (last 24 hours)
        - Top 5 security alerts (last 24 hours)

        Returns the PDF as an attachment download.
        """
        if pdf_generator is None:
            raise HTTPException(status_code=503, detail="PDF generator not configured")

        logger.info("PDF report generation requested")

        # Run generation with a 10-second timeout to satisfy Requirement 12.5
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(pdf_generator.generate_report)
            try:
                pdf_bytes = future.result(timeout=10)
            except FuturesTimeoutError:
                logger.error("PDF generation timed out after 10 seconds")
                raise HTTPException(status_code=504, detail="Report generation timed out")
            except Exception as exc:
                logger.error(f"PDF generation failed: {exc}")
                raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

        today = datetime.now().strftime("%Y-%m-%d")
        filename = f"campus_security_audit_{today}.pdf"

        logger.info(f"PDF report generated successfully: {filename} ({len(pdf_bytes)} bytes)")

        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # -----------------------------------------------------------------------
    # Feature 1 (testing): Validate PCAP processing without storing results
    # -----------------------------------------------------------------------

    @app.get("/api/test/upload-pcap")
    def test_upload_pcap(file_path: str = Query(..., description="Path to an existing .pcap file")):
        """
        Validate PCAP processing without persisting any results to the database.
        Useful for automated tests and pre-flight checks.

        Args:
            file_path: Absolute or relative path to an existing .pcap file.

        Returns:
            Processing summary dict (packets_processed, duration_seconds, errors).
        """
        if pcap_processor is None:
            raise HTTPException(status_code=503, detail="PCAP processor not configured")

        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail=f"File not found: {file_path}")

        try:
            from modules.pcap_processor import PcapProcessor
            test_processor = PcapProcessor(
                traffic_analyzer=traffic_analyzer,
                test_mode=True,  # keeps the file; does not delete it
            )
            summary = test_processor.process_file(file_path)
            return summary
        except Exception as exc:
            logger.error(f"Test PCAP processing failed: {exc}")
            raise HTTPException(status_code=500, detail=str(exc))

    return app
