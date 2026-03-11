"""
FastAPI REST API Routes

Provides HTTP endpoints for the admin dashboard to access network data.

Endpoints:
- GET /api/networks - List all WiFi networks
- GET /api/networks/{id} - Get network details
- GET /api/networks/{id}/devices - Get connected devices
- GET /api/networks/{id}/metrics - Get performance metrics
- GET /api/packets - Get packet logs
- GET /api/protocols/{network_id} - Get protocol distribution
- GET /api/bandwidth/{network_id} - Get top bandwidth consumers
- GET /api/alerts - Get security alerts
- POST /api/prohibited-websites - Add prohibited domain
- DELETE /api/prohibited-websites/{id} - Remove prohibited domain
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


# Pydantic models for request/response validation
class ProhibitedWebsiteCreate(BaseModel):
    domain: str
    category: str


class ProhibitedWebsiteResponse(BaseModel):
    id: int
    domain: str
    category: str
    added_at: datetime


def create_app(db_manager, traffic_analyzer, ids_engine):
    """
    Create FastAPI application with all routes.
    
    Args:
        db_manager: DatabaseManager instance
        traffic_analyzer: TrafficAnalyzer instance
        ids_engine: IntrusionDetectionEngine instance
    
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
    
    return app
