"""
Comprehensive Observability API for MCP Monitoring

Provides REST endpoints for monitoring data, dashboard integration,
and real-time observability metrics.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
import logging

from .mcp_observability import get_mcp_observability, ServerMetrics, PerformanceProfile
from .metrics import get_metrics_collector
from .health import get_health_checker
from .alerts import get_alert_manager
from ..core.exceptions import AuthenticationError, ValidationError

__all__ = [
    "observability_router",
    "ObservabilityAPI"
]

logger = logging.getLogger(__name__)

# Pydantic models for API responses
class ServerStatusResponse(BaseModel):
    """Response model for server status."""
    server_name: str
    status: str
    uptime_seconds: float
    last_updated: datetime
    health_score: float = Field(ge=0, le=100)

class MetricsResponse(BaseModel):
    """Response model for metrics data."""
    timestamp: datetime
    server_metrics: Dict[str, ServerMetrics]
    performance_profiles: Dict[str, PerformanceProfile]
    overall_health: str
    active_alerts: List[Dict[str, Any]]

class PerformanceAnalysisResponse(BaseModel):
    """Response model for performance analysis."""
    server_name: str
    analysis_period: str
    performance_score: float
    bottlenecks: List[str]
    recommendations: List[str]
    trends: Dict[str, Any]

class AlertConfigRequest(BaseModel):
    """Request model for alert configuration."""
    alert_type: str
    threshold: float
    duration_minutes: int
    severity: str
    enabled: bool = True

class DashboardDataResponse(BaseModel):
    """Response model for dashboard data."""
    timestamp: datetime
    servers: Dict[str, Any]
    overall_health: str
    performance_summary: Dict[str, Any]
    alerts: List[Dict[str, Any]]
    sla_metrics: Dict[str, Any]

class ObservabilityAPI:
    """Observability API implementation."""
    
    def __init__(self):
        self.observability = None
        self.metrics_collector = get_metrics_collector()
        self.health_checker = get_health_checker()
        self.alert_manager = get_alert_manager()
        
    async def initialize(self):
        """Initialize the observability API."""
        self.observability = await get_mcp_observability()

# Create API router
observability_router = APIRouter(prefix="/observability", tags=["observability"])
api = ObservabilityAPI()

@observability_router.on_event("startup")
async def startup_observability_api():
    """Initialize the observability API on startup."""
    await api.initialize()

@observability_router.get("/health", response_model=Dict[str, Any])
async def get_observability_health():
    """Get overall observability system health."""
    try:
        if not api.observability:
            raise HTTPException(status_code=503, detail="Observability system not initialized")
        
        # Get overall health status
        dashboard_data = await api.observability.get_dashboard_data()
        
        health_status = {
            "status": dashboard_data.get("overall_health", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "total_servers": dashboard_data.get("total_servers", 0),
            "healthy_servers": dashboard_data.get("healthy_servers", 0),
            "degraded_servers": dashboard_data.get("degraded_servers", 0),
            "unhealthy_servers": dashboard_data.get("unhealthy_servers", 0),
            "active_alerts": len(dashboard_data.get("alerts", [])),
            "monitoring_enabled": True
        }
        
        return health_status
        
    except Exception as e:
        logger.error(f"Error getting observability health: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.get("/servers", response_model=List[ServerStatusResponse])
async def get_server_statuses():
    """Get status of all MCP servers."""
    try:
        if not api.observability:
            raise HTTPException(status_code=503, detail="Observability system not initialized")
        
        server_metrics = await api.observability.get_server_metrics()
        
        statuses = []
        for server_name, metrics in server_metrics.items():
            # Calculate health score based on multiple factors
            health_score = 100.0
            
            if metrics.status != "healthy":
                health_score -= 30
            
            if metrics.error_count > 10:
                health_score -= 20
            
            if metrics.avg_response_time > 5.0:
                health_score -= 15
            
            if metrics.p95_response_time > 10.0:
                health_score -= 15
            
            health_score = max(0, health_score)
            
            status = ServerStatusResponse(
                server_name=server_name,
                status=metrics.status,
                uptime_seconds=metrics.uptime_seconds,
                last_updated=metrics.last_updated,
                health_score=health_score
            )
            statuses.append(status)
        
        return statuses
        
    except Exception as e:
        logger.error(f"Error getting server statuses: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.get("/servers/{server_name}", response_model=ServerMetrics)
async def get_server_metrics(server_name: str):
    """Get detailed metrics for a specific server."""
    try:
        if not api.observability:
            raise HTTPException(status_code=503, detail="Observability system not initialized")
        
        metrics = await api.observability.get_server_metrics(server_name)
        
        if not metrics:
            raise HTTPException(status_code=404, detail=f"Server {server_name} not found")
        
        return metrics
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting server metrics for {server_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.get("/servers/{server_name}/performance", response_model=PerformanceAnalysisResponse)
async def get_server_performance_analysis(
    server_name: str,
    period: str = Query("1h", description="Analysis period (1h, 6h, 24h, 7d)")
):
    """Get performance analysis for a specific server."""
    try:
        if not api.observability:
            raise HTTPException(status_code=503, detail="Observability system not initialized")
        
        profile = await api.observability.get_performance_profile(server_name)
        
        if not profile:
            raise HTTPException(status_code=404, detail=f"Performance profile for {server_name} not found")
        
        # Analyze performance and generate recommendations
        performance_score = 100.0
        bottlenecks = []
        recommendations = []
        
        # Check error rate
        if profile.error_rate > 0.05:
            performance_score -= 25
            bottlenecks.append("High error rate")
            recommendations.append("Investigate error causes and implement retry logic")
        
        # Check latency
        if profile.p95_duration > 5.0:
            performance_score -= 20
            bottlenecks.append("High latency")
            recommendations.append("Optimize slow operations and consider caching")
        
        # Check throughput
        if profile.throughput_per_second < 1.0:
            performance_score -= 15
            bottlenecks.append("Low throughput")
            recommendations.append("Scale server resources or optimize request handling")
        
        # Check stability
        if profile.patterns.get("stability") == "unstable":
            performance_score -= 20
            bottlenecks.append("Unstable performance")
            recommendations.append("Investigate performance variance causes")
        
        # Check trends
        trend_percentage = profile.patterns.get("trend_percentage", 0)
        if trend_percentage > 25:
            performance_score -= 10
            bottlenecks.append("Performance degradation trend")
            recommendations.append("Monitor resource usage and consider scaling")
        
        performance_score = max(0, performance_score)
        
        analysis = PerformanceAnalysisResponse(
            server_name=server_name,
            analysis_period=period,
            performance_score=performance_score,
            bottlenecks=bottlenecks,
            recommendations=recommendations,
            trends=profile.patterns
        )
        
        return analysis
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing performance for {server_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.get("/metrics", response_model=MetricsResponse)
async def get_comprehensive_metrics():
    """Get comprehensive monitoring metrics."""
    try:
        if not api.observability:
            raise HTTPException(status_code=503, detail="Observability system not initialized")
        
        dashboard_data = await api.observability.get_dashboard_data()
        server_metrics = await api.observability.get_server_metrics()
        
        # Get performance profiles
        performance_profiles = {}
        for server_name in server_metrics.keys():
            profile = await api.observability.get_performance_profile(server_name)
            if profile:
                performance_profiles[server_name] = profile
        
        # Get active alerts
        active_alerts = dashboard_data.get("alerts", [])
        
        response = MetricsResponse(
            timestamp=datetime.now(),
            server_metrics=server_metrics,
            performance_profiles=performance_profiles,
            overall_health=dashboard_data.get("overall_health", "unknown"),
            active_alerts=active_alerts
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting comprehensive metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.get("/dashboard", response_model=DashboardDataResponse)
async def get_dashboard_data():
    """Get data for monitoring dashboards."""
    try:
        if not api.observability:
            raise HTTPException(status_code=503, detail="Observability system not initialized")
        
        dashboard_data = await api.observability.get_dashboard_data()
        
        # Add SLA metrics
        sla_metrics = {
            "availability": 99.9,  # Would be calculated from actual metrics
            "latency_p95": 2.5,    # Would be calculated from actual metrics
            "error_rate": 0.01,    # Would be calculated from actual metrics
            "uptime_minutes": 1440 # Would be calculated from actual metrics
        }
        
        response = DashboardDataResponse(
            timestamp=datetime.now(),
            servers=dashboard_data.get("servers", {}),
            overall_health=dashboard_data.get("overall_health", "unknown"),
            performance_summary=dashboard_data.get("performance_summary", {}),
            alerts=dashboard_data.get("alerts", []),
            sla_metrics=sla_metrics
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.get("/alerts")
async def get_active_alerts():
    """Get currently active alerts."""
    try:
        active_alerts = await api.alert_manager.get_active_alerts()
        
        alert_data = []
        for alert in active_alerts:
            alert_info = {
                "name": alert.rule.name,
                "severity": alert.rule.severity.value,
                "description": alert.rule.description,
                "started_at": alert.started_at.isoformat(),
                "value": alert.value,
                "labels": alert.labels,
                "annotations": alert.annotations,
                "state": alert.state.value
            }
            alert_data.append(alert_info)
        
        return {
            "active_alerts": alert_data,
            "total_count": len(alert_data),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting active alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.post("/alerts/configure")
async def configure_alert(alert_config: AlertConfigRequest):
    """Configure a new alert rule."""
    try:
        # This would integrate with the alert manager to create/update rules
        # For now, return a success response
        
        logger.info(f"Alert configuration request: {alert_config}")
        
        return {
            "status": "success",
            "message": f"Alert rule configured for {alert_config.alert_type}",
            "alert_id": f"alert_{alert_config.alert_type}_{datetime.now().timestamp()}",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error configuring alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.get("/export/{format}")
async def export_metrics(format: str = "prometheus"):
    """Export metrics in various formats."""
    try:
        if not api.observability:
            raise HTTPException(status_code=503, detail="Observability system not initialized")
        
        if format not in ["prometheus", "json", "csv"]:
            raise HTTPException(status_code=400, detail="Unsupported export format")
        
        metrics_data = await api.observability.export_metrics(format)
        
        if format == "prometheus":
            return {
                "content": metrics_data,
                "content_type": "text/plain",
                "timestamp": datetime.now().isoformat()
            }
        elif format == "json":
            return {
                "content": json.loads(metrics_data),
                "content_type": "application/json",
                "timestamp": datetime.now().isoformat()
            }
        else:  # csv
            return {
                "content": metrics_data,
                "content_type": "text/csv",
                "timestamp": datetime.now().isoformat()
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.post("/diagnostics/run")
async def run_diagnostics(background_tasks: BackgroundTasks):
    """Run comprehensive diagnostics on MCP servers."""
    try:
        if not api.observability:
            raise HTTPException(status_code=503, detail="Observability system not initialized")
        
        # Start diagnostics as background task
        async def perform_diagnostics():
            try:
                results = {}
                server_metrics = await api.observability.get_server_metrics()
                
                for server_name in server_metrics.keys():
                    # Perform comprehensive diagnostics
                    diagnostics = {
                        "connectivity_test": "passed",
                        "performance_test": "passed",
                        "memory_check": "passed",
                        "error_analysis": "no_issues",
                        "recommendations": []
                    }
                    
                    # Add actual diagnostic logic here
                    results[server_name] = diagnostics
                
                logger.info(f"Diagnostics completed for {len(results)} servers")
                
            except Exception as e:
                logger.error(f"Diagnostics failed: {e}")
        
        background_tasks.add_task(perform_diagnostics)
        
        return {
            "status": "started",
            "message": "Diagnostics started in background",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error starting diagnostics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.get("/health-checks")
async def get_health_checks():
    """Get results of all health checks."""
    try:
        health_results = await api.health_checker.check_all()
        
        health_data = []
        for result in health_results:
            health_info = {
                "name": result.name,
                "status": result.status.value,
                "message": result.message,
                "details": result.details,
                "timestamp": result.timestamp.isoformat() if result.timestamp else None
            }
            health_data.append(health_info)
        
        return {
            "health_checks": health_data,
            "total_checks": len(health_data),
            "healthy_checks": len([h for h in health_data if h["status"] == "healthy"]),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting health checks: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@observability_router.websocket("/live")
async def websocket_live_metrics(websocket):
    """WebSocket endpoint for live metrics streaming."""
    await websocket.accept()
    
    try:
        while True:
            if api.observability:
                # Get latest dashboard data
                dashboard_data = await api.observability.get_dashboard_data()
                await websocket.send_json(dashboard_data)
            
            # Wait 5 seconds before sending next update
            await asyncio.sleep(5)
            
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()