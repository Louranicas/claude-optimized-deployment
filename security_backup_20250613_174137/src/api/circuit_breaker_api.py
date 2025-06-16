"""
FastAPI endpoints for circuit breaker monitoring and management.

Provides REST API access to circuit breaker states, metrics, and controls.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List, Optional
from datetime import datetime

from src.core.circuit_breaker import (
    get_circuit_breaker_manager,
    CircuitBreakerConfig,
    CircuitState
)

__all__ = [
    "CircuitBreakerAPI",
    "include_router"
]
from src.core.circuit_breaker_monitoring import (
    get_circuit_breaker_monitor,
    MonitoringConfig,
    get_monitoring_status
)

router = APIRouter(prefix="/api/circuit-breakers", tags=["circuit-breakers"])


@router.get("/status")
async def get_circuit_breaker_status() -> Dict[str, Any]:
    """
    Get overall circuit breaker system status.
    
    Returns:
        Summary of all circuit breakers including states and metrics
    """
    manager = get_circuit_breaker_manager()
    monitor_status = get_monitoring_status()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "monitoring": monitor_status,
        "summary": manager.get_summary(),
        "health": _calculate_system_health(manager.get_summary())
    }


@router.get("/breakers")
async def get_all_circuit_breakers(
    state: Optional[str] = Query(None, description="Filter by state (open, closed, half_open)")
) -> Dict[str, Any]:
    """
    Get detailed information about all circuit breakers.
    
    Args:
        state: Optional filter by circuit breaker state
        
    Returns:
        Detailed metrics for each circuit breaker
    """
    manager = get_circuit_breaker_manager()
    all_metrics = manager.get_all_metrics()
    
    # Filter by state if requested
    if state:
        state_filter = state.lower().replace("-", "_")
        all_metrics = {
            name: metrics
            for name, metrics in all_metrics.items()
            if metrics["state"] == state_filter
        }
    
    return {
        "timestamp": datetime.now().isoformat(),
        "total": len(all_metrics),
        "breakers": all_metrics
    }


@router.get("/breakers/{breaker_name}")
async def get_circuit_breaker(breaker_name: str) -> Dict[str, Any]:
    """
    Get detailed information about a specific circuit breaker.
    
    Args:
        breaker_name: Name of the circuit breaker
        
    Returns:
        Detailed metrics for the circuit breaker
    """
    manager = get_circuit_breaker_manager()
    breaker = manager.get(breaker_name)
    
    if not breaker:
        raise HTTPException(status_code=404, detail=f"Circuit breaker '{breaker_name}' not found")
    
    return {
        "timestamp": datetime.now().isoformat(),
        "breaker": breaker.get_metrics()
    }


@router.post("/breakers/{breaker_name}/reset")
async def reset_circuit_breaker(breaker_name: str) -> Dict[str, Any]:
    """
    Manually reset a circuit breaker to closed state.
    
    Args:
        breaker_name: Name of the circuit breaker to reset
        
    Returns:
        Updated circuit breaker status
    """
    manager = get_circuit_breaker_manager()
    breaker = manager.get(breaker_name)
    
    if not breaker:
        raise HTTPException(status_code=404, detail=f"Circuit breaker '{breaker_name}' not found")
    
    previous_state = breaker.state
    breaker.reset()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "breaker_name": breaker_name,
        "previous_state": previous_state.value,
        "current_state": breaker.state.value,
        "message": f"Circuit breaker '{breaker_name}' reset to CLOSED state"
    }


@router.post("/breakers/reset-all")
async def reset_all_circuit_breakers() -> Dict[str, Any]:
    """
    Reset all circuit breakers to closed state.
    
    Returns:
        Summary of reset operation
    """
    manager = get_circuit_breaker_manager()
    summary_before = manager.get_summary()
    
    manager.reset_all()
    
    summary_after = manager.get_summary()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "message": "All circuit breakers reset to CLOSED state",
        "before": {
            "open_circuits": len(summary_before["open_circuits"]),
            "half_open_circuits": len(summary_before["half_open_circuits"])
        },
        "after": {
            "open_circuits": len(summary_after["open_circuits"]),
            "half_open_circuits": len(summary_after["half_open_circuits"])
        }
    }


@router.get("/alerts")
async def get_circuit_breaker_alerts(limit: int = Query(10, ge=1, le=100)) -> Dict[str, Any]:
    """
    Get recent circuit breaker alerts.
    
    Args:
        limit: Maximum number of alerts to return (1-100)
        
    Returns:
        List of recent alerts
    """
    try:
        monitor = await get_circuit_breaker_monitor()
        alerts = monitor.get_recent_alerts(limit)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total": len(alerts),
            "alerts": alerts
        }
    except Exception as e:
        # Monitor might not be initialized
        return {
            "timestamp": datetime.now().isoformat(),
            "total": 0,
            "alerts": [],
            "note": "Monitoring not active"
        }


@router.post("/monitoring/start")
async def start_monitoring(
    check_interval: float = Query(10.0, description="Seconds between checks"),
    alert_on_open: bool = Query(True, description="Alert when circuit opens"),
    alert_on_half_open: bool = Query(True, description="Alert when circuit goes to half-open"),
    alert_on_close: bool = Query(False, description="Alert when circuit closes")
) -> Dict[str, Any]:
    """
    Start circuit breaker monitoring.
    
    Args:
        check_interval: How often to check circuit breakers (seconds)
        alert_on_open: Whether to alert when circuits open
        alert_on_half_open: Whether to alert when circuits go to half-open
        alert_on_close: Whether to alert when circuits close
        
    Returns:
        Monitoring status
    """
    config = MonitoringConfig(
        check_interval=check_interval,
        alert_on_open=alert_on_open,
        alert_on_half_open=alert_on_half_open,
        alert_on_close=alert_on_close
    )
    
    from src.core.circuit_breaker_monitoring import start_monitoring
    await start_monitoring(config)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "status": "started",
        "config": {
            "check_interval": check_interval,
            "alert_on_open": alert_on_open,
            "alert_on_half_open": alert_on_half_open,
            "alert_on_close": alert_on_close
        }
    }


@router.post("/monitoring/stop")
async def stop_monitoring() -> Dict[str, Any]:
    """
    Stop circuit breaker monitoring.
    
    Returns:
        Monitoring status
    """
    from src.core.circuit_breaker_monitoring import stop_monitoring
    await stop_monitoring()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "status": "stopped"
    }


@router.get("/health")
async def get_system_health() -> Dict[str, Any]:
    """
    Get overall system health based on circuit breaker states.
    
    Returns:
        System health assessment
    """
    manager = get_circuit_breaker_manager()
    summary = manager.get_summary()
    health = _calculate_system_health(summary)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "health": health,
        "details": {
            "total_breakers": summary["total_breakers"],
            "healthy_breakers": len(summary["closed_circuits"]),
            "degraded_breakers": len(summary["half_open_circuits"]),
            "failed_breakers": len(summary["open_circuits"]),
            "overall_failure_rate": f"{summary['overall_failure_rate']:.1%}"
        },
        "recommendations": _get_health_recommendations(summary, health)
    }


def _calculate_system_health(summary: Dict[str, Any]) -> str:
    """Calculate overall system health status."""
    if not summary["total_breakers"]:
        return "unknown"
    
    open_ratio = len(summary["open_circuits"]) / summary["total_breakers"]
    half_open_ratio = len(summary["half_open_circuits"]) / summary["total_breakers"]
    failure_rate = summary["overall_failure_rate"]
    
    if open_ratio > 0.5 or failure_rate > 0.7:
        return "critical"
    elif open_ratio > 0.3 or failure_rate > 0.5:
        return "degraded"
    elif open_ratio > 0.1 or half_open_ratio > 0.3 or failure_rate > 0.3:
        return "warning"
    else:
        return "healthy"


def _get_health_recommendations(summary: Dict[str, Any], health: str) -> List[str]:
    """Get recommendations based on system health."""
    recommendations = []
    
    if health == "critical":
        recommendations.extend([
            "System is experiencing critical failures. Investigate root causes immediately.",
            "Consider enabling fallback mechanisms for affected services.",
            "Review recent deployments or configuration changes."
        ])
    elif health == "degraded":
        recommendations.extend([
            "Multiple services are experiencing issues. Monitor closely.",
            "Check external dependencies and network connectivity.",
            "Consider scaling resources if load is high."
        ])
    elif health == "warning":
        recommendations.extend([
            "Some services are showing signs of instability.",
            "Monitor error rates and response times.",
            "Review logs for the affected services."
        ])
    
    # Specific recommendations
    if summary["open_circuits"]:
        recommendations.append(
            f"Services with open circuits: {', '.join(summary['open_circuits'][:5])}"
        )
    
    if summary["overall_failure_rate"] > 0.3:
        recommendations.append(
            f"High overall failure rate ({summary['overall_failure_rate']:.1%}). "
            "Check for systemic issues."
        )
    
    return recommendations


# Include router in main API
def include_router(app):
    """Include circuit breaker routes in main FastAPI app."""
    app.include_router(router)


class CircuitBreakerAPI:
    """Circuit Breaker API management class."""
    
    def __init__(self):
        self.router = router
        self.manager = get_circuit_breaker_manager()
        self.monitor = get_circuit_breaker_monitor()
    
    def get_router(self):
        """Get the FastAPI router for circuit breaker endpoints."""
        return self.router
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker system status."""
        return {
            "timestamp": datetime.now().isoformat(),
            "monitoring": get_monitoring_status(),
            "summary": self.manager.get_summary(),
            "health": _calculate_system_health(self.manager.get_summary())
        }