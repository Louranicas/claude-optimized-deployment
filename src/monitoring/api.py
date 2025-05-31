"""
API endpoints for monitoring, health checks, and metrics.

Provides FastAPI routes for:
- Health check endpoints (liveness/readiness)
- Prometheus metrics endpoint
- SLA reporting endpoints
- Alert management endpoints
"""

from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from .health import get_health_checker, HealthStatus
from .metrics import get_metrics_collector, CONTENT_TYPE_LATEST
from .sla import get_sla_tracker, SLAObjective, SLAType
from .alerts import get_alert_manager, AlertSeverity


# Create monitoring router
monitoring_router = APIRouter(prefix="/monitoring", tags=["monitoring"])


@monitoring_router.get("/health", response_model=Dict[str, Any])
async def health_check(detailed: bool = Query(False, description="Include detailed check results")):
    """
    Comprehensive health check endpoint.
    
    Returns overall health status and optionally detailed check results.
    """
    checker = get_health_checker()
    report = await checker.check_health_async()
    
    if detailed:
        return report.to_dict()
    else:
        return {
            "status": report.status.value,
            "timestamp": report.timestamp.isoformat(),
            "uptime_seconds": report.uptime_seconds
        }


@monitoring_router.get("/health/live", response_model=Dict[str, str])
async def liveness_probe():
    """
    Kubernetes liveness probe endpoint.
    
    Returns 200 if the service is alive, 503 if it should be restarted.
    """
    checker = get_health_checker()
    is_alive = checker.liveness_probe()
    
    if is_alive:
        return {"status": "alive"}
    else:
        raise HTTPException(status_code=503, detail="Service is not alive")


@monitoring_router.get("/health/ready", response_model=Dict[str, str])
async def readiness_probe():
    """
    Kubernetes readiness probe endpoint.
    
    Returns 200 if the service is ready to accept traffic, 503 if not.
    """
    checker = get_health_checker()
    is_ready = checker.readiness_probe()
    
    if is_ready:
        return {"status": "ready"}
    else:
        raise HTTPException(status_code=503, detail="Service is not ready")


@monitoring_router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """
    Prometheus metrics endpoint.
    
    Exposes all application metrics in Prometheus format.
    """
    collector = get_metrics_collector()
    metrics_data = collector.get_metrics()
    
    return Response(
        content=metrics_data,
        media_type=CONTENT_TYPE_LATEST,
        headers={"Content-Type": CONTENT_TYPE_LATEST}
    )


@monitoring_router.get("/sla", response_model=Dict[str, Any])
async def sla_report(
    format: str = Query("json", description="Report format (json or markdown)"),
    objective: Optional[str] = Query(None, description="Specific SLA objective to check")
):
    """
    Get SLA compliance report.
    
    Returns current SLA compliance status for all or specific objectives.
    """
    tracker = get_sla_tracker()
    
    try:
        if objective:
            if objective not in tracker.objectives:
                raise HTTPException(status_code=404, detail=f"SLA objective '{objective}' not found")
            
            report = await tracker.check_objective(tracker.objectives[objective])
            if format == "json":
                return report.to_dict()
            else:
                return PlainTextResponse(
                    content=tracker.generate_report({objective: report}, format=format)
                )
        else:
            reports = await tracker.check_all_objectives()
            if format == "json":
                return {
                    "timestamp": datetime.now().isoformat(),
                    "objectives": {name: report.to_dict() for name, report in reports.items()}
                }
            else:
                return PlainTextResponse(
                    content=tracker.generate_report(reports, format=format)
                )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@monitoring_router.get("/sla/objectives", response_model=Dict[str, Any])
async def list_sla_objectives():
    """
    List all configured SLA objectives.
    """
    tracker = get_sla_tracker()
    
    objectives = {}
    for name, obj in tracker.objectives.items():
        objectives[name] = {
            "type": obj.type.value,
            "target": obj.target,
            "measurement_window_days": obj.measurement_window.days,
            "description": obj.description,
            "labels": obj.labels
        }
    
    return {"objectives": objectives}


@monitoring_router.post("/sla/objectives", response_model=Dict[str, str])
async def add_sla_objective(objective: Dict[str, Any]):
    """
    Add a new SLA objective.
    """
    try:
        sla_type = SLAType(objective.get("type", "custom"))
        
        new_objective = SLAObjective(
            name=objective["name"],
            type=sla_type,
            target=objective["target"],
            measurement_window=timedelta(days=objective.get("measurement_window_days", 30)),
            description=objective.get("description", ""),
            labels=objective.get("labels", {})
        )
        
        # Add type-specific fields
        if sla_type == SLAType.LATENCY:
            new_objective.latency_percentile = objective.get("latency_percentile", 0.95)
            new_objective.latency_threshold_ms = objective.get("latency_threshold_ms", 1000)
        elif sla_type == SLAType.CUSTOM:
            new_objective.custom_query = objective.get("custom_query")
        
        tracker = get_sla_tracker()
        tracker.add_objective(new_objective)
        
        return {"status": "success", "message": f"SLA objective '{new_objective.name}' added"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@monitoring_router.delete("/sla/objectives/{name}", response_model=Dict[str, str])
async def remove_sla_objective(name: str):
    """
    Remove an SLA objective.
    """
    tracker = get_sla_tracker()
    
    if name not in tracker.objectives:
        raise HTTPException(status_code=404, detail=f"SLA objective '{name}' not found")
    
    tracker.remove_objective(name)
    return {"status": "success", "message": f"SLA objective '{name}' removed"}


@monitoring_router.get("/sla/error-budget/{objective}", response_model=Dict[str, Any])
async def error_budget_status(objective: str):
    """
    Get error budget status for a specific SLA objective.
    """
    tracker = get_sla_tracker()
    
    if objective not in tracker.objectives:
        raise HTTPException(status_code=404, detail=f"SLA objective '{objective}' not found")
    
    report = await tracker.check_objective(tracker.objectives[objective])
    burn_rate = tracker.get_error_budget_burn_rate(objective)
    exhaustion_date = tracker.predict_budget_exhaustion(objective, burn_rate)
    
    return {
        "objective": objective,
        "error_budget_remaining": report.error_budget_remaining,
        "burn_rate": burn_rate,
        "exhaustion_prediction": exhaustion_date.isoformat() if exhaustion_date else None,
        "status": "critical" if report.error_budget_remaining < 10 else "warning" if report.error_budget_remaining < 25 else "healthy"
    }


@monitoring_router.get("/alerts", response_model=Dict[str, Any])
async def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    active_only: bool = Query(True, description="Show only active alerts")
):
    """
    List current alerts.
    """
    manager = get_alert_manager()
    
    severity_filter = AlertSeverity(severity) if severity else None
    alerts = manager.get_active_alerts(severity=severity_filter)
    
    alert_list = []
    for alert in alerts:
        alert_data = {
            "name": alert.rule.name,
            "state": alert.state.value,
            "severity": alert.rule.severity.value,
            "started_at": alert.started_at.isoformat(),
            "duration": str(alert.duration),
            "message": alert.annotations.get("summary", ""),
            "labels": alert.labels,
            "value": alert.value
        }
        
        if alert.fired_at:
            alert_data["fired_at"] = alert.fired_at.isoformat()
        if alert.resolved_at:
            alert_data["resolved_at"] = alert.resolved_at.isoformat()
        
        alert_list.append(alert_data)
    
    return {
        "total": len(alert_list),
        "alerts": alert_list
    }


@monitoring_router.get("/alerts/rules", response_model=Dict[str, Any])
async def list_alert_rules(enabled_only: bool = Query(False, description="Show only enabled rules")):
    """
    List configured alert rules.
    """
    manager = get_alert_manager()
    
    rules = []
    for name, rule in manager.rules.items():
        if enabled_only and not rule.enabled:
            continue
        
        rules.append({
            "name": name,
            "expression": rule.expression,
            "duration_seconds": rule.duration.total_seconds(),
            "severity": rule.severity.value,
            "enabled": rule.enabled,
            "labels": rule.labels,
            "annotations": rule.annotations
        })
    
    return {"total": len(rules), "rules": rules}


@monitoring_router.post("/alerts/rules/{name}/enable", response_model=Dict[str, str])
async def enable_alert_rule(name: str):
    """
    Enable an alert rule.
    """
    manager = get_alert_manager()
    
    if name not in manager.rules:
        raise HTTPException(status_code=404, detail=f"Alert rule '{name}' not found")
    
    manager.enable_rule(name)
    return {"status": "success", "message": f"Alert rule '{name}' enabled"}


@monitoring_router.post("/alerts/rules/{name}/disable", response_model=Dict[str, str])
async def disable_alert_rule(name: str):
    """
    Disable an alert rule.
    """
    manager = get_alert_manager()
    
    if name not in manager.rules:
        raise HTTPException(status_code=404, detail=f"Alert rule '{name}' not found")
    
    manager.disable_rule(name)
    return {"status": "success", "message": f"Alert rule '{name}' disabled"}


@monitoring_router.get("/alerts/prometheus-rules", response_class=PlainTextResponse)
async def export_prometheus_rules():
    """
    Export alert rules in Prometheus format.
    """
    import yaml
    
    manager = get_alert_manager()
    rules = manager.get_prometheus_rules()
    
    prometheus_config = {
        "groups": [{
            "name": "claude_deployment_engine",
            "interval": "30s",
            "rules": rules
        }]
    }
    
    return PlainTextResponse(
        content=yaml.dump(prometheus_config, default_flow_style=False),
        media_type="text/yaml"
    )


# Health check middleware for automatic metrics collection
async def health_check_middleware(request, call_next):
    """
    Middleware to collect health metrics for each request.
    """
    start_time = datetime.now()
    
    try:
        response = await call_next(request)
        
        # Record successful request
        duration = (datetime.now() - start_time).total_seconds()
        collector = get_metrics_collector()
        collector.record_http_request(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code,
            duration=duration
        )
        
        return response
    except Exception as e:
        # Record failed request
        duration = (datetime.now() - start_time).total_seconds()
        collector = get_metrics_collector()
        collector.record_http_request(
            method=request.method,
            endpoint=request.url.path,
            status=500,
            duration=duration
        )
        collector.record_error(
            error_type=type(e).__name__,
            component="api"
        )
        raise