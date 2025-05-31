"""
Comprehensive monitoring example demonstrating all monitoring features.

This example shows how to:
- Set up metrics collection
- Implement health checks
- Use distributed tracing
- Configure alerts
- Integrate with FastAPI
"""

import asyncio
import random
import time
from pathlib import Path
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn

from src.monitoring import (
    # Metrics
    get_metrics_collector,
    metrics_decorator,
    record_request,
    record_error,
    record_business_metric,
    
    # Health
    get_health_checker,
    register_health_check,
    HealthStatus,
    HealthCheckResult,
    
    # Tracing
    init_tracing,
    get_tracer,
    trace_span,
    trace_async,
    set_span_attribute,
    add_span_event,
    
    # Alerts
    get_alert_manager,
    AlertRule,
    AlertSeverity,
    register_alert_handler,
    log_alert_handler,
)

# Initialize FastAPI app
app = FastAPI(title="Claude Deployment Engine", version="1.0.0")

# Initialize tracing
tracing_manager = init_tracing(
    service_name="claude-deployment-engine",
    environment="development",
    sample_rate=1.0,
    exporter_type="console",  # Use "jaeger" for real deployment
)

# Get instances
metrics_collector = get_metrics_collector()
health_checker = get_health_checker()
alert_manager = get_alert_manager()

# Register alert handlers
register_alert_handler(log_alert_handler)


# Custom health checks
async def check_database_health() -> HealthCheckResult:
    """Check database connectivity."""
    # Simulate database check
    await asyncio.sleep(0.1)
    
    if random.random() > 0.1:  # 90% success rate
        return HealthCheckResult(
            name="database",
            status=HealthStatus.HEALTHY,
            message="Database connection is healthy",
            details={"connections": 10, "pool_size": 20}
        )
    else:
        return HealthCheckResult(
            name="database",
            status=HealthStatus.UNHEALTHY,
            message="Database connection failed",
            details={"error": "Connection timeout"}
        )


async def check_mcp_servers() -> HealthCheckResult:
    """Check MCP server availability."""
    # Simulate MCP check
    await asyncio.sleep(0.05)
    
    available_servers = random.randint(8, 11)
    total_servers = 11
    
    if available_servers == total_servers:
        status = HealthStatus.HEALTHY
        message = f"All {total_servers} MCP servers are available"
    elif available_servers >= 8:
        status = HealthStatus.DEGRADED
        message = f"{available_servers}/{total_servers} MCP servers available"
    else:
        status = HealthStatus.UNHEALTHY
        message = f"Only {available_servers}/{total_servers} MCP servers available"
    
    return HealthCheckResult(
        name="mcp_servers",
        status=status,
        message=message,
        details={
            "available": available_servers,
            "total": total_servers,
            "servers": ["docker", "kubernetes", "prometheus", "security-scanner"]
        }
    )


# Register custom health checks
register_health_check("database", check_database_health, is_async=True)
register_health_check("mcp_servers", check_mcp_servers, is_async=True)


# Middleware for automatic request metrics
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Automatically collect metrics for all HTTP requests."""
    start_time = time.time()
    
    # Extract trace context from headers
    tracer = get_tracer()
    
    with tracer.start_as_current_span(
        f"HTTP {request.method} {request.url.path}",
        attributes={
            "http.method": request.method,
            "http.url": str(request.url),
            "http.scheme": request.url.scheme,
            "http.host": request.url.hostname,
            "http.target": request.url.path,
        }
    ) as span:
        try:
            response = await call_next(request)
            
            # Record metrics
            duration = time.time() - start_time
            record_request(
                method=request.method,
                endpoint=request.url.path,
                status=response.status_code,
                duration=duration,
            )
            
            # Set span attributes
            span.set_attribute("http.status_code", response.status_code)
            
            return response
            
        except Exception as e:
            # Record error
            duration = time.time() - start_time
            record_request(
                method=request.method,
                endpoint=request.url.path,
                status=500,
                duration=duration,
            )
            record_error("http_error", "middleware")
            
            # Record exception in span
            span.record_exception(e)
            span.set_attribute("http.status_code", 500)
            
            raise


# API Endpoints
@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Claude Deployment Engine API", "status": "operational"}


@app.get("/health")
async def health():
    """Basic health check endpoint."""
    report = await health_checker.check_health_async()
    
    status_code = 200 if report.status == HealthStatus.HEALTHY else 503
    
    return JSONResponse(
        content=report.to_dict(),
        status_code=status_code
    )


@app.get("/health/live")
async def liveness():
    """Kubernetes liveness probe endpoint."""
    if health_checker.liveness_probe():
        return {"status": "alive"}
    else:
        return JSONResponse(
            content={"status": "dead"},
            status_code=503
        )


@app.get("/health/ready")
async def readiness():
    """Kubernetes readiness probe endpoint."""
    if health_checker.readiness_probe():
        return {"status": "ready"}
    else:
        return JSONResponse(
            content={"status": "not ready"},
            status_code=503
        )


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    metrics_data = metrics_collector.get_metrics()
    
    return Response(
        content=metrics_data,
        media_type="text/plain; version=0.0.4"
    )


@app.get("/alerts")
async def get_alerts():
    """Get active alerts."""
    alerts = alert_manager.get_active_alerts()
    
    return {
        "total": len(alerts),
        "alerts": [
            {
                "name": alert.rule.name,
                "severity": alert.rule.severity.value,
                "state": alert.state.value,
                "started_at": alert.started_at.isoformat(),
                "duration": str(alert.duration),
                "labels": alert.labels,
                "annotations": alert.annotations,
                "value": alert.value
            }
            for alert in alerts
        ]
    }


# Example business operations with monitoring
@trace_async(name="deploy_application")
@metrics_decorator(operation="deployment")
async def deploy_application(app_name: str, environment: str):
    """Example deployment operation with full monitoring."""
    tracer = get_tracer()
    
    # Set span attributes
    set_span_attribute("app.name", app_name)
    set_span_attribute("deployment.environment", environment)
    
    # Add event
    add_span_event("deployment_started", {
        "app_name": app_name,
        "environment": environment
    })
    
    # Simulate deployment steps
    with tracer.start_as_current_span("validate_configuration") as span:
        await asyncio.sleep(0.1)
        span.set_attribute("validation.result", "passed")
    
    with tracer.start_as_current_span("build_container") as span:
        await asyncio.sleep(0.5)
        span.set_attribute("container.tag", f"{app_name}:latest")
    
    with tracer.start_as_current_span("deploy_to_kubernetes") as span:
        await asyncio.sleep(0.3)
        span.set_attribute("kubernetes.namespace", environment)
        span.set_attribute("kubernetes.replicas", 3)
    
    # Record business metric
    record_business_metric(
        operation="deployment",
        status="success",
        duration=0.9
    )
    
    # Update metrics
    metrics_collector.business_operations_total.labels(
        operation="deployment",
        status="success"
    ).inc()
    
    add_span_event("deployment_completed", {
        "duration_seconds": 0.9
    })
    
    return {
        "status": "deployed",
        "app_name": app_name,
        "environment": environment,
        "duration": 0.9
    }


@app.post("/deploy/{app_name}")
async def deploy_endpoint(app_name: str, environment: str = "staging"):
    """API endpoint for deployment."""
    result = await deploy_application(app_name, environment)
    return result


# Example of monitoring AI operations
@trace_async(name="ai_consultation")
async def consult_ai_experts(query: str, experts: list):
    """Example AI consultation with monitoring."""
    start_time = time.time()
    
    # Simulate AI requests
    for expert in experts:
        with get_tracer().start_as_current_span(f"query_{expert}") as span:
            span.set_attribute("ai.model", expert)
            span.set_attribute("ai.provider", "openai" if expert == "gpt-4" else "anthropic")
            
            # Simulate API call
            await asyncio.sleep(random.uniform(0.5, 2.0))
            
            # Record AI metrics
            duration = random.uniform(0.5, 2.0)
            tokens = random.randint(100, 1000)
            cost = tokens * 0.00001
            
            metrics_collector.record_ai_request(
                model=expert,
                provider="openai" if expert == "gpt-4" else "anthropic",
                status="success",
                duration=duration,
                input_tokens=tokens // 2,
                output_tokens=tokens // 2,
                cost=cost
            )
    
    total_duration = time.time() - start_time
    
    # Check for high latency alert
    if total_duration > 5.0:
        alert_manager.check_alert(
            alert_manager.rules["HighAILatency"],
            value=total_duration,
            labels={"query_type": "multi_expert"}
        )
    
    return {
        "query": query,
        "experts_consulted": experts,
        "duration": total_duration
    }


@app.post("/ai/consult")
async def ai_consult_endpoint(query: str, experts: list = ["gpt-4", "claude-3"]):
    """API endpoint for AI consultation."""
    result = await consult_ai_experts(query, experts)
    return result


# Simulate background monitoring tasks
async def monitor_resources():
    """Background task to monitor resources and check alerts."""
    while True:
        # Update resource metrics
        metrics_collector._update_resource_metrics()
        
        # Check CPU alert
        cpu_usage = psutil.cpu_percent(interval=0.1)
        alert_manager.check_alert(
            alert_manager.rules["HighCPUUsage"],
            value=cpu_usage
        )
        
        # Check memory alert
        memory = psutil.virtual_memory()
        alert_manager.check_alert(
            alert_manager.rules["HighMemoryUsage"],
            value=memory.percent
        )
        
        # Update SLA metrics (simulated)
        sla_compliance = random.uniform(99.0, 100.0)
        metrics_collector.update_sla_compliance("api", sla_compliance)
        
        # Check SLA alert
        if sla_compliance < 99.9:
            alert_manager.check_alert(
                alert_manager.rules["SLAViolation"],
                value=sla_compliance,
                labels={"sla_type": "api"}
            )
        
        await asyncio.sleep(10)  # Check every 10 seconds


@app.on_event("startup")
async def startup_event():
    """Start background monitoring tasks."""
    asyncio.create_task(monitor_resources())
    print("Monitoring system initialized")
    print("Access metrics at: http://localhost:8000/metrics")
    print("Access health at: http://localhost:8000/health")
    print("Access alerts at: http://localhost:8000/alerts")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    tracing_manager.shutdown()
    print("Monitoring system shutdown")


if __name__ == "__main__":
    # Example: Export Prometheus alert rules
    alert_rules_path = Path("prometheus_alerts.yml")
    alert_manager.export_prometheus_rules(alert_rules_path)
    print(f"Exported Prometheus alert rules to {alert_rules_path}")
    
    # Run the application
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )


import psutil