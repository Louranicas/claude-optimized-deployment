#!/usr/bin/env python3
"""
Comprehensive OpenTelemetry Tracing Example

This example demonstrates all the advanced tracing features:
- Advanced sampling strategies
- Business context tracking
- Performance monitoring with SLI/SLO
- Cross-service correlation
- Multi-exporter setup
- Trace-based alerting
"""

import asyncio
import time
import logging
from typing import Dict, Any

from fastapi import FastAPI, HTTPException
from sqlalchemy import create_engine
import redis

# Import our comprehensive tracing system
from src.monitoring.tracing import (
    init_comprehensive_tracing,
    trace_performance,
    trace_with_correlation,
    BusinessMetrics,
    PerformanceMetrics,
    get_correlation_id,
    create_correlation_id,
    get_current_trace_info,
    get_trace_context_headers,
)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Example FastAPI application
app = FastAPI(title="Tracing Example API")

# Example database and cache connections
engine = create_engine("sqlite:///example.db")
redis_client = redis.Redis(host='localhost', port=6379, db=0)


@app.on_event("startup")
async def startup_event():
    """Initialize comprehensive tracing on startup."""
    tracing_manager = init_comprehensive_tracing(
        app=app,
        engine=engine
    )
    
    logger.info("Tracing initialized with features:")
    logger.info("- Advanced sampling with business rules")
    logger.info("- Multi-exporter (Jaeger + Zipkin + OTLP)")
    logger.info("- Auto-instrumentation for FastAPI, SQLAlchemy, Redis")
    logger.info("- Performance tracking with SLI/SLO")
    logger.info("- Business context and correlation")
    logger.info("- Trace-based alerting")


# Example 1: Basic API endpoint with performance tracking
@app.get("/api/users/{user_id}")
@trace_performance(
    name="get_user_api",
    sli_name="api_latency",
    slo_threshold=500.0,
    operation_type="api"
)
async def get_user(user_id: str):
    """Example API endpoint with performance tracking."""
    
    # Simulate some business logic
    business_metrics = BusinessMetrics(
        user_id=user_id,
        tenant_id="tenant_123",
        operation_type="api",
        customer_tier="premium",
        business_value=100.0
    )
    
    # Get tracing manager for enhanced spans
    from src.monitoring.tracing import _tracing_manager
    
    with _tracing_manager.enhanced_span(
        "fetch_user_data",
        business_metrics=business_metrics
    ):
        # Simulate database query
        await simulate_database_query(user_id)
        
        # Simulate cache lookup
        await simulate_cache_lookup(f"user:{user_id}")
        
        # Simulate external service call
        await simulate_external_service_call("user-service", user_id)
    
    return {
        "user_id": user_id,
        "name": f"User {user_id}",
        "tier": "premium",
        "trace_info": get_current_trace_info()
    }


# Example 2: Background task with correlation
@trace_with_correlation(
    name="process_user_data",
    business_context={"task_type": "background", "priority": "high"}
)
async def process_user_data(user_id: str, data: Dict[str, Any]):
    """Example background task with correlation tracking."""
    
    logger.info(f"Processing user data for {user_id} with correlation {get_correlation_id()}")
    
    # Simulate processing steps
    with _tracing_manager.create_performance_span(
        "validate_data",
        sli_name="data_validation_latency",
        slo_threshold=100.0
    ):
        await asyncio.sleep(0.05)  # Simulate validation
    
    with _tracing_manager.create_business_span(
        "enrich_data",
        user_id=user_id,
        operation_type="enrichment"
    ):
        await asyncio.sleep(0.1)  # Simulate enrichment
    
    # Simulate potential error
    if user_id == "error_user":
        raise HTTPException(status_code=500, detail="Simulated error")
    
    return {"status": "processed", "user_id": user_id}


# Example 3: Service-to-service call with context propagation
async def call_external_service(service_name: str, endpoint: str, data: Dict[str, Any]):
    """Example of calling external service with trace context."""
    import httpx
    
    # Get trace context headers for propagation
    headers = get_trace_context_headers()
    headers.update({
        "Content-Type": "application/json",
        "X-Service-Name": "claude-deployment-engine"
    })
    
    async with httpx.AsyncClient() as client:
        with _tracing_manager.enhanced_span(
            f"call_{service_name}",
            business_metrics=BusinessMetrics(
                operation_type="external",
                custom_attributes={"target_service": service_name}
            )
        ) as span:
            try:
                response = await client.post(
                    f"http://{service_name}/{endpoint}",
                    json=data,
                    headers=headers,
                    timeout=5.0
                )
                span.set_attribute("http.response.status_code", response.status_code)
                return response.json()
            except Exception as e:
                span.set_attribute("error", True)
                span.set_attribute("error.message", str(e))
                raise


# Simulation functions for demonstration
async def simulate_database_query(user_id: str):
    """Simulate a database query."""
    with _tracing_manager.create_performance_span(
        "db_query_user",
        sli_name="database_latency",
        slo_threshold=100.0
    ):
        # Simulate query time
        await asyncio.sleep(0.02)


async def simulate_cache_lookup(cache_key: str):
    """Simulate a cache lookup."""
    with _tracing_manager.enhanced_span(
        "cache_lookup",
        business_metrics=BusinessMetrics(
            operation_type="cache",
            custom_attributes={"cache_key": cache_key}
        )
    ):
        # Simulate cache access
        await asyncio.sleep(0.01)


async def simulate_external_service_call(service: str, user_id: str):
    """Simulate an external service call."""
    with _tracing_manager.create_performance_span(
        f"external_{service}",
        sli_name="external_service_latency",
        slo_threshold=2000.0
    ):
        # Simulate external call
        await asyncio.sleep(0.1)


# Example 4: Monitoring and analysis endpoints
@app.get("/monitoring/trace-health")
async def get_trace_health():
    """Get current trace health status."""
    return _tracing_manager.get_trace_health_status()


@app.get("/monitoring/performance-insights")
async def get_performance_insights():
    """Get performance insights from traces."""
    return _tracing_manager.get_performance_insights()


@app.get("/monitoring/slo-compliance")
async def get_slo_compliance():
    """Get SLO compliance status."""
    insights = _tracing_manager.get_performance_insights()
    return insights.get("slo_compliance", {})


@app.post("/monitoring/export-analysis")
async def export_trace_analysis():
    """Export trace analysis to file."""
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        _tracing_manager.export_traces_analysis(f.name)
        return {"file_path": f.name, "status": "exported"}


# Example 5: Custom business scenarios
@app.post("/business/premium-operation")
@trace_performance(
    name="premium_operation",
    operation_type="api",
    auto_correlation=True
)
async def premium_operation(data: Dict[str, Any]):
    """Example premium operation that's always sampled."""
    
    business_metrics = BusinessMetrics(
        user_id=data.get("user_id"),
        customer_tier="premium",
        business_value=1000.0,
        operation_type="premium",
        feature_flags={"premium_features": True}
    )
    
    with _tracing_manager.enhanced_span(
        "premium_processing",
        business_metrics=business_metrics
    ):
        # This will be always sampled due to premium tier
        await asyncio.sleep(0.2)
        
        # Simulate high-value operation
        with _tracing_manager.enhanced_span(
            "payment_processing",
            business_metrics=BusinessMetrics(
                operation_type="payment",
                business_value=data.get("amount", 0),
                custom_attributes={"payment_method": data.get("method", "card")}
            )
        ):
            await asyncio.sleep(0.1)
    
    return {
        "status": "processed",
        "correlation_id": get_correlation_id(),
        "trace_info": get_current_trace_info()
    }


# Example usage script
async def main():
    """Example usage of the tracing system."""
    
    print("🔍 OpenTelemetry Comprehensive Tracing Example")
    print("=" * 50)
    
    # Initialize tracing (normally done in app startup)
    tracing_manager = init_comprehensive_tracing()
    
    print("✅ Tracing initialized with advanced features")
    
    # Example 1: Basic traced operation
    print("\n📊 Example 1: Basic traced operation")
    with tracing_manager.enhanced_span("example_operation"):
        await asyncio.sleep(0.1)
        print("   Completed basic operation")
    
    # Example 2: Business context tracking
    print("\n💼 Example 2: Business context tracking")
    business_metrics = BusinessMetrics(
        user_id="user_123",
        tenant_id="tenant_456",
        customer_tier="enterprise",
        business_value=500.0
    )
    
    with tracing_manager.enhanced_span(
        "business_operation",
        business_metrics=business_metrics
    ):
        await asyncio.sleep(0.05)
        print("   Completed business operation with context")
    
    # Example 3: Performance tracking
    print("\n⚡ Example 3: Performance tracking with SLO")
    performance_metrics = PerformanceMetrics(
        sli_name="example_latency",
        slo_threshold=100.0,
        actual_value=0.0
    )
    
    with tracing_manager.enhanced_span(
        "performance_operation",
        performance_metrics=performance_metrics
    ):
        await asyncio.sleep(0.08)
        print("   Completed performance operation")
    
    # Example 4: Get insights
    print("\n📈 Example 4: Performance insights")
    insights = tracing_manager.get_performance_insights()
    print(f"   Performance summary: {len(insights.get('performance_summary', {}))} operations tracked")
    print(f"   SLO violations: {len(insights.get('slo_violations', []))}")
    print(f"   Active alerts: {len(insights.get('active_alerts', []))}")
    
    # Example 5: Health status
    print("\n🏥 Example 5: Trace health status")
    health = tracing_manager.get_trace_health_status()
    print(f"   Health status: {health['status']}")
    print(f"   Health score: {health['health_score']:.1f}")
    
    print("\n🎉 Example completed successfully!")
    print("\nTo see traces:")
    print("  - Jaeger UI: http://localhost:16686")
    print("  - Zipkin UI: http://localhost:9411")
    print("\nTo run the FastAPI example:")
    print("  uvicorn examples.tracing_example:app --reload")


if __name__ == "__main__":
    asyncio.run(main())