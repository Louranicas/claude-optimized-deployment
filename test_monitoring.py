"""
Test the monitoring module implementation.
"""

import asyncio
import time
import random
from datetime import datetime, timedelta

from src.monitoring import (
    # Metrics
    get_metrics_collector,
    metrics_decorator,
    
    # Health
    get_health_checker,
    HealthStatus,
    HealthCheckResult,
    health_check,
    
    # Tracing
    init_tracing,
    get_tracer,
    trace_async,
    
    # Alerts
    get_alert_manager,
    AlertRule,
    AlertSeverity,
    log_alert_handler,
)


# Test health check
@health_check("test_service")
async def check_test_service():
    """Test service health check."""
    await asyncio.sleep(0.1)
    return HealthCheckResult(
        name="test_service",
        status=HealthStatus.HEALTHY,
        message="Test service is operational",
        details={"version": "1.0.0", "uptime": 3600}
    )


# Test traced function
@trace_async(name="test_operation")
@metrics_decorator(operation="test_operation")
async def test_traced_operation(duration: float = 1.0):
    """Test operation with tracing and metrics."""
    await asyncio.sleep(duration)
    return {"status": "completed", "duration": duration}


async def test_metrics():
    """Test metrics collection."""
    print("\n=== Testing Metrics Collection ===")
    
    collector = get_metrics_collector()
    
    # Record some HTTP requests
    for i in range(10):
        status = 200 if random.random() > 0.1 else 500
        duration = random.uniform(0.01, 0.5)
        
        collector.record_http_request(
            method="GET",
            endpoint="/api/test",
            status=status,
            duration=duration,
            request_size=random.randint(100, 1000),
            response_size=random.randint(1000, 10000)
        )
    
    # Record AI requests
    for model in ["gpt-4", "claude-3", "gemini-pro"]:
        collector.record_ai_request(
            model=model,
            provider="openai" if model == "gpt-4" else "anthropic",
            status="success",
            duration=random.uniform(1.0, 5.0),
            input_tokens=random.randint(100, 1000),
            output_tokens=random.randint(500, 2000),
            cost=random.uniform(0.01, 0.10)
        )
    
    # Get metrics output
    metrics_output = collector.get_metrics().decode('utf-8')
    print(f"Generated {len(metrics_output.splitlines())} metric lines")
    
    # Show a sample
    sample_lines = metrics_output.splitlines()[:10]
    print("\nSample metrics:")
    for line in sample_lines:
        if line and not line.startswith("#"):
            print(f"  {line}")


async def test_health_checks():
    """Test health check system."""
    print("\n=== Testing Health Checks ===")
    
    checker = get_health_checker()
    
    # Run health checks
    report = await checker.check_health_async()
    
    print(f"Overall status: {report.status.value}")
    print(f"Environment: {report.environment}")
    print(f"Uptime: {report.uptime_seconds:.1f} seconds")
    print(f"\nHealth checks ({len(report.checks)}):")
    
    for check in report.checks:
        print(f"  - {check.name}: {check.status.value}")
        print(f"    Message: {check.message}")
        print(f"    Duration: {check.duration_ms:.1f}ms")
        if check.details:
            print(f"    Details: {check.details}")
    
    # Test probes
    print(f"\nLiveness probe: {'PASS' if checker.liveness_probe() else 'FAIL'}")
    print(f"Readiness probe: {'PASS' if checker.readiness_probe() else 'FAIL'}")


async def test_tracing():
    """Test distributed tracing."""
    print("\n=== Testing Distributed Tracing ===")
    
    # Initialize tracing (console exporter for testing)
    init_tracing(
        service_name="monitoring-test",
        environment="test",
        sample_rate=1.0,
        exporter_type="console"
    )
    
    tracer = get_tracer()
    
    # Create a trace with nested spans
    with tracer.start_as_current_span("test_trace") as span:
        span.set_attribute("test.type", "integration")
        
        # Child span 1
        with tracer.start_as_current_span("database_query") as db_span:
            await asyncio.sleep(0.1)
            db_span.set_attribute("db.query", "SELECT * FROM users")
            db_span.set_attribute("db.rows_returned", 42)
        
        # Child span 2
        with tracer.start_as_current_span("api_call") as api_span:
            await asyncio.sleep(0.2)
            api_span.set_attribute("http.method", "POST")
            api_span.set_attribute("http.url", "https://api.example.com/data")
            api_span.set_attribute("http.status_code", 200)
        
        # Test traced function
        result = await test_traced_operation(0.1)
        span.set_attribute("result", str(result))
    
    print("Trace completed (check console output for spans)")


async def test_alerts():
    """Test alert system."""
    print("\n=== Testing Alert System ===")
    
    manager = get_alert_manager()
    
    # Register log handler
    manager.register_handler(log_alert_handler)
    
    # Add a custom alert rule
    custom_rule = AlertRule(
        name="TestAlert",
        expression="test_metric > 100",
        duration=timedelta(seconds=5),
        severity=AlertSeverity.MEDIUM,
        annotations={
            "summary": "Test alert is firing",
            "description": "This is a test alert for demonstration"
        }
    )
    manager.add_rule(custom_rule)
    
    print(f"Total alert rules: {len(manager.rules)}")
    print("\nAvailable alerts:")
    for name, rule in manager.rules.items():
        print(f"  - {name} ({rule.severity.value}): {rule.annotations.get('summary', 'No summary')}")
    
    # Simulate alert conditions
    print("\nSimulating alert conditions...")
    
    # Check high CPU alert
    manager.check_alert(
        manager.rules["HighCPUUsage"],
        value=95.0,
        labels={"host": "test-server"}
    )
    
    # Check custom alert multiple times to trigger
    for i in range(3):
        manager.check_alert(
            custom_rule,
            value=150.0,
            labels={"iteration": str(i)}
        )
        await asyncio.sleep(2)
    
    # Show active alerts
    active_alerts = manager.get_active_alerts()
    print(f"\nActive alerts: {len(active_alerts)}")
    for alert in active_alerts:
        print(f"  - {alert.rule.name} ({alert.state.value})")
        print(f"    Severity: {alert.rule.severity.value}")
        print(f"    Started: {alert.started_at}")
        print(f"    Value: {alert.value}")
    
    # Resolve an alert
    manager.resolve_alert("TestAlert", labels={"iteration": "1"})
    print("\nResolved test alert")


async def test_business_metrics():
    """Test business operation metrics."""
    print("\n=== Testing Business Metrics ===")
    
    collector = get_metrics_collector()
    
    # Simulate business operations
    operations = ["user_signup", "payment_process", "report_generation", "data_export"]
    
    for op in operations:
        with collector.time_operation(op):
            # Simulate operation time
            await asyncio.sleep(random.uniform(0.1, 0.5))
            
            # Randomly fail some operations
            if random.random() < 0.1:
                raise Exception(f"Simulated {op} failure")
    
    # Update business metrics
    collector.set_active_users(random.randint(100, 500))
    collector.set_queue_size("email_queue", random.randint(0, 100))
    collector.set_queue_size("notification_queue", random.randint(0, 50))
    
    # Update SLA metrics
    collector.update_sla_compliance("api", 99.95)
    collector.update_availability("web", 99.99)
    collector.update_availability("api", 99.97)
    
    print("Business metrics recorded successfully")


async def main():
    """Run all monitoring tests."""
    print("Starting Monitoring Module Tests")
    print("=" * 50)
    
    try:
        await test_metrics()
        await test_health_checks()
        await test_tracing()
        await test_alerts()
        await test_business_metrics()
        
        print("\n" + "=" * 50)
        print("All monitoring tests completed successfully!")
        
    except Exception as e:
        print(f"\nError during testing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main()