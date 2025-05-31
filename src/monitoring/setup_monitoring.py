#!/usr/bin/env python3
"""
Setup script for comprehensive monitoring stack.

This script:
1. Validates monitoring dependencies
2. Initializes the monitoring components
3. Sets up health checks for all services
4. Configures SLA objectives
5. Registers alert handlers
6. Starts the monitoring stack
"""

import os
import sys
import asyncio
import subprocess
from pathlib import Path
from typing import Dict, Any, List

# Add src to path to import monitoring modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from monitoring import (
    get_metrics_collector,
    get_health_checker,
    init_tracing,
    get_alert_manager,
    get_sla_tracker,
    register_alert_handler,
    log_alert_handler,
    slack_alert_handler,
    add_sla_objective,
)
from monitoring.sla import SLAObjective, SLAType
from monitoring.alerts import AlertRule, AlertSeverity


def check_dependencies() -> Dict[str, bool]:
    """Check if required monitoring dependencies are available."""
    dependencies = {
        "prometheus_client": False,
        "psutil": False,
        "opentelemetry": False,
        "fastapi": False,
        "docker": False,
        "docker-compose": False,
    }
    
    # Check Python packages
    try:
        import prometheus_client
        dependencies["prometheus_client"] = True
    except ImportError:
        pass
    
    try:
        import psutil
        dependencies["psutil"] = True
    except ImportError:
        pass
    
    try:
        import opentelemetry
        dependencies["opentelemetry"] = True
    except ImportError:
        pass
    
    try:
        import fastapi
        dependencies["fastapi"] = True
    except ImportError:
        pass
    
    # Check external tools
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
        dependencies["docker"] = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    try:
        subprocess.run(["docker-compose", "--version"], capture_output=True, check=True)
        dependencies["docker-compose"] = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Try docker compose (newer syntax)
        try:
            subprocess.run(["docker", "compose", "version"], capture_output=True, check=True)
            dependencies["docker-compose"] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    
    return dependencies


def install_missing_dependencies(missing: List[str]):
    """Install missing Python dependencies."""
    python_packages = {
        "prometheus_client": "prometheus-client",
        "psutil": "psutil",
        "opentelemetry": "opentelemetry-api opentelemetry-sdk opentelemetry-instrumentation-fastapi opentelemetry-exporter-jaeger opentelemetry-exporter-otlp",
        "fastapi": "fastapi uvicorn[standard]",
    }
    
    for package in missing:
        if package in python_packages:
            print(f"Installing {package}...")
            subprocess.run([
                sys.executable, "-m", "pip", "install", 
                python_packages[package]
            ], check=True)


def setup_custom_health_checks():
    """Set up custom health checks for application components."""
    checker = get_health_checker()
    
    # AI providers health check
    @checker.register_check("ai_providers", is_async=True)
    async def check_ai_providers():
        """Check if AI providers are accessible."""
        try:
            # Mock implementation - in real app, would check actual providers
            return {
                "status": "healthy",
                "providers": {
                    "anthropic": True,
                    "openai": True,
                    "google": True
                }
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }
    
    # MCP servers health check
    @checker.register_check("mcp_servers", is_async=True)
    async def check_mcp_servers():
        """Check if MCP servers are responsive."""
        try:
            # Mock implementation
            return {
                "status": "healthy",
                "servers": {
                    "desktop_commander": True,
                    "docker": True,
                    "kubernetes": True,
                    "security_scanner": True
                }
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }
    
    # Database connectivity check
    @checker.register_check("database", is_async=True)
    async def check_database():
        """Check database connectivity."""
        try:
            # Mock implementation
            return {
                "status": "healthy",
                "connection_pool": "active",
                "queries_per_second": 150
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }


def setup_custom_sla_objectives():
    """Set up custom SLA objectives."""
    # API Performance SLAs
    add_sla_objective(SLAObjective(
        name="api_response_time_p99",
        type=SLAType.LATENCY,
        target=99.0,  # 99% of requests under 2 seconds
        latency_percentile=0.99,
        latency_threshold_ms=2000,
        description="99th percentile API response time under 2 seconds"
    ))
    
    # Business SLAs
    add_sla_objective(SLAObjective(
        name="deployment_success_rate",
        type=SLAType.ERROR_RATE,
        target=98.0,
        description="Deployment success rate should be at least 98%"
    ))
    
    add_sla_objective(SLAObjective(
        name="circle_of_experts_availability",
        type=SLAType.AVAILABILITY,
        target=99.5,
        description="Circle of Experts service availability"
    ))
    
    # Cost SLA
    add_sla_objective(SLAObjective(
        name="ai_cost_efficiency",
        type=SLAType.CUSTOM,
        target=95.0,
        description="AI cost should stay within budget 95% of the time",
        custom_query="rate(ai_cost_dollars[1h]) * 24 < 100"  # Under $100/day
    ))


def setup_alert_handlers():
    """Set up alert notification handlers."""
    # Register logging handler (always enabled)
    register_alert_handler(log_alert_handler, is_async=False)
    
    # Register Slack handler if webhook is configured
    slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
    if slack_webhook:
        register_alert_handler(slack_alert_handler, is_async=True)
        print("✓ Slack alert handler configured")
    else:
        print("⚠ Slack webhook not configured (set SLACK_WEBHOOK_URL)")


def setup_tracing():
    """Initialize distributed tracing."""
    environment = os.getenv("ENVIRONMENT", "development")
    jaeger_endpoint = os.getenv("JAEGER_ENDPOINT", "localhost:6831")
    
    sample_rate = 1.0 if environment == "development" else 0.1
    
    init_tracing(
        service_name="claude-deployment-engine",
        environment=environment,
        sample_rate=sample_rate,
        exporter_type="jaeger",
        endpoint=jaeger_endpoint
    )
    
    print(f"✓ Tracing initialized (environment: {environment}, sample_rate: {sample_rate})")


def start_monitoring_stack():
    """Start the Docker monitoring stack."""
    monitoring_dir = Path(__file__).parent
    compose_file = monitoring_dir / "docker-compose.monitoring.yml"
    
    if not compose_file.exists():
        print("❌ Monitoring Docker Compose file not found")
        return False
    
    try:
        # Try docker compose first (newer syntax)
        try:
            subprocess.run([
                "docker", "compose", "-f", str(compose_file), "up", "-d"
            ], check=True, cwd=monitoring_dir)
        except subprocess.CalledProcessError:
            # Fallback to docker-compose
            subprocess.run([
                "docker-compose", "-f", str(compose_file), "up", "-d"
            ], check=True, cwd=monitoring_dir)
        
        print("✓ Monitoring stack started successfully")
        print("  • Prometheus: http://localhost:9090")
        print("  • Grafana: http://localhost:3000 (admin/admin123)")
        print("  • Jaeger: http://localhost:16686")
        print("  • AlertManager: http://localhost:9093")
        
        return True
    
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start monitoring stack: {e}")
        return False


def verify_monitoring_endpoints():
    """Verify that monitoring endpoints are accessible."""
    import time
    import requests
    
    endpoints = {
        "Prometheus": "http://localhost:9090/-/healthy",
        "Grafana": "http://localhost:3000/api/health",
        "Jaeger": "http://localhost:16686/",
        "AlertManager": "http://localhost:9093/-/healthy",
    }
    
    print("\nVerifying monitoring endpoints...")
    
    # Wait a bit for services to start
    time.sleep(10)
    
    for service, url in endpoints.items():
        try:
            response = requests.get(url, timeout=5)
            if response.status_code < 400:
                print(f"✓ {service} is accessible")
            else:
                print(f"⚠ {service} returned status {response.status_code}")
        except requests.exceptions.RequestException:
            print(f"❌ {service} is not accessible")


async def run_monitoring_validation():
    """Run a comprehensive monitoring validation."""
    print("\n🔍 Running monitoring validation...")
    
    # Test metrics collection
    collector = get_metrics_collector()
    collector.record_http_request("GET", "/test", 200, 0.1)
    print("✓ Metrics collection working")
    
    # Test health checks
    checker = get_health_checker()
    health_report = await checker.check_health_async()
    print(f"✓ Health checks working (status: {health_report.status.value})")
    
    # Test SLA tracking
    tracker = get_sla_tracker()
    sla_reports = await tracker.check_all_objectives()
    print(f"✓ SLA tracking working ({len(sla_reports)} objectives)")
    
    # Test alerting
    alert_manager = get_alert_manager()
    rules = alert_manager.get_prometheus_rules()
    print(f"✓ Alert system working ({len(rules)} rules)")


def main():
    """Main setup function."""
    print("🚀 Setting up Claude Deployment Engine monitoring...")
    
    # Check dependencies
    print("\n📋 Checking dependencies...")
    deps = check_dependencies()
    missing = [name for name, available in deps.items() if not available]
    
    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        
        python_missing = [dep for dep in missing if dep in ["prometheus_client", "psutil", "opentelemetry", "fastapi"]]
        if python_missing:
            try:
                install_missing_dependencies(python_missing)
                print("✓ Python dependencies installed")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install dependencies: {e}")
                return 1
        
        # Check for Docker
        if "docker" in missing:
            print("❌ Docker is required but not installed. Please install Docker Desktop.")
            return 1
    else:
        print("✓ All dependencies available")
    
    # Initialize monitoring components
    print("\n⚙️ Initializing monitoring components...")
    
    try:
        # Set up health checks
        setup_custom_health_checks()
        print("✓ Health checks configured")
        
        # Set up SLA objectives
        setup_custom_sla_objectives()
        print("✓ SLA objectives configured")
        
        # Set up alert handlers
        setup_alert_handlers()
        print("✓ Alert handlers configured")
        
        # Initialize tracing
        setup_tracing()
        
        # Start monitoring stack
        print("\n🐳 Starting monitoring stack...")
        if start_monitoring_stack():
            verify_monitoring_endpoints()
        
        # Run validation
        asyncio.run(run_monitoring_validation())
        
        print("\n🎉 Monitoring setup complete!")
        print("\nNext steps:")
        print("1. Configure your application to include monitoring endpoints")
        print("2. Import and use monitoring decorators in your code")
        print("3. Set up alert notification webhooks")
        print("4. Import Grafana dashboards from src/monitoring/dashboards/")
        
        return 0
        
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())