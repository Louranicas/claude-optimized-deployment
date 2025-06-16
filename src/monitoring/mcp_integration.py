"""
Integration between the monitoring module and MCP servers.

Provides seamless integration with:
- Prometheus MCP server for metrics querying
- Security Scanner MCP for vulnerability monitoring
- Slack MCP for alert notifications
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

from .metrics import get_metrics_collector, MetricsCollector
from .health import get_health_checker, HealthCheckResult, HealthStatus
from .alerts import get_alert_manager, Alert, AlertSeverity
from ..mcp.manager import get_mcp_manager

from src.core.error_handler import (
    handle_errors, async_handle_errors, log_error,
    ServiceUnavailableError, ExternalServiceError, ConfigurationError
)

__all__ = [
    "MCPMonitoringIntegration"
]



class MCPMonitoringIntegration:
    """Integrates monitoring with MCP servers."""
    
    def __init__(self):
        self.metrics_collector = get_metrics_collector()
        self.health_checker = get_health_checker()
        self.alert_manager = get_alert_manager()
        self.mcp_manager = None
        
        # Register MCP-specific health checks
        self._register_mcp_health_checks()
        
        # Register alert handlers
        self._register_alert_handlers()
    
    async def initialize(self):
        """Initialize MCP manager."""
        self.mcp_manager = await get_mcp_manager()
        await self.mcp_manager.initialize()
    
    def _register_mcp_health_checks(self):
        """Register health checks for MCP servers."""
        # Check MCP server availability
        async def check_mcp_servers():
            if not self.mcp_manager:
                return HealthCheckResult(
                    name="mcp_servers",
                    status=HealthStatus.UNHEALTHY,
                    message="MCP manager not initialized"
                )
            
            available_servers = []
            unavailable_servers = []
            
            for server_name, server in self.mcp_manager.registry.servers.items():
                try:
                    # Try to get server info
                    info = await server.get_server_info()
                    if info:
                        available_servers.append(server_name)
                    else:
                        unavailable_servers.append(server_name)
                except Exception as e:
                    # Log the error but continue checking other servers
                    logger.warning(f"Failed to check MCP server {server_name}: {e}")
                    unavailable_servers.append(server_name)
            
            total = len(available_servers) + len(unavailable_servers)
            available = len(available_servers)
            
            if available == total:
                status = HealthStatus.HEALTHY
                message = f"All {total} MCP servers are available"
            elif available >= total * 0.8:
                status = HealthStatus.DEGRADED
                message = f"{available}/{total} MCP servers available"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"Only {available}/{total} MCP servers available"
            
            return HealthCheckResult(
                name="mcp_servers",
                status=status,
                message=message,
                details={
                    "available": available_servers,
                    "unavailable": unavailable_servers,
                    "total": total
                }
            )
        
        # Check Prometheus connectivity
        async def check_prometheus():
            if not self.mcp_manager:
                return HealthCheckResult(
                    name="prometheus",
                    status=HealthStatus.UNHEALTHY,
                    message="MCP manager not initialized"
                )
            
            try:
                # Query Prometheus for a simple metric
                result = await self.mcp_manager.call_tool(
                    "prometheus-monitoring.prometheus_query",
                    {"query": "up"}
                )
                
                if result and "data" in result:
                    return HealthCheckResult(
                        name="prometheus",
                        status=HealthStatus.HEALTHY,
                        message="Prometheus is accessible",
                        details={"targets_up": len(result.get("data", {}).get("result", []))}
                    )
                else:
                    return HealthCheckResult(
                        name="prometheus",
                        status=HealthStatus.DEGRADED,
                        message="Prometheus returned no data"
                    )
            except Exception as e:
                return HealthCheckResult(
                    name="prometheus",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Prometheus check failed: {str(e)}"
                )
        
        # Register the health checks
        self.health_checker.register_check("mcp_servers", check_mcp_servers, is_async=True)
        self.health_checker.register_check("prometheus", check_prometheus, is_async=True)
    
    def _register_alert_handlers(self):
        """Register alert handlers for MCP integration."""
        # Slack notification handler
        async def slack_alert_handler(alert: Alert):
            if not self.mcp_manager or alert.state.value != "firing":
                return
            
            try:
                severity_emoji = {
                    AlertSeverity.CRITICAL: "🚨",
                    AlertSeverity.HIGH: "⚠️",
                    AlertSeverity.MEDIUM: "⚡",
                    AlertSeverity.LOW: "ℹ️",
                    AlertSeverity.INFO: "📌"
                }
                
                emoji = severity_emoji.get(alert.rule.severity, "❗")
                
                message = f"{emoji} *Alert: {alert.rule.name}*
"
                message += f"Severity: {alert.rule.severity.value.upper()}
"
                message += f"{alert.annotations.get('summary', 'No summary')}
"
                
                if alert.annotations.get('description'):
                    message += f"\n{alert.annotations['description']}\n"\n\n                if alert.value is not None:\n                    message += f"\nCurrent value: {alert.value}\n"\n\n                message += f"\nStarted: {alert.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"\n\n                await self.mcp_manager.call_tool(\n                    "slack-notifications.send_notification",\n                    {\n                        "message": message,\n                        "notification_type": "alert"\n                    }\n                )\n            except Exception:\n                pass  # Silently fail\n\n        self.alert_manager.register_handler(slack_alert_handler, is_async=True)\n\n    async def query_prometheus_metrics(\n        self,\n        query: str,\n        start: Optional[datetime] = None,\n        end: Optional[datetime] = None,\n        step: str = "60s"\n    ) -> Optional[Dict[str, Any]]:\n        """Query metrics from Prometheus via MCP."""\n        if not self.mcp_manager:\n            return None\n\n        try:\n            if start and end:\n                # Range query\n                result = await self.mcp_manager.call_tool(\n                    "prometheus-monitoring.prometheus_query_range",\n                    {\n                        "query": query,\n                        "start": int(start.timestamp()),\n                        "end": int(end.timestamp()),\n                        "step": step\n                    }\n                )\n            else:\n                # Instant query\n                result = await self.mcp_manager.call_tool(\n                    "prometheus-monitoring.prometheus_query",\n                    {"query": query}\n                )\n\n            return result\n        except Exception:\n            return None\n\n    async def run_security_scan(self, scan_type: str = "all") -> Dict[str, Any]:\n        """Run security scans via MCP and record metrics."""\n        if not self.mcp_manager:\n            return {"error": "MCP manager not initialized"}\n\n        results = {}\n        scan_start = datetime.now()\n\n        try:\n            # Run different security scans based on type\n            if scan_type in ["all", "npm"]:\n                npm_result = await self.mcp_manager.call_tool(\n                    "security-scanner.npm_audit",\n                    {"package_json_path": "package.json"}\n                )\n                results["npm"] = npm_result\n\n                # Record metrics\n                vulnerabilities = len(npm_result.get("vulnerabilities", []))\n                self.metrics_collector.business_operations_total.labels(\n                    operation="security_scan_npm",\n                    status="success" if vulnerabilities == 0 else "vulnerabilities_found"\n                ).inc()\n\n            if scan_type in ["all", "python"]:\n                python_result = await self.mcp_manager.call_tool(\n                    "security-scanner.python_safety_check",\n                    {"requirements_file": "requirements.txt"}\n                )\n                results["python"] = python_result\n\n                # Record metrics\n                vulnerabilities = len(python_result.get("vulnerabilities", []))\n                self.metrics_collector.business_operations_total.labels(\n                    operation="security_scan_python",\n                    status="success" if vulnerabilities == 0 else "vulnerabilities_found"\n                ).inc()\n\n            if scan_type in ["all", "docker"]:\n                docker_result = await self.mcp_manager.call_tool(\n                    "security-scanner.docker_security_scan",\n                    {"image_name": "claude-deployment-engine:latest"}\n                )\n                results["docker"] = docker_result\n\n                # Record metrics\n                vulnerabilities = docker_result.get("total_vulnerabilities", 0)\n                self.metrics_collector.business_operations_total.labels(\n                    operation="security_scan_docker",\n                    status="success" if vulnerabilities == 0 else "vulnerabilities_found"\n                ).inc()\n\n            # Calculate total scan duration\n            scan_duration = (datetime.now() - scan_start).total_seconds()\n            self.metrics_collector.business_operation_duration_seconds.labels(\n                operation="security_scan_total"\n            ).observe(scan_duration)\n\n            # Check if we need to trigger security alerts\n            total_vulnerabilities = sum(\n                len(r.get("vulnerabilities", [])) if isinstance(r.get("vulnerabilities"), list)\n                else r.get("total_vulnerabilities", 0)\n                for r in results.values()\n            )\n\n            if total_vulnerabilities > 0:\n                # Create custom alert\n                self.alert_manager.check_alert(\n                    self.alert_manager.rules.get("SecurityVulnerabilities",\n                        self.alert_manager.rules["HighErrorRate"]),  # Fallback\n                    value=total_vulnerabilities,\n                    labels={"scan_type": scan_type}\n                )\n\n            return results\n\n        except Exception as e:\n            self.metrics_collector.record_error("security_scan_error", "mcp_integration")\n            return {"error": str(e)}\n\n    async def export_metrics_to_s3(self, bucket: str, key_prefix: str = "metrics/") -> bool:\n        """Export current metrics to S3 for long-term storage."""\n        if not self.mcp_manager:\n            return False\n\n        try:\n            # Get current metrics\n            metrics_data = self.metrics_collector.get_metrics()\n\n            # Generate filename with timestamp\n            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")\n            filename = f"{key_prefix}metrics_{timestamp}.txt"\n\n            # Upload to S3\n            result = await self.mcp_manager.call_tool(\n                "s3-storage.s3_upload_file",\n                {\n                    "file_content": metrics_data.decode('utf-8'),\n                    "bucket": bucket,\n                    "key": filename,\n                    "content_type": "text/plain"\n                }\n            )\n\n            if result and result.get("success"):\n                self.metrics_collector.business_operations_total.labels(\n                    operation="metrics_export",\n                    status="success"\n                ).inc()\n                return True\n            else:\n                self.metrics_collector.record_error("metrics_export_failed", "mcp_integration")\n                return False\n\n        except Exception as e:\n            self.metrics_collector.record_error("metrics_export_error", "mcp_integration")\n            return False\n\n    async def monitor_deployment(self, deployment_name: str, namespace: str = "default") -> Dict[str, Any]:\n        """Monitor a Kubernetes deployment via MCP."""\n        if not self.mcp_manager:\n            return {"error": "MCP manager not initialized"}\n\n        try:\n            # Get deployment status\n            deployment_result = await self.mcp_manager.call_tool(\n                "kubernetes.kubectl_get",\n                {\n                    "resource_type": "deployment",\n                    "name": deployment_name,\n                    "namespace": namespace,\n                    "output": "json"\n                }\n            )\n\n            if deployment_result and "items" in deployment_result:\n                deployment = deployment_result["items"][0] if deployment_result["items"] else {}\n\n                # Extract metrics\n                replicas = deployment.get("spec", {}).get("replicas", 0)\n                ready_replicas = deployment.get("status", {}).get("readyReplicas", 0)\n\n                # Update Prometheus-style metrics\n                self.metrics_collector.business_operations_total.labels(\n                    operation="deployment_check",\n                    status="healthy" if ready_replicas == replicas else "degraded"\n                ).inc()\n\n                # Check if we need to alert\n                if ready_replicas < replicas:\n                    availability = (ready_replicas / replicas * 100) if replicas > 0 else 0\n                    self.alert_manager.check_alert(\n                        self.alert_manager.rules["AvailabilityLow"],\n                        value=availability,\n                        labels={\n                            "deployment": deployment_name,\n                            "namespace": namespace\n                        }\n                    )\n\n                return {\n                    "deployment": deployment_name,\n                    "namespace": namespace,\n                    "replicas": replicas,\n                    "ready_replicas": ready_replicas,\n                    "status": "healthy" if ready_replicas == replicas else "degraded"\n                }\n            else:\n                return {"error": "Deployment not found"}\n\n        except Exception as e:\n            self.metrics_collector.record_error("deployment_monitoring_error", "mcp_integration")\n            return {"error": str(e)}\n\n\n# Global instance\n_mcp_monitoring: Optional[MCPMonitoringIntegration] = None\n\n\nasync def get_mcp_monitoring() -> MCPMonitoringIntegration:\n    """Get the global MCP monitoring integration instance."""\n    global _mcp_monitoring\n    if _mcp_monitoring is None:\n        _mcp_monitoring = MCPMonitoringIntegration()\n        await _mcp_monitoring.initialize()\n    return _mcp_monitoring