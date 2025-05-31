"""
Integration between the monitoring module and MCP servers.

Provides seamless integration with:
- Prometheus MCP server for metrics querying
- Security Scanner MCP for vulnerability monitoring
- Slack MCP for alert notifications
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from .metrics import get_metrics_collector, MetricsCollector
from .health import get_health_checker, HealthCheckResult, HealthStatus
from .alerts import get_alert_manager, Alert, AlertSeverity
from ..mcp.manager import get_mcp_manager


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
                except:
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
                
                message = f"{emoji} *Alert: {alert.rule.name}*\n"
                message += f"Severity: {alert.rule.severity.value.upper()}\n"
                message += f"{alert.annotations.get('summary', 'No summary')}\n"
                
                if alert.annotations.get('description'):
                    message += f"\n{alert.annotations['description']}\n"
                
                if alert.value is not None:
                    message += f"\nCurrent value: {alert.value}\n"
                
                message += f"\nStarted: {alert.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                
                await self.mcp_manager.call_tool(
                    "slack-notifications.send_notification",
                    {
                        "message": message,
                        "notification_type": "alert"
                    }
                )
            except Exception:
                pass  # Silently fail
        
        self.alert_manager.register_handler(slack_alert_handler, is_async=True)
    
    async def query_prometheus_metrics(
        self,
        query: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        step: str = "60s"
    ) -> Optional[Dict[str, Any]]:
        """Query metrics from Prometheus via MCP."""
        if not self.mcp_manager:
            return None
        
        try:
            if start and end:
                # Range query
                result = await self.mcp_manager.call_tool(
                    "prometheus-monitoring.prometheus_query_range",
                    {
                        "query": query,
                        "start": int(start.timestamp()),
                        "end": int(end.timestamp()),
                        "step": step
                    }
                )
            else:
                # Instant query
                result = await self.mcp_manager.call_tool(
                    "prometheus-monitoring.prometheus_query",
                    {"query": query}
                )
            
            return result
        except Exception:
            return None
    
    async def run_security_scan(self, scan_type: str = "all") -> Dict[str, Any]:
        """Run security scans via MCP and record metrics."""
        if not self.mcp_manager:
            return {"error": "MCP manager not initialized"}
        
        results = {}
        scan_start = datetime.now()
        
        try:
            # Run different security scans based on type
            if scan_type in ["all", "npm"]:
                npm_result = await self.mcp_manager.call_tool(
                    "security-scanner.npm_audit",
                    {"package_json_path": "package.json"}
                )
                results["npm"] = npm_result
                
                # Record metrics
                vulnerabilities = len(npm_result.get("vulnerabilities", []))
                self.metrics_collector.business_operations_total.labels(
                    operation="security_scan_npm",
                    status="success" if vulnerabilities == 0 else "vulnerabilities_found"
                ).inc()
            
            if scan_type in ["all", "python"]:
                python_result = await self.mcp_manager.call_tool(
                    "security-scanner.python_safety_check",
                    {"requirements_file": "requirements.txt"}
                )
                results["python"] = python_result
                
                # Record metrics
                vulnerabilities = len(python_result.get("vulnerabilities", []))
                self.metrics_collector.business_operations_total.labels(
                    operation="security_scan_python",
                    status="success" if vulnerabilities == 0 else "vulnerabilities_found"
                ).inc()
            
            if scan_type in ["all", "docker"]:
                docker_result = await self.mcp_manager.call_tool(
                    "security-scanner.docker_security_scan",
                    {"image_name": "claude-deployment-engine:latest"}
                )
                results["docker"] = docker_result
                
                # Record metrics
                vulnerabilities = docker_result.get("total_vulnerabilities", 0)
                self.metrics_collector.business_operations_total.labels(
                    operation="security_scan_docker",
                    status="success" if vulnerabilities == 0 else "vulnerabilities_found"
                ).inc()
            
            # Calculate total scan duration
            scan_duration = (datetime.now() - scan_start).total_seconds()
            self.metrics_collector.business_operation_duration_seconds.labels(
                operation="security_scan_total"
            ).observe(scan_duration)
            
            # Check if we need to trigger security alerts
            total_vulnerabilities = sum(
                len(r.get("vulnerabilities", [])) if isinstance(r.get("vulnerabilities"), list) 
                else r.get("total_vulnerabilities", 0)
                for r in results.values()
            )
            
            if total_vulnerabilities > 0:
                # Create custom alert
                self.alert_manager.check_alert(
                    self.alert_manager.rules.get("SecurityVulnerabilities", 
                        self.alert_manager.rules["HighErrorRate"]),  # Fallback
                    value=total_vulnerabilities,
                    labels={"scan_type": scan_type}
                )
            
            return results
            
        except Exception as e:
            self.metrics_collector.record_error("security_scan_error", "mcp_integration")
            return {"error": str(e)}
    
    async def export_metrics_to_s3(self, bucket: str, key_prefix: str = "metrics/") -> bool:
        """Export current metrics to S3 for long-term storage."""
        if not self.mcp_manager:
            return False
        
        try:
            # Get current metrics
            metrics_data = self.metrics_collector.get_metrics()
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{key_prefix}metrics_{timestamp}.txt"
            
            # Upload to S3
            result = await self.mcp_manager.call_tool(
                "s3-storage.s3_upload_file",
                {
                    "file_content": metrics_data.decode('utf-8'),
                    "bucket": bucket,
                    "key": filename,
                    "content_type": "text/plain"
                }
            )
            
            if result and result.get("success"):
                self.metrics_collector.business_operations_total.labels(
                    operation="metrics_export",
                    status="success"
                ).inc()
                return True
            else:
                self.metrics_collector.record_error("metrics_export_failed", "mcp_integration")
                return False
                
        except Exception as e:
            self.metrics_collector.record_error("metrics_export_error", "mcp_integration")
            return False
    
    async def monitor_deployment(self, deployment_name: str, namespace: str = "default") -> Dict[str, Any]:
        """Monitor a Kubernetes deployment via MCP."""
        if not self.mcp_manager:
            return {"error": "MCP manager not initialized"}
        
        try:
            # Get deployment status
            deployment_result = await self.mcp_manager.call_tool(
                "kubernetes.kubectl_get",
                {
                    "resource_type": "deployment",
                    "name": deployment_name,
                    "namespace": namespace,
                    "output": "json"
                }
            )
            
            if deployment_result and "items" in deployment_result:
                deployment = deployment_result["items"][0] if deployment_result["items"] else {}
                
                # Extract metrics
                replicas = deployment.get("spec", {}).get("replicas", 0)
                ready_replicas = deployment.get("status", {}).get("readyReplicas", 0)
                
                # Update Prometheus-style metrics
                self.metrics_collector.business_operations_total.labels(
                    operation="deployment_check",
                    status="healthy" if ready_replicas == replicas else "degraded"
                ).inc()
                
                # Check if we need to alert
                if ready_replicas < replicas:
                    availability = (ready_replicas / replicas * 100) if replicas > 0 else 0
                    self.alert_manager.check_alert(
                        self.alert_manager.rules["AvailabilityLow"],
                        value=availability,
                        labels={
                            "deployment": deployment_name,
                            "namespace": namespace
                        }
                    )
                
                return {
                    "deployment": deployment_name,
                    "namespace": namespace,
                    "replicas": replicas,
                    "ready_replicas": ready_replicas,
                    "status": "healthy" if ready_replicas == replicas else "degraded"
                }
            else:
                return {"error": "Deployment not found"}
                
        except Exception as e:
            self.metrics_collector.record_error("deployment_monitoring_error", "mcp_integration")
            return {"error": str(e)}


# Global instance
_mcp_monitoring: Optional[MCPMonitoringIntegration] = None


async def get_mcp_monitoring() -> MCPMonitoringIntegration:
    """Get the global MCP monitoring integration instance."""
    global _mcp_monitoring
    if _mcp_monitoring is None:
        _mcp_monitoring = MCPMonitoringIntegration()
        await _mcp_monitoring.initialize()
    return _mcp_monitoring