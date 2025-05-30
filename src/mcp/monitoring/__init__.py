"""
Monitoring MCP servers for the CODE project.

Production-ready monitoring with enhanced security and reliability.
"""

from .prometheus_server import PrometheusMonitoringMCP

# Backward compatibility alias
PrometheusMonitoringMCPServer = PrometheusMonitoringMCP

__all__ = ["PrometheusMonitoringMCP", "PrometheusMonitoringMCPServer"]