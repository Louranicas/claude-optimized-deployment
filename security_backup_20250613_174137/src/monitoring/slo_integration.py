"""
SLO Integration Module

Integrates SLI/SLO tracking with existing monitoring infrastructure,
including Prometheus, Grafana, alerting systems, and deployment pipelines.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import aiohttp
from prometheus_client import CollectorRegistry, Counter, Gauge, push_to_gateway

from ..core.logging_config import get_logger
from .sli_slo_tracking import (
    SLOTrackingSystem,
    SLOCompliance,
    ErrorBudgetManager,
    SLOAlertManager
)

logger = get_logger(__name__)


class PrometheusIntegration:
    """Integration with Prometheus for SLI/SLO metrics."""
    
    def __init__(self, prometheus_url: str, pushgateway_url: Optional[str] = None):
        self.prometheus_url = prometheus_url
        self.pushgateway_url = pushgateway_url
        self.registry = CollectorRegistry()
        self._setup_metrics()
    
    def _setup_metrics(self):
        """Setup Prometheus metrics for SLO tracking."""
        self.slo_compliance_gauge = Gauge(
            'slo_compliance_percentage',
            'SLO compliance percentage',
            ['slo_name', 'time_window', 'service'],
            registry=self.registry
        )
        
        self.error_budget_gauge = Gauge(
            'slo_error_budget_remaining_percentage',
            'Remaining error budget percentage',
            ['slo_name', 'time_window', 'service'],
            registry=self.registry
        )
        
        self.error_budget_consumed_counter = Counter(
            'slo_error_budget_consumed_total',
            'Total error budget consumed',
            ['slo_name', 'time_window', 'service'],
            registry=self.registry
        )
        
        self.slo_breach_counter = Counter(
            'slo_breaches_total',
            'Total SLO breaches',
            ['slo_name', 'time_window', 'service', 'severity'],
            registry=self.registry
        )
        
        self.deployment_freeze_gauge = Gauge(
            'slo_deployment_freeze_active',
            'Whether deployment freeze is active',
            ['slo_name', 'service'],
            registry=self.registry
        )
    
    async def update_metrics(self, compliance: SLOCompliance):
        """Update Prometheus metrics with SLO compliance data."""
        service = self._extract_service_from_slo(compliance.slo_name)
        
        # Update compliance percentage
        self.slo_compliance_gauge.labels(
            slo_name=compliance.slo_name,
            time_window=compliance.time_window.value,
            service=service
        ).set(compliance.compliance_percentage)
        
        # Update error budget
        self.error_budget_gauge.labels(
            slo_name=compliance.slo_name,
            time_window=compliance.time_window.value,
            service=service
        ).set(compliance.error_budget_remaining)
        
        # Update breach counter if SLO is breached
        if not compliance.is_compliant:
            self.slo_breach_counter.labels(
                slo_name=compliance.slo_name,
                time_window=compliance.time_window.value,
                service=service,
                severity="critical" if compliance.error_budget_remaining < 10 else "warning"
            ).inc()
        
        # Push metrics if pushgateway is configured
        if self.pushgateway_url:
            try:
                push_to_gateway(
                    self.pushgateway_url,
                    job='slo-tracker',
                    registry=self.registry
                )
            except Exception as e:
                logger.error(f"Failed to push metrics to gateway: {e}")
    
    def _extract_service_from_slo(self, slo_name: str) -> str:
        """Extract service name from SLO name."""
        # Simple extraction - could be more sophisticated
        if "api" in slo_name.lower():
            return "api"
        elif "database" in slo_name.lower():
            return "database"
        elif "mcp" in slo_name.lower():
            return "mcp"
        elif "experts" in slo_name.lower():
            return "experts"
        elif "auth" in slo_name.lower():
            return "auth"
        else:
            return "unknown"
    
    async def query_prometheus(self, query: str, time_range: Optional[tuple] = None) -> Dict[str, Any]:
        """Query Prometheus for metrics data."""
        params = {"query": query}
        
        if time_range:
            start_time, end_time = time_range
            params.update({
                "start": start_time.timestamp(),
                "end": end_time.timestamp(),
                "step": "60s"
            })
            endpoint = "query_range"
        else:
            endpoint = "query"
        
        url = f"{self.prometheus_url}/api/v1/{endpoint}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise Exception(f"Prometheus query failed: {response.status}")


class GrafanaIntegration:
    """Integration with Grafana for SLO dashboards."""
    
    def __init__(self, grafana_url: str, api_key: str):
        self.grafana_url = grafana_url
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    async def create_slo_dashboard(
        self,
        dashboard_config: Dict[str, Any],
        folder_name: str = "SLO Dashboards"
    ) -> str:
        """Create or update SLO dashboard in Grafana."""
        # First, ensure folder exists
        folder_id = await self._ensure_folder_exists(folder_name)
        
        # Update dashboard config with folder
        dashboard_config["dashboard"]["folderId"] = folder_id
        
        url = f"{self.grafana_url}/api/dashboards/db"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers=self.headers,
                json=dashboard_config
            ) as response:
                if response.status in [200, 201]:
                    result = await response.json()
                    return result.get("url", "")
                else:
                    raise Exception(f"Failed to create dashboard: {response.status}")
    
    async def _ensure_folder_exists(self, folder_name: str) -> int:
        """Ensure dashboard folder exists and return its ID."""
        # Search for existing folder
        search_url = f"{self.grafana_url}/api/search"
        params = {"query": folder_name, "type": "dash-folder"}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                search_url,
                headers=self.headers,
                params=params
            ) as response:
                if response.status == 200:
                    folders = await response.json()
                    if folders:
                        return folders[0]["id"]
        
        # Create folder if it doesn't exist
        create_url = f"{self.grafana_url}/api/folders"
        folder_data = {
            "title": folder_name,
            "uid": folder_name.lower().replace(" ", "-")
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                create_url,
                headers=self.headers,
                json=folder_data
            ) as response:
                if response.status in [200, 201]:
                    result = await response.json()
                    return result["id"]
                else:
                    raise Exception(f"Failed to create folder: {response.status}")
    
    async def create_slo_alerts(self, alert_rules: List[Dict[str, Any]]):
        """Create alert rules in Grafana."""
        for rule in alert_rules:
            await self._create_alert_rule(rule)
    
    async def _create_alert_rule(self, rule_config: Dict[str, Any]):
        """Create individual alert rule."""
        url = f"{self.grafana_url}/api/ruler/grafana/api/v1/rules"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers=self.headers,
                json=rule_config
            ) as response:
                if response.status not in [200, 201, 202]:
                    logger.error(f"Failed to create alert rule: {response.status}")


class SlackIntegration:
    """Integration with Slack for SLO notifications."""
    
    def __init__(self, webhook_urls: Dict[str, str]):
        self.webhook_urls = webhook_urls
    
    async def send_slo_alert(
        self,
        channel: str,
        compliance: SLOCompliance,
        alert_type: str,
        additional_context: Optional[Dict[str, Any]] = None
    ):
        """Send SLO alert to Slack."""
        webhook_url = self.webhook_urls.get(channel)
        if not webhook_url:
            logger.error(f"No webhook URL configured for channel: {channel}")
            return
        
        message = self._format_slack_message(compliance, alert_type, additional_context)
        
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=message) as response:
                if response.status != 200:
                    logger.error(f"Failed to send Slack alert: {response.status}")
    
    def _format_slack_message(
        self,
        compliance: SLOCompliance,
        alert_type: str,
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Format SLO alert as Slack message."""
        color = self._get_alert_color(alert_type, compliance)
        icon = self._get_alert_icon(alert_type)
        
        fields = [
            {
                "title": "SLO Name",
                "value": compliance.slo_name,
                "short": True
            },
            {
                "title": "Current Compliance",
                "value": f"{compliance.compliance_percentage:.2f}%",
                "short": True
            },
            {
                "title": "Target",
                "value": f"{compliance.target_value}%",
                "short": True
            },
            {
                "title": "Error Budget Remaining",
                "value": f"{compliance.error_budget_remaining:.2f}%",
                "short": True
            },
            {
                "title": "Time Window",
                "value": compliance.time_window.value,
                "short": True
            },
            {
                "title": "Trend",
                "value": compliance.trend,
                "short": True
            }
        ]
        
        if compliance.forecast_breach_time:
            fields.append({
                "title": "Forecast Breach Time",
                "value": compliance.forecast_breach_time.strftime("%Y-%m-%d %H:%M UTC"),
                "short": False
            })
        
        if additional_context:
            for key, value in additional_context.items():
                fields.append({
                    "title": key.replace("_", " ").title(),
                    "value": str(value),
                    "short": True
                })
        
        return {
            "attachments": [
                {
                    "color": color,
                    "pretext": f"{icon} SLO Alert: {alert_type.replace('_', ' ').title()}",
                    "fields": fields,
                    "ts": int(compliance.calculated_at.timestamp())
                }
            ]
        }
    
    def _get_alert_color(self, alert_type: str, compliance: SLOCompliance) -> str:
        """Get color for alert based on type and severity."""
        if "breach" in alert_type.lower() or not compliance.is_compliant:
            return "danger"
        elif "warning" in alert_type.lower() or compliance.error_budget_remaining < 20:
            return "warning"
        else:
            return "good"
    
    def _get_alert_icon(self, alert_type: str) -> str:
        """Get emoji icon for alert type."""
        icons = {
            "slo_breach": "🚨",
            "error_budget_low": "⚠️",
            "error_budget_exhausted": "🛑",
            "deployment_freeze": "❄️",
            "trend_degrading": "📉",
            "recovery": "✅"
        }
        return icons.get(alert_type, "📊")


class DeploymentIntegration:
    """Integration with deployment pipelines for error budget policies."""
    
    def __init__(self, ci_cd_webhook_url: Optional[str] = None):
        self.ci_cd_webhook_url = ci_cd_webhook_url
        self.deployment_freezes: Dict[str, datetime] = {}
    
    async def check_deployment_allowed(self, service: str) -> tuple[bool, Optional[str]]:
        """Check if deployment is allowed based on error budget policies."""
        # Check if there's an active freeze for this service
        freeze_time = self.deployment_freezes.get(service)
        if freeze_time and datetime.utcnow() < freeze_time:
            return False, f"Deployment frozen until {freeze_time}"
        
        # Additional checks could be added here
        return True, None
    
    async def activate_deployment_freeze(
        self,
        service: str,
        duration_hours: int = 24,
        reason: str = "SLO error budget exhausted"
    ):
        """Activate deployment freeze for a service."""
        freeze_until = datetime.utcnow() + timedelta(hours=duration_hours)
        self.deployment_freezes[service] = freeze_until
        
        logger.warning(f"Deployment freeze activated for {service} until {freeze_until}: {reason}")
        
        # Notify CI/CD system if webhook is configured
        if self.ci_cd_webhook_url:
            await self._notify_cicd_freeze(service, freeze_until, reason)
    
    async def _notify_cicd_freeze(self, service: str, freeze_until: datetime, reason: str):
        """Notify CI/CD system about deployment freeze."""
        payload = {
            "action": "freeze_deployments",
            "service": service,
            "freeze_until": freeze_until.isoformat(),
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.ci_cd_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status != 200:
                    logger.error(f"Failed to notify CI/CD about freeze: {response.status}")
    
    async def lift_deployment_freeze(self, service: str, reason: str = "Error budget recovered"):
        """Lift deployment freeze for a service."""
        if service in self.deployment_freezes:
            del self.deployment_freezes[service]
            logger.info(f"Deployment freeze lifted for {service}: {reason}")
            
            # Notify CI/CD system
            if self.ci_cd_webhook_url:
                await self._notify_cicd_unfreeze(service, reason)
    
    async def _notify_cicd_unfreeze(self, service: str, reason: str):
        """Notify CI/CD system about freeze lift."""
        payload = {
            "action": "unfreeze_deployments",
            "service": service,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.ci_cd_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status != 200:
                    logger.error(f"Failed to notify CI/CD about unfreeze: {response.status}")


class IncidentManagementIntegration:
    """Integration with incident management systems."""
    
    def __init__(self, pagerduty_integration_key: Optional[str] = None):
        self.pagerduty_integration_key = pagerduty_integration_key
    
    async def create_incident(
        self,
        compliance: SLOCompliance,
        severity: str = "high",
        description: Optional[str] = None
    ):
        """Create incident for SLO breach."""
        if not self.pagerduty_integration_key:
            logger.warning("No PagerDuty integration configured")
            return
        
        incident_description = description or self._generate_incident_description(compliance)
        
        payload = {
            "routing_key": self.pagerduty_integration_key,
            "event_action": "trigger",
            "dedup_key": f"slo-breach-{compliance.slo_name}",
            "payload": {
                "summary": f"SLO Breach: {compliance.slo_name}",
                "source": "slo-tracker",
                "severity": severity,
                "custom_details": {
                    "slo_name": compliance.slo_name,
                    "current_compliance": compliance.compliance_percentage,
                    "target": compliance.target_value,
                    "error_budget_remaining": compliance.error_budget_remaining,
                    "time_window": compliance.time_window.value,
                    "trend": compliance.trend
                }
            }
        }
        
        url = "https://events.pagerduty.com/v2/enqueue"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status != 202:
                    logger.error(f"Failed to create PagerDuty incident: {response.status}")
    
    def _generate_incident_description(self, compliance: SLOCompliance) -> str:
        """Generate incident description from compliance data."""
        return f"""
SLO Breach Detected

SLO: {compliance.slo_name}
Current Compliance: {compliance.compliance_percentage:.2f}%
Target: {compliance.target_value}%
Error Budget Remaining: {compliance.error_budget_remaining:.2f}%
Time Window: {compliance.time_window.value}
Trend: {compliance.trend}

Immediate investigation and remediation required.
        """.strip()


class SLOIntegrationOrchestrator:
    """Orchestrates all SLO integrations."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.prometheus = None
        self.grafana = None
        self.slack = None
        self.deployment = None
        self.incident_mgmt = None
        
        self._initialize_integrations()
    
    def _initialize_integrations(self):
        """Initialize all configured integrations."""
        # Prometheus integration
        if "prometheus" in self.config:
            self.prometheus = PrometheusIntegration(
                self.config["prometheus"]["url"],
                self.config["prometheus"].get("pushgateway_url")
            )
        
        # Grafana integration
        if "grafana" in self.config:
            self.grafana = GrafanaIntegration(
                self.config["grafana"]["url"],
                self.config["grafana"]["api_key"]
            )
        
        # Slack integration
        if "slack" in self.config:
            self.slack = SlackIntegration(
                self.config["slack"]["webhook_urls"]
            )
        
        # Deployment integration
        if "deployment" in self.config:
            self.deployment = DeploymentIntegration(
                self.config["deployment"].get("webhook_url")
            )
        
        # Incident management integration
        if "incident_management" in self.config:
            self.incident_mgmt = IncidentManagementIntegration(
                self.config["incident_management"].get("pagerduty_key")
            )
    
    async def process_slo_event(
        self,
        event_type: str,
        compliance: SLOCompliance,
        additional_data: Optional[Dict[str, Any]] = None
    ):
        """Process SLO events and trigger appropriate integrations."""
        try:
            # Update Prometheus metrics
            if self.prometheus:
                await self.prometheus.update_metrics(compliance)
            
            # Handle different event types
            if event_type == "slo_breach":
                await self._handle_slo_breach(compliance, additional_data)
            elif event_type == "error_budget_low":
                await self._handle_error_budget_low(compliance, additional_data)
            elif event_type == "deployment_freeze":
                await self._handle_deployment_freeze(compliance, additional_data)
            elif event_type == "trend_degrading":
                await self._handle_trend_degrading(compliance, additional_data)
            
        except Exception as e:
            logger.error(f"Error processing SLO event {event_type}: {e}")
    
    async def _handle_slo_breach(
        self,
        compliance: SLOCompliance,
        additional_data: Optional[Dict[str, Any]]
    ):
        """Handle SLO breach event."""
        # Send Slack alert
        if self.slack:
            await self.slack.send_slo_alert(
                "sre-alerts",
                compliance,
                "slo_breach",
                additional_data
            )
        
        # Create incident if critical
        if self.incident_mgmt and compliance.error_budget_remaining < 10:
            await self.incident_mgmt.create_incident(
                compliance,
                "critical",
                f"Critical SLO breach: {compliance.slo_name}"
            )
    
    async def _handle_error_budget_low(
        self,
        compliance: SLOCompliance,
        additional_data: Optional[Dict[str, Any]]
    ):
        """Handle low error budget event."""
        # Send warning alerts
        if self.slack:
            await self.slack.send_slo_alert(
                "sre-alerts",
                compliance,
                "error_budget_low",
                additional_data
            )
        
        # Activate deployment freeze if budget is critically low
        if self.deployment and compliance.error_budget_remaining < 10:
            service = self._extract_service_from_slo(compliance.slo_name)
            await self.deployment.activate_deployment_freeze(
                service,
                24,
                f"Error budget critically low: {compliance.error_budget_remaining:.1f}%"
            )
    
    async def _handle_deployment_freeze(
        self,
        compliance: SLOCompliance,
        additional_data: Optional[Dict[str, Any]]
    ):
        """Handle deployment freeze event."""
        # Notify deployment channel
        if self.slack:
            await self.slack.send_slo_alert(
                "deployments",
                compliance,
                "deployment_freeze",
                additional_data
            )
    
    async def _handle_trend_degrading(
        self,
        compliance: SLOCompliance,
        additional_data: Optional[Dict[str, Any]]
    ):
        """Handle degrading trend event."""
        # Send informational alert
        if self.slack:
            await self.slack.send_slo_alert(
                "sre-alerts",
                compliance,
                "trend_degrading",
                additional_data
            )
    
    def _extract_service_from_slo(self, slo_name: str) -> str:
        """Extract service name from SLO name."""
        # Simple extraction - could be more sophisticated
        if "api" in slo_name.lower():
            return "api"
        elif "database" in slo_name.lower():
            return "database"
        elif "mcp" in slo_name.lower():
            return "mcp"
        elif "experts" in slo_name.lower():
            return "experts"
        elif "auth" in slo_name.lower():
            return "auth"
        else:
            return "unknown"


# Example integration configuration
INTEGRATION_CONFIG_EXAMPLE = {
    "prometheus": {
        "url": "http://localhost:9090",
        "pushgateway_url": "http://localhost:9091"
    },
    "grafana": {
        "url": "http://localhost:3000",
        "api_key": "${GRAFANA_API_KEY}"
    },
    "slack": {
        "webhook_urls": {
            "sre-alerts": "${SLACK_SRE_WEBHOOK}",
            "deployments": "${SLACK_DEPLOYMENT_WEBHOOK}",
            "incidents": "${SLACK_INCIDENT_WEBHOOK}"
        }
    },
    "deployment": {
        "webhook_url": "${CI_CD_WEBHOOK_URL}"
    },
    "incident_management": {
        "pagerduty_key": "${PAGERDUTY_INTEGRATION_KEY}"
    }
}