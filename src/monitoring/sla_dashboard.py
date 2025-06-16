"""
SLA dashboard data feeds and reporting.

Provides:
- Real-time SLA dashboard data
- Performance reports and analytics
- Executive summaries
- Grafana/dashboard integration
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import logging

from .sla import get_sla_tracker, SLATracker, SLAReport
from .sla_alerting import get_sla_alert_manager, SLAAlertManager
from .sla_history import get_sla_history_tracker, SLAHistoryTracker
from .prometheus_client import get_prometheus_client

__all__ = [
    "SLADashboardData",
    "SLAExecutiveSummary", 
    "SLADashboardAPI",
    "get_sla_dashboard_api"
]

logger = logging.getLogger(__name__)


@dataclass
class SLADashboardData:
    """Complete SLA dashboard data structure."""
    timestamp: str
    overall_health: str  # excellent, good, warning, critical
    overall_score: float
    
    # Current status
    objectives: Dict[str, Any]
    active_alerts: List[Dict[str, Any]]
    
    # Trends and history
    trends: Dict[str, Any]
    compliance_summary: Dict[str, Any]
    
    # System metrics
    system_status: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass 
class SLAExecutiveSummary:
    """Executive-level SLA summary."""
    period: str
    overall_availability: float
    total_objectives: int
    objectives_met: int
    critical_incidents: int
    
    # Key metrics
    worst_performing_sla: Optional[str]
    best_performing_sla: Optional[str]
    average_error_budget_remaining: float
    
    # Trends
    month_over_month_change: float
    predicted_next_month: str  # improving, stable, degrading
    
    # Risk assessment
    high_risk_objectives: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class SLADashboardAPI:
    """API for SLA dashboard data and reporting."""
    
    def __init__(self):
        self.sla_tracker = get_sla_tracker()
        self.alert_manager = get_sla_alert_manager()
        self.history_tracker = get_sla_history_tracker()
        self.prometheus_client = get_prometheus_client()
        
        # Cache for expensive operations
        self._cache: Dict[str, Any] = {}
        self._cache_expiry: Dict[str, datetime] = {}
        self._cache_duration = timedelta(minutes=5)
    
    async def get_dashboard_data(self, refresh_cache: bool = False) -> SLADashboardData:
        \"\"\"Get complete dashboard data.\"\"\"
        cache_key = \"dashboard_data\"
        
        if not refresh_cache and self._is_cached(cache_key):
            return self._cache[cache_key]
        
        # Get current SLA reports
        sla_reports = await self.sla_tracker.check_all_objectives()
        
        # Get active alerts
        active_alerts = self.alert_manager.get_active_alerts()
        
        # Get trends (cached for longer)
        trends = await self._get_trends_cached()
        
        # Get compliance summary
        compliance_summary = await self.history_tracker.get_compliance_summary(days=7)
        
        # Calculate overall health and score
        overall_health, overall_score = self._calculate_overall_health(sla_reports, active_alerts)
        
        # Get system status
        system_status = await self._get_system_status()
        
        # Format objectives data
        objectives_data = self._format_objectives_data(sla_reports)
        
        # Format alerts data
        alerts_data = [alert.to_dict() for alert in active_alerts]
        
        dashboard_data = SLADashboardData(
            timestamp=datetime.now().isoformat(),
            overall_health=overall_health,
            overall_score=overall_score,
            objectives=objectives_data,
            active_alerts=alerts_data,
            trends=trends,
            compliance_summary=compliance_summary,
            system_status=system_status
        )
        
        # Cache the result
        self._cache[cache_key] = dashboard_data
        self._cache_expiry[cache_key] = datetime.now() + self._cache_duration
        
        return dashboard_data
    
    async def get_executive_summary(self, period_days: int = 30) -> SLAExecutiveSummary:
        \"\"\"Get executive summary for specified period.\"\"\"
        end_time = datetime.now()
        start_time = end_time - timedelta(days=period_days)
        
        # Get historical data
        compliance_summary = await self.history_tracker.get_compliance_summary(days=period_days)
        trends = await self.history_tracker.get_trend_summary(days=period_days)
        
        # Get current SLA status
        current_reports = await self.sla_tracker.check_all_objectives()
        
        # Get alerts for the period
        alert_history = self.alert_manager.get_alert_history(hours=period_days * 24)
        
        # Calculate key metrics
        total_objectives = len(current_reports)
        objectives_met = sum(1 for report in current_reports.values() if report.is_compliant)
        
        # Calculate overall availability (weighted average)
        if compliance_summary:
            availabilities = [data['mean'] for data in compliance_summary.values()]
            overall_availability = sum(availabilities) / len(availabilities) if availabilities else 0
        else:
            overall_availability = 0
        
        # Find worst and best performing SLAs
        worst_sla = None
        best_sla = None
        if compliance_summary:
            sorted_slas = sorted(
                compliance_summary.items(),
                key=lambda x: x[1]['mean']
            )
            if sorted_slas:
                worst_sla = sorted_slas[0][0]
                best_sla = sorted_slas[-1][0]
        
        # Calculate average error budget
        error_budgets = [report.error_budget_remaining for report in current_reports.values()]
        avg_error_budget = sum(error_budgets) / len(error_budgets) if error_budgets else 0
        
        # Count critical incidents
        critical_incidents = sum(
            1 for alert in alert_history
            if alert.severity.value == \"critical\"
        )
        
        # Calculate month-over-month change (simplified)
        mom_change = 0.0
        if period_days >= 60:
            # Compare first half vs second half of period
            mid_point = start_time + timedelta(days=period_days // 2)
            
            early_summary = await self.history_tracker.get_compliance_summary(
                days=period_days // 2
            )
            
            if early_summary and compliance_summary:
                early_avg = sum(data['mean'] for data in early_summary.values()) / len(early_summary)
                current_avg = sum(data['mean'] for data in compliance_summary.values()) / len(compliance_summary)
                mom_change = current_avg - early_avg
        
        # Predict next month trend
        if trends:
            improving_count = sum(1 for trend in trends.values() if trend.direction.value == \"improving\")
            degrading_count = sum(1 for trend in trends.values() if trend.direction.value == \"degrading\")
            
            if improving_count > degrading_count:
                predicted_trend = \"improving\"
            elif degrading_count > improving_count:
                predicted_trend = \"degrading\"
            else:
                predicted_trend = \"stable\"
        else:
            predicted_trend = \"stable\"
        
        # Identify high-risk objectives
        high_risk_objectives = [
            name for name, trend in trends.items()
            if trend.risk_level in [\"high\", \"critical\"]
        ] if trends else []
        
        return SLAExecutiveSummary(
            period=f\"{period_days} days\",
            overall_availability=overall_availability,
            total_objectives=total_objectives,
            objectives_met=objectives_met,
            critical_incidents=critical_incidents,
            worst_performing_sla=worst_sla,
            best_performing_sla=best_sla,
            average_error_budget_remaining=avg_error_budget,
            month_over_month_change=mom_change,
            predicted_next_month=predicted_trend,
            high_risk_objectives=high_risk_objectives
        )
    
    async def get_sla_details(self, objective_name: str) -> Dict[str, Any]:
        \"\"\"Get detailed information for a specific SLA objective.\"\"\"
        if objective_name not in self.sla_tracker.objectives:
            raise ValueError(f\"Unknown SLA objective: {objective_name}\")
        
        # Get current report
        objective = self.sla_tracker.objectives[objective_name]
        current_report = await self.sla_tracker.check_objective(objective)
        
        # Get recent history
        history = await self.history_tracker.get_history(
            objective_name,
            start_time=datetime.now() - timedelta(days=7),
            limit=100
        )
        
        # Get trend analysis
        trend = await self.history_tracker.analyze_trend(objective_name, days=30)
        
        # Get active alerts for this objective
        active_alerts = [
            alert for alert in self.alert_manager.get_active_alerts()
            if alert.objective_name == objective_name
        ]
        
        # Calculate burn rate
        burn_rate = await self.sla_tracker.get_error_budget_burn_rate(objective_name)
        
        # Predict budget exhaustion
        exhaustion_prediction = await self.sla_tracker.predict_budget_exhaustion(
            objective_name, burn_rate
        )
        
        return {
            \"objective\": {
                \"name\": objective.name,
                \"type\": objective.type.value,
                \"target\": objective.target,
                \"description\": objective.description,
                \"measurement_window\": str(objective.measurement_window),
                \"labels\": objective.labels
            },
            \"current_status\": current_report.to_dict(),
            \"trend\": trend.to_dict() if trend else None,
            \"history\": [point.to_dict() for point in history[-50:]],  # Last 50 points
            \"active_alerts\": [alert.to_dict() for alert in active_alerts],
            \"error_budget\": {
                \"remaining_percent\": current_report.error_budget_remaining,
                \"burn_rate\": burn_rate,
                \"exhaustion_prediction\": exhaustion_prediction.isoformat() if exhaustion_prediction else None
            }
        }
    
    async def get_grafana_metrics(self) -> Dict[str, Any]:
        \"\"\"Get metrics formatted for Grafana dashboards.\"\"\"
        sla_reports = await self.sla_tracker.check_all_objectives()
        
        metrics = {
            \"sla_compliance\": {},
            \"error_budget_remaining\": {},
            \"sla_violations\": {},
            \"overall_health_score\": 0
        }
        
        total_compliance = 0
        for name, report in sla_reports.items():
            metrics[\"sla_compliance\"][name] = report.compliance_percent
            metrics[\"error_budget_remaining\"][name] = report.error_budget_remaining
            metrics[\"sla_violations\"][name] = len(report.violations)
            total_compliance += report.compliance_percent
        
        if sla_reports:
            metrics[\"overall_health_score\"] = total_compliance / len(sla_reports)
        
        # Add alert counts
        active_alerts = self.alert_manager.get_active_alerts()
        metrics[\"active_alerts_by_severity\"] = {
            \"critical\": sum(1 for a in active_alerts if a.severity.value == \"critical\"),
            \"high\": sum(1 for a in active_alerts if a.severity.value == \"high\"),
            \"medium\": sum(1 for a in active_alerts if a.severity.value == \"medium\"),
            \"low\": sum(1 for a in active_alerts if a.severity.value == \"low\")
        }
        
        return metrics
    
    async def export_report(self, 
                          format: str = \"json\", 
                          period_days: int = 30) -> str:
        \"\"\"Export comprehensive SLA report.\"\"\"
        if format not in [\"json\", \"markdown\", \"csv\"]:
            raise ValueError(f\"Unsupported format: {format}\")
        
        # Get comprehensive data
        dashboard_data = await self.get_dashboard_data(refresh_cache=True)
        executive_summary = await self.get_executive_summary(period_days)
        
        if format == \"json\":
            return json.dumps({
                \"executive_summary\": executive_summary.to_dict(),
                \"dashboard_data\": dashboard_data.to_dict(),
                \"export_timestamp\": datetime.now().isoformat()
            }, indent=2)
        
        elif format == \"markdown\":
            return self._generate_markdown_report(executive_summary, dashboard_data)
        
        elif format == \"csv\":
            return self._generate_csv_report(dashboard_data)
        
        return \"\"
    
    def _calculate_overall_health(self, 
                                sla_reports: Dict[str, SLAReport],
                                active_alerts: List[Any]) -> tuple[str, float]:
        \"\"\"Calculate overall system health.\"\"\"
        if not sla_reports:
            return \"unknown\", 0.0
        
        # Calculate compliance score
        compliance_scores = [report.compliance_percent for report in sla_reports.values()]
        avg_compliance = sum(compliance_scores) / len(compliance_scores)
        
        # Factor in active alerts
        critical_alerts = sum(1 for alert in active_alerts if alert.severity.value == \"critical\")
        high_alerts = sum(1 for alert in active_alerts if alert.severity.value == \"high\")
        
        # Determine health status
        if critical_alerts > 0 or avg_compliance < 95:
            health = \"critical\"
        elif high_alerts > 0 or avg_compliance < 98:
            health = \"warning\"
        elif avg_compliance < 99.5:
            health = \"good\"
        else:
            health = \"excellent\"
        
        # Calculate score (0-100)
        score = avg_compliance
        
        # Penalize for alerts
        score -= critical_alerts * 10
        score -= high_alerts * 5
        
        score = max(0, min(100, score))
        
        return health, score
    
    def _format_objectives_data(self, sla_reports: Dict[str, SLAReport]) -> Dict[str, Any]:
        \"\"\"Format objectives data for dashboard.\"\"\"
        formatted = {}
        
        for name, report in sla_reports.items():
            formatted[name] = {
                \"compliance_percent\": report.compliance_percent,
                \"current_value\": report.current_value,
                \"target\": report.objective.target,
                \"error_budget_remaining\": report.error_budget_remaining,
                \"is_compliant\": report.is_compliant,
                \"violations\": len(report.violations),
                \"type\": report.objective.type.value,
                \"status\": \"healthy\" if report.is_compliant else \"unhealthy\"
            }
        
        return formatted
    
    async def _get_trends_cached(self) -> Dict[str, Any]:
        \"\"\"Get trends with longer caching.\"\"\"
        cache_key = \"trends_30d\"
        cache_duration = timedelta(hours=1)  # Cache trends for 1 hour
        
        if (cache_key in self._cache and 
            cache_key in self._cache_expiry and
            datetime.now() < self._cache_expiry[cache_key]):
            return self._cache[cache_key]
        
        trends = await self.history_tracker.get_trend_summary(days=30)
        trends_dict = {name: trend.to_dict() for name, trend in trends.items()}
        
        self._cache[cache_key] = trends_dict
        self._cache_expiry[cache_key] = datetime.now() + cache_duration
        
        return trends_dict
    
    async def _get_system_status(self) -> Dict[str, Any]:
        \"\"\"Get general system status metrics.\"\"\"
        try:
            # Query basic system metrics from Prometheus
            cpu_query = \"avg(100 - (avg by (instance) (rate(node_cpu_seconds_total{mode='idle'}[5m])) * 100))\"
            memory_query = \"avg((1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100)\"
            
            cpu_metrics = await self.prometheus_client.query(cpu_query)
            memory_metrics = await self.prometheus_client.query(memory_query)
            
            cpu_usage = cpu_metrics[0].latest_value if cpu_metrics else 0
            memory_usage = memory_metrics[0].latest_value if memory_metrics else 0
            
            return {
                \"cpu_usage_percent\": round(cpu_usage, 2) if cpu_usage else 0,
                \"memory_usage_percent\": round(memory_usage, 2) if memory_usage else 0,
                \"timestamp\": datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.warning(f\"Failed to get system status: {e}\")
            return {
                \"cpu_usage_percent\": 0,
                \"memory_usage_percent\": 0,
                \"error\": str(e),
                \"timestamp\": datetime.now().isoformat()
            }
    
    def _is_cached(self, key: str) -> bool:
        \"\"\"Check if data is cached and not expired.\"\"\"
        return (key in self._cache and 
                key in self._cache_expiry and
                datetime.now() < self._cache_expiry[key])
    
    def _generate_markdown_report(self, 
                                executive_summary: SLAExecutiveSummary,
                                dashboard_data: SLADashboardData) -> str:
        \"\"\"Generate markdown format report.\"\"\"
        lines = [
            \"# SLA Performance Report\",
            f\"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\",
            \"\",
            \"## Executive Summary\",
            f\"- **Period**: {executive_summary.period}\",
            f\"- **Overall Availability**: {executive_summary.overall_availability:.2f}%\",
            f\"- **Objectives Met**: {executive_summary.objectives_met}/{executive_summary.total_objectives}\",
            f\"- **Critical Incidents**: {executive_summary.critical_incidents}\",
            f\"- **Average Error Budget**: {executive_summary.average_error_budget_remaining:.2f}%\",
            \"\",
            \"## Current Status\",
            f\"- **Overall Health**: {dashboard_data.overall_health.title()}\",
            f\"- **Health Score**: {dashboard_data.overall_score:.1f}/100\",
            f\"- **Active Alerts**: {len(dashboard_data.active_alerts)}\",
            \"\",
            \"## SLA Objectives\"
        ]
        
        for name, obj in dashboard_data.objectives.items():
            status_icon = \"✅\" if obj[\"is_compliant\"] else \"❌\"
            lines.extend([
                f\"### {status_icon} {name}\",
                f\"- **Compliance**: {obj['compliance_percent']:.2f}%\",
                f\"- **Target**: {obj['target']}%\",
                f\"- **Error Budget**: {obj['error_budget_remaining']:.2f}%\",
                \"\"
            ])
        
        return \"\
\".join(lines)
    
    def _generate_csv_report(self, dashboard_data: SLADashboardData) -> str:
        \"\"\"Generate CSV format report.\"\"\"
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Headers
        writer.writerow([
            \"Objective\", \"Type\", \"Compliance %\", \"Target %\", 
            \"Current Value\", \"Error Budget %\", \"Status\", \"Violations\"
        ])
        
        # Data rows
        for name, obj in dashboard_data.objectives.items():
            writer.writerow([
                name,
                obj[\"type\"],
                obj[\"compliance_percent\"],
                obj[\"target\"],
                obj[\"current_value\"],
                obj[\"error_budget_remaining\"],
                obj[\"status\"],
                obj[\"violations\"]
            ])
        
        return output.getvalue()


# Global dashboard API instance
_sla_dashboard_api: Optional[SLADashboardAPI] = None


def get_sla_dashboard_api() -> SLADashboardAPI:
    \"\"\"Get the global SLA dashboard API instance.\"\"\"
    global _sla_dashboard_api
    if _sla_dashboard_api is None:
        _sla_dashboard_api = SLADashboardAPI()
    return _sla_dashboard_api