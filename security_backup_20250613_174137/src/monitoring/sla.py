"""
SLA (Service Level Agreement) tracking and reporting.

Provides:
- SLA objective definitions
- SLA compliance tracking
- Error budget calculation
- SLA reporting and dashboards
"""

import os
import json
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
import asyncio

from prometheus_client import Gauge, Counter, Histogram
from .metrics import get_metrics_collector
from .prometheus_client import get_prometheus_client, PrometheusClient

from src.core.error_handler import (
    handle_errors, async_handle_errors, log_error,
    ServiceUnavailableError, ExternalServiceError, ConfigurationError
)

__all__ = [
    "SLAType",
    "SLAObjective", 
    "SLAReport",
    "SLATracker",
    "get_sla_tracker",
    "add_sla_objective",
    "get_sla_report",
    "get_comprehensive_sla_status"
]



class SLAType(Enum):
    """Types of SLA objectives."""
    AVAILABILITY = "availability"
    LATENCY = "latency"
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"
    CUSTOM = "custom"


@dataclass
class SLAObjective:
    """SLA objective definition."""
    name: str
    type: SLAType
    target: float  # Target value (e.g., 99.9 for availability)
    measurement_window: timedelta = timedelta(days=30)
    description: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    
    # For latency SLAs
    latency_percentile: float = 0.95  # e.g., 95th percentile
    latency_threshold_ms: float = 1000  # e.g., 1 second
    
    # For custom SLAs
    custom_query: Optional[str] = None  # Prometheus query


@dataclass
class SLAReport:
    """SLA compliance report."""
    objective: SLAObjective
    current_value: float
    compliance_percent: float
    error_budget_remaining: float  # Percentage of error budget left
    time_range: Tuple[datetime, datetime]
    violations: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def is_compliant(self) -> bool:
        """Check if SLA is currently compliant."""
        return self.compliance_percent >= self.objective.target
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "objective": {
                "name": self.objective.name,
                "type": self.objective.type.value,
                "target": self.objective.target,
                "description": self.objective.description
            },
            "current_value": self.current_value,
            "compliance_percent": self.compliance_percent,
            "error_budget_remaining": self.error_budget_remaining,
            "is_compliant": self.is_compliant,
            "time_range": {
                "start": self.time_range[0].isoformat(),
                "end": self.time_range[1].isoformat()
            },
            "violations": self.violations
        }


class SLATracker:
    """Tracks and reports on SLA compliance."""
    
    # Default SLA objectives
    DEFAULT_OBJECTIVES = [
        SLAObjective(
            name="api_availability",
            type=SLAType.AVAILABILITY,
            target=99.9,
            description="API availability should be at least 99.9%"
        ),
        SLAObjective(
            name="api_latency_p95",
            type=SLAType.LATENCY,
            target=95.0,  # 95% of requests under threshold
            latency_percentile=0.95,
            latency_threshold_ms=1000,
            description="95th percentile latency should be under 1 second"
        ),
        SLAObjective(
            name="api_error_rate",
            type=SLAType.ERROR_RATE,
            target=99.0,  # Less than 1% errors
            description="Error rate should be less than 1%"
        ),
        SLAObjective(
            name="ai_availability",
            type=SLAType.AVAILABILITY,
            target=99.5,
            description="AI service availability should be at least 99.5%"
        ),
        SLAObjective(
            name="mcp_tool_success_rate",
            type=SLAType.ERROR_RATE,
            target=98.0,
            description="MCP tool success rate should be at least 98%"
        ),
    ]
    
    def __init__(self):
        self.objectives: Dict[str, SLAObjective] = {}
        self.metrics_collector = get_metrics_collector()
        
        # SLA-specific metrics
        self.sla_violations_total = Counter(
            'sla_violations_total',
            'Total SLA violations',
            ['sla_name', 'sla_type']
        )
        
        self.error_budget_consumed = Gauge(
            'error_budget_consumed_percent',
            'Percentage of error budget consumed',
            ['sla_name']
        )
        
        self.sla_compliance_score = Gauge(
            'sla_compliance_score',
            'Overall SLA compliance score',
        )
        
        # Load default objectives
        for objective in self.DEFAULT_OBJECTIVES:
            self.add_objective(objective)
    
    def add_objective(self, objective: SLAObjective):
        """Add an SLA objective."""
        self.objectives[objective.name] = objective
    
    def remove_objective(self, name: str):
        """Remove an SLA objective."""
        self.objectives.pop(name, None)
    
    def calculate_availability(
        self,
        success_count: int,
        total_count: int
    ) -> float:
        """Calculate availability percentage."""
        if total_count == 0:
            return 100.0
        return (success_count / total_count) * 100
    
    def calculate_error_rate_compliance(
        self,
        error_count: int,
        total_count: int,
        target: float
    ) -> float:
        """Calculate error rate SLA compliance."""
        if total_count == 0:
            return 100.0
        
        success_rate = ((total_count - error_count) / total_count) * 100
        return success_rate
    
    def calculate_latency_compliance(
        self,
        latency_values: List[float],
        percentile: float,
        threshold: float
    ) -> float:
        """Calculate latency SLA compliance."""
        if not latency_values:
            return 100.0
        
        sorted_values = sorted(latency_values)
        percentile_index = int(len(sorted_values) * percentile)
        percentile_value = sorted_values[percentile_index]
        
        # Calculate what percentage of requests meet the threshold
        under_threshold = sum(1 for v in latency_values if v <= threshold)
        return (under_threshold / len(latency_values)) * 100
    
    def calculate_error_budget(
        self,
        objective: SLAObjective,
        current_compliance: float
    ) -> float:
        """Calculate remaining error budget."""
        # Error budget is the allowed failure rate
        allowed_failure_rate = 100 - objective.target
        current_failure_rate = 100 - current_compliance
        
        if allowed_failure_rate == 0:
            return 0 if current_failure_rate > 0 else 100
        
        consumed = (current_failure_rate / allowed_failure_rate) * 100
        remaining = max(0, 100 - consumed)
        
        return remaining
    
    async def check_objective(
        self,
        objective: SLAObjective,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> SLAReport:
        """Check compliance for a specific SLA objective."""
        if time_range is None:
            end_time = datetime.now()
            start_time = end_time - objective.measurement_window
            time_range = (start_time, end_time)
        
        prometheus_client = get_prometheus_client()
        start_time, end_time = time_range
        
        try:
            if objective.type == SLAType.AVAILABILITY:
                current_value = await self._calculate_availability(
                    prometheus_client, objective, start_time, end_time
                )
                compliance = current_value
                
            elif objective.type == SLAType.LATENCY:
                current_value, compliance = await self._calculate_latency_compliance(
                    prometheus_client, objective, start_time, end_time
                )
                
            elif objective.type == SLAType.ERROR_RATE:
                current_value, compliance = await self._calculate_error_rate_compliance(
                    prometheus_client, objective, start_time, end_time
                )
                
            elif objective.type == SLAType.THROUGHPUT:
                current_value, compliance = await self._calculate_throughput_compliance(
                    prometheus_client, objective, start_time, end_time
                )
                
            elif objective.type == SLAType.CUSTOM:
                current_value, compliance = await self._calculate_custom_sla(
                    prometheus_client, objective, start_time, end_time
                )
                
            else:
                # Fallback for unknown types
                current_value = 0.0
                compliance = 0.0
        
        except Exception as e:
            log_error(f"Error calculating SLA for {objective.name}: {e}")
            # Fallback to conservative values on error
            current_value = 0.0
            compliance = 0.0
        
        # Calculate error budget
        error_budget = self.calculate_error_budget(objective, compliance)
        
        # Update metrics
        self.metrics_collector.update_sla_compliance(objective.name, compliance)
        self.error_budget_consumed.labels(sla_name=objective.name).set(100 - error_budget)
        
        # Check for violations and generate detailed context
        violations = await self._check_violations(
            objective, compliance, error_budget, start_time, end_time
        )
        
        return SLAReport(
            objective=objective,
            current_value=current_value,
            compliance_percent=compliance,
            error_budget_remaining=error_budget,
            time_range=time_range,
            violations=violations
        )
    
    async def check_all_objectives(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> Dict[str, SLAReport]:
        """Check all SLA objectives."""
        reports = {}
        
        tasks = []
        for name, objective in self.objectives.items():
            tasks.append(self.check_objective(objective, time_range))
        
        results = await asyncio.gather(*tasks)
        
        for objective, report in zip(self.objectives.values(), results):
            reports[objective.name] = report
        
        # Calculate overall compliance score
        if reports:
            compliant_count = sum(1 for r in reports.values() if r.is_compliant)
            overall_score = (compliant_count / len(reports)) * 100
            self.sla_compliance_score.set(overall_score)
        
        return reports
    
    def generate_report(
        self,
        reports: Dict[str, SLAReport],
        format: str = "json"
    ) -> str:
        """Generate SLA compliance report."""
        if format == "json":
            report_data = {
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_objectives": len(reports),
                    "compliant": sum(1 for r in reports.values() if r.is_compliant),
                    "violations": sum(1 for r in reports.values() if not r.is_compliant),
                    "overall_score": (sum(1 for r in reports.values() if r.is_compliant) / len(reports)) * 100 if reports else 100
                },
                "objectives": {name: report.to_dict() for name, report in reports.items()}
            }
            return json.dumps(report_data, indent=2)
        
        elif format == "markdown":
            lines = [
                "# SLA Compliance Report",
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "## Summary",
                f"- Total Objectives: {len(reports)}",
                f"- Compliant: {sum(1 for r in reports.values() if r.is_compliant)}",
                f"- Violations: {sum(1 for r in reports.values() if not r.is_compliant)}",
                "",
                "## Objectives",
                ""
            ]
            
            for name, report in reports.items():
                status = "✅" if report.is_compliant else "❌"
                lines.extend([
                    f"### {status} {name}",
                    f"- **Type**: {report.objective.type.value}",
                    f"- **Target**: {report.objective.target}%",
                    f"- **Current**: {report.current_value:.2f}%",
                    f"- **Compliance**: {report.compliance_percent:.2f}%",
                    f"- **Error Budget Remaining**: {report.error_budget_remaining:.2f}%",
                    ""
                ])
            
            return "\n".join(lines)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    async def _calculate_availability(
        self,
        prometheus_client: PrometheusClient,
        objective: SLAObjective,
        start_time: datetime,
        end_time: datetime
    ) -> float:
        """Calculate real availability from Prometheus metrics."""
        service_name = objective.labels.get('service', 'claude-api')
        return await prometheus_client.get_metric_availability(service_name, start_time, end_time)
    
    async def _calculate_latency_compliance(
        self,
        prometheus_client: PrometheusClient,
        objective: SLAObjective,
        start_time: datetime,
        end_time: datetime
    ) -> Tuple[float, float]:
        """Calculate latency SLA compliance from real metrics."""
        service_name = objective.labels.get('service', 'claude-api')
        percentile_value = await prometheus_client.get_latency_percentile(
            service_name, objective.latency_percentile, start_time, end_time
        )
        
        # Convert to milliseconds if needed
        percentile_ms = percentile_value * 1000 if percentile_value < 100 else percentile_value
        
        # Calculate compliance: percentage of requests under threshold
        compliance = 100.0 if percentile_ms <= objective.latency_threshold_ms else (
            (objective.latency_threshold_ms / percentile_ms) * 100
        )
        
        return percentile_ms, min(100.0, compliance)
    
    async def _calculate_error_rate_compliance(
        self,
        prometheus_client: PrometheusClient,
        objective: SLAObjective,
        start_time: datetime,
        end_time: datetime
    ) -> Tuple[float, float]:
        """Calculate error rate SLA compliance from real metrics."""
        service_name = objective.labels.get('service', 'claude-api')
        error_rate = await prometheus_client.get_error_rate(service_name, start_time, end_time)
        
        # Success rate is inverse of error rate
        success_rate = 100.0 - error_rate
        
        # Compliance is the success rate
        return success_rate, success_rate
    
    async def _calculate_throughput_compliance(
        self,
        prometheus_client: PrometheusClient,
        objective: SLAObjective,
        start_time: datetime,
        end_time: datetime
    ) -> Tuple[float, float]:
        """Calculate throughput SLA compliance."""
        service_name = objective.labels.get('service', 'claude-api')
        current_throughput = await prometheus_client.get_throughput(service_name, start_time, end_time)
        
        # Compliance is percentage of target throughput achieved
        target_throughput = objective.target  # Expected to be in RPS
        compliance = (current_throughput / target_throughput) * 100 if target_throughput > 0 else 100.0
        
        return current_throughput, min(100.0, compliance)
    
    async def _calculate_custom_sla(
        self,
        prometheus_client: PrometheusClient,
        objective: SLAObjective,
        start_time: datetime,
        end_time: datetime
    ) -> Tuple[float, float]:
        """Calculate custom SLA using provided PromQL query."""
        if not objective.custom_query:
            return 0.0, 0.0
        
        try:
            metrics = await prometheus_client.query_range(
                objective.custom_query, start_time, end_time
            )
            
            if metrics:
                # Use average of all returned values
                all_values = [p.value for m in metrics for p in m.values]
                current_value = sum(all_values) / len(all_values) if all_values else 0.0
                
                # For custom SLAs, assume the query returns a percentage
                compliance = current_value
                return current_value, min(100.0, max(0.0, compliance))
        
        except Exception as e:
            log_error(f"Custom SLA query failed: {e}")
        
        return 0.0, 0.0
    
    async def _check_violations(
        self,
        objective: SLAObjective,
        compliance: float,
        error_budget: float,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Check for SLA violations with detailed context."""
        violations = []
        
        if compliance < objective.target:
            self.sla_violations_total.labels(
                sla_name=objective.name,
                sla_type=objective.type.value
            ).inc()
            
            # Determine severity based on how far below target and error budget
            deviation = objective.target - compliance
            if error_budget < 5 or deviation > 5:
                severity = "critical"
            elif error_budget < 10 or deviation > 2:
                severity = "high"
            elif error_budget < 25 or deviation > 1:
                severity = "medium"
            else:
                severity = "low"
            
            violations.append({
                "timestamp": datetime.now().isoformat(),
                "compliance": compliance,
                "target": objective.target,
                "deviation": deviation,
                "error_budget_remaining": error_budget,
                "severity": severity,
                "duration_minutes": (end_time - start_time).total_seconds() / 60,
                "measurement_window": str(objective.measurement_window)
            })
        
        return violations
    
    async def get_error_budget_burn_rate(
        self,
        objective_name: str,
        time_window: timedelta = timedelta(hours=1)
    ) -> float:
        """Calculate error budget burn rate from real metrics."""
        if objective_name not in self.objectives:
            return 0.0
        
        objective = self.objectives[objective_name]
        prometheus_client = get_prometheus_client()
        
        # Calculate current period and previous period for comparison
        end_time = datetime.now()
        start_time = end_time - time_window
        previous_start = start_time - time_window
        
        try:
            # Get current error budget consumption
            current_report = await self.check_objective(objective, (start_time, end_time))
            current_budget_used = 100 - current_report.error_budget_remaining
            
            # Get previous period error budget consumption
            previous_report = await self.check_objective(objective, (previous_start, start_time))
            previous_budget_used = 100 - previous_report.error_budget_remaining
            
            # Calculate burn rate (how much faster we're consuming budget)
            if previous_budget_used == 0:
                return 1.0  # Normal rate
            
            burn_rate = current_budget_used / previous_budget_used
            return max(0.0, burn_rate)
            
        except Exception as e:
            log_error(f"Error calculating burn rate for {objective_name}: {e}")
            return 1.0  # Conservative fallback
    
    async def predict_budget_exhaustion(
        self,
        objective_name: str,
        current_burn_rate: Optional[float] = None
    ) -> Optional[datetime]:
        """Predict when error budget will be exhausted based on current burn rate."""
        if objective_name not in self.objectives:
            return None
        
        objective = self.objectives[objective_name]
        
        try:
            # Get current error budget status
            current_report = await self.check_objective(objective)
            remaining_budget = current_report.error_budget_remaining
            
            if remaining_budget <= 0:
                return datetime.now()  # Already exhausted
            
            if remaining_budget >= 99:
                return None  # Plenty of budget remaining
            
            # Calculate burn rate if not provided
            if current_burn_rate is None:
                current_burn_rate = await self.get_error_budget_burn_rate(objective_name)
            
            if current_burn_rate <= 0:
                return None  # Not consuming budget
            
            # Estimate time to exhaustion based on current burn rate
            # This is a simplified calculation - in practice you'd want more sophisticated modeling
            window_hours = objective.measurement_window.total_seconds() / 3600
            budget_consumption_rate = (100 - remaining_budget) / window_hours  # Budget % per hour
            
            if budget_consumption_rate <= 0:
                return None
            
            # Apply burn rate multiplier
            adjusted_rate = budget_consumption_rate * current_burn_rate
            
            if adjusted_rate <= 0:
                return None
            
            hours_to_exhaustion = remaining_budget / adjusted_rate
            
            # Cap at reasonable maximum
            if hours_to_exhaustion > 24 * 30:  # 30 days
                return None
            
            return datetime.now() + timedelta(hours=hours_to_exhaustion)
            
        except Exception as e:
            log_error(f"Error predicting budget exhaustion for {objective_name}: {e}")
            return None


# Global SLA tracker instance
_sla_tracker: Optional[SLATracker] = None


def get_sla_tracker() -> SLATracker:
    """Get the global SLA tracker instance."""
    global _sla_tracker
    if _sla_tracker is None:
        _sla_tracker = SLATracker()
    return _sla_tracker


# Convenience functions
async def check_sla_compliance(
    objective_name: Optional[str] = None
) -> Union[SLAReport, Dict[str, SLAReport]]:
    """Check SLA compliance for one or all objectives."""
    tracker = get_sla_tracker()
    
    if objective_name:
        if objective_name in tracker.objectives:
            return await tracker.check_objective(tracker.objectives[objective_name])
        else:
            raise ValueError(f"Unknown SLA objective: {objective_name}")
    else:
        return await tracker.check_all_objectives()


def add_sla_objective(objective: SLAObjective):
    """Add a new SLA objective."""
    get_sla_tracker().add_objective(objective)


def get_sla_report(format: str = "json") -> str:
    """Get SLA compliance report."""
    tracker = get_sla_tracker()
    reports = asyncio.run(tracker.check_all_objectives())
    return tracker.generate_report(reports, format)


async def get_comprehensive_sla_status() -> Dict[str, Any]:
    """Get comprehensive SLA status including all components."""
    try:
        # Import here to avoid circular imports
        from .sla_alerting import get_sla_alert_manager
        from .sla_history import get_sla_history_tracker
        from .sla_dashboard import get_sla_dashboard_api
        
        tracker = get_sla_tracker()
        alert_manager = get_sla_alert_manager()
        history_tracker = get_sla_history_tracker()
        dashboard_api = get_sla_dashboard_api()
        
        # Get current reports
        current_reports = await tracker.check_all_objectives()
        
        # Get active alerts
        active_alerts = alert_manager.get_active_alerts()
        
        # Get trends for past 30 days
        trends = await history_tracker.get_trend_summary(days=30)
        
        # Get dashboard data
        dashboard_data = await dashboard_api.get_dashboard_data()
        
        # Calculate summary statistics
        total_objectives = len(current_reports)
        compliant_objectives = sum(1 for report in current_reports.values() if report.is_compliant)
        critical_alerts = sum(1 for alert in active_alerts if alert.severity.value == "critical")
        
        # Get overall compliance score
        if current_reports:
            overall_compliance = sum(
                report.compliance_percent for report in current_reports.values()
            ) / len(current_reports)
        else:
            overall_compliance = 0.0
        
        # Get average error budget
        if current_reports:
            avg_error_budget = sum(
                report.error_budget_remaining for report in current_reports.values()
            ) / len(current_reports)
        else:
            avg_error_budget = 0.0
        
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_objectives": total_objectives,
                "compliant_objectives": compliant_objectives,
                "compliance_rate": (compliant_objectives / total_objectives * 100) if total_objectives > 0 else 0,
                "overall_compliance": overall_compliance,
                "average_error_budget_remaining": avg_error_budget,
                "active_alerts": len(active_alerts),
                "critical_alerts": critical_alerts,
                "overall_health": dashboard_data.overall_health,
                "health_score": dashboard_data.overall_score
            },
            "objectives": {
                name: {
                    "compliance_percent": report.compliance_percent,
                    "target": report.objective.target,
                    "error_budget_remaining": report.error_budget_remaining,
                    "is_compliant": report.is_compliant,
                    "violations": len(report.violations),
                    "type": report.objective.type.value
                }
                for name, report in current_reports.items()
            },
            "alerts": [alert.to_dict() for alert in active_alerts],
            "trends": {name: trend.to_dict() for name, trend in trends.items()},
            "system_status": {
                "prometheus_connected": True,  # If we got here, it's connected
                "monitoring_active": True,
                "data_sources": ["prometheus", "internal_metrics"]
            }
        }
        
    except Exception as e:
        log_error(f"Failed to get comprehensive SLA status: {e}")
        return {
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "summary": {
                "total_objectives": 0,
                "compliant_objectives": 0,
                "compliance_rate": 0,
                "overall_compliance": 0,
                "average_error_budget_remaining": 0,
                "active_alerts": 0,
                "critical_alerts": 0,
                "overall_health": "unknown",
                "health_score": 0
            }
        }