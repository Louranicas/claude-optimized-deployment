"""
Service Level Indicator (SLI) and Service Level Objective (SLO) Tracking System.

This module implements a comprehensive SLI/SLO tracking system following SRE best practices,
including error budget management, multi-source data collection, and compliance reporting.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from prometheus_client import Counter, Gauge, Histogram, Summary
from pydantic import BaseModel, Field, validator

from ..core.logging_config import get_logger
from ..database.models import SLIMetric, SLODefinition, ErrorBudget
from .metrics import MetricsCollector

logger = get_logger(__name__)


class SLIType(str, Enum):
    """Types of Service Level Indicators."""
    
    AVAILABILITY = "availability"
    LATENCY = "latency"
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"
    QUALITY = "quality"
    FRESHNESS = "freshness"
    CORRECTNESS = "correctness"
    COVERAGE = "coverage"
    DURABILITY = "durability"


class SLOStatus(str, Enum):
    """SLO compliance status."""
    
    MEETING = "meeting"
    AT_RISK = "at_risk"
    BREACHING = "breaching"
    BREACHED = "breached"


class TimeWindow(str, Enum):
    """Time windows for SLO measurement."""
    
    ROLLING_1H = "rolling_1h"
    ROLLING_24H = "rolling_24h"
    ROLLING_7D = "rolling_7d"
    ROLLING_30D = "rolling_30d"
    CALENDAR_MONTH = "calendar_month"
    CALENDAR_QUARTER = "calendar_quarter"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class SLIDataPoint(BaseModel):
    """Individual SLI measurement."""
    
    timestamp: datetime
    value: float
    labels: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SLIDefinition(BaseModel):
    """Service Level Indicator definition."""
    
    name: str
    type: SLIType
    description: str
    unit: str
    query: str  # Prometheus query or data source query
    aggregation: str = "avg"  # avg, sum, min, max, p50, p95, p99
    labels: Dict[str, str] = Field(default_factory=dict)
    
    @validator("aggregation")
    def validate_aggregation(cls, v):
        valid = ["avg", "sum", "min", "max", "p50", "p90", "p95", "p99", "p99.9"]
        if v not in valid:
            raise ValueError(f"Aggregation must be one of {valid}")
        return v


class SLOTarget(BaseModel):
    """SLO target configuration."""
    
    sli_name: str
    target: float  # Target value (e.g., 99.9 for 99.9%)
    comparison: str = "gte"  # gte (>=), lte (<=), gt (>), lt (<)
    time_window: TimeWindow
    description: str
    
    @validator("target")
    def validate_target(cls, v):
        if not 0 <= v <= 100:
            raise ValueError("Target must be between 0 and 100")
        return v
    
    @validator("comparison")
    def validate_comparison(cls, v):
        if v not in ["gte", "lte", "gt", "lt"]:
            raise ValueError("Comparison must be one of: gte, lte, gt, lt")
        return v


class ErrorBudgetPolicy(BaseModel):
    """Error budget policy configuration."""
    
    name: str
    slo_name: str
    actions: List[Dict[str, Any]]  # Actions to take at different budget levels
    freeze_threshold: float = 0.2  # Freeze deployments when budget < 20%
    alert_thresholds: Dict[float, AlertSeverity] = Field(
        default_factory=lambda: {
            0.5: AlertSeverity.WARNING,
            0.2: AlertSeverity.ERROR,
            0.0: AlertSeverity.CRITICAL
        }
    )


class SLOCompliance(BaseModel):
    """SLO compliance calculation result."""
    
    slo_name: str
    current_value: float
    target_value: float
    is_compliant: bool
    compliance_percentage: float
    error_budget_remaining: float
    error_budget_consumed: float
    time_window: TimeWindow
    calculated_at: datetime
    trend: str = "stable"  # improving, stable, degrading
    forecast_breach_time: Optional[datetime] = None


class SLIDataSource(ABC):
    """Abstract base class for SLI data sources."""
    
    @abstractmethod
    async def fetch_data(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        labels: Dict[str, str]
    ) -> List[SLIDataPoint]:
        """Fetch SLI data from the source."""
        pass


class PrometheusDataSource(SLIDataSource):
    """Prometheus data source for SLI collection."""
    
    def __init__(self, prometheus_url: str):
        self.prometheus_url = prometheus_url
        self.session = None
    
    async def fetch_data(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        labels: Dict[str, str]
    ) -> List[SLIDataPoint]:
        """Fetch data from Prometheus."""
        # Implementation would query Prometheus
        # This is a placeholder for the actual implementation
        return []


class SLICollector:
    """Collects SLI data from multiple sources."""
    
    def __init__(self):
        self.data_sources: Dict[str, SLIDataSource] = {}
        self.sli_definitions: Dict[str, SLIDefinition] = {}
        self.data_cache: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        
        # Metrics for monitoring the SLI collection
        self.collection_counter = Counter(
            "sli_collection_total",
            "Total SLI collections",
            ["sli_name", "status"]
        )
        self.collection_duration = Histogram(
            "sli_collection_duration_seconds",
            "SLI collection duration",
            ["sli_name"]
        )
    
    def register_data_source(self, name: str, source: SLIDataSource):
        """Register a data source."""
        self.data_sources[name] = source
    
    def register_sli(self, sli: SLIDefinition):
        """Register an SLI definition."""
        self.sli_definitions[sli.name] = sli
    
    async def collect_sli(
        self,
        sli_name: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[SLIDataPoint]:
        """Collect data for a specific SLI."""
        if sli_name not in self.sli_definitions:
            raise ValueError(f"SLI {sli_name} not registered")
        
        sli = self.sli_definitions[sli_name]
        
        with self.collection_duration.labels(sli_name=sli_name).time():
            try:
                # For now, assume Prometheus as default source
                source = self.data_sources.get("prometheus")
                if not source:
                    raise ValueError("No data source available")
                
                data = await source.fetch_data(
                    sli.query,
                    start_time,
                    end_time,
                    sli.labels
                )
                
                # Cache the data
                for point in data:
                    self.data_cache[sli_name].append(point)
                
                self.collection_counter.labels(
                    sli_name=sli_name,
                    status="success"
                ).inc()
                
                return data
                
            except Exception as e:
                logger.error(f"Failed to collect SLI {sli_name}: {e}")
                self.collection_counter.labels(
                    sli_name=sli_name,
                    status="failure"
                ).inc()
                raise


class SLOCalculator:
    """Calculates SLO compliance and error budgets."""
    
    def __init__(self):
        self.slo_targets: Dict[str, SLOTarget] = {}
        self.compliance_gauge = Gauge(
            "slo_compliance",
            "SLO compliance percentage",
            ["slo_name", "time_window"]
        )
        self.error_budget_gauge = Gauge(
            "slo_error_budget_remaining",
            "Remaining error budget percentage",
            ["slo_name", "time_window"]
        )
    
    def register_slo(self, slo: SLOTarget):
        """Register an SLO target."""
        self.slo_targets[f"{slo.sli_name}_{slo.time_window.value}"] = slo
    
    def calculate_compliance(
        self,
        sli_data: List[SLIDataPoint],
        slo: SLOTarget,
        current_time: Optional[datetime] = None
    ) -> SLOCompliance:
        """Calculate SLO compliance for given SLI data."""
        if not sli_data:
            raise ValueError("No SLI data provided")
        
        current_time = current_time or datetime.utcnow()
        
        # Calculate the aggregate value based on SLO comparison
        values = [point.value for point in sli_data]
        
        if slo.comparison in ["gte", "gt"]:
            # For availability, higher is better
            current_value = sum(1 for v in values if self._compare(v, slo.target, slo.comparison)) / len(values) * 100
        else:
            # For latency/error rate, lower is better
            current_value = sum(values) / len(values)
        
        # Check compliance
        is_compliant = self._compare(current_value, slo.target, slo.comparison)
        
        # Calculate error budget
        if slo.comparison in ["gte", "gt"]:
            error_budget_total = 100 - slo.target
            error_budget_consumed = max(0, slo.target - current_value)
        else:
            error_budget_total = slo.target
            error_budget_consumed = max(0, current_value - slo.target)
        
        error_budget_remaining = max(0, error_budget_total - error_budget_consumed)
        
        # Calculate compliance percentage
        if error_budget_total > 0:
            compliance_percentage = (error_budget_remaining / error_budget_total) * 100
        else:
            compliance_percentage = 100 if is_compliant else 0
        
        # Determine trend
        trend = self._calculate_trend(sli_data)
        
        # Forecast breach time if trending down
        forecast_breach_time = None
        if trend == "degrading" and compliance_percentage > 0:
            forecast_breach_time = self._forecast_breach(
                sli_data,
                error_budget_remaining,
                error_budget_total
            )
        
        # Update metrics
        self.compliance_gauge.labels(
            slo_name=slo.sli_name,
            time_window=slo.time_window.value
        ).set(compliance_percentage)
        
        self.error_budget_gauge.labels(
            slo_name=slo.sli_name,
            time_window=slo.time_window.value
        ).set(error_budget_remaining)
        
        return SLOCompliance(
            slo_name=slo.sli_name,
            current_value=current_value,
            target_value=slo.target,
            is_compliant=is_compliant,
            compliance_percentage=compliance_percentage,
            error_budget_remaining=error_budget_remaining,
            error_budget_consumed=error_budget_consumed,
            time_window=slo.time_window,
            calculated_at=current_time,
            trend=trend,
            forecast_breach_time=forecast_breach_time
        )
    
    def _compare(self, value: float, target: float, comparison: str) -> bool:
        """Compare value against target."""
        if comparison == "gte":
            return value >= target
        elif comparison == "lte":
            return value <= target
        elif comparison == "gt":
            return value > target
        elif comparison == "lt":
            return value < target
        else:
            raise ValueError(f"Invalid comparison: {comparison}")
    
    def _calculate_trend(self, data: List[SLIDataPoint]) -> str:
        """Calculate trend from recent data."""
        if len(data) < 10:
            return "stable"
        
        # Simple linear regression on recent values
        recent = data[-10:]
        values = [p.value for p in recent]
        
        # Calculate slope
        n = len(values)
        x_mean = (n - 1) / 2
        y_mean = sum(values) / n
        
        numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return "stable"
        
        slope = numerator / denominator
        
        # Determine trend based on slope
        if abs(slope) < 0.1:
            return "stable"
        elif slope > 0:
            return "improving"
        else:
            return "degrading"
    
    def _forecast_breach(
        self,
        data: List[SLIDataPoint],
        budget_remaining: float,
        budget_total: float
    ) -> Optional[datetime]:
        """Forecast when error budget will be exhausted."""
        if len(data) < 2:
            return None
        
        # Calculate burn rate from recent data
        recent_window = min(len(data), 100)
        recent_data = data[-recent_window:]
        
        # Calculate average burn rate
        time_span = (recent_data[-1].timestamp - recent_data[0].timestamp).total_seconds()
        if time_span <= 0:
            return None
        
        budget_consumed_in_window = self._calculate_budget_consumed(recent_data, budget_total)
        burn_rate_per_second = budget_consumed_in_window / time_span
        
        if burn_rate_per_second <= 0:
            return None
        
        # Forecast time to breach
        seconds_to_breach = budget_remaining / burn_rate_per_second
        return datetime.utcnow() + timedelta(seconds=seconds_to_breach)
    
    def _calculate_budget_consumed(
        self,
        data: List[SLIDataPoint],
        budget_total: float
    ) -> float:
        """Calculate budget consumed in the given data window."""
        # Simplified calculation - would be more complex in production
        violations = sum(1 for p in data if p.value < 99.9)  # Example threshold
        return (violations / len(data)) * budget_total


class ErrorBudgetManager:
    """Manages error budgets and policies."""
    
    def __init__(self):
        self.policies: Dict[str, ErrorBudgetPolicy] = {}
        self.budget_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.action_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    def register_policy(self, policy: ErrorBudgetPolicy):
        """Register an error budget policy."""
        self.policies[policy.name] = policy
    
    async def evaluate_budget(
        self,
        slo_compliance: SLOCompliance
    ) -> List[Dict[str, Any]]:
        """Evaluate error budget and determine actions."""
        actions = []
        
        # Find relevant policies
        for policy in self.policies.values():
            if policy.slo_name != slo_compliance.slo_name:
                continue
            
            # Record budget history
            self.budget_history[policy.name].append({
                "timestamp": slo_compliance.calculated_at,
                "budget_remaining": slo_compliance.error_budget_remaining,
                "compliance": slo_compliance.compliance_percentage
            })
            
            # Check alert thresholds
            for threshold, severity in sorted(
                policy.alert_thresholds.items(),
                reverse=True
            ):
                if slo_compliance.error_budget_remaining <= threshold * 100:
                    actions.append({
                        "type": "alert",
                        "severity": severity.value,
                        "message": f"Error budget below {threshold*100}% for {slo_compliance.slo_name}",
                        "budget_remaining": slo_compliance.error_budget_remaining,
                        "threshold": threshold * 100
                    })
                    break
            
            # Check freeze threshold
            if slo_compliance.error_budget_remaining <= policy.freeze_threshold * 100:
                actions.append({
                    "type": "deployment_freeze",
                    "message": f"Deployment freeze triggered for {slo_compliance.slo_name}",
                    "budget_remaining": slo_compliance.error_budget_remaining,
                    "threshold": policy.freeze_threshold * 100
                })
            
            # Execute policy-specific actions
            for action in policy.actions:
                if self._should_execute_action(action, slo_compliance):
                    actions.append(action)
        
        # Record actions
        if actions:
            self.action_history[slo_compliance.slo_name].append({
                "timestamp": slo_compliance.calculated_at,
                "actions": actions,
                "compliance": slo_compliance.dict()
            })
        
        return actions
    
    def _should_execute_action(
        self,
        action: Dict[str, Any],
        compliance: SLOCompliance
    ) -> bool:
        """Determine if an action should be executed."""
        if "budget_threshold" in action:
            return compliance.error_budget_remaining <= action["budget_threshold"]
        if "compliance_threshold" in action:
            return compliance.compliance_percentage <= action["compliance_threshold"]
        return False
    
    def get_budget_burn_rate(
        self,
        policy_name: str,
        window: timedelta
    ) -> float:
        """Calculate error budget burn rate."""
        history = self.budget_history.get(policy_name, deque())
        if len(history) < 2:
            return 0.0
        
        cutoff = datetime.utcnow() - window
        relevant_history = [
            h for h in history
            if h["timestamp"] >= cutoff
        ]
        
        if len(relevant_history) < 2:
            return 0.0
        
        # Calculate burn rate
        first = relevant_history[0]
        last = relevant_history[-1]
        time_diff = (last["timestamp"] - first["timestamp"]).total_seconds()
        
        if time_diff <= 0:
            return 0.0
        
        budget_diff = first["budget_remaining"] - last["budget_remaining"]
        return budget_diff / (time_diff / 3600)  # Burn rate per hour


class SLOAlertManager:
    """Manages SLO-based alerting."""
    
    def __init__(self):
        self.alert_rules: Dict[str, Dict[str, Any]] = {}
        self.alert_history: deque = deque(maxlen=10000)
        self.notification_channels: Dict[str, Any] = {}
        
        self.alert_counter = Counter(
            "slo_alerts_total",
            "Total SLO alerts",
            ["slo_name", "severity", "type"]
        )
    
    def register_alert_rule(
        self,
        name: str,
        condition: Dict[str, Any],
        actions: List[Dict[str, Any]]
    ):
        """Register an alert rule."""
        self.alert_rules[name] = {
            "condition": condition,
            "actions": actions,
            "last_fired": None
        }
    
    async def process_compliance(
        self,
        compliance: SLOCompliance,
        budget_actions: List[Dict[str, Any]]
    ):
        """Process compliance and trigger alerts."""
        alerts = []
        
        # Check alert rules
        for rule_name, rule in self.alert_rules.items():
            if self._evaluate_condition(rule["condition"], compliance):
                # Check cooldown
                if self._should_fire_alert(rule):
                    alert = {
                        "rule_name": rule_name,
                        "slo_name": compliance.slo_name,
                        "severity": rule["condition"].get("severity", "warning"),
                        "timestamp": datetime.utcnow(),
                        "compliance": compliance.dict(),
                        "message": self._format_alert_message(rule, compliance)
                    }
                    alerts.append(alert)
                    rule["last_fired"] = datetime.utcnow()
        
        # Process budget actions as alerts
        for action in budget_actions:
            if action["type"] == "alert":
                alerts.append({
                    "rule_name": "error_budget_policy",
                    "slo_name": compliance.slo_name,
                    "severity": action["severity"],
                    "timestamp": datetime.utcnow(),
                    "compliance": compliance.dict(),
                    "message": action["message"]
                })
        
        # Send alerts
        for alert in alerts:
            await self._send_alert(alert)
            self.alert_counter.labels(
                slo_name=alert["slo_name"],
                severity=alert["severity"],
                type=alert.get("type", "threshold")
            ).inc()
            self.alert_history.append(alert)
    
    def _evaluate_condition(
        self,
        condition: Dict[str, Any],
        compliance: SLOCompliance
    ) -> bool:
        """Evaluate alert condition."""
        if "compliance_threshold" in condition:
            if compliance.compliance_percentage < condition["compliance_threshold"]:
                return True
        
        if "budget_threshold" in condition:
            if compliance.error_budget_remaining < condition["budget_threshold"]:
                return True
        
        if "trend" in condition:
            if compliance.trend == condition["trend"]:
                return True
        
        return False
    
    def _should_fire_alert(self, rule: Dict[str, Any]) -> bool:
        """Check if alert should fire based on cooldown."""
        if rule["last_fired"] is None:
            return True
        
        cooldown = rule.get("cooldown_minutes", 15)
        time_since_last = datetime.utcnow() - rule["last_fired"]
        return time_since_last > timedelta(minutes=cooldown)
    
    def _format_alert_message(
        self,
        rule: Dict[str, Any],
        compliance: SLOCompliance
    ) -> str:
        """Format alert message."""
        template = rule.get(
            "message_template",
            "SLO {slo_name} is {status} with {compliance_percentage:.2f}% compliance"
        )
        
        status = "breaching" if not compliance.is_compliant else "at risk"
        
        return template.format(
            slo_name=compliance.slo_name,
            status=status,
            compliance_percentage=compliance.compliance_percentage,
            error_budget_remaining=compliance.error_budget_remaining,
            trend=compliance.trend
        )
    
    async def _send_alert(self, alert: Dict[str, Any]):
        """Send alert through configured channels."""
        # This would integrate with actual notification systems
        logger.warning(f"SLO Alert: {alert['message']}")


class SLOReporter:
    """Generates SLO reports and analysis."""
    
    def __init__(self):
        self.compliance_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=10000)
        )
    
    def record_compliance(self, compliance: SLOCompliance):
        """Record compliance for historical analysis."""
        key = f"{compliance.slo_name}_{compliance.time_window.value}"
        self.compliance_history[key].append(compliance)
    
    def generate_report(
        self,
        slo_names: Optional[List[str]] = None,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        format: str = "json"
    ) -> Union[Dict[str, Any], str]:
        """Generate SLO compliance report."""
        if time_range is None:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=30)
        else:
            start_time, end_time = time_range
        
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "slos": {}
        }
        
        for key, history in self.compliance_history.items():
            slo_name = key.split("_")[0]
            
            if slo_names and slo_name not in slo_names:
                continue
            
            # Filter by time range
            relevant_history = [
                c for c in history
                if start_time <= c.calculated_at <= end_time
            ]
            
            if not relevant_history:
                continue
            
            # Calculate statistics
            compliance_values = [c.compliance_percentage for c in relevant_history]
            budget_values = [c.error_budget_remaining for c in relevant_history]
            
            report["slos"][key] = {
                "slo_name": slo_name,
                "time_window": relevant_history[0].time_window.value,
                "statistics": {
                    "average_compliance": sum(compliance_values) / len(compliance_values),
                    "min_compliance": min(compliance_values),
                    "max_compliance": max(compliance_values),
                    "average_error_budget": sum(budget_values) / len(budget_values),
                    "min_error_budget": min(budget_values),
                    "breaches": sum(1 for c in relevant_history if not c.is_compliant),
                    "total_evaluations": len(relevant_history)
                },
                "current_status": {
                    "compliance": relevant_history[-1].compliance_percentage,
                    "error_budget": relevant_history[-1].error_budget_remaining,
                    "trend": relevant_history[-1].trend,
                    "is_compliant": relevant_history[-1].is_compliant
                }
            }
        
        if format == "json":
            return report
        elif format == "markdown":
            return self._format_markdown_report(report)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _format_markdown_report(self, report: Dict[str, Any]) -> str:
        """Format report as markdown."""
        lines = [
            "# SLO Compliance Report",
            f"\nGenerated: {report['generated_at']}",\n            f"Period: {report['time_range']['start']} to {report['time_range']['end']}",\n            "\n## SLO Summary\n"\n        ]\n\n        for slo_key, slo_data in report["slos"].items():\n            lines.extend([\n                f"### {slo_data['slo_name']} ({slo_data['time_window']})",\n                f"- **Current Compliance**: {slo_data['current_status']['compliance']:.2f}%",\n                f"- **Error Budget Remaining**: {slo_data['current_status']['error_budget']:.2f}%",\n                f"- **Status**: {'✅ Compliant' if slo_data['current_status']['is_compliant'] else '❌ Non-compliant'}",\n                f"- **Trend**: {slo_data['current_status']['trend']}",\n                "\n**Statistics**:",\n                f"- Average Compliance: {slo_data['statistics']['average_compliance']:.2f}%",\n                f"- Min/Max Compliance: {slo_data['statistics']['min_compliance']:.2f}% / {slo_data['statistics']['max_compliance']:.2f}%",\n                f"- Breaches: {slo_data['statistics']['breaches']} / {slo_data['statistics']['total_evaluations']}",\n                "\n"\n            ])\n\n        return "\n".join(lines)\n\n    def analyze_trends(\n        self,\n        slo_name: str,\n        time_window: TimeWindow,\n        analysis_window: timedelta = timedelta(days=7)\n    ) -> Dict[str, Any]:\n        """Analyze SLO trends over time."""\n        key = f"{slo_name}_{time_window.value}"\n        history = self.compliance_history.get(key, deque())\n\n        if not history:\n            return {"error": "No historical data available"}\n\n        cutoff = datetime.utcnow() - analysis_window\n        recent_history = [c for c in history if c.calculated_at >= cutoff]\n\n        if len(recent_history) < 2:\n            return {"error": "Insufficient data for trend analysis"}\n\n        # Calculate trend metrics\n        compliance_values = [c.compliance_percentage for c in recent_history]\n        budget_values = [c.error_budget_remaining for c in recent_history]\n\n        # Simple moving averages\n        window_size = min(10, len(recent_history) // 2)\n        if window_size > 0:\n            recent_avg = sum(compliance_values[-window_size:]) / window_size\n            older_avg = sum(compliance_values[:window_size]) / window_size\n            improvement = recent_avg - older_avg\n        else:\n            improvement = 0\n\n        return {\n            "slo_name": slo_name,\n            "time_window": time_window.value,\n            "analysis_period": analysis_window.total_seconds() / 86400,  # days\n            "data_points": len(recent_history),\n            "trend": {\n                "overall": "improving" if improvement > 1 else "degrading" if improvement < -1 else "stable",\n                "improvement_percentage": improvement,\n                "current_compliance": compliance_values[-1],\n                "average_compliance": sum(compliance_values) / len(compliance_values),\n                "volatility": self._calculate_volatility(compliance_values)\n            },\n            "predictions": {\n                "estimated_breach_time": self._predict_breach_time(recent_history),\n                "confidence": self._calculate_prediction_confidence(compliance_values)\n            }\n        }\n\n    def _calculate_volatility(self, values: List[float]) -> float:\n        """Calculate volatility as standard deviation."""\n        if len(values) < 2:\n            return 0.0\n\n        mean = sum(values) / len(values)\n        variance = sum((x - mean) ** 2 for x in values) / len(values)\n        return variance ** 0.5\n\n    def _predict_breach_time(\n        self,\n        history: List[SLOCompliance]\n    ) -> Optional[str]:\n        """Predict when SLO might breach based on trends."""\n        if len(history) < 5:\n            return None\n\n        # Use the last forecast if available\n        recent_forecasts = [\n            c.forecast_breach_time\n            for c in history[-5:]\n            if c.forecast_breach_time\n        ]\n\n        if recent_forecasts:\n            # Return the median forecast\n            recent_forecasts.sort()\n            median_idx = len(recent_forecasts) // 2\n            return recent_forecasts[median_idx].isoformat()\n\n        return None\n\n    def _calculate_prediction_confidence(self, values: List[float]) -> float:\n        """Calculate confidence in predictions based on data stability."""\n        if len(values) < 10:\n            return 0.0\n\n        volatility = self._calculate_volatility(values)\n        # Lower volatility = higher confidence\n        confidence = max(0, min(100, 100 - volatility))\n        return confidence\n\n\nclass SLOGovernance:\n    """Manages SLO governance and review processes."""\n\n    def __init__(self):\n        self.review_schedule: Dict[str, Dict[str, Any]] = {}\n        self.review_history: List[Dict[str, Any]] = []\n        self.slo_changes: List[Dict[str, Any]] = []\n\n    def schedule_review(\n        self,\n        slo_name: str,\n        review_date: datetime,\n        reviewers: List[str],\n        review_type: str = "regular"\n    ):\n        """Schedule an SLO review."""\n        self.review_schedule[slo_name] = {\n            "review_date": review_date,\n            "reviewers": reviewers,\n            "review_type": review_type,\n            "status": "scheduled"\n        }\n\n    def record_review(\n        self,\n        slo_name: str,\n        review_date: datetime,\n        decisions: List[Dict[str, Any]],\n        next_review: Optional[datetime] = None\n    ):\n        """Record the outcome of an SLO review."""\n        review = {\n            "slo_name": slo_name,\n            "review_date": review_date,\n            "decisions": decisions,\n            "next_review": next_review or review_date + timedelta(days=90)\n        }\n\n        self.review_history.append(review)\n\n        # Update schedule\n        if slo_name in self.review_schedule:\n            self.review_schedule[slo_name]["status"] = "completed"\n\n        # Schedule next review\n        if next_review:\n            self.schedule_review(\n                slo_name,\n                next_review,\n                self.review_schedule.get(slo_name, {}).get("reviewers", []),\n                "regular"\n            )\n\n    def propose_slo_change(\n        self,\n        slo_name: str,\n        proposed_changes: Dict[str, Any],\n        justification: str,\n        proposer: str\n    ) -> str:\n        """Propose a change to an SLO."""\n        change_id = f"change_{slo_name}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"\n\n        self.slo_changes.append({\n            "change_id": change_id,\n            "slo_name": slo_name,\n            "proposed_changes": proposed_changes,\n            "justification": justification,\n            "proposer": proposer,\n            "proposed_date": datetime.utcnow(),\n            "status": "proposed",\n            "approvals": [],\n            "comments": []\n        })\n\n        return change_id\n\n    def approve_change(\n        self,\n        change_id: str,\n        approver: str,\n        comments: Optional[str] = None\n    ):\n        """Approve an SLO change."""\n        for change in self.slo_changes:\n            if change["change_id"] == change_id:\n                change["approvals"].append({\n                    "approver": approver,\n                    "approved_date": datetime.utcnow(),\n                    "comments": comments\n                })\n\n                # Auto-approve if enough approvals (e.g., 2)\n                if len(change["approvals"]) >= 2:\n                    change["status"] = "approved"\n\n                break\n\n    def get_pending_reviews(self) -> List[Dict[str, Any]]:\n        """Get list of pending SLO reviews."""\n        pending = []\n        current_time = datetime.utcnow()\n\n        for slo_name, schedule in self.review_schedule.items():\n            if (\n                schedule["status"] == "scheduled" and\n                schedule["review_date"] <= current_time\n            ):\n                pending.append({\n                    "slo_name": slo_name,\n                    "review_date": schedule["review_date"],\n                    "days_overdue": (current_time - schedule["review_date"]).days,\n                    "reviewers": schedule["reviewers"],\n                    "review_type": schedule["review_type"]\n                })\n\n        return sorted(pending, key=lambda x: x["days_overdue"], reverse=True)\n\n\nclass SLIComplianceDashboard:\n    """Dashboard data provider for SLO compliance visualization."""\n\n    def __init__(self, reporter: SLOReporter):\n        self.reporter = reporter\n\n    def get_dashboard_data(\n        self,\n        time_range: Optional[Tuple[datetime, datetime]] = None\n    ) -> Dict[str, Any]:\n        """Get data for SLO compliance dashboard."""\n        if time_range is None:\n            end_time = datetime.utcnow()\n            start_time = end_time - timedelta(hours=24)\n        else:\n            start_time, end_time = time_range\n\n        # Get report data\n        report = self.reporter.generate_report(time_range=(start_time, end_time))\n\n        # Calculate summary metrics\n        total_slos = len(report["slos"])\n        compliant_slos = sum(\n            1 for slo in report["slos"].values()\n            if slo["current_status"]["is_compliant"]\n        )\n\n        # Group by status\n        status_groups = {\n            "meeting": [],\n            "at_risk": [],\n            "breaching": []\n        }\n\n        for slo_key, slo_data in report["slos"].items():\n            status = self._determine_status(slo_data["current_status"])\n            status_groups[status].append(slo_data)\n\n        return {\n            "summary": {\n                "total_slos": total_slos,\n                "compliant_slos": compliant_slos,\n                "compliance_rate": (compliant_slos / total_slos * 100) if total_slos > 0 else 0,\n                "at_risk_count": len(status_groups["at_risk"]),\n                "breaching_count": len(status_groups["breaching"])\n            },\n            "slos_by_status": status_groups,\n            "time_range": {\n                "start": start_time.isoformat(),\n                "end": end_time.isoformat()\n            },\n            "generated_at": datetime.utcnow().isoformat()\n        }\n\n    def _determine_status(self, current_status: Dict[str, Any]) -> str:\n        """Determine SLO status category."""\n        if not current_status["is_compliant"]:\n            return "breaching"\n        elif current_status["error_budget"] < 20:\n            return "at_risk"\n        else:\n            return "meeting"\n\n    def get_time_series_data(\n        self,\n        slo_name: str,\n        time_window: TimeWindow,\n        points: int = 100\n    ) -> List[Dict[str, Any]]:\n        """Get time series data for charting."""\n        key = f"{slo_name}_{time_window.value}"\n        history = self.reporter.compliance_history.get(key, deque())\n\n        if not history:\n            return []\n\n        # Sample points evenly\n        step = max(1, len(history) // points)\n        sampled = list(history)[::step]\n\n        return [\n            {\n                "timestamp": c.calculated_at.isoformat(),\n                "compliance": c.compliance_percentage,\n                "error_budget": c.error_budget_remaining,\n                "is_compliant": c.is_compliant\n            }\n            for c in sampled\n        ]\n\n\nclass SLOTrackingSystem:\n    """Main SLO tracking system orchestrator."""\n\n    def __init__(self):\n        self.sli_collector = SLICollector()\n        self.slo_calculator = SLOCalculator()\n        self.error_budget_manager = ErrorBudgetManager()\n        self.alert_manager = SLOAlertManager()\n        self.reporter = SLOReporter()\n        self.governance = SLOGovernance()\n        self.dashboard = SLIComplianceDashboard(self.reporter)\n\n        self._running = False\n        self._tasks = []\n\n    async def initialize(self):\n        """Initialize the SLO tracking system."""\n        # Register data sources\n        prometheus_source = PrometheusDataSource("http://localhost:9090")\n        self.sli_collector.register_data_source("prometheus", prometheus_source)\n\n        # Load SLI/SLO definitions from configuration\n        await self._load_definitions()\n\n        logger.info("SLO tracking system initialized")\n\n    async def _load_definitions(self):\n        """Load SLI/SLO definitions from configuration."""\n        # Example definitions - would normally load from config\n\n        # API availability SLI\n        self.sli_collector.register_sli(SLIDefinition(\n            name="api_availability",\n            type=SLIType.AVAILABILITY,\n            description="API endpoint availability",\n            unit="ratio",\n            query='up{job="api"}',\n            aggregation="avg"\n        ))\n\n        # API latency SLI\n        self.sli_collector.register_sli(SLIDefinition(\n            name="api_latency_p99",\n            type=SLIType.LATENCY,\n            description="API 99th percentile latency",\n            unit="seconds",\n            query='histogram_quantile(0.99, http_request_duration_seconds_bucket{job="api"})',\n            aggregation="p99"\n        ))\n\n        # Error rate SLI\n        self.sli_collector.register_sli(SLIDefinition(\n            name="api_error_rate",\n            type=SLIType.ERROR_RATE,\n            description="API error rate",\n            unit="ratio",\n            query='rate(http_requests_total{job="api",status=~"5.."}[5m])',\n            aggregation="avg"\n        ))\n\n        # Register SLO targets\n        self.slo_calculator.register_slo(SLOTarget(\n            sli_name="api_availability",\n            target=99.9,\n            comparison="gte",\n            time_window=TimeWindow.ROLLING_30D,\n            description="API availability should be at least 99.9% over 30 days"\n        ))\n\n        self.slo_calculator.register_slo(SLOTarget(\n            sli_name="api_latency_p99",\n            target=1.0,\n            comparison="lte",\n            time_window=TimeWindow.ROLLING_24H,\n            description="API p99 latency should be less than 1 second over 24 hours"\n        ))\n\n        self.slo_calculator.register_slo(SLOTarget(\n            sli_name="api_error_rate",\n            target=0.1,\n            comparison="lte",\n            time_window=TimeWindow.ROLLING_1H,\n            description="API error rate should be less than 0.1% over 1 hour"\n        ))\n\n        # Register error budget policies\n        self.error_budget_manager.register_policy(ErrorBudgetPolicy(\n            name="api_availability_policy",\n            slo_name="api_availability",\n            actions=[\n                {\n                    "budget_threshold": 10,\n                    "type": "page_oncall",\n                    "message": "API availability error budget critically low"\n                }\n            ]\n        ))\n\n        # Register alert rules\n        self.alert_manager.register_alert_rule(\n            "api_availability_breach",\n            {\n                "compliance_threshold": 99.5,\n                "severity": "critical"\n            },\n            [\n                {\n                    "type": "webhook",\n                    "url": "https://alerts.example.com/slo"\n                }\n            ]\n        )\n\n    async def start(self):\n        """Start the SLO tracking system."""\n        self._running = True\n\n        # Start collection tasks\n        self._tasks.append(\n            asyncio.create_task(self._collection_loop())\n        )\n        self._tasks.append(\n            asyncio.create_task(self._evaluation_loop())\n        )\n\n        logger.info("SLO tracking system started")\n\n    async def stop(self):\n        """Stop the SLO tracking system."""\n        self._running = False\n\n        for task in self._tasks:\n            task.cancel()\n\n        await asyncio.gather(*self._tasks, return_exceptions=True)\n        logger.info("SLO tracking system stopped")\n\n    async def _collection_loop(self):\n        """Main collection loop."""\n        while self._running:\n            try:\n                # Collect SLI data for all registered SLIs\n                for sli_name in self.sli_collector.sli_definitions:\n                    try:\n                        end_time = datetime.utcnow()\n                        start_time = end_time - timedelta(minutes=5)\n\n                        await self.sli_collector.collect_sli(\n                            sli_name,\n                            start_time,\n                            end_time\n                        )\n                    except Exception as e:\n                        logger.error(f"Failed to collect SLI {sli_name}: {e}")\n\n                # Sleep for collection interval\n                await asyncio.sleep(60)  # Collect every minute\n\n            except asyncio.CancelledError:\n                break\n            except Exception as e:\n                logger.error(f"Error in collection loop: {e}")\n                await asyncio.sleep(60)\n\n    async def _evaluation_loop(self):\n        """Main evaluation loop."""\n        while self._running:\n            try:\n                # Evaluate all SLOs\n                for slo_key, slo in self.slo_calculator.slo_targets.items():\n                    try:\n                        # Get time window for data\n                        window_duration = self._get_window_duration(slo.time_window)\n                        end_time = datetime.utcnow()\n                        start_time = end_time - window_duration\n\n                        # Get SLI data\n                        sli_data = await self.sli_collector.collect_sli(\n                            slo.sli_name,\n                            start_time,\n                            end_time\n                        )\n\n                        if not sli_data:\n                            continue\n\n                        # Calculate compliance\n                        compliance = self.slo_calculator.calculate_compliance(\n                            sli_data,\n                            slo\n                        )\n\n                        # Record compliance\n                        self.reporter.record_compliance(compliance)\n\n                        # Evaluate error budget\n                        budget_actions = await self.error_budget_manager.evaluate_budget(\n                            compliance\n                        )\n\n                        # Process alerts\n                        await self.alert_manager.process_compliance(\n                            compliance,\n                            budget_actions\n                        )\n\n                    except Exception as e:\n                        logger.error(f"Failed to evaluate SLO {slo_key}: {e}")\n\n                # Sleep for evaluation interval\n                await asyncio.sleep(300)  # Evaluate every 5 minutes\n\n            except asyncio.CancelledError:\n                break\n            except Exception as e:\n                logger.error(f"Error in evaluation loop: {e}")\n                await asyncio.sleep(300)\n\n    def _get_window_duration(self, window: TimeWindow) -> timedelta:\n        """Get duration for time window."""\n        durations = {\n            TimeWindow.ROLLING_1H: timedelta(hours=1),\n            TimeWindow.ROLLING_24H: timedelta(hours=24),\n            TimeWindow.ROLLING_7D: timedelta(days=7),\n            TimeWindow.ROLLING_30D: timedelta(days=30),\n            TimeWindow.CALENDAR_MONTH: timedelta(days=30),\n            TimeWindow.CALENDAR_QUARTER: timedelta(days=90)\n        }\n        return durations.get(window, timedelta(days=30))\n\n\n# Example usage\nif __name__ == "__main__":\n    async def main():\n        system = SLOTrackingSystem()\n        await system.initialize()\n        await system.start()\n\n        try:\n            # Run for demonstration\n            await asyncio.sleep(3600)\n        finally:\n            await system.stop()\n\n    asyncio.run(main())