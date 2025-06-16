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
            f"\nGenerated: {report['generated_at']}",
            f"Period: {report['time_range']['start']} to {report['time_range']['end']}",
            "\n## SLO Summary\n"
        ]
        
        for slo_key, slo_data in report["slos"].items():
            lines.extend([
                f"### {slo_data['slo_name']} ({slo_data['time_window']})",
                f"- **Current Compliance**: {slo_data['current_status']['compliance']:.2f}%",
                f"- **Error Budget Remaining**: {slo_data['current_status']['error_budget']:.2f}%",
                f"- **Status**: {'✅ Compliant' if slo_data['current_status']['is_compliant'] else '❌ Non-compliant'}",
                f"- **Trend**: {slo_data['current_status']['trend']}",
                "\n**Statistics**:",
                f"- Average Compliance: {slo_data['statistics']['average_compliance']:.2f}%",
                f"- Min/Max Compliance: {slo_data['statistics']['min_compliance']:.2f}% / {slo_data['statistics']['max_compliance']:.2f}%",
                f"- Breaches: {slo_data['statistics']['breaches']} / {slo_data['statistics']['total_evaluations']}",
                "\n"
            ])
        
        return "\n".join(lines)
    
    def analyze_trends(
        self,
        slo_name: str,
        time_window: TimeWindow,
        analysis_window: timedelta = timedelta(days=7)
    ) -> Dict[str, Any]:
        """Analyze SLO trends over time."""
        key = f"{slo_name}_{time_window.value}"
        history = self.compliance_history.get(key, deque())
        
        if not history:
            return {"error": "No historical data available"}
        
        cutoff = datetime.utcnow() - analysis_window
        recent_history = [c for c in history if c.calculated_at >= cutoff]
        
        if len(recent_history) < 2:
            return {"error": "Insufficient data for trend analysis"}
        
        # Calculate trend metrics
        compliance_values = [c.compliance_percentage for c in recent_history]
        budget_values = [c.error_budget_remaining for c in recent_history]
        
        # Simple moving averages
        window_size = min(10, len(recent_history) // 2)
        if window_size > 0:
            recent_avg = sum(compliance_values[-window_size:]) / window_size
            older_avg = sum(compliance_values[:window_size]) / window_size
            improvement = recent_avg - older_avg
        else:
            improvement = 0
        
        return {
            "slo_name": slo_name,
            "time_window": time_window.value,
            "analysis_period": analysis_window.total_seconds() / 86400,  # days
            "data_points": len(recent_history),
            "trend": {
                "overall": "improving" if improvement > 1 else "degrading" if improvement < -1 else "stable",
                "improvement_percentage": improvement,
                "current_compliance": compliance_values[-1],
                "average_compliance": sum(compliance_values) / len(compliance_values),
                "volatility": self._calculate_volatility(compliance_values)
            },
            "predictions": {
                "estimated_breach_time": self._predict_breach_time(recent_history),
                "confidence": self._calculate_prediction_confidence(compliance_values)
            }
        }
    
    def _calculate_volatility(self, values: List[float]) -> float:
        """Calculate volatility as standard deviation."""
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5
    
    def _predict_breach_time(
        self,
        history: List[SLOCompliance]
    ) -> Optional[str]:
        """Predict when SLO might breach based on trends."""
        if len(history) < 5:
            return None
        
        # Use the last forecast if available
        recent_forecasts = [
            c.forecast_breach_time
            for c in history[-5:]
            if c.forecast_breach_time
        ]
        
        if recent_forecasts:
            # Return the median forecast
            recent_forecasts.sort()
            median_idx = len(recent_forecasts) // 2
            return recent_forecasts[median_idx].isoformat()
        
        return None
    
    def _calculate_prediction_confidence(self, values: List[float]) -> float:
        """Calculate confidence in predictions based on data stability."""
        if len(values) < 10:
            return 0.0
        
        volatility = self._calculate_volatility(values)
        # Lower volatility = higher confidence
        confidence = max(0, min(100, 100 - volatility))
        return confidence


class SLOGovernance:
    """Manages SLO governance and review processes."""
    
    def __init__(self):
        self.review_schedule: Dict[str, Dict[str, Any]] = {}
        self.review_history: List[Dict[str, Any]] = []
        self.slo_changes: List[Dict[str, Any]] = []
    
    def schedule_review(
        self,
        slo_name: str,
        review_date: datetime,
        reviewers: List[str],
        review_type: str = "regular"
    ):
        """Schedule an SLO review."""
        self.review_schedule[slo_name] = {
            "review_date": review_date,
            "reviewers": reviewers,
            "review_type": review_type,
            "status": "scheduled"
        }
    
    def record_review(
        self,
        slo_name: str,
        review_date: datetime,
        decisions: List[Dict[str, Any]],
        next_review: Optional[datetime] = None
    ):
        """Record the outcome of an SLO review."""
        review = {
            "slo_name": slo_name,
            "review_date": review_date,
            "decisions": decisions,
            "next_review": next_review or review_date + timedelta(days=90)
        }
        
        self.review_history.append(review)
        
        # Update schedule
        if slo_name in self.review_schedule:
            self.review_schedule[slo_name]["status"] = "completed"
        
        # Schedule next review
        if next_review:
            self.schedule_review(
                slo_name,
                next_review,
                self.review_schedule.get(slo_name, {}).get("reviewers", []),
                "regular"
            )
    
    def propose_slo_change(
        self,
        slo_name: str,
        proposed_changes: Dict[str, Any],
        justification: str,
        proposer: str
    ) -> str:
        """Propose a change to an SLO."""
        change_id = f"change_{slo_name}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        self.slo_changes.append({
            "change_id": change_id,
            "slo_name": slo_name,
            "proposed_changes": proposed_changes,
            "justification": justification,
            "proposer": proposer,
            "proposed_date": datetime.utcnow(),
            "status": "proposed",
            "approvals": [],
            "comments": []
        })
        
        return change_id
    
    def approve_change(
        self,
        change_id: str,
        approver: str,
        comments: Optional[str] = None
    ):
        """Approve an SLO change."""
        for change in self.slo_changes:
            if change["change_id"] == change_id:
                change["approvals"].append({
                    "approver": approver,
                    "approved_date": datetime.utcnow(),
                    "comments": comments
                })
                
                # Auto-approve if enough approvals (e.g., 2)
                if len(change["approvals"]) >= 2:
                    change["status"] = "approved"
                
                break
    
    def get_pending_reviews(self) -> List[Dict[str, Any]]:
        """Get list of pending SLO reviews."""
        pending = []
        current_time = datetime.utcnow()
        
        for slo_name, schedule in self.review_schedule.items():
            if (
                schedule["status"] == "scheduled" and
                schedule["review_date"] <= current_time
            ):
                pending.append({
                    "slo_name": slo_name,
                    "review_date": schedule["review_date"],
                    "days_overdue": (current_time - schedule["review_date"]).days,
                    "reviewers": schedule["reviewers"],
                    "review_type": schedule["review_type"]
                })
        
        return sorted(pending, key=lambda x: x["days_overdue"], reverse=True)


class SLIComplianceDashboard:
    """Dashboard data provider for SLO compliance visualization."""
    
    def __init__(self, reporter: SLOReporter):
        self.reporter = reporter
    
    def get_dashboard_data(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> Dict[str, Any]:
        """Get data for SLO compliance dashboard."""
        if time_range is None:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=24)
        else:
            start_time, end_time = time_range
        
        # Get report data
        report = self.reporter.generate_report(time_range=(start_time, end_time))
        
        # Calculate summary metrics
        total_slos = len(report["slos"])
        compliant_slos = sum(
            1 for slo in report["slos"].values()
            if slo["current_status"]["is_compliant"]
        )
        
        # Group by status
        status_groups = {
            "meeting": [],
            "at_risk": [],
            "breaching": []
        }
        
        for slo_key, slo_data in report["slos"].items():
            status = self._determine_status(slo_data["current_status"])
            status_groups[status].append(slo_data)
        
        return {
            "summary": {
                "total_slos": total_slos,
                "compliant_slos": compliant_slos,
                "compliance_rate": (compliant_slos / total_slos * 100) if total_slos > 0 else 0,
                "at_risk_count": len(status_groups["at_risk"]),
                "breaching_count": len(status_groups["breaching"])
            },
            "slos_by_status": status_groups,
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def _determine_status(self, current_status: Dict[str, Any]) -> str:
        """Determine SLO status category."""
        if not current_status["is_compliant"]:
            return "breaching"
        elif current_status["error_budget"] < 20:
            return "at_risk"
        else:
            return "meeting"
    
    def get_time_series_data(
        self,
        slo_name: str,
        time_window: TimeWindow,
        points: int = 100
    ) -> List[Dict[str, Any]]:
        """Get time series data for charting."""
        key = f"{slo_name}_{time_window.value}"
        history = self.reporter.compliance_history.get(key, deque())
        
        if not history:
            return []
        
        # Sample points evenly
        step = max(1, len(history) // points)
        sampled = list(history)[::step]
        
        return [
            {
                "timestamp": c.calculated_at.isoformat(),
                "compliance": c.compliance_percentage,
                "error_budget": c.error_budget_remaining,
                "is_compliant": c.is_compliant
            }
            for c in sampled
        ]


class SLOTrackingSystem:
    """Main SLO tracking system orchestrator."""
    
    def __init__(self):
        self.sli_collector = SLICollector()
        self.slo_calculator = SLOCalculator()
        self.error_budget_manager = ErrorBudgetManager()
        self.alert_manager = SLOAlertManager()
        self.reporter = SLOReporter()
        self.governance = SLOGovernance()
        self.dashboard = SLIComplianceDashboard(self.reporter)
        
        self._running = False
        self._tasks = []
    
    async def initialize(self):
        """Initialize the SLO tracking system."""
        # Register data sources
        prometheus_source = PrometheusDataSource("http://localhost:9090")
        self.sli_collector.register_data_source("prometheus", prometheus_source)
        
        # Load SLI/SLO definitions from configuration
        await self._load_definitions()
        
        logger.info("SLO tracking system initialized")
    
    async def _load_definitions(self):
        """Load SLI/SLO definitions from configuration."""
        # Example definitions - would normally load from config
        
        # API availability SLI
        self.sli_collector.register_sli(SLIDefinition(
            name="api_availability",
            type=SLIType.AVAILABILITY,
            description="API endpoint availability",
            unit="ratio",
            query='up{job="api"}',
            aggregation="avg"
        ))
        
        # API latency SLI
        self.sli_collector.register_sli(SLIDefinition(
            name="api_latency_p99",
            type=SLIType.LATENCY,
            description="API 99th percentile latency",
            unit="seconds",
            query='histogram_quantile(0.99, http_request_duration_seconds_bucket{job="api"})',
            aggregation="p99"
        ))
        
        # Error rate SLI
        self.sli_collector.register_sli(SLIDefinition(
            name="api_error_rate",
            type=SLIType.ERROR_RATE,
            description="API error rate",
            unit="ratio",
            query='rate(http_requests_total{job="api",status=~"5.."}[5m])',
            aggregation="avg"
        ))
        
        # Register SLO targets
        self.slo_calculator.register_slo(SLOTarget(
            sli_name="api_availability",
            target=99.9,
            comparison="gte",
            time_window=TimeWindow.ROLLING_30D,
            description="API availability should be at least 99.9% over 30 days"
        ))
        
        self.slo_calculator.register_slo(SLOTarget(
            sli_name="api_latency_p99",
            target=1.0,
            comparison="lte",
            time_window=TimeWindow.ROLLING_24H,
            description="API p99 latency should be less than 1 second over 24 hours"
        ))
        
        self.slo_calculator.register_slo(SLOTarget(
            sli_name="api_error_rate",
            target=0.1,
            comparison="lte",
            time_window=TimeWindow.ROLLING_1H,
            description="API error rate should be less than 0.1% over 1 hour"
        ))
        
        # Register error budget policies
        self.error_budget_manager.register_policy(ErrorBudgetPolicy(
            name="api_availability_policy",
            slo_name="api_availability",
            actions=[
                {
                    "budget_threshold": 10,
                    "type": "page_oncall",
                    "message": "API availability error budget critically low"
                }
            ]
        ))
        
        # Register alert rules
        self.alert_manager.register_alert_rule(
            "api_availability_breach",
            {
                "compliance_threshold": 99.5,
                "severity": "critical"
            },
            [
                {
                    "type": "webhook",
                    "url": "https://alerts.example.com/slo"
                }
            ]
        )
    
    async def start(self):
        """Start the SLO tracking system."""
        self._running = True
        
        # Start collection tasks
        self._tasks.append(
            asyncio.create_task(self._collection_loop())
        )
        self._tasks.append(
            asyncio.create_task(self._evaluation_loop())
        )
        
        logger.info("SLO tracking system started")
    
    async def stop(self):
        """Stop the SLO tracking system."""
        self._running = False
        
        for task in self._tasks:
            task.cancel()
        
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("SLO tracking system stopped")
    
    async def _collection_loop(self):
        """Main collection loop."""
        while self._running:
            try:
                # Collect SLI data for all registered SLIs
                for sli_name in self.sli_collector.sli_definitions:
                    try:
                        end_time = datetime.utcnow()
                        start_time = end_time - timedelta(minutes=5)
                        
                        await self.sli_collector.collect_sli(
                            sli_name,
                            start_time,
                            end_time
                        )
                    except Exception as e:
                        logger.error(f"Failed to collect SLI {sli_name}: {e}")
                
                # Sleep for collection interval
                await asyncio.sleep(60)  # Collect every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")
                await asyncio.sleep(60)
    
    async def _evaluation_loop(self):
        """Main evaluation loop."""
        while self._running:
            try:
                # Evaluate all SLOs
                for slo_key, slo in self.slo_calculator.slo_targets.items():
                    try:
                        # Get time window for data
                        window_duration = self._get_window_duration(slo.time_window)
                        end_time = datetime.utcnow()
                        start_time = end_time - window_duration
                        
                        # Get SLI data
                        sli_data = await self.sli_collector.collect_sli(
                            slo.sli_name,
                            start_time,
                            end_time
                        )
                        
                        if not sli_data:
                            continue
                        
                        # Calculate compliance
                        compliance = self.slo_calculator.calculate_compliance(
                            sli_data,
                            slo
                        )
                        
                        # Record compliance
                        self.reporter.record_compliance(compliance)
                        
                        # Evaluate error budget
                        budget_actions = await self.error_budget_manager.evaluate_budget(
                            compliance
                        )
                        
                        # Process alerts
                        await self.alert_manager.process_compliance(
                            compliance,
                            budget_actions
                        )
                        
                    except Exception as e:
                        logger.error(f"Failed to evaluate SLO {slo_key}: {e}")
                
                # Sleep for evaluation interval
                await asyncio.sleep(300)  # Evaluate every 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in evaluation loop: {e}")
                await asyncio.sleep(300)
    
    def _get_window_duration(self, window: TimeWindow) -> timedelta:
        """Get duration for time window."""
        durations = {
            TimeWindow.ROLLING_1H: timedelta(hours=1),
            TimeWindow.ROLLING_24H: timedelta(hours=24),
            TimeWindow.ROLLING_7D: timedelta(days=7),
            TimeWindow.ROLLING_30D: timedelta(days=30),
            TimeWindow.CALENDAR_MONTH: timedelta(days=30),
            TimeWindow.CALENDAR_QUARTER: timedelta(days=90)
        }
        return durations.get(window, timedelta(days=30))


# Example usage
if __name__ == "__main__":
    async def main():
        system = SLOTrackingSystem()
        await system.initialize()
        await system.start()
        
        try:
            # Run for demonstration
            await asyncio.sleep(3600)
        finally:
            await system.stop()
    
    asyncio.run(main())