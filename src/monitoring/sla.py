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
        
        # Mock implementation - in real system, would query Prometheus
        # This is where you'd integrate with your metrics backend
        
        if objective.type == SLAType.AVAILABILITY:
            # Simulate availability check
            current_value = 99.95  # Mock value
            compliance = current_value
            
        elif objective.type == SLAType.LATENCY:
            # Simulate latency check
            compliance = 96.5  # Mock: 96.5% of requests under threshold
            current_value = compliance
            
        elif objective.type == SLAType.ERROR_RATE:
            # Simulate error rate check
            success_rate = 99.2  # Mock: 0.8% error rate
            current_value = success_rate
            compliance = success_rate
            
        else:
            # Custom SLA
            current_value = 100.0
            compliance = 100.0
        
        # Calculate error budget
        error_budget = self.calculate_error_budget(objective, compliance)
        
        # Update metrics
        self.metrics_collector.update_sla_compliance(objective.name, compliance)
        self.error_budget_consumed.labels(sla_name=objective.name).set(100 - error_budget)
        
        # Check for violations
        violations = []
        if compliance < objective.target:
            self.sla_violations_total.labels(
                sla_name=objective.name,
                sla_type=objective.type.value
            ).inc()
            
            violations.append({
                "timestamp": datetime.now().isoformat(),
                "compliance": compliance,
                "target": objective.target,
                "severity": "high" if error_budget < 10 else "medium"
            })
        
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
    
    def get_error_budget_burn_rate(
        self,
        objective_name: str,
        time_window: timedelta = timedelta(hours=1)
    ) -> float:
        """Calculate error budget burn rate."""
        # In a real implementation, this would calculate the rate
        # at which the error budget is being consumed
        # Mock implementation
        return 1.5  # 1.5x normal burn rate
    
    def predict_budget_exhaustion(
        self,
        objective_name: str,
        current_burn_rate: float
    ) -> Optional[datetime]:
        """Predict when error budget will be exhausted."""
        if objective_name not in self.objectives:
            return None
        
        # Mock implementation
        # In reality, would calculate based on current burn rate
        if current_burn_rate > 2.0:
            return datetime.now() + timedelta(days=5)
        elif current_burn_rate > 1.0:
            return datetime.now() + timedelta(days=15)
        else:
            return None  # Budget won't be exhausted


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