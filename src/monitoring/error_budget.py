"""
Advanced error budget tracking and burn rate analysis.

Provides:
- Real-time error budget monitoring
- Burn rate calculations and predictions
- Multi-window burn rate analysis
- Alert-worthy budget exhaustion predictions
"""

import asyncio
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import statistics
import logging

from .sla import SLATracker, SLAObjective, get_sla_tracker
from .prometheus_client import get_prometheus_client, PrometheusClient

__all__ = [
    "BurnRateWindow",
    "ErrorBudgetStatus",
    "BurnRateAlert",
    "ErrorBudgetTracker",
    "get_error_budget_tracker"
]

logger = logging.getLogger(__name__)


class BurnRateWindow(Enum):
    """Time windows for burn rate analysis."""
    SHORT = "1h"      # 1 hour
    MEDIUM = "6h"     # 6 hours  
    LONG = "24h"      # 24 hours
    EXTENDED = "72h"  # 3 days


@dataclass
class ErrorBudgetStatus:
    """Current error budget status for an SLA objective."""
    objective_name: str
    total_budget_percent: float
    consumed_percent: float
    remaining_percent: float
    
    # Burn rates for different windows
    burn_rates: Dict[str, float] = field(default_factory=dict)
    
    # Predictions
    exhaustion_predictions: Dict[str, Optional[datetime]] = field(default_factory=dict)
    
    # Risk assessment
    risk_level: str = "low"  # low, medium, high, critical
    
    # Historical context
    budget_consumed_last_24h: float = 0.0
    budget_consumed_last_week: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "objective_name": self.objective_name,
            "total_budget_percent": self.total_budget_percent,
            "consumed_percent": self.consumed_percent,
            "remaining_percent": self.remaining_percent,
            "burn_rates": self.burn_rates,
            "exhaustion_predictions": {
                window: pred.isoformat() if pred else None
                for window, pred in self.exhaustion_predictions.items()
            },
            "risk_level": self.risk_level,
            "budget_consumed_last_24h": self.budget_consumed_last_24h,
            "budget_consumed_last_week": self.budget_consumed_last_week
        }


@dataclass
class BurnRateAlert:
    """Alert for concerning burn rates."""
    objective_name: str
    window: str
    burn_rate: float
    severity: str
    message: str
    predicted_exhaustion: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "objective_name": self.objective_name,
            "window": self.window,
            "burn_rate": self.burn_rate,
            "severity": self.severity,
            "message": self.message,
            "predicted_exhaustion": self.predicted_exhaustion.isoformat() if self.predicted_exhaustion else None
        }


class ErrorBudgetTracker:
    """Advanced error budget tracking and analysis."""
    
    def __init__(self):
        self.sla_tracker = get_sla_tracker()
        self.prometheus_client = get_prometheus_client()
        
        # Burn rate thresholds for alerting
        self.burn_rate_thresholds = {
            BurnRateWindow.SHORT.value: {
                "high": 14.4,      # Will exhaust budget in 2 hours at this rate
                "critical": 28.8   # Will exhaust budget in 1 hour
            },
            BurnRateWindow.MEDIUM.value: {
                "high": 6.0,       # Will exhaust budget in 12 hours
                "critical": 12.0   # Will exhaust budget in 6 hours
            },
            BurnRateWindow.LONG.value: {
                "high": 3.0,       # Will exhaust budget in 2 days
                "critical": 6.0    # Will exhaust budget in 1 day
            },
            BurnRateWindow.EXTENDED.value: {
                "high": 2.0,       # Will exhaust budget in 1.5 days
                "critical": 4.0    # Will exhaust budget in 18 hours
            }
        }
    
    async def get_error_budget_status(self, objective_name: str) -> ErrorBudgetStatus:
        \"\"\"Get comprehensive error budget status for an objective.\"\"\"
        if objective_name not in self.sla_tracker.objectives:
            raise ValueError(f\"Unknown SLA objective: {objective_name}\")
        
        objective = self.sla_tracker.objectives[objective_name]
        
        # Get current SLA report
        current_report = await self.sla_tracker.check_objective(objective)
        
        # Calculate total error budget (100 - target)
        total_budget = 100 - objective.target
        current_failure_rate = 100 - current_report.compliance_percent
        
        consumed_percent = (current_failure_rate / total_budget * 100) if total_budget > 0 else 0
        remaining_percent = max(0, 100 - consumed_percent)
        
        # Calculate burn rates for different windows
        burn_rates = {}
        for window in BurnRateWindow:
            try:
                burn_rate = await self._calculate_burn_rate(objective_name, window.value)
                burn_rates[window.value] = burn_rate
            except Exception as e:
                logger.warning(f\"Failed to calculate {window.value} burn rate for {objective_name}: {e}\")
                burn_rates[window.value] = 0.0
        
        # Predict exhaustion times
        exhaustion_predictions = {}
        for window, rate in burn_rates.items():
            prediction = self._predict_exhaustion_time(remaining_percent, rate)
            exhaustion_predictions[window] = prediction
        
        # Assess risk level
        risk_level = self._assess_budget_risk(burn_rates, remaining_percent)
        
        # Get historical consumption
        budget_24h = await self._get_historical_budget_consumption(objective_name, timedelta(hours=24))
        budget_week = await self._get_historical_budget_consumption(objective_name, timedelta(days=7))
        
        return ErrorBudgetStatus(
            objective_name=objective_name,
            total_budget_percent=total_budget,
            consumed_percent=consumed_percent,
            remaining_percent=remaining_percent,
            burn_rates=burn_rates,
            exhaustion_predictions=exhaustion_predictions,
            risk_level=risk_level,
            budget_consumed_last_24h=budget_24h,
            budget_consumed_last_week=budget_week
        )
    
    async def _calculate_burn_rate(self, objective_name: str, window: str) -> float:
        \"\"\"Calculate error budget burn rate for a specific time window.\"\"\"
        objective = self.sla_tracker.objectives[objective_name]
        service_name = objective.labels.get('service', 'claude-api')
        
        # Parse window duration
        window_duration = self._parse_window_duration(window)
        end_time = datetime.now()
        start_time = end_time - window_duration
        
        if objective.type.value == \"availability\":
            # For availability SLOs, calculate based on uptime
            availability = await self.prometheus_client.get_metric_availability(
                service_name, start_time, end_time
            )
            failure_rate = 100 - availability
            
        elif objective.type.value == \"error_rate\":
            # For error rate SLOs, get error rate directly
            failure_rate = await self.prometheus_client.get_error_rate(
                service_name, start_time, end_time
            )
            
        elif objective.type.value == \"latency\":
            # For latency SLOs, calculate based on threshold violations
            latency_p95 = await self.prometheus_client.get_latency_percentile(
                service_name, 0.95, start_time, end_time
            )
            latency_ms = latency_p95 * 1000 if latency_p95 < 100 else latency_p95
            
            # Failure rate is when latency exceeds threshold
            if latency_ms > objective.latency_threshold_ms:
                failure_rate = ((latency_ms - objective.latency_threshold_ms) / 
                              objective.latency_threshold_ms) * 100
            else:
                failure_rate = 0.0
        
        else:
            # Fallback for other types
            failure_rate = 0.0
        
        # Calculate burn rate (how much budget consumed vs normal rate)
        error_budget = 100 - objective.target
        if error_budget == 0:
            return 0.0
        
        # Normal burn rate would be error_budget / measurement_window
        normal_rate = error_budget / (objective.measurement_window.total_seconds() / 3600)  # per hour
        current_rate = failure_rate  # Current failure rate
        
        # Burn rate is the multiple of normal consumption
        if normal_rate == 0:
            return 0.0
        
        burn_rate = current_rate / normal_rate
        return max(0.0, burn_rate)
    
    def _parse_window_duration(self, window: str) -> timedelta:
        \"\"\"Parse window string to timedelta.\"\"\"
        if window.endswith('h'):
            hours = int(window[:-1])
            return timedelta(hours=hours)
        elif window.endswith('d'):
            days = int(window[:-1])
            return timedelta(days=days)
        elif window.endswith('m'):
            minutes = int(window[:-1])
            return timedelta(minutes=minutes)
        else:
            # Default to 1 hour
            return timedelta(hours=1)
    
    def _predict_exhaustion_time(self, 
                               remaining_percent: float, 
                               burn_rate: float) -> Optional[datetime]:
        \"\"\"Predict when error budget will be exhausted.\"\"\"
        if burn_rate <= 0 or remaining_percent <= 0:
            return None
        
        if remaining_percent >= 99:
            return None  # Plenty of budget
        
        # Simple linear extrapolation
        # At current burn rate, how long until budget is exhausted?
        hours_to_exhaustion = remaining_percent / (burn_rate * 0.1)  # Rough estimate
        
        if hours_to_exhaustion > 24 * 30:  # More than 30 days
            return None
        
        return datetime.now() + timedelta(hours=hours_to_exhaustion)
    
    def _assess_budget_risk(self, 
                          burn_rates: Dict[str, float], 
                          remaining_percent: float) -> str:
        \"\"\"Assess overall risk level based on burn rates and remaining budget.\"\"\"
        if remaining_percent <= 5:
            return \"critical\"
        
        if remaining_percent <= 10:
            return \"high\"
        
        # Check burn rates against thresholds
        critical_burns = 0
        high_burns = 0
        
        for window, rate in burn_rates.items():
            thresholds = self.burn_rate_thresholds.get(window, {})
            
            if rate >= thresholds.get(\"critical\", float('inf')):
                critical_burns += 1
            elif rate >= thresholds.get(\"high\", float('inf')):
                high_burns += 1
        
        if critical_burns > 0:
            return \"critical\"
        elif high_burns >= 2:  # Multiple windows showing high burn
            return \"high\"
        elif high_burns > 0 or remaining_percent <= 25:
            return \"medium\"
        else:
            return \"low\"
    
    async def _get_historical_budget_consumption(self, 
                                               objective_name: str, 
                                               period: timedelta) -> float:
        \"\"\"Get error budget consumption over historical period.\"\"\"
        try:
            objective = self.sla_tracker.objectives[objective_name]
            
            # Get SLA status at start and end of period
            end_time = datetime.now()
            start_time = end_time - period
            
            current_report = await self.sla_tracker.check_objective(objective)
            past_report = await self.sla_tracker.check_objective(
                objective, (start_time, start_time + timedelta(minutes=5))
            )
            
            # Calculate consumption difference
            current_consumed = 100 - current_report.error_budget_remaining
            past_consumed = 100 - past_report.error_budget_remaining
            
            consumption = current_consumed - past_consumed
            return max(0.0, consumption)
            
        except Exception as e:
            logger.warning(f\"Failed to get historical consumption for {objective_name}: {e}\")
            return 0.0
    
    async def check_burn_rate_alerts(self) -> List[BurnRateAlert]:
        \"\"\"Check all objectives for concerning burn rates.\"\"\"
        alerts = []
        
        for objective_name in self.sla_tracker.objectives.keys():
            try:
                status = await self.get_error_budget_status(objective_name)
                
                # Check each window for alerting thresholds
                for window, burn_rate in status.burn_rates.items():
                    thresholds = self.burn_rate_thresholds.get(window, {})
                    
                    severity = None
                    if burn_rate >= thresholds.get(\"critical\", float('inf')):
                        severity = \"critical\"
                    elif burn_rate >= thresholds.get(\"high\", float('inf')):
                        severity = \"high\"
                    
                    if severity:
                        prediction = status.exhaustion_predictions.get(window)
                        
                        message = (
                            f\"High error budget burn rate detected for {objective_name} \"
                            f\"({window} window): {burn_rate:.2f}x normal rate\"
                        )
                        
                        if prediction:
                            message += f\". Budget may be exhausted by {prediction.strftime('%Y-%m-%d %H:%M')}\"
                        
                        alerts.append(BurnRateAlert(
                            objective_name=objective_name,
                            window=window,
                            burn_rate=burn_rate,
                            severity=severity,
                            message=message,
                            predicted_exhaustion=prediction
                        ))
            
            except Exception as e:
                logger.error(f\"Error checking burn rate for {objective_name}: {e}\")
        
        return alerts
    
    async def get_budget_summary(self) -> Dict[str, Any]:
        \"\"\"Get summary of error budget status across all objectives.\"\"\"
        summary = {
            \"timestamp\": datetime.now().isoformat(),
            \"objectives\": {},
            \"overall_risk\": \"low\",
            \"alerts\": [],
            \"statistics\": {
                \"total_objectives\": 0,
                \"high_risk_objectives\": 0,
                \"average_remaining_budget\": 0.0,
                \"lowest_remaining_budget\": 100.0
            }
        }
        
        budget_statuses = []
        
        for objective_name in self.sla_tracker.objectives.keys():
            try:
                status = await self.get_error_budget_status(objective_name)
                summary[\"objectives\"][objective_name] = status.to_dict()
                budget_statuses.append(status)
                
            except Exception as e:
                logger.error(f\"Error getting budget status for {objective_name}: {e}\")
        
        # Get burn rate alerts
        burn_rate_alerts = await self.check_burn_rate_alerts()
        summary[\"alerts\"] = [alert.to_dict() for alert in burn_rate_alerts]
        
        # Calculate statistics
        if budget_statuses:
            summary[\"statistics\"][\"total_objectives\"] = len(budget_statuses)
            summary[\"statistics\"][\"high_risk_objectives\"] = sum(
                1 for status in budget_statuses 
                if status.risk_level in [\"high\", \"critical\"]
            )
            
            remaining_budgets = [status.remaining_percent for status in budget_statuses]
            summary[\"statistics\"][\"average_remaining_budget\"] = sum(remaining_budgets) / len(remaining_budgets)
            summary[\"statistics\"][\"lowest_remaining_budget\"] = min(remaining_budgets)
            
            # Determine overall risk
            risk_levels = [status.risk_level for status in budget_statuses]
            if \"critical\" in risk_levels:
                summary[\"overall_risk\"] = \"critical\"
            elif \"high\" in risk_levels:
                summary[\"overall_risk\"] = \"high\"
            elif \"medium\" in risk_levels:
                summary[\"overall_risk\"] = \"medium\"
        
        return summary


# Global error budget tracker instance
_error_budget_tracker: Optional[ErrorBudgetTracker] = None


def get_error_budget_tracker() -> ErrorBudgetTracker:
    \"\"\"Get the global error budget tracker instance.\"\"\"
    global _error_budget_tracker
    if _error_budget_tracker is None:
        _error_budget_tracker = ErrorBudgetTracker()
    return _error_budget_tracker