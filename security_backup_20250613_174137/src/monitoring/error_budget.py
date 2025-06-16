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
        }\n    \n    async def get_error_budget_status(self, objective_name: str) -> ErrorBudgetStatus:\n        \"\"\"Get comprehensive error budget status for an objective.\"\"\"\n        if objective_name not in self.sla_tracker.objectives:\n            raise ValueError(f\"Unknown SLA objective: {objective_name}\")\n        \n        objective = self.sla_tracker.objectives[objective_name]\n        \n        # Get current SLA report\n        current_report = await self.sla_tracker.check_objective(objective)\n        \n        # Calculate total error budget (100 - target)\n        total_budget = 100 - objective.target\n        current_failure_rate = 100 - current_report.compliance_percent\n        \n        consumed_percent = (current_failure_rate / total_budget * 100) if total_budget > 0 else 0\n        remaining_percent = max(0, 100 - consumed_percent)\n        \n        # Calculate burn rates for different windows\n        burn_rates = {}\n        for window in BurnRateWindow:\n            try:\n                burn_rate = await self._calculate_burn_rate(objective_name, window.value)\n                burn_rates[window.value] = burn_rate\n            except Exception as e:\n                logger.warning(f\"Failed to calculate {window.value} burn rate for {objective_name}: {e}\")\n                burn_rates[window.value] = 0.0\n        \n        # Predict exhaustion times\n        exhaustion_predictions = {}\n        for window, rate in burn_rates.items():\n            prediction = self._predict_exhaustion_time(remaining_percent, rate)\n            exhaustion_predictions[window] = prediction\n        \n        # Assess risk level\n        risk_level = self._assess_budget_risk(burn_rates, remaining_percent)\n        \n        # Get historical consumption\n        budget_24h = await self._get_historical_budget_consumption(objective_name, timedelta(hours=24))\n        budget_week = await self._get_historical_budget_consumption(objective_name, timedelta(days=7))\n        \n        return ErrorBudgetStatus(\n            objective_name=objective_name,\n            total_budget_percent=total_budget,\n            consumed_percent=consumed_percent,\n            remaining_percent=remaining_percent,\n            burn_rates=burn_rates,\n            exhaustion_predictions=exhaustion_predictions,\n            risk_level=risk_level,\n            budget_consumed_last_24h=budget_24h,\n            budget_consumed_last_week=budget_week\n        )\n    \n    async def _calculate_burn_rate(self, objective_name: str, window: str) -> float:\n        \"\"\"Calculate error budget burn rate for a specific time window.\"\"\"\n        objective = self.sla_tracker.objectives[objective_name]\n        service_name = objective.labels.get('service', 'claude-api')\n        \n        # Parse window duration\n        window_duration = self._parse_window_duration(window)\n        end_time = datetime.now()\n        start_time = end_time - window_duration\n        \n        if objective.type.value == \"availability\":\n            # For availability SLOs, calculate based on uptime\n            availability = await self.prometheus_client.get_metric_availability(\n                service_name, start_time, end_time\n            )\n            failure_rate = 100 - availability\n            \n        elif objective.type.value == \"error_rate\":\n            # For error rate SLOs, get error rate directly\n            failure_rate = await self.prometheus_client.get_error_rate(\n                service_name, start_time, end_time\n            )\n            \n        elif objective.type.value == \"latency\":\n            # For latency SLOs, calculate based on threshold violations\n            latency_p95 = await self.prometheus_client.get_latency_percentile(\n                service_name, 0.95, start_time, end_time\n            )\n            latency_ms = latency_p95 * 1000 if latency_p95 < 100 else latency_p95\n            \n            # Failure rate is when latency exceeds threshold\n            if latency_ms > objective.latency_threshold_ms:\n                failure_rate = ((latency_ms - objective.latency_threshold_ms) / \n                              objective.latency_threshold_ms) * 100\n            else:\n                failure_rate = 0.0\n        \n        else:\n            # Fallback for other types\n            failure_rate = 0.0\n        \n        # Calculate burn rate (how much budget consumed vs normal rate)\n        error_budget = 100 - objective.target\n        if error_budget == 0:\n            return 0.0\n        \n        # Normal burn rate would be error_budget / measurement_window\n        normal_rate = error_budget / (objective.measurement_window.total_seconds() / 3600)  # per hour\n        current_rate = failure_rate  # Current failure rate\n        \n        # Burn rate is the multiple of normal consumption\n        if normal_rate == 0:\n            return 0.0\n        \n        burn_rate = current_rate / normal_rate\n        return max(0.0, burn_rate)\n    \n    def _parse_window_duration(self, window: str) -> timedelta:\n        \"\"\"Parse window string to timedelta.\"\"\"\n        if window.endswith('h'):\n            hours = int(window[:-1])\n            return timedelta(hours=hours)\n        elif window.endswith('d'):\n            days = int(window[:-1])\n            return timedelta(days=days)\n        elif window.endswith('m'):\n            minutes = int(window[:-1])\n            return timedelta(minutes=minutes)\n        else:\n            # Default to 1 hour\n            return timedelta(hours=1)\n    \n    def _predict_exhaustion_time(self, \n                               remaining_percent: float, \n                               burn_rate: float) -> Optional[datetime]:\n        \"\"\"Predict when error budget will be exhausted.\"\"\"\n        if burn_rate <= 0 or remaining_percent <= 0:\n            return None\n        \n        if remaining_percent >= 99:\n            return None  # Plenty of budget\n        \n        # Simple linear extrapolation\n        # At current burn rate, how long until budget is exhausted?\n        hours_to_exhaustion = remaining_percent / (burn_rate * 0.1)  # Rough estimate\n        \n        if hours_to_exhaustion > 24 * 30:  # More than 30 days\n            return None\n        \n        return datetime.now() + timedelta(hours=hours_to_exhaustion)\n    \n    def _assess_budget_risk(self, \n                          burn_rates: Dict[str, float], \n                          remaining_percent: float) -> str:\n        \"\"\"Assess overall risk level based on burn rates and remaining budget.\"\"\"\n        if remaining_percent <= 5:\n            return \"critical\"\n        \n        if remaining_percent <= 10:\n            return \"high\"\n        \n        # Check burn rates against thresholds\n        critical_burns = 0\n        high_burns = 0\n        \n        for window, rate in burn_rates.items():\n            thresholds = self.burn_rate_thresholds.get(window, {})\n            \n            if rate >= thresholds.get(\"critical\", float('inf')):\n                critical_burns += 1\n            elif rate >= thresholds.get(\"high\", float('inf')):\n                high_burns += 1\n        \n        if critical_burns > 0:\n            return \"critical\"\n        elif high_burns >= 2:  # Multiple windows showing high burn\n            return \"high\"\n        elif high_burns > 0 or remaining_percent <= 25:\n            return \"medium\"\n        else:\n            return \"low\"\n    \n    async def _get_historical_budget_consumption(self, \n                                               objective_name: str, \n                                               period: timedelta) -> float:\n        \"\"\"Get error budget consumption over historical period.\"\"\"\n        try:\n            objective = self.sla_tracker.objectives[objective_name]\n            \n            # Get SLA status at start and end of period\n            end_time = datetime.now()\n            start_time = end_time - period\n            \n            current_report = await self.sla_tracker.check_objective(objective)\n            past_report = await self.sla_tracker.check_objective(\n                objective, (start_time, start_time + timedelta(minutes=5))\n            )\n            \n            # Calculate consumption difference\n            current_consumed = 100 - current_report.error_budget_remaining\n            past_consumed = 100 - past_report.error_budget_remaining\n            \n            consumption = current_consumed - past_consumed\n            return max(0.0, consumption)\n            \n        except Exception as e:\n            logger.warning(f\"Failed to get historical consumption for {objective_name}: {e}\")\n            return 0.0\n    \n    async def check_burn_rate_alerts(self) -> List[BurnRateAlert]:\n        \"\"\"Check all objectives for concerning burn rates.\"\"\"\n        alerts = []\n        \n        for objective_name in self.sla_tracker.objectives.keys():\n            try:\n                status = await self.get_error_budget_status(objective_name)\n                \n                # Check each window for alerting thresholds\n                for window, burn_rate in status.burn_rates.items():\n                    thresholds = self.burn_rate_thresholds.get(window, {})\n                    \n                    severity = None\n                    if burn_rate >= thresholds.get(\"critical\", float('inf')):\n                        severity = \"critical\"\n                    elif burn_rate >= thresholds.get(\"high\", float('inf')):\n                        severity = \"high\"\n                    \n                    if severity:\n                        prediction = status.exhaustion_predictions.get(window)\n                        \n                        message = (\n                            f\"High error budget burn rate detected for {objective_name} \"\n                            f\"({window} window): {burn_rate:.2f}x normal rate\"\n                        )\n                        \n                        if prediction:\n                            message += f\". Budget may be exhausted by {prediction.strftime('%Y-%m-%d %H:%M')}\"\n                        \n                        alerts.append(BurnRateAlert(\n                            objective_name=objective_name,\n                            window=window,\n                            burn_rate=burn_rate,\n                            severity=severity,\n                            message=message,\n                            predicted_exhaustion=prediction\n                        ))\n            \n            except Exception as e:\n                logger.error(f\"Error checking burn rate for {objective_name}: {e}\")\n        \n        return alerts\n    \n    async def get_budget_summary(self) -> Dict[str, Any]:\n        \"\"\"Get summary of error budget status across all objectives.\"\"\"\n        summary = {\n            \"timestamp\": datetime.now().isoformat(),\n            \"objectives\": {},\n            \"overall_risk\": \"low\",\n            \"alerts\": [],\n            \"statistics\": {\n                \"total_objectives\": 0,\n                \"high_risk_objectives\": 0,\n                \"average_remaining_budget\": 0.0,\n                \"lowest_remaining_budget\": 100.0\n            }\n        }\n        \n        budget_statuses = []\n        \n        for objective_name in self.sla_tracker.objectives.keys():\n            try:\n                status = await self.get_error_budget_status(objective_name)\n                summary[\"objectives\"][objective_name] = status.to_dict()\n                budget_statuses.append(status)\n                \n            except Exception as e:\n                logger.error(f\"Error getting budget status for {objective_name}: {e}\")\n        \n        # Get burn rate alerts\n        burn_rate_alerts = await self.check_burn_rate_alerts()\n        summary[\"alerts\"] = [alert.to_dict() for alert in burn_rate_alerts]\n        \n        # Calculate statistics\n        if budget_statuses:\n            summary[\"statistics\"][\"total_objectives\"] = len(budget_statuses)\n            summary[\"statistics\"][\"high_risk_objectives\"] = sum(\n                1 for status in budget_statuses \n                if status.risk_level in [\"high\", \"critical\"]\n            )\n            \n            remaining_budgets = [status.remaining_percent for status in budget_statuses]\n            summary[\"statistics\"][\"average_remaining_budget\"] = sum(remaining_budgets) / len(remaining_budgets)\n            summary[\"statistics\"][\"lowest_remaining_budget\"] = min(remaining_budgets)\n            \n            # Determine overall risk\n            risk_levels = [status.risk_level for status in budget_statuses]\n            if \"critical\" in risk_levels:\n                summary[\"overall_risk\"] = \"critical\"\n            elif \"high\" in risk_levels:\n                summary[\"overall_risk\"] = \"high\"\n            elif \"medium\" in risk_levels:\n                summary[\"overall_risk\"] = \"medium\"\n        \n        return summary\n\n\n# Global error budget tracker instance\n_error_budget_tracker: Optional[ErrorBudgetTracker] = None\n\n\ndef get_error_budget_tracker() -> ErrorBudgetTracker:\n    \"\"\"Get the global error budget tracker instance.\"\"\"\n    global _error_budget_tracker\n    if _error_budget_tracker is None:\n        _error_budget_tracker = ErrorBudgetTracker()\n    return _error_budget_tracker