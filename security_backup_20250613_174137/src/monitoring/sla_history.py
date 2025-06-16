"""
Historical SLA tracking and trending analysis.

Provides:
- Long-term SLA trend analysis
- Historical performance tracking
- Seasonal pattern detection
- Predictive analytics for SLA health
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import statistics
import logging

from .sla import SLATracker, SLAReport, SLAObjective, get_sla_tracker
from .prometheus_client import get_prometheus_client, PrometheusClient
from src.database.repositories.metrics_repository import MetricsRepository

__all__ = [
    "SLAHistoryPoint",
    "SLATrend",
    "TrendDirection", 
    "SLAHistoryTracker",
    "get_sla_history_tracker"
]

logger = logging.getLogger(__name__)


class TrendDirection(Enum):
    """SLA trend direction."""
    IMPROVING = "improving"
    DEGRADING = "degrading"
    STABLE = "stable"
    VOLATILE = "volatile"


@dataclass
class SLAHistoryPoint:
    """Single historical SLA measurement."""
    timestamp: datetime
    compliance_percent: float
    error_budget_remaining: float
    current_value: float
    violations: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "compliance_percent": self.compliance_percent,
            "error_budget_remaining": self.error_budget_remaining,
            "current_value": self.current_value,
            "violations": self.violations,
            "metadata": self.metadata
        }


@dataclass
class SLATrend:
    """SLA trend analysis result."""
    objective_name: str
    direction: TrendDirection
    slope: float  # Rate of change per day
    confidence: float  # Confidence in trend (0-1)
    period_days: int
    
    # Statistical measures
    mean_compliance: float
    std_deviation: float
    min_compliance: float
    max_compliance: float
    
    # Predictions
    predicted_compliance_7d: Optional[float] = None
    predicted_compliance_30d: Optional[float] = None
    
    # Risk assessment
    risk_level: str = "low"  # low, medium, high, critical
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "objective_name": self.objective_name,
            "direction": self.direction.value,
            "slope": self.slope,
            "confidence": self.confidence,
            "period_days": self.period_days,
            "mean_compliance": self.mean_compliance,
            "std_deviation": self.std_deviation,
            "min_compliance": self.min_compliance,
            "max_compliance": self.max_compliance,
            "predicted_compliance_7d": self.predicted_compliance_7d,
            "predicted_compliance_30d": self.predicted_compliance_30d,
            "risk_level": self.risk_level
        }


class SLAHistoryTracker:
    """Tracks and analyzes historical SLA performance."""
    
    def __init__(self):
        self.sla_tracker = get_sla_tracker()
        self.prometheus_client = get_prometheus_client()
        self.metrics_repo = MetricsRepository()
        
        # In-memory cache for recent history
        self.history_cache: Dict[str, List[SLAHistoryPoint]] = {}
        self.cache_duration = timedelta(hours=6)\n        self.last_cache_update = {}\n        \n        # Background tracking task\n        self._tracking_task: Optional[asyncio.Task] = None\n        self._is_running = False\n    \n    async def record_sla_measurement(self, report: SLAReport):\n        \"\"\"Record a single SLA measurement for historical tracking.\"\"\"\n        point = SLAHistoryPoint(\n            timestamp=datetime.now(),\n            compliance_percent=report.compliance_percent,\n            error_budget_remaining=report.error_budget_remaining,\n            current_value=report.current_value,\n            violations=len(report.violations),\n            metadata={\n                "objective_type": report.objective.type.value,\n                "target": report.objective.target,\n                "measurement_window": str(report.objective.measurement_window)\n            }\n        )\n        \n        # Add to cache\n        objective_name = report.objective.name\n        if objective_name not in self.history_cache:\n            self.history_cache[objective_name] = []\n        \n        self.history_cache[objective_name].append(point)\n        \n        # Limit cache size (keep last 1000 points)\n        if len(self.history_cache[objective_name]) > 1000:\n            self.history_cache[objective_name] = self.history_cache[objective_name][-1000:]\n        \n        # Store in database for long-term persistence\n        try:\n            await self.metrics_repo.store_sla_measurement(\n                objective_name=objective_name,\n                timestamp=point.timestamp,\n                compliance_percent=point.compliance_percent,\n                error_budget_remaining=point.error_budget_remaining,\n                current_value=point.current_value,\n                violations=point.violations,\n                metadata=point.metadata\n            )\n        except Exception as e:\n            logger.warning(f\"Failed to store SLA measurement in database: {e}\")\n    \n    async def get_history(self, \n                         objective_name: str, \n                         start_time: Optional[datetime] = None,\n                         end_time: Optional[datetime] = None,\n                         limit: int = 1000) -> List[SLAHistoryPoint]:\n        \"\"\"Get historical SLA data for an objective.\"\"\"\n        if end_time is None:\n            end_time = datetime.now()\n        \n        if start_time is None:\n            start_time = end_time - timedelta(days=30)\n        \n        # Try to get from cache first for recent data\n        if self._is_recent_data(start_time, end_time):\n            cached_data = self.history_cache.get(objective_name, [])\n            filtered_data = [\n                point for point in cached_data\n                if start_time <= point.timestamp <= end_time\n            ]\n            \n            if len(filtered_data) > 0:\n                return sorted(filtered_data, key=lambda p: p.timestamp)[-limit:]\n        \n        # Fallback to database\n        try:\n            db_data = await self.metrics_repo.get_sla_history(\n                objective_name=objective_name,\n                start_time=start_time,\n                end_time=end_time,\n                limit=limit\n            )\n            \n            return [\n                SLAHistoryPoint(\n                    timestamp=row['timestamp'],\n                    compliance_percent=row['compliance_percent'],\n                    error_budget_remaining=row['error_budget_remaining'],\n                    current_value=row['current_value'],\n                    violations=row['violations'],\n                    metadata=row.get('metadata', {})\n                )\n                for row in db_data\n            ]\n        \n        except Exception as e:\n            logger.warning(f\"Failed to retrieve SLA history from database: {e}\")\n            return []\n    \n    def _is_recent_data(self, start_time: datetime, end_time: datetime) -> bool:\n        \"\"\"Check if requested time range is recent enough for cache.\"\"\"\n        now = datetime.now()\n        return (now - start_time) <= self.cache_duration\n    \n    async def analyze_trend(self, \n                          objective_name: str, \n                          days: int = 30) -> Optional[SLATrend]:\n        \"\"\"Analyze SLA trend over specified period.\"\"\"\n        end_time = datetime.now()\n        start_time = end_time - timedelta(days=days)\n        \n        history = await self.get_history(objective_name, start_time, end_time)\n        \n        if len(history) < 10:  # Need minimum data points for analysis\n            logger.warning(f\"Insufficient data for trend analysis: {len(history)} points\")\n            return None\n        \n        # Extract compliance values and timestamps\n        compliance_values = [point.compliance_percent for point in history]\n        timestamps = [point.timestamp for point in history]\n        \n        # Calculate basic statistics\n        mean_compliance = statistics.mean(compliance_values)\n        std_deviation = statistics.stdev(compliance_values) if len(compliance_values) > 1 else 0\n        min_compliance = min(compliance_values)\n        max_compliance = max(compliance_values)\n        \n        # Calculate trend slope using linear regression\n        slope, confidence = self._calculate_trend_slope(timestamps, compliance_values)\n        \n        # Determine trend direction\n        direction = self._determine_trend_direction(slope, std_deviation, mean_compliance)\n        \n        # Make predictions\n        predicted_7d = self._predict_compliance(timestamps, compliance_values, 7)\n        predicted_30d = self._predict_compliance(timestamps, compliance_values, 30)\n        \n        # Assess risk\n        risk_level = self._assess_risk_level(\n            mean_compliance, std_deviation, slope, \n            objective_name, predicted_7d\n        )\n        \n        return SLATrend(\n            objective_name=objective_name,\n            direction=direction,\n            slope=slope,\n            confidence=confidence,\n            period_days=days,\n            mean_compliance=mean_compliance,\n            std_deviation=std_deviation,\n            min_compliance=min_compliance,\n            max_compliance=max_compliance,\n            predicted_compliance_7d=predicted_7d,\n            predicted_compliance_30d=predicted_30d,\n            risk_level=risk_level\n        )\n    \n    def _calculate_trend_slope(self, \n                              timestamps: List[datetime], \n                              values: List[float]) -> Tuple[float, float]:\n        \"\"\"Calculate trend slope using simple linear regression.\"\"\"\n        if len(timestamps) < 2:\n            return 0.0, 0.0\n        \n        # Convert timestamps to days since first timestamp\n        base_time = timestamps[0]\n        x_values = [(ts - base_time).total_seconds() / 86400 for ts in timestamps]\n        y_values = values\n        \n        n = len(x_values)\n        sum_x = sum(x_values)\n        sum_y = sum(y_values)\n        sum_xy = sum(x * y for x, y in zip(x_values, y_values))\n        sum_x2 = sum(x * x for x in x_values)\n        \n        # Calculate slope\n        denominator = n * sum_x2 - sum_x * sum_x\n        if denominator == 0:\n            return 0.0, 0.0\n        \n        slope = (n * sum_xy - sum_x * sum_y) / denominator\n        \n        # Calculate correlation coefficient as confidence measure\n        if n < 2:\n            confidence = 0.0\n        else:\n            sum_y2 = sum(y * y for y in y_values)\n            numerator = n * sum_xy - sum_x * sum_y\n            denominator = ((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y)) ** 0.5\n            \n            if denominator == 0:\n                confidence = 0.0\n            else:\n                correlation = numerator / denominator\n                confidence = abs(correlation)\n        \n        return slope, confidence\n    \n    def _determine_trend_direction(self, \n                                 slope: float, \n                                 std_deviation: float, \n                                 mean_compliance: float) -> TrendDirection:\n        \"\"\"Determine trend direction based on slope and volatility.\"\"\"\n        # High volatility indicates unstable trend\n        if std_deviation > 5.0:  # More than 5% standard deviation\n            return TrendDirection.VOLATILE\n        \n        # Significant slope indicates clear trend\n        if slope > 0.1:  # Improving by more than 0.1% per day\n            return TrendDirection.IMPROVING\n        elif slope < -0.1:  # Degrading by more than 0.1% per day\n            return TrendDirection.DEGRADING\n        else:\n            return TrendDirection.STABLE\n    \n    def _predict_compliance(self, \n                          timestamps: List[datetime], \n                          values: List[float], \n                          days_ahead: int) -> Optional[float]:\n        \"\"\"Predict compliance for specified days in the future.\"\"\"\n        if len(timestamps) < 5:\n            return None\n        \n        slope, confidence = self._calculate_trend_slope(timestamps, values)\n        \n        # Only make predictions if we have reasonable confidence\n        if confidence < 0.3:\n            return None\n        \n        # Simple linear extrapolation\n        last_value = values[-1]\n        predicted = last_value + (slope * days_ahead)\n        \n        # Clamp to reasonable bounds\n        return max(0.0, min(100.0, predicted))\n    \n    def _assess_risk_level(self, \n                         mean_compliance: float, \n                         std_deviation: float, \n                         slope: float,\n                         objective_name: str,\n                         predicted_7d: Optional[float]) -> str:\n        \"\"\"Assess risk level based on multiple factors.\"\"\"\n        # Get SLA target for comparison\n        objective = self.sla_tracker.objectives.get(objective_name)\n        target = objective.target if objective else 99.0\n        \n        # Risk factors\n        risk_score = 0\n        \n        # Current performance vs target\n        if mean_compliance < target - 2:\n            risk_score += 3\n        elif mean_compliance < target - 1:\n            risk_score += 2\n        elif mean_compliance < target:\n            risk_score += 1\n        \n        # Volatility\n        if std_deviation > 10:\n            risk_score += 3\n        elif std_deviation > 5:\n            risk_score += 2\n        elif std_deviation > 2:\n            risk_score += 1\n        \n        # Trend direction\n        if slope < -0.5:  # Rapidly degrading\n            risk_score += 3\n        elif slope < -0.1:\n            risk_score += 2\n        elif slope < 0:\n            risk_score += 1\n        \n        # Future prediction\n        if predicted_7d and predicted_7d < target - 1:\n            risk_score += 2\n        \n        # Determine risk level\n        if risk_score >= 7:\n            return \"critical\"\n        elif risk_score >= 5:\n            return \"high\"\n        elif risk_score >= 3:\n            return \"medium\"\n        else:\n            return \"low\"\n    \n    async def get_trend_summary(self, days: int = 30) -> Dict[str, SLATrend]:\n        \"\"\"Get trend analysis for all SLA objectives.\"\"\"\n        trends = {}\n        \n        for objective_name in self.sla_tracker.objectives.keys():\n            try:\n                trend = await self.analyze_trend(objective_name, days)\n                if trend:\n                    trends[objective_name] = trend\n            except Exception as e:\n                logger.error(f\"Failed to analyze trend for {objective_name}: {e}\")\n        \n        return trends\n    \n    async def get_compliance_summary(self, \n                                   days: int = 7) -> Dict[str, Dict[str, float]]:\n        \"\"\"Get compliance summary statistics for recent period.\"\"\"\n        end_time = datetime.now()\n        start_time = end_time - timedelta(days=days)\n        \n        summary = {}\n        \n        for objective_name in self.sla_tracker.objectives.keys():\n            try:\n                history = await self.get_history(objective_name, start_time, end_time)\n                \n                if history:\n                    compliance_values = [p.compliance_percent for p in history]\n                    \n                    summary[objective_name] = {\n                        \"mean\": statistics.mean(compliance_values),\n                        \"median\": statistics.median(compliance_values),\n                        \"min\": min(compliance_values),\n                        \"max\": max(compliance_values),\n                        \"std_dev\": statistics.stdev(compliance_values) if len(compliance_values) > 1 else 0,\n                        \"data_points\": len(compliance_values),\n                        \"violations\": sum(p.violations for p in history)\n                    }\n                else:\n                    summary[objective_name] = {\n                        \"mean\": 0, \"median\": 0, \"min\": 0, \"max\": 0,\n                        \"std_dev\": 0, \"data_points\": 0, \"violations\": 0\n                    }\n            \n            except Exception as e:\n                logger.error(f\"Failed to get compliance summary for {objective_name}: {e}\")\n        \n        return summary\n    \n    async def start_tracking(self, interval_minutes: int = 5):\n        \"\"\"Start background SLA tracking.\"\"\"\n        if self._is_running:\n            return\n        \n        self._is_running = True\n        self._tracking_task = asyncio.create_task(\n            self._tracking_loop(interval_minutes)\n        )\n        logger.info(f\"Started SLA history tracking with {interval_minutes}min interval\")\n    \n    async def stop_tracking(self):\n        \"\"\"Stop background tracking.\"\"\"\n        self._is_running = False\n        if self._tracking_task:\n            self._tracking_task.cancel()\n            try:\n                await self._tracking_task\n            except asyncio.CancelledError:\n                pass\n        logger.info(\"Stopped SLA history tracking\")\n    \n    async def _tracking_loop(self, interval_minutes: int):\n        \"\"\"Background tracking loop.\"\"\"\n        interval_seconds = interval_minutes * 60\n        \n        while self._is_running:\n            try:\n                # Get current SLA reports and record them\n                reports = await self.sla_tracker.check_all_objectives()\n                \n                for report in reports.values():\n                    await self.record_sla_measurement(report)\n                \n                await asyncio.sleep(interval_seconds)\n                \n            except asyncio.CancelledError:\n                break\n            except Exception as e:\n                logger.error(f\"Error in SLA tracking loop: {e}\", exc_info=True)\n                await asyncio.sleep(min(interval_seconds, 300))  # Back off on error\n\n\n# Global history tracker instance\n_sla_history_tracker: Optional[SLAHistoryTracker] = None\n\n\ndef get_sla_history_tracker() -> SLAHistoryTracker:\n    \"\"\"Get the global SLA history tracker instance.\"\"\"\n    global _sla_history_tracker\n    if _sla_history_tracker is None:\n        _sla_history_tracker = SLAHistoryTracker()\n    return _sla_history_tracker