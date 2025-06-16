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
        self.cache_duration = timedelta(hours=6)
        self.last_cache_update = {}
        
        # Background tracking task
        self._tracking_task: Optional[asyncio.Task] = None
        self._is_running = False
    
    async def record_sla_measurement(self, report: SLAReport):
        \"\"\"Record a single SLA measurement for historical tracking.\"\"\"
        point = SLAHistoryPoint(
            timestamp=datetime.now(),
            compliance_percent=report.compliance_percent,
            error_budget_remaining=report.error_budget_remaining,
            current_value=report.current_value,
            violations=len(report.violations),
            metadata={
                "objective_type": report.objective.type.value,
                "target": report.objective.target,
                "measurement_window": str(report.objective.measurement_window)
            }
        )
        
        # Add to cache
        objective_name = report.objective.name
        if objective_name not in self.history_cache:
            self.history_cache[objective_name] = []
        
        self.history_cache[objective_name].append(point)
        
        # Limit cache size (keep last 1000 points)
        if len(self.history_cache[objective_name]) > 1000:
            self.history_cache[objective_name] = self.history_cache[objective_name][-1000:]
        
        # Store in database for long-term persistence
        try:
            await self.metrics_repo.store_sla_measurement(
                objective_name=objective_name,
                timestamp=point.timestamp,
                compliance_percent=point.compliance_percent,
                error_budget_remaining=point.error_budget_remaining,
                current_value=point.current_value,
                violations=point.violations,
                metadata=point.metadata
            )
        except Exception as e:
            logger.warning(f\"Failed to store SLA measurement in database: {e}\")
    
    async def get_history(self, 
                         objective_name: str, 
                         start_time: Optional[datetime] = None,
                         end_time: Optional[datetime] = None,
                         limit: int = 1000) -> List[SLAHistoryPoint]:
        \"\"\"Get historical SLA data for an objective.\"\"\"
        if end_time is None:
            end_time = datetime.now()
        
        if start_time is None:
            start_time = end_time - timedelta(days=30)
        
        # Try to get from cache first for recent data
        if self._is_recent_data(start_time, end_time):
            cached_data = self.history_cache.get(objective_name, [])
            filtered_data = [
                point for point in cached_data
                if start_time <= point.timestamp <= end_time
            ]
            
            if len(filtered_data) > 0:
                return sorted(filtered_data, key=lambda p: p.timestamp)[-limit:]
        
        # Fallback to database
        try:
            db_data = await self.metrics_repo.get_sla_history(
                objective_name=objective_name,
                start_time=start_time,
                end_time=end_time,
                limit=limit
            )
            
            return [
                SLAHistoryPoint(
                    timestamp=row['timestamp'],
                    compliance_percent=row['compliance_percent'],
                    error_budget_remaining=row['error_budget_remaining'],
                    current_value=row['current_value'],
                    violations=row['violations'],
                    metadata=row.get('metadata', {})
                )
                for row in db_data
            ]
        
        except Exception as e:
            logger.warning(f\"Failed to retrieve SLA history from database: {e}\")
            return []
    
    def _is_recent_data(self, start_time: datetime, end_time: datetime) -> bool:
        \"\"\"Check if requested time range is recent enough for cache.\"\"\"
        now = datetime.now()
        return (now - start_time) <= self.cache_duration
    
    async def analyze_trend(self, 
                          objective_name: str, 
                          days: int = 30) -> Optional[SLATrend]:
        \"\"\"Analyze SLA trend over specified period.\"\"\"
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        history = await self.get_history(objective_name, start_time, end_time)
        
        if len(history) < 10:  # Need minimum data points for analysis
            logger.warning(f\"Insufficient data for trend analysis: {len(history)} points\")
            return None
        
        # Extract compliance values and timestamps
        compliance_values = [point.compliance_percent for point in history]
        timestamps = [point.timestamp for point in history]
        
        # Calculate basic statistics
        mean_compliance = statistics.mean(compliance_values)
        std_deviation = statistics.stdev(compliance_values) if len(compliance_values) > 1 else 0
        min_compliance = min(compliance_values)
        max_compliance = max(compliance_values)
        
        # Calculate trend slope using linear regression
        slope, confidence = self._calculate_trend_slope(timestamps, compliance_values)
        
        # Determine trend direction
        direction = self._determine_trend_direction(slope, std_deviation, mean_compliance)
        
        # Make predictions
        predicted_7d = self._predict_compliance(timestamps, compliance_values, 7)
        predicted_30d = self._predict_compliance(timestamps, compliance_values, 30)
        
        # Assess risk
        risk_level = self._assess_risk_level(
            mean_compliance, std_deviation, slope, 
            objective_name, predicted_7d
        )
        
        return SLATrend(
            objective_name=objective_name,
            direction=direction,
            slope=slope,
            confidence=confidence,
            period_days=days,
            mean_compliance=mean_compliance,
            std_deviation=std_deviation,
            min_compliance=min_compliance,
            max_compliance=max_compliance,
            predicted_compliance_7d=predicted_7d,
            predicted_compliance_30d=predicted_30d,
            risk_level=risk_level
        )
    
    def _calculate_trend_slope(self, 
                              timestamps: List[datetime], 
                              values: List[float]) -> Tuple[float, float]:
        \"\"\"Calculate trend slope using simple linear regression.\"\"\"
        if len(timestamps) < 2:
            return 0.0, 0.0
        
        # Convert timestamps to days since first timestamp
        base_time = timestamps[0]
        x_values = [(ts - base_time).total_seconds() / 86400 for ts in timestamps]
        y_values = values
        
        n = len(x_values)
        sum_x = sum(x_values)
        sum_y = sum(y_values)
        sum_xy = sum(x * y for x, y in zip(x_values, y_values))
        sum_x2 = sum(x * x for x in x_values)
        
        # Calculate slope
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return 0.0, 0.0
        
        slope = (n * sum_xy - sum_x * sum_y) / denominator
        
        # Calculate correlation coefficient as confidence measure
        if n < 2:
            confidence = 0.0
        else:
            sum_y2 = sum(y * y for y in y_values)
            numerator = n * sum_xy - sum_x * sum_y
            denominator = ((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y)) ** 0.5
            
            if denominator == 0:
                confidence = 0.0
            else:
                correlation = numerator / denominator
                confidence = abs(correlation)
        
        return slope, confidence
    
    def _determine_trend_direction(self, 
                                 slope: float, 
                                 std_deviation: float, 
                                 mean_compliance: float) -> TrendDirection:
        \"\"\"Determine trend direction based on slope and volatility.\"\"\"
        # High volatility indicates unstable trend
        if std_deviation > 5.0:  # More than 5% standard deviation
            return TrendDirection.VOLATILE
        
        # Significant slope indicates clear trend
        if slope > 0.1:  # Improving by more than 0.1% per day
            return TrendDirection.IMPROVING
        elif slope < -0.1:  # Degrading by more than 0.1% per day
            return TrendDirection.DEGRADING
        else:
            return TrendDirection.STABLE
    
    def _predict_compliance(self, 
                          timestamps: List[datetime], 
                          values: List[float], 
                          days_ahead: int) -> Optional[float]:
        \"\"\"Predict compliance for specified days in the future.\"\"\"
        if len(timestamps) < 5:
            return None
        
        slope, confidence = self._calculate_trend_slope(timestamps, values)
        
        # Only make predictions if we have reasonable confidence
        if confidence < 0.3:
            return None
        
        # Simple linear extrapolation
        last_value = values[-1]
        predicted = last_value + (slope * days_ahead)
        
        # Clamp to reasonable bounds
        return max(0.0, min(100.0, predicted))
    
    def _assess_risk_level(self, 
                         mean_compliance: float, 
                         std_deviation: float, 
                         slope: float,
                         objective_name: str,
                         predicted_7d: Optional[float]) -> str:
        \"\"\"Assess risk level based on multiple factors.\"\"\"
        # Get SLA target for comparison
        objective = self.sla_tracker.objectives.get(objective_name)
        target = objective.target if objective else 99.0
        
        # Risk factors
        risk_score = 0
        
        # Current performance vs target
        if mean_compliance < target - 2:
            risk_score += 3
        elif mean_compliance < target - 1:
            risk_score += 2
        elif mean_compliance < target:
            risk_score += 1
        
        # Volatility
        if std_deviation > 10:
            risk_score += 3
        elif std_deviation > 5:
            risk_score += 2
        elif std_deviation > 2:
            risk_score += 1
        
        # Trend direction
        if slope < -0.5:  # Rapidly degrading
            risk_score += 3
        elif slope < -0.1:
            risk_score += 2
        elif slope < 0:
            risk_score += 1
        
        # Future prediction
        if predicted_7d and predicted_7d < target - 1:
            risk_score += 2
        
        # Determine risk level
        if risk_score >= 7:
            return \"critical\"
        elif risk_score >= 5:
            return \"high\"
        elif risk_score >= 3:
            return \"medium\"
        else:
            return \"low\"
    
    async def get_trend_summary(self, days: int = 30) -> Dict[str, SLATrend]:
        \"\"\"Get trend analysis for all SLA objectives.\"\"\"
        trends = {}
        
        for objective_name in self.sla_tracker.objectives.keys():
            try:
                trend = await self.analyze_trend(objective_name, days)
                if trend:
                    trends[objective_name] = trend
            except Exception as e:
                logger.error(f\"Failed to analyze trend for {objective_name}: {e}\")
        
        return trends
    
    async def get_compliance_summary(self, 
                                   days: int = 7) -> Dict[str, Dict[str, float]]:
        \"\"\"Get compliance summary statistics for recent period.\"\"\"
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        summary = {}
        
        for objective_name in self.sla_tracker.objectives.keys():
            try:
                history = await self.get_history(objective_name, start_time, end_time)
                
                if history:
                    compliance_values = [p.compliance_percent for p in history]
                    
                    summary[objective_name] = {
                        \"mean\": statistics.mean(compliance_values),
                        \"median\": statistics.median(compliance_values),
                        \"min\": min(compliance_values),
                        \"max\": max(compliance_values),
                        \"std_dev\": statistics.stdev(compliance_values) if len(compliance_values) > 1 else 0,
                        \"data_points\": len(compliance_values),
                        \"violations\": sum(p.violations for p in history)
                    }
                else:
                    summary[objective_name] = {
                        \"mean\": 0, \"median\": 0, \"min\": 0, \"max\": 0,
                        \"std_dev\": 0, \"data_points\": 0, \"violations\": 0
                    }
            
            except Exception as e:
                logger.error(f\"Failed to get compliance summary for {objective_name}: {e}\")
        
        return summary
    
    async def start_tracking(self, interval_minutes: int = 5):
        \"\"\"Start background SLA tracking.\"\"\"
        if self._is_running:
            return
        
        self._is_running = True
        self._tracking_task = asyncio.create_task(
            self._tracking_loop(interval_minutes)
        )
        logger.info(f\"Started SLA history tracking with {interval_minutes}min interval\")
    
    async def stop_tracking(self):
        \"\"\"Stop background tracking.\"\"\"
        self._is_running = False
        if self._tracking_task:
            self._tracking_task.cancel()
            try:
                await self._tracking_task
            except asyncio.CancelledError:
                pass
        logger.info(\"Stopped SLA history tracking\")
    
    async def _tracking_loop(self, interval_minutes: int):
        \"\"\"Background tracking loop.\"\"\"
        interval_seconds = interval_minutes * 60
        
        while self._is_running:
            try:
                # Get current SLA reports and record them
                reports = await self.sla_tracker.check_all_objectives()
                
                for report in reports.values():
                    await self.record_sla_measurement(report)
                
                await asyncio.sleep(interval_seconds)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f\"Error in SLA tracking loop: {e}\", exc_info=True)
                await asyncio.sleep(min(interval_seconds, 300))  # Back off on error


# Global history tracker instance
_sla_history_tracker: Optional[SLAHistoryTracker] = None


def get_sla_history_tracker() -> SLAHistoryTracker:
    \"\"\"Get the global SLA history tracker instance.\"\"\"
    global _sla_history_tracker
    if _sla_history_tracker is None:
        _sla_history_tracker = SLAHistoryTracker()
    return _sla_history_tracker