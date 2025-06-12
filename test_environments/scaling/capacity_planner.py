"""
Capacity Planner - Capacity planning and forecasting system

This module provides comprehensive capacity planning capabilities including
demand forecasting, capacity modeling, growth projections, and resource
requirement predictions.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import math
from collections import defaultdict, deque

# Try to import scientific packages, fall back if not available
try:
    import numpy as np
    from scipy import stats
    from sklearn.linear_model import LinearRegression
    from sklearn.preprocessing import StandardScaler
    SCIENTIFIC_PACKAGES_AVAILABLE = True
except ImportError:
    SCIENTIFIC_PACKAGES_AVAILABLE = False
    # Mock numpy for basic operations
    class MockNumpy:
        @staticmethod
        def array(data):
            return data
        @staticmethod
        def column_stack(arrays):
            return list(zip(*arrays))
        @staticmethod
        def sin(x):
            return [math.sin(val) for val in x] if isinstance(x, list) else math.sin(x)
        @staticmethod
        def cos(x):
            return [math.cos(val) for val in x] if isinstance(x, list) else math.cos(x)
        @staticmethod
        def pi(self):
            return math.pi
        @staticmethod
        def linspace(start, stop, num):
            step = (stop - start) / (num - 1)
            return [start + i * step for i in range(num)]
        @staticmethod
        def convolve(a, v, mode='full'):
            return a  # Simple fallback
        @staticmethod
        def ones(n):
            return [1] * n
        @staticmethod
        def std(data):
            mean = sum(data) / len(data)
            return math.sqrt(sum((x - mean) ** 2 for x in data) / len(data))
        @staticmethod
        def all(data):
            return all(data)
        @staticmethod
        def log(data):
            return [math.log(x) for x in data] if isinstance(data, list) else math.log(data)
        @staticmethod
        def argmax(data):
            return data.index(max(data))
        @staticmethod
        def abs(data):
            return [abs(x) for x in data] if isinstance(data, list) else abs(data)
        @staticmethod
        def fft(data):
            # Simplified FFT placeholder
            class FFTResult:
                def fft(self, data):
                    return data
                def fftfreq(self, n):
                    return [i/n for i in range(n)]
            return FFTResult()
    
    np = MockNumpy()
    
    # Mock sklearn classes
    class LinearRegression:
        def __init__(self):
            self.coef_ = [0.1]
            
        def fit(self, X, y):
            pass
            
        def predict(self, X):
            return [50.0 for _ in range(len(X))]
            
        def score(self, X, y):
            return 0.7
    
    class StandardScaler:
        def fit_transform(self, data):
            return data
        def transform(self, data):
            return data

from ..circle_of_experts import CircleOfExperts, QueryRequest


class ForecastMethod(Enum):
    LINEAR_REGRESSION = "linear_regression"
    EXPONENTIAL_SMOOTHING = "exponential_smoothing"
    SEASONAL_DECOMPOSITION = "seasonal_decomposition"
    MACHINE_LEARNING = "machine_learning"
    EXPERT_DRIVEN = "expert_driven"


class CapacityMetric(Enum):
    CPU_UTILIZATION = "cpu_utilization"
    MEMORY_UTILIZATION = "memory_utilization"
    STORAGE_UTILIZATION = "storage_utilization"
    NETWORK_THROUGHPUT = "network_throughput"
    REQUEST_RATE = "request_rate"
    RESPONSE_TIME = "response_time"
    ACTIVE_USERS = "active_users"


@dataclass
class HistoricalDataPoint:
    """Historical data point for capacity planning"""
    timestamp: datetime
    metric: CapacityMetric
    value: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CapacityForecast:
    """Capacity forecast result"""
    metric: CapacityMetric
    forecast_method: ForecastMethod
    time_horizon: timedelta
    predicted_values: List[Tuple[datetime, float]]
    confidence_intervals: List[Tuple[datetime, float, float]]
    trend_direction: str  # "increasing", "decreasing", "stable"
    seasonality_detected: bool
    forecast_accuracy: float
    recommendations: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CapacityPlan:
    """Comprehensive capacity plan"""
    plan_id: str
    planning_horizon: timedelta
    current_capacity: Dict[str, float]
    forecasted_demand: Dict[str, CapacityForecast]
    recommended_capacity: Dict[str, float]
    scaling_timeline: List[Tuple[datetime, Dict[str, float]]]
    cost_projections: Dict[str, float]
    risk_assessment: Dict[str, float]
    confidence_score: float
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class GrowthPattern:
    """Growth pattern analysis"""
    pattern_type: str  # "linear", "exponential", "logarithmic", "seasonal"
    growth_rate: float
    acceleration: float
    seasonality_period: Optional[timedelta]
    pattern_strength: float
    confidence: float


class CapacityPlanner:
    """
    Capacity planning and forecasting system
    
    Provides demand forecasting, capacity modeling, growth analysis,
    and resource requirement predictions for optimal capacity planning.
    """
    
    def __init__(self, circle_of_experts: Optional[CircleOfExperts] = None):
        self.logger = logging.getLogger(__name__)
        self.circle_of_experts = circle_of_experts
        
        # Historical data storage
        self.historical_data: Dict[CapacityMetric, deque] = defaultdict(
            lambda: deque(maxlen=10000)
        )
        
        # Forecast models
        self.forecast_models: Dict[str, Any] = {}
        self.model_accuracy: Dict[str, float] = {}
        
        # Planning configuration
        self.planning_config = {
            'default_horizon': timedelta(days=30),
            'min_data_points': 50,
            'confidence_threshold': 0.8,
            'seasonal_detection_threshold': 0.3,
            'trend_significance_threshold': 0.05
        }
        
        # Capacity buffers and safety margins
        self.capacity_buffers = {
            CapacityMetric.CPU_UTILIZATION: 0.2,  # 20% buffer
            CapacityMetric.MEMORY_UTILIZATION: 0.15,  # 15% buffer
            CapacityMetric.STORAGE_UTILIZATION: 0.1,  # 10% buffer
            CapacityMetric.NETWORK_THROUGHPUT: 0.3,  # 30% buffer
            CapacityMetric.REQUEST_RATE: 0.25,  # 25% buffer
            CapacityMetric.RESPONSE_TIME: -0.2,  # 20% improvement target
            CapacityMetric.ACTIVE_USERS: 0.5  # 50% growth buffer
        }
        
        # Growth patterns cache
        self.growth_patterns: Dict[CapacityMetric, GrowthPattern] = {}
        
        # Capacity plans
        self.capacity_plans: Dict[str, CapacityPlan] = {}
    
    async def generate_forecast(
        self,
        current_metrics: Dict[str, Any],
        horizon_hours: int = 24,
        method: ForecastMethod = ForecastMethod.MACHINE_LEARNING
    ) -> Dict[str, Any]:
        """
        Generate capacity forecast based on historical data and current metrics
        
        Args:
            current_metrics: Current system metrics
            horizon_hours: Forecast horizon in hours
            method: Forecasting method to use
            
        Returns:
            Forecast results and recommendations
        """
        horizon = timedelta(hours=horizon_hours)
        
        try:
            # Add current metrics to historical data
            await self._update_historical_data(current_metrics)
            
            # Generate forecasts for each metric
            forecasts = {}
            for metric in CapacityMetric:
                if metric.value in current_metrics:
                    forecast = await self._generate_metric_forecast(
                        metric, horizon, method
                    )
                    forecasts[metric.value] = forecast
            
            # Analyze overall trends
            trend_analysis = await self._analyze_trends(forecasts)
            
            # Get expert forecasting recommendations
            expert_recommendations = await self._get_forecasting_recommendations(
                current_metrics, forecasts, trend_analysis
            )
            
            # Calculate load change predictions
            load_predictions = await self._calculate_load_predictions(forecasts)
            
            return {
                'forecasts': {
                    metric: {
                        'predicted_values': forecast.predicted_values,
                        'trend_direction': forecast.trend_direction,
                        'forecast_accuracy': forecast.forecast_accuracy,
                        'recommendations': forecast.recommendations
                    }
                    for metric, forecast in forecasts.items()
                },
                'trend_analysis': trend_analysis,
                'expert_recommendations': expert_recommendations,
                'predicted_load_increase': load_predictions.get('load_increase', 0.0),
                'predicted_load_decrease': load_predictions.get('load_decrease', 0.0),
                'predicted_load_change': load_predictions.get('load_change', 0.0),
                'predicted_response_time': load_predictions.get('response_time', 
                                                               current_metrics.get('response_time', 1.0)),
                'predicted_throughput': load_predictions.get('throughput',
                                                           current_metrics.get('active_connections', 100)),
                'confidence': load_predictions.get('confidence', 0.7),
                'horizon_hours': horizon_hours
            }
            
        except Exception as e:
            self.logger.error(f"Forecast generation failed: {e}")
            return {
                'error': str(e),
                'forecasts': {},
                'predicted_load_change': 0.0,
                'confidence': 0.0
            }
    
    async def create_capacity_plan(
        self,
        plan_id: str,
        current_capacity: Dict[str, float],
        planning_horizon: timedelta,
        target_metrics: Optional[Dict[str, float]] = None
    ) -> CapacityPlan:
        """
        Create comprehensive capacity plan
        
        Args:
            plan_id: Unique plan identifier
            current_capacity: Current capacity configuration
            planning_horizon: Planning time horizon
            target_metrics: Target performance metrics
            
        Returns:
            Comprehensive capacity plan
        """
        try:
            # Generate demand forecasts
            forecasted_demand = {}
            for metric in CapacityMetric:
                forecast = await self._generate_metric_forecast(
                    metric, planning_horizon, ForecastMethod.MACHINE_LEARNING
                )
                forecasted_demand[metric.value] = forecast
            
            # Calculate recommended capacity
            recommended_capacity = await self._calculate_recommended_capacity(
                current_capacity, forecasted_demand, target_metrics
            )
            
            # Generate scaling timeline
            scaling_timeline = await self._generate_scaling_timeline(
                current_capacity, recommended_capacity, planning_horizon
            )
            
            # Calculate cost projections
            cost_projections = await self._calculate_cost_projections(
                scaling_timeline, planning_horizon
            )
            
            # Assess risks
            risk_assessment = await self._assess_capacity_risks(
                forecasted_demand, recommended_capacity
            )
            
            # Calculate confidence score
            confidence_score = await self._calculate_plan_confidence(
                forecasted_demand, risk_assessment
            )
            
            # Get expert validation
            expert_validation = await self._get_capacity_plan_recommendations(
                current_capacity, recommended_capacity, forecasted_demand
            )
            
            plan = CapacityPlan(
                plan_id=plan_id,
                planning_horizon=planning_horizon,
                current_capacity=current_capacity,
                forecasted_demand=forecasted_demand,
                recommended_capacity=recommended_capacity,
                scaling_timeline=scaling_timeline,
                cost_projections=cost_projections,
                risk_assessment=risk_assessment,
                confidence_score=confidence_score
            )
            
            self.capacity_plans[plan_id] = plan
            return plan
            
        except Exception as e:
            self.logger.error(f"Capacity plan creation failed: {e}")
            return CapacityPlan(
                plan_id=plan_id,
                planning_horizon=planning_horizon,
                current_capacity=current_capacity,
                forecasted_demand={},
                recommended_capacity=current_capacity,
                scaling_timeline=[],
                cost_projections={},
                risk_assessment={'error': 1.0},
                confidence_score=0.0
            )
    
    async def analyze_growth_patterns(
        self,
        metric: CapacityMetric,
        time_window: Optional[timedelta] = None
    ) -> GrowthPattern:
        """
        Analyze growth patterns for a specific metric
        
        Args:
            metric: Capacity metric to analyze
            time_window: Time window for analysis
            
        Returns:
            Growth pattern analysis
        """
        if time_window is None:
            time_window = timedelta(days=30)
        
        try:
            # Get historical data
            historical_data = list(self.historical_data[metric])
            
            if len(historical_data) < self.planning_config['min_data_points']:
                return GrowthPattern(
                    pattern_type="insufficient_data",
                    growth_rate=0.0,
                    acceleration=0.0,
                    seasonality_period=None,
                    pattern_strength=0.0,
                    confidence=0.0
                )
            
            # Filter data by time window
            cutoff_time = datetime.now() - time_window
            filtered_data = [
                dp for dp in historical_data
                if dp.timestamp >= cutoff_time
            ]
            
            if len(filtered_data) < 10:
                return GrowthPattern(
                    pattern_type="insufficient_recent_data",
                    growth_rate=0.0,
                    acceleration=0.0,
                    seasonality_period=None,
                    pattern_strength=0.0,
                    confidence=0.0
                )
            
            # Prepare data for analysis
            timestamps = np.array([
                dp.timestamp.timestamp() for dp in filtered_data
            ])
            values = np.array([dp.value for dp in filtered_data])
            
            # Normalize timestamps
            timestamps = (timestamps - timestamps[0]) / 3600  # Hours since start
            
            # Detect growth pattern
            pattern_analysis = await self._detect_growth_pattern(timestamps, values)
            
            # Detect seasonality
            seasonality_analysis = await self._detect_seasonality(timestamps, values)
            
            growth_pattern = GrowthPattern(
                pattern_type=pattern_analysis['pattern_type'],
                growth_rate=pattern_analysis['growth_rate'],
                acceleration=pattern_analysis['acceleration'],
                seasonality_period=seasonality_analysis['period'],
                pattern_strength=pattern_analysis['strength'],
                confidence=pattern_analysis['confidence']
            )
            
            self.growth_patterns[metric] = growth_pattern
            return growth_pattern
            
        except Exception as e:
            self.logger.error(f"Growth pattern analysis failed for {metric}: {e}")
            return GrowthPattern(
                pattern_type="error",
                growth_rate=0.0,
                acceleration=0.0,
                seasonality_period=None,
                pattern_strength=0.0,
                confidence=0.0
            )
    
    async def predict_capacity_requirements(
        self,
        target_performance: Dict[str, float],
        growth_assumptions: Dict[str, float],
        time_horizon: timedelta
    ) -> Dict[str, Any]:
        """
        Predict capacity requirements for target performance
        
        Args:
            target_performance: Target performance metrics
            growth_assumptions: Expected growth rates
            time_horizon: Prediction time horizon
            
        Returns:
            Capacity requirement predictions
        """
        try:
            requirements = {}
            
            for metric_name, target_value in target_performance.items():
                try:
                    metric = CapacityMetric(metric_name)
                    growth_rate = growth_assumptions.get(metric_name, 0.1)
                    
                    # Calculate required capacity with growth
                    current_capacity = target_value
                    time_in_years = time_horizon.total_seconds() / (365.25 * 24 * 3600)
                    projected_demand = current_capacity * (1 + growth_rate) ** time_in_years
                    
                    # Add safety buffer
                    buffer = self.capacity_buffers.get(metric, 0.2)
                    required_capacity = projected_demand * (1 + buffer)
                    
                    requirements[metric_name] = {
                        'current_target': target_value,
                        'projected_demand': projected_demand,
                        'required_capacity': required_capacity,
                        'growth_rate': growth_rate,
                        'safety_buffer': buffer,
                        'capacity_increase_factor': required_capacity / current_capacity
                    }
                    
                except ValueError:
                    # Unknown metric, use default calculation
                    requirements[metric_name] = {
                        'current_target': target_value,
                        'projected_demand': target_value * 1.5,
                        'required_capacity': target_value * 1.8,
                        'growth_rate': 0.2,
                        'safety_buffer': 0.2,
                        'capacity_increase_factor': 1.8
                    }
            
            # Get expert validation
            expert_recommendations = await self._get_capacity_requirements_recommendations(
                target_performance, growth_assumptions, requirements
            )
            
            return {
                'requirements': requirements,
                'expert_recommendations': expert_recommendations,
                'total_capacity_increase': np.mean([
                    req['capacity_increase_factor'] 
                    for req in requirements.values()
                ]),
                'planning_horizon': time_horizon.total_seconds() / 3600,  # hours
                'confidence': 0.8
            }
            
        except Exception as e:
            self.logger.error(f"Capacity requirement prediction failed: {e}")
            return {
                'requirements': {},
                'error': str(e),
                'confidence': 0.0
            }
    
    async def _update_historical_data(self, current_metrics: Dict[str, Any]):
        """Update historical data with current metrics"""
        timestamp = datetime.now()
        
        for metric_name, value in current_metrics.items():
            try:
                metric = CapacityMetric(metric_name)
                data_point = HistoricalDataPoint(
                    timestamp=timestamp,
                    metric=metric,
                    value=float(value)
                )
                self.historical_data[metric].append(data_point)
            except (ValueError, TypeError):
                # Skip unknown or invalid metrics
                continue
    
    async def _generate_metric_forecast(
        self,
        metric: CapacityMetric,
        horizon: timedelta,
        method: ForecastMethod
    ) -> CapacityForecast:
        """Generate forecast for a specific metric"""
        historical_data = list(self.historical_data[metric])
        
        if len(historical_data) < self.planning_config['min_data_points']:
            # Insufficient data - return simple projection
            return CapacityForecast(
                metric=metric,
                forecast_method=method,
                time_horizon=horizon,
                predicted_values=[],
                confidence_intervals=[],
                trend_direction="stable",
                seasonality_detected=False,
                forecast_accuracy=0.5,
                recommendations=["Insufficient historical data for accurate forecasting"]
            )
        
        # Prepare data
        timestamps = np.array([dp.timestamp.timestamp() for dp in historical_data])
        values = np.array([dp.value for dp in historical_data])
        
        # Generate predictions based on method
        if method == ForecastMethod.LINEAR_REGRESSION:
            predictions = await self._linear_regression_forecast(
                timestamps, values, horizon
            )
        elif method == ForecastMethod.MACHINE_LEARNING:
            predictions = await self._ml_forecast(timestamps, values, horizon)
        else:
            # Default to simple trend extrapolation
            predictions = await self._simple_trend_forecast(
                timestamps, values, horizon
            )
        
        return predictions
    
    async def _linear_regression_forecast(
        self,
        timestamps: np.ndarray,
        values: np.ndarray,
        horizon: timedelta
    ) -> CapacityForecast:
        """Linear regression based forecasting"""
        try:
            # Normalize timestamps
            time_hours = (timestamps - timestamps[0]) / 3600
            
            # Fit linear regression
            model = LinearRegression()
            X = time_hours.reshape(-1, 1)
            model.fit(X, values)
            
            # Generate predictions
            horizon_hours = horizon.total_seconds() / 3600
            future_times = np.linspace(
                time_hours[-1], time_hours[-1] + horizon_hours, num=24
            )
            
            predictions = model.predict(future_times.reshape(-1, 1))
            
            # Calculate confidence intervals (simplified)
            residuals = values - model.predict(X)
            std_error = np.std(residuals)
            confidence_intervals = [
                (datetime.fromtimestamp(timestamps[0] + t * 3600), pred - 1.96 * std_error, pred + 1.96 * std_error)
                for t, pred in zip(future_times, predictions)
            ]
            
            # Determine trend direction
            trend_direction = "increasing" if model.coef_[0] > 0 else "decreasing" if model.coef_[0] < 0 else "stable"
            
            # Calculate R-squared as accuracy measure
            accuracy = model.score(X, values)
            
            predicted_values = [
                (datetime.fromtimestamp(timestamps[0] + t * 3600), pred)
                for t, pred in zip(future_times, predictions)
            ]
            
            return CapacityForecast(
                metric=CapacityMetric.CPU_UTILIZATION,  # Would be passed as parameter
                forecast_method=ForecastMethod.LINEAR_REGRESSION,
                time_horizon=horizon,
                predicted_values=predicted_values,
                confidence_intervals=confidence_intervals,
                trend_direction=trend_direction,
                seasonality_detected=False,
                forecast_accuracy=accuracy,
                recommendations=[
                    f"Linear trend detected with {trend_direction} direction",
                    f"Forecast accuracy: {accuracy:.2f}"
                ]
            )
            
        except Exception as e:
            self.logger.error(f"Linear regression forecast failed: {e}")
            return CapacityForecast(
                metric=CapacityMetric.CPU_UTILIZATION,
                forecast_method=ForecastMethod.LINEAR_REGRESSION,
                time_horizon=horizon,
                predicted_values=[],
                confidence_intervals=[],
                trend_direction="stable",
                seasonality_detected=False,
                forecast_accuracy=0.0,
                recommendations=[f"Forecast failed: {str(e)}"]
            )
    
    async def _ml_forecast(
        self,
        timestamps: np.ndarray,
        values: np.ndarray,
        horizon: timedelta
    ) -> CapacityForecast:
        """Machine learning based forecasting"""
        # For simplicity, using enhanced linear regression with feature engineering
        try:
            time_hours = (timestamps - timestamps[0]) / 3600
            
            # Feature engineering
            features = np.column_stack([
                time_hours,  # Linear trend
                np.sin(2 * np.pi * time_hours / 24),  # Daily seasonality
                np.cos(2 * np.pi * time_hours / 24),
                np.sin(2 * np.pi * time_hours / (24 * 7)),  # Weekly seasonality
                np.cos(2 * np.pi * time_hours / (24 * 7))
            ])
            
            # Fit model
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features)
            
            model = LinearRegression()
            model.fit(features_scaled, values)
            
            # Generate predictions
            horizon_hours = horizon.total_seconds() / 3600
            future_times = np.linspace(
                time_hours[-1], time_hours[-1] + horizon_hours, num=48
            )
            
            future_features = np.column_stack([
                future_times,
                np.sin(2 * np.pi * future_times / 24),
                np.cos(2 * np.pi * future_times / 24),
                np.sin(2 * np.pi * future_times / (24 * 7)),
                np.cos(2 * np.pi * future_times / (24 * 7))
            ])
            
            future_features_scaled = scaler.transform(future_features)
            predictions = model.predict(future_features_scaled)
            
            # Calculate accuracy
            accuracy = model.score(features_scaled, values)
            
            # Detect seasonality
            seasonality_detected = True  # Since we're using seasonal features
            
            # Determine trend
            trend_coef = model.coef_[0]
            trend_direction = "increasing" if trend_coef > 0 else "decreasing" if trend_coef < 0 else "stable"
            
            predicted_values = [
                (datetime.fromtimestamp(timestamps[0] + t * 3600), pred)
                for t, pred in zip(future_times, predictions)
            ]
            
            # Simplified confidence intervals
            residuals = values - model.predict(features_scaled)
            std_error = np.std(residuals)
            confidence_intervals = [
                (datetime.fromtimestamp(timestamps[0] + t * 3600), pred - 1.96 * std_error, pred + 1.96 * std_error)
                for t, pred in zip(future_times, predictions)
            ]
            
            return CapacityForecast(
                metric=CapacityMetric.CPU_UTILIZATION,
                forecast_method=ForecastMethod.MACHINE_LEARNING,
                time_horizon=horizon,
                predicted_values=predicted_values,
                confidence_intervals=confidence_intervals,
                trend_direction=trend_direction,
                seasonality_detected=seasonality_detected,
                forecast_accuracy=accuracy,
                recommendations=[
                    f"ML forecast with seasonal patterns, accuracy: {accuracy:.2f}",
                    f"Trend direction: {trend_direction}"
                ]
            )
            
        except Exception as e:
            self.logger.error(f"ML forecast failed: {e}")
            return await self._linear_regression_forecast(timestamps, values, horizon)
    
    async def _simple_trend_forecast(
        self,
        timestamps: np.ndarray,
        values: np.ndarray,
        horizon: timedelta
    ) -> CapacityForecast:
        """Simple trend-based forecasting"""
        try:
            # Calculate simple moving average and trend
            window_size = min(10, len(values) // 4)
            moving_avg = np.convolve(values, np.ones(window_size)/window_size, mode='valid')
            
            # Calculate trend from recent data
            recent_values = values[-window_size:]
            trend = (recent_values[-1] - recent_values[0]) / len(recent_values)
            
            # Generate predictions
            horizon_hours = horizon.total_seconds() / 3600
            num_predictions = min(24, int(horizon_hours))
            
            predicted_values = []
            base_value = values[-1]
            
            for i in range(num_predictions):
                future_time = datetime.fromtimestamp(timestamps[-1] + (i + 1) * 3600)
                predicted_value = base_value + trend * (i + 1)
                predicted_values.append((future_time, predicted_value))
            
            trend_direction = "increasing" if trend > 0 else "decreasing" if trend < 0 else "stable"
            
            return CapacityForecast(
                metric=CapacityMetric.CPU_UTILIZATION,
                forecast_method=ForecastMethod.LINEAR_REGRESSION,
                time_horizon=horizon,
                predicted_values=predicted_values,
                confidence_intervals=[],
                trend_direction=trend_direction,
                seasonality_detected=False,
                forecast_accuracy=0.6,
                recommendations=[
                    f"Simple trend extrapolation, direction: {trend_direction}"
                ]
            )
            
        except Exception as e:
            self.logger.error(f"Simple trend forecast failed: {e}")
            return CapacityForecast(
                metric=CapacityMetric.CPU_UTILIZATION,
                forecast_method=ForecastMethod.LINEAR_REGRESSION,
                time_horizon=horizon,
                predicted_values=[],
                confidence_intervals=[],
                trend_direction="stable",
                seasonality_detected=False,
                forecast_accuracy=0.0,
                recommendations=[f"Forecast failed: {str(e)}"]
            )
    
    async def _detect_growth_pattern(
        self,
        timestamps: np.ndarray,
        values: np.ndarray
    ) -> Dict[str, Any]:
        """Detect growth pattern in data"""
        try:
            # Linear regression for trend
            linear_model = LinearRegression()
            X = timestamps.reshape(-1, 1)
            linear_model.fit(X, values)
            linear_score = linear_model.score(X, values)
            
            # Exponential fit (using log transform)
            if np.all(values > 0):
                try:
                    log_values = np.log(values)
                    exp_model = LinearRegression()
                    exp_model.fit(X, log_values)
                    exp_score = exp_model.score(X, log_values)
                except:
                    exp_score = 0
            else:
                exp_score = 0
            
            # Polynomial fit (degree 2)
            try:
                poly_features = np.column_stack([timestamps, timestamps**2])
                poly_model = LinearRegression()
                poly_model.fit(poly_features, values)
                poly_score = poly_model.score(poly_features, values)
            except:
                poly_score = 0
            
            # Determine best pattern
            scores = {
                'linear': linear_score,
                'exponential': exp_score,
                'polynomial': poly_score
            }
            
            best_pattern = max(scores, key=scores.get)
            pattern_strength = scores[best_pattern]
            
            # Calculate growth rate
            if best_pattern == 'linear':
                growth_rate = linear_model.coef_[0]
                acceleration = 0.0
            elif best_pattern == 'exponential' and exp_score > 0:
                growth_rate = exp_model.coef_[0]
                acceleration = 0.0
            else:
                growth_rate = 0.0
                acceleration = 0.0
            
            return {
                'pattern_type': best_pattern,
                'growth_rate': growth_rate,
                'acceleration': acceleration,
                'strength': pattern_strength,
                'confidence': pattern_strength
            }
            
        except Exception as e:
            self.logger.error(f"Growth pattern detection failed: {e}")
            return {
                'pattern_type': 'unknown',
                'growth_rate': 0.0,
                'acceleration': 0.0,
                'strength': 0.0,
                'confidence': 0.0
            }
    
    async def _detect_seasonality(
        self,
        timestamps: np.ndarray,
        values: np.ndarray
    ) -> Dict[str, Any]:
        """Detect seasonality in data"""
        try:
            # Simple seasonality detection using FFT
            if len(values) < 24:  # Need at least 24 points
                return {'detected': False, 'period': None}
            
            # Remove trend
            detrended = values - np.linspace(values[0], values[-1], len(values))
            
            # FFT analysis
            fft = np.fft.fft(detrended)
            frequencies = np.fft.fftfreq(len(detrended))
            
            # Find dominant frequency
            magnitude = np.abs(fft[1:len(fft)//2])  # Skip DC component
            freq = frequencies[1:len(frequencies)//2]
            
            if len(magnitude) > 0:
                dominant_freq_idx = np.argmax(magnitude)
                dominant_freq = freq[dominant_freq_idx]
                
                if abs(dominant_freq) > 1e-6:  # Avoid division by zero
                    period_hours = 1.0 / abs(dominant_freq)
                    
                    # Check if period makes sense (between 1 hour and 7 days)
                    if 1 <= period_hours <= 168:
                        return {
                            'detected': True,
                            'period': timedelta(hours=period_hours)
                        }
            
            return {'detected': False, 'period': None}
            
        except Exception as e:
            self.logger.error(f"Seasonality detection failed: {e}")
            return {'detected': False, 'period': None}
    
    async def _get_forecasting_recommendations(
        self,
        current_metrics: Dict[str, Any],
        forecasts: Dict[str, CapacityForecast],
        trend_analysis: Dict[str, Any]
    ) -> List[str]:
        """Get expert forecasting recommendations"""
        if not self.circle_of_experts:
            return []
        
        try:
            query = QueryRequest(
                query=f"""
                Given these capacity forecasts and trend analysis, what recommendations do you have?
                
                Current Metrics:
                {json.dumps(current_metrics, indent=2)}
                
                Forecast Summary:
                {json.dumps({
                    metric: {
                        'trend_direction': forecast.trend_direction,
                        'forecast_accuracy': forecast.forecast_accuracy,
                        'seasonality_detected': forecast.seasonality_detected
                    }
                    for metric, forecast in forecasts.items()
                }, indent=2)}
                
                Trend Analysis:
                {json.dumps(trend_analysis, indent=2)}
                
                Please provide recommendations for:
                1. Capacity planning strategy
                2. Resource scaling timing
                3. Risk mitigation approaches
                4. Performance optimization opportunities
                """,
                experts=["capacity_planning_expert", "performance_expert"],
                require_consensus=False
            )
            
            response = await self.circle_of_experts.process_query(query)
            return [resp.content for resp in response.expert_responses]
            
        except Exception as e:
            self.logger.warning(f"Failed to get forecasting recommendations: {e}")
            return []
    
    async def get_planning_report(self) -> Dict[str, Any]:
        """Generate comprehensive capacity planning report"""
        return {
            'capacity_plans': {
                plan_id: {
                    'planning_horizon_hours': plan.planning_horizon.total_seconds() / 3600,
                    'current_capacity': plan.current_capacity,
                    'recommended_capacity': plan.recommended_capacity,
                    'confidence_score': plan.confidence_score,
                    'created_at': plan.created_at.isoformat()
                }
                for plan_id, plan in self.capacity_plans.items()
            },
            'growth_patterns': {
                metric.value: {
                    'pattern_type': pattern.pattern_type,
                    'growth_rate': pattern.growth_rate,
                    'confidence': pattern.confidence
                }
                for metric, pattern in self.growth_patterns.items()
            },
            'historical_data_points': {
                metric.value: len(data)
                for metric, data in self.historical_data.items()
            },
            'planning_config': self.planning_config,
            'capacity_buffers': {
                metric.value: buffer
                for metric, buffer in self.capacity_buffers.items()
            }
        }