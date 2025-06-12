#!/usr/bin/env python3
"""
Advanced Analytics Engine for Performance Metrics
Statistical analysis, trend detection, and forecasting capabilities
"""

import asyncio
import time
import logging
import threading
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque
import json
import statistics
import math
from datetime import datetime, timedelta
from enum import Enum
import numpy as np
from scipy import stats
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN

from metrics_collector import MetricValue
from real_time_processor import AnomalyDetectionResult, AlertLevel

# Enhanced logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TrendDirection(Enum):
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    OSCILLATING = "oscillating"
    UNKNOWN = "unknown"

class SeasonalityType(Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    NONE = "none"

@dataclass
class StatisticalAnalysis:
    """Comprehensive statistical analysis result"""
    metric_name: str
    count: int
    mean: float
    median: float
    mode: Optional[float]
    std_dev: float
    variance: float
    min_value: float
    max_value: float
    range_value: float
    percentiles: Dict[int, float]
    skewness: float
    kurtosis: float
    coefficient_of_variation: float
    timestamp: float

@dataclass
class TrendAnalysis:
    """Trend analysis result"""
    metric_name: str
    direction: TrendDirection
    slope: float
    correlation: float
    confidence: float
    forecast_values: List[float]
    forecast_timestamps: List[float]
    seasonality: SeasonalityType
    cycle_length: Optional[int]
    timestamp: float

@dataclass
class CorrelationAnalysis:
    """Correlation analysis between metrics"""
    metric1: str
    metric2: str
    correlation_coefficient: float
    p_value: float
    significance_level: float
    relationship_strength: str
    timestamp: float

@dataclass
class AnomalyCluster:
    """Cluster of related anomalies"""
    cluster_id: int
    metrics: List[str]
    anomalies: List[AnomalyDetectionResult]
    severity: AlertLevel
    start_time: float
    end_time: float
    duration: float
    impact_score: float

class AdvancedAnalyticsEngine:
    """Advanced analytics engine with statistical analysis and ML capabilities"""
    
    def __init__(self, analysis_interval: float = 60.0, history_size: int = 10000):
        self.analysis_interval = analysis_interval
        self.history_size = history_size
        self.metric_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=history_size))
        self.analysis_cache: Dict[str, Any] = {}
        self.running = False
        self.analysis_thread: Optional[threading.Thread] = None
        
        # Analysis components
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.scaler = StandardScaler()
        
        # Results storage
        self.statistical_results: Dict[str, StatisticalAnalysis] = {}
        self.trend_results: Dict[str, TrendAnalysis] = {}
        self.correlation_results: Dict[Tuple[str, str], CorrelationAnalysis] = {}
        self.anomaly_clusters: List[AnomalyCluster] = []
        
        # Performance tracking
        self.analysis_stats = {
            'total_analyses': 0,
            'analysis_errors': 0,
            'last_analysis_time': 0,
            'avg_analysis_duration': 0.0,
            'metrics_analyzed': 0,
            'correlations_found': 0,
            'anomaly_clusters': 0
        }
    
    def add_metric(self, metric: MetricValue):
        """Add metric to history for analysis"""
        if isinstance(metric.value, (int, float)):
            self.metric_history[metric.name].append({
                'value': metric.value,
                'timestamp': metric.timestamp,
                'tags': metric.tags,
                'metadata': metric.metadata
            })
    
    def start(self):
        """Start analytics engine"""
        if self.running:
            logger.warning("Analytics engine already running")
            return
        
        self.running = True
        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self.analysis_thread.start()
        
        logger.info("Started analytics engine")
    
    def stop(self):
        """Stop analytics engine"""
        self.running = False
        
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=10)
        
        logger.info("Stopped analytics engine")
    
    def _analysis_loop(self):
        """Main analysis loop"""
        while self.running:
            try:
                start_time = time.time()
                
                # Perform comprehensive analysis
                self._perform_statistical_analysis()
                self._perform_trend_analysis()
                self._perform_correlation_analysis()
                self._detect_advanced_anomalies()
                self._cluster_anomalies()
                
                # Update statistics
                analysis_duration = time.time() - start_time
                self.analysis_stats['total_analyses'] += 1
                self.analysis_stats['last_analysis_time'] = time.time()
                self.analysis_stats['avg_analysis_duration'] = (
                    (self.analysis_stats['avg_analysis_duration'] * 0.9) + 
                    (analysis_duration * 0.1)
                )
                
                # Sleep until next analysis
                elapsed = time.time() - start_time
                sleep_time = max(0, self.analysis_interval - elapsed)
                if sleep_time > 0:
                    time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Analysis loop error: {e}")
                self.analysis_stats['analysis_errors'] += 1
                time.sleep(self.analysis_interval)
    
    def _perform_statistical_analysis(self):
        """Perform comprehensive statistical analysis on all metrics"""
        for metric_name, history in self.metric_history.items():
            if len(history) < 10:  # Need minimum data points
                continue
            
            try:
                values = [item['value'] for item in history]
                timestamps = [item['timestamp'] for item in history]
                
                # Basic statistics
                count = len(values)
                mean_val = statistics.mean(values)
                median_val = statistics.median(values)
                std_dev = statistics.stdev(values) if count > 1 else 0
                variance = statistics.variance(values) if count > 1 else 0
                min_val = min(values)
                max_val = max(values)
                range_val = max_val - min_val
                
                # Mode calculation (for numeric data, use most frequent rounded value)
                try:
                    rounded_values = [round(v, 2) for v in values]
                    mode_val = statistics.mode(rounded_values)
                except statistics.StatisticsError:
                    mode_val = None
                
                # Percentiles
                percentiles = {}
                for p in [10, 25, 50, 75, 90, 95, 99]:
                    try:
                        percentiles[p] = np.percentile(values, p)
                    except Exception:
                        percentiles[p] = median_val
                
                # Advanced statistics using scipy
                try:
                    skewness = stats.skew(values)
                    kurtosis = stats.kurtosis(values)
                    cv = std_dev / mean_val if mean_val != 0 else 0
                except Exception:
                    skewness = 0
                    kurtosis = 0
                    cv = 0
                
                # Store results
                analysis = StatisticalAnalysis(
                    metric_name=metric_name,
                    count=count,
                    mean=mean_val,
                    median=median_val,
                    mode=mode_val,
                    std_dev=std_dev,
                    variance=variance,
                    min_value=min_val,
                    max_value=max_val,
                    range_value=range_val,
                    percentiles=percentiles,
                    skewness=skewness,
                    kurtosis=kurtosis,
                    coefficient_of_variation=cv,
                    timestamp=time.time()
                )
                
                self.statistical_results[metric_name] = analysis
                self.analysis_stats['metrics_analyzed'] += 1
                
            except Exception as e:
                logger.error(f"Statistical analysis error for {metric_name}: {e}")
    
    def _perform_trend_analysis(self):
        """Perform trend analysis and forecasting"""
        for metric_name, history in self.metric_history.items():
            if len(history) < 20:  # Need more data for trend analysis
                continue
            
            try:
                values = np.array([item['value'] for item in history])
                timestamps = np.array([item['timestamp'] for item in history])
                
                # Normalize timestamps for analysis
                time_normalized = (timestamps - timestamps[0]) / 3600  # Convert to hours
                
                # Linear trend analysis
                slope, intercept, r_value, p_value, std_err = stats.linregress(time_normalized, values)
                
                # Determine trend direction
                if abs(slope) < std_err * 2:  # Not statistically significant
                    direction = TrendDirection.STABLE
                elif slope > 0:
                    direction = TrendDirection.INCREASING
                else:
                    direction = TrendDirection.DECREASING
                
                # Check for oscillation
                if self._detect_oscillation(values):
                    direction = TrendDirection.OSCILLATING
                
                # Confidence based on R-squared
                confidence = r_value ** 2
                
                # Forecasting (simple linear extrapolation)
                forecast_hours = 12  # Forecast next 12 hours
                future_times = np.linspace(time_normalized[-1], time_normalized[-1] + forecast_hours, 24)
                forecast_values = slope * future_times + intercept
                forecast_timestamps = future_times * 3600 + timestamps[0]
                
                # Seasonality detection
                seasonality, cycle_length = self._detect_seasonality(values, timestamps)
                
                # Store results
                trend = TrendAnalysis(
                    metric_name=metric_name,
                    direction=direction,
                    slope=slope,
                    correlation=r_value,
                    confidence=confidence,
                    forecast_values=forecast_values.tolist(),
                    forecast_timestamps=forecast_timestamps.tolist(),
                    seasonality=seasonality,
                    cycle_length=cycle_length,
                    timestamp=time.time()
                )
                
                self.trend_results[metric_name] = trend
                
            except Exception as e:
                logger.error(f"Trend analysis error for {metric_name}: {e}")
    
    def _detect_oscillation(self, values: np.ndarray) -> bool:
        """Detect if data shows oscillating pattern"""
        try:
            # Simple oscillation detection using zero crossings of first derivative
            if len(values) < 10:
                return False
            
            diff = np.diff(values)
            sign_changes = np.where(np.diff(np.sign(diff)))[0]
            
            # If we have many sign changes relative to data length, it's oscillating
            oscillation_ratio = len(sign_changes) / len(values)
            return oscillation_ratio > 0.1
            
        except Exception:
            return False
    
    def _detect_seasonality(self, values: np.ndarray, timestamps: np.ndarray) -> Tuple[SeasonalityType, Optional[int]]:
        """Detect seasonality in the data"""
        try:
            if len(values) < 100:  # Need substantial data for seasonality
                return SeasonalityType.NONE, None
            
            # Convert timestamps to time differences in hours
            time_hours = (timestamps - timestamps[0]) / 3600
            
            # Check for daily patterns (24-hour cycles)
            daily_cycle = 24
            if len(values) > daily_cycle * 3:  # At least 3 days of data
                if self._check_cycle_strength(values, daily_cycle):
                    return SeasonalityType.DAILY, daily_cycle
            
            # Check for weekly patterns (168-hour cycles)
            weekly_cycle = 168
            if len(values) > weekly_cycle * 2:  # At least 2 weeks of data
                if self._check_cycle_strength(values, weekly_cycle):
                    return SeasonalityType.WEEKLY, weekly_cycle
            
            return SeasonalityType.NONE, None
            
        except Exception:
            return SeasonalityType.NONE, None
    
    def _check_cycle_strength(self, values: np.ndarray, cycle_length: int) -> bool:
        """Check if a specific cycle length shows strong periodicity"""
        try:
            # Use autocorrelation to detect cycles
            if len(values) < cycle_length * 2:
                return False
            
            # Calculate autocorrelation at the cycle lag
            correlation = np.corrcoef(values[:-cycle_length], values[cycle_length:])[0, 1]
            
            # Strong cycle if correlation > 0.3
            return not np.isnan(correlation) and correlation > 0.3
            
        except Exception:
            return False
    
    def _perform_correlation_analysis(self):
        """Perform correlation analysis between metrics"""
        metric_names = list(self.metric_history.keys())
        
        for i, metric1 in enumerate(metric_names):
            for metric2 in metric_names[i+1:]:
                if len(self.metric_history[metric1]) < 20 or len(self.metric_history[metric2]) < 20:
                    continue
                
                try:
                    # Get synchronized data points
                    values1, values2 = self._synchronize_metrics(metric1, metric2)
                    
                    if len(values1) < 10:
                        continue
                    
                    # Calculate correlation
                    correlation, p_value = stats.pearsonr(values1, values2)
                    
                    # Determine relationship strength
                    abs_corr = abs(correlation)
                    if abs_corr > 0.8:
                        strength = "very_strong"
                    elif abs_corr > 0.6:
                        strength = "strong"
                    elif abs_corr > 0.4:
                        strength = "moderate"
                    elif abs_corr > 0.2:
                        strength = "weak"
                    else:
                        strength = "very_weak"
                    
                    # Store results for significant correlations
                    if abs_corr > 0.3:  # Only store meaningful correlations
                        correlation_result = CorrelationAnalysis(
                            metric1=metric1,
                            metric2=metric2,
                            correlation_coefficient=correlation,
                            p_value=p_value,
                            significance_level=0.05,
                            relationship_strength=strength,
                            timestamp=time.time()
                        )
                        
                        self.correlation_results[(metric1, metric2)] = correlation_result
                        self.analysis_stats['correlations_found'] += 1
                
                except Exception as e:
                    logger.error(f"Correlation analysis error for {metric1} vs {metric2}: {e}")
    
    def _synchronize_metrics(self, metric1: str, metric2: str) -> Tuple[List[float], List[float]]:
        """Synchronize two metrics by timestamp for correlation analysis"""
        history1 = list(self.metric_history[metric1])
        history2 = list(self.metric_history[metric2])
        
        # Create timestamp-value mappings
        data1 = {item['timestamp']: item['value'] for item in history1}
        data2 = {item['timestamp']: item['value'] for item in history2}
        
        # Find common timestamps (within 5-second tolerance)
        values1, values2 = [], []
        for ts1, val1 in data1.items():
            for ts2, val2 in data2.items():
                if abs(ts1 - ts2) <= 5:  # 5-second tolerance
                    values1.append(val1)
                    values2.append(val2)
                    break
        
        return values1, values2
    
    def _detect_advanced_anomalies(self):
        """Detect anomalies using machine learning approaches"""
        for metric_name, history in self.metric_history.items():
            if len(history) < 50:  # Need sufficient data for ML
                continue
            
            try:
                values = np.array([item['value'] for item in history]).reshape(-1, 1)
                
                # Fit isolation forest for anomaly detection
                outliers = self.isolation_forest.fit_predict(values)
                
                # Find anomalous points
                for i, (outlier, item) in enumerate(zip(outliers, history)):
                    if outlier == -1:  # Anomaly detected
                        # Create enhanced anomaly result
                        anomaly = AnomalyDetectionResult(
                            metric_name=metric_name,
                            is_anomaly=True,
                            confidence=0.8,  # ML-based confidence
                            reason="Machine learning anomaly detection",
                            current_value=item['value'],
                            expected_range=(min(v['value'] for v in history), 
                                          max(v['value'] for v in history)),
                            timestamp=item['timestamp']
                        )
                        
                        # Store for clustering
                        if not hasattr(self, '_ml_anomalies'):
                            self._ml_anomalies = []
                        self._ml_anomalies.append(anomaly)
            
            except Exception as e:
                logger.error(f"ML anomaly detection error for {metric_name}: {e}")
    
    def _cluster_anomalies(self):
        """Cluster related anomalies to identify system-wide issues"""
        if not hasattr(self, '_ml_anomalies') or len(self._ml_anomalies) < 5:
            return
        
        try:
            # Prepare data for clustering (timestamp + normalized values)
            cluster_data = []
            anomaly_list = []
            
            for anomaly in self._ml_anomalies:
                if time.time() - anomaly.timestamp < 3600:  # Only recent anomalies
                    cluster_data.append([
                        anomaly.timestamp / 3600,  # Normalize timestamp to hours
                        anomaly.current_value / 100,  # Normalize value
                        hash(anomaly.metric_name) % 1000 / 1000  # Metric identifier
                    ])
                    anomaly_list.append(anomaly)
            
            if len(cluster_data) < 5:
                return
            
            # Perform clustering
            cluster_data = np.array(cluster_data)
            clusters = self.dbscan.fit_predict(cluster_data)
            
            # Group anomalies by cluster
            cluster_groups = defaultdict(list)
            for anomaly, cluster_id in zip(anomaly_list, clusters):
                if cluster_id != -1:  # Ignore noise points
                    cluster_groups[cluster_id].append(anomaly)
            
            # Create anomaly clusters
            self.anomaly_clusters = []
            for cluster_id, anomalies in cluster_groups.items():
                if len(anomalies) >= 3:  # Only significant clusters
                    metrics = list(set(a.metric_name for a in anomalies))
                    start_time = min(a.timestamp for a in anomalies)
                    end_time = max(a.timestamp for a in anomalies)
                    duration = end_time - start_time
                    
                    # Calculate impact score based on number of metrics and duration
                    impact_score = len(metrics) * math.log(duration + 1)
                    
                    # Determine severity
                    if impact_score > 10:
                        severity = AlertLevel.CRITICAL
                    elif impact_score > 5:
                        severity = AlertLevel.WARNING
                    else:
                        severity = AlertLevel.INFO
                    
                    cluster = AnomalyCluster(
                        cluster_id=cluster_id,
                        metrics=metrics,
                        anomalies=anomalies,
                        severity=severity,
                        start_time=start_time,
                        end_time=end_time,
                        duration=duration,
                        impact_score=impact_score
                    )
                    
                    self.anomaly_clusters.append(cluster)
                    self.analysis_stats['anomaly_clusters'] += 1
        
        except Exception as e:
            logger.error(f"Anomaly clustering error: {e}")
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """Get comprehensive analytics report"""
        return {
            'timestamp': time.time(),
            'analysis_stats': self.analysis_stats,
            'statistical_summaries': {
                name: {
                    'mean': result.mean,
                    'std_dev': result.std_dev,
                    'trend_direction': self.trend_results.get(name, {}).direction.value if name in self.trend_results else 'unknown',
                    'anomaly_risk': 'high' if any(name in cluster.metrics for cluster in self.anomaly_clusters) else 'low'
                }
                for name, result in self.statistical_results.items()
            },
            'trends': {
                name: {
                    'direction': result.direction.value,
                    'confidence': result.confidence,
                    'seasonality': result.seasonality.value
                }
                for name, result in self.trend_results.items()
            },
            'correlations': [
                {
                    'metrics': [corr.metric1, corr.metric2],
                    'correlation': corr.correlation_coefficient,
                    'strength': corr.relationship_strength
                }
                for corr in self.correlation_results.values()
                if abs(corr.correlation_coefficient) > 0.5
            ],
            'anomaly_clusters': [
                {
                    'id': cluster.cluster_id,
                    'metrics': cluster.metrics,
                    'severity': cluster.severity.value,
                    'duration': cluster.duration,
                    'impact_score': cluster.impact_score
                }
                for cluster in self.anomaly_clusters
            ]
        }
    
    def get_metric_insights(self, metric_name: str) -> Dict[str, Any]:
        """Get detailed insights for a specific metric"""
        insights = {
            'metric_name': metric_name,
            'timestamp': time.time()
        }
        
        # Statistical insights
        if metric_name in self.statistical_results:
            stat = self.statistical_results[metric_name]
            insights['statistics'] = {
                'mean': stat.mean,
                'std_dev': stat.std_dev,
                'coefficient_of_variation': stat.coefficient_of_variation,
                'percentiles': stat.percentiles,
                'distribution_shape': 'normal' if -0.5 < stat.skewness < 0.5 else 'skewed'
            }
        
        # Trend insights
        if metric_name in self.trend_results:
            trend = self.trend_results[metric_name]
            insights['trend'] = {
                'direction': trend.direction.value,
                'confidence': trend.confidence,
                'seasonality': trend.seasonality.value,
                'forecast': trend.forecast_values[:12] if trend.forecast_values else []
            }
        
        # Correlation insights
        related_metrics = []
        for (m1, m2), corr in self.correlation_results.items():
            if m1 == metric_name or m2 == metric_name:
                other_metric = m2 if m1 == metric_name else m1
                related_metrics.append({
                    'metric': other_metric,
                    'correlation': corr.correlation_coefficient,
                    'strength': corr.relationship_strength
                })
        
        insights['correlations'] = sorted(related_metrics, key=lambda x: abs(x['correlation']), reverse=True)[:5]
        
        # Anomaly insights
        insights['anomaly_risk'] = 'high' if any(metric_name in cluster.metrics for cluster in self.anomaly_clusters) else 'low'
        
        return insights

# Example usage
async def main():
    """Example usage of the analytics engine"""
    from metrics_collector import MetricsCollector
    
    # Create analytics engine
    analytics = AdvancedAnalyticsEngine(analysis_interval=30.0)
    
    # Create metrics collector
    collector = MetricsCollector(collection_interval=1.0)
    
    # Connect collector to analytics
    collector.add_callback(analytics.add_metric)
    
    # Start both systems
    analytics.start()
    collector.start()
    
    try:
        # Run for 5 minutes to collect data
        await asyncio.sleep(300)
        
        # Get comprehensive report
        report = analytics.get_comprehensive_report()
        
        print("=== Analytics Report ===")
        print(json.dumps(report, indent=2, default=str))
        
        # Get insights for CPU metric
        if 'system.cpu_usage_percent' in analytics.statistical_results:
            cpu_insights = analytics.get_metric_insights('system.cpu_usage_percent')
            print("\n=== CPU Insights ===")
            print(json.dumps(cpu_insights, indent=2, default=str))
    
    finally:
        collector.stop()
        analytics.stop()

if __name__ == "__main__":
    asyncio.run(main())