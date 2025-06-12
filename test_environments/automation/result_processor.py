"""
Test Result Processor - Advanced test result analysis and processing.

This module provides comprehensive result processing capabilities including
analysis, aggregation, anomaly detection, and trend analysis.
"""

import json
import logging
import statistics
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
import numpy as np
from scipy import stats
import pandas as pd

from prometheus_client import Counter, Histogram, Gauge, Summary

logger = logging.getLogger(__name__)

# Metrics
processed_results = Counter('processed_results_total', 'Total processed results', ['test_type', 'status'])
processing_duration = Histogram('processing_duration_seconds', 'Result processing duration')
anomalies_detected = Counter('anomalies_detected_total', 'Anomalies detected', ['anomaly_type'])
trend_analysis_runs = Counter('trend_analysis_runs_total', 'Trend analysis runs')


class AnalysisType(Enum):
    """Types of result analysis."""
    BASIC = "basic"
    STATISTICAL = "statistical"
    TREND = "trend"
    ANOMALY = "anomaly"
    PERFORMANCE = "performance"
    REGRESSION = "regression"


class SeverityLevel(Enum):
    """Severity levels for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TestMetric:
    """Test metric data."""
    name: str
    value: float
    unit: str
    timestamp: datetime
    test_name: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceBaseline:
    """Performance baseline for comparison."""
    test_name: str
    metric_name: str
    baseline_value: float
    variance_threshold: float = 0.15  # 15% variance allowed
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    sample_count: int = 0


@dataclass
class Anomaly:
    """Detected anomaly."""
    test_name: str
    metric_name: str
    expected_value: float
    actual_value: float
    deviation_percent: float
    severity: SeverityLevel
    detection_method: str
    timestamp: datetime
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrendAnalysis:
    """Trend analysis result."""
    test_name: str
    metric_name: str
    trend_direction: str  # "increasing", "decreasing", "stable"
    slope: float
    r_squared: float
    confidence_level: float
    period_days: int
    sample_count: int
    significance: SeverityLevel


@dataclass
class ProcessedResults:
    """Comprehensive processed test results."""
    summary: Dict[str, Any]
    metrics: List[TestMetric]
    baselines: Dict[str, PerformanceBaseline]
    anomalies: List[Anomaly]
    trends: List[TrendAnalysis]
    recommendations: List[str]
    quality_score: float
    processing_metadata: Dict[str, Any]


class ResultProcessor:
    """Advanced test result processor with analysis capabilities."""
    
    def __init__(self, baseline_file: Optional[str] = None):
        self.baselines: Dict[str, PerformanceBaseline] = {}
        self.historical_data: Dict[str, List[TestMetric]] = defaultdict(list)
        self.baseline_file = baseline_file or "test_baselines.json"
        
        # Load existing baselines
        self._load_baselines()
        
        # Analysis configuration
        self.anomaly_thresholds = {
            'performance': 0.20,  # 20% deviation
            'memory': 0.25,       # 25% deviation
            'cpu': 0.30,          # 30% deviation
            'duration': 0.15      # 15% deviation
        }
        
        self.trend_analysis_config = {
            'min_samples': 10,
            'analysis_period_days': 30,
            'significance_threshold': 0.05
        }
        
        logger.info("Result processor initialized")
        
    def process_results(self, results: List[Any]) -> ProcessedResults:
        """Process test results with comprehensive analysis."""
        start_time = datetime.now()
        
        try:
            # Extract metrics from results
            metrics = self._extract_metrics(results)
            
            # Update baselines
            self._update_baselines(metrics)
            
            # Detect anomalies
            anomalies = self._detect_anomalies(metrics)
            
            # Perform trend analysis
            trends = self._analyze_trends(metrics)
            
            # Generate summary
            summary = self._generate_summary(results, metrics, anomalies, trends)
            
            # Calculate quality score
            quality_score = self._calculate_quality_score(results, anomalies, trends)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(results, anomalies, trends)
            
            # Create processed results
            processed = ProcessedResults(
                summary=summary,
                metrics=metrics,
                baselines=dict(self.baselines),
                anomalies=anomalies,
                trends=trends,
                recommendations=recommendations,
                quality_score=quality_score,
                processing_metadata={
                    'processed_at': datetime.now().isoformat(),
                    'processing_duration': (datetime.now() - start_time).total_seconds(),
                    'total_tests': len(results),
                    'total_metrics': len(metrics),
                    'anomalies_count': len(anomalies),
                    'trends_count': len(trends)
                }
            )
            
            # Update metrics
            processing_duration.observe((datetime.now() - start_time).total_seconds())
            
            for result in results:
                status = 'passed' if getattr(result, 'success', True) else 'failed'
                test_type = getattr(result, 'test_type', 'unknown')
                processed_results.labels(test_type=test_type, status=status).inc()
                
            return processed
            
        except Exception as e:
            logger.error(f"Error processing results: {e}")
            raise
            
    def _extract_metrics(self, results: List[Any]) -> List[TestMetric]:
        """Extract metrics from test results."""
        metrics = []
        
        for result in results:
            try:
                test_name = getattr(result, 'test_name', 'unknown')
                timestamp = getattr(result, 'end_time', datetime.now())
                
                # Extract duration metric
                duration = getattr(result, 'duration', 0)
                if duration > 0:
                    metrics.append(TestMetric(
                        name='duration',
                        value=duration,
                        unit='seconds',
                        timestamp=timestamp,
                        test_name=test_name
                    ))
                    
                # Extract resource usage metrics
                resource_usage = getattr(result, 'resource_usage', {})
                if resource_usage:
                    for metric_name, value in resource_usage.items():
                        if isinstance(value, (int, float)):
                            unit = self._get_metric_unit(metric_name)
                            metrics.append(TestMetric(
                                name=metric_name,
                                value=float(value),
                                unit=unit,
                                timestamp=timestamp,
                                test_name=test_name
                            ))
                            
                # Extract custom metrics
                custom_metrics = getattr(result, 'metrics', {})
                if custom_metrics:
                    for metric_name, value in custom_metrics.items():
                        if isinstance(value, (int, float)):
                            unit = self._get_metric_unit(metric_name)
                            metrics.append(TestMetric(
                                name=metric_name,
                                value=float(value),
                                unit=unit,
                                timestamp=timestamp,
                                test_name=test_name,
                                metadata=custom_metrics
                            ))
                            
            except Exception as e:
                logger.warning(f"Error extracting metrics from result: {e}")
                
        # Add to historical data
        for metric in metrics:
            key = f"{metric.test_name}:{metric.name}"
            self.historical_data[key].append(metric)
            
            # Keep only recent data (last 1000 entries)
            if len(self.historical_data[key]) > 1000:
                self.historical_data[key] = self.historical_data[key][-1000:]
                
        return metrics
        
    def _get_metric_unit(self, metric_name: str) -> str:
        """Get appropriate unit for metric."""
        metric_units = {
            'duration': 'seconds',
            'memory_mb': 'MB',
            'memory': 'MB',
            'cpu_percent': 'percent',
            'cpu': 'percent',
            'disk_mb': 'MB',
            'disk': 'MB',
            'requests_per_second': 'req/s',
            'response_time': 'ms',
            'throughput': 'ops/s',
            'latency': 'ms',
            'error_rate': 'percent'
        }
        
        for pattern, unit in metric_units.items():
            if pattern in metric_name.lower():
                return unit
                
        return 'units'
        
    def _update_baselines(self, metrics: List[TestMetric]) -> None:
        """Update performance baselines."""
        for metric in metrics:
            key = f"{metric.test_name}:{metric.name}"
            
            if key not in self.baselines:
                # Create new baseline
                self.baselines[key] = PerformanceBaseline(
                    test_name=metric.test_name,
                    metric_name=metric.name,
                    baseline_value=metric.value,
                    sample_count=1
                )
            else:
                # Update existing baseline using exponential moving average
                baseline = self.baselines[key]
                alpha = 0.1  # Smoothing factor
                baseline.baseline_value = (
                    alpha * metric.value + (1 - alpha) * baseline.baseline_value
                )
                baseline.sample_count += 1
                baseline.updated_at = datetime.now()
                
        # Save baselines
        self._save_baselines()
        
    def _detect_anomalies(self, metrics: List[TestMetric]) -> List[Anomaly]:
        """Detect anomalies in test metrics."""
        anomalies = []
        
        for metric in metrics:
            key = f"{metric.test_name}:{metric.name}"
            baseline = self.baselines.get(key)
            
            if baseline and baseline.sample_count >= 5:  # Need sufficient history
                # Calculate deviation
                deviation = abs(metric.value - baseline.baseline_value) / baseline.baseline_value
                
                # Get threshold for this metric type
                threshold = self._get_anomaly_threshold(metric.name)
                
                if deviation > threshold:
                    severity = self._determine_severity(deviation, threshold)
                    
                    anomaly = Anomaly(
                        test_name=metric.test_name,
                        metric_name=metric.name,
                        expected_value=baseline.baseline_value,
                        actual_value=metric.value,
                        deviation_percent=deviation * 100,
                        severity=severity,
                        detection_method='baseline_deviation',
                        timestamp=metric.timestamp,
                        context={
                            'baseline_samples': baseline.sample_count,
                            'threshold_percent': threshold * 100
                        }
                    )
                    
                    anomalies.append(anomaly)
                    anomalies_detected.labels(anomaly_type=metric.name).inc()
                    
            # Statistical anomaly detection for metrics with sufficient history
            historical = self.historical_data.get(key, [])
            if len(historical) >= 20:
                statistical_anomalies = self._detect_statistical_anomalies(metric, historical)
                anomalies.extend(statistical_anomalies)
                
        return anomalies
        
    def _get_anomaly_threshold(self, metric_name: str) -> float:
        """Get anomaly threshold for metric type."""
        for pattern, threshold in self.anomaly_thresholds.items():
            if pattern in metric_name.lower():
                return threshold
        return 0.20  # Default 20% threshold
        
    def _determine_severity(self, deviation: float, threshold: float) -> SeverityLevel:
        """Determine severity level based on deviation."""
        if deviation > threshold * 3:
            return SeverityLevel.CRITICAL
        elif deviation > threshold * 2:
            return SeverityLevel.HIGH
        elif deviation > threshold * 1.5:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
            
    def _detect_statistical_anomalies(self, current_metric: TestMetric, 
                                    historical: List[TestMetric]) -> List[Anomaly]:
        """Detect anomalies using statistical methods."""
        anomalies = []
        
        try:
            values = [m.value for m in historical[-50:]]  # Last 50 values
            
            if len(values) < 10:
                return anomalies
                
            # Z-score based detection
            mean_val = statistics.mean(values)
            std_val = statistics.stdev(values) if len(values) > 1 else 0
            
            if std_val > 0:
                z_score = abs(current_metric.value - mean_val) / std_val
                
                if z_score > 3:  # 3-sigma rule
                    severity = SeverityLevel.HIGH if z_score > 4 else SeverityLevel.MEDIUM
                    
                    anomaly = Anomaly(
                        test_name=current_metric.test_name,
                        metric_name=current_metric.name,
                        expected_value=mean_val,
                        actual_value=current_metric.value,
                        deviation_percent=abs(current_metric.value - mean_val) / mean_val * 100,
                        severity=severity,
                        detection_method='statistical_zscore',
                        timestamp=current_metric.timestamp,
                        context={
                            'z_score': z_score,
                            'mean': mean_val,
                            'std_dev': std_val,
                            'sample_size': len(values)
                        }
                    )
                    
                    anomalies.append(anomaly)
                    
            # Interquartile Range (IQR) based detection
            q1 = np.percentile(values, 25)
            q3 = np.percentile(values, 75)
            iqr = q3 - q1
            
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            
            if current_metric.value < lower_bound or current_metric.value > upper_bound:
                # Check if this is more severe than z-score detection
                deviation = max(
                    abs(current_metric.value - lower_bound) / (upper_bound - lower_bound),
                    abs(current_metric.value - upper_bound) / (upper_bound - lower_bound)
                ) if upper_bound != lower_bound else 0
                
                severity = SeverityLevel.MEDIUM if deviation > 2 else SeverityLevel.LOW
                
                # Only add if not already detected by z-score
                if not any(a.detection_method == 'statistical_zscore' and 
                          a.test_name == current_metric.test_name and
                          a.metric_name == current_metric.name for a in anomalies):
                    
                    anomaly = Anomaly(
                        test_name=current_metric.test_name,
                        metric_name=current_metric.name,
                        expected_value=(q1 + q3) / 2,
                        actual_value=current_metric.value,
                        deviation_percent=deviation * 100,
                        severity=severity,
                        detection_method='statistical_iqr',
                        timestamp=current_metric.timestamp,
                        context={
                            'q1': q1,
                            'q3': q3,
                            'iqr': iqr,
                            'lower_bound': lower_bound,
                            'upper_bound': upper_bound
                        }
                    )
                    
                    anomalies.append(anomaly)
                    
        except Exception as e:
            logger.warning(f"Error in statistical anomaly detection: {e}")
            
        return anomalies
        
    def _analyze_trends(self, metrics: List[TestMetric]) -> List[TrendAnalysis]:
        """Analyze trends in test metrics."""
        trends = []
        trend_analysis_runs.inc()
        
        # Group metrics by test and metric name
        metric_groups = defaultdict(list)
        for metric in metrics:
            key = f"{metric.test_name}:{metric.name}"
            metric_groups[key].append(metric)
            
        # Include historical data for trend analysis
        for key, current_metrics in metric_groups.items():
            historical = self.historical_data.get(key, [])
            all_metrics = historical + current_metrics
            
            if len(all_metrics) >= self.trend_analysis_config['min_samples']:
                trend = self._calculate_trend(key, all_metrics)
                if trend:
                    trends.append(trend)
                    
        return trends
        
    def _calculate_trend(self, metric_key: str, metrics: List[TestMetric]) -> Optional[TrendAnalysis]:
        """Calculate trend for a specific metric."""
        try:
            test_name, metric_name = metric_key.split(':', 1)
            
            # Filter to recent data
            cutoff_date = datetime.now() - timedelta(days=self.trend_analysis_config['analysis_period_days'])
            recent_metrics = [m for m in metrics if m.timestamp >= cutoff_date]
            
            if len(recent_metrics) < self.trend_analysis_config['min_samples']:
                return None
                
            # Prepare data for regression
            timestamps = [(m.timestamp - recent_metrics[0].timestamp).total_seconds() 
                         for m in recent_metrics]
            values = [m.value for m in recent_metrics]
            
            # Perform linear regression
            slope, intercept, r_value, p_value, std_err = stats.linregress(timestamps, values)
            r_squared = r_value ** 2
            
            # Determine trend direction
            if abs(slope) < std_err:
                trend_direction = "stable"
                significance = SeverityLevel.INFO
            elif slope > 0:
                trend_direction = "increasing"
                significance = self._get_trend_significance(slope, std_err, p_value)
            else:
                trend_direction = "decreasing"
                significance = self._get_trend_significance(abs(slope), std_err, p_value)
                
            confidence_level = 1 - p_value
            
            return TrendAnalysis(
                test_name=test_name,
                metric_name=metric_name,
                trend_direction=trend_direction,
                slope=slope,
                r_squared=r_squared,
                confidence_level=confidence_level,
                period_days=self.trend_analysis_config['analysis_period_days'],
                sample_count=len(recent_metrics),
                significance=significance
            )
            
        except Exception as e:
            logger.warning(f"Error calculating trend for {metric_key}: {e}")
            return None
            
    def _get_trend_significance(self, slope: float, std_err: float, p_value: float) -> SeverityLevel:
        """Determine trend significance level."""
        if p_value > self.trend_analysis_config['significance_threshold']:
            return SeverityLevel.INFO
            
        slope_ratio = abs(slope) / std_err if std_err > 0 else 0
        
        if slope_ratio > 5:
            return SeverityLevel.HIGH
        elif slope_ratio > 3:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
            
    def _generate_summary(self, results: List[Any], metrics: List[TestMetric],
                         anomalies: List[Anomaly], trends: List[TrendAnalysis]) -> Dict[str, Any]:
        """Generate comprehensive summary."""
        total_tests = len(results)
        passed_tests = sum(1 for r in results if getattr(r, 'success', True))
        failed_tests = total_tests - passed_tests
        
        # Test duration statistics
        durations = [getattr(r, 'duration', 0) for r in results if getattr(r, 'duration', 0) > 0]
        duration_stats = {}
        if durations:
            duration_stats = {
                'total': sum(durations),
                'average': statistics.mean(durations),
                'median': statistics.median(durations),
                'min': min(durations),
                'max': max(durations),
                'std_dev': statistics.stdev(durations) if len(durations) > 1 else 0
            }
            
        # Anomaly summary
        anomaly_summary = {
            'total': len(anomalies),
            'by_severity': dict(Counter(a.severity.value for a in anomalies)),
            'by_metric': dict(Counter(a.metric_name for a in anomalies))
        }
        
        # Trend summary
        trend_summary = {
            'total': len(trends),
            'by_direction': dict(Counter(t.trend_direction for t in trends)),
            'by_significance': dict(Counter(t.significance.value for t in trends))
        }
        
        return {
            'execution_summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': failed_tests,
                'success_rate': passed_tests / total_tests if total_tests > 0 else 0,
                'duration_stats': duration_stats
            },
            'metrics_summary': {
                'total_metrics': len(metrics),
                'unique_metrics': len(set(m.name for m in metrics)),
                'test_coverage': len(set(m.test_name for m in metrics))
            },
            'anomaly_summary': anomaly_summary,
            'trend_summary': trend_summary,
            'overall_health': self._calculate_health_score(results, anomalies, trends)
        }
        
    def _calculate_quality_score(self, results: List[Any], anomalies: List[Anomaly],
                               trends: List[TrendAnalysis]) -> float:
        """Calculate overall quality score (0-100)."""
        if not results:
            return 0.0
            
        # Base score from test success rate
        success_rate = sum(1 for r in results if getattr(r, 'success', True)) / len(results)
        base_score = success_rate * 60  # Up to 60 points for passing tests
        
        # Deduct points for anomalies
        anomaly_penalty = 0
        for anomaly in anomalies:
            if anomaly.severity == SeverityLevel.CRITICAL:
                anomaly_penalty += 10
            elif anomaly.severity == SeverityLevel.HIGH:
                anomaly_penalty += 5
            elif anomaly.severity == SeverityLevel.MEDIUM:
                anomaly_penalty += 2
            else:
                anomaly_penalty += 1
                
        # Deduct points for negative trends
        trend_penalty = 0
        for trend in trends:
            if trend.significance in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                if trend.trend_direction == "increasing" and "error" in trend.metric_name.lower():
                    trend_penalty += 5
                elif trend.trend_direction == "decreasing" and "performance" in trend.metric_name.lower():
                    trend_penalty += 5
                    
        # Performance consistency bonus
        consistency_bonus = min(20, max(0, 20 - len(anomalies)))
        
        # Trend stability bonus
        stable_trends = sum(1 for t in trends if t.trend_direction == "stable")
        stability_bonus = min(20, stable_trends * 2)
        
        total_score = base_score + consistency_bonus + stability_bonus - anomaly_penalty - trend_penalty
        return max(0, min(100, total_score))
        
    def _calculate_health_score(self, results: List[Any], anomalies: List[Anomaly],
                              trends: List[TrendAnalysis]) -> str:
        """Calculate overall health status."""
        quality_score = self._calculate_quality_score(results, anomalies, trends)
        
        if quality_score >= 90:
            return "excellent"
        elif quality_score >= 80:
            return "good"
        elif quality_score >= 70:
            return "fair"
        elif quality_score >= 60:
            return "poor"
        else:
            return "critical"
            
    def _generate_recommendations(self, results: List[Any], anomalies: List[Anomaly],
                                trends: List[TrendAnalysis]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        # Recommendations based on anomalies
        critical_anomalies = [a for a in anomalies if a.severity == SeverityLevel.CRITICAL]
        if critical_anomalies:
            recommendations.append(
                f"URGENT: Investigate {len(critical_anomalies)} critical performance anomalies detected"
            )
            
        high_anomalies = [a for a in anomalies if a.severity == SeverityLevel.HIGH]
        if high_anomalies:
            recommendations.append(
                f"High priority: Address {len(high_anomalies)} high-severity anomalies"
            )
            
        # Recommendations based on trends
        degrading_trends = [t for t in trends if t.trend_direction == "increasing" 
                           and ("error" in t.metric_name.lower() or "latency" in t.metric_name.lower())]
        if degrading_trends:
            recommendations.append(
                f"Performance degradation detected in {len(degrading_trends)} metrics - consider optimization"
            )
            
        improving_trends = [t for t in trends if t.trend_direction == "decreasing" 
                           and ("duration" in t.metric_name.lower() or "memory" in t.metric_name.lower())]
        if improving_trends:
            recommendations.append(
                f"Good news: {len(improving_trends)} metrics showing improvement trends"
            )
            
        # Test failure recommendations
        failed_tests = [r for r in results if not getattr(r, 'success', True)]
        if failed_tests:
            failure_rate = len(failed_tests) / len(results)
            if failure_rate > 0.1:  # More than 10% failure rate
                recommendations.append(
                    f"High failure rate ({failure_rate:.1%}) - investigate failing tests"
                )
                
        # Resource usage recommendations
        memory_anomalies = [a for a in anomalies if 'memory' in a.metric_name.lower()]
        if memory_anomalies:
            recommendations.append("Memory usage anomalies detected - check for memory leaks")
            
        cpu_anomalies = [a for a in anomalies if 'cpu' in a.metric_name.lower()]
        if cpu_anomalies:
            recommendations.append("CPU usage anomalies detected - profile application performance")
            
        # General recommendations
        if not anomalies and not any(t.significance in [SeverityLevel.HIGH, SeverityLevel.CRITICAL] 
                                   for t in trends):
            recommendations.append("System performance is stable - continue monitoring")
            
        return recommendations
        
    def _load_baselines(self) -> None:
        """Load performance baselines from file."""
        try:
            if Path(self.baseline_file).exists():
                with open(self.baseline_file, 'r') as f:
                    data = json.load(f)
                    
                for key, baseline_data in data.items():
                    self.baselines[key] = PerformanceBaseline(
                        test_name=baseline_data['test_name'],
                        metric_name=baseline_data['metric_name'],
                        baseline_value=baseline_data['baseline_value'],
                        variance_threshold=baseline_data.get('variance_threshold', 0.15),
                        created_at=datetime.fromisoformat(baseline_data['created_at']),
                        updated_at=datetime.fromisoformat(baseline_data['updated_at']),
                        sample_count=baseline_data.get('sample_count', 0)
                    )
                    
                logger.info(f"Loaded {len(self.baselines)} baselines from {self.baseline_file}")
                
        except Exception as e:
            logger.warning(f"Could not load baselines: {e}")
            
    def _save_baselines(self) -> None:
        """Save performance baselines to file."""
        try:
            data = {}
            for key, baseline in self.baselines.items():
                data[key] = {
                    'test_name': baseline.test_name,
                    'metric_name': baseline.metric_name,
                    'baseline_value': baseline.baseline_value,
                    'variance_threshold': baseline.variance_threshold,
                    'created_at': baseline.created_at.isoformat(),
                    'updated_at': baseline.updated_at.isoformat(),
                    'sample_count': baseline.sample_count
                }
                
            with open(self.baseline_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.warning(f"Could not save baselines: {e}")
            
    def export_analysis(self, processed_results: ProcessedResults, 
                       output_path: str, format_type: str = 'json') -> None:
        """Export analysis results to file."""
        try:
            if format_type.lower() == 'json':
                # Convert to JSON-serializable format
                data = {
                    'summary': processed_results.summary,
                    'metrics': [asdict(m) for m in processed_results.metrics],
                    'baselines': {k: asdict(v) for k, v in processed_results.baselines.items()},
                    'anomalies': [asdict(a) for a in processed_results.anomalies],
                    'trends': [asdict(t) for t in processed_results.trends],
                    'recommendations': processed_results.recommendations,
                    'quality_score': processed_results.quality_score,
                    'processing_metadata': processed_results.processing_metadata
                }
                
                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
                    
            elif format_type.lower() == 'csv':
                # Export metrics to CSV
                df = pd.DataFrame([asdict(m) for m in processed_results.metrics])
                df.to_csv(output_path, index=False)
                
            logger.info(f"Exported analysis results to {output_path}")
            
        except Exception as e:
            logger.error(f"Error exporting analysis: {e}")


# Example usage
if __name__ == "__main__":
    from dataclasses import dataclass
    from datetime import datetime
    
    @dataclass
    class MockTestResult:
        test_name: str
        success: bool
        duration: float
        resource_usage: Dict[str, Any]
        
    # Create sample results
    results = [
        MockTestResult("test_performance", True, 45.2, {"memory_mb": 512, "cpu_percent": 25}),
        MockTestResult("test_stress", True, 120.5, {"memory_mb": 1024, "cpu_percent": 85}),
        MockTestResult("test_integration", False, 30.1, {"memory_mb": 256, "cpu_percent": 15})
    ]
    
    processor = ResultProcessor()
    processed = processor.process_results(results)
    
    print(f"Quality Score: {processed.quality_score}")
    print(f"Recommendations: {processed.recommendations}")
    print(f"Anomalies Detected: {len(processed.anomalies)}")
    print(f"Trends Analyzed: {len(processed.trends)}")