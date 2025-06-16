#!/usr/bin/env python3
"""
Performance Regression Testing Suite for CODE v1.0.0
===================================================

This suite establishes performance baselines and detects regressions:
- Baseline establishment for all components
- Regression detection algorithms
- Performance trend analysis
- Automated alerting for degradation
- Historical performance tracking
"""

import json
import time
import statistics
import hashlib
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import numpy as np
import sys

# Add project root to path
sys.path.insert(0, '/home/louranicas/projects/claude-optimized-deployment')

@dataclass
class PerformanceBaseline:
    """Performance baseline definition"""
    component: str
    metric_name: str
    baseline_value: float
    standard_deviation: float
    min_acceptable: float
    max_acceptable: float
    measurement_unit: str
    confidence_interval: Tuple[float, float]
    sample_size: int
    created_timestamp: float
    environment_hash: str

@dataclass 
class RegressionTestResult:
    """Regression test result"""
    component: str
    metric_name: str
    current_value: float
    baseline_value: float
    deviation_percent: float
    is_regression: bool
    severity: str  # "critical", "major", "minor", "none"
    confidence_score: float
    timestamp: float
    test_environment: str

@dataclass
class PerformanceTrend:
    """Performance trend analysis"""
    component: str
    metric_name: str
    trend_direction: str  # "improving", "degrading", "stable"
    trend_slope: float
    correlation_coefficient: float
    prediction_30_days: float
    confidence_interval: Tuple[float, float]
    analysis_period_days: int

class PerformanceRegressionSuite:
    """Main regression testing suite"""
    
    def __init__(self):
        self.baseline_dir = Path('/home/louranicas/projects/claude-optimized-deployment/performance_baselines')
        self.results_dir = Path('/home/louranicas/projects/claude-optimized-deployment/performance_reports')
        self.baseline_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
        
        self.baselines: Dict[str, PerformanceBaseline] = {}
        self.regression_results: List[RegressionTestResult] = []
        self.trends: List[PerformanceTrend] = []
        
        # Load existing baselines
        self.load_baselines()
    
    def get_environment_hash(self) -> str:
        """Generate hash representing current test environment"""
        import platform
        import psutil
        
        env_info = {
            'python_version': sys.version,
            'platform': platform.platform(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'architecture': platform.architecture()[0]
        }
        
        env_string = json.dumps(env_info, sort_keys=True)
        return hashlib.md5(env_string.encode()).hexdigest()[:16]
    
    def load_baselines(self):
        """Load existing performance baselines"""
        baseline_file = self.baseline_dir / 'performance_baselines.json'
        
        if baseline_file.exists():
            try:
                with open(baseline_file, 'r') as f:
                    data = json.load(f)
                
                for key, baseline_data in data.items():
                    baseline = PerformanceBaseline(**baseline_data)
                    self.baselines[key] = baseline
                
                print(f"✅ Loaded {len(self.baselines)} performance baselines")
            except Exception as e:
                print(f"⚠️  Error loading baselines: {e}")
    
    def save_baselines(self):
        """Save performance baselines to disk"""
        baseline_file = self.baseline_dir / 'performance_baselines.json'
        
        try:
            data = {}
            for key, baseline in self.baselines.items():
                data[key] = asdict(baseline)
            
            with open(baseline_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            print(f"✅ Saved {len(self.baselines)} performance baselines")
        except Exception as e:
            print(f"❌ Error saving baselines: {e}")
    
    def establish_baseline(self, component: str, metric_name: str, measurements: List[float]) -> PerformanceBaseline:
        """Establish performance baseline from measurements"""
        if len(measurements) < 5:
            raise ValueError(f"Need at least 5 measurements, got {len(measurements)}")
        
        # Calculate statistics
        mean_value = statistics.mean(measurements)
        std_dev = statistics.stdev(measurements) if len(measurements) > 1 else 0
        
        # Calculate confidence intervals (95%)
        confidence_margin = 1.96 * (std_dev / np.sqrt(len(measurements)))
        confidence_interval = (mean_value - confidence_margin, mean_value + confidence_margin)
        
        # Set acceptable ranges (±20% from baseline, adjustable per component)
        tolerance = self._get_tolerance(component, metric_name)
        min_acceptable = mean_value * (1 - tolerance)
        max_acceptable = mean_value * (1 + tolerance)
        
        baseline = PerformanceBaseline(
            component=component,
            metric_name=metric_name,
            baseline_value=mean_value,
            standard_deviation=std_dev,
            min_acceptable=min_acceptable,
            max_acceptable=max_acceptable,
            measurement_unit=self._get_unit(metric_name),
            confidence_interval=confidence_interval,
            sample_size=len(measurements),
            created_timestamp=time.time(),
            environment_hash=self.get_environment_hash()
        )
        
        baseline_key = f"{component}:{metric_name}"
        self.baselines[baseline_key] = baseline
        
        print(f"📊 Established baseline for {baseline_key}: {mean_value:.2f} ± {std_dev:.2f}")
        return baseline
    
    def _get_tolerance(self, component: str, metric_name: str) -> float:
        """Get tolerance threshold for component/metric"""
        tolerances = {
            # Strict tolerances for critical performance metrics
            'throughput': 0.10,  # ±10%
            'latency': 0.15,     # ±15%
            'response_time': 0.15,
            'cpu_usage': 0.20,   # ±20%
            'memory_usage': 0.25, # ±25%
            
            # Component-specific tolerances
            'rust_acceleration': 0.05,  # Very strict for Rust components
            'circuit_breaker': 0.10,
            'cache': 0.15,
            'database': 0.20,
        }
        
        # Check metric-specific tolerance first
        for key, tolerance in tolerances.items():
            if key in metric_name.lower():
                return tolerance
        
        # Check component-specific tolerance
        for key, tolerance in tolerances.items():
            if key in component.lower():
                return tolerance
        
        # Default tolerance
        return 0.20
    
    def _get_unit(self, metric_name: str) -> str:
        """Get measurement unit for metric"""
        units = {
            'throughput': 'ops/sec',
            'latency': 'ms',
            'response_time': 'ms',
            'duration': 'seconds',
            'cpu_usage': 'percent',
            'memory_usage': 'MB',
            'error_rate': 'percent',
            'success_rate': 'percent'
        }
        
        for key, unit in units.items():
            if key in metric_name.lower():
                return unit
        
        return 'units'
    
    def check_regression(self, component: str, metric_name: str, current_value: float) -> RegressionTestResult:
        """Check if current measurement indicates regression"""
        baseline_key = f"{component}:{metric_name}"
        
        if baseline_key not in self.baselines:
            print(f"⚠️  No baseline found for {baseline_key}, establishing from single measurement")
            # Create baseline with current value (not ideal, but functional)
            self.establish_baseline(component, metric_name, [current_value])
            baseline = self.baselines[baseline_key]
        else:
            baseline = self.baselines[baseline_key]
        
        # Calculate deviation
        deviation_percent = ((current_value - baseline.baseline_value) / baseline.baseline_value) * 100
        
        # Determine if regression based on metric type
        is_regression = self._is_performance_regression(metric_name, current_value, baseline)
        
        # Calculate severity
        severity = self._calculate_severity(deviation_percent, metric_name)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence(current_value, baseline)
        
        result = RegressionTestResult(
            component=component,
            metric_name=metric_name,
            current_value=current_value,
            baseline_value=baseline.baseline_value,
            deviation_percent=deviation_percent,
            is_regression=is_regression,
            severity=severity,
            confidence_score=confidence_score,
            timestamp=time.time(),
            test_environment=self.get_environment_hash()
        )
        
        self.regression_results.append(result)
        
        if is_regression:
            print(f"🚨 REGRESSION DETECTED: {component}:{metric_name}")
            print(f"   Current: {current_value:.2f}, Baseline: {baseline.baseline_value:.2f}")
            print(f"   Deviation: {deviation_percent:.1f}%, Severity: {severity}")
        else:
            print(f"✅ No regression: {component}:{metric_name} ({deviation_percent:+.1f}%)")
        
        return result
    
    def _is_performance_regression(self, metric_name: str, current_value: float, baseline: PerformanceBaseline) -> bool:
        """Determine if measurement indicates performance regression"""
        # For "lower is better" metrics (latency, response time, error rate)
        lower_is_better = any(keyword in metric_name.lower() for keyword in 
                             ['latency', 'response_time', 'duration', 'error_rate', 'memory_usage'])
        
        # For "higher is better" metrics (throughput, success rate)
        higher_is_better = any(keyword in metric_name.lower() for keyword in 
                              ['throughput', 'success_rate', 'ops_per_sec'])
        
        if lower_is_better:
            # Regression if current value is significantly higher than baseline
            return current_value > baseline.max_acceptable
        elif higher_is_better:
            # Regression if current value is significantly lower than baseline
            return current_value < baseline.min_acceptable
        else:
            # For neutral metrics, check if outside acceptable range
            return not (baseline.min_acceptable <= current_value <= baseline.max_acceptable)
    
    def _calculate_severity(self, deviation_percent: float, metric_name: str) -> str:
        """Calculate regression severity"""
        abs_deviation = abs(deviation_percent)
        
        # Adjust thresholds based on metric criticality
        critical_metrics = ['throughput', 'latency', 'response_time']
        is_critical = any(metric in metric_name.lower() for metric in critical_metrics)
        
        if is_critical:
            if abs_deviation >= 30:
                return "critical"
            elif abs_deviation >= 20:
                return "major"
            elif abs_deviation >= 10:
                return "minor"
        else:
            if abs_deviation >= 50:
                return "critical"
            elif abs_deviation >= 30:
                return "major"  
            elif abs_deviation >= 15:
                return "minor"
        
        return "none"
    
    def _calculate_confidence(self, current_value: float, baseline: PerformanceBaseline) -> float:
        """Calculate confidence score for regression detection"""
        # Distance from baseline in standard deviations
        if baseline.standard_deviation > 0:
            z_score = abs(current_value - baseline.baseline_value) / baseline.standard_deviation
            # Convert to confidence percentage (higher z-score = higher confidence)
            confidence = min(1.0, z_score / 3.0)  # 3 sigma = 99.7% confidence
        else:
            # If no deviation data, use distance from baseline
            deviation = abs(current_value - baseline.baseline_value) / baseline.baseline_value
            confidence = min(1.0, deviation * 2)  # 50% deviation = 100% confidence
        
        return confidence
    
    def analyze_trends(self, days_back: int = 30) -> List[PerformanceTrend]:
        """Analyze performance trends over time"""
        print(f"📈 Analyzing performance trends over last {days_back} days")
        
        # Load historical data
        historical_data = self._load_historical_data(days_back)
        
        trends = []
        
        # Group by component and metric
        grouped_data = {}
        for result in historical_data:
            key = f"{result['component']}:{result['metric_name']}"
            if key not in grouped_data:
                grouped_data[key] = []
            grouped_data[key].append(result)
        
        for key, data_points in grouped_data.items():
            if len(data_points) < 5:  # Need minimum data points for trend analysis
                continue
            
            component, metric_name = key.split(':', 1)
            
            # Sort by timestamp
            data_points.sort(key=lambda x: x['timestamp'])
            
            # Extract values and timestamps
            values = [point['current_value'] for point in data_points]
            timestamps = [point['timestamp'] for point in data_points]
            
            # Calculate trend
            trend = self._calculate_trend(timestamps, values, component, metric_name, days_back)
            if trend:
                trends.append(trend)
        
        self.trends = trends
        return trends
    
    def _load_historical_data(self, days_back: int) -> List[Dict[str, Any]]:
        """Load historical regression test results"""
        cutoff_time = time.time() - (days_back * 24 * 3600)
        historical_data = []
        
        # Load from current session
        for result in self.regression_results:
            if result.timestamp >= cutoff_time:
                historical_data.append(asdict(result))
        
        # Load from historical files
        for file_path in self.results_dir.glob('regression_results_*.json'):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    
                for result in data.get('regression_results', []):
                    if result['timestamp'] >= cutoff_time:
                        historical_data.append(result)
            except Exception as e:
                print(f"Warning: Could not load {file_path}: {e}")
        
        return historical_data
    
    def _calculate_trend(self, timestamps: List[float], values: List[float], 
                        component: str, metric_name: str, period_days: int) -> Optional[PerformanceTrend]:
        """Calculate performance trend from historical data"""
        if len(values) < 5:
            return None
        
        try:
            # Convert timestamps to days from first measurement
            start_time = min(timestamps)
            days = [(t - start_time) / (24 * 3600) for t in timestamps]
            
            # Calculate linear regression
            slope, intercept, correlation, p_value, std_err = self._linear_regression(days, values)
            
            # Determine trend direction
            if abs(correlation) < 0.3:
                direction = "stable"
            elif slope > 0:
                if any(keyword in metric_name.lower() for keyword in ['throughput', 'success_rate']):
                    direction = "improving"  # Higher is better
                else:
                    direction = "degrading"  # Higher is worse (latency, etc.)
            else:
                if any(keyword in metric_name.lower() for keyword in ['throughput', 'success_rate']):
                    direction = "degrading"  # Lower is worse
                else:
                    direction = "improving"  # Lower is better
            
            # Predict value 30 days from now
            prediction_30_days = intercept + slope * (period_days + 30)
            
            # Calculate confidence interval for prediction
            prediction_std = std_err * np.sqrt(30)  # Simplified confidence calculation
            confidence_interval = (
                prediction_30_days - 1.96 * prediction_std,
                prediction_30_days + 1.96 * prediction_std
            )
            
            return PerformanceTrend(
                component=component,
                metric_name=metric_name,
                trend_direction=direction,
                trend_slope=slope,
                correlation_coefficient=correlation,
                prediction_30_days=prediction_30_days,
                confidence_interval=confidence_interval,
                analysis_period_days=period_days
            )
            
        except Exception as e:
            print(f"Error calculating trend for {component}:{metric_name}: {e}")
            return None
    
    def _linear_regression(self, x: List[float], y: List[float]) -> Tuple[float, float, float, float, float]:
        """Simple linear regression implementation"""
        n = len(x)
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(y)
        
        # Calculate slope and intercept
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return 0, y_mean, 0, 1, 0
        
        slope = numerator / denominator
        intercept = y_mean - slope * x_mean
        
        # Calculate correlation coefficient
        x_var = statistics.variance(x) if n > 1 else 0
        y_var = statistics.variance(y) if n > 1 else 0
        
        if x_var == 0 or y_var == 0:
            correlation = 0
        else:
            correlation = numerator / np.sqrt(denominator * sum((y[i] - y_mean) ** 2 for i in range(n)))
        
        # Calculate standard error (simplified)
        y_pred = [intercept + slope * x[i] for i in range(n)]
        residuals = [y[i] - y_pred[i] for i in range(n)]
        mse = statistics.mean(r ** 2 for r in residuals)
        std_err = np.sqrt(mse)
        
        p_value = 0.05  # Simplified - would need proper t-test for real p-value
        
        return slope, intercept, correlation, p_value, std_err
    
    def generate_regression_report(self) -> Dict[str, Any]:
        """Generate comprehensive regression analysis report"""
        print("📋 Generating Regression Analysis Report")
        
        current_time = time.time()
        
        # Count regressions by severity
        regression_counts = {
            "critical": len([r for r in self.regression_results if r.is_regression and r.severity == "critical"]),
            "major": len([r for r in self.regression_results if r.is_regression and r.severity == "major"]),
            "minor": len([r for r in self.regression_results if r.is_regression and r.severity == "minor"]),
            "total": len([r for r in self.regression_results if r.is_regression])
        }
        
        # Analyze trends
        degrading_trends = [t for t in self.trends if t.trend_direction == "degrading"]
        improving_trends = [t for t in self.trends if t.trend_direction == "improving"]
        
        # Calculate overall health score
        total_checks = len(self.regression_results)
        regression_rate = regression_counts["total"] / max(1, total_checks)
        health_score = max(0, 100 - (regression_rate * 100 + regression_counts["critical"] * 20))
        
        report = {
            "regression_analysis": {
                "timestamp": current_time,
                "total_performance_checks": total_checks,
                "regression_counts": regression_counts,
                "regression_rate_percent": regression_rate * 100,
                "health_score": health_score,
                "baselines_established": len(self.baselines),
                "trends_analyzed": len(self.trends)
            },
            "regression_details": [asdict(result) for result in self.regression_results],
            "performance_baselines": {key: asdict(baseline) for key, baseline in self.baselines.items()},
            "trend_analysis": [asdict(trend) for trend in self.trends],
            "alerts": self._generate_alerts(),
            "recommendations": self._generate_regression_recommendations()
        }
        
        return report
    
    def _generate_alerts(self) -> List[Dict[str, Any]]:
        """Generate performance alerts"""
        alerts = []
        
        # Critical regressions
        for result in self.regression_results:
            if result.is_regression and result.severity == "critical":
                alerts.append({
                    "type": "critical_regression",
                    "component": result.component,
                    "metric": result.metric_name,
                    "message": f"Critical performance regression in {result.component}:{result.metric_name}",
                    "deviation": f"{result.deviation_percent:.1f}%",
                    "timestamp": result.timestamp,
                    "priority": "high"
                })
        
        # Degrading trends
        for trend in self.trends:
            if trend.trend_direction == "degrading" and abs(trend.correlation_coefficient) > 0.7:
                alerts.append({
                    "type": "performance_trend",
                    "component": trend.component,
                    "metric": trend.metric_name,
                    "message": f"Degrading performance trend detected in {trend.component}:{trend.metric_name}",
                    "correlation": f"{trend.correlation_coefficient:.2f}",
                    "prediction": f"{trend.prediction_30_days:.2f}",
                    "priority": "medium"
                })
        
        return alerts
    
    def _generate_regression_recommendations(self) -> List[str]:
        """Generate recommendations based on regression analysis"""
        recommendations = []
        
        if not self.regression_results:
            return ["No regression data available for recommendations"]
        
        # Critical regressions
        critical_regressions = [r for r in self.regression_results if r.severity == "critical"]
        if critical_regressions:
            components = list(set(r.component for r in critical_regressions))
            recommendations.append(
                f"URGENT: Address critical performance regressions in: {', '.join(components)}. "
                "These require immediate attention."
            )
        
        # Frequent regressions in same component
        component_counts = {}
        for result in self.regression_results:
            if result.is_regression:
                component_counts[result.component] = component_counts.get(result.component, 0) + 1
        
        problematic_components = [comp for comp, count in component_counts.items() if count >= 3]
        if problematic_components:
            recommendations.append(
                f"Components with frequent regressions: {', '.join(problematic_components)}. "
                "Consider architectural review and optimization."
            )
        
        # Trend-based recommendations
        degrading_trends = [t for t in self.trends if t.trend_direction == "degrading"]
        if degrading_trends:
            trend_components = list(set(t.component for t in degrading_trends))
            recommendations.append(
                f"Performance degradation trends detected in: {', '.join(trend_components)}. "
                "Monitor closely and plan optimization sprints."
            )
        
        # General recommendations
        recommendations.extend([
            "Establish automated performance testing in CI/CD pipeline",
            "Set up real-time monitoring with alerting for critical metrics",
            "Regular performance review meetings with development team",
            "Implement performance budgets for new features",
            "Consider performance profiling for components with frequent issues"
        ])
        
        return recommendations
    
    def save_regression_results(self):
        """Save regression results to disk"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        results_file = self.results_dir / f'regression_results_{timestamp}.json'
        
        data = {
            "regression_results": [asdict(result) for result in self.regression_results],
            "trends": [asdict(trend) for trend in self.trends],
            "timestamp": time.time()
        }
        
        try:
            with open(results_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            print(f"✅ Saved regression results to {results_file}")
        except Exception as e:
            print(f"❌ Error saving regression results: {e}")

def main():
    """Main function for running regression testing"""
    print("🔍 Performance Regression Testing Suite")
    print("=" * 50)
    
    suite = PerformanceRegressionSuite()
    
    # Example: Establish baselines for key metrics
    example_metrics = {
        'rust_acceleration': {
            'infrastructure_scanning_throughput': [1200, 1180, 1220, 1195, 1205, 1210, 1190, 1215],
            'config_parsing_latency': [2.1, 2.0, 2.2, 2.1, 1.9, 2.0, 2.1, 2.0],
            'simd_operations_throughput': [5000, 4950, 5100, 5020, 4980, 5050, 5000, 4990]
        },
        'circuit_breaker': {
            'normal_operation_latency': [15.2, 14.8, 15.5, 15.0, 14.9, 15.1, 15.3, 14.7],
            'failure_detection_time': [100, 95, 105, 98, 102, 99, 101, 97]
        },
        'distributed_cache': {
            'read_throughput': [8000, 7950, 8100, 8020, 7980, 8050, 8000, 7990],
            'write_latency': [5.1, 5.0, 5.2, 5.1, 4.9, 5.0, 5.1, 5.0]
        }
    }
    
    # Establish baselines
    print("📊 Establishing Performance Baselines...")
    for component, metrics in example_metrics.items():
        for metric_name, measurements in metrics.items():
            suite.establish_baseline(component, metric_name, measurements)
    
    # Save baselines
    suite.save_baselines()
    
    # Example: Check for regressions with new measurements
    print("\n🔍 Checking for Performance Regressions...")
    
    test_measurements = {
        ('rust_acceleration', 'infrastructure_scanning_throughput'): 1050,  # Regression
        ('rust_acceleration', 'config_parsing_latency'): 1.95,  # Improvement
        ('circuit_breaker', 'normal_operation_latency'): 18.5,  # Regression
        ('distributed_cache', 'read_throughput'): 8200,  # Improvement
    }
    
    for (component, metric), value in test_measurements.items():
        suite.check_regression(component, metric, value)
    
    # Analyze trends
    print("\n📈 Analyzing Performance Trends...")
    trends = suite.analyze_trends(days_back=30)
    
    # Generate report
    print("\n📋 Generating Final Report...")
    report = suite.generate_regression_report()
    
    # Save results
    suite.save_regression_results()
    
    # Display summary
    print("\n" + "=" * 50)
    print("🎯 Regression Testing Summary")
    print(f"Performance Health Score: {report['regression_analysis']['health_score']:.1f}/100")
    print(f"Total Regressions: {report['regression_analysis']['regression_counts']['total']}")
    print(f"Critical Issues: {report['regression_analysis']['regression_counts']['critical']}")
    print(f"Baselines Established: {report['regression_analysis']['baselines_established']}")
    print("=" * 50)
    
    return report

if __name__ == "__main__":
    try:
        report = main()
        sys.exit(0)
    except Exception as e:
        print(f"❌ Regression testing failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)