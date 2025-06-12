"""
Statistical Analysis for Memory Testing
Advanced statistical methods for memory performance analysis.
"""

import statistics
import math
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
import numpy as np
from scipy import stats
import warnings


@dataclass
class TrendAnalysis:
    """Statistical trend analysis result"""
    trend_type: str  # 'increasing', 'decreasing', 'stable', 'oscillating'
    slope: float
    r_squared: float
    p_value: float
    confidence_interval: Tuple[float, float]
    significance_level: float
    is_significant: bool
    trend_strength: str  # 'weak', 'moderate', 'strong'


@dataclass
class RegressionAnalysis:
    """Memory performance regression analysis"""
    regression_detected: bool
    improvement_detected: bool
    change_magnitude: float
    change_percentage: float
    confidence_level: float
    statistical_significance: float
    baseline_mean: float
    current_mean: float
    effect_size: float


@dataclass
class AnomalyDetection:
    """Memory anomaly detection result"""
    anomalies_detected: bool
    anomaly_count: int
    anomaly_indices: List[int]
    anomaly_scores: List[float]
    threshold: float
    method: str


@dataclass
class DistributionAnalysis:
    """Memory distribution analysis"""
    mean: float
    median: float
    std_dev: float
    variance: float
    skewness: float
    kurtosis: float
    distribution_type: str
    normality_test_p_value: float
    is_normal: bool


class MemoryStatisticalAnalyzer:
    """Advanced statistical analysis for memory testing"""
    
    def __init__(self, significance_level: float = 0.05):
        self.significance_level = significance_level
        
    def analyze_memory_trend(
        self, 
        memory_readings: List[float],
        time_points: Optional[List[float]] = None
    ) -> TrendAnalysis:
        """Analyze memory usage trend with statistical rigor"""
        
        if len(memory_readings) < 3:
            return TrendAnalysis(
                trend_type='insufficient_data',
                slope=0.0,
                r_squared=0.0,
                p_value=1.0,
                confidence_interval=(0.0, 0.0),
                significance_level=self.significance_level,
                is_significant=False,
                trend_strength='none'
            )
        
        # Use time points or create sequence
        if time_points is None:
            x = np.array(range(len(memory_readings)))
        else:
            x = np.array(time_points)
        
        y = np.array(memory_readings)
        
        # Linear regression
        slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
        r_squared = r_value ** 2
        
        # Confidence interval for slope
        df = len(x) - 2  # degrees of freedom
        t_critical = stats.t.ppf(1 - self.significance_level/2, df)
        margin_error = t_critical * std_err
        confidence_interval = (slope - margin_error, slope + margin_error)
        
        # Determine trend type
        if p_value < self.significance_level:
            if slope > 0:
                trend_type = 'increasing'
            else:
                trend_type = 'decreasing'
        else:
            # Check for oscillation
            if self._detect_oscillation(memory_readings):
                trend_type = 'oscillating'
            else:
                trend_type = 'stable'
        
        # Determine trend strength
        if r_squared > 0.8:
            trend_strength = 'strong'
        elif r_squared > 0.5:
            trend_strength = 'moderate'
        else:
            trend_strength = 'weak'
        
        return TrendAnalysis(
            trend_type=trend_type,
            slope=slope,
            r_squared=r_squared,
            p_value=p_value,
            confidence_interval=confidence_interval,
            significance_level=self.significance_level,
            is_significant=p_value < self.significance_level,
            trend_strength=trend_strength
        )
    
    def detect_regression(
        self,
        baseline_data: List[float],
        current_data: List[float],
        regression_threshold: float = 0.15
    ) -> RegressionAnalysis:
        """Detect performance regression with statistical significance"""
        
        baseline_mean = statistics.mean(baseline_data)
        current_mean = statistics.mean(current_data)
        
        # Calculate change
        change_magnitude = current_mean - baseline_mean
        change_percentage = (change_magnitude / baseline_mean) * 100 if baseline_mean != 0 else 0
        
        # Statistical test (Welch's t-test for unequal variances)
        t_statistic, p_value = stats.ttest_ind(current_data, baseline_data, equal_var=False)
        
        # Effect size (Cohen's d)
        pooled_std = math.sqrt(
            (statistics.variance(baseline_data) + statistics.variance(current_data)) / 2
        )
        effect_size = change_magnitude / pooled_std if pooled_std != 0 else 0
        
        # Confidence level
        confidence_level = 1 - p_value
        
        # Regression detection
        regression_detected = (
            change_percentage > regression_threshold * 100 and
            p_value < self.significance_level and
            t_statistic > 0  # Current is significantly higher than baseline
        )
        
        # Improvement detection
        improvement_detected = (
            change_percentage < -regression_threshold * 100 and
            p_value < self.significance_level and
            t_statistic < 0  # Current is significantly lower than baseline
        )
        
        return RegressionAnalysis(
            regression_detected=regression_detected,
            improvement_detected=improvement_detected,
            change_magnitude=change_magnitude,
            change_percentage=change_percentage,
            confidence_level=confidence_level,
            statistical_significance=p_value,
            baseline_mean=baseline_mean,
            current_mean=current_mean,
            effect_size=effect_size
        )
    
    def detect_anomalies(
        self,
        memory_readings: List[float],
        method: str = 'iqr',
        sensitivity: float = 1.5
    ) -> AnomalyDetection:
        """Detect memory usage anomalies"""
        
        data = np.array(memory_readings)
        anomaly_indices = []
        anomaly_scores = []
        
        if method == 'iqr':
            # Interquartile Range method
            q1 = np.percentile(data, 25)
            q3 = np.percentile(data, 75)
            iqr = q3 - q1
            threshold = sensitivity * iqr
            lower_bound = q1 - threshold
            upper_bound = q3 + threshold
            
            for i, value in enumerate(data):
                if value < lower_bound or value > upper_bound:
                    anomaly_indices.append(i)
                    # Score based on distance from bounds
                    if value < lower_bound:
                        score = (lower_bound - value) / threshold
                    else:
                        score = (value - upper_bound) / threshold
                    anomaly_scores.append(score)
        
        elif method == 'zscore':
            # Z-score method
            mean = np.mean(data)
            std = np.std(data)
            threshold = sensitivity
            
            for i, value in enumerate(data):
                z_score = abs((value - mean) / std) if std != 0 else 0
                if z_score > threshold:
                    anomaly_indices.append(i)
                    anomaly_scores.append(z_score)
        
        elif method == 'modified_zscore':
            # Modified Z-score using median
            median = np.median(data)
            mad = np.median(np.abs(data - median))
            threshold = sensitivity
            
            for i, value in enumerate(data):
                modified_z_score = 0.6745 * (value - median) / mad if mad != 0 else 0
                if abs(modified_z_score) > threshold:
                    anomaly_indices.append(i)
                    anomaly_scores.append(abs(modified_z_score))
        
        return AnomalyDetection(
            anomalies_detected=len(anomaly_indices) > 0,
            anomaly_count=len(anomaly_indices),
            anomaly_indices=anomaly_indices,
            anomaly_scores=anomaly_scores,
            threshold=threshold if 'threshold' in locals() else sensitivity,
            method=method
        )
    
    def analyze_distribution(self, memory_readings: List[float]) -> DistributionAnalysis:
        """Analyze memory usage distribution"""
        
        data = np.array(memory_readings)
        
        # Basic statistics
        mean = np.mean(data)
        median = np.median(data)
        std_dev = np.std(data)
        variance = np.var(data)
        
        # Shape statistics
        skewness = stats.skew(data)
        kurtosis = stats.kurtosis(data)
        
        # Normality test
        if len(data) >= 8:  # Minimum for Shapiro-Wilk
            _, normality_p_value = stats.shapiro(data)
        else:
            normality_p_value = 1.0  # Assume normal for small samples
        
        is_normal = normality_p_value > self.significance_level
        
        # Determine distribution type
        if is_normal:
            distribution_type = 'normal'
        elif skewness > 1:
            distribution_type = 'right_skewed'
        elif skewness < -1:
            distribution_type = 'left_skewed'
        elif abs(kurtosis) > 2:
            distribution_type = 'heavy_tailed' if kurtosis > 0 else 'light_tailed'
        else:
            distribution_type = 'approximately_normal'
        
        return DistributionAnalysis(
            mean=mean,
            median=median,
            std_dev=std_dev,
            variance=variance,
            skewness=skewness,
            kurtosis=kurtosis,
            distribution_type=distribution_type,
            normality_test_p_value=normality_p_value,
            is_normal=is_normal
        )
    
    def calculate_confidence_interval(
        self,
        data: List[float],
        confidence_level: float = 0.95
    ) -> Tuple[float, float]:
        """Calculate confidence interval for mean"""
        
        n = len(data)
        if n < 2:
            return (0.0, 0.0)
        
        mean = statistics.mean(data)
        std_err = statistics.stdev(data) / math.sqrt(n)
        
        # t-distribution for small samples
        alpha = 1 - confidence_level
        df = n - 1
        t_critical = stats.t.ppf(1 - alpha/2, df)
        
        margin_error = t_critical * std_err
        
        return (mean - margin_error, mean + margin_error)
    
    def statistical_power_analysis(
        self,
        baseline_data: List[float],
        effect_size: float = 0.5,
        alpha: float = 0.05,
        power: float = 0.8
    ) -> Dict[str, float]:
        """Calculate required sample size for detecting effect"""
        
        # Estimate standard deviation from baseline
        std_dev = statistics.stdev(baseline_data) if len(baseline_data) > 1 else 1.0
        
        # Cohen's d to effect size conversion
        effect_size_standardized = effect_size / std_dev
        
        # Approximate sample size calculation
        z_alpha = stats.norm.ppf(1 - alpha/2)
        z_beta = stats.norm.ppf(power)
        
        # Sample size for two-sample t-test
        n_approx = 2 * ((z_alpha + z_beta) / effect_size_standardized) ** 2
        
        return {
            'recommended_sample_size': max(int(n_approx), 5),
            'current_sample_size': len(baseline_data),
            'effect_size': effect_size,
            'standardized_effect_size': effect_size_standardized,
            'alpha': alpha,
            'power': power,
            'adequate_sample_size': len(baseline_data) >= n_approx
        }
    
    def compare_multiple_groups(
        self,
        groups: Dict[str, List[float]]
    ) -> Dict[str, Any]:
        """Compare multiple memory performance groups"""
        
        group_names = list(groups.keys())
        group_data = list(groups.values())
        
        # Overall ANOVA test
        if len(groups) > 2:
            f_statistic, p_value = stats.f_oneway(*group_data)
            overall_significant = p_value < self.significance_level
        else:
            f_statistic, p_value = 0.0, 1.0
            overall_significant = False
        
        # Pairwise comparisons
        pairwise_comparisons = {}
        for i, name1 in enumerate(group_names):
            for j, name2 in enumerate(group_names[i+1:], i+1):
                data1 = groups[name1]
                data2 = groups[name2]
                
                t_stat, p_val = stats.ttest_ind(data1, data2, equal_var=False)
                
                comparison_key = f"{name1}_vs_{name2}"
                pairwise_comparisons[comparison_key] = {
                    't_statistic': t_stat,
                    'p_value': p_val,
                    'significant': p_val < self.significance_level,
                    'mean_difference': statistics.mean(data2) - statistics.mean(data1)
                }
        
        # Group statistics
        group_stats = {}
        for name, data in groups.items():
            group_stats[name] = {
                'mean': statistics.mean(data),
                'std_dev': statistics.stdev(data) if len(data) > 1 else 0,
                'median': statistics.median(data),
                'sample_size': len(data)
            }
        
        return {
            'overall_f_statistic': f_statistic,
            'overall_p_value': p_value,
            'overall_significant': overall_significant,
            'pairwise_comparisons': pairwise_comparisons,
            'group_statistics': group_stats,
            'best_performing_group': min(group_stats.keys(), key=lambda x: group_stats[x]['mean']),
            'worst_performing_group': max(group_stats.keys(), key=lambda x: group_stats[x]['mean'])
        }
    
    def _detect_oscillation(self, data: List[float], min_cycles: int = 2) -> bool:
        """Detect oscillating patterns in memory usage"""
        if len(data) < 6:  # Need at least 3 peaks and valleys
            return False
        
        # Find local maxima and minima
        peaks = []
        valleys = []
        
        for i in range(1, len(data) - 1):
            if data[i] > data[i-1] and data[i] > data[i+1]:
                peaks.append(i)
            elif data[i] < data[i-1] and data[i] < data[i+1]:
                valleys.append(i)
        
        # Check for alternating pattern
        total_extrema = len(peaks) + len(valleys)
        return total_extrema >= min_cycles * 2
    
    def calculate_stability_index(self, memory_readings: List[float]) -> float:
        """Calculate memory stability index (0-1, higher is more stable)"""
        if len(memory_readings) < 2:
            return 1.0
        
        # Coefficient of variation
        mean_val = statistics.mean(memory_readings)
        std_val = statistics.stdev(memory_readings)
        
        if mean_val == 0:
            return 1.0
        
        cv = std_val / mean_val
        
        # Convert to stability index (inverse of variability)
        stability_index = 1 / (1 + cv)
        
        return min(stability_index, 1.0)
    
    def calculate_memory_efficiency_score(
        self,
        memory_usage: List[float],
        operations_count: int,
        baseline_memory: float
    ) -> float:
        """Calculate memory efficiency score"""
        if operations_count == 0:
            return 0.0
        
        avg_memory = statistics.mean(memory_usage)
        peak_memory = max(memory_usage)
        
        # Memory per operation
        memory_per_op = avg_memory / operations_count
        
        # Efficiency relative to baseline
        if baseline_memory > 0:
            efficiency_ratio = baseline_memory / avg_memory
        else:
            efficiency_ratio = 1.0
        
        # Peak usage penalty
        peak_penalty = 1.0 - min((peak_memory - avg_memory) / avg_memory, 0.5)
        
        # Combined efficiency score
        efficiency_score = efficiency_ratio * peak_penalty
        
        return min(efficiency_score, 10.0)  # Cap at 10x efficiency


# Example usage and testing
if __name__ == "__main__":
    # Test statistical analyzer
    analyzer = MemoryStatisticalAnalyzer()
    
    # Generate test data
    np.random.seed(42)
    baseline_data = np.random.normal(100, 10, 50).tolist()
    current_data = np.random.normal(110, 12, 50).tolist()  # Slight regression
    
    # Test regression detection
    regression = analyzer.detect_regression(baseline_data, current_data)
    print(f"Regression detected: {regression.regression_detected}")
    print(f"Change percentage: {regression.change_percentage:.2f}%")
    
    # Test trend analysis
    trend_data = [100 + i * 0.5 + np.random.normal(0, 2) for i in range(50)]
    trend = analyzer.analyze_memory_trend(trend_data)
    print(f"Trend type: {trend.trend_type}")
    print(f"Trend strength: {trend.trend_strength}")
    
    # Test anomaly detection
    anomaly_data = baseline_data + [200, 300]  # Add outliers
    anomalies = analyzer.detect_anomalies(anomaly_data)
    print(f"Anomalies detected: {anomalies.anomalies_detected}")
    print(f"Number of anomalies: {anomalies.anomaly_count}")
    
    print("Statistical analysis test completed!")