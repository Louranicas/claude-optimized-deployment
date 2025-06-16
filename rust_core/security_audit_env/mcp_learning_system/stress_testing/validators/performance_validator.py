"""
Performance validation for stress testing results.

Validates latency, throughput, and resource usage against target requirements.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import numpy as np
import logging

logger = logging.getLogger(__name__)


@dataclass
class PerformanceThresholds:
    """Performance validation thresholds."""
    # Latency thresholds (milliseconds)
    max_pattern_match_latency_ms: float = 1.0
    max_learning_update_latency_ms: float = 10.0
    max_cross_instance_latency_ms: float = 50.0
    
    # Throughput thresholds
    min_pattern_match_throughput: float = 1000  # ops/sec
    min_learning_throughput: float = 100        # ops/sec
    min_cross_instance_throughput: float = 100  # msgs/sec
    
    # Resource usage thresholds
    max_cpu_usage_percent: float = 80.0
    max_memory_usage_gb: float = 12.0
    max_disk_usage_percent: float = 85.0
    
    # Percentile requirements
    p95_latency_multiplier: float = 2.0  # P95 should be < 2x mean
    p99_latency_multiplier: float = 5.0  # P99 should be < 5x mean


@dataclass
class ValidationResult:
    """Result of performance validation."""
    metric_name: str
    actual_value: float
    threshold_value: float
    passed: bool
    severity: str  # 'info', 'warning', 'error', 'critical'
    message: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'metric_name': self.metric_name,
            'actual_value': self.actual_value,
            'threshold_value': self.threshold_value,
            'passed': self.passed,
            'severity': self.severity,
            'message': self.message
        }


class PerformanceValidator:
    """Validates performance metrics against requirements."""
    
    def __init__(self, thresholds: Optional[PerformanceThresholds] = None):
        """Initialize validator with performance thresholds."""
        self.thresholds = thresholds or PerformanceThresholds()
        
    def validate_benchmark_results(
        self, 
        benchmark_results: Dict[str, Any]
    ) -> List[ValidationResult]:
        """Validate benchmark results against thresholds."""
        validations = []
        
        # Validate pattern matching performance
        if 'pattern_match_small' in benchmark_results:
            validations.extend(
                self._validate_pattern_matching(benchmark_results['pattern_match_small'])
            )
        
        # Validate learning performance
        if 'learning_update_single' in benchmark_results:
            validations.extend(
                self._validate_learning_performance(benchmark_results['learning_update_single'])
            )
        
        # Validate concurrent performance
        if 'learning_update_concurrent_100' in benchmark_results:
            validations.extend(
                self._validate_concurrent_performance(benchmark_results['learning_update_concurrent_100'])
            )
        
        # Validate cross-instance performance
        if 'cross_instance_latency' in benchmark_results:
            validations.extend(
                self._validate_cross_instance_performance(benchmark_results['cross_instance_latency'])
            )
        
        return validations
    
    def validate_stress_test_results(
        self, 
        stress_results: Dict[str, Any]
    ) -> List[ValidationResult]:
        """Validate stress test results."""
        validations = []
        
        for phase_name, phase_result in stress_results.items():
            if isinstance(phase_result, dict) and 'metrics' in phase_result:
                validations.extend(
                    self._validate_phase_performance(phase_name, phase_result['metrics'])
                )
        
        return validations
    
    def validate_load_scenario_results(
        self, 
        load_results: Dict[str, Any]
    ) -> List[ValidationResult]:
        """Validate load scenario results."""
        validations = []
        
        for scenario_name, scenario_result in load_results.items():
            if hasattr(scenario_result, 'latency_metrics'):
                validations.extend(
                    self._validate_latency_metrics(scenario_name, scenario_result.latency_metrics)
                )
            
            if hasattr(scenario_result, 'resource_metrics'):
                validations.extend(
                    self._validate_resource_metrics(scenario_name, scenario_result.resource_metrics)
                )
        
        return validations
    
    def _validate_pattern_matching(self, result: Dict[str, Any]) -> List[ValidationResult]:
        """Validate pattern matching performance."""
        validations = []
        
        # Mean latency validation
        if 'mean_time' in result:
            mean_latency_ms = result['mean_time'] * 1000
            
            validations.append(ValidationResult(
                metric_name='pattern_match_mean_latency',
                actual_value=mean_latency_ms,
                threshold_value=self.thresholds.max_pattern_match_latency_ms,
                passed=mean_latency_ms <= self.thresholds.max_pattern_match_latency_ms,
                severity='error' if mean_latency_ms > self.thresholds.max_pattern_match_latency_ms else 'info',
                message=f"Pattern matching mean latency: {mean_latency_ms:.2f}ms "
                       f"(threshold: {self.thresholds.max_pattern_match_latency_ms}ms)"
            ))
        
        # P95 latency validation
        if 'p95_time' in result and 'mean_time' in result:
            p95_latency_ms = result['p95_time'] * 1000
            mean_latency_ms = result['mean_time'] * 1000
            expected_p95_max = mean_latency_ms * self.thresholds.p95_latency_multiplier
            
            validations.append(ValidationResult(
                metric_name='pattern_match_p95_latency',
                actual_value=p95_latency_ms,
                threshold_value=expected_p95_max,
                passed=p95_latency_ms <= expected_p95_max,
                severity='warning' if p95_latency_ms > expected_p95_max else 'info',
                message=f"Pattern matching P95 latency: {p95_latency_ms:.2f}ms "
                       f"(expected max: {expected_p95_max:.2f}ms)"
            ))
        
        # Throughput validation
        if 'throughput' in result:
            throughput = result['throughput']
            
            validations.append(ValidationResult(
                metric_name='pattern_match_throughput',
                actual_value=throughput,
                threshold_value=self.thresholds.min_pattern_match_throughput,
                passed=throughput >= self.thresholds.min_pattern_match_throughput,
                severity='error' if throughput < self.thresholds.min_pattern_match_throughput else 'info',
                message=f"Pattern matching throughput: {throughput:.1f} ops/sec "
                       f"(min required: {self.thresholds.min_pattern_match_throughput})"
            ))
        
        return validations
    
    def _validate_learning_performance(self, result: Dict[str, Any]) -> List[ValidationResult]:
        """Validate learning performance."""
        validations = []
        
        # Mean latency validation
        if 'mean_time' in result:
            mean_latency_ms = result['mean_time'] * 1000
            
            validations.append(ValidationResult(
                metric_name='learning_mean_latency',
                actual_value=mean_latency_ms,
                threshold_value=self.thresholds.max_learning_update_latency_ms,
                passed=mean_latency_ms <= self.thresholds.max_learning_update_latency_ms,
                severity='error' if mean_latency_ms > self.thresholds.max_learning_update_latency_ms else 'info',
                message=f"Learning mean latency: {mean_latency_ms:.2f}ms "
                       f"(threshold: {self.thresholds.max_learning_update_latency_ms}ms)"
            ))
        
        # P99 latency validation (critical for learning)
        if 'p99_time' in result:
            p99_latency_ms = result['p99_time'] * 1000
            max_p99 = self.thresholds.max_learning_update_latency_ms * 2  # Allow 2x for P99
            
            validations.append(ValidationResult(
                metric_name='learning_p99_latency',
                actual_value=p99_latency_ms,
                threshold_value=max_p99,
                passed=p99_latency_ms <= max_p99,
                severity='critical' if p99_latency_ms > max_p99 else 'info',
                message=f"Learning P99 latency: {p99_latency_ms:.2f}ms "
                       f"(max allowed: {max_p99:.2f}ms)"
            ))
        
        # Throughput validation
        if 'throughput' in result:
            throughput = result['throughput']
            
            validations.append(ValidationResult(
                metric_name='learning_throughput',
                actual_value=throughput,
                threshold_value=self.thresholds.min_learning_throughput,
                passed=throughput >= self.thresholds.min_learning_throughput,
                severity='warning' if throughput < self.thresholds.min_learning_throughput else 'info',
                message=f"Learning throughput: {throughput:.1f} ops/sec "
                       f"(min required: {self.thresholds.min_learning_throughput})"
            ))
        
        return validations
    
    def _validate_concurrent_performance(self, result: Dict[str, Any]) -> List[ValidationResult]:
        """Validate concurrent performance."""
        validations = []
        
        # Concurrent performance should degrade gracefully
        if 'mean_time' in result:
            concurrent_latency_ms = result['mean_time'] * 1000
            max_concurrent_latency = self.thresholds.max_learning_update_latency_ms * 3  # Allow 3x for concurrency
            
            validations.append(ValidationResult(
                metric_name='concurrent_learning_latency',
                actual_value=concurrent_latency_ms,
                threshold_value=max_concurrent_latency,
                passed=concurrent_latency_ms <= max_concurrent_latency,
                severity='error' if concurrent_latency_ms > max_concurrent_latency else 'info',
                message=f"Concurrent learning latency: {concurrent_latency_ms:.2f}ms "
                       f"(max allowed: {max_concurrent_latency:.2f}ms)"
            ))
        
        # Concurrency metadata validation
        if 'metadata' in result and 'concurrency' in result['metadata']:
            concurrency = result['metadata']['concurrency']
            if concurrency >= 100:  # High concurrency test
                # Ensure reasonable scalability
                if 'throughput' in result:
                    expected_min_throughput = self.thresholds.min_learning_throughput * 0.5  # 50% of baseline
                    
                    validations.append(ValidationResult(
                        metric_name='high_concurrency_throughput',
                        actual_value=result['throughput'],
                        threshold_value=expected_min_throughput,
                        passed=result['throughput'] >= expected_min_throughput,
                        severity='warning' if result['throughput'] < expected_min_throughput else 'info',
                        message=f"High concurrency throughput: {result['throughput']:.1f} ops/sec "
                               f"(min expected: {expected_min_throughput:.1f})"
                    ))
        
        return validations
    
    def _validate_cross_instance_performance(self, result: Dict[str, Any]) -> List[ValidationResult]:
        """Validate cross-instance performance."""
        validations = []
        
        # Cross-instance latency validation
        if 'mean_time' in result:
            cross_latency_ms = result['mean_time'] * 1000
            
            validations.append(ValidationResult(
                metric_name='cross_instance_latency',
                actual_value=cross_latency_ms,
                threshold_value=self.thresholds.max_cross_instance_latency_ms,
                passed=cross_latency_ms <= self.thresholds.max_cross_instance_latency_ms,
                severity='error' if cross_latency_ms > self.thresholds.max_cross_instance_latency_ms else 'info',
                message=f"Cross-instance latency: {cross_latency_ms:.2f}ms "
                       f"(threshold: {self.thresholds.max_cross_instance_latency_ms}ms)"
            ))
        
        # Cross-instance P99 validation (critical for real-time coordination)
        if 'p99_time' in result:
            p99_latency_ms = result['p99_time'] * 1000
            max_p99_cross = self.thresholds.max_cross_instance_latency_ms * 3  # Allow 3x for P99
            
            validations.append(ValidationResult(
                metric_name='cross_instance_p99_latency',
                actual_value=p99_latency_ms,
                threshold_value=max_p99_cross,
                passed=p99_latency_ms <= max_p99_cross,
                severity='critical' if p99_latency_ms > max_p99_cross else 'info',
                message=f"Cross-instance P99 latency: {p99_latency_ms:.2f}ms "
                       f"(max allowed: {max_p99_cross:.2f}ms)"
            ))
        
        return validations
    
    def _validate_phase_performance(
        self, 
        phase_name: str, 
        metrics: Dict[str, Any]
    ) -> List[ValidationResult]:
        """Validate performance for a specific stress test phase."""
        validations = []
        
        # Learning latency under stress
        if 'avg_learning_latency' in metrics:
            latency_ms = metrics['avg_learning_latency'] * 1000
            
            # Stress-adjusted thresholds based on phase
            stress_multipliers = {
                'baseline': 1.0,
                'light': 1.5,
                'medium': 2.0,
                'heavy': 3.0,
                'extreme': 5.0,
                'critical': 8.0,
                'chaos': 10.0
            }
            
            multiplier = stress_multipliers.get(phase_name, 5.0)
            max_allowed_latency = self.thresholds.max_learning_update_latency_ms * multiplier
            
            severity = 'info'
            if latency_ms > max_allowed_latency:
                severity = 'error' if multiplier <= 3.0 else 'warning'
            
            validations.append(ValidationResult(
                metric_name=f'{phase_name}_learning_latency',
                actual_value=latency_ms,
                threshold_value=max_allowed_latency,
                passed=latency_ms <= max_allowed_latency,
                severity=severity,
                message=f"{phase_name} phase learning latency: {latency_ms:.2f}ms "
                       f"(max allowed: {max_allowed_latency:.2f}ms)"
            ))
        
        # Memory usage validation
        if 'memory_usage_mb' in metrics:
            memory_gb = metrics['memory_usage_mb'] / 1024
            
            validations.append(ValidationResult(
                metric_name=f'{phase_name}_memory_usage',
                actual_value=memory_gb,
                threshold_value=self.thresholds.max_memory_usage_gb,
                passed=memory_gb <= self.thresholds.max_memory_usage_gb,
                severity='critical' if memory_gb > self.thresholds.max_memory_usage_gb else 'info',
                message=f"{phase_name} phase memory usage: {memory_gb:.2f}GB "
                       f"(max allowed: {self.thresholds.max_memory_usage_gb}GB)"
            ))
        
        return validations
    
    def _validate_latency_metrics(
        self, 
        scenario_name: str, 
        latency_metrics: Dict[str, Any]
    ) -> List[ValidationResult]:
        """Validate latency metrics from load scenarios."""
        validations = []
        
        # Average latency validation
        if 'mean' in latency_metrics:
            mean_latency_ms = latency_metrics['mean'] * 1000
            
            # Different thresholds for different scenarios
            threshold_map = {
                'gradual_load': self.thresholds.max_learning_update_latency_ms * 2,
                'sustained_load': self.thresholds.max_learning_update_latency_ms * 3,
                'burst_load': self.thresholds.max_learning_update_latency_ms * 5,
                'variable_load': self.thresholds.max_learning_update_latency_ms * 2.5
            }
            
            threshold = threshold_map.get(scenario_name, self.thresholds.max_learning_update_latency_ms * 3)
            
            validations.append(ValidationResult(
                metric_name=f'{scenario_name}_mean_latency',
                actual_value=mean_latency_ms,
                threshold_value=threshold,
                passed=mean_latency_ms <= threshold,
                severity='error' if mean_latency_ms > threshold else 'info',
                message=f"{scenario_name} mean latency: {mean_latency_ms:.2f}ms "
                       f"(threshold: {threshold:.2f}ms)"
            ))
        
        # P95 latency validation
        if 'p95' in latency_metrics:
            p95_latency_ms = latency_metrics['p95'] * 1000
            max_p95 = (latency_metrics.get('mean', 0.01) * 1000) * self.thresholds.p95_latency_multiplier
            
            validations.append(ValidationResult(
                metric_name=f'{scenario_name}_p95_latency',
                actual_value=p95_latency_ms,
                threshold_value=max_p95,
                passed=p95_latency_ms <= max_p95,
                severity='warning' if p95_latency_ms > max_p95 else 'info',
                message=f"{scenario_name} P95 latency: {p95_latency_ms:.2f}ms "
                       f"(max expected: {max_p95:.2f}ms)"
            ))
        
        # P99 latency validation (critical for user experience)
        if 'p99' in latency_metrics:
            p99_latency_ms = latency_metrics['p99'] * 1000
            max_p99 = (latency_metrics.get('mean', 0.01) * 1000) * self.thresholds.p99_latency_multiplier
            
            validations.append(ValidationResult(
                metric_name=f'{scenario_name}_p99_latency',
                actual_value=p99_latency_ms,
                threshold_value=max_p99,
                passed=p99_latency_ms <= max_p99,
                severity='critical' if p99_latency_ms > max_p99 else 'info',
                message=f"{scenario_name} P99 latency: {p99_latency_ms:.2f}ms "
                       f"(max expected: {max_p99:.2f}ms)"
            ))
        
        return validations
    
    def _validate_resource_metrics(
        self, 
        scenario_name: str, 
        resource_metrics: Dict[str, Any]
    ) -> List[ValidationResult]:
        """Validate resource usage metrics."""
        validations = []
        
        # CPU usage validation
        if 'cpu_usage' in resource_metrics:
            cpu_usage = resource_metrics['cpu_usage']
            
            validations.append(ValidationResult(
                metric_name=f'{scenario_name}_cpu_usage',
                actual_value=cpu_usage,
                threshold_value=self.thresholds.max_cpu_usage_percent,
                passed=cpu_usage <= self.thresholds.max_cpu_usage_percent,
                severity='warning' if cpu_usage > self.thresholds.max_cpu_usage_percent else 'info',
                message=f"{scenario_name} CPU usage: {cpu_usage:.1f}% "
                       f"(max allowed: {self.thresholds.max_cpu_usage_percent}%)"
            ))
        
        # Memory efficiency validation
        if 'memory_per_pattern_kb' in resource_metrics:
            memory_per_pattern = resource_metrics['memory_per_pattern_kb']
            max_memory_per_pattern = 100  # 100KB per pattern threshold
            
            validations.append(ValidationResult(
                metric_name=f'{scenario_name}_memory_efficiency',
                actual_value=memory_per_pattern,
                threshold_value=max_memory_per_pattern,
                passed=memory_per_pattern <= max_memory_per_pattern,
                severity='warning' if memory_per_pattern > max_memory_per_pattern else 'info',
                message=f"{scenario_name} memory per pattern: {memory_per_pattern:.1f}KB "
                       f"(max allowed: {max_memory_per_pattern}KB)"
            ))
        
        return validations
    
    def generate_performance_report(
        self, 
        validations: List[ValidationResult]
    ) -> Dict[str, Any]:
        """Generate comprehensive performance validation report."""
        report = {
            'total_validations': len(validations),
            'passed_validations': 0,
            'failed_validations': 0,
            'by_severity': {'info': 0, 'warning': 0, 'error': 0, 'critical': 0},
            'critical_issues': [],
            'performance_score': 0.0,
            'recommendations': [],
            'detailed_results': []
        }
        
        # Process validations
        for validation in validations:
            report['detailed_results'].append(validation.to_dict())
            
            if validation.passed:
                report['passed_validations'] += 1
            else:
                report['failed_validations'] += 1
                
                if validation.severity == 'critical':
                    report['critical_issues'].append(validation.message)
            
            report['by_severity'][validation.severity] += 1
        
        # Calculate performance score
        if validations:
            # Weight by severity
            severity_weights = {'info': 1.0, 'warning': 0.8, 'error': 0.5, 'critical': 0.0}
            
            total_weight = 0
            weighted_score = 0
            
            for validation in validations:
                weight = severity_weights[validation.severity]
                total_weight += 1
                weighted_score += weight if validation.passed else 0
            
            report['performance_score'] = weighted_score / total_weight if total_weight > 0 else 0
        
        # Generate recommendations
        if report['by_severity']['critical'] > 0:
            report['recommendations'].append(
                f"CRITICAL: {report['by_severity']['critical']} critical performance issues detected - "
                "immediate action required"
            )
        
        if report['by_severity']['error'] > 0:
            report['recommendations'].append(
                f"ERROR: {report['by_severity']['error']} performance errors detected - "
                "system optimization needed"
            )
        
        if report['performance_score'] < 0.8:
            report['recommendations'].append(
                f"Performance score ({report['performance_score']:.2f}) below target (0.8) - "
                "comprehensive performance review recommended"
            )
        
        # Specific recommendations based on patterns
        latency_issues = [v for v in validations if 'latency' in v.metric_name and not v.passed]
        if len(latency_issues) > 3:
            report['recommendations'].append(
                "Multiple latency issues detected - consider caching, connection pooling, "
                "or algorithm optimization"
            )
        
        memory_issues = [v for v in validations if 'memory' in v.metric_name and not v.passed]
        if len(memory_issues) > 2:
            report['recommendations'].append(
                "Memory usage issues detected - implement memory pooling, garbage collection "
                "tuning, or data structure optimization"
            )
        
        return report