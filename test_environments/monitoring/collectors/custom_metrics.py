#!/usr/bin/env python3
"""
Custom Metrics Collector
Test-specific and business metrics for comprehensive monitoring
"""

import time
import logging
import threading
import asyncio
import json
import queue
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import math
import statistics

from ..metrics_collector import MetricValue

logger = logging.getLogger(__name__)

class TestPhase(Enum):
    INITIALIZATION = "initialization"
    WARM_UP = "warm_up"
    LOAD_GENERATION = "load_generation"
    STRESS_TESTING = "stress_testing"
    CHAOS_INJECTION = "chaos_injection"
    RECOVERY_TESTING = "recovery_testing"
    COOL_DOWN = "cool_down"
    ANALYSIS = "analysis"
    COMPLETED = "completed"

class TestSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EXTREME = "extreme"

@dataclass
class TestScenario:
    """Test scenario configuration and state"""
    name: str
    description: str
    phase: TestPhase
    severity: TestSeverity
    start_time: float
    expected_duration: float
    actual_duration: Optional[float] = None
    success_criteria: Dict[str, Any] = field(default_factory=dict)
    metrics_collected: int = 0
    errors_encountered: int = 0
    
@dataclass
class BusinessMetric:
    """Business-level metric definition"""
    name: str
    description: str
    value_type: str  # 'counter', 'gauge', 'histogram', 'rate'
    unit: str
    business_impact: str  # 'low', 'medium', 'high', 'critical'
    collection_frequency: float = 60.0  # seconds

@dataclass
class StressTestMetrics:
    """Stress testing specific metrics"""
    cycle_number: int
    concurrent_users: int
    requests_per_second: float
    error_rate: float
    response_time_avg: float
    response_time_p95: float
    response_time_p99: float
    throughput: float
    resource_utilization: Dict[str, float]
    breaking_point_reached: bool
    recovery_time: Optional[float] = None

class CustomMetricsCollector:
    """Advanced custom metrics collector for test-specific and business metrics"""
    
    def __init__(self):
        self.start_time = time.time()
        self.collection_errors = defaultdict(int)
        
        # Test scenario tracking
        self.current_scenario: Optional[TestScenario] = None
        self.scenario_history: List[TestScenario] = []
        self.test_phase_start_times: Dict[TestPhase, float] = {}
        
        # Business metrics registry
        self.business_metrics: Dict[str, BusinessMetric] = {}
        self.business_metric_values: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Stress testing metrics
        self.stress_test_cycles: List[StressTestMetrics] = []
        self.current_stress_cycle: Optional[StressTestMetrics] = None
        
        # Custom counters and gauges
        self.custom_counters = defaultdict(int)
        self.custom_gauges = defaultdict(float)
        self.custom_histograms = defaultdict(lambda: deque(maxlen=1000))
        
        # Performance baselines
        self.performance_baselines = {}
        self.performance_degradation_thresholds = {
            'response_time': 2.0,  # 2x baseline
            'error_rate': 0.05,    # 5% error rate
            'throughput': 0.8      # 80% of baseline
        }
        
        # Test environment state
        self.environment_state = {
            'load_generators_active': 0,
            'chaos_injectors_active': 0,
            'monitoring_overhead': 0.0,
            'test_data_size_mb': 0,
            'network_simulation_active': False,
            'resource_constraints_active': False
        }
        
        # Initialize default business metrics
        self._initialize_business_metrics()
        
        logger.info("Initialized custom metrics collector")
    
    def _initialize_business_metrics(self):
        """Initialize default business metrics"""
        default_metrics = [
            BusinessMetric("system_availability", "System uptime percentage", "gauge", "percent", "critical"),
            BusinessMetric("user_satisfaction_score", "User satisfaction rating", "gauge", "score", "high"),
            BusinessMetric("performance_efficiency", "System performance efficiency", "gauge", "ratio", "high"),
            BusinessMetric("resource_cost_efficiency", "Resource utilization cost efficiency", "gauge", "ratio", "medium"),
            BusinessMetric("failure_recovery_time", "Time to recover from failures", "histogram", "seconds", "critical"),
            BusinessMetric("capacity_utilization", "System capacity utilization", "gauge", "percent", "medium"),
            BusinessMetric("scalability_factor", "System scalability factor", "gauge", "ratio", "high"),
            BusinessMetric("reliability_score", "System reliability score", "gauge", "score", "critical")
        ]
        
        for metric in default_metrics:
            self.business_metrics[metric.name] = metric
    
    def collect_all_metrics(self) -> List[MetricValue]:
        """Collect all custom metrics"""
        timestamp = time.time()
        metrics = []
        
        try:
            # Test scenario metrics
            metrics.extend(self._collect_test_scenario_metrics(timestamp))
            
            # Stress testing metrics
            metrics.extend(self._collect_stress_testing_metrics(timestamp))
            
            # Business metrics
            metrics.extend(self._collect_business_metrics(timestamp))
            
            # Performance baseline metrics
            metrics.extend(self._collect_performance_baseline_metrics(timestamp))
            
            # Test environment metrics
            metrics.extend(self._collect_test_environment_metrics(timestamp))
            
            # Custom counters, gauges, and histograms
            metrics.extend(self._collect_custom_metric_values(timestamp))
            
            # Test progression metrics
            metrics.extend(self._collect_test_progression_metrics(timestamp))
            
        except Exception as e:
            logger.error(f"Error collecting custom metrics: {e}")
            self.collection_errors['general'] += 1
        
        return metrics
    
    def _collect_test_scenario_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect test scenario metrics"""
        metrics = []
        
        try:
            if self.current_scenario:
                scenario = self.current_scenario
                
                # Current scenario state
                metrics.extend([
                    MetricValue("test_scenario_active", 1, timestamp,
                              source="test", tags={"type": "scenario", "name": scenario.name}),
                    MetricValue("test_scenario_phase", scenario.phase.value, timestamp,
                              source="test", tags={"type": "scenario", "name": scenario.name}),
                    MetricValue("test_scenario_severity", scenario.severity.value, timestamp,
                              source="test", tags={"type": "scenario", "name": scenario.name}),
                    MetricValue("test_scenario_duration", timestamp - scenario.start_time, timestamp,
                              source="test", tags={"type": "scenario", "name": scenario.name}),
                    MetricValue("test_scenario_metrics_collected", scenario.metrics_collected, timestamp,
                              source="test", tags={"type": "scenario", "name": scenario.name}),
                    MetricValue("test_scenario_errors", scenario.errors_encountered, timestamp,
                              source="test", tags={"type": "scenario", "name": scenario.name})
                ])
                
                # Progress percentage
                if scenario.expected_duration > 0:
                    progress = min(1.0, (timestamp - scenario.start_time) / scenario.expected_duration)
                    metrics.append(MetricValue(
                        "test_scenario_progress", progress, timestamp,
                        source="test", tags={"type": "scenario", "name": scenario.name}
                    ))
            else:
                metrics.append(MetricValue(
                    "test_scenario_active", 0, timestamp,
                    source="test", tags={"type": "scenario"}
                ))
            
            # Scenario history metrics
            metrics.extend([
                MetricValue("test_scenarios_completed", len(self.scenario_history), timestamp,
                          source="test", tags={"type": "scenario_history"}),
                MetricValue("test_scenarios_total_duration", 
                          sum(s.actual_duration or 0 for s in self.scenario_history), timestamp,
                          source="test", tags={"type": "scenario_history"})
            ])
            
            # Phase timing metrics
            for phase, start_time in self.test_phase_start_times.items():
                if start_time > 0:
                    phase_duration = timestamp - start_time
                    metrics.append(MetricValue(
                        "test_phase_duration", phase_duration, timestamp,
                        source="test", tags={"type": "phase", "phase": phase.value}
                    ))
        
        except Exception as e:
            logger.error(f"Test scenario metrics collection error: {e}")
            self.collection_errors['test_scenario'] += 1
        
        return metrics
    
    def _collect_stress_testing_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect stress testing specific metrics"""
        metrics = []
        
        try:
            if self.current_stress_cycle:
                cycle = self.current_stress_cycle
                
                # Current stress cycle metrics
                metrics.extend([
                    MetricValue("stress_test_cycle_number", cycle.cycle_number, timestamp,
                              source="test", tags={"type": "stress_test"}),
                    MetricValue("stress_test_concurrent_users", cycle.concurrent_users, timestamp,
                              source="test", tags={"type": "stress_test"}),
                    MetricValue("stress_test_requests_per_second", cycle.requests_per_second, timestamp,
                              source="test", tags={"type": "stress_test"}),
                    MetricValue("stress_test_error_rate", cycle.error_rate, timestamp,
                              source="test", tags={"type": "stress_test"}),
                    MetricValue("stress_test_response_time_avg", cycle.response_time_avg, timestamp,
                              source="test", tags={"type": "stress_test"}),
                    MetricValue("stress_test_response_time_p95", cycle.response_time_p95, timestamp,
                              source="test", tags={"type": "stress_test"}),
                    MetricValue("stress_test_response_time_p99", cycle.response_time_p99, timestamp,
                              source="test", tags={"type": "stress_test"}),
                    MetricValue("stress_test_throughput", cycle.throughput, timestamp,
                              source="test", tags={"type": "stress_test"}),
                    MetricValue("stress_test_breaking_point_reached", int(cycle.breaking_point_reached), timestamp,
                              source="test", tags={"type": "stress_test"})
                ])
                
                # Resource utilization during stress test
                for resource, utilization in cycle.resource_utilization.items():
                    metrics.append(MetricValue(
                        "stress_test_resource_utilization", utilization, timestamp,
                        source="test", tags={"type": "stress_test", "resource": resource}
                    ))
                
                # Recovery time if available
                if cycle.recovery_time is not None:
                    metrics.append(MetricValue(
                        "stress_test_recovery_time", cycle.recovery_time, timestamp,
                        source="test", tags={"type": "stress_test"}
                    ))
            
            # Historical stress test metrics
            if self.stress_test_cycles:
                completed_cycles = len(self.stress_test_cycles)
                avg_error_rate = statistics.mean(c.error_rate for c in self.stress_test_cycles)
                avg_response_time = statistics.mean(c.response_time_avg for c in self.stress_test_cycles)
                breaking_points_reached = sum(1 for c in self.stress_test_cycles if c.breaking_point_reached)
                
                metrics.extend([
                    MetricValue("stress_test_cycles_completed", completed_cycles, timestamp,
                              source="test", tags={"type": "stress_test_history"}),
                    MetricValue("stress_test_avg_error_rate", avg_error_rate, timestamp,
                              source="test", tags={"type": "stress_test_history"}),
                    MetricValue("stress_test_avg_response_time", avg_response_time, timestamp,
                              source="test", tags={"type": "stress_test_history"}),
                    MetricValue("stress_test_breaking_points_reached", breaking_points_reached, timestamp,
                              source="test", tags={"type": "stress_test_history"})
                ])
                
                # Recovery time statistics
                recovery_times = [c.recovery_time for c in self.stress_test_cycles if c.recovery_time is not None]
                if recovery_times:
                    avg_recovery_time = statistics.mean(recovery_times)
                    max_recovery_time = max(recovery_times)
                    metrics.extend([
                        MetricValue("stress_test_avg_recovery_time", avg_recovery_time, timestamp,
                                  source="test", tags={"type": "stress_test_history"}),
                        MetricValue("stress_test_max_recovery_time", max_recovery_time, timestamp,
                                  source="test", tags={"type": "stress_test_history"})
                    ])
        
        except Exception as e:
            logger.error(f"Stress testing metrics collection error: {e}")
            self.collection_errors['stress_testing'] += 1
        
        return metrics
    
    def _collect_business_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect business-level metrics"""
        metrics = []
        
        try:
            for metric_name, business_metric in self.business_metrics.items():
                values = self.business_metric_values.get(metric_name, deque())
                
                if values:
                    # Latest value
                    latest_value = values[-1] if values else 0
                    metrics.append(MetricValue(
                        f"business_{metric_name}", latest_value, timestamp,
                        source="business", 
                        tags={
                            "type": "business_metric",
                            "impact": business_metric.business_impact,
                            "unit": business_metric.unit,
                            "value_type": business_metric.value_type
                        }
                    ))
                    
                    # Statistical analysis for histograms and time series
                    if business_metric.value_type in ['histogram', 'gauge'] and len(values) > 1:
                        values_list = list(values)
                        
                        metrics.extend([
                            MetricValue(f"business_{metric_name}_avg", statistics.mean(values_list), timestamp,
                                      source="business", tags={"type": "business_metric_stats", "metric": metric_name}),
                            MetricValue(f"business_{metric_name}_min", min(values_list), timestamp,
                                      source="business", tags={"type": "business_metric_stats", "metric": metric_name}),
                            MetricValue(f"business_{metric_name}_max", max(values_list), timestamp,
                                      source="business", tags={"type": "business_metric_stats", "metric": metric_name})
                        ])
                        
                        if len(values_list) > 5:
                            try:
                                metrics.extend([
                                    MetricValue(f"business_{metric_name}_p95", 
                                              statistics.quantiles(values_list, n=20)[18], timestamp,
                                              source="business", tags={"type": "business_metric_stats", "metric": metric_name}),
                                    MetricValue(f"business_{metric_name}_std", statistics.stdev(values_list), timestamp,
                                              source="business", tags={"type": "business_metric_stats", "metric": metric_name})
                                ])
                            except Exception:
                                pass
                
                # Metric collection rate
                collection_rate = len(values) / max(1, (timestamp - self.start_time) / business_metric.collection_frequency)
                metrics.append(MetricValue(
                    f"business_{metric_name}_collection_rate", collection_rate, timestamp,
                    source="business", tags={"type": "business_metric_health", "metric": metric_name}
                ))
            
            # Overall business health score
            if self.business_metric_values:
                # Calculate weighted business health score
                weighted_scores = []
                for metric_name, business_metric in self.business_metrics.items():
                    values = self.business_metric_values.get(metric_name, deque())
                    if values:
                        latest_value = values[-1]
                        
                        # Weight based on business impact
                        weight = {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(business_metric.business_impact, 1)
                        
                        # Normalize value (assuming 0-1 range for scores, 0-100 for percentages)
                        if business_metric.unit == "percent":
                            normalized_value = latest_value / 100.0
                        elif business_metric.unit == "score":
                            normalized_value = latest_value  # Assume already 0-1
                        elif business_metric.unit == "ratio":
                            normalized_value = min(1.0, latest_value)  # Cap at 1.0
                        else:
                            normalized_value = 0.5  # Default neutral score
                        
                        weighted_scores.append(normalized_value * weight)
                
                if weighted_scores:
                    business_health = sum(weighted_scores) / len(weighted_scores)
                    metrics.append(MetricValue(
                        "business_health_score", business_health, timestamp,
                        source="business", tags={"type": "business_health"}
                    ))
        
        except Exception as e:
            logger.error(f"Business metrics collection error: {e}")
            self.collection_errors['business'] += 1
        
        return metrics
    
    def _collect_performance_baseline_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect performance baseline and degradation metrics"""
        metrics = []
        
        try:
            for metric_name, baseline_value in self.performance_baselines.items():
                # Current vs baseline comparison
                current_value = self.custom_gauges.get(f"current_{metric_name}", baseline_value)
                
                if baseline_value > 0:
                    # Calculate degradation ratio
                    if metric_name == 'throughput':
                        degradation = baseline_value / max(current_value, 0.001)  # Higher is better
                    else:
                        degradation = current_value / baseline_value  # Lower is better for response time, error rate
                    
                    metrics.extend([
                        MetricValue(f"performance_baseline_{metric_name}", baseline_value, timestamp,
                                  source="test", tags={"type": "performance_baseline"}),
                        MetricValue(f"performance_current_{metric_name}", current_value, timestamp,
                                  source="test", tags={"type": "performance_current"}),
                        MetricValue(f"performance_degradation_{metric_name}", degradation, timestamp,
                                  source="test", tags={"type": "performance_degradation"})
                    ])
                    
                    # Check if degradation threshold is exceeded
                    threshold = self.performance_degradation_thresholds.get(metric_name, 2.0)
                    is_degraded = degradation > threshold
                    metrics.append(MetricValue(
                        f"performance_degraded_{metric_name}", int(is_degraded), timestamp,
                        source="test", tags={"type": "performance_alert"}
                    ))
            
            # Overall performance health
            degradation_values = []
            for metric_name in self.performance_baselines.keys():
                degradation_key = f"performance_degradation_{metric_name}"
                if degradation_key in [m.name for m in metrics]:
                    degradation = next(m.value for m in metrics if m.name == degradation_key)
                    threshold = self.performance_degradation_thresholds.get(metric_name, 2.0)
                    health_score = max(0, 1 - (degradation - 1) / (threshold - 1))
                    degradation_values.append(health_score)
            
            if degradation_values:
                overall_performance_health = statistics.mean(degradation_values)
                metrics.append(MetricValue(
                    "performance_health_score", overall_performance_health, timestamp,
                    source="test", tags={"type": "performance_health"}
                ))
        
        except Exception as e:
            logger.error(f"Performance baseline metrics collection error: {e}")
            self.collection_errors['performance_baseline'] += 1
        
        return metrics
    
    def _collect_test_environment_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect test environment state metrics"""
        metrics = []
        
        try:
            for state_name, value in self.environment_state.items():
                metrics.append(MetricValue(
                    f"test_environment_{state_name}", value, timestamp,
                    source="test", tags={"type": "environment_state"}
                ))
            
            # Test environment health score
            health_factors = []
            
            # Factor in monitoring overhead
            monitoring_overhead = self.environment_state.get('monitoring_overhead', 0.0)
            overhead_health = max(0, 1 - monitoring_overhead / 0.1)  # 10% overhead is concerning
            health_factors.append(overhead_health)
            
            # Factor in active load generators
            load_generators = self.environment_state.get('load_generators_active', 0)
            load_health = min(1, load_generators / 5)  # Assume 5 is optimal
            health_factors.append(load_health)
            
            # Factor in chaos injection
            chaos_active = self.environment_state.get('chaos_injectors_active', 0)
            chaos_health = 1 - min(0.5, chaos_active / 10)  # Chaos reduces environment health
            health_factors.append(chaos_health)
            
            if health_factors:
                environment_health = statistics.mean(health_factors)
                metrics.append(MetricValue(
                    "test_environment_health_score", environment_health, timestamp,
                    source="test", tags={"type": "environment_health"}
                ))
        
        except Exception as e:
            logger.error(f"Test environment metrics collection error: {e}")
            self.collection_errors['test_environment'] += 1
        
        return metrics
    
    def _collect_custom_metric_values(self, timestamp: float) -> List[MetricValue]:
        """Collect custom counters, gauges, and histograms"""
        metrics = []
        
        try:
            # Custom counters
            for name, value in self.custom_counters.items():
                metrics.append(MetricValue(
                    f"custom_counter_{name}", value, timestamp,
                    source="custom", tags={"type": "counter"}
                ))
            
            # Custom gauges
            for name, value in self.custom_gauges.items():
                metrics.append(MetricValue(
                    f"custom_gauge_{name}", value, timestamp,
                    source="custom", tags={"type": "gauge"}
                ))
            
            # Custom histograms
            for name, values in self.custom_histograms.items():
                if values:
                    values_list = list(values)
                    
                    metrics.extend([
                        MetricValue(f"custom_histogram_{name}_count", len(values_list), timestamp,
                                  source="custom", tags={"type": "histogram", "stat": "count"}),
                        MetricValue(f"custom_histogram_{name}_avg", statistics.mean(values_list), timestamp,
                                  source="custom", tags={"type": "histogram", "stat": "mean"}),
                        MetricValue(f"custom_histogram_{name}_min", min(values_list), timestamp,
                                  source="custom", tags={"type": "histogram", "stat": "min"}),
                        MetricValue(f"custom_histogram_{name}_max", max(values_list), timestamp,
                                  source="custom", tags={"type": "histogram", "stat": "max"})
                    ])
                    
                    if len(values_list) > 5:
                        try:
                            sorted_values = sorted(values_list)
                            p50_idx = len(sorted_values) // 2
                            p95_idx = int(len(sorted_values) * 0.95)
                            p99_idx = int(len(sorted_values) * 0.99)
                            
                            metrics.extend([
                                MetricValue(f"custom_histogram_{name}_p50", sorted_values[p50_idx], timestamp,
                                          source="custom", tags={"type": "histogram", "stat": "p50"}),
                                MetricValue(f"custom_histogram_{name}_p95", sorted_values[p95_idx], timestamp,
                                          source="custom", tags={"type": "histogram", "stat": "p95"}),
                                MetricValue(f"custom_histogram_{name}_p99", sorted_values[p99_idx], timestamp,
                                          source="custom", tags={"type": "histogram", "stat": "p99"})
                            ])
                        except Exception:
                            pass
        
        except Exception as e:
            logger.error(f"Custom metric values collection error: {e}")
            self.collection_errors['custom_values'] += 1
        
        return metrics
    
    def _collect_test_progression_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect test progression and milestone metrics"""
        metrics = []
        
        try:
            # Test suite progression
            total_test_time = timestamp - self.start_time
            metrics.append(MetricValue(
                "test_suite_total_time", total_test_time, timestamp,
                source="test", tags={"type": "progression"}
            ))
            
            # Phase progression
            completed_phases = len([p for p, t in self.test_phase_start_times.items() if t > 0])
            total_phases = len(TestPhase)
            phase_progress = completed_phases / total_phases
            
            metrics.extend([
                MetricValue("test_phases_completed", completed_phases, timestamp,
                          source="test", tags={"type": "progression"}),
                MetricValue("test_phase_progress", phase_progress, timestamp,
                          source="test", tags={"type": "progression"})
            ])
            
            # Test milestone achievements
            milestones = [
                ("first_load_test", "load_generators_active"),
                ("chaos_injection_started", "chaos_injectors_active"),
                ("performance_baseline_established", len(self.performance_baselines) > 0),
                ("stress_testing_initiated", len(self.stress_test_cycles) > 0)
            ]
            
            for milestone_name, condition in milestones:
                if isinstance(condition, str):
                    achieved = self.environment_state.get(condition, 0) > 0
                else:
                    achieved = condition
                
                metrics.append(MetricValue(
                    f"test_milestone_{milestone_name}", int(achieved), timestamp,
                    source="test", tags={"type": "milestone"}
                ))
            
            # Success rate metrics
            total_errors = sum(self.collection_errors.values())
            total_metrics_attempts = sum(getattr(s, 'metrics_collected', 0) for s in self.scenario_history)
            
            if total_metrics_attempts > 0:
                success_rate = 1 - (total_errors / max(total_metrics_attempts, 1))
                metrics.append(MetricValue(
                    "test_success_rate", success_rate, timestamp,
                    source="test", tags={"type": "quality"}
                ))
        
        except Exception as e:
            logger.error(f"Test progression metrics collection error: {e}")
            self.collection_errors['test_progression'] += 1
        
        return metrics
    
    # Public methods for updating custom metrics
    def start_test_scenario(self, name: str, description: str, severity: TestSeverity, expected_duration: float):
        """Start a new test scenario"""
        if self.current_scenario:
            self.end_test_scenario()
        
        self.current_scenario = TestScenario(
            name=name,
            description=description,
            phase=TestPhase.INITIALIZATION,
            severity=severity,
            start_time=time.time(),
            expected_duration=expected_duration
        )
        
        logger.info(f"Started test scenario: {name} ({severity.value})")
    
    def end_test_scenario(self):
        """End the current test scenario"""
        if self.current_scenario:
            self.current_scenario.actual_duration = time.time() - self.current_scenario.start_time
            self.scenario_history.append(self.current_scenario)
            self.current_scenario = None
            logger.info("Ended test scenario")
    
    def set_test_phase(self, phase: TestPhase):
        """Set the current test phase"""
        if self.current_scenario:
            self.current_scenario.phase = phase
        
        self.test_phase_start_times[phase] = time.time()
        logger.info(f"Test phase changed to: {phase.value}")
    
    def start_stress_test_cycle(self, cycle_number: int, concurrent_users: int, requests_per_second: float):
        """Start a new stress test cycle"""
        self.current_stress_cycle = StressTestMetrics(
            cycle_number=cycle_number,
            concurrent_users=concurrent_users,
            requests_per_second=requests_per_second,
            error_rate=0.0,
            response_time_avg=0.0,
            response_time_p95=0.0,
            response_time_p99=0.0,
            throughput=0.0,
            resource_utilization={},
            breaking_point_reached=False
        )
        
        logger.info(f"Started stress test cycle {cycle_number} with {concurrent_users} users")
    
    def update_stress_test_cycle(self, **kwargs):
        """Update current stress test cycle metrics"""
        if self.current_stress_cycle:
            for key, value in kwargs.items():
                if hasattr(self.current_stress_cycle, key):
                    setattr(self.current_stress_cycle, key, value)
    
    def end_stress_test_cycle(self):
        """End the current stress test cycle"""
        if self.current_stress_cycle:
            self.stress_test_cycles.append(self.current_stress_cycle)
            self.current_stress_cycle = None
            logger.info("Ended stress test cycle")
    
    def record_business_metric(self, metric_name: str, value: float):
        """Record a business metric value"""
        if metric_name in self.business_metrics:
            self.business_metric_values[metric_name].append(value)
        else:
            logger.warning(f"Unknown business metric: {metric_name}")
    
    def set_performance_baseline(self, metric_name: str, baseline_value: float):
        """Set a performance baseline"""
        self.performance_baselines[metric_name] = baseline_value
        logger.info(f"Set performance baseline for {metric_name}: {baseline_value}")
    
    def update_environment_state(self, **kwargs):
        """Update test environment state"""
        self.environment_state.update(kwargs)
    
    def increment_custom_counter(self, name: str, value: int = 1):
        """Increment a custom counter"""
        self.custom_counters[name] += value
    
    def set_custom_gauge(self, name: str, value: float):
        """Set a custom gauge value"""
        self.custom_gauges[name] = value
    
    def record_custom_histogram(self, name: str, value: float):
        """Record a value in a custom histogram"""
        self.custom_histograms[name].append(value)
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        return {
            'collection_errors': dict(self.collection_errors),
            'total_errors': sum(self.collection_errors.values()),
            'current_scenario': self.current_scenario.name if self.current_scenario else None,
            'scenarios_completed': len(self.scenario_history),
            'stress_cycles_completed': len(self.stress_test_cycles),
            'business_metrics_count': len(self.business_metrics),
            'performance_baselines_count': len(self.performance_baselines),
            'custom_counters_count': len(self.custom_counters),
            'custom_gauges_count': len(self.custom_gauges),
            'custom_histograms_count': len(self.custom_histograms)
        }

# Example usage
if __name__ == "__main__":
    collector = CustomMetricsCollector()
    
    # Simulate test scenario
    collector.start_test_scenario("Load Test", "Basic load testing", TestSeverity.MEDIUM, 300)
    collector.set_test_phase(TestPhase.LOAD_GENERATION)
    
    # Simulate stress testing
    collector.start_stress_test_cycle(1, 100, 50.0)
    collector.update_stress_test_cycle(
        error_rate=0.02,
        response_time_avg=0.5,
        response_time_p95=1.2,
        throughput=48.5,
        resource_utilization={"cpu": 0.7, "memory": 0.6}
    )
    
    # Record business metrics
    collector.record_business_metric("system_availability", 0.99)
    collector.record_business_metric("user_satisfaction_score", 0.85)
    
    # Set performance baselines
    collector.set_performance_baseline("response_time", 0.3)
    collector.set_performance_baseline("throughput", 50.0)
    
    # Custom metrics
    collector.increment_custom_counter("test_requests", 1000)
    collector.set_custom_gauge("load_factor", 0.75)
    collector.record_custom_histogram("processing_time", 0.45)
    
    print("=== Custom Metrics Collection ===")
    metrics = collector.collect_all_metrics()
    
    print(f"Collected {len(metrics)} custom metrics")
    
    # Show sample metrics
    for metric in metrics[:20]:
        print(f"{metric.name}: {metric.value} (tags: {metric.tags})")
    
    print("\n=== Collection Statistics ===")
    stats = collector.get_collection_stats()
    print(json.dumps(stats, indent=2, default=str))