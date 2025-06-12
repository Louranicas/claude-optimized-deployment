"""
Breaking Point Analyzer

Identifies system breaking points, capacity limits, and performance cliffs.
Provides detailed analysis of system limits and failure thresholds.
"""

import asyncio
import logging
import time
import statistics
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import json

logger = logging.getLogger(__name__)


class BreakingPointType(Enum):
    """Types of breaking points"""
    CAPACITY_LIMIT = "capacity_limit"
    PERFORMANCE_CLIFF = "performance_cliff"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    LATENCY_THRESHOLD = "latency_threshold"
    ERROR_RATE_SPIKE = "error_rate_spike"
    THROUGHPUT_CEILING = "throughput_ceiling"
    MEMORY_LIMIT = "memory_limit"
    CONNECTION_LIMIT = "connection_limit"
    DISK_IO_LIMIT = "disk_io_limit"
    NETWORK_BANDWIDTH_LIMIT = "network_bandwidth_limit"


@dataclass
class BreakingPointMeasurement:
    """Individual breaking point measurement"""
    breaking_point_type: BreakingPointType
    service_name: str
    measurement_timestamp: datetime
    
    # Threshold values
    threshold_value: float
    threshold_unit: str
    confidence_level: float = 0.0
    
    # Context at breaking point
    system_metrics_at_breaking_point: Dict[str, Any] = field(default_factory=dict)
    load_characteristics: Dict[str, Any] = field(default_factory=dict)
    
    # Impact analysis
    degradation_pattern: str = ""
    failure_mode: str = ""
    recovery_difficulty: float = 0.0  # 0-1 scale
    
    # Performance characteristics
    performance_before_breaking_point: Dict[str, Any] = field(default_factory=dict)
    performance_at_breaking_point: Dict[str, Any] = field(default_factory=dict)
    performance_after_breaking_point: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemCapacityProfile:
    """Overall system capacity profile"""
    service_name: str
    analysis_timestamp: datetime
    
    # Capacity metrics
    max_throughput_rps: float = 0.0
    max_concurrent_connections: int = 0
    max_memory_usage_mb: float = 0.0
    max_cpu_utilization_percent: float = 0.0
    max_disk_io_ops_sec: float = 0.0
    max_network_bandwidth_mbps: float = 0.0
    
    # Breaking points
    breaking_points: List[BreakingPointMeasurement] = field(default_factory=list)
    
    # Performance characteristics
    performance_cliff_points: List[float] = field(default_factory=list)
    linear_scaling_limit: float = 0.0
    graceful_degradation_threshold: float = 0.0
    
    # Safety margins
    recommended_operating_limit: float = 0.0
    safety_margin_percent: float = 20.0
    
    # Stability analysis
    stable_operating_range: Tuple[float, float] = (0.0, 0.0)
    unstable_regions: List[Tuple[float, float]] = field(default_factory=list)


class BreakingPointAnalyzer:
    """
    Analyzes system breaking points, capacity limits, and performance cliffs.
    Identifies system limits and provides capacity planning recommendations.
    """
    
    def __init__(self):
        self.analysis_history: List[SystemCapacityProfile] = []
        self.measurement_cache: Dict[str, Dict[str, Any]] = {}
        
        # Analysis configuration
        self.load_increment_percentage = 10  # Increase load by 10% each step
        self.measurement_duration_seconds = 30  # Measure for 30 seconds at each load
        self.stability_threshold_seconds = 15  # Require 15 seconds of stability
        self.max_load_multiplier = 10.0  # Maximum 10x normal load
        
        # Breaking point detection thresholds
        self.performance_degradation_threshold = 0.2  # 20% degradation
        self.error_rate_threshold = 0.05  # 5% error rate
        self.latency_multiplier_threshold = 2.0  # 2x baseline latency
        
        logger.info("Breaking Point Analyzer initialized")
    
    async def analyze_breaking_points(self, services: List[str], 
                                    failure_scenarios: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze breaking points across multiple services"""
        logger.info(f"Analyzing breaking points for {len(services)} services")
        
        analysis_results = {}
        
        for service in services:
            try:
                service_analysis = await self._analyze_service_breaking_points(service)
                analysis_results[service] = service_analysis
                
            except Exception as e:
                logger.error(f"Breaking point analysis failed for {service}: {e}")
                analysis_results[service] = {"error": str(e)}
        
        # Analyze system-wide breaking points
        system_analysis = await self._analyze_system_wide_breaking_points(analysis_results)
        
        return {
            "analysis_timestamp": datetime.now().isoformat(),
            "service_analysis": analysis_results,
            "system_analysis": system_analysis,
            "capacity_recommendations": self._generate_capacity_recommendations(analysis_results)
        }
    
    async def find_capacity_limits(self, service: str, load_pattern: str = "linear") -> Dict[str, Any]:
        """Find capacity limits using systematic load testing"""
        logger.info(f"Finding capacity limits for {service} using {load_pattern} load pattern")
        
        # Get baseline metrics
        baseline_metrics = await self._get_baseline_metrics(service)
        
        # Initialize load testing
        current_load_multiplier = 1.0
        breaking_points = []
        performance_data = []
        
        while current_load_multiplier <= self.max_load_multiplier:
            try:
                # Apply load
                load_metrics = await self._apply_load(service, current_load_multiplier, load_pattern)
                
                # Measure performance
                performance_metrics = await self._measure_performance_under_load(
                    service, current_load_multiplier, baseline_metrics
                )
                
                performance_data.append({
                    "load_multiplier": current_load_multiplier,
                    "performance_metrics": performance_metrics,
                    "load_metrics": load_metrics,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Check for breaking points
                breaking_point = await self._detect_breaking_point(
                    service, current_load_multiplier, performance_metrics, baseline_metrics
                )
                
                if breaking_point:
                    breaking_points.append(breaking_point)
                    
                    # If critical breaking point, stop testing
                    if breaking_point.breaking_point_type in [
                        BreakingPointType.CAPACITY_LIMIT,
                        BreakingPointType.RESOURCE_EXHAUSTION
                    ]:
                        logger.warning(f"Critical breaking point reached for {service} at {current_load_multiplier}x load")
                        break
                
                # Increment load
                current_load_multiplier += self.load_increment_percentage / 100
                
                # Allow system to stabilize between tests
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Load testing failed at {current_load_multiplier}x load: {e}")
                break
        
        # Analyze results
        capacity_analysis = self._analyze_capacity_data(service, performance_data, breaking_points)
        
        return {
            "service": service,
            "load_pattern": load_pattern,
            "max_load_tested": current_load_multiplier,
            "breaking_points": [bp.__dict__ for bp in breaking_points],
            "performance_data": performance_data,
            "capacity_analysis": capacity_analysis,
            "baseline_metrics": baseline_metrics
        }
    
    async def identify_performance_cliffs(self, service: str) -> Dict[str, Any]:
        """Identify performance cliffs where performance drops rapidly"""
        logger.info(f"Identifying performance cliffs for {service}")
        
        # Get performance data across load range
        load_range = [i * 0.1 for i in range(1, 51)]  # 0.1x to 5.0x load
        performance_cliff_data = []
        
        for load_multiplier in load_range:
            try:
                performance_metrics = await self._measure_performance_under_load(
                    service, load_multiplier, await self._get_baseline_metrics(service)
                )
                
                performance_cliff_data.append({
                    "load": load_multiplier,
                    "response_time": performance_metrics.get("response_time", 0),
                    "throughput": performance_metrics.get("throughput", 0),
                    "error_rate": performance_metrics.get("error_rate", 0),
                    "cpu_usage": performance_metrics.get("cpu_usage", 0),
                    "memory_usage": performance_metrics.get("memory_usage", 0)
                })
                
            except Exception as e:
                logger.debug(f"Performance measurement failed at {load_multiplier}x load: {e}")
        
        # Analyze for cliffs
        cliffs = self._detect_performance_cliffs(performance_cliff_data)
        
        return {
            "service": service,
            "performance_data": performance_cliff_data,
            "detected_cliffs": cliffs,
            "cliff_analysis": self._analyze_performance_cliffs(cliffs)
        }
    
    async def analyze_resource_exhaustion_points(self, service: str) -> Dict[str, Any]:
        """Analyze points where resources become exhausted"""
        logger.info(f"Analyzing resource exhaustion points for {service}")
        
        resource_types = ["cpu", "memory", "disk_io", "network", "connections"]
        exhaustion_points = {}
        
        for resource_type in resource_types:
            try:
                exhaustion_point = await self._find_resource_exhaustion_point(service, resource_type)
                exhaustion_points[resource_type] = exhaustion_point
                
            except Exception as e:
                logger.error(f"Resource exhaustion analysis failed for {resource_type}: {e}")
                exhaustion_points[resource_type] = {"error": str(e)}
        
        # Analyze resource interaction effects
        interaction_analysis = await self._analyze_resource_interactions(service, exhaustion_points)
        
        return {
            "service": service,
            "exhaustion_points": exhaustion_points,
            "resource_interactions": interaction_analysis,
            "critical_resources": self._identify_critical_resources(exhaustion_points)
        }
    
    async def measure_system_stability_boundaries(self, service: str) -> Dict[str, Any]:
        """Measure boundaries of stable system operation"""
        logger.info(f"Measuring stability boundaries for {service}")
        
        stability_measurements = []
        load_levels = [i * 0.2 for i in range(1, 26)]  # 0.2x to 5.0x load
        
        for load_level in load_levels:
            try:
                stability_metrics = await self._measure_stability_at_load(service, load_level)
                stability_measurements.append({
                    "load_level": load_level,
                    "stability_score": stability_metrics["stability_score"],
                    "variance_metrics": stability_metrics["variance_metrics"],
                    "stability_duration": stability_metrics["measurement_duration"]
                })
                
            except Exception as e:
                logger.debug(f"Stability measurement failed at {load_level}x load: {e}")
        
        # Analyze stability boundaries
        stability_analysis = self._analyze_stability_boundaries(stability_measurements)
        
        return {
            "service": service,
            "stability_measurements": stability_measurements,
            "stability_boundaries": stability_analysis,
            "recommended_operating_range": stability_analysis.get("safe_operating_range", (0.0, 1.0))
        }
    
    # Internal analysis methods
    async def _analyze_service_breaking_points(self, service: str) -> SystemCapacityProfile:
        """Analyze breaking points for a single service"""
        capacity_profile = SystemCapacityProfile(
            service_name=service,
            analysis_timestamp=datetime.now()
        )
        
        # Find capacity limits
        capacity_results = await self.find_capacity_limits(service)
        capacity_profile.breaking_points = [
            BreakingPointMeasurement(**bp) for bp in capacity_results.get("breaking_points", [])
        ]
        
        # Identify performance cliffs
        cliff_results = await self.identify_performance_cliffs(service)
        capacity_profile.performance_cliff_points = [
            cliff["load_point"] for cliff in cliff_results.get("detected_cliffs", [])
        ]
        
        # Analyze resource exhaustion
        resource_results = await self.analyze_resource_exhaustion_points(service)
        
        # Measure stability boundaries
        stability_results = await self.measure_system_stability_boundaries(service)
        capacity_profile.stable_operating_range = stability_results.get("recommended_operating_range", (0.0, 1.0))
        
        # Calculate derived metrics
        capacity_profile.max_throughput_rps = max(
            [bp.threshold_value for bp in capacity_profile.breaking_points 
             if bp.breaking_point_type == BreakingPointType.THROUGHPUT_CEILING],
            default=0.0
        )
        
        capacity_profile.linear_scaling_limit = min(
            capacity_profile.performance_cliff_points, default=float('inf')
        )
        
        capacity_profile.recommended_operating_limit = capacity_profile.stable_operating_range[1] * 0.8  # 80% of stable limit
        
        return capacity_profile
    
    async def _apply_load(self, service: str, load_multiplier: float, pattern: str) -> Dict[str, Any]:
        """Apply load to service according to pattern"""
        if pattern == "linear":
            rps = 100 * load_multiplier  # Linear scaling from 100 RPS baseline
        elif pattern == "exponential":
            rps = 100 * (2 ** (load_multiplier - 1))  # Exponential scaling
        elif pattern == "step":
            rps = 100 * math.ceil(load_multiplier)  # Step function
        else:
            rps = 100 * load_multiplier  # Default to linear
        
        # Simulate load application
        await asyncio.sleep(0.1)  # Simulate load ramp-up time
        
        return {
            "target_rps": rps,
            "actual_rps": rps * 0.95,  # Simulate slight variance
            "load_pattern": pattern,
            "load_multiplier": load_multiplier
        }
    
    async def _measure_performance_under_load(self, service: str, load_multiplier: float,
                                            baseline_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Measure performance metrics under specific load"""
        # Simulate performance measurement
        baseline_response_time = baseline_metrics.get("response_time", 0.1)
        baseline_throughput = baseline_metrics.get("throughput", 100.0)
        baseline_error_rate = baseline_metrics.get("error_rate", 0.01)
        
        # Performance degrades with load
        response_time = baseline_response_time * (1 + (load_multiplier - 1) * 0.5)
        throughput = baseline_throughput * min(load_multiplier, 3.0)  # Throughput plateaus at 3x
        error_rate = baseline_error_rate * (load_multiplier ** 1.5)  # Exponential error increase
        
        # Resource usage increases with load
        cpu_usage = min(1.0, 0.3 + (load_multiplier - 1) * 0.2)
        memory_usage = min(1.0, 0.4 + (load_multiplier - 1) * 0.15)
        
        return {
            "response_time": response_time,
            "throughput": throughput,
            "error_rate": min(error_rate, 1.0),
            "cpu_usage": cpu_usage,
            "memory_usage": memory_usage,
            "load_multiplier": load_multiplier,
            "measurement_timestamp": datetime.now().isoformat()
        }
    
    async def _detect_breaking_point(self, service: str, load_multiplier: float,
                                   performance_metrics: Dict[str, Any],
                                   baseline_metrics: Dict[str, Any]) -> Optional[BreakingPointMeasurement]:
        """Detect if current conditions represent a breaking point"""
        
        # Check for performance cliff
        response_time_ratio = performance_metrics["response_time"] / baseline_metrics.get("response_time", 0.1)
        if response_time_ratio > self.latency_multiplier_threshold:
            return BreakingPointMeasurement(
                breaking_point_type=BreakingPointType.PERFORMANCE_CLIFF,
                service_name=service,
                measurement_timestamp=datetime.now(),
                threshold_value=load_multiplier,
                threshold_unit="load_multiplier",
                confidence_level=0.9,
                system_metrics_at_breaking_point=performance_metrics,
                degradation_pattern="latency_spike",
                failure_mode="response_time_degradation"
            )
        
        # Check for error rate spike
        if performance_metrics["error_rate"] > self.error_rate_threshold:
            return BreakingPointMeasurement(
                breaking_point_type=BreakingPointType.ERROR_RATE_SPIKE,
                service_name=service,
                measurement_timestamp=datetime.now(),
                threshold_value=performance_metrics["error_rate"],
                threshold_unit="error_rate",
                confidence_level=0.95,
                system_metrics_at_breaking_point=performance_metrics,
                degradation_pattern="error_spike",
                failure_mode="service_overload"
            )
        
        # Check for resource exhaustion
        if performance_metrics["cpu_usage"] > 0.95:
            return BreakingPointMeasurement(
                breaking_point_type=BreakingPointType.RESOURCE_EXHAUSTION,
                service_name=service,
                measurement_timestamp=datetime.now(),
                threshold_value=performance_metrics["cpu_usage"],
                threshold_unit="cpu_utilization",
                confidence_level=0.98,
                system_metrics_at_breaking_point=performance_metrics,
                degradation_pattern="resource_saturation",
                failure_mode="cpu_exhaustion"
            )
        
        # Check for throughput ceiling
        throughput_ratio = performance_metrics["throughput"] / baseline_metrics.get("throughput", 100.0)
        if load_multiplier > 2.0 and throughput_ratio < load_multiplier * 0.7:  # Throughput not scaling with load
            return BreakingPointMeasurement(
                breaking_point_type=BreakingPointType.THROUGHPUT_CEILING,
                service_name=service,
                measurement_timestamp=datetime.now(),
                threshold_value=performance_metrics["throughput"],
                threshold_unit="requests_per_second",
                confidence_level=0.85,
                system_metrics_at_breaking_point=performance_metrics,
                degradation_pattern="throughput_plateau",
                failure_mode="capacity_limit"
            )
        
        return None
    
    def _detect_performance_cliffs(self, performance_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect performance cliffs in the data"""
        cliffs = []
        
        if len(performance_data) < 3:
            return cliffs
        
        # Analyze response time cliffs
        response_times = [d["response_time"] for d in performance_data]
        for i in range(1, len(response_times) - 1):
            # Check for sudden increase
            prev_rt = response_times[i-1]
            curr_rt = response_times[i]
            next_rt = response_times[i+1]
            
            # Cliff detected if current response time is significantly higher than previous
            # and trend continues
            if (curr_rt > prev_rt * 1.5 and next_rt > curr_rt * 1.2):
                cliffs.append({
                    "cliff_type": "response_time",
                    "load_point": performance_data[i]["load"],
                    "severity": (curr_rt - prev_rt) / prev_rt,
                    "metric_before": prev_rt,
                    "metric_after": curr_rt
                })
        
        # Analyze throughput cliffs
        throughputs = [d["throughput"] for d in performance_data]
        for i in range(1, len(throughputs) - 1):
            prev_tp = throughputs[i-1]
            curr_tp = throughputs[i]
            next_tp = throughputs[i+1]
            
            # Cliff detected if throughput drops significantly
            if (curr_tp < prev_tp * 0.8 and next_tp < curr_tp * 0.9):
                cliffs.append({
                    "cliff_type": "throughput",
                    "load_point": performance_data[i]["load"],
                    "severity": (prev_tp - curr_tp) / prev_tp,
                    "metric_before": prev_tp,
                    "metric_after": curr_tp
                })
        
        return cliffs
    
    async def _find_resource_exhaustion_point(self, service: str, resource_type: str) -> Dict[str, Any]:
        """Find exhaustion point for specific resource"""
        load_multiplier = 1.0
        
        while load_multiplier <= self.max_load_multiplier:
            performance_metrics = await self._measure_performance_under_load(
                service, load_multiplier, await self._get_baseline_metrics(service)
            )
            
            resource_usage = performance_metrics.get(f"{resource_type}_usage", 0)
            
            # Check if resource is exhausted (>95% usage)
            if resource_usage > 0.95:
                return {
                    "exhaustion_load": load_multiplier,
                    "resource_usage_at_exhaustion": resource_usage,
                    "performance_impact": self._calculate_performance_impact(performance_metrics),
                    "exhaustion_point_reached": True
                }
            
            load_multiplier += 0.5
        
        return {
            "exhaustion_point_reached": False,
            "max_load_tested": load_multiplier,
            "max_resource_usage": performance_metrics.get(f"{resource_type}_usage", 0)
        }
    
    async def _measure_stability_at_load(self, service: str, load_level: float) -> Dict[str, Any]:
        """Measure system stability at specific load level"""
        measurements = []
        measurement_duration = 60  # 60 seconds
        sample_interval = 2  # Every 2 seconds
        
        samples = int(measurement_duration / sample_interval)
        
        for _ in range(samples):
            performance_metrics = await self._measure_performance_under_load(
                service, load_level, await self._get_baseline_metrics(service)
            )
            measurements.append(performance_metrics)
            await asyncio.sleep(sample_interval)
        
        # Calculate stability metrics
        response_times = [m["response_time"] for m in measurements]
        throughputs = [m["throughput"] for m in measurements]
        error_rates = [m["error_rate"] for m in measurements]
        
        stability_score = self._calculate_stability_score(response_times, throughputs, error_rates)
        
        return {
            "stability_score": stability_score,
            "variance_metrics": {
                "response_time_cv": statistics.stdev(response_times) / statistics.mean(response_times) if statistics.mean(response_times) > 0 else 0,
                "throughput_cv": statistics.stdev(throughputs) / statistics.mean(throughputs) if statistics.mean(throughputs) > 0 else 0,
                "error_rate_variance": statistics.variance(error_rates)
            },
            "measurement_duration": measurement_duration,
            "sample_count": len(measurements)
        }
    
    # Analysis helper methods
    def _analyze_capacity_data(self, service: str, performance_data: List[Dict[str, Any]],
                              breaking_points: List[BreakingPointMeasurement]) -> Dict[str, Any]:
        """Analyze capacity data to determine limits and recommendations"""
        if not performance_data:
            return {"error": "No performance data available"}
        
        # Find maximum stable load
        stable_loads = []
        for data_point in performance_data:
            if (data_point["performance_metrics"]["error_rate"] < 0.02 and
                data_point["performance_metrics"]["response_time"] < 1.0):
                stable_loads.append(data_point["load_multiplier"])
        
        max_stable_load = max(stable_loads) if stable_loads else 1.0
        
        # Find maximum throughput
        max_throughput = max(
            [d["performance_metrics"]["throughput"] for d in performance_data],
            default=0.0
        )
        
        # Analyze scaling characteristics
        scaling_analysis = self._analyze_scaling_characteristics(performance_data)
        
        return {
            "max_stable_load": max_stable_load,
            "max_throughput": max_throughput,
            "recommended_limit": max_stable_load * 0.8,  # 80% of max stable
            "scaling_analysis": scaling_analysis,
            "breaking_point_summary": {
                "total_breaking_points": len(breaking_points),
                "critical_breaking_points": len([bp for bp in breaking_points if bp.breaking_point_type in [
                    BreakingPointType.CAPACITY_LIMIT, BreakingPointType.RESOURCE_EXHAUSTION
                ]]),
                "first_breaking_point_load": min([bp.threshold_value for bp in breaking_points], default=0.0)
            }
        }
    
    def _analyze_performance_cliffs(self, cliffs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze detected performance cliffs"""
        if not cliffs:
            return {"cliff_count": 0, "analysis": "No performance cliffs detected"}
        
        cliff_types = {}
        for cliff in cliffs:
            cliff_type = cliff["cliff_type"]
            if cliff_type not in cliff_types:
                cliff_types[cliff_type] = []
            cliff_types[cliff_type].append(cliff)
        
        analysis = {
            "cliff_count": len(cliffs),
            "cliff_types": cliff_types,
            "most_severe_cliff": max(cliffs, key=lambda x: x["severity"]),
            "earliest_cliff_load": min([c["load_point"] for c in cliffs]),
            "cliff_load_distribution": [c["load_point"] for c in cliffs]
        }
        
        return analysis
    
    async def _analyze_resource_interactions(self, service: str, exhaustion_points: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze how resource exhaustion points interact"""
        interactions = {}
        
        # Find resource exhaustion order
        exhaustion_order = []
        for resource, data in exhaustion_points.items():
            if isinstance(data, dict) and data.get("exhaustion_point_reached", False):
                exhaustion_order.append({
                    "resource": resource,
                    "exhaustion_load": data["exhaustion_load"]
                })
        
        exhaustion_order.sort(key=lambda x: x["exhaustion_load"])
        
        interactions["exhaustion_order"] = exhaustion_order
        interactions["bottleneck_resource"] = exhaustion_order[0]["resource"] if exhaustion_order else None
        
        # Analyze resource contention
        if len(exhaustion_order) > 1:
            interactions["resource_contention"] = True
            interactions["contention_analysis"] = "Multiple resources reach exhaustion within similar load ranges"
        else:
            interactions["resource_contention"] = False
        
        return interactions
    
    def _identify_critical_resources(self, exhaustion_points: Dict[str, Any]) -> List[str]:
        """Identify critical resources that limit system capacity"""
        critical_resources = []
        
        for resource, data in exhaustion_points.items():
            if isinstance(data, dict) and data.get("exhaustion_point_reached", False):
                exhaustion_load = data["exhaustion_load"]
                if exhaustion_load < 3.0:  # Resources that exhaust before 3x load are critical
                    critical_resources.append(resource)
        
        return critical_resources
    
    def _analyze_stability_boundaries(self, stability_measurements: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze stability boundaries from measurements"""
        if not stability_measurements:
            return {"error": "No stability measurements available"}
        
        # Find stable operating range
        stable_loads = []
        for measurement in stability_measurements:
            if measurement["stability_score"] > 0.8:  # Stability threshold
                stable_loads.append(measurement["load_level"])
        
        if stable_loads:
            stable_range = (min(stable_loads), max(stable_loads))
        else:
            stable_range = (0.0, 1.0)  # Conservative default
        
        # Find instability regions
        unstable_regions = []
        current_unstable_start = None
        
        for measurement in stability_measurements:
            if measurement["stability_score"] <= 0.8:
                if current_unstable_start is None:
                    current_unstable_start = measurement["load_level"]
            else:
                if current_unstable_start is not None:
                    unstable_regions.append((current_unstable_start, measurement["load_level"]))
                    current_unstable_start = None
        
        return {
            "safe_operating_range": stable_range,
            "unstable_regions": unstable_regions,
            "stability_cliff_load": min([m["load_level"] for m in stability_measurements if m["stability_score"] <= 0.5], default=float('inf')),
            "overall_stability_score": statistics.mean([m["stability_score"] for m in stability_measurements])
        }
    
    async def _analyze_system_wide_breaking_points(self, service_analyses: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze breaking points across the entire system"""
        system_breaking_points = []
        system_capacity_limits = {}
        
        for service, analysis in service_analyses.items():
            if isinstance(analysis, dict) and "error" not in analysis:
                # Extract breaking points
                if hasattr(analysis, 'breaking_points'):
                    system_breaking_points.extend(analysis.breaking_points)
                
                # Extract capacity limits
                if hasattr(analysis, 'max_throughput_rps'):
                    system_capacity_limits[service] = {
                        "max_throughput": analysis.max_throughput_rps,
                        "stable_range": analysis.stable_operating_range,
                        "recommended_limit": analysis.recommended_operating_limit
                    }
        
        # Identify system bottlenecks
        bottleneck_services = []
        if system_capacity_limits:
            min_capacity = min([limits["max_throughput"] for limits in system_capacity_limits.values()])
            bottleneck_services = [
                service for service, limits in system_capacity_limits.items()
                if limits["max_throughput"] == min_capacity
            ]
        
        return {
            "total_breaking_points": len(system_breaking_points),
            "bottleneck_services": bottleneck_services,
            "system_capacity_summary": system_capacity_limits,
            "cascade_failure_risk": self._assess_cascade_failure_risk(system_capacity_limits),
            "system_resilience_score": self._calculate_system_resilience_score(system_capacity_limits)
        }
    
    def _generate_capacity_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate capacity planning recommendations"""
        recommendations = []
        
        for service, analysis in analysis_results.items():
            if isinstance(analysis, dict) and "error" not in analysis:
                if hasattr(analysis, 'recommended_operating_limit'):
                    if analysis.recommended_operating_limit < 2.0:
                        recommendations.append(f"Service {service}: Consider scaling capacity - current limit is {analysis.recommended_operating_limit:.1f}x")
                
                if hasattr(analysis, 'breaking_points'):
                    critical_breaking_points = [
                        bp for bp in analysis.breaking_points 
                        if bp.breaking_point_type in [BreakingPointType.CAPACITY_LIMIT, BreakingPointType.RESOURCE_EXHAUSTION]
                    ]
                    if critical_breaking_points:
                        recommendations.append(f"Service {service}: Address critical breaking points at {len(critical_breaking_points)} load levels")
        
        return recommendations
    
    # Utility methods
    async def _get_baseline_metrics(self, service: str) -> Dict[str, Any]:
        """Get baseline performance metrics for service"""
        return {
            "response_time": 0.1,
            "throughput": 100.0,
            "error_rate": 0.01,
            "cpu_usage": 0.3,
            "memory_usage": 0.4
        }
    
    def _calculate_performance_impact(self, performance_metrics: Dict[str, Any]) -> float:
        """Calculate overall performance impact score"""
        # Weighted impact based on multiple metrics
        response_time_impact = min(1.0, performance_metrics.get("response_time", 0) / 5.0)  # Normalize to 5 seconds
        error_rate_impact = min(1.0, performance_metrics.get("error_rate", 0) / 0.1)  # Normalize to 10%
        
        overall_impact = (response_time_impact * 0.6 + error_rate_impact * 0.4)
        return overall_impact
    
    def _calculate_stability_score(self, response_times: List[float], throughputs: List[float], error_rates: List[float]) -> float:
        """Calculate stability score based on metric variance"""
        if not response_times or not throughputs:
            return 0.0
        
        # Calculate coefficients of variation
        rt_cv = statistics.stdev(response_times) / statistics.mean(response_times) if statistics.mean(response_times) > 0 else 1.0
        tp_cv = statistics.stdev(throughputs) / statistics.mean(throughputs) if statistics.mean(throughputs) > 0 else 1.0
        er_variance = statistics.variance(error_rates) if len(error_rates) > 1 else 0.0
        
        # Stability score (lower variance = higher stability)
        stability_score = max(0, 1.0 - (rt_cv + tp_cv + er_variance) / 3)
        return stability_score
    
    def _analyze_scaling_characteristics(self, performance_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze how the system scales with load"""
        if len(performance_data) < 3:
            return {"error": "Insufficient data for scaling analysis"}
        
        loads = [d["load_multiplier"] for d in performance_data]
        throughputs = [d["performance_metrics"]["throughput"] for d in performance_data]
        
        # Linear scaling analysis
        linear_correlation = self._calculate_correlation(loads, throughputs)
        
        # Find scaling breakpoint
        scaling_efficiency = []
        for i in range(1, len(performance_data)):
            prev_load = loads[i-1]
            curr_load = loads[i]
            prev_throughput = throughputs[i-1]
            curr_throughput = throughputs[i]
            
            load_increase = curr_load - prev_load
            throughput_increase = curr_throughput - prev_throughput
            
            if load_increase > 0:
                efficiency = throughput_increase / load_increase
                scaling_efficiency.append(efficiency)
        
        return {
            "linear_correlation": linear_correlation,
            "scaling_efficiency": scaling_efficiency,
            "avg_scaling_efficiency": statistics.mean(scaling_efficiency) if scaling_efficiency else 0,
            "scaling_degradation_point": self._find_scaling_degradation_point(loads, scaling_efficiency)
        }
    
    def _calculate_correlation(self, x_values: List[float], y_values: List[float]) -> float:
        """Calculate correlation coefficient between two lists"""
        if len(x_values) != len(y_values) or len(x_values) < 2:
            return 0.0
        
        n = len(x_values)
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(y_values)
        
        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, y_values))
        x_var = sum((x - x_mean) ** 2 for x in x_values)
        y_var = sum((y - y_mean) ** 2 for y in y_values)
        
        if x_var == 0 or y_var == 0:
            return 0.0
        
        correlation = numerator / math.sqrt(x_var * y_var)
        return correlation
    
    def _find_scaling_degradation_point(self, loads: List[float], efficiencies: List[float]) -> Optional[float]:
        """Find the load point where scaling efficiency starts to degrade"""
        if len(efficiencies) < 3:
            return None
        
        # Find point where efficiency drops significantly
        for i in range(2, len(efficiencies)):
            if efficiencies[i] < efficiencies[0] * 0.5:  # 50% of initial efficiency
                return loads[i] if i < len(loads) else None
        
        return None
    
    def _assess_cascade_failure_risk(self, capacity_limits: Dict[str, Any]) -> float:
        """Assess risk of cascade failures based on capacity limits"""
        if not capacity_limits:
            return 0.0
        
        # Check if services have similar capacity limits (risk of simultaneous failure)
        throughputs = [limits["max_throughput"] for limits in capacity_limits.values()]
        
        if len(throughputs) < 2:
            return 0.0
        
        # High risk if throughputs are very similar (low variance)
        throughput_cv = statistics.stdev(throughputs) / statistics.mean(throughputs) if statistics.mean(throughputs) > 0 else 1.0
        cascade_risk = max(0, 1.0 - throughput_cv * 2)  # High CV = low risk
        
        return cascade_risk
    
    def _calculate_system_resilience_score(self, capacity_limits: Dict[str, Any]) -> float:
        """Calculate overall system resilience score"""
        if not capacity_limits:
            return 0.0
        
        # Base score on minimum capacity and range diversity
        min_capacity = min([limits["max_throughput"] for limits in capacity_limits.values()])
        avg_capacity = statistics.mean([limits["max_throughput"] for limits in capacity_limits.values()])
        
        # Resilience is higher when minimum capacity is closer to average (less variation)
        capacity_ratio = min_capacity / avg_capacity if avg_capacity > 0 else 0
        
        # Factor in safety margins
        avg_safety_margin = statistics.mean([
            limits["recommended_limit"] / limits["max_throughput"] 
            for limits in capacity_limits.values() 
            if limits["max_throughput"] > 0
        ])
        
        resilience_score = (capacity_ratio * 0.6 + avg_safety_margin * 0.4)
        return min(1.0, max(0.0, resilience_score))