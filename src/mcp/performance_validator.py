"""
MCP Performance Validation and Reporting System
Agent 7: Comprehensive validation and reporting for MCP performance optimizations.

This module validates the effectiveness of performance optimizations and generates
detailed reports on improvements, bottlenecks, and recommendations.
"""

import asyncio
import time
import logging
import json
import os
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
import statistics
from enum import Enum

from .performance import MCPPerformanceOptimizer, PerformanceConfig, PerformanceMetrics
from .performance_monitor import MCPPerformanceMonitor, Alert, AlertLevel
from .scaling_advisor import MCPScalingAdvisor, ScalingRecommendation
from .startup_optimizer import MCPStartupOptimizer, StartupConfig
from .connection_optimizer import MCPConnectionManager, MCPConnectionConfig
from ..core.mcp_cache import get_mcp_cache
from ..monitoring.metrics import get_metrics_collector

logger = logging.getLogger(__name__)


class ValidationResult(Enum):
    """Validation test results."""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIP = "skip"


class TestCategory(Enum):
    """Performance test categories."""
    CACHING = "caching"
    CONNECTION_POOLING = "connection_pooling"
    STARTUP_OPTIMIZATION = "startup_optimization"
    MONITORING = "monitoring"
    SCALING = "scaling"
    RESOURCE_USAGE = "resource_usage"
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    ERROR_HANDLING = "error_handling"


@dataclass
class ValidationTest:
    """Individual validation test."""
    name: str
    category: TestCategory
    description: str
    result: ValidationResult
    expected_value: Optional[float] = None
    actual_value: Optional[float] = None
    improvement_percent: Optional[float] = None
    details: str = ""
    recommendations: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "result": self.result.value,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "improvement_percent": self.improvement_percent,
            "details": self.details,
            "recommendations": self.recommendations,
            "execution_time_ms": self.execution_time_ms
        }


@dataclass
class PerformanceBaseline:
    """Performance baseline for comparison."""
    timestamp: datetime
    avg_response_time_ms: float
    p95_response_time_ms: float
    throughput_rps: float
    error_rate: float
    cpu_usage_percent: float
    memory_usage_mb: float
    cache_hit_rate: float
    startup_time_ms: float
    active_connections: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "avg_response_time_ms": self.avg_response_time_ms,
            "p95_response_time_ms": self.p95_response_time_ms,
            "throughput_rps": self.throughput_rps,
            "error_rate": self.error_rate,
            "cpu_usage_percent": self.cpu_usage_percent,
            "memory_usage_mb": self.memory_usage_mb,
            "cache_hit_rate": self.cache_hit_rate,
            "startup_time_ms": self.startup_time_ms,
            "active_connections": self.active_connections
        }


@dataclass
class OptimizationImpact:
    """Impact analysis of optimizations."""
    optimization_name: str
    baseline_value: float
    optimized_value: float
    improvement_percent: float
    metric_name: str
    confidence: float
    impact_category: str  # high, medium, low
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "optimization_name": self.optimization_name,
            "baseline_value": self.baseline_value,
            "optimized_value": self.optimized_value,
            "improvement_percent": self.improvement_percent,
            "metric_name": self.metric_name,
            "confidence": self.confidence,
            "impact_category": self.impact_category
        }


class MCPPerformanceValidator:
    """
    Comprehensive performance validation system for MCP optimizations.
    
    Features:
    - Pre/post optimization comparison
    - Automated performance testing
    - Regression detection
    - Optimization impact analysis
    - Comprehensive reporting
    """
    
    def __init__(self):
        # Performance components
        self.performance_optimizer: Optional[MCPPerformanceOptimizer] = None
        self.performance_monitor: Optional[MCPPerformanceMonitor] = None
        self.scaling_advisor: Optional[MCPScalingAdvisor] = None
        self.startup_optimizer: Optional[MCPStartupOptimizer] = None
        self.connection_manager: Optional[MCPConnectionManager] = None
        
        # Validation state
        self.baseline: Optional[PerformanceBaseline] = None
        self.validation_tests: List[ValidationTest] = []
        self.optimization_impacts: List[OptimizationImpact] = []
        
        # Test configuration
        self.test_config = {
            "cache_hit_rate_threshold": 0.3,
            "response_time_improvement_threshold": 0.15,
            "throughput_improvement_threshold": 0.10,
            "startup_time_threshold_ms": 10000,
            "error_rate_threshold": 0.05,
            "cpu_usage_threshold": 80.0,
            "memory_usage_threshold": 85.0
        }
    
    async def initialize(self):
        """Initialize the validator with performance components."""
        logger.info("Initializing MCP Performance Validator")
        
        # Initialize performance components
        try:
            from .performance import get_performance_optimizer
            self.performance_optimizer = await get_performance_optimizer()
        except Exception as e:
            logger.warning(f"Performance optimizer not available: {e}")
        
        try:
            from .performance_monitor import get_performance_monitor
            self.performance_monitor = await get_performance_monitor()
        except Exception as e:
            logger.warning(f"Performance monitor not available: {e}")
        
        try:
            if self.performance_monitor:
                self.scaling_advisor = MCPScalingAdvisor(self.performance_monitor)
                await self.scaling_advisor.initialize()
        except Exception as e:
            logger.warning(f"Scaling advisor not available: {e}")
        
        try:
            self.startup_optimizer = MCPStartupOptimizer()
            await self.startup_optimizer.initialize()
        except Exception as e:
            logger.warning(f"Startup optimizer not available: {e}")
        
        try:
            from .connection_optimizer import get_mcp_connection_manager
            self.connection_manager = await get_mcp_connection_manager()
        except Exception as e:
            logger.warning(f"Connection manager not available: {e}")
        
        logger.info("MCP Performance Validator initialized")
    
    async def capture_baseline(self) -> PerformanceBaseline:
        """Capture performance baseline before optimizations."""
        logger.info("Capturing performance baseline")
        
        # Simulate some load to get meaningful metrics
        await self._simulate_baseline_load()
        
        # Collect baseline metrics
        baseline_metrics = await self._collect_current_metrics()
        
        self.baseline = PerformanceBaseline(
            timestamp=datetime.now(),
            **baseline_metrics
        )
        
        logger.info(f"Baseline captured: avg_response_time={self.baseline.avg_response_time_ms:.2f}ms, "
                   f"throughput={self.baseline.throughput_rps:.2f}rps")
        
        return self.baseline
    
    async def _simulate_baseline_load(self):
        """Simulate load to generate baseline metrics."""
        if not self.performance_optimizer:
            return
        
        logger.info("Simulating baseline load...")
        
        # Simulate various MCP operations
        test_operations = [
            ("brave", "brave_web_search", {"query": "test query", "count": 5}),
            ("docker", "docker_ps", {}),
            ("kubernetes", "kubectl_version", {}),
            ("security-scanner", "file_security_scan", {"file_path": "test.py"}),
        ]
        
        for _ in range(10):  # Multiple iterations for stable metrics
            for server, tool, args in test_operations:
                try:
                    await self.performance_optimizer.optimize_tool_call(
                        server, tool, args
                    )
                except Exception as e:
                    logger.debug(f"Baseline simulation error for {server}.{tool}: {e}")
            
            await asyncio.sleep(0.5)  # Small delay between iterations
    
    async def _collect_current_metrics(self) -> Dict[str, float]:
        """Collect current performance metrics."""
        metrics = {
            "avg_response_time_ms": 0.0,
            "p95_response_time_ms": 0.0,
            "throughput_rps": 0.0,
            "error_rate": 0.0,
            "cpu_usage_percent": 0.0,
            "memory_usage_mb": 0.0,
            "cache_hit_rate": 0.0,
            "startup_time_ms": 0.0,
            "active_connections": 0
        }
        
        # Get performance metrics
        if self.performance_optimizer:
            perf_report = self.performance_optimizer.get_performance_report()
            
            summary = perf_report.get("summary", {})
            metrics["avg_response_time_ms"] = float(summary.get("avg_response_time_ms", "0.0"))
            metrics["throughput_rps"] = float(summary.get("throughput_rps", "0.0"))
            metrics["error_rate"] = float(summary.get("error_rate", "0.0"))
            
            response_times = perf_report.get("response_times", {})
            metrics["p95_response_time_ms"] = response_times.get("p95_ms", 0.0)
            
            caching = perf_report.get("caching", {})
            metrics["cache_hit_rate"] = caching.get("hit_rate", 0.0)
            
            # System metrics
            import psutil
            metrics["cpu_usage_percent"] = psutil.cpu_percent(interval=0.1)
            metrics["memory_usage_mb"] = psutil.virtual_memory().used / 1024 / 1024
        
        # Connection metrics
        if self.connection_manager:
            conn_metrics = self.connection_manager.get_all_metrics()
            total_active = sum(
                pool_data.get("pool_metrics", {}).get("active_connections", 0)
                for pool_data in conn_metrics.values()
            )
            metrics["active_connections"] = total_active
        
        # Startup metrics
        if self.startup_optimizer:
            startup_report = self.startup_optimizer.get_optimization_report()
            startup_metrics = startup_report.get("metrics", {})
            metrics["startup_time_ms"] = startup_metrics.get("total_startup_time", 0.0) * 1000
        
        return metrics
    
    async def run_validation_tests(self) -> List[ValidationTest]:
        """Run comprehensive validation tests."""
        logger.info("Running MCP performance validation tests")
        
        self.validation_tests = []
        
        # Run different categories of tests
        await self._test_caching_performance()
        await self._test_connection_pooling()
        await self._test_startup_optimization()
        await self._test_monitoring_effectiveness()
        await self._test_scaling_recommendations()
        await self._test_resource_usage()
        await self._test_latency_improvements()
        await self._test_throughput_improvements()
        await self._test_error_handling()
        
        # Calculate overall validation results
        total_tests = len(self.validation_tests)
        passed_tests = len([t for t in self.validation_tests if t.result == ValidationResult.PASS])
        
        logger.info(f"Validation completed: {passed_tests}/{total_tests} tests passed")
        
        return self.validation_tests
    
    async def _test_caching_performance(self):
        """Test caching effectiveness."""
        start_time = time.time()
        
        try:
            cache = await get_mcp_cache()
            cache_stats = cache.get_stats()
            
            hit_rate = cache_stats.get("hit_rate", 0.0)
            expected_hit_rate = self.test_config["cache_hit_rate_threshold"]
            
            if hit_rate >= expected_hit_rate:
                result = ValidationResult.PASS
                details = f"Cache hit rate ({hit_rate:.2%}) meets threshold ({expected_hit_rate:.2%})"
                recommendations = []
            elif hit_rate > 0:
                result = ValidationResult.WARNING
                details = f"Cache hit rate ({hit_rate:.2%}) below threshold ({expected_hit_rate:.2%})"
                recommendations = ["Increase cache TTL", "Optimize cache key strategies"]
            else:
                result = ValidationResult.FAIL
                details = "Caching system not operational"
                recommendations = ["Enable caching", "Configure cache properly"]
            
            test = ValidationTest(
                name="Cache Hit Rate",
                category=TestCategory.CACHING,
                description="Validate caching effectiveness through hit rate analysis",
                result=result,
                expected_value=expected_hit_rate,
                actual_value=hit_rate,
                details=details,
                recommendations=recommendations,
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            test = ValidationTest(
                name="Cache Hit Rate",
                category=TestCategory.CACHING,
                description="Validate caching effectiveness through hit rate analysis",
                result=ValidationResult.FAIL,
                details=f"Cache test failed: {e}",
                recommendations=["Check cache configuration", "Ensure cache is properly initialized"],
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        self.validation_tests.append(test)
    
    async def _test_connection_pooling(self):
        """Test connection pooling effectiveness."""
        start_time = time.time()
        
        try:
            if not self.connection_manager:
                test = ValidationTest(
                    name="Connection Pooling",
                    category=TestCategory.CONNECTION_POOLING,
                    description="Validate connection pooling is active and effective",
                    result=ValidationResult.SKIP,
                    details="Connection manager not available",
                    recommendations=["Initialize connection manager"],
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            else:
                metrics = self.connection_manager.get_all_metrics()
                
                if metrics:
                    # Check if pools are being utilized
                    total_pools = len(metrics)
                    active_pools = sum(1 for pool_data in metrics.values() 
                                     if pool_data.get("pool_metrics", {}).get("active_connections", 0) > 0)
                    
                    if active_pools > 0:
                        result = ValidationResult.PASS
                        details = f"Connection pooling active ({active_pools}/{total_pools} pools utilized)"
                        recommendations = []
                    else:
                        result = ValidationResult.WARNING
                        details = "Connection pools configured but not actively used"
                        recommendations = ["Check if connections are being made through pools"]
                else:
                    result = ValidationResult.FAIL
                    details = "No connection pools configured"
                    recommendations = ["Configure connection pools for MCP servers"]
                
                test = ValidationTest(
                    name="Connection Pooling",
                    category=TestCategory.CONNECTION_POOLING,
                    description="Validate connection pooling is active and effective",
                    result=result,
                    actual_value=float(active_pools),
                    details=details,
                    recommendations=recommendations,
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            
        except Exception as e:
            test = ValidationTest(
                name="Connection Pooling",
                category=TestCategory.CONNECTION_POOLING,
                description="Validate connection pooling is active and effective",
                result=ValidationResult.FAIL,
                details=f"Connection pooling test failed: {e}",
                recommendations=["Check connection manager configuration"],
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        self.validation_tests.append(test)
    
    async def _test_startup_optimization(self):
        """Test startup optimization effectiveness."""
        start_time = time.time()
        
        try:
            if not self.startup_optimizer:
                test = ValidationTest(
                    name="Startup Optimization",
                    category=TestCategory.STARTUP_OPTIMIZATION,
                    description="Validate startup time optimization",
                    result=ValidationResult.SKIP,
                    details="Startup optimizer not available",
                    recommendations=["Initialize startup optimizer"],
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            else:
                report = self.startup_optimizer.get_optimization_report()
                startup_time_ms = report.get("metrics", {}).get("total_startup_time", 0) * 1000
                threshold_ms = self.test_config["startup_time_threshold_ms"]
                
                if startup_time_ms <= threshold_ms:
                    result = ValidationResult.PASS
                    details = f"Startup time ({startup_time_ms:.0f}ms) within threshold ({threshold_ms}ms)"
                    recommendations = []
                elif startup_time_ms <= threshold_ms * 1.5:
                    result = ValidationResult.WARNING
                    details = f"Startup time ({startup_time_ms:.0f}ms) above threshold ({threshold_ms}ms)"
                    recommendations = ["Optimize slow-starting servers", "Consider lazy initialization"]
                else:
                    result = ValidationResult.FAIL
                    details = f"Startup time ({startup_time_ms:.0f}ms) significantly above threshold"
                    recommendations = ["Implement parallel startup", "Profile startup bottlenecks"]
                
                test = ValidationTest(
                    name="Startup Optimization",
                    category=TestCategory.STARTUP_OPTIMIZATION,
                    description="Validate startup time optimization",
                    result=result,
                    expected_value=float(threshold_ms),
                    actual_value=startup_time_ms,
                    details=details,
                    recommendations=recommendations,
                    execution_time_ms=(time.time() - start_time) * 1000
                )
        
        except Exception as e:
            test = ValidationTest(
                name="Startup Optimization",
                category=TestCategory.STARTUP_OPTIMIZATION,
                description="Validate startup time optimization",
                result=ValidationResult.FAIL,
                details=f"Startup optimization test failed: {e}",
                recommendations=["Check startup optimizer configuration"],
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        self.validation_tests.append(test)
    
    async def _test_monitoring_effectiveness(self):
        """Test monitoring system effectiveness."""
        start_time = time.time()
        
        try:
            if not self.performance_monitor:
                test = ValidationTest(
                    name="Performance Monitoring",
                    category=TestCategory.MONITORING,
                    description="Validate performance monitoring is collecting metrics",
                    result=ValidationResult.SKIP,
                    details="Performance monitor not available",
                    recommendations=["Initialize performance monitor"],
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            else:
                summary = self.performance_monitor.get_performance_summary()
                
                operations_count = len(summary.get("operations", {}))
                alerts_count = len(summary.get("alerts", []))
                
                if operations_count > 0:
                    result = ValidationResult.PASS
                    details = f"Monitoring active ({operations_count} operations tracked, {alerts_count} alerts)"
                    recommendations = []
                else:
                    result = ValidationResult.WARNING
                    details = "Monitoring configured but no operations tracked"
                    recommendations = ["Ensure MCP operations are being monitored"]
                
                test = ValidationTest(
                    name="Performance Monitoring",
                    category=TestCategory.MONITORING,
                    description="Validate performance monitoring is collecting metrics",
                    result=result,
                    actual_value=float(operations_count),
                    details=details,
                    recommendations=recommendations,
                    execution_time_ms=(time.time() - start_time) * 1000
                )
        
        except Exception as e:
            test = ValidationTest(
                name="Performance Monitoring",
                category=TestCategory.MONITORING,
                description="Validate performance monitoring is collecting metrics",
                result=ValidationResult.FAIL,
                details=f"Monitoring test failed: {e}",
                recommendations=["Check performance monitor configuration"],
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        self.validation_tests.append(test)
    
    async def _test_scaling_recommendations(self):
        """Test scaling advisor functionality."""
        start_time = time.time()
        
        try:
            if not self.scaling_advisor:
                test = ValidationTest(
                    name="Scaling Recommendations",
                    category=TestCategory.SCALING,
                    description="Validate scaling advisor is providing recommendations",
                    result=ValidationResult.SKIP,
                    details="Scaling advisor not available",
                    recommendations=["Initialize scaling advisor"],
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            else:
                recommendations = self.scaling_advisor.get_scaling_recommendations()
                report = self.scaling_advisor.generate_scaling_report()
                
                if report:
                    result = ValidationResult.PASS
                    details = f"Scaling analysis active ({len(recommendations)} recommendations generated)"
                    recommendations_list = []
                else:
                    result = ValidationResult.WARNING
                    details = "Scaling advisor configured but no analysis available"
                    recommendations_list = ["Allow time for data collection", "Check metric collection"]
                
                test = ValidationTest(
                    name="Scaling Recommendations",
                    category=TestCategory.SCALING,
                    description="Validate scaling advisor is providing recommendations",
                    result=result,
                    actual_value=float(len(recommendations)),
                    details=details,
                    recommendations=recommendations_list,
                    execution_time_ms=(time.time() - start_time) * 1000
                )
        
        except Exception as e:
            test = ValidationTest(
                name="Scaling Recommendations",
                category=TestCategory.SCALING,
                description="Validate scaling advisor is providing recommendations",
                result=ValidationResult.FAIL,
                details=f"Scaling test failed: {e}",
                recommendations=["Check scaling advisor configuration"],
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        self.validation_tests.append(test)
    
    async def _test_resource_usage(self):
        """Test resource usage optimization."""
        start_time = time.time()
        
        try:
            import psutil
            
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent
            
            cpu_threshold = self.test_config["cpu_usage_threshold"]
            memory_threshold = self.test_config["memory_usage_threshold"]
            
            issues = []
            if cpu_percent > cpu_threshold:
                issues.append(f"High CPU usage: {cpu_percent:.1f}%")
            if memory_percent > memory_threshold:
                issues.append(f"High memory usage: {memory_percent:.1f}%")
            
            if not issues:
                result = ValidationResult.PASS
                details = f"Resource usage within limits (CPU: {cpu_percent:.1f}%, Memory: {memory_percent:.1f}%)"
                recommendations = []
            else:
                result = ValidationResult.WARNING
                details = f"Resource usage concerns: {', '.join(issues)}"
                recommendations = ["Monitor resource usage trends", "Consider scaling if sustained"]
            
            test = ValidationTest(
                name="Resource Usage",
                category=TestCategory.RESOURCE_USAGE,
                description="Validate system resource usage is optimized",
                result=result,
                actual_value=max(cpu_percent, memory_percent),
                details=details,
                recommendations=recommendations,
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        except Exception as e:
            test = ValidationTest(
                name="Resource Usage",
                category=TestCategory.RESOURCE_USAGE,
                description="Validate system resource usage is optimized",
                result=ValidationResult.FAIL,
                details=f"Resource usage test failed: {e}",
                recommendations=["Check system monitoring"],
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        self.validation_tests.append(test)
    
    async def _test_latency_improvements(self):
        """Test latency improvements against baseline."""
        start_time = time.time()
        
        try:
            current_metrics = await self._collect_current_metrics()
            current_latency = current_metrics["avg_response_time_ms"]
            
            if self.baseline:
                baseline_latency = self.baseline.avg_response_time_ms
                improvement_threshold = self.test_config["response_time_improvement_threshold"]
                
                if baseline_latency > 0:
                    improvement = (baseline_latency - current_latency) / baseline_latency
                    
                    if improvement >= improvement_threshold:
                        result = ValidationResult.PASS
                        details = f"Latency improved by {improvement:.2%} ({baseline_latency:.1f}ms → {current_latency:.1f}ms)"
                        recommendations = []
                    elif improvement > 0:
                        result = ValidationResult.WARNING
                        details = f"Minor latency improvement {improvement:.2%} (target: {improvement_threshold:.2%})"
                        recommendations = ["Further optimize slow operations", "Review caching strategies"]
                    else:
                        result = ValidationResult.FAIL
                        details = f"Latency regression detected: {abs(improvement):.2%} slower"
                        recommendations = ["Investigate performance regression", "Review recent changes"]
                else:
                    result = ValidationResult.WARNING
                    details = "No baseline latency data for comparison"
                    recommendations = ["Capture baseline for future comparisons"]
            else:
                result = ValidationResult.WARNING
                details = f"Current latency: {current_latency:.1f}ms (no baseline for comparison)"
                recommendations = ["Capture baseline for performance tracking"]
            
            test = ValidationTest(
                name="Latency Improvements",
                category=TestCategory.LATENCY,
                description="Validate response time improvements against baseline",
                result=result,
                actual_value=current_latency,
                improvement_percent=improvement if self.baseline and baseline_latency > 0 else None,
                details=details,
                recommendations=recommendations,
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        except Exception as e:
            test = ValidationTest(
                name="Latency Improvements",
                category=TestCategory.LATENCY,
                description="Validate response time improvements against baseline",
                result=ValidationResult.FAIL,
                details=f"Latency test failed: {e}",
                recommendations=["Check performance metrics collection"],
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        self.validation_tests.append(test)
    
    async def _test_throughput_improvements(self):
        """Test throughput improvements against baseline."""
        start_time = time.time()
        
        try:
            current_metrics = await self._collect_current_metrics()
            current_throughput = current_metrics["throughput_rps"]
            
            if self.baseline:
                baseline_throughput = self.baseline.throughput_rps
                improvement_threshold = self.test_config["throughput_improvement_threshold"]
                
                if baseline_throughput > 0:
                    improvement = (current_throughput - baseline_throughput) / baseline_throughput
                    
                    if improvement >= improvement_threshold:
                        result = ValidationResult.PASS
                        details = f"Throughput improved by {improvement:.2%} ({baseline_throughput:.1f} → {current_throughput:.1f} RPS)"
                        recommendations = []
                    elif improvement > 0:
                        result = ValidationResult.WARNING
                        details = f"Minor throughput improvement {improvement:.2%} (target: {improvement_threshold:.2%})"
                        recommendations = ["Optimize request processing", "Consider connection pooling"]
                    else:
                        result = ValidationResult.FAIL
                        details = f"Throughput regression detected: {abs(improvement):.2%} lower"
                        recommendations = ["Investigate throughput bottlenecks", "Check resource constraints"]
                else:
                    result = ValidationResult.WARNING
                    details = "No baseline throughput data for comparison"
                    recommendations = ["Generate load for meaningful throughput measurements"]
            else:
                result = ValidationResult.WARNING
                details = f"Current throughput: {current_throughput:.1f} RPS (no baseline for comparison)"
                recommendations = ["Capture baseline under load"]
            
            test = ValidationTest(
                name="Throughput Improvements",
                category=TestCategory.THROUGHPUT,
                description="Validate throughput improvements against baseline",
                result=result,
                actual_value=current_throughput,
                improvement_percent=improvement if self.baseline and baseline_throughput > 0 else None,
                details=details,
                recommendations=recommendations,
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        except Exception as e:
            test = ValidationTest(
                name="Throughput Improvements",
                category=TestCategory.THROUGHPUT,
                description="Validate throughput improvements against baseline",
                result=ValidationResult.FAIL,
                details=f"Throughput test failed: {e}",
                recommendations=["Check throughput metrics collection"],
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        self.validation_tests.append(test)
    
    async def _test_error_handling(self):
        """Test error handling and recovery."""
        start_time = time.time()
        
        try:
            current_metrics = await self._collect_current_metrics()
            error_rate = current_metrics["error_rate"]
            threshold = self.test_config["error_rate_threshold"]
            
            if error_rate <= threshold:
                result = ValidationResult.PASS
                details = f"Error rate ({error_rate:.2%}) within acceptable threshold ({threshold:.2%})"
                recommendations = []
            elif error_rate <= threshold * 2:
                result = ValidationResult.WARNING
                details = f"Error rate ({error_rate:.2%}) above threshold ({threshold:.2%})"
                recommendations = ["Monitor error patterns", "Review error handling logic"]
            else:
                result = ValidationResult.FAIL
                details = f"High error rate detected: {error_rate:.2%}"
                recommendations = ["Investigate error causes", "Improve error handling", "Check service health"]
            
            test = ValidationTest(
                name="Error Handling",
                category=TestCategory.ERROR_HANDLING,
                description="Validate error rates are within acceptable limits",
                result=result,
                expected_value=threshold,
                actual_value=error_rate,
                details=details,
                recommendations=recommendations,
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        except Exception as e:
            test = ValidationTest(
                name="Error Handling",
                category=TestCategory.ERROR_HANDLING,
                description="Validate error rates are within acceptable limits",
                result=ValidationResult.FAIL,
                details=f"Error handling test failed: {e}",
                recommendations=["Check error rate metrics collection"],
                execution_time_ms=(time.time() - start_time) * 1000
            )
        
        self.validation_tests.append(test)
    
    def analyze_optimization_impacts(self) -> List[OptimizationImpact]:
        """Analyze the impact of optimizations."""
        if not self.baseline:
            return []
        
        current_metrics = asyncio.create_task(self._collect_current_metrics())
        current = current_metrics.result() if current_metrics.done() else {}
        
        impacts = []
        
        # Analyze each metric
        metric_comparisons = [
            ("avg_response_time_ms", "Response Time", "ms", False),  # Lower is better
            ("throughput_rps", "Throughput", "RPS", True),  # Higher is better
            ("cache_hit_rate", "Cache Hit Rate", "%", True),  # Higher is better
            ("error_rate", "Error Rate", "%", False),  # Lower is better
            ("startup_time_ms", "Startup Time", "ms", False),  # Lower is better
        ]
        
        for metric_key, metric_name, unit, higher_is_better in metric_comparisons:
            baseline_value = getattr(self.baseline, metric_key, 0)
            current_value = current.get(metric_key, 0)
            
            if baseline_value > 0:
                if higher_is_better:
                    improvement = (current_value - baseline_value) / baseline_value
                else:
                    improvement = (baseline_value - current_value) / baseline_value
                
                improvement_percent = improvement * 100
                
                # Determine impact category
                if abs(improvement_percent) >= 20:
                    impact_category = "high"
                elif abs(improvement_percent) >= 10:
                    impact_category = "medium"
                else:
                    impact_category = "low"
                
                # Determine confidence based on magnitude of change
                confidence = min(0.95, abs(improvement_percent) / 50 + 0.5)
                
                impact = OptimizationImpact(
                    optimization_name=f"{metric_name} Optimization",
                    baseline_value=baseline_value,
                    optimized_value=current_value,
                    improvement_percent=improvement_percent,
                    metric_name=metric_name,
                    confidence=confidence,
                    impact_category=impact_category
                )
                
                impacts.append(impact)
        
        self.optimization_impacts = impacts
        return impacts
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance validation report."""
        current_time = datetime.now()
        
        # Analyze optimization impacts
        impacts = self.analyze_optimization_impacts()
        
        # Calculate test results summary
        test_summary = {
            "total_tests": len(self.validation_tests),
            "passed": len([t for t in self.validation_tests if t.result == ValidationResult.PASS]),
            "warnings": len([t for t in self.validation_tests if t.result == ValidationResult.WARNING]),
            "failed": len([t for t in self.validation_tests if t.result == ValidationResult.FAIL]),
            "skipped": len([t for t in self.validation_tests if t.result == ValidationResult.SKIP])
        }
        
        test_summary["pass_rate"] = (test_summary["passed"] / max(test_summary["total_tests"], 1)) * 100
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(test_summary, impacts)
        
        # Organize tests by category
        tests_by_category = {}
        for test in self.validation_tests:
            category = test.category.value
            if category not in tests_by_category:
                tests_by_category[category] = []
            tests_by_category[category].append(test.to_dict())
        
        report = {
            "timestamp": current_time.isoformat(),
            "report_version": "1.0",
            "executive_summary": executive_summary,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "test_summary": test_summary,
            "validation_tests": tests_by_category,
            "optimization_impacts": [impact.to_dict() for impact in impacts],
            "recommendations": self._generate_overall_recommendations(),
            "performance_trends": self._analyze_performance_trends(),
            "next_steps": self._suggest_next_steps()
        }
        
        return report
    
    def _generate_executive_summary(
        self,
        test_summary: Dict[str, Any],
        impacts: List[OptimizationImpact]
    ) -> Dict[str, Any]:
        """Generate executive summary of validation results."""
        # Calculate overall optimization success
        high_impact_optimizations = len([i for i in impacts if i.impact_category == "high"])
        positive_improvements = len([i for i in impacts if i.improvement_percent > 0])
        
        # Determine overall status
        if test_summary["pass_rate"] >= 80 and positive_improvements >= len(impacts) * 0.7:
            overall_status = "Excellent"
        elif test_summary["pass_rate"] >= 60 and positive_improvements >= len(impacts) * 0.5:
            overall_status = "Good"
        elif test_summary["pass_rate"] >= 40:
            overall_status = "Fair"
        else:
            overall_status = "Poor"
        
        return {
            "overall_status": overall_status,
            "optimization_effectiveness": f"{positive_improvements}/{len(impacts)} optimizations showed improvement",
            "test_pass_rate": f"{test_summary['pass_rate']:.1f}%",
            "high_impact_optimizations": high_impact_optimizations,
            "critical_issues": test_summary["failed"],
            "key_achievements": self._identify_key_achievements(impacts),
            "primary_concerns": self._identify_primary_concerns()
        }
    
    def _identify_key_achievements(self, impacts: List[OptimizationImpact]) -> List[str]:
        """Identify key optimization achievements."""
        achievements = []
        
        for impact in impacts:
            if impact.improvement_percent > 20 and impact.confidence > 0.7:
                achievements.append(
                    f"{impact.metric_name} improved by {impact.improvement_percent:.1f}%"
                )
        
        # Add general achievements
        passed_tests = len([t for t in self.validation_tests if t.result == ValidationResult.PASS])
        if passed_tests > 0:
            achievements.append(f"{passed_tests} validation tests passed successfully")
        
        return achievements[:5]  # Top 5 achievements
    
    def _identify_primary_concerns(self) -> List[str]:
        """Identify primary concerns from validation."""
        concerns = []
        
        # Failed tests
        failed_tests = [t for t in self.validation_tests if t.result == ValidationResult.FAIL]
        for test in failed_tests[:3]:  # Top 3 concerns
            concerns.append(f"{test.name}: {test.details}")
        
        # Negative impacts
        negative_impacts = [i for i in self.optimization_impacts if i.improvement_percent < -10]
        for impact in negative_impacts[:2]:  # Top 2 regression concerns
            concerns.append(f"{impact.metric_name} regression: {abs(impact.improvement_percent):.1f}% worse")
        
        return concerns
    
    def _generate_overall_recommendations(self) -> List[str]:
        """Generate overall recommendations based on validation results."""
        recommendations = set()
        
        # Collect recommendations from failed/warning tests
        for test in self.validation_tests:
            if test.result in [ValidationResult.FAIL, ValidationResult.WARNING]:
                recommendations.update(test.recommendations)
        
        # Add strategic recommendations
        pass_rate = (len([t for t in self.validation_tests if t.result == ValidationResult.PASS]) / 
                    max(len(self.validation_tests), 1)) * 100
        
        if pass_rate < 60:
            recommendations.add("Conduct thorough performance review and optimization")
        
        if not self.baseline:
            recommendations.add("Establish performance baselines for future comparisons")
        
        return list(recommendations)[:10]  # Top 10 recommendations
    
    def _analyze_performance_trends(self) -> Dict[str, Any]:
        """Analyze performance trends."""
        if not self.baseline:
            return {"status": "No baseline available for trend analysis"}
        
        # Simple trend analysis based on baseline comparison
        current_metrics = asyncio.create_task(self._collect_current_metrics())
        current = current_metrics.result() if current_metrics.done() else {}
        
        trends = {}
        
        if current:
            for metric in ["avg_response_time_ms", "throughput_rps", "cache_hit_rate"]:
                baseline_value = getattr(self.baseline, metric, 0)
                current_value = current.get(metric, 0)
                
                if baseline_value > 0:
                    change = ((current_value - baseline_value) / baseline_value) * 100
                    
                    if abs(change) < 5:
                        trend = "stable"
                    elif change > 0:
                        trend = "improving" if metric in ["throughput_rps", "cache_hit_rate"] else "degrading"
                    else:
                        trend = "degrading" if metric in ["throughput_rps", "cache_hit_rate"] else "improving"
                    
                    trends[metric] = {
                        "trend": trend,
                        "change_percent": change
                    }
        
        return trends
    
    def _suggest_next_steps(self) -> List[str]:
        """Suggest next steps based on validation results."""
        next_steps = []
        
        # Based on failed tests
        failed_tests = [t for t in self.validation_tests if t.result == ValidationResult.FAIL]
        if failed_tests:
            next_steps.append("Address critical test failures immediately")
        
        # Based on warnings
        warning_tests = [t for t in self.validation_tests if t.result == ValidationResult.WARNING]
        if warning_tests:
            next_steps.append("Investigate and resolve warning conditions")
        
        # Based on optimization impacts
        if not self.optimization_impacts:
            next_steps.append("Establish performance baseline for optimization tracking")
        
        # General recommendations
        next_steps.extend([
            "Continue monitoring performance metrics",
            "Plan regular performance validation cycles",
            "Document optimization strategies for future reference"
        ])
        
        return next_steps[:5]  # Top 5 next steps
    
    def export_report(self, filepath: str):
        """Export validation report to file."""
        report = self.generate_comprehensive_report()
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Performance validation report exported to {filepath}")
    
    async def shutdown(self):
        """Shutdown the validator."""
        logger.info("Shutting down MCP Performance Validator")
        
        # Shutdown components
        if self.scaling_advisor:
            await self.scaling_advisor.shutdown()
        
        if self.startup_optimizer:
            await self.startup_optimizer.shutdown()
        
        logger.info("MCP Performance Validator shutdown complete")


__all__ = [
    "ValidationResult",
    "TestCategory",
    "ValidationTest",
    "PerformanceBaseline",
    "OptimizationImpact",
    "MCPPerformanceValidator"
]