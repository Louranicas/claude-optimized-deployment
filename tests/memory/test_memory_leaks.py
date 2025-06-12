"""
Advanced Memory Leak Detection Framework
Builds upon existing memory profiling with enhanced leak detection algorithms.
"""

import pytest
import asyncio
import gc
import tracemalloc
import psutil
import time
import statistics
import json
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Callable, Optional, Tuple
from pathlib import Path
import sys
import os
import threading
from collections import defaultdict
import weakref

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.circle_of_experts.core.expert_manager import ExpertManager
from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
from src.circle_of_experts.models.response import ExpertResponse
from src.mcp.manager import get_mcp_manager
from src.circle_of_experts.core.rust_accelerated import (
    ExpertAnalyzer,
    ConsensusEngine,
    ResponseAggregator
)


@dataclass
class MemoryLeakResult:
    """Results from memory leak detection"""
    component_name: str
    test_duration: float
    iterations: int
    initial_memory_mb: float
    final_memory_mb: float
    peak_memory_mb: float
    memory_growth_mb: float
    growth_per_iteration_mb: float
    leak_detected: bool
    confidence_level: float
    trend_analysis: Dict[str, Any]
    gc_stats: Dict[str, int]
    memory_snapshots: List[float]
    leak_severity: str
    recommendations: List[str]


@dataclass
class AllocationTracker:
    """Track memory allocations for detailed analysis"""
    timestamp: float
    size_bytes: int
    location: str
    object_type: str
    traceback: List[str]


class MemoryLeakDetector:
    """Advanced memory leak detection with statistical analysis"""
    
    def __init__(self):
        self.baseline_tolerance = 5.0  # MB
        self.growth_threshold = 0.1    # MB per iteration
        self.statistical_confidence = 0.95
        self.memory_snapshots = []
        self.allocation_history = []
        self.object_references = weakref.WeakSet()
        self.process = psutil.Process()
        
    def start_tracking(self):
        """Start memory tracking"""
        tracemalloc.start()
        gc.collect()
        self.memory_snapshots = []
        self.allocation_history = []
        
    def stop_tracking(self):
        """Stop memory tracking"""
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        gc.collect()
        
    def take_memory_snapshot(self, description: str = "") -> float:
        """Take a memory snapshot and return RSS in MB"""
        memory_info = self.process.memory_info()
        rss_mb = memory_info.rss / 1024 / 1024
        
        snapshot = {
            'timestamp': time.time(),
            'rss_mb': rss_mb,
            'description': description,
            'gc_count': sum(gc.get_count())
        }
        
        self.memory_snapshots.append(snapshot)
        return rss_mb
        
    def analyze_memory_trend(self, memory_readings: List[float]) -> Dict[str, Any]:
        """Statistical analysis of memory growth patterns"""
        if len(memory_readings) < 3:
            return {
                'trend': 'insufficient_data',
                'slope': 0,
                'r_squared': 0,
                'is_linear_growth': False,
                'growth_rate': 0
            }
        
        # Simple linear regression
        n = len(memory_readings)
        x = list(range(n))
        y = memory_readings
        
        # Calculate slope and intercept
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(y)
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            slope = 0
        else:
            slope = numerator / denominator
            
        intercept = y_mean - slope * x_mean
        
        # Calculate R-squared
        y_pred = [slope * x[i] + intercept for i in range(n)]
        ss_res = sum((y[i] - y_pred[i]) ** 2 for i in range(n))
        ss_tot = sum((y[i] - y_mean) ** 2 for i in range(n))
        
        r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0
        
        # Determine trend characteristics
        is_linear_growth = r_squared > 0.7 and slope > self.growth_threshold
        
        return {
            'trend': 'linear_growth' if is_linear_growth else 'stable',
            'slope': slope,
            'r_squared': r_squared,
            'is_linear_growth': is_linear_growth,
            'growth_rate': slope,
            'confidence': r_squared
        }
    
    async def detect_leaks_in_component(
        self, 
        component_factory: Callable,
        operation_func: Callable,
        iterations: int = 100,
        warmup_iterations: int = 10
    ) -> MemoryLeakResult:
        """Detect memory leaks in a specific component"""
        
        # Start tracking
        self.start_tracking()
        
        # Warmup phase
        component = component_factory()
        for _ in range(warmup_iterations):
            if asyncio.iscoroutinefunction(operation_func):
                await operation_func(component)
            else:
                operation_func(component)
        
        # Clear after warmup
        del component
        gc.collect()
        
        # Initial memory measurement
        initial_memory = self.take_memory_snapshot("Initial")
        initial_gc = dict(enumerate(gc.get_count()))
        start_time = time.time()
        
        # Test iterations
        memory_readings = []
        
        for i in range(iterations):
            # Create fresh component instance
            component = component_factory()
            
            # Execute operation
            if asyncio.iscoroutinefunction(operation_func):
                await operation_func(component)
            else:
                operation_func(component)
            
            # Clean up component reference
            del component
            
            # Force garbage collection periodically
            if i % 10 == 0:
                gc.collect()
                memory_reading = self.take_memory_snapshot(f"Iteration {i}")
                memory_readings.append(memory_reading)
        
        # Final measurements
        gc.collect()
        final_memory = self.take_memory_snapshot("Final")
        final_gc = dict(enumerate(gc.get_count()))
        test_duration = time.time() - start_time
        
        # Stop tracking
        self.stop_tracking()
        
        # Analysis
        peak_memory = max(memory_readings) if memory_readings else final_memory
        memory_growth = final_memory - initial_memory
        growth_per_iteration = memory_growth / iterations if iterations > 0 else 0
        
        # Trend analysis
        trend_analysis = self.analyze_memory_trend(memory_readings)
        
        # Leak detection logic
        leak_detected = (
            growth_per_iteration > self.growth_threshold or
            memory_growth > self.baseline_tolerance or
            trend_analysis['is_linear_growth']
        )
        
        # Confidence calculation
        confidence_level = min(
            trend_analysis.get('confidence', 0.5),
            1.0 - (self.baseline_tolerance / max(memory_growth, 1.0))
        )
        
        # Severity assessment
        if memory_growth > 50:
            leak_severity = "critical"
        elif memory_growth > 20:
            leak_severity = "major"
        elif memory_growth > 5:
            leak_severity = "minor"
        else:
            leak_severity = "none"
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            memory_growth, growth_per_iteration, trend_analysis
        )
        
        return MemoryLeakResult(
            component_name=component_factory.__name__ if hasattr(component_factory, '__name__') else str(component_factory),
            test_duration=test_duration,
            iterations=iterations,
            initial_memory_mb=initial_memory,
            final_memory_mb=final_memory,
            peak_memory_mb=peak_memory,
            memory_growth_mb=memory_growth,
            growth_per_iteration_mb=growth_per_iteration,
            leak_detected=leak_detected,
            confidence_level=confidence_level,
            trend_analysis=trend_analysis,
            gc_stats={
                'initial': initial_gc,
                'final': final_gc,
                'delta': {gen: final_gc.get(gen, 0) - initial_gc.get(gen, 0) 
                         for gen in range(3)}
            },
            memory_snapshots=[s['rss_mb'] for s in self.memory_snapshots[-10:]],
            leak_severity=leak_severity,
            recommendations=recommendations
        )
    
    def _generate_recommendations(
        self, 
        memory_growth: float, 
        growth_per_iteration: float, 
        trend_analysis: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations based on leak analysis"""
        recommendations = []
        
        if memory_growth > self.baseline_tolerance:
            recommendations.append(
                f"Memory growth of {memory_growth:.2f}MB detected. "
                "Review object lifecycle and ensure proper cleanup."
            )
        
        if growth_per_iteration > self.growth_threshold:
            recommendations.append(
                f"Consistent growth of {growth_per_iteration:.3f}MB per iteration. "
                "Check for accumulating references or caches."
            )
        
        if trend_analysis.get('is_linear_growth'):
            recommendations.append(
                "Linear memory growth pattern detected. "
                "Investigate potential accumulation of objects or data structures."
            )
        
        if not recommendations:
            recommendations.append(
                "No significant memory leaks detected. "
                "Memory usage appears stable."
            )
        
        return recommendations
    
    def generate_leak_report(self, results: List[MemoryLeakResult]) -> str:
        """Generate detailed leak analysis report"""
        report = []
        report.append("# Memory Leak Detection Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("\n## Executive Summary")
        
        # Summary statistics
        total_tests = len(results)
        leaks_detected = sum(1 for r in results if r.leak_detected)
        critical_leaks = sum(1 for r in results if r.leak_severity == "critical")
        major_leaks = sum(1 for r in results if r.leak_severity == "major")
        
        report.append(f"- **Total Components Tested**: {total_tests}")
        report.append(f"- **Leaks Detected**: {leaks_detected} ({leaks_detected/total_tests*100:.1f}%)")
        report.append(f"- **Critical Issues**: {critical_leaks}")
        report.append(f"- **Major Issues**: {major_leaks}")
        
        if critical_leaks > 0:
            report.append("\n⚠️ **CRITICAL**: Immediate attention required for critical memory leaks!")
        elif major_leaks > 0:
            report.append("\n⚠️ **WARNING**: Major memory leaks detected - review recommended")
        else:
            report.append("\n✅ **GOOD**: No critical memory leaks detected")
        
        # Detailed results
        report.append("\n## Detailed Results")
        
        for result in sorted(results, key=lambda x: x.memory_growth_mb, reverse=True):
            report.append(f"\n### {result.component_name}")
            report.append(f"- **Severity**: {result.leak_severity.upper()}")
            report.append(f"- **Memory Growth**: {result.memory_growth_mb:.2f} MB")
            report.append(f"- **Growth per Iteration**: {result.growth_per_iteration_mb:.3f} MB")
            report.append(f"- **Leak Detected**: {'Yes' if result.leak_detected else 'No'}")
            report.append(f"- **Confidence Level**: {result.confidence_level:.2f}")
            report.append(f"- **Test Duration**: {result.test_duration:.2f}s")
            report.append(f"- **Iterations**: {result.iterations}")
            
            # Trend analysis
            trend = result.trend_analysis
            report.append(f"- **Trend Analysis**:")
            report.append(f"  - Pattern: {trend.get('trend', 'unknown')}")
            report.append(f"  - Growth Rate: {trend.get('growth_rate', 0):.3f} MB/iteration")
            report.append(f"  - R²: {trend.get('r_squared', 0):.3f}")
            
            # Recommendations
            report.append("- **Recommendations**:")
            for rec in result.recommendations:
                report.append(f"  - {rec}")
        
        return "\n".join(report)


# Test implementations
class TestMemoryLeaks:
    """Memory leak detection test suite"""
    
    def __init__(self):
        self.leak_detector = MemoryLeakDetector()
    
    @pytest.mark.memory
    async def test_expert_manager_leaks(self):
        """Test ExpertManager for memory leaks"""
        
        def create_expert_manager():
            return ExpertManager()
        
        async def expert_operation(manager):
            query = ExpertQuery(
                title="Leak test query",
                content="Testing for memory leaks in expert manager",
                query_type=QueryType.TECHNICAL,
                priority=QueryPriority.MEDIUM,
                requester="leak_test@test.com"
            )
            # Simulate query processing without actual API calls
            await asyncio.sleep(0.001)
        
        result = await self.leak_detector.detect_leaks_in_component(
            create_expert_manager,
            expert_operation,
            iterations=100,
            warmup_iterations=10
        )
        
        # Assertions
        assert result.leak_severity in ["none", "minor"], f"Memory leak detected: {result.leak_severity}"
        assert result.memory_growth_mb < 10, f"Excessive memory growth: {result.memory_growth_mb:.2f}MB"
        
        # Print results for analysis
        print(f"\n📊 ExpertManager Leak Test Results:")
        print(f"   Memory Growth: {result.memory_growth_mb:.2f}MB")
        print(f"   Growth per Iteration: {result.growth_per_iteration_mb:.3f}MB")
        print(f"   Leak Detected: {result.leak_detected}")
        
        return result
    
    @pytest.mark.memory
    async def test_mcp_manager_leaks(self):
        """Test MCP Manager for memory leaks"""
        
        def create_mcp_manager():
            return get_mcp_manager()
        
        async def mcp_operation(manager):
            try:
                await manager.call_tool("desktop.execute_command", {"command": "echo 'leak test'"})
            except:
                pass  # Ignore errors for leak testing
        
        result = await self.leak_detector.detect_leaks_in_component(
            create_mcp_manager,
            mcp_operation,
            iterations=50,  # Fewer iterations for network operations
            warmup_iterations=5
        )
        
        # Assertions
        assert result.leak_severity != "critical", f"Critical memory leak detected: {result.leak_severity}"
        assert result.memory_growth_mb < 20, f"Excessive memory growth: {result.memory_growth_mb:.2f}MB"
        
        print(f"\n📊 MCP Manager Leak Test Results:")
        print(f"   Memory Growth: {result.memory_growth_mb:.2f}MB")
        print(f"   Growth per Iteration: {result.growth_per_iteration_mb:.3f}MB")
        print(f"   Leak Detected: {result.leak_detected}")
        
        return result
    
    @pytest.mark.memory
    async def test_rust_modules_leaks(self):
        """Test Rust modules for memory leaks"""
        
        def create_rust_analyzer():
            return ExpertAnalyzer()
        
        def rust_operation(analyzer):
            # Create test responses
            responses = []
            for i in range(10):
                response = ExpertResponse(
                    expert_type=f"expert_{i}",
                    content="Test content for leak detection",
                    confidence=0.9,
                    response_time=1.0,
                    model_used="test",
                    cost_estimate=0.001
                )
                responses.append(response)
            
            # Analyze responses
            analyzer.analyze_responses(responses)
        
        result = await self.leak_detector.detect_leaks_in_component(
            create_rust_analyzer,
            rust_operation,
            iterations=200,
            warmup_iterations=20
        )
        
        # Rust modules should have minimal leaks
        assert result.leak_severity in ["none", "minor"], f"Rust module leak detected: {result.leak_severity}"
        assert result.memory_growth_mb < 5, f"Rust module memory growth: {result.memory_growth_mb:.2f}MB"
        
        print(f"\n📊 Rust Modules Leak Test Results:")
        print(f"   Memory Growth: {result.memory_growth_mb:.2f}MB")
        print(f"   Growth per Iteration: {result.growth_per_iteration_mb:.3f}MB")
        print(f"   Leak Detected: {result.leak_detected}")
        
        return result
    
    @pytest.mark.memory
    async def test_response_aggregation_leaks(self):
        """Test response aggregation for memory leaks"""
        
        def create_aggregator():
            return ResponseAggregator()
        
        def aggregation_operation(aggregator):
            # Create test responses
            responses = []
            for i in range(20):
                response = ExpertResponse(
                    expert_type=f"expert_{i % 5}",
                    content=f"Response content {i} " * 50,  # Larger content
                    confidence=0.8 + (i % 2) * 0.1,
                    response_time=1.0 + i * 0.1,
                    model_used="test",
                    cost_estimate=0.001 * i
                )
                responses.append(response)
            
            # Aggregate responses
            aggregator.aggregate_responses(responses)
        
        result = await self.leak_detector.detect_leaks_in_component(
            create_aggregator,
            aggregation_operation,
            iterations=100,
            warmup_iterations=10
        )
        
        # Assertions
        assert result.leak_severity != "critical", f"Critical aggregation leak: {result.leak_severity}"
        assert result.memory_growth_mb < 15, f"Aggregation memory growth: {result.memory_growth_mb:.2f}MB"
        
        print(f"\n📊 Response Aggregation Leak Test Results:")
        print(f"   Memory Growth: {result.memory_growth_mb:.2f}MB")
        print(f"   Growth per Iteration: {result.growth_per_iteration_mb:.3f}MB")
        print(f"   Leak Detected: {result.leak_detected}")
        
        return result
    
    @pytest.mark.memory_comprehensive
    async def test_comprehensive_leak_detection(self):
        """Run comprehensive leak detection across all components"""
        
        print("\n🔍 Running Comprehensive Memory Leak Detection...")
        
        # Test all components
        results = []
        
        results.append(await self.test_expert_manager_leaks())
        results.append(await self.test_mcp_manager_leaks())
        results.append(await self.test_rust_modules_leaks())
        results.append(await self.test_response_aggregation_leaks())
        
        # Generate comprehensive report
        report = self.leak_detector.generate_leak_report(results)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"tests/memory/leak_detection_report_{timestamp}.md"
        
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, 'w') as f:
            f.write(report)
        
        # Save detailed results
        results_data = [asdict(r) for r in results]
        results_path = f"tests/memory/leak_detection_results_{timestamp}.json"
        with open(results_path, 'w') as f:
            json.dump(results_data, f, indent=2, default=str)
        
        print(f"\n✅ Comprehensive leak detection complete!")
        print(f"📄 Report: {report_path}")
        print(f"📊 Results: {results_path}")
        
        # Overall assertions
        critical_leaks = sum(1 for r in results if r.leak_severity == "critical")
        assert critical_leaks == 0, f"Critical memory leaks detected in {critical_leaks} components"
        
        major_leaks = sum(1 for r in results if r.leak_severity == "major")
        if major_leaks > 0:
            print(f"⚠️ Warning: {major_leaks} major memory leaks detected")
        
        return results


async def run_leak_detection():
    """Run memory leak detection suite"""
    tester = TestMemoryLeaks()
    return await tester.test_comprehensive_leak_detection()


if __name__ == "__main__":
    # Run leak detection
    asyncio.run(run_leak_detection())