"""
Memory Performance Regression Testing Framework
Ensures optimization improvements are maintained over time.
"""

import pytest
import asyncio
import gc
import tracemalloc
import psutil
import time
import json
import statistics
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Callable, Optional, Tuple
from pathlib import Path
import sys
import os

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
class MemoryPerformanceMetrics:
    """Memory performance metrics for comparison"""
    component_name: str
    test_name: str
    timestamp: str
    memory_metrics: Dict[str, float]
    performance_metrics: Dict[str, float]
    gc_metrics: Dict[str, int]
    environment_info: Dict[str, Any]
    rust_acceleration: bool


@dataclass
class RegressionTestResult:
    """Results from regression testing"""
    component_name: str
    test_name: str
    current_metrics: MemoryPerformanceMetrics
    baseline_metrics: Optional[MemoryPerformanceMetrics]
    regression_detected: bool
    improvement_detected: bool
    performance_change: Dict[str, float]
    regression_severity: str
    recommendations: List[str]
    confidence_level: float


class MemoryPerformanceRegression:
    """Track memory performance metrics over time"""
    
    def __init__(self):
        self.baseline_file = Path("benchmarks/memory_baselines.json")
        self.regression_threshold = 0.15  # 15% regression threshold
        self.improvement_threshold = 0.10  # 10% improvement threshold
        self.confidence_threshold = 0.80   # 80% confidence required
        self.process = psutil.Process()
        
        # Ensure directories exist
        self.baseline_file.parent.mkdir(exist_ok=True)
        
    def load_baselines(self) -> Dict[str, MemoryPerformanceMetrics]:
        """Load baseline metrics from file"""
        if not self.baseline_file.exists():
            return {}
        
        try:
            with open(self.baseline_file, 'r') as f:
                data = json.load(f)
            
            baselines = {}
            for key, baseline_data in data.items():
                baselines[key] = MemoryPerformanceMetrics(**baseline_data)
            
            return baselines
        except Exception as e:
            print(f"Warning: Could not load baselines: {e}")
            return {}
    
    def save_baselines(self, baselines: Dict[str, MemoryPerformanceMetrics]):
        """Save baseline metrics to file"""
        try:
            baseline_data = {
                key: asdict(metrics) for key, metrics in baselines.items()
            }
            
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2, default=str)
                
        except Exception as e:
            print(f"Warning: Could not save baselines: {e}")
    
    async def benchmark_memory_performance(
        self, 
        component_name: str,
        test_name: str,
        test_function: Callable,
        iterations: int = 50,
        warmup_iterations: int = 10
    ) -> MemoryPerformanceMetrics:
        """Benchmark memory performance with statistical validation"""
        
        # Environment info
        environment_info = {
            'python_version': sys.version,
            'platform': sys.platform,
            'cpu_count': os.cpu_count(),
            'memory_total_gb': psutil.virtual_memory().total / (1024**3)
        }
        
        # Check for Rust acceleration
        rust_acceleration = self._check_rust_acceleration()
        
        # Start tracking
        tracemalloc.start()
        gc.collect()
        
        # Warmup
        for _ in range(warmup_iterations):
            if asyncio.iscoroutinefunction(test_function):
                await test_function()
            else:
                test_function()
        
        gc.collect()
        
        # Benchmark measurements
        memory_measurements = []
        time_measurements = []
        gc_collections_before = list(gc.get_count())
        
        for i in range(iterations):
            # Pre-test state
            gc.collect()
            memory_before = self.process.memory_info().rss / 1024 / 1024
            
            # Execute test
            start_time = time.perf_counter()
            
            if asyncio.iscoroutinefunction(test_function):
                await test_function()
            else:
                test_function()
            
            end_time = time.perf_counter()
            
            # Post-test measurements
            memory_after = self.process.memory_info().rss / 1024 / 1024
            memory_delta = memory_after - memory_before
            execution_time = end_time - start_time
            
            memory_measurements.append(memory_delta)
            time_measurements.append(execution_time)
        
        gc_collections_after = list(gc.get_count())
        
        # Stop tracking
        current_memory, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Calculate statistics
        memory_metrics = {
            'mean_memory_delta_mb': statistics.mean(memory_measurements),
            'median_memory_delta_mb': statistics.median(memory_measurements),
            'max_memory_delta_mb': max(memory_measurements),
            'min_memory_delta_mb': min(memory_measurements),
            'stdev_memory_delta_mb': statistics.stdev(memory_measurements) if len(memory_measurements) > 1 else 0,
            'peak_memory_mb': peak_memory / 1024 / 1024,
            'current_memory_mb': current_memory / 1024 / 1024
        }
        
        performance_metrics = {
            'mean_execution_time_ms': statistics.mean(time_measurements) * 1000,
            'median_execution_time_ms': statistics.median(time_measurements) * 1000,
            'max_execution_time_ms': max(time_measurements) * 1000,
            'min_execution_time_ms': min(time_measurements) * 1000,
            'stdev_execution_time_ms': statistics.stdev(time_measurements) * 1000 if len(time_measurements) > 1 else 0,
            'throughput_ops_per_second': 1.0 / statistics.mean(time_measurements) if statistics.mean(time_measurements) > 0 else 0
        }
        
        gc_metrics = {
            f'gc_gen_{i}_delta': gc_collections_after[i] - gc_collections_before[i] 
            for i in range(len(gc_collections_before))
        }
        
        return MemoryPerformanceMetrics(
            component_name=component_name,
            test_name=test_name,
            timestamp=datetime.now().isoformat(),
            memory_metrics=memory_metrics,
            performance_metrics=performance_metrics,
            gc_metrics=gc_metrics,
            environment_info=environment_info,
            rust_acceleration=rust_acceleration
        )
    
    def compare_with_baseline(
        self, 
        current_metrics: MemoryPerformanceMetrics, 
        baseline_metrics: Optional[MemoryPerformanceMetrics]
    ) -> RegressionTestResult:
        """Compare current performance with established baseline"""
        
        if baseline_metrics is None:
            return RegressionTestResult(
                component_name=current_metrics.component_name,
                test_name=current_metrics.test_name,
                current_metrics=current_metrics,
                baseline_metrics=None,
                regression_detected=False,
                improvement_detected=False,
                performance_change={},
                regression_severity="none",
                recommendations=["No baseline available - current metrics will be used as baseline"],
                confidence_level=0.0
            )
        
        # Calculate performance changes
        performance_change = {}
        
        # Memory performance changes
        for metric in ['mean_memory_delta_mb', 'median_memory_delta_mb', 'peak_memory_mb']:
            current_val = current_metrics.memory_metrics.get(metric, 0)
            baseline_val = baseline_metrics.memory_metrics.get(metric, 0)
            
            if baseline_val != 0:
                change = (current_val - baseline_val) / baseline_val
                performance_change[f'{metric}_change'] = change
        
        # Performance timing changes
        for metric in ['mean_execution_time_ms', 'median_execution_time_ms', 'throughput_ops_per_second']:
            current_val = current_metrics.performance_metrics.get(metric, 0)
            baseline_val = baseline_metrics.performance_metrics.get(metric, 0)
            
            if baseline_val != 0:
                if metric == 'throughput_ops_per_second':
                    # Higher throughput is better
                    change = (current_val - baseline_val) / baseline_val
                else:
                    # Lower execution time is better
                    change = (current_val - baseline_val) / baseline_val
                
                performance_change[f'{metric}_change'] = change
        
        # Detect regressions and improvements
        memory_regression = any(
            change > self.regression_threshold 
            for key, change in performance_change.items() 
            if 'memory' in key and 'change' in key
        )
        
        performance_regression = any(
            change > self.regression_threshold 
            for key, change in performance_change.items() 
            if 'execution_time' in key and 'change' in key
        )
        
        throughput_improvement = performance_change.get('throughput_ops_per_second_change', 0) > self.improvement_threshold
        
        regression_detected = memory_regression or performance_regression
        improvement_detected = throughput_improvement and not regression_detected
        
        # Determine severity
        max_regression = max([
            change for key, change in performance_change.items()
            if change > 0
        ], default=0)
        
        if max_regression > 0.5:  # 50% regression
            regression_severity = "critical"
        elif max_regression > 0.3:  # 30% regression
            regression_severity = "major"
        elif max_regression > self.regression_threshold:
            regression_severity = "minor"
        else:
            regression_severity = "none"
        
        # Generate recommendations
        recommendations = self._generate_regression_recommendations(
            performance_change, regression_detected, improvement_detected
        )
        
        # Calculate confidence level
        confidence_level = self._calculate_confidence(current_metrics, baseline_metrics)
        
        return RegressionTestResult(
            component_name=current_metrics.component_name,
            test_name=current_metrics.test_name,
            current_metrics=current_metrics,
            baseline_metrics=baseline_metrics,
            regression_detected=regression_detected,
            improvement_detected=improvement_detected,
            performance_change=performance_change,
            regression_severity=regression_severity,
            recommendations=recommendations,
            confidence_level=confidence_level
        )
    
    def update_baseline(self, new_metrics: MemoryPerformanceMetrics) -> bool:
        """Update baseline metrics after validated improvements"""
        try:
            baselines = self.load_baselines()
            key = f"{new_metrics.component_name}_{new_metrics.test_name}"
            baselines[key] = new_metrics
            self.save_baselines(baselines)
            return True
        except Exception as e:
            print(f"Error updating baseline: {e}")
            return False
    
    def _check_rust_acceleration(self) -> bool:
        """Check if Rust acceleration is available"""
        try:
            from src.circle_of_experts.core.rust_accelerated import ExpertAnalyzer
            ExpertAnalyzer()
            return True
        except:
            return False
    
    def _generate_regression_recommendations(
        self, 
        performance_change: Dict[str, float],
        regression_detected: bool,
        improvement_detected: bool
    ) -> List[str]:
        """Generate recommendations based on regression analysis"""
        recommendations = []
        
        if regression_detected:
            recommendations.append("Performance regression detected - investigate recent changes")
            
            # Memory-specific recommendations
            memory_regressions = [
                (key, change) for key, change in performance_change.items()
                if 'memory' in key and change > self.regression_threshold
            ]
            
            if memory_regressions:
                recommendations.append("Memory usage regression detected:")
                for key, change in memory_regressions:
                    recommendations.append(f"  - {key}: {change*100:.1f}% increase")
                recommendations.append("  Consider: object pooling, garbage collection tuning, memory profiling")
            
            # Performance-specific recommendations
            time_regressions = [
                (key, change) for key, change in performance_change.items()
                if 'execution_time' in key and change > self.regression_threshold
            ]
            
            if time_regressions:
                recommendations.append("Execution time regression detected:")
                for key, change in time_regressions:
                    recommendations.append(f"  - {key}: {change*100:.1f}% increase")
                recommendations.append("  Consider: algorithmic improvements, Rust acceleration, caching")
        
        elif improvement_detected:
            recommendations.append("Performance improvement detected - consider updating baseline")
            
            throughput_change = performance_change.get('throughput_ops_per_second_change', 0)
            if throughput_change > self.improvement_threshold:
                recommendations.append(f"Throughput improved by {throughput_change*100:.1f}%")
        
        else:
            recommendations.append("Performance is stable within acceptable thresholds")
        
        return recommendations
    
    def _calculate_confidence(
        self, 
        current_metrics: MemoryPerformanceMetrics,
        baseline_metrics: MemoryPerformanceMetrics
    ) -> float:
        """Calculate confidence level in the comparison"""
        
        # Check environment consistency
        env_consistency = 1.0
        
        current_env = current_metrics.environment_info
        baseline_env = baseline_metrics.environment_info
        
        # Python version consistency
        if current_env.get('python_version') != baseline_env.get('python_version'):
            env_consistency *= 0.8
        
        # Rust acceleration consistency
        if current_metrics.rust_acceleration != baseline_metrics.rust_acceleration:
            env_consistency *= 0.7
        
        # Time recency (more recent comparisons are more reliable)
        try:
            baseline_time = datetime.fromisoformat(baseline_metrics.timestamp)
            time_diff = datetime.now() - baseline_time
            
            if time_diff > timedelta(days=30):
                time_consistency = 0.8
            elif time_diff > timedelta(days=7):
                time_consistency = 0.9
            else:
                time_consistency = 1.0
        except:
            time_consistency = 0.7
        
        # Statistical confidence based on standard deviation
        current_stdev = current_metrics.memory_metrics.get('stdev_memory_delta_mb', 0)
        baseline_stdev = baseline_metrics.memory_metrics.get('stdev_memory_delta_mb', 0)
        
        avg_stdev = (current_stdev + baseline_stdev) / 2
        if avg_stdev < 1.0:  # Low standard deviation means high confidence
            stat_confidence = 0.95
        elif avg_stdev < 5.0:
            stat_confidence = 0.85
        else:
            stat_confidence = 0.70
        
        return min(env_consistency * time_consistency * stat_confidence, 1.0)


# Test implementations
class TestMemoryPerformanceRegression:
    """Memory performance regression test suite"""
    
    def __init__(self):
        self.regression_tester = MemoryPerformanceRegression()
    
    @pytest.mark.memory_regression
    async def test_expert_manager_performance_regression(self):
        """Test ExpertManager memory performance regression"""
        
        async def expert_manager_benchmark():
            manager = ExpertManager()
            
            # Create multiple queries for realistic testing
            queries = []
            for i in range(10):
                query = ExpertQuery(
                    title=f"Performance test query {i}",
                    content=f"Testing memory performance for query {i}",
                    query_type=QueryType.TECHNICAL,
                    priority=QueryPriority.MEDIUM,
                    requester=f"perf_test_{i}@test.com"
                )
                queries.append(query)
            
            # Simulate processing
            for query in queries:
                await asyncio.sleep(0.001)  # Simulate processing time
        
        # Benchmark current performance
        current_metrics = await self.regression_tester.benchmark_memory_performance(
            component_name="ExpertManager",
            test_name="query_processing_performance",
            test_function=expert_manager_benchmark,
            iterations=30,
            warmup_iterations=5
        )
        
        # Load baseline and compare
        baselines = self.regression_tester.load_baselines()
        baseline_key = f"{current_metrics.component_name}_{current_metrics.test_name}"
        baseline_metrics = baselines.get(baseline_key)
        
        result = self.regression_tester.compare_with_baseline(current_metrics, baseline_metrics)
        
        # Print results
        print(f"\n📊 ExpertManager Performance Regression Test:")
        print(f"   Component: {result.component_name}")
        print(f"   Regression Detected: {result.regression_detected}")
        print(f"   Improvement Detected: {result.improvement_detected}")
        print(f"   Severity: {result.regression_severity}")
        print(f"   Confidence: {result.confidence_level:.2f}")
        
        if result.performance_change:
            print("   Performance Changes:")
            for metric, change in result.performance_change.items():
                print(f"     {metric}: {change*100:+.1f}%")
        
        # Update baseline if no regression or if improvement
        if not result.regression_detected:
            self.regression_tester.update_baseline(current_metrics)
        
        # Assertions
        assert not (result.regression_detected and result.regression_severity == "critical"), \
            f"Critical performance regression detected: {result.recommendations}"
        
        return result
    
    @pytest.mark.memory_regression
    async def test_rust_modules_performance_regression(self):
        """Test Rust modules memory performance regression"""
        
        def rust_modules_benchmark():
            # Test ExpertAnalyzer
            analyzer = ExpertAnalyzer()
            
            responses = []
            for i in range(50):
                response = ExpertResponse(
                    expert_type=f"expert_{i % 5}",
                    content=f"Regression test content {i} " * 20,
                    confidence=0.85,
                    response_time=1.2,
                    model_used="test_model",
                    cost_estimate=0.001
                )
                responses.append(response)
            
            # Analyze responses
            analyzer.analyze_responses(responses)
            
            # Test ResponseAggregator
            aggregator = ResponseAggregator()
            aggregator.aggregate_responses(responses)
        
        # Benchmark current performance
        current_metrics = await self.regression_tester.benchmark_memory_performance(
            component_name="RustModules",
            test_name="analysis_aggregation_performance",
            test_function=rust_modules_benchmark,
            iterations=50,
            warmup_iterations=10
        )
        
        # Load baseline and compare
        baselines = self.regression_tester.load_baselines()
        baseline_key = f"{current_metrics.component_name}_{current_metrics.test_name}"
        baseline_metrics = baselines.get(baseline_key)
        
        result = self.regression_tester.compare_with_baseline(current_metrics, baseline_metrics)
        
        # Print results
        print(f"\n📊 Rust Modules Performance Regression Test:")
        print(f"   Component: {result.component_name}")
        print(f"   Regression Detected: {result.regression_detected}")
        print(f"   Improvement Detected: {result.improvement_detected}")
        print(f"   Severity: {result.regression_severity}")
        print(f"   Confidence: {result.confidence_level:.2f}")
        
        if result.performance_change:
            print("   Performance Changes:")
            for metric, change in result.performance_change.items():
                print(f"     {metric}: {change*100:+.1f}%")
        
        # Update baseline if no regression
        if not result.regression_detected:
            self.regression_tester.update_baseline(current_metrics)
        
        # Rust modules should have minimal regression
        assert not (result.regression_detected and result.regression_severity in ["critical", "major"]), \
            f"Significant Rust performance regression: {result.recommendations}"
        
        return result
    
    @pytest.mark.memory_regression
    async def test_mcp_tools_performance_regression(self):
        """Test MCP tools memory performance regression"""
        
        async def mcp_tools_benchmark():
            manager = get_mcp_manager()
            
            # Test multiple tool calls
            tools_to_test = [
                ("desktop.execute_command", {"command": "echo 'regression test'"}),
                ("desktop.read_file", {"file_path": "README.md", "lines": 10}),
            ]
            
            for tool_name, params in tools_to_test:
                try:
                    await manager.call_tool(tool_name, params)
                except:
                    pass  # Ignore errors for performance testing
        
        # Benchmark current performance
        current_metrics = await self.regression_tester.benchmark_memory_performance(
            component_name="MCPTools",
            test_name="tool_execution_performance",
            test_function=mcp_tools_benchmark,
            iterations=25,
            warmup_iterations=5
        )
        
        # Load baseline and compare
        baselines = self.regression_tester.load_baselines()
        baseline_key = f"{current_metrics.component_name}_{current_metrics.test_name}"
        baseline_metrics = baselines.get(baseline_key)
        
        result = self.regression_tester.compare_with_baseline(current_metrics, baseline_metrics)
        
        # Print results
        print(f"\n📊 MCP Tools Performance Regression Test:")
        print(f"   Component: {result.component_name}")
        print(f"   Regression Detected: {result.regression_detected}")
        print(f"   Improvement Detected: {result.improvement_detected}")
        print(f"   Severity: {result.regression_severity}")
        print(f"   Confidence: {result.confidence_level:.2f}")
        
        # Update baseline if no regression
        if not result.regression_detected:
            self.regression_tester.update_baseline(current_metrics)
        
        # Assertions
        assert not (result.regression_detected and result.regression_severity == "critical"), \
            f"Critical MCP performance regression: {result.recommendations}"
        
        return result
    
    @pytest.mark.memory_regression_comprehensive
    async def test_comprehensive_performance_regression(self):
        """Run comprehensive performance regression testing"""
        
        print("\n🔍 Running Comprehensive Memory Performance Regression Testing...")
        
        # Test all components
        results = []
        
        results.append(await self.test_expert_manager_performance_regression())
        results.append(await self.test_rust_modules_performance_regression())
        results.append(await self.test_mcp_tools_performance_regression())
        
        # Generate comprehensive report
        report = self._generate_regression_report(results)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"tests/memory/performance_regression_report_{timestamp}.md"
        
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, 'w') as f:
            f.write(report)
        
        # Save detailed results
        results_data = [asdict(r) for r in results]
        results_path = f"tests/memory/performance_regression_results_{timestamp}.json"
        with open(results_path, 'w') as f:
            json.dump(results_data, f, indent=2, default=str)
        
        print(f"\n✅ Performance regression testing complete!")
        print(f"📄 Report: {report_path}")
        print(f"📊 Results: {results_path}")
        
        # Overall assertions
        critical_regressions = sum(1 for r in results if r.regression_severity == "critical")
        assert critical_regressions == 0, f"Critical regressions detected in {critical_regressions} components"
        
        return results
    
    def _generate_regression_report(self, results: List[RegressionTestResult]) -> str:
        """Generate comprehensive regression report"""
        report = []
        report.append("# Memory Performance Regression Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        
        # Summary
        report.append("\n## Executive Summary")
        total_tests = len(results)
        regressions = sum(1 for r in results if r.regression_detected)
        improvements = sum(1 for r in results if r.improvement_detected)
        critical_issues = sum(1 for r in results if r.regression_severity == "critical")
        
        report.append(f"- **Total Components Tested**: {total_tests}")
        report.append(f"- **Regressions Detected**: {regressions}")
        report.append(f"- **Improvements Detected**: {improvements}")
        report.append(f"- **Critical Issues**: {critical_issues}")
        
        if critical_issues > 0:
            report.append("\n⚠️ **CRITICAL**: Immediate attention required!")
        elif regressions > 0:
            report.append("\n⚠️ **WARNING**: Performance regressions detected")
        else:
            report.append("\n✅ **GOOD**: No significant regressions detected")
        
        # Detailed results
        report.append("\n## Detailed Results")
        
        for result in results:
            report.append(f"\n### {result.component_name} - {result.test_name}")
            report.append(f"- **Regression Detected**: {result.regression_detected}")
            report.append(f"- **Improvement Detected**: {result.improvement_detected}")
            report.append(f"- **Severity**: {result.regression_severity}")
            report.append(f"- **Confidence**: {result.confidence_level:.2f}")
            
            if result.performance_change:
                report.append("- **Performance Changes**:")
                for metric, change in result.performance_change.items():
                    report.append(f"  - {metric}: {change*100:+.1f}%")
            
            report.append("- **Recommendations**:")
            for rec in result.recommendations:
                report.append(f"  - {rec}")
        
        return "\n".join(report)


async def run_regression_testing():
    """Run performance regression testing suite"""
    tester = TestMemoryPerformanceRegression()
    return await tester.test_comprehensive_performance_regression()


if __name__ == "__main__":
    # Run regression testing
    asyncio.run(run_regression_testing())