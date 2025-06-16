"""
Performance test fixtures for Claude Optimized Deployment.

This module provides specialized fixtures for performance testing,
including benchmarking utilities, resource monitoring, and regression detection.
"""

import pytest
import time
import psutil
import threading
import json
import statistics
from typing import Dict, Any, List, Optional, Callable
from unittest.mock import Mock, AsyncMock
from dataclasses import dataclass, asdict
import asyncio
from pathlib import Path


@dataclass
class PerformanceMetrics:
    """Performance metrics for a test run."""
    duration: float
    cpu_usage: float
    memory_usage: float
    memory_peak: float
    throughput: Optional[float] = None
    latency: Optional[float] = None
    error_rate: Optional[float] = None


@dataclass
class BenchmarkResult:
    """Benchmark result with statistical analysis."""
    name: str
    mean: float
    median: float
    std_dev: float
    min_time: float
    max_time: float
    iterations: int
    samples: List[float]


@pytest.fixture
def performance_monitor():
    """Monitor system resources during test execution."""
    class PerformanceMonitor:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.cpu_samples = []
            self.memory_samples = []
            self.monitoring = False
            self.monitor_thread = None
            self.interval = 0.1  # Sample every 100ms
        
        def start(self):
            """Start monitoring system resources."""
            self.start_time = time.time()
            self.monitoring = True
            self.cpu_samples = []
            self.memory_samples = []
            self.monitor_thread = threading.Thread(target=self._monitor_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
        
        def stop(self):
            """Stop monitoring and return metrics."""
            self.end_time = time.time()
            self.monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=1.0)
            
            return self.get_metrics()
        
        def _monitor_loop(self):
            """Monitor loop running in separate thread."""
            while self.monitoring:
                try:
                    self.cpu_samples.append(psutil.cpu_percent())
                    self.memory_samples.append(psutil.virtual_memory().percent)
                    time.sleep(self.interval)
                except Exception:
                    break
        
        def get_metrics(self) -> PerformanceMetrics:
            """Get performance metrics."""
            duration = self.end_time - self.start_time if self.end_time else 0
            
            return PerformanceMetrics(
                duration=duration,
                cpu_usage=statistics.mean(self.cpu_samples) if self.cpu_samples else 0,
                memory_usage=statistics.mean(self.memory_samples) if self.memory_samples else 0,
                memory_peak=max(self.memory_samples) if self.memory_samples else 0
            )
    
    return PerformanceMonitor()


@pytest.fixture
def benchmark_runner():
    """Utility for running performance benchmarks."""
    class BenchmarkRunner:
        def __init__(self):
            self.results = []
        
        def run_benchmark(self, name: str, func: Callable, iterations: int = 100, 
                         warmup: int = 10) -> BenchmarkResult:
            """Run a benchmark and collect timing data."""
            # Warmup runs
            for _ in range(warmup):
                func()
            
            # Actual benchmark runs
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                func()
                end = time.perf_counter()
                times.append(end - start)
            
            result = BenchmarkResult(
                name=name,
                mean=statistics.mean(times),
                median=statistics.median(times),
                std_dev=statistics.stdev(times) if len(times) > 1 else 0,
                min_time=min(times),
                max_time=max(times),
                iterations=iterations,
                samples=times
            )
            
            self.results.append(result)
            return result
        
        async def run_async_benchmark(self, name: str, async_func: Callable, 
                                    iterations: int = 100, warmup: int = 10) -> BenchmarkResult:
            """Run an async benchmark."""
            # Warmup runs
            for _ in range(warmup):
                await async_func()
            
            # Actual benchmark runs
            times = []
            for _ in range(iterations):
                start = time.perf_counter()
                await async_func()
                end = time.perf_counter()
                times.append(end - start)
            
            result = BenchmarkResult(
                name=name,
                mean=statistics.mean(times),
                median=statistics.median(times),
                std_dev=statistics.stdev(times) if len(times) > 1 else 0,
                min_time=min(times),
                max_time=max(times),
                iterations=iterations,
                samples=times
            )
            
            self.results.append(result)
            return result
        
        def save_results(self, filepath: Path):
            """Save benchmark results to file."""
            data = [asdict(result) for result in self.results]
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        
        def load_baseline(self, filepath: Path) -> List[BenchmarkResult]:
            """Load baseline results for comparison."""
            if not filepath.exists():
                return []
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            return [BenchmarkResult(**item) for item in data]
    
    return BenchmarkRunner()


@pytest.fixture
def regression_detector():
    """Detect performance regressions by comparing against baseline."""
    class RegressionDetector:
        def __init__(self, threshold_percent: float = 10.0):
            self.threshold_percent = threshold_percent
        
        def check_regression(self, current: BenchmarkResult, 
                           baseline: BenchmarkResult) -> Dict[str, Any]:
            """Check if current result shows regression compared to baseline."""
            if current.name != baseline.name:
                raise ValueError("Cannot compare different benchmarks")
            
            # Calculate percentage change
            percent_change = ((current.mean - baseline.mean) / baseline.mean) * 100
            
            # Determine if this is a regression
            is_regression = percent_change > self.threshold_percent
            is_improvement = percent_change < -self.threshold_percent
            
            return {
                "benchmark_name": current.name,
                "current_mean": current.mean,
                "baseline_mean": baseline.mean,
                "percent_change": percent_change,
                "is_regression": is_regression,
                "is_improvement": is_improvement,
                "threshold_percent": self.threshold_percent,
                "verdict": "REGRESSION" if is_regression else "IMPROVEMENT" if is_improvement else "STABLE"
            }
        
        def batch_check(self, current_results: List[BenchmarkResult], 
                       baseline_results: List[BenchmarkResult]) -> List[Dict[str, Any]]:
            """Check multiple benchmarks for regressions."""
            baseline_by_name = {r.name: r for r in baseline_results}
            results = []
            
            for current in current_results:
                if current.name in baseline_by_name:
                    result = self.check_regression(current, baseline_by_name[current.name])
                    results.append(result)
                else:
                    results.append({
                        "benchmark_name": current.name,
                        "current_mean": current.mean,
                        "baseline_mean": None,
                        "percent_change": None,
                        "is_regression": False,
                        "is_improvement": False,
                        "verdict": "NEW_BENCHMARK"
                    })
            
            return results
    
    return RegressionDetector()


@pytest.fixture
def load_test_executor():
    """Execute load tests with configurable parameters."""
    class LoadTestExecutor:
        def __init__(self):
            self.results = []
        
        async def execute_load_test(self, target_func: Callable, 
                                  concurrent_users: int = 10, 
                                  duration_seconds: int = 30, 
                                  ramp_up_seconds: int = 5) -> Dict[str, Any]:
            """Execute a load test against a target function."""
            start_time = time.time()
            end_time = start_time + duration_seconds
            ramp_up_end = start_time + ramp_up_seconds
            
            results = []
            errors = []
            active_tasks = set()
            
            async def worker():
                while time.time() < end_time:
                    try:
                        request_start = time.perf_counter()
                        await target_func()
                        request_end = time.perf_counter()
                        results.append(request_end - request_start)
                    except Exception as e:
                        errors.append(str(e))
                    
                    # Small delay to prevent overwhelming
                    await asyncio.sleep(0.01)
            
            # Ramp up users gradually
            current_users = 0
            while time.time() < ramp_up_end and current_users < concurrent_users:
                task = asyncio.create_task(worker())
                active_tasks.add(task)
                current_users += 1
                
                # Calculate delay for even ramp-up
                users_per_second = concurrent_users / ramp_up_seconds
                delay = 1.0 / users_per_second
                await asyncio.sleep(delay)
            
            # Add remaining users immediately
            while current_users < concurrent_users:
                task = asyncio.create_task(worker())
                active_tasks.add(task)
                current_users += 1
            
            # Wait for test duration to complete
            await asyncio.sleep(max(0, end_time - time.time()))
            
            # Cancel all tasks
            for task in active_tasks:
                task.cancel()
            
            # Wait for cancellation
            await asyncio.gather(*active_tasks, return_exceptions=True)
            
            # Calculate metrics
            total_requests = len(results)
            error_count = len(errors)
            error_rate = error_count / (total_requests + error_count) if (total_requests + error_count) > 0 else 0
            
            return {
                "concurrent_users": concurrent_users,
                "duration_seconds": duration_seconds,
                "total_requests": total_requests,
                "error_count": error_count,
                "error_rate": error_rate,
                "requests_per_second": total_requests / duration_seconds,
                "avg_response_time": statistics.mean(results) if results else 0,
                "median_response_time": statistics.median(results) if results else 0,
                "p95_response_time": self._percentile(results, 95) if results else 0,
                "p99_response_time": self._percentile(results, 99) if results else 0,
                "min_response_time": min(results) if results else 0,
                "max_response_time": max(results) if results else 0,
                "errors": errors[:10]  # First 10 errors for debugging
            }
        
        def _percentile(self, data: List[float], percentile: float) -> float:
            """Calculate percentile value."""
            if not data:
                return 0
            sorted_data = sorted(data)
            index = int((percentile / 100) * len(sorted_data))
            return sorted_data[min(index, len(sorted_data) - 1)]
    
    return LoadTestExecutor()


@pytest.fixture
def memory_profiler():
    """Profile memory usage during test execution."""
    class MemoryProfiler:
        def __init__(self):
            self.process = psutil.Process()
            self.baseline_memory = None
            self.peak_memory = None
            self.memory_samples = []
            self.monitoring = False
            self.monitor_thread = None
        
        def start_profiling(self):
            """Start memory profiling."""
            self.baseline_memory = self.process.memory_info().rss
            self.peak_memory = self.baseline_memory
            self.memory_samples = []
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_memory)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
        
        def stop_profiling(self) -> Dict[str, Any]:
            """Stop profiling and return memory metrics."""
            self.monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=1.0)
            
            current_memory = self.process.memory_info().rss
            memory_increase = current_memory - self.baseline_memory
            
            return {
                "baseline_memory_mb": self.baseline_memory / (1024 * 1024),
                "current_memory_mb": current_memory / (1024 * 1024),
                "peak_memory_mb": self.peak_memory / (1024 * 1024),
                "memory_increase_mb": memory_increase / (1024 * 1024),
                "memory_samples": len(self.memory_samples),
                "avg_memory_mb": statistics.mean(self.memory_samples) / (1024 * 1024) if self.memory_samples else 0
            }
        
        def _monitor_memory(self):
            """Monitor memory usage in background thread."""
            while self.monitoring:
                try:
                    memory = self.process.memory_info().rss
                    self.memory_samples.append(memory)
                    self.peak_memory = max(self.peak_memory, memory)
                    time.sleep(0.1)
                except Exception:
                    break
    
    return MemoryProfiler()


@pytest.fixture
def performance_thresholds():
    """Define performance thresholds for different types of operations."""
    return {
        "api_response_time": 0.1,  # 100ms
        "database_query": 0.05,    # 50ms
        "cache_access": 0.001,     # 1ms
        "file_operation": 0.01,    # 10ms
        "network_request": 0.5,    # 500ms
        "cpu_usage_percent": 80,
        "memory_usage_mb": 512,
        "throughput_rps": 1000     # requests per second
    }


@pytest.fixture
def mock_performance_data():
    """Generate mock performance data for testing."""
    import random
    
    def generate_response_times(count: int = 100, mean: float = 0.1, std_dev: float = 0.02) -> List[float]:
        """Generate realistic response time data."""
        return [max(0.001, random.gauss(mean, std_dev)) for _ in range(count)]
    
    def generate_throughput_data(duration: int = 60, base_rps: int = 100) -> List[int]:
        """Generate throughput data over time."""
        return [base_rps + random.randint(-20, 20) for _ in range(duration)]
    
    return {
        "response_times": generate_response_times,
        "throughput_data": generate_throughput_data
    }


@pytest.fixture(scope="session")
def performance_baseline_dir(tmp_path_factory):
    """Directory for storing performance baseline data."""
    return tmp_path_factory.mktemp("performance_baselines")


@pytest.fixture
def performance_assertion():
    """Assertion utilities for performance tests."""
    class PerformanceAssertion:
        def __init__(self, thresholds: Dict[str, float]):
            self.thresholds = thresholds
        
        def assert_response_time(self, actual: float, operation: str = "api_response_time"):
            """Assert that response time is within threshold."""
            threshold = self.thresholds.get(operation, 1.0)
            assert actual <= threshold, f"Response time {actual:.3f}s exceeds threshold {threshold:.3f}s for {operation}"
        
        def assert_throughput(self, actual: float, min_throughput: str = "throughput_rps"):
            """Assert that throughput meets minimum requirement."""
            threshold = self.thresholds.get(min_throughput, 100)
            assert actual >= threshold, f"Throughput {actual:.1f} RPS below minimum {threshold} RPS"
        
        def assert_memory_usage(self, actual_mb: float):
            """Assert that memory usage is within limits."""
            threshold = self.thresholds.get("memory_usage_mb", 1024)
            assert actual_mb <= threshold, f"Memory usage {actual_mb:.1f}MB exceeds threshold {threshold}MB"
        
        def assert_cpu_usage(self, actual_percent: float):
            """Assert that CPU usage is within limits."""
            threshold = self.thresholds.get("cpu_usage_percent", 90)
            assert actual_percent <= threshold, f"CPU usage {actual_percent:.1f}% exceeds threshold {threshold}%"
    
    return PerformanceAssertion


# Auto-apply performance monitoring to all performance tests
@pytest.fixture(autouse=True)
def auto_performance_monitor(request, performance_monitor):
    """Automatically monitor performance for tests marked with @pytest.mark.performance."""
    if request.node.get_closest_marker("performance"):
        performance_monitor.start()
        yield
        metrics = performance_monitor.stop()
        
        # Store metrics in test node for later retrieval
        request.node.performance_metrics = metrics
    else:
        yield