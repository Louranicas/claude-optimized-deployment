#!/usr/bin/env python3
"""
Performance Regression Test Suite
Tracks performance metrics over time and alerts on regressions
"""

import pytest
import time
import json
import statistics
import psutil
import gc
import asyncio
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import sqlite3
import pickle


@dataclass
class PerformanceMetric:
    """Performance metric data"""
    name: str
    category: str
    value: float
    unit: str
    timestamp: str
    git_commit: Optional[str] = None
    environment: Optional[Dict] = None


class PerformanceBaseline:
    """Manages performance baselines and comparisons"""
    
    def __init__(self, db_path: Path = Path("performance_baselines.db")):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        """Initialize SQLite database for baselines"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    git_commit TEXT,
                    environment TEXT,
                    UNIQUE(name, category)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    git_commit TEXT,
                    environment TEXT
                )
            """)
            
    def save_metric(self, metric: PerformanceMetric):
        """Save a performance metric"""
        with sqlite3.connect(self.db_path) as conn:
            # Add to history
            conn.execute("""
                INSERT INTO history (name, category, value, unit, timestamp, git_commit, environment)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                metric.name, metric.category, metric.value, metric.unit,
                metric.timestamp, metric.git_commit,
                json.dumps(metric.environment) if metric.environment else None
            ))
            
            # Update baseline if better
            conn.execute("""
                INSERT OR REPLACE INTO baselines (name, category, value, unit, timestamp, git_commit, environment)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                metric.name, metric.category, metric.value, metric.unit,
                metric.timestamp, metric.git_commit,
                json.dumps(metric.environment) if metric.environment else None
            ))
            
    def get_baseline(self, name: str, category: str) -> Optional[Dict]:
        """Get baseline for a metric"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT value, unit, timestamp FROM baselines
                WHERE name = ? AND category = ?
            """, (name, category))
            
            row = cursor.fetchone()
            if row:
                return {
                    "value": row[0],
                    "unit": row[1],
                    "timestamp": row[2]
                }
        return None
        
    def check_regression(self, metric: PerformanceMetric, threshold: float = 0.1) -> Optional[Dict]:
        """Check if metric represents a regression"""
        baseline = self.get_baseline(metric.name, metric.category)
        
        if not baseline:
            return None
            
        baseline_value = baseline["value"]
        
        # Calculate percentage change
        if baseline_value > 0:
            change = (metric.value - baseline_value) / baseline_value
            
            # For time-based metrics, increase is bad
            if metric.unit in ["seconds", "ms", "us"]:
                if change > threshold:
                    return {
                        "regression": True,
                        "baseline": baseline_value,
                        "current": metric.value,
                        "change_percent": change * 100,
                        "threshold_percent": threshold * 100
                    }
            # For throughput metrics, decrease is bad
            elif metric.unit in ["ops/sec", "MB/s", "requests/sec"]:
                if change < -threshold:
                    return {
                        "regression": True,
                        "baseline": baseline_value,
                        "current": metric.value,
                        "change_percent": change * 100,
                        "threshold_percent": threshold * 100
                    }
                    
        return None


class PerformanceProfiler:
    """Profile code performance with multiple metrics"""
    
    def __init__(self):
        self.baseline_db = PerformanceBaseline()
        
    def measure_function(self, func, *args, **kwargs) -> Dict:
        """Measure function performance"""
        # Warm up
        for _ in range(3):
            func(*args, **kwargs)
            
        # Force garbage collection
        gc.collect()
        gc.disable()
        
        # Measure memory before
        process = psutil.Process()
        mem_before = process.memory_info().rss
        
        # Measure execution time
        times = []
        for _ in range(10):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            end = time.perf_counter()
            times.append(end - start)
            
        gc.enable()
        gc.collect()
        
        # Measure memory after
        mem_after = process.memory_info().rss
        
        return {
            "result": result,
            "min_time": min(times),
            "max_time": max(times),
            "mean_time": statistics.mean(times),
            "median_time": statistics.median(times),
            "stddev_time": statistics.stdev(times) if len(times) > 1 else 0,
            "memory_used": mem_after - mem_before,
            "iterations": len(times)
        }


@pytest.mark.performance
class TestCorePerformance:
    """Core performance regression tests"""
    
    @pytest.fixture(autouse=True)
    def setup_profiler(self):
        self.profiler = PerformanceProfiler()
        self.baseline_db = PerformanceBaseline()
        
    def test_startup_time(self):
        """Test application startup time"""
        def startup():
            # Simulate app startup
            import src
            from src import create_app
            app = create_app()
            return app
            
        metrics = self.profiler.measure_function(startup)
        
        metric = PerformanceMetric(
            name="app_startup",
            category="core",
            value=metrics["mean_time"],
            unit="seconds",
            timestamp=datetime.now().isoformat()
        )
        
        # Check for regression
        regression = self.baseline_db.check_regression(metric)
        if regression:
            pytest.fail(f"Startup time regression: {regression}")
            
        # Save metric
        self.baseline_db.save_metric(metric)
        
    def test_api_response_time(self):
        """Test API endpoint response times"""
        from fastapi.testclient import TestClient
        from src import create_app
        
        app = create_app()
        client = TestClient(app)
        
        endpoints = [
            ("/health", "GET"),
            ("/api/v1/status", "GET"),
            ("/api/v1/experts", "GET"),
        ]
        
        for endpoint, method in endpoints:
            def make_request():
                return client.request(method, endpoint)
                
            metrics = self.profiler.measure_function(make_request)
            
            metric = PerformanceMetric(
                name=f"api_{endpoint}",
                category="api",
                value=metrics["mean_time"] * 1000,  # Convert to ms
                unit="ms",
                timestamp=datetime.now().isoformat()
            )
            
            regression = self.baseline_db.check_regression(metric, threshold=0.2)
            if regression:
                pytest.fail(f"API response time regression for {endpoint}: {regression}")
                
            self.baseline_db.save_metric(metric)


@pytest.mark.performance
class TestConcurrencyPerformance:
    """Test concurrent operation performance"""
    
    @pytest.fixture(autouse=True)
    def setup_profiler(self):
        self.profiler = PerformanceProfiler()
        self.baseline_db = PerformanceBaseline()
        
    def test_thread_pool_performance(self):
        """Test thread pool executor performance"""
        def cpu_bound_task(n):
            total = 0
            for i in range(n):
                total += i ** 2
            return total
            
        def run_concurrent():
            with ThreadPoolExecutor(max_workers=12) as executor:
                futures = []
                for _ in range(100):
                    futures.append(executor.submit(cpu_bound_task, 10000))
                results = [f.result() for f in futures]
                return results
                
        metrics = self.profiler.measure_function(run_concurrent)
        
        metric = PerformanceMetric(
            name="thread_pool_100_tasks",
            category="concurrency",
            value=metrics["mean_time"],
            unit="seconds",
            timestamp=datetime.now().isoformat()
        )
        
        regression = self.baseline_db.check_regression(metric)
        if regression:
            pytest.fail(f"Thread pool performance regression: {regression}")
            
        self.baseline_db.save_metric(metric)
        
    @pytest.mark.asyncio
    async def test_async_performance(self):
        """Test async operation performance"""
        async def async_task(delay):
            await asyncio.sleep(delay)
            return delay
            
        async def run_async_tasks():
            tasks = []
            for i in range(100):
                tasks.append(async_task(0.001))
            results = await asyncio.gather(*tasks)
            return results
            
        start = time.perf_counter()
        results = await run_async_tasks()
        duration = time.perf_counter() - start
        
        metric = PerformanceMetric(
            name="async_100_tasks",
            category="concurrency",
            value=duration,
            unit="seconds",
            timestamp=datetime.now().isoformat()
        )
        
        # Should complete in ~0.1 seconds (100 * 0.001), not 100 seconds
        assert duration < 0.5, f"Async tasks took too long: {duration}s"
        
        self.baseline_db.save_metric(metric)


@pytest.mark.performance
@pytest.mark.memory
class TestMemoryPerformance:
    """Test memory usage and leak detection"""
    
    @pytest.fixture(autouse=True)
    def setup_profiler(self):
        self.profiler = PerformanceProfiler()
        self.baseline_db = PerformanceBaseline()
        
    def test_memory_allocation_performance(self):
        """Test memory allocation performance"""
        def allocate_memory():
            # Allocate 100MB
            data = bytearray(100 * 1024 * 1024)
            # Do some operations
            for i in range(0, len(data), 1024):
                data[i] = i % 256
            return len(data)
            
        metrics = self.profiler.measure_function(allocate_memory)
        
        metric = PerformanceMetric(
            name="memory_allocation_100mb",
            category="memory",
            value=metrics["mean_time"],
            unit="seconds",
            timestamp=datetime.now().isoformat()
        )
        
        regression = self.baseline_db.check_regression(metric)
        if regression:
            pytest.fail(f"Memory allocation performance regression: {regression}")
            
        self.baseline_db.save_metric(metric)
        
    def test_garbage_collection_impact(self):
        """Test garbage collection performance impact"""
        def create_garbage():
            # Create many small objects
            objects = []
            for i in range(100000):
                objects.append({"id": i, "data": f"object_{i}" * 10})
            return len(objects)
            
        # Test with GC enabled
        gc.enable()
        metrics_with_gc = self.profiler.measure_function(create_garbage)
        
        # Test with GC disabled
        gc.disable()
        metrics_without_gc = self.profiler.measure_function(create_garbage)
        gc.enable()
        
        gc_overhead = metrics_with_gc["mean_time"] - metrics_without_gc["mean_time"]
        gc_overhead_percent = (gc_overhead / metrics_without_gc["mean_time"]) * 100
        
        metric = PerformanceMetric(
            name="gc_overhead_percent",
            category="memory",
            value=gc_overhead_percent,
            unit="percent",
            timestamp=datetime.now().isoformat()
        )
        
        # GC overhead should be reasonable (< 20%)
        assert gc_overhead_percent < 20, f"GC overhead too high: {gc_overhead_percent}%"
        
        self.baseline_db.save_metric(metric)


@pytest.mark.performance
class TestDataProcessingPerformance:
    """Test data processing performance"""
    
    @pytest.fixture(autouse=True)
    def setup_profiler(self):
        self.profiler = PerformanceProfiler()
        self.baseline_db = PerformanceBaseline()
        
    def test_json_serialization_performance(self):
        """Test JSON serialization performance"""
        import json
        
        # Create test data
        data = {
            "users": [
                {
                    "id": i,
                    "name": f"user_{i}",
                    "email": f"user_{i}@example.com",
                    "metadata": {"score": i * 1.5, "tags": [f"tag_{j}" for j in range(10)]}
                }
                for i in range(10000)
            ]
        }
        
        def serialize():
            return json.dumps(data)
            
        metrics = self.profiler.measure_function(serialize)
        
        metric = PerformanceMetric(
            name="json_serialize_10k_objects",
            category="serialization",
            value=metrics["mean_time"],
            unit="seconds",
            timestamp=datetime.now().isoformat()
        )
        
        regression = self.baseline_db.check_regression(metric)
        if regression:
            pytest.fail(f"JSON serialization regression: {regression}")
            
        self.baseline_db.save_metric(metric)
        
    def test_data_transformation_performance(self):
        """Test data transformation performance"""
        # Create test dataframe
        data = {
            "id": list(range(100000)),
            "value": np.random.randn(100000),
            "category": np.random.choice(["A", "B", "C"], 100000)
        }
        
        def transform_data():
            # Group by category and calculate statistics
            result = {}
            for cat in ["A", "B", "C"]:
                mask = [c == cat for c in data["category"]]
                values = [v for v, m in zip(data["value"], mask) if m]
                result[cat] = {
                    "count": len(values),
                    "mean": statistics.mean(values) if values else 0,
                    "std": statistics.stdev(values) if len(values) > 1 else 0
                }
            return result
            
        metrics = self.profiler.measure_function(transform_data)
        
        metric = PerformanceMetric(
            name="data_transform_100k_rows",
            category="data_processing",
            value=metrics["mean_time"],
            unit="seconds",
            timestamp=datetime.now().isoformat()
        )
        
        regression = self.baseline_db.check_regression(metric)
        if regression:
            pytest.fail(f"Data transformation regression: {regression}")
            
        self.baseline_db.save_metric(metric)


@pytest.mark.performance
@pytest.mark.rust
class TestRustIntegrationPerformance:
    """Test Rust integration performance"""
    
    @pytest.fixture(autouse=True)
    def setup_profiler(self):
        self.profiler = PerformanceProfiler()
        self.baseline_db = PerformanceBaseline()
        
    def test_ffi_overhead(self):
        """Test FFI call overhead"""
        try:
            from claude_deployment import _rust_core
        except ImportError:
            pytest.skip("Rust core not available")
            
        def call_rust():
            return _rust_core.add_integers(42, 58)
            
        metrics = self.profiler.measure_function(call_rust)
        
        # FFI overhead should be minimal (< 1 microsecond)
        assert metrics["mean_time"] < 0.000001, f"FFI overhead too high: {metrics['mean_time']}s"
        
        metric = PerformanceMetric(
            name="ffi_call_overhead",
            category="rust",
            value=metrics["mean_time"] * 1_000_000,  # Convert to microseconds
            unit="us",
            timestamp=datetime.now().isoformat()
        )
        
        self.baseline_db.save_metric(metric)
        
    def test_rust_computation_speedup(self):
        """Test Rust computation speedup vs Python"""
        # Python implementation
        def python_compute(n):
            total = 0
            for i in range(n):
                total += i * i
            return total
            
        # Rust implementation
        try:
            from claude_deployment import _rust_core
            rust_compute = _rust_core.compute_sum_of_squares
        except ImportError:
            pytest.skip("Rust core not available")
            
        n = 1_000_000
        
        python_metrics = self.profiler.measure_function(python_compute, n)
        rust_metrics = self.profiler.measure_function(rust_compute, n)
        
        speedup = python_metrics["mean_time"] / rust_metrics["mean_time"]
        
        metric = PerformanceMetric(
            name="rust_speedup_factor",
            category="rust",
            value=speedup,
            unit="x",
            timestamp=datetime.now().isoformat()
        )
        
        # Rust should be at least 10x faster for this operation
        assert speedup > 10, f"Rust speedup insufficient: {speedup}x"
        
        self.baseline_db.save_metric(metric)


def generate_performance_report():
    """Generate comprehensive performance report"""
    baseline_db = PerformanceBaseline()
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "categories": {},
        "regressions": [],
        "improvements": []
    }
    
    # Query all current baselines
    with sqlite3.connect(baseline_db.db_path) as conn:
        cursor = conn.execute("""
            SELECT name, category, value, unit, timestamp
            FROM baselines
            ORDER BY category, name
        """)
        
        for row in cursor:
            name, category, value, unit, timestamp = row
            
            if category not in report["categories"]:
                report["categories"][category] = []
                
            report["categories"][category].append({
                "name": name,
                "value": value,
                "unit": unit,
                "timestamp": timestamp
            })
    
    # Save report
    report_path = Path("performance_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
        
    print(f"Performance report saved to: {report_path}")
    
    # Print summary
    print("\nPerformance Summary:")
    print("=" * 60)
    
    for category, metrics in report["categories"].items():
        print(f"\n{category.upper()}:")
        for metric in metrics:
            print(f"  {metric['name']}: {metric['value']:.4f} {metric['unit']}")


if __name__ == "__main__":
    # Run performance tests
    exit_code = pytest.main([
        __file__,
        "-v",
        "--benchmark-only",
        "-m", "performance",
    ])
    
    # Generate report
    generate_performance_report()
    
    exit(exit_code)