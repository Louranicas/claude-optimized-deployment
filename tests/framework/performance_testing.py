"""
Performance Testing and Benchmarking Framework

This module provides comprehensive performance testing capabilities including
hardware-optimized benchmarking, memory profiling, and performance regression detection.
"""

import asyncio
import gc
import json
import multiprocessing
import os
import statistics
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union
import logging

import psutil
import numpy as np
try:
    import uvloop
except ImportError:
    uvloop = None

logger = logging.getLogger(__name__)


class BenchmarkType(Enum):
    """Benchmark type enumeration."""
    CPU_INTENSIVE = "cpu_intensive"
    MEMORY_INTENSIVE = "memory_intensive"
    IO_INTENSIVE = "io_intensive"
    NETWORK_INTENSIVE = "network_intensive"
    MIXED_WORKLOAD = "mixed_workload"
    CONCURRENT = "concurrent"


class PerformanceMetric(Enum):
    """Performance metrics to track."""
    THROUGHPUT = "throughput"
    LATENCY = "latency"
    MEMORY_USAGE = "memory_usage"
    CPU_USAGE = "cpu_usage"
    CACHE_HITS = "cache_hits"
    CACHE_MISSES = "cache_misses"
    GC_TIME = "gc_time"
    THREAD_COUNT = "thread_count"


@dataclass
class HardwareSpecs:
    """System hardware specifications."""
    cpu_count: int
    cpu_freq_mhz: float
    memory_total_gb: float
    memory_available_gb: float
    disk_type: str  # SSD, HDD, NVMe
    disk_size_gb: float
    network_bandwidth_mbps: float
    
    @classmethod
    def detect_system_specs(cls) -> 'HardwareSpecs':
        """Auto-detect system hardware specifications."""
        cpu_info = psutil.cpu_freq()
        memory_info = psutil.virtual_memory()
        disk_info = psutil.disk_usage('/')
        
        return cls(
            cpu_count=psutil.cpu_count(),
            cpu_freq_mhz=cpu_info.current if cpu_info else 0.0,
            memory_total_gb=memory_info.total / (1024 ** 3),
            memory_available_gb=memory_info.available / (1024 ** 3),
            disk_type="NVMe",  # Assume NVMe SSD based on project specs
            disk_size_gb=disk_info.total / (1024 ** 3),
            network_bandwidth_mbps=1000.0  # Assume gigabit
        )


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark execution."""
    name: str
    benchmark_type: BenchmarkType
    iterations: int = 1000
    warmup_iterations: int = 100
    threads: int = 1
    processes: int = 1
    timeout_seconds: int = 300
    memory_limit_mb: int = 8192
    cpu_affinity: Optional[List[int]] = None
    use_all_cores: bool = False
    collect_detailed_metrics: bool = True


@dataclass
class BenchmarkResult:
    """Results from benchmark execution."""
    config: BenchmarkConfig
    success: bool
    start_time: datetime
    end_time: datetime
    total_duration_seconds: float
    iterations_completed: int
    
    # Performance metrics
    throughput_ops_per_sec: float
    avg_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    
    # Resource usage
    peak_memory_mb: float
    avg_memory_mb: float
    peak_cpu_percent: float
    avg_cpu_percent: float
    
    # Detailed metrics
    detailed_metrics: Dict[str, List[float]] = field(default_factory=dict)
    system_info: Optional[HardwareSpecs] = None
    error_message: Optional[str] = None


class SystemResourceMonitor:
    """Real-time system resource monitoring."""
    
    def __init__(self, interval_seconds: float = 0.1):
        self.interval_seconds = interval_seconds
        self.monitoring = False
        self.measurements = []
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start resource monitoring."""
        self.monitoring = True
        self.measurements = []
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
    
    def _monitor_loop(self):
        """Resource monitoring loop."""
        process = psutil.Process()
        
        while self.monitoring:
            try:
                # CPU usage
                cpu_percent = process.cpu_percent()
                system_cpu_percent = psutil.cpu_percent(interval=None)
                
                # Memory usage
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)
                
                # System memory
                system_memory = psutil.virtual_memory()
                system_memory_percent = system_memory.percent
                
                # Disk I/O
                disk_io = psutil.disk_io_counters()
                
                # Network I/O
                network_io = psutil.net_io_counters()
                
                measurement = {
                    'timestamp': time.time(),
                    'cpu_percent': cpu_percent,
                    'system_cpu_percent': system_cpu_percent,
                    'memory_mb': memory_mb,
                    'system_memory_percent': system_memory_percent,
                    'disk_read_mb': disk_io.read_bytes / (1024 * 1024) if disk_io else 0,
                    'disk_write_mb': disk_io.write_bytes / (1024 * 1024) if disk_io else 0,
                    'network_sent_mb': network_io.bytes_sent / (1024 * 1024) if network_io else 0,
                    'network_recv_mb': network_io.bytes_recv / (1024 * 1024) if network_io else 0,
                    'thread_count': threading.active_count(),
                }
                
                self.measurements.append(measurement)
                
                # Keep only last 10000 measurements to prevent memory issues
                if len(self.measurements) > 10000:
                    self.measurements = self.measurements[-5000:]
                
                time.sleep(self.interval_seconds)
                
            except Exception as e:
                logger.warning(f"Resource monitoring error: {e}")
                break
    
    def get_peak_values(self) -> Dict[str, float]:
        """Get peak resource usage values."""
        if not self.measurements:
            return {}
        
        return {
            'peak_cpu_percent': max(m['cpu_percent'] for m in self.measurements),
            'peak_memory_mb': max(m['memory_mb'] for m in self.measurements),
            'peak_system_cpu_percent': max(m['system_cpu_percent'] for m in self.measurements),
            'peak_system_memory_percent': max(m['system_memory_percent'] for m in self.measurements),
        }
    
    def get_average_values(self) -> Dict[str, float]:
        """Get average resource usage values."""
        if not self.measurements:
            return {}
        
        return {
            'avg_cpu_percent': statistics.mean(m['cpu_percent'] for m in self.measurements),
            'avg_memory_mb': statistics.mean(m['memory_mb'] for m in self.measurements),
            'avg_system_cpu_percent': statistics.mean(m['system_cpu_percent'] for m in self.measurements),
            'avg_system_memory_percent': statistics.mean(m['system_memory_percent'] for m in self.measurements),
        }


class PerformanceBenchmark:
    """Base class for performance benchmarks."""
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self.resource_monitor = SystemResourceMonitor()
        
    async def run(self) -> BenchmarkResult:
        """Run the benchmark."""
        logger.info(f"Starting benchmark: {self.config.name}")
        
        system_info = HardwareSpecs.detect_system_specs()
        start_time = datetime.now()
        
        result = BenchmarkResult(
            config=self.config,
            success=False,
            start_time=start_time,
            end_time=start_time,
            total_duration_seconds=0.0,
            iterations_completed=0,
            throughput_ops_per_sec=0.0,
            avg_latency_ms=0.0,
            min_latency_ms=0.0,
            max_latency_ms=0.0,
            p50_latency_ms=0.0,
            p95_latency_ms=0.0,
            p99_latency_ms=0.0,
            peak_memory_mb=0.0,
            avg_memory_mb=0.0,
            peak_cpu_percent=0.0,
            avg_cpu_percent=0.0,
            system_info=system_info
        )
        
        try:
            # Set CPU affinity if specified
            if self.config.cpu_affinity:
                os.sched_setaffinity(0, self.config.cpu_affinity)
            elif self.config.use_all_cores:
                os.sched_setaffinity(0, range(psutil.cpu_count()))
            
            # Start resource monitoring
            self.resource_monitor.start_monitoring()
            
            # Warmup phase
            logger.info(f"Warmup phase: {self.config.warmup_iterations} iterations")
            await self._warmup()
            
            # Main benchmark execution
            logger.info(f"Main benchmark: {self.config.iterations} iterations")
            latencies = await self._execute_benchmark()
            
            # Calculate results
            end_time = datetime.now()
            total_duration = (end_time - start_time).total_seconds()
            
            if latencies:
                result.success = True
                result.iterations_completed = len(latencies)
                result.total_duration_seconds = total_duration
                result.throughput_ops_per_sec = len(latencies) / total_duration
                
                # Latency statistics
                latencies_ms = [lat * 1000 for lat in latencies]  # Convert to milliseconds
                result.avg_latency_ms = statistics.mean(latencies_ms)
                result.min_latency_ms = min(latencies_ms)
                result.max_latency_ms = max(latencies_ms)
                
                # Percentiles
                sorted_latencies = sorted(latencies_ms)
                result.p50_latency_ms = self._percentile(sorted_latencies, 50)
                result.p95_latency_ms = self._percentile(sorted_latencies, 95)
                result.p99_latency_ms = self._percentile(sorted_latencies, 99)
                
                # Resource usage
                peak_values = self.resource_monitor.get_peak_values()
                avg_values = self.resource_monitor.get_average_values()
                
                result.peak_memory_mb = peak_values.get('peak_memory_mb', 0.0)
                result.avg_memory_mb = avg_values.get('avg_memory_mb', 0.0)
                result.peak_cpu_percent = peak_values.get('peak_cpu_percent', 0.0)
                result.avg_cpu_percent = avg_values.get('avg_cpu_percent', 0.0)
                
                # Detailed metrics
                if self.config.collect_detailed_metrics:
                    result.detailed_metrics = {
                        'latencies_ms': latencies_ms,
                        'resource_measurements': self.resource_monitor.measurements
                    }
            
            result.end_time = end_time
            
        except Exception as e:
            result.error_message = str(e)
            logger.error(f"Benchmark {self.config.name} failed: {e}")
        
        finally:
            self.resource_monitor.stop_monitoring()
        
        logger.info(f"Benchmark {self.config.name} completed: {result.success}")
        return result
    
    async def _warmup(self):
        """Warmup phase to stabilize performance."""
        for _ in range(self.config.warmup_iterations):
            await self._single_operation()
            await asyncio.sleep(0.001)  # Small delay to prevent overwhelming
    
    async def _execute_benchmark(self) -> List[float]:
        """Execute main benchmark and return latencies."""
        latencies = []
        
        if self.config.threads > 1:
            # Multi-threaded execution
            latencies = await self._execute_threaded()
        elif self.config.processes > 1:
            # Multi-process execution
            latencies = await self._execute_multiprocess()
        else:
            # Single-threaded execution
            for i in range(self.config.iterations):
                start_time = time.perf_counter()
                await self._single_operation()
                end_time = time.perf_counter()
                latencies.append(end_time - start_time)
                
                # Periodic yielding for responsiveness
                if i % 100 == 0:
                    await asyncio.sleep(0.001)
        
        return latencies
    
    async def _execute_threaded(self) -> List[float]:
        """Execute benchmark with multiple threads."""
        latencies = []
        iterations_per_thread = self.config.iterations // self.config.threads
        
        def thread_worker():
            thread_latencies = []
            for _ in range(iterations_per_thread):
                start_time = time.perf_counter()
                # Run synchronous version of operation
                self._sync_single_operation()
                end_time = time.perf_counter()
                thread_latencies.append(end_time - start_time)
            return thread_latencies
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(thread_worker) for _ in range(self.config.threads)]
            
            for future in futures:
                thread_latencies = future.result()
                latencies.extend(thread_latencies)
        
        return latencies
    
    async def _execute_multiprocess(self) -> List[float]:
        """Execute benchmark with multiple processes."""
        latencies = []
        iterations_per_process = self.config.iterations // self.config.processes
        
        def process_worker():
            process_latencies = []
            for _ in range(iterations_per_process):
                start_time = time.perf_counter()
                # Run synchronous version of operation
                self._sync_single_operation()
                end_time = time.perf_counter()
                process_latencies.append(end_time - start_time)
            return process_latencies
        
        with ProcessPoolExecutor(max_workers=self.config.processes) as executor:
            futures = [executor.submit(process_worker) for _ in range(self.config.processes)]
            
            for future in futures:
                process_latencies = future.result()
                latencies.extend(process_latencies)
        
        return latencies
    
    async def _single_operation(self):
        """Single benchmark operation (to be overridden)."""
        raise NotImplementedError("Subclasses must implement _single_operation")
    
    def _sync_single_operation(self):
        """Synchronous version of single operation (to be overridden)."""
        raise NotImplementedError("Subclasses must implement _sync_single_operation")
    
    def _percentile(self, sorted_values: List[float], percentile: int) -> float:
        """Calculate percentile from sorted values."""
        if not sorted_values:
            return 0.0
        
        index = (percentile / 100.0) * (len(sorted_values) - 1)
        lower_index = int(index)
        upper_index = min(lower_index + 1, len(sorted_values) - 1)
        
        if lower_index == upper_index:
            return sorted_values[lower_index]
        
        weight = index - lower_index
        return sorted_values[lower_index] * (1 - weight) + sorted_values[upper_index] * weight


class CPUIntensiveBenchmark(PerformanceBenchmark):
    """CPU-intensive benchmark for testing computational performance."""
    
    def __init__(self, config: BenchmarkConfig, complexity: int = 1000):
        super().__init__(config)
        self.complexity = complexity
    
    async def _single_operation(self):
        """CPU-intensive operation."""
        # Fibonacci calculation (CPU intensive)
        result = self._fibonacci(self.complexity % 40)  # Cap to prevent excessive computation
        
        # Matrix multiplication (CPU intensive)
        if self.complexity > 100:
            a = np.random.rand(50, 50)
            b = np.random.rand(50, 50)
            result = np.dot(a, b)
        
        return result
    
    def _sync_single_operation(self):
        """Synchronous CPU-intensive operation."""
        result = self._fibonacci(self.complexity % 40)
        
        if self.complexity > 100:
            a = np.random.rand(50, 50)
            b = np.random.rand(50, 50)
            result = np.dot(a, b)
        
        return result
    
    def _fibonacci(self, n: int) -> int:
        """Calculate Fibonacci number (CPU intensive)."""
        if n <= 1:
            return n
        return self._fibonacci(n - 1) + self._fibonacci(n - 2)


class MemoryIntensiveBenchmark(PerformanceBenchmark):
    """Memory-intensive benchmark for testing memory allocation/access patterns."""
    
    def __init__(self, config: BenchmarkConfig, data_size_mb: int = 100):
        super().__init__(config)
        self.data_size_mb = data_size_mb
    
    async def _single_operation(self):
        """Memory-intensive operation."""
        # Allocate large array
        size = (self.data_size_mb * 1024 * 1024) // 8  # 8 bytes per float64
        data = np.random.rand(size)
        
        # Memory access patterns
        result = np.sum(data)  # Sequential access
        result += np.sum(data[::100])  # Strided access
        
        # Force garbage collection to test memory management
        del data
        gc.collect()
        
        return result
    
    def _sync_single_operation(self):
        """Synchronous memory-intensive operation."""
        size = (self.data_size_mb * 1024 * 1024) // 8
        data = np.random.rand(size)
        
        result = np.sum(data)
        result += np.sum(data[::100])
        
        del data
        gc.collect()
        
        return result


class IOIntensiveBenchmark(PerformanceBenchmark):
    """IO-intensive benchmark for testing disk performance."""
    
    def __init__(self, config: BenchmarkConfig, file_size_mb: int = 10):
        super().__init__(config)
        self.file_size_mb = file_size_mb
        self.temp_dir = Path("/tmp/benchmark_io")
        self.temp_dir.mkdir(exist_ok=True)
    
    async def _single_operation(self):
        """IO-intensive operation."""
        file_path = self.temp_dir / f"test_{time.time()}.dat"
        
        # Write data
        data = os.urandom(self.file_size_mb * 1024 * 1024)
        with open(file_path, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())  # Force write to disk
        
        # Read data back
        with open(file_path, 'rb') as f:
            read_data = f.read()
        
        # Cleanup
        file_path.unlink()
        
        return len(read_data)
    
    def _sync_single_operation(self):
        """Synchronous IO-intensive operation."""
        file_path = self.temp_dir / f"test_{time.time()}.dat"
        
        data = os.urandom(self.file_size_mb * 1024 * 1024)
        with open(file_path, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        
        with open(file_path, 'rb') as f:
            read_data = f.read()
        
        file_path.unlink()
        
        return len(read_data)


class ConcurrentBenchmark(PerformanceBenchmark):
    """Concurrent benchmark for testing parallel processing capabilities."""
    
    def __init__(self, config: BenchmarkConfig, concurrent_tasks: int = 100):
        super().__init__(config)
        self.concurrent_tasks = concurrent_tasks
    
    async def _single_operation(self):
        """Concurrent operation with multiple async tasks."""
        async def worker_task(task_id: int):
            # Simulate mixed workload
            await asyncio.sleep(0.001)  # IO simulation
            result = sum(i * i for i in range(1000))  # CPU simulation
            return result + task_id
        
        # Run multiple concurrent tasks
        tasks = [worker_task(i) for i in range(self.concurrent_tasks)]
        results = await asyncio.gather(*tasks)
        
        return sum(results)
    
    def _sync_single_operation(self):
        """Synchronous version using threads."""
        def worker_task(task_id: int):
            time.sleep(0.001)
            result = sum(i * i for i in range(1000))
            return result + task_id
        
        with ThreadPoolExecutor(max_workers=min(self.concurrent_tasks, 50)) as executor:
            futures = [executor.submit(worker_task, i) for i in range(self.concurrent_tasks)]
            results = [future.result() for future in futures]
        
        return sum(results)


class PerformanceTestSuite:
    """Comprehensive performance test suite."""
    
    def __init__(self, hardware_specs: Optional[HardwareSpecs] = None):
        self.hardware_specs = hardware_specs or HardwareSpecs.detect_system_specs()
        self.results: List[BenchmarkResult] = []
    
    async def run_comprehensive_suite(self) -> Dict[str, Any]:
        """Run comprehensive performance test suite."""
        logger.info("Starting comprehensive performance test suite")
        
        # Define benchmark configurations optimized for available hardware
        benchmarks = [
            # CPU-intensive benchmarks
            CPUIntensiveBenchmark(BenchmarkConfig(
                name="cpu_single_thread",
                benchmark_type=BenchmarkType.CPU_INTENSIVE,
                iterations=1000,
                threads=1,
                complexity=1000
            )),
            
            CPUIntensiveBenchmark(BenchmarkConfig(
                name="cpu_multi_thread",
                benchmark_type=BenchmarkType.CPU_INTENSIVE,
                iterations=2000,
                threads=min(self.hardware_specs.cpu_count, 8),
                use_all_cores=False,
                complexity=500
            )),
            
            CPUIntensiveBenchmark(BenchmarkConfig(
                name="cpu_all_cores",
                benchmark_type=BenchmarkType.CPU_INTENSIVE,
                iterations=5000,
                threads=self.hardware_specs.cpu_count,
                use_all_cores=True,
                complexity=200
            )),
            
            # Memory-intensive benchmarks
            MemoryIntensiveBenchmark(BenchmarkConfig(
                name="memory_small_allocations",
                benchmark_type=BenchmarkType.MEMORY_INTENSIVE,
                iterations=500,
                data_size_mb=10
            )),
            
            MemoryIntensiveBenchmark(BenchmarkConfig(
                name="memory_large_allocations",
                benchmark_type=BenchmarkType.MEMORY_INTENSIVE,
                iterations=100,
                data_size_mb=min(100, int(self.hardware_specs.memory_available_gb * 100))
            )),
            
            # IO-intensive benchmarks
            IOIntensiveBenchmark(BenchmarkConfig(
                name="io_small_files",
                benchmark_type=BenchmarkType.IO_INTENSIVE,
                iterations=200,
                file_size_mb=1
            )),
            
            IOIntensiveBenchmark(BenchmarkConfig(
                name="io_large_files",
                benchmark_type=BenchmarkType.IO_INTENSIVE,
                iterations=50,
                file_size_mb=50
            )),
            
            # Concurrent benchmarks
            ConcurrentBenchmark(BenchmarkConfig(
                name="concurrent_light",
                benchmark_type=BenchmarkType.CONCURRENT,
                iterations=100,
                concurrent_tasks=50
            )),
            
            ConcurrentBenchmark(BenchmarkConfig(
                name="concurrent_heavy",
                benchmark_type=BenchmarkType.CONCURRENT,
                iterations=20,
                concurrent_tasks=200
            )),
        ]
        
        # Run benchmarks
        for benchmark in benchmarks:
            try:
                result = await benchmark.run()
                self.results.append(result)
                
                logger.info(f"Benchmark {result.config.name}: "
                           f"{'PASS' if result.success else 'FAIL'} "
                           f"({result.throughput_ops_per_sec:.2f} ops/sec)")
                
            except Exception as e:
                logger.error(f"Benchmark {benchmark.config.name} failed: {e}")
        
        # Generate comprehensive report
        return self._generate_performance_report()
    
    def _generate_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        successful_results = [r for r in self.results if r.success]
        failed_results = [r for r in self.results if not r.success]
        
        # Performance summary by category
        categories = {}
        for result in successful_results:
            category = result.config.benchmark_type.value
            if category not in categories:
                categories[category] = []
            categories[category].append(result)
        
        category_summaries = {}
        for category, results in categories.items():
            category_summaries[category] = {
                'count': len(results),
                'avg_throughput': statistics.mean(r.throughput_ops_per_sec for r in results),
                'avg_latency_ms': statistics.mean(r.avg_latency_ms for r in results),
                'avg_memory_mb': statistics.mean(r.avg_memory_mb for r in results),
                'avg_cpu_percent': statistics.mean(r.avg_cpu_percent for r in results)
            }
        
        # Overall performance score (arbitrary scale)
        performance_score = 0
        if successful_results:
            # Normalize and weight different metrics
            throughput_score = min(100, statistics.mean(r.throughput_ops_per_sec for r in successful_results) / 10)
            latency_score = max(0, 100 - statistics.mean(r.avg_latency_ms for r in successful_results))
            memory_score = max(0, 100 - statistics.mean(r.avg_memory_mb for r in successful_results) / 100)
            
            performance_score = (throughput_score + latency_score + memory_score) / 3
        
        report = {
            'session_info': {
                'session_id': f"perf_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'timestamp': datetime.now().isoformat(),
                'hardware_specs': {
                    'cpu_count': self.hardware_specs.cpu_count,
                    'cpu_freq_mhz': self.hardware_specs.cpu_freq_mhz,
                    'memory_total_gb': self.hardware_specs.memory_total_gb,
                    'disk_type': self.hardware_specs.disk_type
                }
            },
            'summary': {
                'total_benchmarks': len(self.results),
                'successful': len(successful_results),
                'failed': len(failed_results),
                'overall_performance_score': performance_score,
                'total_duration_seconds': sum(r.total_duration_seconds for r in self.results)
            },
            'category_summaries': category_summaries,
            'detailed_results': [
                {
                    'benchmark_name': r.config.name,
                    'benchmark_type': r.config.benchmark_type.value,
                    'success': r.success,
                    'throughput_ops_per_sec': r.throughput_ops_per_sec,
                    'avg_latency_ms': r.avg_latency_ms,
                    'p95_latency_ms': r.p95_latency_ms,
                    'p99_latency_ms': r.p99_latency_ms,
                    'peak_memory_mb': r.peak_memory_mb,
                    'avg_cpu_percent': r.avg_cpu_percent,
                    'duration_seconds': r.total_duration_seconds,
                    'iterations_completed': r.iterations_completed,
                    'error_message': r.error_message
                }
                for r in self.results
            ]
        }
        
        return report
    
    def save_report(self, report: Dict[str, Any], output_path: Optional[str] = None):
        """Save performance report to file."""
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"tests/results/performance_report_{timestamp}.json"
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Performance report saved to: {output_file}")


async def main():
    """Main entry point for performance testing."""
    # Enable uvloop for better async performance if available
    if uvloop:
        uvloop.install()
    
    test_suite = PerformanceTestSuite()
    
    # Run comprehensive performance tests
    report = await test_suite.run_comprehensive_suite()
    
    # Save report
    test_suite.save_report(report)
    
    # Print summary
    print(f"Performance Test Results:")
    print(f"  Total Benchmarks: {report['summary']['total_benchmarks']}")
    print(f"  Successful: {report['summary']['successful']}")
    print(f"  Failed: {report['summary']['failed']}")
    print(f"  Overall Performance Score: {report['summary']['overall_performance_score']:.1f}/100")
    print(f"  Total Duration: {report['summary']['total_duration_seconds']:.2f} seconds")
    
    # Print category summaries
    print(f"\nPerformance by Category:")
    for category, summary in report['category_summaries'].items():
        print(f"  {category.upper()}:")
        print(f"    Avg Throughput: {summary['avg_throughput']:.2f} ops/sec")
        print(f"    Avg Latency: {summary['avg_latency_ms']:.2f} ms")
        print(f"    Avg Memory: {summary['avg_memory_mb']:.2f} MB")


if __name__ == "__main__":
    asyncio.run(main())