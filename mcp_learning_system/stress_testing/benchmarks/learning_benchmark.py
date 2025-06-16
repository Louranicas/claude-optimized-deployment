"""
Learning performance benchmarks for stress testing.

Measures pattern recognition, learning update speed, and accuracy under load.
"""

import asyncio
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import psutil
import logging

from mcp_learning_system.core import LearningMCPCluster

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Container for benchmark results."""
    name: str
    iterations: int
    total_time: float
    min_time: float
    max_time: float
    mean_time: float
    median_time: float
    p95_time: float
    p99_time: float
    throughput: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'iterations': self.iterations,
            'total_time': self.total_time,
            'min_time': self.min_time,
            'max_time': self.max_time,
            'mean_time': self.mean_time,
            'median_time': self.median_time,
            'p95_time': self.p95_time,
            'p99_time': self.p99_time,
            'throughput': self.throughput,
            'metadata': self.metadata
        }
    
    def __str__(self) -> str:
        """String representation."""
        return (
            f"{self.name}:\n"
            f"  Iterations: {self.iterations}\n"
            f"  Total time: {self.total_time:.3f}s\n"
            f"  Mean: {self.mean_time*1000:.3f}ms\n"
            f"  Median: {self.median_time*1000:.3f}ms\n"
            f"  P95: {self.p95_time*1000:.3f}ms\n"
            f"  P99: {self.p99_time*1000:.3f}ms\n"
            f"  Throughput: {self.throughput:.1f} ops/s"
        )


class LearningBenchmark:
    """Comprehensive learning performance benchmarks."""
    
    def __init__(self, mcp_cluster: Optional[LearningMCPCluster] = None):
        """Initialize benchmark suite."""
        self.mcp_cluster = mcp_cluster or LearningMCPCluster()
        self.executor = ThreadPoolExecutor(max_workers=psutil.cpu_count())
        
        # Benchmark configurations
        self.configs = {
            'small': {'pattern_size': 100, 'iterations': 10000},
            'medium': {'pattern_size': 1000, 'iterations': 1000},
            'large': {'pattern_size': 10000, 'iterations': 100}
        }
        
    async def run_all_benchmarks(self) -> Dict[str, BenchmarkResult]:
        """Run complete benchmark suite."""
        logger.info("Starting learning benchmarks")
        
        results = {}
        
        # Initialize cluster
        await self.mcp_cluster.initialize()
        
        try:
            # Pattern recognition benchmarks
            results['pattern_match_small'] = await self.benchmark_pattern_matching('small')
            results['pattern_match_medium'] = await self.benchmark_pattern_matching('medium')
            results['pattern_match_large'] = await self.benchmark_pattern_matching('large')
            
            # Learning update benchmarks
            results['learning_update_single'] = await self.benchmark_learning_update(1)
            results['learning_update_concurrent_10'] = await self.benchmark_learning_update(10)
            results['learning_update_concurrent_100'] = await self.benchmark_learning_update(100)
            
            # Accuracy benchmarks
            results['accuracy_baseline'] = await self.benchmark_accuracy(load_level=0)
            results['accuracy_under_load'] = await self.benchmark_accuracy(load_level=50)
            results['accuracy_extreme_load'] = await self.benchmark_accuracy(load_level=90)
            
            # Cross-instance benchmarks
            results['cross_instance_latency'] = await self.benchmark_cross_instance_latency()
            results['cross_instance_throughput'] = await self.benchmark_cross_instance_throughput()
            
            # Memory efficiency benchmarks
            results['memory_pattern_storage'] = await self.benchmark_memory_efficiency()
            
        finally:
            await self.mcp_cluster.shutdown()
            self.executor.shutdown()
            
        return results
    
    async def benchmark_pattern_matching(self, size: str) -> BenchmarkResult:
        """Benchmark pattern matching performance."""
        config = self.configs[size]
        pattern_size = config['pattern_size']
        iterations = config['iterations']
        
        logger.info(f"Benchmarking pattern matching: {size} ({iterations} iterations)")
        
        # Generate test patterns
        patterns = [
            self._generate_pattern(pattern_size) 
            for _ in range(min(100, iterations))
        ]
        
        times = []
        start_total = time.perf_counter()
        
        for i in range(iterations):
            pattern = patterns[i % len(patterns)]
            
            # Measure single operation
            start = time.perf_counter()
            result = await self.mcp_cluster.match_pattern(pattern)
            elapsed = time.perf_counter() - start
            
            times.append(elapsed)
            
            # Small delay to prevent overwhelming
            if i % 100 == 0:
                await asyncio.sleep(0)
        
        total_time = time.perf_counter() - start_total
        
        return self._calculate_result(
            name=f"pattern_match_{size}",
            times=times,
            total_time=total_time,
            metadata={'pattern_size': pattern_size}
        )
    
    async def benchmark_learning_update(self, concurrency: int) -> BenchmarkResult:
        """Benchmark concurrent learning updates."""
        iterations_per_worker = 100
        total_iterations = iterations_per_worker * concurrency
        
        logger.info(f"Benchmarking learning update: {concurrency} concurrent workers")
        
        async def worker(worker_id: int) -> List[float]:
            times = []
            for i in range(iterations_per_worker):
                interaction = self._generate_learning_interaction(worker_id, i)
                
                start = time.perf_counter()
                await self.mcp_cluster.learn(interaction)
                elapsed = time.perf_counter() - start
                
                times.append(elapsed)
            return times
        
        # Run concurrent workers
        start_total = time.perf_counter()
        
        worker_tasks = [
            asyncio.create_task(worker(i)) 
            for i in range(concurrency)
        ]
        
        worker_results = await asyncio.gather(*worker_tasks)
        total_time = time.perf_counter() - start_total
        
        # Flatten results
        all_times = [t for times in worker_results for t in times]
        
        return self._calculate_result(
            name=f"learning_update_concurrent_{concurrency}",
            times=all_times,
            total_time=total_time,
            metadata={'concurrency': concurrency}
        )
    
    async def benchmark_accuracy(self, load_level: int) -> BenchmarkResult:
        """Benchmark learning accuracy under different load levels."""
        test_duration = 60  # seconds
        logger.info(f"Benchmarking accuracy at {load_level}% load")
        
        # Apply simulated load
        load_task = None
        if load_level > 0:
            load_task = asyncio.create_task(self._simulate_load(load_level))
        
        accuracies = []
        times = []
        start_total = time.perf_counter()
        
        try:
            while time.perf_counter() - start_total < test_duration:
                # Test prediction accuracy
                test_set = self._generate_test_set(100)
                
                start = time.perf_counter()
                correct = 0
                for test_case in test_set:
                    prediction = await self.mcp_cluster.predict(test_case['input'])
                    if prediction == test_case['expected']:
                        correct += 1
                elapsed = time.perf_counter() - start
                
                accuracy = correct / len(test_set)
                accuracies.append(accuracy)
                times.append(elapsed)
                
                await asyncio.sleep(1)  # Test every second
                
        finally:
            if load_task:
                load_task.cancel()
                try:
                    await load_task
                except asyncio.CancelledError:
                    pass
        
        total_time = time.perf_counter() - start_total
        
        # Use accuracy as the primary metric
        result = self._calculate_result(
            name=f"accuracy_load_{load_level}",
            times=times,
            total_time=total_time,
            metadata={
                'load_level': load_level,
                'mean_accuracy': np.mean(accuracies),
                'min_accuracy': np.min(accuracies),
                'max_accuracy': np.max(accuracies)
            }
        )
        
        return result
    
    async def benchmark_cross_instance_latency(self) -> BenchmarkResult:
        """Benchmark cross-instance communication latency."""
        iterations = 1000
        logger.info("Benchmarking cross-instance latency")
        
        instances = list(self.mcp_cluster.instances.keys())
        times = []
        
        start_total = time.perf_counter()
        
        for i in range(iterations):
            # Random source and target
            source = instances[i % len(instances)]
            target = instances[(i + 1) % len(instances)]
            
            knowledge = {
                'pattern': f"test_pattern_{i}",
                'confidence': 0.95,
                'timestamp': time.time()
            }
            
            start = time.perf_counter()
            await self.mcp_cluster.share_knowledge(source, target, knowledge)
            elapsed = time.perf_counter() - start
            
            times.append(elapsed)
        
        total_time = time.perf_counter() - start_total
        
        return self._calculate_result(
            name="cross_instance_latency",
            times=times,
            total_time=total_time,
            metadata={'instances': len(instances)}
        )
    
    async def benchmark_cross_instance_throughput(self) -> BenchmarkResult:
        """Benchmark maximum cross-instance throughput."""
        test_duration = 30  # seconds
        logger.info("Benchmarking cross-instance throughput")
        
        instances = list(self.mcp_cluster.instances.keys())
        operations = 0
        times = []
        
        start_total = time.perf_counter()
        
        # Create high-throughput sharing tasks
        async def share_continuously(source_idx: int):
            nonlocal operations
            while time.perf_counter() - start_total < test_duration:
                source = instances[source_idx % len(instances)]
                target = instances[(source_idx + 1) % len(instances)]
                
                knowledge = {'data': f"throughput_test_{operations}"}
                
                start = time.perf_counter()
                await self.mcp_cluster.share_knowledge(source, target, knowledge)
                times.append(time.perf_counter() - start)
                
                operations += 1
        
        # Run multiple sharing tasks concurrently
        tasks = [
            asyncio.create_task(share_continuously(i))
            for i in range(len(instances))
        ]
        
        await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_total
        
        return self._calculate_result(
            name="cross_instance_throughput",
            times=times,
            total_time=total_time,
            metadata={
                'total_operations': operations,
                'throughput': operations / total_time
            }
        )
    
    async def benchmark_memory_efficiency(self) -> BenchmarkResult:
        """Benchmark memory usage efficiency."""
        logger.info("Benchmarking memory efficiency")
        
        # Get baseline memory
        baseline_memory = psutil.Process().memory_info().rss
        
        patterns_stored = 0
        memory_samples = []
        times = []
        
        start_total = time.perf_counter()
        
        # Store patterns and measure memory growth
        for batch in range(100):
            batch_patterns = []
            
            # Generate batch of patterns
            for _ in range(100):
                pattern = self._generate_large_pattern()
                batch_patterns.append(pattern)
            
            # Store batch
            start = time.perf_counter()
            for pattern in batch_patterns:
                await self.mcp_cluster.store_pattern(pattern)
                patterns_stored += 1
            elapsed = time.perf_counter() - start
            times.append(elapsed)
            
            # Measure memory
            current_memory = psutil.Process().memory_info().rss
            memory_growth = current_memory - baseline_memory
            memory_samples.append({
                'patterns': patterns_stored,
                'memory_bytes': memory_growth,
                'bytes_per_pattern': memory_growth / patterns_stored if patterns_stored > 0 else 0
            })
            
            # Small delay
            await asyncio.sleep(0.1)
        
        total_time = time.perf_counter() - start_total
        
        # Calculate memory efficiency metrics
        final_memory = memory_samples[-1]
        
        return self._calculate_result(
            name="memory_pattern_storage",
            times=times,
            total_time=total_time,
            metadata={
                'total_patterns': patterns_stored,
                'total_memory_mb': final_memory['memory_bytes'] / (1024 * 1024),
                'bytes_per_pattern': final_memory['bytes_per_pattern'],
                'memory_efficiency': patterns_stored / (final_memory['memory_bytes'] / (1024 * 1024))
            }
        )
    
    def _generate_pattern(self, size: int) -> Dict[str, Any]:
        """Generate test pattern of specified size."""
        return {
            'id': f"pattern_{time.time()}",
            'features': np.random.rand(size).tolist(),
            'metadata': {
                'size': size,
                'timestamp': time.time()
            }
        }
    
    def _generate_large_pattern(self) -> Dict[str, Any]:
        """Generate large pattern for memory testing."""
        return {
            'id': f"large_pattern_{time.time()}",
            'features': np.random.rand(10000).tolist(),
            'embeddings': np.random.rand(768).tolist(),
            'metadata': {
                'source': 'benchmark',
                'timestamp': time.time(),
                'tags': ['test', 'benchmark', 'memory']
            }
        }
    
    def _generate_learning_interaction(self, worker_id: int, iteration: int) -> Dict[str, Any]:
        """Generate learning interaction for benchmarking."""
        return {
            'type': 'supervised',
            'input': f"input_w{worker_id}_i{iteration}",
            'output': f"output_w{worker_id}_i{iteration}",
            'context': {
                'worker': worker_id,
                'iteration': iteration,
                'timestamp': time.time()
            }
        }
    
    def _generate_test_set(self, size: int) -> List[Dict[str, Any]]:
        """Generate test set for accuracy benchmarking."""
        test_set = []
        for i in range(size):
            test_set.append({
                'input': f"test_input_{i}",
                'expected': f"test_output_{i % 10}"  # 10 classes
            })
        return test_set
    
    async def _simulate_load(self, load_level: int):
        """Simulate system load for testing."""
        # Calculate number of CPU-bound tasks based on load level
        cpu_count = psutil.cpu_count()
        num_tasks = max(1, int(cpu_count * load_level / 100))
        
        async def cpu_task():
            while True:
                # CPU-intensive calculation
                result = sum(i ** 2 for i in range(10000))
                await asyncio.sleep(0.001)  # Yield occasionally
        
        # Create CPU tasks
        tasks = [asyncio.create_task(cpu_task()) for _ in range(num_tasks)]
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
    
    def _calculate_result(
        self, 
        name: str, 
        times: List[float], 
        total_time: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> BenchmarkResult:
        """Calculate benchmark statistics."""
        times_array = np.array(times)
        
        return BenchmarkResult(
            name=name,
            iterations=len(times),
            total_time=total_time,
            min_time=np.min(times_array),
            max_time=np.max(times_array),
            mean_time=np.mean(times_array),
            median_time=np.median(times_array),
            p95_time=np.percentile(times_array, 95),
            p99_time=np.percentile(times_array, 99),
            throughput=len(times) / total_time,
            metadata=metadata or {}
        )


# Rust benchmark wrapper
class RustLearningBenchmark:
    """Python wrapper for Rust learning benchmarks."""
    
    def __init__(self):
        """Initialize Rust benchmark wrapper."""
        try:
            from mcp_learning_system.rust_core import run_learning_benchmarks
            self.run_benchmarks = run_learning_benchmarks
        except ImportError:
            logger.warning("Rust benchmarks not available")
            self.run_benchmarks = None
    
    async def run_rust_benchmarks(self) -> Dict[str, Any]:
        """Run Rust-based performance benchmarks."""
        if not self.run_benchmarks:
            return {'error': 'Rust benchmarks not available'}
        
        logger.info("Running Rust benchmarks")
        
        # Run benchmarks in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self.run_benchmarks)
        
        return result