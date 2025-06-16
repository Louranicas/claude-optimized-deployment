"""
Cache performance benchmarking and tuning utilities.

This module provides comprehensive benchmarking tools for evaluating
cache performance under various conditions and workloads.
"""

import asyncio
import random
import time
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, Tuple
from enum import Enum
import structlog

from .distributed_cache import CacheManager, CacheConfig, CachePattern

__all__ = [
    "BenchmarkType",
    "WorkloadPattern",
    "BenchmarkConfig",
    "BenchmarkResult",
    "BenchmarkSuite",
    "CacheBenchmarker"
]

logger = structlog.get_logger(__name__)


class BenchmarkType(Enum):
    """Types of cache benchmarks."""
    LATENCY = "latency"
    THROUGHPUT = "throughput"
    HIT_RATE = "hit_rate"
    MEMORY_USAGE = "memory_usage"
    SCALABILITY = "scalability"
    CONSISTENCY = "consistency"


class WorkloadPattern(Enum):
    """Cache workload patterns for benchmarking."""
    UNIFORM_RANDOM = "uniform_random"
    ZIPFIAN = "zipfian"
    SEQUENTIAL = "sequential"
    HOTSPOT = "hotspot"
    BURST = "burst"
    MIXED = "mixed"


@dataclass
class BenchmarkConfig:
    """Configuration for cache benchmarks."""
    # Test parameters
    duration_seconds: float = 60.0
    warmup_seconds: float = 10.0
    num_keys: int = 10000
    value_size_bytes: int = 1024
    concurrency: int = 10
    
    # Workload configuration
    read_percentage: float = 0.8  # 80% reads, 20% writes
    workload_pattern: WorkloadPattern = WorkloadPattern.UNIFORM_RANDOM
    
    # Cache configuration
    cache_size: int = 1000
    ttl_seconds: float = 3600.0
    
    # Advanced settings
    key_prefix: str = "bench_"
    zipfian_exponent: float = 0.99
    hotspot_percentage: float = 0.1  # 10% of keys are hot
    hotspot_access_percentage: float = 0.9  # 90% of accesses to hot keys
    burst_intensity: float = 10.0  # Multiplier for burst load
    burst_duration: float = 5.0  # Burst duration in seconds
    
    # Output configuration
    detailed_metrics: bool = True
    percentiles: List[float] = field(default_factory=lambda: [50, 90, 95, 99, 99.9])


@dataclass
class BenchmarkResult:
    """Results from a cache benchmark."""
    benchmark_type: BenchmarkType
    config: BenchmarkConfig
    
    # Timing metrics
    duration_seconds: float = 0.0
    total_operations: int = 0
    operations_per_second: float = 0.0
    
    # Latency metrics (in milliseconds)
    avg_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    latency_percentiles: Dict[float, float] = field(default_factory=dict)
    
    # Cache metrics
    hit_rate: float = 0.0
    miss_rate: float = 0.0
    total_hits: int = 0
    total_misses: int = 0
    total_sets: int = 0
    total_deletes: int = 0
    
    # Memory metrics
    peak_memory_mb: float = 0.0
    avg_memory_mb: float = 0.0
    memory_efficiency: float = 0.0  # hit_rate / memory_usage
    
    # Error metrics
    error_count: int = 0
    error_rate: float = 0.0
    
    # Additional metrics
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "benchmark_type": self.benchmark_type.value,
            "duration_seconds": self.duration_seconds,
            "total_operations": self.total_operations,
            "operations_per_second": self.operations_per_second,
            "avg_latency_ms": self.avg_latency_ms,
            "min_latency_ms": self.min_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "latency_percentiles": self.latency_percentiles,
            "hit_rate": self.hit_rate,
            "miss_rate": self.miss_rate,
            "total_hits": self.total_hits,
            "total_misses": self.total_misses,
            "total_sets": self.total_sets,
            "total_deletes": self.total_deletes,
            "peak_memory_mb": self.peak_memory_mb,
            "avg_memory_mb": self.avg_memory_mb,
            "memory_efficiency": self.memory_efficiency,
            "error_count": self.error_count,
            "error_rate": self.error_rate,
            "metadata": self.metadata
        }


class BenchmarkSuite:
    """Collection of benchmark configurations for comprehensive testing."""
    
    @staticmethod
    def quick_test() -> List[BenchmarkConfig]:
        """Quick benchmark suite for basic testing."""
        return [
            BenchmarkConfig(
                duration_seconds=30.0,
                num_keys=1000,
                concurrency=5,
                workload_pattern=WorkloadPattern.UNIFORM_RANDOM
            ),
            BenchmarkConfig(
                duration_seconds=30.0,
                num_keys=1000,
                concurrency=5,
                workload_pattern=WorkloadPattern.ZIPFIAN
            )
        ]
    
    @staticmethod
    def comprehensive_test() -> List[BenchmarkConfig]:
        """Comprehensive benchmark suite for thorough evaluation."""
        configs = []
        
        # Latency tests with different concurrency levels
        for concurrency in [1, 5, 10, 20]:
            configs.append(BenchmarkConfig(
                duration_seconds=60.0,
                concurrency=concurrency,
                workload_pattern=WorkloadPattern.UNIFORM_RANDOM,
                read_percentage=0.8
            ))
        
        # Workload pattern tests
        for pattern in [WorkloadPattern.UNIFORM_RANDOM, WorkloadPattern.ZIPFIAN, 
                       WorkloadPattern.HOTSPOT, WorkloadPattern.SEQUENTIAL]:
            configs.append(BenchmarkConfig(
                duration_seconds=60.0,
                workload_pattern=pattern,
                concurrency=10
            ))
        
        # Read/write ratio tests
        for read_pct in [0.5, 0.8, 0.9, 0.95, 1.0]:
            configs.append(BenchmarkConfig(
                duration_seconds=60.0,
                read_percentage=read_pct,
                workload_pattern=WorkloadPattern.UNIFORM_RANDOM,
                concurrency=10
            ))
        
        # Value size tests
        for value_size in [64, 256, 1024, 4096, 16384]:
            configs.append(BenchmarkConfig(
                duration_seconds=60.0,
                value_size_bytes=value_size,
                workload_pattern=WorkloadPattern.UNIFORM_RANDOM,
                concurrency=10
            ))
        
        return configs
    
    @staticmethod
    def stress_test() -> List[BenchmarkConfig]:
        """Stress test configurations for performance limits."""
        return [
            # High concurrency
            BenchmarkConfig(
                duration_seconds=120.0,
                concurrency=100,
                num_keys=100000,
                workload_pattern=WorkloadPattern.UNIFORM_RANDOM
            ),
            # Large values
            BenchmarkConfig(
                duration_seconds=120.0,
                value_size_bytes=1024*1024,  # 1MB values
                num_keys=1000,
                concurrency=10
            ),
            # Burst load
            BenchmarkConfig(
                duration_seconds=120.0,
                workload_pattern=WorkloadPattern.BURST,
                burst_intensity=50.0,
                concurrency=20
            )
        ]


class WorkloadGenerator:
    """Generates different types of workloads for benchmarking."""
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self.random = random.Random(42)  # Fixed seed for reproducibility
        
        # Pre-generate keys for consistency
        self.all_keys = [
            f"{config.key_prefix}{i:06d}" 
            for i in range(config.num_keys)
        ]
        
        # Setup workload-specific data
        if config.workload_pattern == WorkloadPattern.HOTSPOT:
            self.hot_key_count = max(1, int(config.num_keys * config.hotspot_percentage))
            self.hot_keys = self.all_keys[:self.hot_key_count]
            self.cold_keys = self.all_keys[self.hot_key_count:]
        
        # For Zipfian distribution
        if config.workload_pattern == WorkloadPattern.ZIPFIAN:
            self._setup_zipfian()
    
    def _setup_zipfian(self) -> None:
        """Setup Zipfian distribution parameters."""
        # Create probability distribution for Zipfian
        n = self.config.num_keys
        s = self.config.zipfian_exponent
        
        # Calculate normalization constant
        harmonic_sum = sum(1.0 / (i ** s) for i in range(1, n + 1))
        
        # Calculate cumulative probabilities
        self.zipfian_probs = []
        cumulative = 0.0
        for i in range(1, n + 1):
            prob = (1.0 / (i ** s)) / harmonic_sum
            cumulative += prob
            self.zipfian_probs.append(cumulative)
    
    def get_key(self) -> str:
        """Get next key based on workload pattern."""
        if self.config.workload_pattern == WorkloadPattern.UNIFORM_RANDOM:
            return self.random.choice(self.all_keys)
        
        elif self.config.workload_pattern == WorkloadPattern.ZIPFIAN:
            r = self.random.random()
            for i, prob in enumerate(self.zipfian_probs):
                if r <= prob:
                    return self.all_keys[i]
            return self.all_keys[-1]
        
        elif self.config.workload_pattern == WorkloadPattern.HOTSPOT:
            if self.random.random() < self.config.hotspot_access_percentage:
                return self.random.choice(self.hot_keys)
            else:
                return self.random.choice(self.cold_keys)
        
        elif self.config.workload_pattern == WorkloadPattern.SEQUENTIAL:
            # Simple round-robin through keys
            index = int(time.time() * 1000) % len(self.all_keys)
            return self.all_keys[index]
        
        else:
            return self.random.choice(self.all_keys)
    
    def get_value(self) -> bytes:
        """Generate value of configured size."""
        return b'x' * self.config.value_size_bytes
    
    def is_read_operation(self) -> bool:
        """Determine if next operation should be read or write."""
        return self.random.random() < self.config.read_percentage


class CacheBenchmarker:
    """Main cache benchmarking class."""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
        self._results: List[BenchmarkResult] = []
    
    async def run_benchmark(
        self, 
        config: BenchmarkConfig,
        benchmark_type: BenchmarkType = BenchmarkType.LATENCY
    ) -> BenchmarkResult:
        """Run a single benchmark."""
        logger.info(
            "Starting benchmark",
            type=benchmark_type.value,
            duration=config.duration_seconds,
            concurrency=config.concurrency,
            workload=config.workload_pattern.value
        )
        
        # Initialize result
        result = BenchmarkResult(
            benchmark_type=benchmark_type,
            config=config
        )
        
        # Warmup phase
        if config.warmup_seconds > 0:
            await self._warmup(config)
        
        # Run the actual benchmark
        if benchmark_type == BenchmarkType.LATENCY:
            await self._benchmark_latency(config, result)
        elif benchmark_type == BenchmarkType.THROUGHPUT:
            await self._benchmark_throughput(config, result)
        elif benchmark_type == BenchmarkType.HIT_RATE:
            await self._benchmark_hit_rate(config, result)
        elif benchmark_type == BenchmarkType.MEMORY_USAGE:
            await self._benchmark_memory_usage(config, result)
        else:
            await self._benchmark_latency(config, result)  # Default to latency
        
        # Calculate derived metrics
        self._calculate_derived_metrics(result)
        
        self._results.append(result)
        
        logger.info(
            "Benchmark completed",
            type=benchmark_type.value,
            ops_per_sec=result.operations_per_second,
            avg_latency_ms=result.avg_latency_ms,
            hit_rate=result.hit_rate
        )
        
        return result
    
    async def _warmup(self, config: BenchmarkConfig) -> None:
        """Warmup the cache with initial data."""
        logger.info("Starting cache warmup", duration=config.warmup_seconds)
        
        workload = WorkloadGenerator(config)
        
        # Fill cache with some initial data
        warmup_keys = min(config.cache_size, config.num_keys // 2)
        tasks = []
        
        for i in range(warmup_keys):
            key = workload.get_key()
            value = workload.get_value()
            task = self.cache_manager.cache.set(key, value, ttl=config.ttl_seconds)
            tasks.append(task)
            
            # Process in batches to avoid overwhelming the cache
            if len(tasks) >= 100:
                await asyncio.gather(*tasks, return_exceptions=True)
                tasks.clear()
                await asyncio.sleep(0.01)  # Small delay
        
        # Process remaining tasks
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info("Cache warmup completed")
    
    async def _benchmark_latency(self, config: BenchmarkConfig, result: BenchmarkResult) -> None:
        """Run latency benchmark."""
        workload = WorkloadGenerator(config)
        latencies = []
        operation_count = 0
        error_count = 0
        
        # Track cache metrics
        initial_metrics = await self.cache_manager.get_metrics()
        
        start_time = time.time()
        end_time = start_time + config.duration_seconds
        
        # Create worker tasks
        async def worker():
            nonlocal operation_count, error_count
            local_latencies = []
            
            while time.time() < end_time:
                op_start = time.time()
                
                try:
                    key = workload.get_key()
                    
                    if workload.is_read_operation():
                        # Read operation
                        await self.cache_manager.cache.get(key)
                    else:
                        # Write operation
                        value = workload.get_value()
                        await self.cache_manager.cache.set(key, value, ttl=config.ttl_seconds)
                    
                    op_end = time.time()
                    latency_ms = (op_end - op_start) * 1000
                    local_latencies.append(latency_ms)
                    operation_count += 1
                    
                except Exception as e:
                    logger.warning("Benchmark operation failed", error=str(e))
                    error_count += 1
                    
                # Handle burst workload
                if config.workload_pattern == WorkloadPattern.BURST:
                    if int(time.time()) % int(config.burst_duration * 2) < config.burst_duration:
                        # In burst mode, reduce delay
                        await asyncio.sleep(0.001 / config.burst_intensity)
                    else:
                        await asyncio.sleep(0.01)
                else:
                    await asyncio.sleep(0.001)  # Small delay to prevent overwhelming
            
            return local_latencies
        
        # Run workers concurrently
        tasks = [worker() for _ in range(config.concurrency)]
        worker_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect all latencies
        for worker_latencies in worker_results:
            if isinstance(worker_latencies, list):
                latencies.extend(worker_latencies)
        
        # Calculate timing metrics
        actual_duration = time.time() - start_time
        result.duration_seconds = actual_duration
        result.total_operations = operation_count
        result.operations_per_second = operation_count / actual_duration if actual_duration > 0 else 0
        result.error_count = error_count
        result.error_rate = error_count / max(1, operation_count + error_count)
        
        # Calculate latency metrics
        if latencies:
            result.avg_latency_ms = statistics.mean(latencies)
            result.min_latency_ms = min(latencies)
            result.max_latency_ms = max(latencies)
            
            # Calculate percentiles
            sorted_latencies = sorted(latencies)
            for percentile in config.percentiles:
                index = int((percentile / 100.0) * len(sorted_latencies))
                index = min(index, len(sorted_latencies) - 1)
                result.latency_percentiles[percentile] = sorted_latencies[index]
        
        # Get final cache metrics
        final_metrics = await self.cache_manager.get_metrics()
        result.total_hits = final_metrics.hits - initial_metrics.hits
        result.total_misses = final_metrics.misses - initial_metrics.misses
        result.total_sets = final_metrics.sets - initial_metrics.sets
        result.total_deletes = final_metrics.deletes - initial_metrics.deletes
        
        total_cache_ops = result.total_hits + result.total_misses
        if total_cache_ops > 0:
            result.hit_rate = result.total_hits / total_cache_ops
            result.miss_rate = result.total_misses / total_cache_ops
    
    async def _benchmark_throughput(self, config: BenchmarkConfig, result: BenchmarkResult) -> None:
        """Run throughput benchmark - focuses on operations per second."""
        # Throughput benchmark is similar to latency but focuses on different metrics
        await self._benchmark_latency(config, result)
        
        # Add throughput-specific metadata
        result.metadata["primary_metric"] = "operations_per_second"
        result.metadata["target_throughput"] = config.concurrency * 1000  # Rough estimate
    
    async def _benchmark_hit_rate(self, config: BenchmarkConfig, result: BenchmarkResult) -> None:
        """Run hit rate benchmark - focuses on cache efficiency."""
        workload = WorkloadGenerator(config)
        
        # Pre-populate cache with known data
        populate_count = min(config.cache_size, config.num_keys // 2)
        for i in range(populate_count):
            key = f"{config.key_prefix}{i:06d}"
            value = workload.get_value()
            await self.cache_manager.cache.set(key, value, ttl=config.ttl_seconds)
        
        # Now run read-heavy workload
        initial_metrics = await self.cache_manager.get_metrics()
        start_time = time.time()
        operation_count = 0
        
        while time.time() < start_time + config.duration_seconds:
            # Mix of known keys (should hit) and unknown keys (should miss)
            if random.random() < 0.7:  # 70% chance of hitting known key
                key = f"{config.key_prefix}{random.randint(0, populate_count - 1):06d}"
            else:  # 30% chance of missing
                key = f"{config.key_prefix}{random.randint(populate_count, config.num_keys - 1):06d}"
            
            await self.cache_manager.cache.get(key)
            operation_count += 1
            
            await asyncio.sleep(0.001)
        
        # Calculate metrics
        final_metrics = await self.cache_manager.get_metrics()
        result.duration_seconds = time.time() - start_time
        result.total_operations = operation_count
        result.total_hits = final_metrics.hits - initial_metrics.hits
        result.total_misses = final_metrics.misses - initial_metrics.misses
        
        total_cache_ops = result.total_hits + result.total_misses
        if total_cache_ops > 0:
            result.hit_rate = result.total_hits / total_cache_ops
            result.miss_rate = result.total_misses / total_cache_ops
    
    async def _benchmark_memory_usage(self, config: BenchmarkConfig, result: BenchmarkResult) -> None:
        """Run memory usage benchmark."""
        workload = WorkloadGenerator(config)
        memory_samples = []
        
        start_time = time.time()
        
        # Gradually fill cache and monitor memory
        for i in range(config.num_keys):
            key = workload.get_key()
            value = workload.get_value()
            await self.cache_manager.cache.set(key, value, ttl=config.ttl_seconds)
            
            # Sample memory usage
            if i % 100 == 0:
                metrics = await self.cache_manager.get_metrics()
                memory_samples.append(metrics.memory_usage / (1024 * 1024))  # Convert to MB
            
            if time.time() > start_time + config.duration_seconds:
                break
        
        # Calculate memory metrics
        if memory_samples:
            result.peak_memory_mb = max(memory_samples)
            result.avg_memory_mb = statistics.mean(memory_samples)
        
        result.duration_seconds = time.time() - start_time
        result.total_operations = len(memory_samples) * 100  # Approximate
    
    def _calculate_derived_metrics(self, result: BenchmarkResult) -> None:
        """Calculate derived metrics from raw measurements."""
        # Memory efficiency (hit rate per MB of memory used)
        if result.avg_memory_mb > 0 and result.hit_rate > 0:
            result.memory_efficiency = result.hit_rate / result.avg_memory_mb
        
        # Add benchmark configuration to metadata
        result.metadata.update({
            "workload_pattern": result.config.workload_pattern.value,
            "read_percentage": result.config.read_percentage,
            "value_size_bytes": result.config.value_size_bytes,
            "concurrency": result.config.concurrency,
            "num_keys": result.config.num_keys
        })
    
    async def run_benchmark_suite(self, configs: List[BenchmarkConfig]) -> List[BenchmarkResult]:
        """Run a suite of benchmarks."""
        results = []
        
        for i, config in enumerate(configs):
            logger.info(f"Running benchmark {i + 1}/{len(configs)}")
            
            # Clear cache between benchmarks for consistency
            await self.cache_manager.cache.clear()
            await asyncio.sleep(1)  # Give cache time to clear
            
            result = await self.run_benchmark(config)
            results.append(result)
            
            # Small delay between benchmarks
            await asyncio.sleep(2)
        
        return results
    
    def get_results(self) -> List[BenchmarkResult]:
        """Get all benchmark results."""
        return self._results.copy()
    
    def export_results(self, filename: str) -> None:
        """Export results to JSON file."""
        import json
        
        data = {
            "timestamp": time.time(),
            "benchmarks": [result.to_dict() for result in self._results]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info("Benchmark results exported", filename=filename)


# Convenience functions for common benchmark scenarios
async def quick_benchmark(cache_manager: CacheManager) -> List[BenchmarkResult]:
    """Run a quick benchmark suite."""
    benchmarker = CacheBenchmarker(cache_manager)
    configs = BenchmarkSuite.quick_test()
    return await benchmarker.run_benchmark_suite(configs)


async def comprehensive_benchmark(cache_manager: CacheManager) -> List[BenchmarkResult]:
    """Run a comprehensive benchmark suite."""
    benchmarker = CacheBenchmarker(cache_manager)
    configs = BenchmarkSuite.comprehensive_test()
    return await benchmarker.run_benchmark_suite(configs)


async def stress_benchmark(cache_manager: CacheManager) -> List[BenchmarkResult]:
    """Run a stress test benchmark suite."""
    benchmarker = CacheBenchmarker(cache_manager)
    configs = BenchmarkSuite.stress_test()
    return await benchmarker.run_benchmark_suite(configs)