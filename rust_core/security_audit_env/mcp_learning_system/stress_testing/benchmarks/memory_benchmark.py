"""
Memory efficiency benchmarks for MCP Learning System.

Tests memory allocation, usage patterns, and efficiency under stress.
"""

import asyncio
import gc
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import psutil
import numpy as np
import logging
import tracemalloc
from memory_profiler import profile

from mcp_learning_system.core import LearningMCPCluster

logger = logging.getLogger(__name__)


@dataclass
class MemorySnapshot:
    """Memory usage snapshot."""
    timestamp: float
    total_memory: int  # bytes
    available_memory: int
    process_memory: int
    learning_memory: int
    cache_memory: int
    pattern_count: int
    
    @property
    def used_memory(self) -> int:
        """Calculate used memory."""
        return self.total_memory - self.available_memory
    
    @property
    def memory_per_pattern(self) -> float:
        """Calculate memory per pattern."""
        if self.pattern_count == 0:
            return 0.0
        return self.learning_memory / self.pattern_count
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp,
            'total_memory_gb': self.total_memory / (1024**3),
            'available_memory_gb': self.available_memory / (1024**3),
            'process_memory_gb': self.process_memory / (1024**3),
            'learning_memory_mb': self.learning_memory / (1024**2),
            'cache_memory_mb': self.cache_memory / (1024**2),
            'pattern_count': self.pattern_count,
            'memory_per_pattern_kb': self.memory_per_pattern / 1024
        }


class MemoryBenchmark:
    """Memory efficiency and stress testing benchmarks."""
    
    def __init__(self, mcp_cluster: Optional[LearningMCPCluster] = None):
        """Initialize memory benchmark suite."""
        self.mcp_cluster = mcp_cluster or LearningMCPCluster()
        self.process = psutil.Process()
        self.snapshots: List[MemorySnapshot] = []
        
        # Memory limits (12GB total as per requirements)
        self.memory_limits = {
            'total': 12 * 1024 * 1024 * 1024,  # 12GB
            'working': 9 * 1024 * 1024 * 1024,  # 9GB
            'learning': 3 * 1024 * 1024 * 1024,  # 3GB
            'per_instance': 3 * 1024 * 1024 * 1024  # 3GB per instance
        }
    
    async def run_memory_benchmarks(self) -> Dict[str, Any]:
        """Run complete memory benchmark suite."""
        logger.info("Starting memory benchmarks")
        
        results = {}
        
        # Start memory tracking
        tracemalloc.start()
        
        try:
            # Initialize cluster
            await self.mcp_cluster.initialize()
            
            # Baseline memory usage
            results['baseline'] = await self.benchmark_baseline_memory()
            
            # Pattern storage efficiency
            results['pattern_storage'] = await self.benchmark_pattern_storage()
            
            # Learning memory growth
            results['learning_growth'] = await self.benchmark_learning_memory_growth()
            
            # Memory under load
            results['memory_under_load'] = await self.benchmark_memory_under_load()
            
            # Memory fragmentation
            results['fragmentation'] = await self.benchmark_memory_fragmentation()
            
            # Cache efficiency
            results['cache_efficiency'] = await self.benchmark_cache_efficiency()
            
            # Memory limits validation
            results['limits_validation'] = await self.validate_memory_limits()
            
            # Generate summary
            results['summary'] = self._generate_summary()
            
        finally:
            # Stop tracking and cleanup
            tracemalloc.stop()
            await self.mcp_cluster.shutdown()
            gc.collect()
            
        return results
    
    async def benchmark_baseline_memory(self) -> Dict[str, Any]:
        """Benchmark baseline memory usage."""
        logger.info("Benchmarking baseline memory usage")
        
        # Force garbage collection
        gc.collect()
        await asyncio.sleep(1)
        
        # Take initial snapshot
        initial = self._take_memory_snapshot(pattern_count=0)
        
        # Wait and take another snapshot
        await asyncio.sleep(5)
        final = self._take_memory_snapshot(pattern_count=0)
        
        # Calculate idle memory usage
        idle_growth = final.process_memory - initial.process_memory
        
        return {
            'initial_memory_mb': initial.process_memory / (1024**2),
            'final_memory_mb': final.process_memory / (1024**2),
            'idle_growth_mb': idle_growth / (1024**2),
            'system_memory_gb': initial.total_memory / (1024**3),
            'available_memory_gb': initial.available_memory / (1024**3)
        }
    
    async def benchmark_pattern_storage(self) -> Dict[str, Any]:
        """Benchmark pattern storage memory efficiency."""
        logger.info("Benchmarking pattern storage efficiency")
        
        results = {
            'pattern_sizes': {},
            'storage_efficiency': {},
            'memory_snapshots': []
        }
        
        pattern_configs = [
            {'name': 'small', 'size': 100, 'count': 10000},
            {'name': 'medium', 'size': 1000, 'count': 1000},
            {'name': 'large', 'size': 10000, 'count': 100}
        ]
        
        for config in pattern_configs:
            # Clear previous patterns
            await self.mcp_cluster.clear_patterns()
            gc.collect()
            
            # Get baseline
            baseline = self._take_memory_snapshot(0)
            
            # Store patterns
            patterns_stored = 0
            for i in range(config['count']):
                pattern = self._generate_pattern(config['size'])
                await self.mcp_cluster.store_pattern(pattern)
                patterns_stored += 1
                
                # Take snapshot every 10%
                if i % (config['count'] // 10) == 0:
                    snapshot = self._take_memory_snapshot(patterns_stored)
                    results['memory_snapshots'].append(snapshot.to_dict())
            
            # Final measurement
            final = self._take_memory_snapshot(patterns_stored)
            memory_used = final.learning_memory - baseline.learning_memory
            
            results['pattern_sizes'][config['name']] = {
                'pattern_size': config['size'],
                'pattern_count': config['count'],
                'total_memory_mb': memory_used / (1024**2),
                'memory_per_pattern_kb': (memory_used / config['count']) / 1024,
                'theoretical_size_kb': (config['size'] * 8) / 1024,  # 8 bytes per float
                'overhead_ratio': (memory_used / config['count']) / (config['size'] * 8)
            }
        
        return results
    
    async def benchmark_learning_memory_growth(self) -> Dict[str, Any]:
        """Benchmark memory growth during continuous learning."""
        logger.info("Benchmarking learning memory growth")
        
        duration = 300  # 5 minutes
        sample_interval = 10  # seconds
        
        results = {
            'duration': duration,
            'samples': [],
            'growth_rate': 0.0,
            'peak_memory': 0,
            'final_memory': 0
        }
        
        start_time = time.time()
        patterns_learned = 0
        
        # Initial snapshot
        initial = self._take_memory_snapshot(0)
        
        while time.time() - start_time < duration:
            # Perform learning operations
            for _ in range(100):
                interaction = self._generate_learning_interaction()
                await self.mcp_cluster.learn(interaction)
                patterns_learned += 1
            
            # Take memory snapshot
            snapshot = self._take_memory_snapshot(patterns_learned)
            self.snapshots.append(snapshot)
            
            sample = {
                'time': time.time() - start_time,
                'patterns_learned': patterns_learned,
                'memory_mb': snapshot.learning_memory / (1024**2),
                'total_process_mb': snapshot.process_memory / (1024**2)
            }
            results['samples'].append(sample)
            
            # Update peak memory
            results['peak_memory'] = max(
                results['peak_memory'],
                snapshot.process_memory
            )
            
            await asyncio.sleep(sample_interval)
        
        # Calculate growth rate
        final = self._take_memory_snapshot(patterns_learned)
        memory_growth = final.learning_memory - initial.learning_memory
        results['growth_rate'] = memory_growth / patterns_learned  # bytes per pattern
        results['final_memory'] = final.process_memory
        
        # Analyze trend
        if len(results['samples']) > 2:
            times = [s['time'] for s in results['samples']]
            memories = [s['memory_mb'] for s in results['samples']]
            
            # Linear regression for growth trend
            slope, intercept = np.polyfit(times, memories, 1)
            results['linear_growth_rate_mb_per_second'] = slope
            results['projected_memory_1hour_mb'] = intercept + slope * 3600
        
        return results
    
    async def benchmark_memory_under_load(self) -> Dict[str, Any]:
        """Benchmark memory behavior under different load levels."""
        logger.info("Benchmarking memory under load")
        
        load_levels = [0, 25, 50, 75, 90, 95]
        results = {
            'load_levels': {},
            'memory_vs_load': []
        }
        
        for load_level in load_levels:
            logger.info(f"Testing at {load_level}% load")
            
            # Apply load
            load_task = asyncio.create_task(self._apply_memory_load(load_level))
            
            try:
                # Run for 60 seconds at each level
                start_time = time.time()
                memory_samples = []
                
                while time.time() - start_time < 60:
                    # Perform operations
                    tasks = []
                    for _ in range(10):
                        task = asyncio.create_task(self._memory_stress_operation())
                        tasks.append(task)
                    
                    await asyncio.gather(*tasks)
                    
                    # Sample memory
                    snapshot = self._take_memory_snapshot(0)
                    memory_samples.append(snapshot.process_memory)
                    
                    await asyncio.sleep(1)
                
                # Calculate statistics
                results['load_levels'][load_level] = {
                    'mean_memory_mb': np.mean(memory_samples) / (1024**2),
                    'max_memory_mb': np.max(memory_samples) / (1024**2),
                    'memory_variance': np.var(memory_samples) / (1024**4),
                    'within_limits': np.max(memory_samples) < self.memory_limits['total']
                }
                
                results['memory_vs_load'].append({
                    'load': load_level,
                    'memory': np.mean(memory_samples) / (1024**2)
                })
                
            finally:
                load_task.cancel()
                try:
                    await load_task
                except asyncio.CancelledError:
                    pass
                
                # Cool down
                await asyncio.sleep(10)
                gc.collect()
        
        return results
    
    async def benchmark_memory_fragmentation(self) -> Dict[str, Any]:
        """Benchmark memory fragmentation effects."""
        logger.info("Benchmarking memory fragmentation")
        
        results = {
            'fragmentation_cycles': [],
            'allocation_efficiency': []
        }
        
        for cycle in range(5):
            logger.info(f"Fragmentation cycle {cycle + 1}")
            
            # Allocate and deallocate in patterns that cause fragmentation
            allocations = []
            
            # Phase 1: Allocate mixed sizes
            for i in range(1000):
                size = np.random.choice([100, 1000, 10000])
                pattern = self._generate_pattern(size)
                await self.mcp_cluster.store_pattern(pattern)
                allocations.append(pattern['id'])
            
            mid_snapshot = self._take_memory_snapshot(len(allocations))
            
            # Phase 2: Delete every other pattern (creates holes)
            for i in range(0, len(allocations), 2):
                await self.mcp_cluster.delete_pattern(allocations[i])
            
            fragmented_snapshot = self._take_memory_snapshot(len(allocations) // 2)
            
            # Phase 3: Try to allocate large patterns
            large_allocations = 0
            try:
                for i in range(100):
                    large_pattern = self._generate_pattern(50000)
                    await self.mcp_cluster.store_pattern(large_pattern)
                    large_allocations += 1
            except Exception as e:
                logger.warning(f"Large allocation failed: {e}")
            
            final_snapshot = self._take_memory_snapshot(
                len(allocations) // 2 + large_allocations
            )
            
            cycle_result = {
                'cycle': cycle + 1,
                'mid_memory_mb': mid_snapshot.process_memory / (1024**2),
                'fragmented_memory_mb': fragmented_snapshot.process_memory / (1024**2),
                'final_memory_mb': final_snapshot.process_memory / (1024**2),
                'large_allocations_successful': large_allocations,
                'fragmentation_overhead': (
                    fragmented_snapshot.process_memory - 
                    (mid_snapshot.process_memory // 2)
                ) / (1024**2)
            }
            
            results['fragmentation_cycles'].append(cycle_result)
            
            # Clear for next cycle
            await self.mcp_cluster.clear_patterns()
            gc.collect()
            await asyncio.sleep(5)
        
        return results
    
    async def benchmark_cache_efficiency(self) -> Dict[str, Any]:
        """Benchmark cache memory efficiency."""
        logger.info("Benchmarking cache efficiency")
        
        results = {
            'cache_sizes': {},
            'hit_rates': {},
            'memory_efficiency': {}
        }
        
        cache_configs = [
            {'size': 1000, 'access_pattern': 'sequential'},
            {'size': 1000, 'access_pattern': 'random'},
            {'size': 10000, 'access_pattern': 'zipf'}  # Power law distribution
        ]
        
        for config in cache_configs:
            logger.info(f"Testing cache: {config}")
            
            # Configure cache
            await self.mcp_cluster.configure_cache(size=config['size'])
            
            # Populate cache
            patterns = []
            for i in range(config['size']):
                pattern = self._generate_pattern(1000)
                await self.mcp_cluster.store_pattern(pattern)
                patterns.append(pattern['id'])
            
            # Measure cache performance
            cache_stats = await self._measure_cache_performance(
                patterns,
                config['access_pattern'],
                iterations=10000
            )
            
            # Get memory usage
            snapshot = self._take_memory_snapshot(config['size'])
            
            key = f"{config['size']}_{config['access_pattern']}"
            results['cache_sizes'][key] = config['size']
            results['hit_rates'][key] = cache_stats['hit_rate']
            results['memory_efficiency'][key] = {
                'cache_memory_mb': snapshot.cache_memory / (1024**2),
                'memory_per_item_kb': (snapshot.cache_memory / config['size']) / 1024,
                'efficiency_score': cache_stats['hit_rate'] / (snapshot.cache_memory / (1024**2))
            }
        
        return results
    
    async def validate_memory_limits(self) -> Dict[str, Any]:
        """Validate memory stays within specified limits."""
        logger.info("Validating memory limits")
        
        results = {
            'limits': {
                'total_gb': self.memory_limits['total'] / (1024**3),
                'working_gb': self.memory_limits['working'] / (1024**3),
                'learning_gb': self.memory_limits['learning'] / (1024**3)
            },
            'violations': [],
            'peak_usage': {},
            'compliance': True
        }
        
        # Stress test to approach limits
        patterns_stored = 0
        peak_total = 0
        peak_learning = 0
        
        try:
            # Keep adding patterns until we approach limits
            while True:
                # Check current usage
                snapshot = self._take_memory_snapshot(patterns_stored)
                
                peak_total = max(peak_total, snapshot.process_memory)
                peak_learning = max(peak_learning, snapshot.learning_memory)
                
                # Check violations
                if snapshot.process_memory > self.memory_limits['total']:
                    violation = f"Total memory exceeded: {snapshot.process_memory / (1024**3):.2f}GB"
                    results['violations'].append(violation)
                    results['compliance'] = False
                    break
                
                if snapshot.learning_memory > self.memory_limits['learning']:
                    violation = f"Learning memory exceeded: {snapshot.learning_memory / (1024**3):.2f}GB"
                    results['violations'].append(violation)
                    results['compliance'] = False
                    break
                
                # Check if we're getting close to limits (90%)
                if snapshot.process_memory > 0.9 * self.memory_limits['total']:
                    logger.warning("Approaching total memory limit")
                    break
                
                # Add more patterns
                batch_size = 100
                for _ in range(batch_size):
                    pattern = self._generate_pattern(10000)  # Large patterns
                    await self.mcp_cluster.store_pattern(pattern)
                    patterns_stored += 1
                
                # Small delay
                await asyncio.sleep(0.1)
                
        except Exception as e:
            results['violations'].append(f"Error during limit test: {str(e)}")
        
        results['peak_usage'] = {
            'total_gb': peak_total / (1024**3),
            'learning_gb': peak_learning / (1024**3),
            'patterns_at_peak': patterns_stored,
            'utilization_percent': (peak_total / self.memory_limits['total']) * 100
        }
        
        return results
    
    def _take_memory_snapshot(self, pattern_count: int) -> MemorySnapshot:
        """Take a memory snapshot."""
        # System memory
        mem = psutil.virtual_memory()
        
        # Process memory
        process_info = self.process.memory_info()
        
        # Get component-specific memory (simulated)
        learning_memory = self._estimate_learning_memory()
        cache_memory = self._estimate_cache_memory()
        
        return MemorySnapshot(
            timestamp=time.time(),
            total_memory=mem.total,
            available_memory=mem.available,
            process_memory=process_info.rss,
            learning_memory=learning_memory,
            cache_memory=cache_memory,
            pattern_count=pattern_count
        )
    
    def _estimate_learning_memory(self) -> int:
        """Estimate memory used by learning components."""
        # This would be replaced with actual measurement in production
        if hasattr(self.mcp_cluster, 'get_learning_memory'):
            return self.mcp_cluster.get_learning_memory()
        
        # Estimate based on process memory
        return int(self.process.memory_info().rss * 0.4)  # 40% estimate
    
    def _estimate_cache_memory(self) -> int:
        """Estimate memory used by caching."""
        # This would be replaced with actual measurement in production
        if hasattr(self.mcp_cluster, 'get_cache_memory'):
            return self.mcp_cluster.get_cache_memory()
        
        # Estimate based on process memory
        return int(self.process.memory_info().rss * 0.1)  # 10% estimate
    
    def _generate_pattern(self, size: int) -> Dict[str, Any]:
        """Generate test pattern."""
        return {
            'id': f"pattern_{time.time()}_{np.random.randint(1000000)}",
            'data': np.random.rand(size).tolist(),
            'metadata': {
                'size': size,
                'timestamp': time.time()
            }
        }
    
    def _generate_learning_interaction(self) -> Dict[str, Any]:
        """Generate learning interaction."""
        return {
            'input': np.random.rand(100).tolist(),
            'output': np.random.rand(10).tolist(),
            'metadata': {
                'timestamp': time.time()
            }
        }
    
    async def _apply_memory_load(self, load_percent: int):
        """Apply memory load to simulate stress."""
        # Calculate memory to allocate
        available_memory = psutil.virtual_memory().available
        target_allocation = int(available_memory * load_percent / 100)
        
        # Allocate in chunks
        chunk_size = 100 * 1024 * 1024  # 100MB chunks
        allocations = []
        
        try:
            allocated = 0
            while allocated < target_allocation:
                allocation = bytearray(min(chunk_size, target_allocation - allocated))
                allocations.append(allocation)
                allocated += len(allocation)
                await asyncio.sleep(0.1)
            
            # Hold allocations
            while True:
                await asyncio.sleep(1)
                
        except asyncio.CancelledError:
            # Clean up allocations
            allocations.clear()
            raise
    
    async def _memory_stress_operation(self):
        """Perform memory-intensive operation."""
        # Allocate temporary memory
        data = np.random.rand(1000, 1000)  # ~8MB
        
        # Perform operations
        result = np.dot(data, data.T)
        
        # Small delay
        await asyncio.sleep(0.01)
        
        return result.sum()
    
    async def _measure_cache_performance(
        self,
        patterns: List[str],
        access_pattern: str,
        iterations: int
    ) -> Dict[str, Any]:
        """Measure cache performance with different access patterns."""
        hits = 0
        misses = 0
        
        for i in range(iterations):
            # Select pattern based on access pattern
            if access_pattern == 'sequential':
                pattern_id = patterns[i % len(patterns)]
            elif access_pattern == 'random':
                pattern_id = np.random.choice(patterns)
            elif access_pattern == 'zipf':
                # Zipf distribution (power law)
                rank = np.random.zipf(1.5)
                index = min(rank - 1, len(patterns) - 1)
                pattern_id = patterns[index]
            else:
                pattern_id = patterns[0]
            
            # Try to access pattern
            result = await self.mcp_cluster.get_pattern(pattern_id)
            
            if result.cache_hit:
                hits += 1
            else:
                misses += 1
        
        return {
            'hits': hits,
            'misses': misses,
            'hit_rate': hits / (hits + misses) if (hits + misses) > 0 else 0
        }
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary of memory benchmarks."""
        if not self.snapshots:
            return {'error': 'No snapshots collected'}
        
        # Analyze snapshots
        memories = [s.process_memory / (1024**2) for s in self.snapshots]
        
        return {
            'total_snapshots': len(self.snapshots),
            'min_memory_mb': np.min(memories),
            'max_memory_mb': np.max(memories),
            'mean_memory_mb': np.mean(memories),
            'memory_growth_mb': memories[-1] - memories[0] if len(memories) > 1 else 0,
            'peak_utilization_percent': (np.max(memories) * 1024**2 / self.memory_limits['total']) * 100
        }