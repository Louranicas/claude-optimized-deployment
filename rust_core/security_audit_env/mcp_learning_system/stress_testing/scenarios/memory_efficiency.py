"""
Memory efficiency stress testing scenario.

Tests memory allocation, usage patterns, and efficiency under various conditions.
"""

import asyncio
import gc
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import numpy as np
import psutil
import logging
import tracemalloc
from memory_profiler import memory_usage

from mcp_learning_system.core import LearningMCPCluster
from ..monitoring import MemoryMonitor

logger = logging.getLogger(__name__)


@dataclass
class MemoryScenarioResult:
    """Results from a memory efficiency scenario."""
    scenario_name: str
    duration: float
    initial_memory_mb: float
    peak_memory_mb: float
    final_memory_mb: float
    memory_efficiency: float
    patterns_stored: int
    memory_per_pattern_kb: float
    violations: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def memory_growth_mb(self) -> float:
        """Calculate total memory growth."""
        return self.final_memory_mb - self.initial_memory_mb
    
    @property
    def within_limits(self) -> bool:
        """Check if memory stayed within limits."""
        return len(self.violations) == 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'scenario_name': self.scenario_name,
            'duration': self.duration,
            'initial_memory_mb': self.initial_memory_mb,
            'peak_memory_mb': self.peak_memory_mb,
            'final_memory_mb': self.final_memory_mb,
            'memory_growth_mb': self.memory_growth_mb,
            'memory_efficiency': self.memory_efficiency,
            'patterns_stored': self.patterns_stored,
            'memory_per_pattern_kb': self.memory_per_pattern_kb,
            'within_limits': self.within_limits,
            'violations': self.violations,
            'metrics': self.metrics
        }


class MemoryEfficiencyScenario:
    """Memory efficiency stress testing scenarios."""
    
    def __init__(self, mcp_cluster: Optional[LearningMCPCluster] = None):
        """Initialize scenario."""
        self.mcp_cluster = mcp_cluster or LearningMCPCluster()
        self.memory_monitor = MemoryMonitor(self.mcp_cluster)
        
        # Memory limits (12GB total)
        self.limits = {
            'total_gb': 12.0,
            'working_gb': 9.0,
            'learning_gb': 3.0,
            'warning_threshold': 0.9,  # 90% of limit
            'critical_threshold': 0.95  # 95% of limit
        }
        
    async def run_scenario(self, duration: int = 600) -> Dict[str, MemoryScenarioResult]:
        """Run complete memory efficiency scenario."""
        logger.info(f"Starting memory efficiency scenario for {duration} seconds")
        
        results = {}
        
        # Start memory profiling
        tracemalloc.start()
        
        try:
            # Initialize cluster
            await self.mcp_cluster.initialize()
            
            # Run different memory scenarios
            results['continuous_growth'] = await self.test_continuous_memory_growth(duration // 5)
            results['allocation_patterns'] = await self.test_allocation_patterns(duration // 5)
            results['memory_pressure'] = await self.test_memory_pressure(duration // 5)
            results['fragmentation'] = await self.test_memory_fragmentation(duration // 5)
            results['memory_limits'] = await self.test_memory_limits(duration // 5)
            
            # Generate summary
            results['summary'] = self._generate_memory_summary(results)
            
        finally:
            tracemalloc.stop()
            await self.mcp_cluster.shutdown()
            gc.collect()
            
        return results
    
    async def test_continuous_memory_growth(self, duration: int) -> MemoryScenarioResult:
        """Test memory growth during continuous learning."""
        logger.info("Testing continuous memory growth")
        
        # Force GC and get baseline
        gc.collect()
        await asyncio.sleep(1)
        
        initial_memory = self.memory_monitor.get_current_usage() / (1024**2)
        
        result = MemoryScenarioResult(
            scenario_name="continuous_growth",
            duration=0,
            initial_memory_mb=initial_memory,
            peak_memory_mb=initial_memory,
            final_memory_mb=initial_memory,
            memory_efficiency=0,
            patterns_stored=0,
            memory_per_pattern_kb=0
        )
        
        start_time = time.time()
        memory_samples = []
        pattern_counts = []
        
        # Continuous pattern learning
        patterns_per_second = 100
        sample_interval = 5  # seconds
        
        while time.time() - start_time < duration:
            # Learn patterns for interval
            interval_start = time.time()
            patterns_added = 0
            
            while time.time() - interval_start < sample_interval:
                # Create and learn pattern
                pattern = self._generate_variable_pattern()
                
                try:
                    await self.mcp_cluster.learn_pattern(pattern)
                    patterns_added += 1
                    result.patterns_stored += 1
                except Exception as e:
                    logger.error(f"Pattern learning failed: {e}")
                
                # Rate limiting
                await asyncio.sleep(1.0 / patterns_per_second)
            
            # Sample memory
            current_memory = self.memory_monitor.get_current_usage() / (1024**2)
            memory_samples.append(current_memory)
            pattern_counts.append(result.patterns_stored)
            
            # Update peak
            result.peak_memory_mb = max(result.peak_memory_mb, current_memory)
            
            # Check limits
            if current_memory > self.limits['total_gb'] * 1024:
                result.violations.append(
                    f"Memory exceeded limit at {time.time() - start_time:.1f}s: "
                    f"{current_memory:.1f}MB > {self.limits['total_gb']*1024:.1f}MB"
                )
            
            # Log progress
            growth_rate = (current_memory - initial_memory) / result.patterns_stored if result.patterns_stored > 0 else 0
            logger.info(
                f"Memory growth: {current_memory:.1f}MB, "
                f"patterns: {result.patterns_stored}, "
                f"rate: {growth_rate:.3f}MB/pattern"
            )
        
        result.duration = time.time() - start_time
        result.final_memory_mb = memory_samples[-1] if memory_samples else initial_memory
        
        # Calculate efficiency metrics
        if result.patterns_stored > 0:
            result.memory_per_pattern_kb = (
                (result.final_memory_mb - result.initial_memory_mb) * 1024 / 
                result.patterns_stored
            )
            
            # Efficiency: patterns per MB
            result.memory_efficiency = result.patterns_stored / (result.final_memory_mb - result.initial_memory_mb)
        
        # Analyze growth trend
        if len(memory_samples) > 2:
            times = np.arange(len(memory_samples)) * sample_interval
            slope, intercept = np.polyfit(times, memory_samples, 1)
            
            result.metrics['growth_rate_mb_per_sec'] = slope
            result.metrics['projected_1hour_mb'] = intercept + slope * 3600
            
            # Check if growth is sustainable
            hours_to_limit = (self.limits['total_gb'] * 1024 - result.final_memory_mb) / (slope * 3600)
            result.metrics['hours_to_limit'] = hours_to_limit
        
        return result
    
    async def test_allocation_patterns(self, duration: int) -> MemoryScenarioResult:
        """Test different memory allocation patterns."""
        logger.info("Testing allocation patterns")
        
        gc.collect()
        initial_memory = self.memory_monitor.get_current_usage() / (1024**2)
        
        result = MemoryScenarioResult(
            scenario_name="allocation_patterns",
            duration=0,
            initial_memory_mb=initial_memory,
            peak_memory_mb=initial_memory,
            final_memory_mb=initial_memory,
            memory_efficiency=0,
            patterns_stored=0,
            memory_per_pattern_kb=0
        )
        
        start_time = time.time()
        
        # Test different allocation patterns
        patterns = [
            {'name': 'uniform_small', 'size': 100, 'count': 10000},
            {'name': 'uniform_medium', 'size': 1000, 'count': 1000},
            {'name': 'uniform_large', 'size': 10000, 'count': 100},
            {'name': 'mixed', 'sizes': [100, 1000, 10000], 'count': 1000},
            {'name': 'exponential', 'base_size': 10, 'count': 1000}
        ]
        
        pattern_results = {}
        
        for pattern_config in patterns:
            if time.time() - start_time >= duration:
                break
                
            logger.info(f"Testing pattern: {pattern_config['name']}")
            
            # Clear previous patterns
            await self.mcp_cluster.clear_patterns()
            gc.collect()
            await asyncio.sleep(1)
            
            pattern_start_memory = self.memory_monitor.get_current_usage() / (1024**2)
            patterns_stored = 0
            
            # Allocate patterns
            if pattern_config['name'] == 'mixed':
                for i in range(pattern_config['count']):
                    size = pattern_config['sizes'][i % len(pattern_config['sizes'])]
                    pattern = self._generate_pattern_sized(size)
                    await self.mcp_cluster.store_pattern(pattern)
                    patterns_stored += 1
                    
            elif pattern_config['name'] == 'exponential':
                for i in range(pattern_config['count']):
                    size = pattern_config['base_size'] * (2 ** (i % 10))
                    pattern = self._generate_pattern_sized(size)
                    await self.mcp_cluster.store_pattern(pattern)
                    patterns_stored += 1
                    
            else:
                for _ in range(pattern_config['count']):
                    pattern = self._generate_pattern_sized(pattern_config['size'])
                    await self.mcp_cluster.store_pattern(pattern)
                    patterns_stored += 1
            
            # Measure memory after allocation
            pattern_end_memory = self.memory_monitor.get_current_usage() / (1024**2)
            memory_used = pattern_end_memory - pattern_start_memory
            
            pattern_results[pattern_config['name']] = {
                'patterns_stored': patterns_stored,
                'memory_used_mb': memory_used,
                'memory_per_pattern_kb': (memory_used * 1024) / patterns_stored if patterns_stored > 0 else 0,
                'efficiency': patterns_stored / memory_used if memory_used > 0 else 0
            }
            
            result.patterns_stored += patterns_stored
            result.peak_memory_mb = max(result.peak_memory_mb, pattern_end_memory)
        
        result.duration = time.time() - start_time
        result.final_memory_mb = self.memory_monitor.get_current_usage() / (1024**2)
        
        # Find most efficient pattern
        if pattern_results:
            best_pattern = max(pattern_results.items(), key=lambda x: x[1]['efficiency'])
            worst_pattern = min(pattern_results.items(), key=lambda x: x[1]['efficiency'])
            
            result.metrics['pattern_results'] = pattern_results
            result.metrics['best_pattern'] = best_pattern[0]
            result.metrics['worst_pattern'] = worst_pattern[0]
            result.memory_efficiency = best_pattern[1]['efficiency']
        
        return result
    
    async def test_memory_pressure(self, duration: int) -> MemoryScenarioResult:
        """Test behavior under memory pressure."""
        logger.info("Testing memory pressure")
        
        gc.collect()
        initial_memory = self.memory_monitor.get_current_usage() / (1024**2)
        
        result = MemoryScenarioResult(
            scenario_name="memory_pressure",
            duration=0,
            initial_memory_mb=initial_memory,
            peak_memory_mb=initial_memory,
            final_memory_mb=initial_memory,
            memory_efficiency=0,
            patterns_stored=0,
            memory_per_pattern_kb=0
        )
        
        start_time = time.time()
        
        # Apply increasing memory pressure
        pressure_levels = [0.5, 0.7, 0.85, 0.95]  # Percentage of limit
        
        for pressure_level in pressure_levels:
            if time.time() - start_time >= duration:
                break
                
            logger.info(f"Applying {pressure_level*100}% memory pressure")
            
            # Calculate target memory
            target_memory_mb = self.limits['total_gb'] * 1024 * pressure_level
            current_memory_mb = self.memory_monitor.get_current_usage() / (1024**2)
            
            # Allocate memory to reach target
            allocation_chunks = []
            chunk_size_mb = 100
            
            while current_memory_mb < target_memory_mb:
                try:
                    # Allocate chunk
                    chunk = bytearray(chunk_size_mb * 1024 * 1024)
                    allocation_chunks.append(chunk)
                    
                    current_memory_mb = self.memory_monitor.get_current_usage() / (1024**2)
                    result.peak_memory_mb = max(result.peak_memory_mb, current_memory_mb)
                    
                except MemoryError:
                    result.violations.append(
                        f"Memory allocation failed at {pressure_level*100}% pressure"
                    )
                    break
            
            # Test learning under pressure
            pressure_test_duration = min(30, duration - (time.time() - start_time))
            pressure_start = time.time()
            
            success_count = 0
            failure_count = 0
            
            while time.time() - pressure_start < pressure_test_duration:
                try:
                    pattern = self._generate_pattern_sized(1000)
                    await self.mcp_cluster.learn_pattern(pattern)
                    success_count += 1
                    result.patterns_stored += 1
                except Exception as e:
                    failure_count += 1
                    if "memory" in str(e).lower():
                        result.violations.append(
                            f"Learning failed under {pressure_level*100}% pressure: {str(e)}"
                        )
                
                await asyncio.sleep(0.1)
            
            # Record metrics
            result.metrics[f'pressure_{int(pressure_level*100)}'] = {
                'success_rate': success_count / (success_count + failure_count) if (success_count + failure_count) > 0 else 0,
                'operations_completed': success_count,
                'memory_mb': current_memory_mb
            }
            
            # Release some memory for next level
            if allocation_chunks:
                release_count = len(allocation_chunks) // 4
                for _ in range(release_count):
                    if allocation_chunks:
                        allocation_chunks.pop()
                gc.collect()
        
        result.duration = time.time() - start_time
        result.final_memory_mb = self.memory_monitor.get_current_usage() / (1024**2)
        
        # Calculate efficiency under pressure
        total_ops = sum(m.get('operations_completed', 0) for m in result.metrics.values())
        if result.memory_growth_mb > 0:
            result.memory_efficiency = total_ops / result.memory_growth_mb
        
        return result
    
    async def test_memory_fragmentation(self, duration: int) -> MemoryScenarioResult:
        """Test memory fragmentation effects."""
        logger.info("Testing memory fragmentation")
        
        gc.collect()
        initial_memory = self.memory_monitor.get_current_usage() / (1024**2)
        
        result = MemoryScenarioResult(
            scenario_name="fragmentation",
            duration=0,
            initial_memory_mb=initial_memory,
            peak_memory_mb=initial_memory,
            final_memory_mb=initial_memory,
            memory_efficiency=0,
            patterns_stored=0,
            memory_per_pattern_kb=0
        )
        
        start_time = time.time()
        fragmentation_cycles = []
        
        cycle_count = 0
        while time.time() - start_time < duration:
            cycle_count += 1
            logger.info(f"Fragmentation cycle {cycle_count}")
            
            cycle_metrics = {
                'cycle': cycle_count,
                'allocations': 0,
                'deallocations': 0,
                'fragmentation_impact': 0
            }
            
            # Phase 1: Allocate patterns of varying sizes
            pattern_ids = []
            sizes = [100, 500, 1000, 5000, 10000]
            
            for _ in range(200):
                size = np.random.choice(sizes)
                pattern = self._generate_pattern_sized(size)
                
                try:
                    pattern_id = await self.mcp_cluster.store_pattern(pattern)
                    pattern_ids.append((pattern_id, size))
                    cycle_metrics['allocations'] += 1
                    result.patterns_stored += 1
                except Exception as e:
                    logger.error(f"Allocation failed: {e}")
            
            mid_memory = self.memory_monitor.get_current_usage() / (1024**2)
            result.peak_memory_mb = max(result.peak_memory_mb, mid_memory)
            
            # Phase 2: Delete patterns in non-sequential order
            # This creates fragmentation
            np.random.shuffle(pattern_ids)
            delete_count = len(pattern_ids) // 2
            
            for i in range(delete_count):
                pattern_id, _ = pattern_ids[i]
                try:
                    await self.mcp_cluster.delete_pattern(pattern_id)
                    cycle_metrics['deallocations'] += 1
                except Exception as e:
                    logger.error(f"Deletion failed: {e}")
            
            fragmented_memory = self.memory_monitor.get_current_usage() / (1024**2)
            
            # Phase 3: Try to allocate large patterns
            large_pattern_size = 50000
            large_success = 0
            large_failures = 0
            
            for _ in range(10):
                try:
                    large_pattern = self._generate_pattern_sized(large_pattern_size)
                    await self.mcp_cluster.store_pattern(large_pattern)
                    large_success += 1
                    result.patterns_stored += 1
                except Exception as e:
                    large_failures += 1
                    if "memory" in str(e).lower():
                        logger.warning(f"Large allocation failed due to fragmentation: {e}")
            
            final_cycle_memory = self.memory_monitor.get_current_usage() / (1024**2)
            
            # Calculate fragmentation impact
            expected_memory = mid_memory - (mid_memory - initial_memory) * (delete_count / cycle_metrics['allocations'])
            fragmentation_overhead = fragmented_memory - expected_memory
            cycle_metrics['fragmentation_impact'] = fragmentation_overhead
            cycle_metrics['large_allocation_success_rate'] = large_success / (large_success + large_failures)
            
            fragmentation_cycles.append(cycle_metrics)
            
            # Defragment (clear all and start fresh)
            if cycle_count < 3:  # Don't clear on last cycle
                await self.mcp_cluster.clear_patterns()
                gc.collect()
                await asyncio.sleep(2)
        
        result.duration = time.time() - start_time
        result.final_memory_mb = self.memory_monitor.get_current_usage() / (1024**2)
        
        # Analyze fragmentation impact
        if fragmentation_cycles:
            avg_impact = np.mean([c['fragmentation_impact'] for c in fragmentation_cycles])
            avg_success_rate = np.mean([c['large_allocation_success_rate'] for c in fragmentation_cycles])
            
            result.metrics['fragmentation_cycles'] = fragmentation_cycles
            result.metrics['avg_fragmentation_impact_mb'] = avg_impact
            result.metrics['avg_large_allocation_success_rate'] = avg_success_rate
            
            # Memory efficiency affected by fragmentation
            result.memory_efficiency = avg_success_rate
        
        return result
    
    async def test_memory_limits(self, duration: int) -> MemoryScenarioResult:
        """Test behavior at memory limits."""
        logger.info("Testing memory limits")
        
        gc.collect()
        initial_memory = self.memory_monitor.get_current_usage() / (1024**2)
        
        result = MemoryScenarioResult(
            scenario_name="memory_limits",
            duration=0,
            initial_memory_mb=initial_memory,
            peak_memory_mb=initial_memory,
            final_memory_mb=initial_memory,
            memory_efficiency=0,
            patterns_stored=0,
            memory_per_pattern_kb=0
        )
        
        start_time = time.time()
        
        # Track limit violations
        limit_tests = {
            'total': {'limit_mb': self.limits['total_gb'] * 1024, 'violations': 0},
            'working': {'limit_mb': self.limits['working_gb'] * 1024, 'violations': 0},
            'learning': {'limit_mb': self.limits['learning_gb'] * 1024, 'violations': 0}
        }
        
        # Gradually approach limits
        patterns_batch = 100
        batch_count = 0
        
        while time.time() - start_time < duration:
            # Store batch of patterns
            for _ in range(patterns_batch):
                pattern = self._generate_pattern_sized(10000)  # Large patterns
                
                try:
                    await self.mcp_cluster.store_pattern(pattern)
                    result.patterns_stored += 1
                except Exception as e:
                    if "memory" in str(e).lower():
                        result.violations.append(f"Pattern storage failed: {str(e)}")
                    break
            
            batch_count += 1
            
            # Check memory usage
            current_usage = self.memory_monitor.get_detailed_usage()
            current_total_mb = current_usage['total'] / (1024**2)
            current_working_mb = current_usage.get('working', current_usage['total']) / (1024**2)
            current_learning_mb = current_usage.get('learning', current_usage['total'] * 0.4) / (1024**2)
            
            result.peak_memory_mb = max(result.peak_memory_mb, current_total_mb)
            
            # Check limits
            for limit_type, limit_info in limit_tests.items():
                current_mb = {
                    'total': current_total_mb,
                    'working': current_working_mb,
                    'learning': current_learning_mb
                }[limit_type]
                
                if current_mb > limit_info['limit_mb']:
                    limit_info['violations'] += 1
                    result.violations.append(
                        f"{limit_type} memory exceeded: {current_mb:.1f}MB > {limit_info['limit_mb']:.1f}MB"
                    )
            
            # Test operations at current memory level
            operation_test_results = await self._test_operations_at_memory_level(
                current_total_mb / (self.limits['total_gb'] * 1024)
            )
            
            result.metrics[f'batch_{batch_count}'] = {
                'memory_mb': current_total_mb,
                'memory_percent': (current_total_mb / (self.limits['total_gb'] * 1024)) * 100,
                'operations': operation_test_results
            }
            
            # Stop if we're at critical threshold
            if current_total_mb > self.limits['total_gb'] * 1024 * self.limits['critical_threshold']:
                logger.warning("Reached critical memory threshold, stopping test")
                break
            
            # Adaptive delay based on memory pressure
            memory_pressure = current_total_mb / (self.limits['total_gb'] * 1024)
            delay = 0.1 + (memory_pressure * 2)  # Increase delay as memory fills
            await asyncio.sleep(delay)
        
        result.duration = time.time() - start_time
        result.final_memory_mb = self.memory_monitor.get_current_usage() / (1024**2)
        
        # Calculate efficiency at limits
        if result.patterns_stored > 0:
            result.memory_per_pattern_kb = (
                (result.final_memory_mb - result.initial_memory_mb) * 1024 / 
                result.patterns_stored
            )
            result.memory_efficiency = result.patterns_stored / result.final_memory_mb
        
        # Summary of limit violations
        result.metrics['limit_violations'] = {
            limit_type: info['violations'] 
            for limit_type, info in limit_tests.items()
        }
        
        return result
    
    async def _test_operations_at_memory_level(self, memory_percent: float) -> Dict[str, Any]:
        """Test various operations at current memory level."""
        operations = {
            'pattern_match': {'success': 0, 'failed': 0, 'avg_time': 0},
            'learning_update': {'success': 0, 'failed': 0, 'avg_time': 0},
            'knowledge_share': {'success': 0, 'failed': 0, 'avg_time': 0}
        }
        
        test_count = 10
        
        # Test pattern matching
        pattern = self._generate_pattern_sized(1000)
        times = []
        
        for _ in range(test_count):
            try:
                start = time.perf_counter()
                await self.mcp_cluster.match_pattern(pattern)
                elapsed = time.perf_counter() - start
                operations['pattern_match']['success'] += 1
                times.append(elapsed)
            except Exception:
                operations['pattern_match']['failed'] += 1
        
        if times:
            operations['pattern_match']['avg_time'] = np.mean(times)
        
        # Test learning update
        times = []
        for _ in range(test_count):
            try:
                start = time.perf_counter()
                await self.mcp_cluster.update_learning({'data': 'test'})
                elapsed = time.perf_counter() - start
                operations['learning_update']['success'] += 1
                times.append(elapsed)
            except Exception:
                operations['learning_update']['failed'] += 1
        
        if times:
            operations['learning_update']['avg_time'] = np.mean(times)
        
        # Test knowledge sharing
        times = []
        for _ in range(test_count):
            try:
                start = time.perf_counter()
                await self.mcp_cluster.share_knowledge('source', 'target', {'data': 'test'})
                elapsed = time.perf_counter() - start
                operations['knowledge_share']['success'] += 1
                times.append(elapsed)
            except Exception:
                operations['knowledge_share']['failed'] += 1
        
        if times:
            operations['knowledge_share']['avg_time'] = np.mean(times)
        
        return operations
    
    def _generate_pattern_sized(self, size: int) -> Dict[str, Any]:
        """Generate pattern of specific size."""
        return {
            'id': f"pattern_{time.time()}_{np.random.randint(1000000)}",
            'data': np.random.rand(size).tolist(),
            'metadata': {
                'size': size,
                'timestamp': time.time()
            }
        }
    
    def _generate_variable_pattern(self) -> Dict[str, Any]:
        """Generate pattern with variable size."""
        # Use exponential distribution for realistic size variation
        size = int(np.random.exponential(1000)) + 100
        size = min(size, 50000)  # Cap at 50k
        
        return self._generate_pattern_sized(size)
    
    def _generate_memory_summary(self, results: Dict[str, MemoryScenarioResult]) -> Dict[str, Any]:
        """Generate summary of memory efficiency results."""
        summary = {
            'total_patterns_stored': 0,
            'peak_memory_mb': 0,
            'avg_memory_per_pattern_kb': 0,
            'violations_count': 0,
            'recommendations': []
        }
        
        # Aggregate metrics
        total_patterns = 0
        total_memory_kb = 0
        
        for name, result in results.items():
            if isinstance(result, MemoryScenarioResult):
                summary['total_patterns_stored'] += result.patterns_stored
                summary['peak_memory_mb'] = max(summary['peak_memory_mb'], result.peak_memory_mb)
                summary['violations_count'] += len(result.violations)
                
                if result.patterns_stored > 0:
                    total_patterns += result.patterns_stored
                    total_memory_kb += result.memory_per_pattern_kb * result.patterns_stored
        
        if total_patterns > 0:
            summary['avg_memory_per_pattern_kb'] = total_memory_kb / total_patterns
        
        # Generate recommendations
        if 'continuous_growth' in results:
            growth_rate = results['continuous_growth'].metrics.get('growth_rate_mb_per_sec', 0)
            if growth_rate > 1.0:  # More than 1MB/sec
                summary['recommendations'].append(
                    f"High memory growth rate ({growth_rate:.2f}MB/s) - implement memory pooling or caching limits"
                )
        
        if 'fragmentation' in results:
            frag_impact = results['fragmentation'].metrics.get('avg_fragmentation_impact_mb', 0)
            if frag_impact > 100:  # More than 100MB fragmentation
                summary['recommendations'].append(
                    f"Significant fragmentation ({frag_impact:.1f}MB) - implement memory compaction"
                )
        
        if 'memory_pressure' in results:
            pressure_95 = results['memory_pressure'].metrics.get('pressure_95', {})
            if pressure_95.get('success_rate', 1) < 0.9:
                summary['recommendations'].append(
                    "Poor performance under memory pressure - implement graceful degradation"
                )
        
        if summary['violations_count'] > 0:
            summary['recommendations'].append(
                f"Memory limit violations detected ({summary['violations_count']}) - "
                "review memory allocation strategy"
            )
        
        # Memory efficiency rating
        if summary['avg_memory_per_pattern_kb'] > 0:
            if summary['avg_memory_per_pattern_kb'] < 10:
                summary['efficiency_rating'] = 'Excellent'
            elif summary['avg_memory_per_pattern_kb'] < 50:
                summary['efficiency_rating'] = 'Good'
            elif summary['avg_memory_per_pattern_kb'] < 100:
                summary['efficiency_rating'] = 'Fair'
            else:
                summary['efficiency_rating'] = 'Poor'
        
        return summary