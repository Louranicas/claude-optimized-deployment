# Memory Optimization Testing Strategy

## Overview

This document provides a comprehensive testing strategy for validating memory optimizations in the Claude Optimized Deployment project. It covers object pool efficiency, memory leak detection, garbage collection performance, cache eviction, and memory pressure simulation.

## Table of Contents

1. [Object Pool Efficiency Tests](#object-pool-efficiency-tests)
2. [Memory Leak Detection Procedures](#memory-leak-detection-procedures)
3. [GC Performance Validation](#gc-performance-validation)
4. [Cache Eviction Testing](#cache-eviction-testing)
5. [Memory Pressure Simulation](#memory-pressure-simulation)
6. [Performance Benchmarks and Thresholds](#performance-benchmarks-and-thresholds)
7. [Memory Profiling Procedures](#memory-profiling-procedures)
8. [Regression Test Suite](#regression-test-suite)

## Object Pool Efficiency Tests

### Test Categories

1. **Pool Allocation Performance**
   - Measure allocation speed vs direct instantiation
   - Track pool hit rate
   - Monitor pool size growth

2. **Resource Utilization**
   - Verify proper resource recycling
   - Check for resource leaks in pool
   - Validate cleanup procedures

### Test Implementation

```python
# tests/test_object_pool_efficiency.py
import pytest
import time
import tracemalloc
from typing import List, Dict, Any
import psutil
import gc

from src.core.object_pool import ObjectPool, PoolableObject


class TestConnection(PoolableObject):
    """Mock connection object for testing"""
    def __init__(self):
        self.data = bytearray(1024 * 10)  # 10KB per object
        self.active = True
        self.reset_count = 0
    
    def reset(self):
        """Reset connection state"""
        self.data = bytearray(1024 * 10)
        self.active = True
        self.reset_count += 1
    
    def close(self):
        """Cleanup connection"""
        self.active = False
        self.data = None


class TestObjectPoolEfficiency:
    """Test suite for object pool efficiency"""
    
    @pytest.fixture
    def pool(self):
        """Create a test pool"""
        return ObjectPool(
            factory=TestConnection,
            min_size=5,
            max_size=20,
            ttl=60
        )
    
    def test_allocation_performance(self, pool, benchmark):
        """Benchmark pool allocation vs direct instantiation"""
        
        def allocate_from_pool():
            obj = pool.acquire()
            pool.release(obj)
        
        def allocate_direct():
            obj = TestConnection()
            obj.close()
        
        # Benchmark pool allocation
        pool_result = benchmark.pedantic(
            allocate_from_pool,
            rounds=1000,
            iterations=10
        )
        
        # Benchmark direct allocation
        direct_result = benchmark.pedantic(
            allocate_direct,
            rounds=1000,
            iterations=10
        )
        
        # Pool should be at least 50% faster after warmup
        assert pool_result.stats['mean'] < direct_result.stats['mean'] * 0.5
    
    def test_pool_hit_rate(self, pool):
        """Test pool hit rate under various loads"""
        hits = 0
        misses = 0
        
        # Warm up the pool
        objects = []
        for _ in range(pool.min_size):
            objects.append(pool.acquire())
        for obj in objects:
            pool.release(obj)
        
        # Track hits and misses
        initial_created = pool.stats['objects_created']
        
        # High reuse scenario
        for _ in range(100):
            obj = pool.acquire()
            pool.release(obj)
        
        final_created = pool.stats['objects_created']
        new_objects = final_created - initial_created
        
        hit_rate = (100 - new_objects) / 100
        assert hit_rate > 0.95  # 95% hit rate expected
    
    def test_memory_efficiency(self, pool):
        """Test memory usage efficiency"""
        tracemalloc.start()
        
        # Baseline memory
        gc.collect()
        baseline = tracemalloc.get_traced_memory()[0]
        
        # Allocate and release many objects
        for _ in range(1000):
            obj = pool.acquire()
            pool.release(obj)
        
        # Check memory after operations
        gc.collect()
        current = tracemalloc.get_traced_memory()[0]
        memory_growth = current - baseline
        
        # Memory growth should be minimal (< 1MB)
        assert memory_growth < 1024 * 1024
        
        tracemalloc.stop()
    
    def test_concurrent_access(self, pool):
        """Test pool efficiency under concurrent access"""
        import threading
        import queue
        
        results = queue.Queue()
        errors = queue.Queue()
        
        def worker():
            try:
                start = time.time()
                for _ in range(100):
                    obj = pool.acquire()
                    time.sleep(0.001)  # Simulate work
                    pool.release(obj)
                results.put(time.time() - start)
            except Exception as e:
                errors.put(e)
        
        # Run concurrent workers
        threads = []
        for _ in range(10):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Check for errors
        assert errors.empty(), f"Errors occurred: {list(errors.queue)}"
        
        # Verify all workers completed
        assert results.qsize() == 10
        
        # Check performance consistency
        times = list(results.queue)
        avg_time = sum(times) / len(times)
        assert all(abs(t - avg_time) < avg_time * 0.2 for t in times)


## Memory Leak Detection Procedures

### Leak Detection Strategy

1. **Baseline Measurement**
   - Establish memory baseline
   - Track object counts
   - Monitor reference cycles

2. **Stress Testing**
   - Run operations in loops
   - Force garbage collection
   - Measure memory growth

### Test Implementation

```python
# tests/test_memory_leaks.py
import pytest
import gc
import weakref
import tracemalloc
import objgraph
from memory_profiler import profile
import asyncio
from typing import List, Set, Dict

from src.circle_of_experts.core.expert_manager import ExpertManager
from src.auth.models import User, Session
from src.core.connections import ConnectionPool


class MemoryLeakDetector:
    """Utility class for detecting memory leaks"""
    
    def __init__(self):
        self.baseline_objects: Dict[type, int] = {}
        self.tracked_refs: Set[weakref.ref] = set()
    
    def take_snapshot(self):
        """Take a snapshot of current object counts"""
        gc.collect()
        self.baseline_objects = {}
        for obj in gc.get_objects():
            obj_type = type(obj)
            self.baseline_objects[obj_type] = self.baseline_objects.get(obj_type, 0) + 1
    
    def track_object(self, obj):
        """Track an object with weak reference"""
        self.tracked_refs.add(weakref.ref(obj))
    
    def check_leaks(self) -> Dict[type, int]:
        """Check for object leaks since baseline"""
        gc.collect()
        current_objects = {}
        
        for obj in gc.get_objects():
            obj_type = type(obj)
            current_objects[obj_type] = current_objects.get(obj_type, 0) + 1
        
        leaks = {}
        for obj_type, count in current_objects.items():
            baseline = self.baseline_objects.get(obj_type, 0)
            if count > baseline + 10:  # Allow small variations
                leaks[obj_type] = count - baseline
        
        return leaks
    
    def check_tracked_objects(self) -> List[object]:
        """Check if tracked objects were properly cleaned up"""
        gc.collect()
        alive_objects = []
        
        for ref in self.tracked_refs:
            obj = ref()
            if obj is not None:
                alive_objects.append(obj)
        
        return alive_objects


class TestMemoryLeaks:
    """Test suite for memory leak detection"""
    
    @pytest.fixture
    def leak_detector(self):
        """Create a leak detector instance"""
        return MemoryLeakDetector()
    
    def test_expert_manager_lifecycle(self, leak_detector):
        """Test ExpertManager for memory leaks"""
        leak_detector.take_snapshot()
        
        # Create and destroy many expert managers
        for i in range(100):
            manager = ExpertManager()
            leak_detector.track_object(manager)
            
            # Simulate operations
            asyncio.run(manager.initialize())
            asyncio.run(manager.shutdown())
            
            del manager
        
        # Check for leaks
        leaks = leak_detector.check_leaks()
        assert not leaks, f"Memory leaks detected: {leaks}"
        
        # Check tracked objects
        alive = leak_detector.check_tracked_objects()
        assert not alive, f"Objects not cleaned up: {alive}"
    
    def test_connection_pool_leaks(self, leak_detector):
        """Test connection pool for memory leaks"""
        tracemalloc.start()
        
        # Baseline
        gc.collect()
        snapshot1 = tracemalloc.take_snapshot()
        
        # Stress test connection pool
        for _ in range(50):
            pool = ConnectionPool(min_size=10, max_size=50)
            
            # Acquire and release connections
            connections = []
            for _ in range(100):
                conn = pool.acquire()
                connections.append(conn)
            
            for conn in connections:
                pool.release(conn)
            
            pool.close()
            del pool
        
        # Final snapshot
        gc.collect()
        snapshot2 = tracemalloc.take_snapshot()
        
        # Analyze differences
        top_stats = snapshot2.compare_to(snapshot1, 'lineno')
        
        # Check for significant memory growth
        total_growth = sum(stat.size_diff for stat in top_stats if stat.size_diff > 0)
        assert total_growth < 10 * 1024 * 1024  # Less than 10MB growth
        
        tracemalloc.stop()
    
    def test_circular_reference_detection(self, leak_detector):
        """Test for circular reference leaks"""
        
        class Node:
            def __init__(self):
                self.refs = []
                self.data = bytearray(1024)  # 1KB
        
        leak_detector.take_snapshot()
        
        # Create circular references
        for _ in range(100):
            # Create circular reference chain
            nodes = [Node() for _ in range(10)]
            for i in range(10):
                nodes[i].refs.append(nodes[(i + 1) % 10])
            
            # Track the first node
            leak_detector.track_object(nodes[0])
            
            # Delete local references
            del nodes
        
        # Force garbage collection
        gc.collect()
        
        # Check for leaks
        leaks = leak_detector.check_leaks()
        node_leaks = leaks.get(Node, 0)
        assert node_leaks == 0, f"Circular references not collected: {node_leaks} nodes leaked"
    
    @pytest.mark.asyncio
    async def test_async_context_leaks(self, leak_detector):
        """Test async context managers for leaks"""
        
        class AsyncResource:
            def __init__(self):
                self.data = bytearray(1024 * 100)  # 100KB
                self.closed = False
            
            async def __aenter__(self):
                return self
            
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                self.closed = True
                self.data = None
        
        leak_detector.take_snapshot()
        
        # Test normal usage
        for _ in range(100):
            async with AsyncResource() as resource:
                # Simulate work
                await asyncio.sleep(0.001)
        
        # Test exception handling
        for _ in range(100):
            try:
                async with AsyncResource() as resource:
                    raise ValueError("Test exception")
            except ValueError:
                pass
        
        # Check for leaks
        await asyncio.sleep(0.1)  # Allow cleanup
        gc.collect()
        
        leaks = leak_detector.check_leaks()
        resource_leaks = leaks.get(AsyncResource, 0)
        assert resource_leaks == 0, f"Async resources leaked: {resource_leaks}"


## GC Performance Validation

### GC Testing Strategy

1. **Collection Frequency**
   - Monitor GC runs
   - Measure collection time
   - Track memory reclaimed

2. **Performance Impact**
   - Measure latency during GC
   - Monitor CPU usage
   - Track application pauses

### Test Implementation

```python
# tests/test_gc_performance.py
import pytest
import gc
import time
import statistics
from typing import List, Dict
import threading
import psutil

from src.core.gc_optimization import GCOptimizer, gc_performance_monitor


class TestGCPerformance:
    """Test suite for garbage collection performance"""
    
    @pytest.fixture
    def gc_optimizer(self):
        """Create GC optimizer instance"""
        optimizer = GCOptimizer()
        optimizer.start()
        yield optimizer
        optimizer.stop()
    
    def test_gc_frequency_optimization(self, gc_optimizer):
        """Test GC frequency under different workloads"""
        
        # Baseline GC stats
        gc.collect()
        initial_stats = gc.get_stats()
        initial_count = sum(stat['collections'] for stat in initial_stats)
        
        # Light workload
        start_time = time.time()
        for _ in range(1000):
            data = [i for i in range(100)]
            del data
        
        light_duration = time.time() - start_time
        light_stats = gc.get_stats()
        light_collections = sum(stat['collections'] for stat in light_stats) - initial_count
        
        # Heavy workload
        start_time = time.time()
        for _ in range(100):
            data = [bytearray(1024 * 100) for _ in range(10)]  # 1MB allocations
            del data
        
        heavy_duration = time.time() - start_time
        heavy_stats = gc.get_stats()
        heavy_collections = sum(stat['collections'] for stat in heavy_stats) - light_collections - initial_count
        
        # Verify adaptive behavior
        assert light_collections < 5, "Too many GC runs for light workload"
        assert heavy_collections > light_collections, "GC should run more frequently under heavy load"
    
    def test_gc_pause_times(self, gc_optimizer):
        """Measure GC pause times"""
        pause_times = []
        
        def measure_gc_pause():
            """Measure single GC pause"""
            gc.disable()
            
            # Create garbage
            garbage = []
            for _ in range(1000):
                obj = {'data': bytearray(1024), 'refs': []}
                garbage.append(obj)
            
            # Measure collection time
            start = time.perf_counter()
            gc.collect()
            pause = time.perf_counter() - start
            
            gc.enable()
            return pause
        
        # Collect pause time samples
        for _ in range(20):
            pause_times.append(measure_gc_pause())
        
        # Analyze pause times
        avg_pause = statistics.mean(pause_times)
        max_pause = max(pause_times)
        p99_pause = sorted(pause_times)[int(len(pause_times) * 0.99)]
        
        # Performance assertions
        assert avg_pause < 0.01, f"Average GC pause too high: {avg_pause:.3f}s"
        assert max_pause < 0.05, f"Maximum GC pause too high: {max_pause:.3f}s"
        assert p99_pause < 0.02, f"99th percentile GC pause too high: {p99_pause:.3f}s"
    
    def test_memory_reclamation_efficiency(self, gc_optimizer):
        """Test memory reclamation efficiency"""
        process = psutil.Process()
        
        # Baseline memory
        gc.collect()
        baseline_memory = process.memory_info().rss
        
        # Allocate memory
        allocations = []
        for _ in range(100):
            data = bytearray(1024 * 1024)  # 1MB
            allocations.append(data)
        
        peak_memory = process.memory_info().rss
        allocated = peak_memory - baseline_memory
        
        # Clear references
        allocations.clear()
        
        # Force collection
        gc.collect()
        time.sleep(0.1)  # Allow OS to reclaim
        
        final_memory = process.memory_info().rss
        reclaimed = peak_memory - final_memory
        
        # Should reclaim at least 90% of allocated memory
        reclaim_ratio = reclaimed / allocated if allocated > 0 else 0
        assert reclaim_ratio > 0.9, f"Poor memory reclamation: {reclaim_ratio:.1%}"
    
    @gc_performance_monitor
    def test_gc_monitoring_decorator(self):
        """Test GC performance monitoring decorator"""
        
        # Create some garbage
        data = []
        for i in range(1000):
            data.append({'index': i, 'data': bytearray(1024)})
        
        # Trigger collection
        del data
        gc.collect()
        
        # The decorator should log performance metrics
        # Check logs or metrics system for recorded data
    
    def test_gc_impact_on_latency(self, gc_optimizer):
        """Test GC impact on request latency"""
        latencies = []
        gc_happened = False
        
        def gc_callback(phase, info):
            nonlocal gc_happened
            gc_happened = True
        
        # Monitor GC events
        gc.callbacks.append(gc_callback)
        
        try:
            # Simulate request processing
            for _ in range(1000):
                start = time.perf_counter()
                
                # Simulate work
                data = [i ** 2 for i in range(1000)]
                result = sum(data)
                
                latency = time.perf_counter() - start
                latencies.append(latency)
                
                # Create garbage to trigger GC
                garbage = [bytearray(1024) for _ in range(100)]
                del garbage
            
            # Analyze latencies
            avg_latency = statistics.mean(latencies)
            p99_latency = sorted(latencies)[int(len(latencies) * 0.99)]
            
            # Ensure GC happened during test
            assert gc_happened, "GC did not occur during test"
            
            # Latency should remain acceptable even with GC
            assert avg_latency < 0.001, f"Average latency too high: {avg_latency:.3f}s"
            assert p99_latency < 0.005, f"P99 latency too high: {p99_latency:.3f}s"
            
        finally:
            gc.callbacks.remove(gc_callback)


## Cache Eviction Testing

### Eviction Strategy Tests

1. **LRU Behavior**
   - Verify least recently used eviction
   - Test access pattern tracking
   - Validate eviction order

2. **TTL Expiration**
   - Test time-based eviction
   - Verify expired item cleanup
   - Check memory release

### Test Implementation

```python
# tests/test_cache_eviction.py
import pytest
import time
import threading
from unittest.mock import Mock, patch
import weakref

from src.core.lru_cache import LRUCache, TTLCache, AdaptiveCache


class TestCacheEviction:
    """Test suite for cache eviction strategies"""
    
    def test_lru_eviction_order(self):
        """Test LRU eviction follows access order"""
        cache = LRUCache(max_size=3)
        
        # Fill cache
        cache.put('a', 1)
        cache.put('b', 2)
        cache.put('c', 3)
        
        # Access 'a' to make it recently used
        assert cache.get('a') == 1
        
        # Add new item, should evict 'b' (least recently used)
        cache.put('d', 4)
        
        assert cache.get('a') == 1
        assert cache.get('c') == 3
        assert cache.get('d') == 4
        assert cache.get('b') is None  # Evicted
    
    def test_ttl_expiration(self):
        """Test TTL-based cache expiration"""
        cache = TTLCache(default_ttl=0.1)  # 100ms TTL
        
        # Add items
        cache.put('short', 1, ttl=0.05)  # 50ms
        cache.put('medium', 2, ttl=0.15)  # 150ms
        cache.put('long', 3, ttl=0.3)  # 300ms
        
        # Immediate access should work
        assert cache.get('short') == 1
        assert cache.get('medium') == 2
        assert cache.get('long') == 3
        
        # After 60ms, short should expire
        time.sleep(0.06)
        assert cache.get('short') is None
        assert cache.get('medium') == 2
        assert cache.get('long') == 3
        
        # After 160ms total, medium should expire
        time.sleep(0.1)
        assert cache.get('medium') is None
        assert cache.get('long') == 3
        
        # After 310ms total, all should expire
        time.sleep(0.15)
        assert cache.get('long') is None
    
    def test_memory_pressure_eviction(self):
        """Test eviction under memory pressure"""
        cache = AdaptiveCache(
            max_size=100,
            max_memory_mb=1,  # 1MB limit
            eviction_batch_size=10
        )
        
        # Fill cache with large objects
        for i in range(100):
            # Each object ~10KB
            cache.put(f'key_{i}', bytearray(10 * 1024))
        
        # Cache should have evicted items to stay under memory limit
        assert cache.size < 100
        assert cache.memory_usage < 1024 * 1024
        
        # Verify most recently added items are kept
        for i in range(90, 100):
            assert cache.get(f'key_{i}') is not None
    
    def test_concurrent_eviction_safety(self):
        """Test cache eviction under concurrent access"""
        cache = LRUCache(max_size=50)
        errors = []
        
        def writer(start_idx):
            try:
                for i in range(100):
                    cache.put(f'key_{start_idx}_{i}', i)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)
        
        def reader():
            try:
                for _ in range(200):
                    key = f'key_{_ % 200}'
                    cache.get(key)
                    time.sleep(0.0005)
            except Exception as e:
                errors.append(e)
        
        # Run concurrent operations
        threads = []
        for i in range(3):
            t = threading.Thread(target=writer, args=(i * 100,))
            threads.append(t)
            t.start()
        
        for i in range(2):
            t = threading.Thread(target=reader)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert not errors, f"Errors during concurrent access: {errors}"
        assert cache.size <= cache.max_size
    
    def test_eviction_callbacks(self):
        """Test eviction callback functionality"""
        evicted_items = []
        
        def on_evict(key, value):
            evicted_items.append((key, value))
        
        cache = LRUCache(max_size=3, on_evict=on_evict)
        
        # Fill and overflow cache
        for i in range(5):
            cache.put(f'key_{i}', i)
        
        # Check eviction callbacks were called
        assert len(evicted_items) == 2
        assert evicted_items[0] == ('key_0', 0)
        assert evicted_items[1] == ('key_1', 1)
    
    def test_weak_reference_eviction(self):
        """Test cache with weak references"""
        cache = LRUCache(max_size=10, use_weak_refs=True)
        
        class TestObject:
            def __init__(self, value):
                self.value = value
        
        # Add objects to cache
        obj1 = TestObject(1)
        obj2 = TestObject(2)
        
        cache.put('obj1', obj1)
        cache.put('obj2', obj2)
        
        # Objects should be retrievable
        assert cache.get('obj1').value == 1
        assert cache.get('obj2').value == 2
        
        # Delete strong reference
        del obj1
        
        # Force garbage collection
        import gc
        gc.collect()
        
        # obj1 should be gone (weak ref cleared)
        assert cache.get('obj1') is None
        assert cache.get('obj2').value == 2


## Memory Pressure Simulation

### Pressure Testing Strategy

1. **Gradual Pressure**
   - Incrementally increase memory usage
   - Monitor system behavior
   - Test degradation handling

2. **Spike Testing**
   - Sudden memory spikes
   - Recovery behavior
   - Emergency eviction

### Test Implementation

```python
# tests/test_memory_pressure.py
import pytest
import psutil
import asyncio
import time
from typing import List
import numpy as np

from src.core.memory_monitor import MemoryMonitor
from src.monitoring.memory_alerts import MemoryAlertSystem


class MemoryPressureSimulator:
    """Simulate various memory pressure scenarios"""
    
    def __init__(self):
        self.allocations: List[np.ndarray] = []
        self.monitor = MemoryMonitor()
    
    def allocate_memory(self, size_mb: int):
        """Allocate memory in MB"""
        # Allocate as numpy array (more predictable than Python lists)
        size_bytes = size_mb * 1024 * 1024
        elements = size_bytes // 8  # 8 bytes per float64
        array = np.ones(elements, dtype=np.float64)
        self.allocations.append(array)
        return array
    
    def release_memory(self, count: int = 1):
        """Release allocated memory"""
        for _ in range(min(count, len(self.allocations))):
            if self.allocations:
                self.allocations.pop()
    
    def get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        process = psutil.Process()
        return process.memory_info().rss / (1024 * 1024)


class TestMemoryPressure:
    """Test suite for memory pressure scenarios"""
    
    @pytest.fixture
    def simulator(self):
        """Create memory pressure simulator"""
        sim = MemoryPressureSimulator()
        yield sim
        # Cleanup
        sim.allocations.clear()
    
    def test_gradual_memory_pressure(self, simulator):
        """Test system behavior under gradual memory increase"""
        initial_memory = simulator.get_memory_usage()
        memory_readings = []
        
        # Gradually increase memory usage
        for i in range(20):
            simulator.allocate_memory(10)  # 10MB at a time
            current_memory = simulator.get_memory_usage()
            memory_readings.append(current_memory - initial_memory)
            
            # Check if system is responding to pressure
            if current_memory > initial_memory + 150:  # 150MB threshold
                # System should start taking defensive actions
                time.sleep(0.1)  # Allow cleanup mechanisms to run
                
                # Verify some cleanup occurred
                new_reading = simulator.get_memory_usage()
                assert new_reading <= current_memory, "No memory cleanup occurred"
        
        # Verify gradual increase pattern
        for i in range(1, len(memory_readings)):
            assert memory_readings[i] >= memory_readings[i-1] * 0.8, \
                "Unexpected memory drop during gradual increase"
    
    def test_memory_spike_recovery(self, simulator):
        """Test recovery from sudden memory spikes"""
        initial_memory = simulator.get_memory_usage()
        
        # Create sudden spike
        spike_size = 200  # 200MB spike
        simulator.allocate_memory(spike_size)
        spike_memory = simulator.get_memory_usage()
        
        assert spike_memory > initial_memory + spike_size * 0.8, \
            "Memory spike not created properly"
        
        # Release memory
        simulator.release_memory()
        
        # Wait for cleanup
        time.sleep(0.5)
        gc.collect()
        
        # Check recovery
        recovered_memory = simulator.get_memory_usage()
        recovery_ratio = (spike_memory - recovered_memory) / (spike_memory - initial_memory)
        
        assert recovery_ratio > 0.8, \
            f"Poor recovery from memory spike: {recovery_ratio:.1%}"
    
    @pytest.mark.asyncio
    async def test_memory_alert_system(self, simulator):
        """Test memory alert system triggers"""
        alerts_received = []
        
        async def alert_handler(alert_type, details):
            alerts_received.append((alert_type, details))
        
        # Setup alert system
        alert_system = MemoryAlertSystem(
            warning_threshold=0.7,
            critical_threshold=0.85,
            check_interval=0.1
        )
        alert_system.add_handler(alert_handler)
        
        # Start monitoring
        monitor_task = asyncio.create_task(alert_system.start_monitoring())
        
        try:
            # Get system memory info
            total_memory = psutil.virtual_memory().total / (1024 * 1024)  # MB
            available = psutil.virtual_memory().available / (1024 * 1024)
            
            # Allocate memory to trigger warning
            warning_allocation = int(available * 0.5)  # Use 50% of available
            simulator.allocate_memory(warning_allocation)
            
            # Wait for alert
            await asyncio.sleep(0.2)
            
            # Should have warning alert
            assert any(alert[0] == 'warning' for alert in alerts_received), \
                "Warning alert not triggered"
            
            # Allocate more for critical
            critical_allocation = int(available * 0.3)  # Use another 30%
            simulator.allocate_memory(critical_allocation)
            
            # Wait for alert
            await asyncio.sleep(0.2)
            
            # Should have critical alert
            assert any(alert[0] == 'critical' for alert in alerts_received), \
                "Critical alert not triggered"
            
        finally:
            alert_system.stop_monitoring()
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
    
    def test_oom_prevention(self, simulator):
        """Test out-of-memory prevention mechanisms"""
        initial_memory = simulator.get_memory_usage()
        available = psutil.virtual_memory().available / (1024 * 1024)
        
        # Try to allocate more than available
        try:
            # Allocate in chunks to test prevention
            chunk_size = 50  # 50MB chunks
            chunks_allocated = 0
            
            while chunks_allocated * chunk_size < available * 1.5:
                # Check if we're approaching limit
                current_usage = simulator.get_memory_usage()
                memory_percent = psutil.virtual_memory().percent
                
                if memory_percent > 90:
                    # System should prevent further allocation
                    break
                
                simulator.allocate_memory(chunk_size)
                chunks_allocated += 1
            
            # Verify we stopped before OOM
            final_percent = psutil.virtual_memory().percent
            assert final_percent < 95, "Failed to prevent OOM condition"
            
        finally:
            # Cleanup
            simulator.allocations.clear()
            gc.collect()


## Performance Benchmarks and Thresholds

### Benchmark Categories

1. **Memory Allocation Speed**
   - Object creation rate
   - Pool allocation speed
   - Memory bandwidth

2. **Garbage Collection Metrics**
   - Collection frequency
   - Pause times
   - Memory reclaimed

3. **Cache Performance**
   - Hit rate
   - Eviction rate
   - Access latency

### Benchmark Implementation

```python
# tests/benchmarks/test_memory_benchmarks.py
import pytest
import time
import statistics
from dataclasses import dataclass
from typing import Dict, List
import json

@dataclass
class BenchmarkResult:
    """Store benchmark results"""
    name: str
    value: float
    unit: str
    threshold: float
    passed: bool
    
    def to_dict(self):
        return {
            'name': self.name,
            'value': self.value,
            'unit': self.unit,
            'threshold': self.threshold,
            'passed': self.passed,
            'status': 'PASS' if self.passed else 'FAIL'
        }


class MemoryBenchmarks:
    """Memory optimization benchmarks"""
    
    # Performance thresholds
    THRESHOLDS = {
        'object_allocation_rate': 1000000,  # objects/second
        'pool_allocation_rate': 2000000,    # objects/second
        'memory_bandwidth': 1000,           # MB/second
        'gc_pause_avg': 0.01,              # seconds
        'gc_pause_p99': 0.05,              # seconds
        'cache_hit_rate': 0.85,            # ratio
        'cache_access_latency': 0.000001,  # seconds (1 microsecond)
    }
    
    def run_all_benchmarks(self) -> List[BenchmarkResult]:
        """Run all memory benchmarks"""
        results = []
        
        # Run each benchmark
        results.append(self.benchmark_object_allocation())
        results.append(self.benchmark_pool_allocation())
        results.append(self.benchmark_memory_bandwidth())
        results.extend(self.benchmark_gc_performance())
        results.extend(self.benchmark_cache_performance())
        
        return results
    
    def benchmark_object_allocation(self) -> BenchmarkResult:
        """Benchmark raw object allocation speed"""
        
        class TestObject:
            def __init__(self):
                self.data = [0] * 100
        
        # Warm up
        for _ in range(1000):
            TestObject()
        
        # Benchmark
        iterations = 100000
        start = time.perf_counter()
        
        for _ in range(iterations):
            obj = TestObject()
        
        duration = time.perf_counter() - start
        rate = iterations / duration
        
        return BenchmarkResult(
            name='object_allocation_rate',
            value=rate,
            unit='objects/second',
            threshold=self.THRESHOLDS['object_allocation_rate'],
            passed=rate >= self.THRESHOLDS['object_allocation_rate']
        )
    
    def benchmark_pool_allocation(self) -> BenchmarkResult:
        """Benchmark pool allocation speed"""
        from src.core.object_pool import ObjectPool
        
        class PooledObject:
            def __init__(self):
                self.data = [0] * 100
            
            def reset(self):
                self.data = [0] * 100
        
        pool = ObjectPool(
            factory=PooledObject,
            min_size=100,
            max_size=1000
        )
        
        # Warm up pool
        objects = []
        for _ in range(100):
            objects.append(pool.acquire())
        for obj in objects:
            pool.release(obj)
        
        # Benchmark
        iterations = 100000
        start = time.perf_counter()
        
        for _ in range(iterations):
            obj = pool.acquire()
            pool.release(obj)
        
        duration = time.perf_counter() - start
        rate = iterations / duration
        
        return BenchmarkResult(
            name='pool_allocation_rate',
            value=rate,
            unit='objects/second',
            threshold=self.THRESHOLDS['pool_allocation_rate'],
            passed=rate >= self.THRESHOLDS['pool_allocation_rate']
        )
    
    def benchmark_memory_bandwidth(self) -> BenchmarkResult:
        """Benchmark memory bandwidth"""
        import numpy as np
        
        # Create large arrays
        size_mb = 100
        size_bytes = size_mb * 1024 * 1024
        elements = size_bytes // 8  # 8 bytes per float64
        
        src = np.ones(elements, dtype=np.float64)
        dst = np.zeros(elements, dtype=np.float64)
        
        # Benchmark memory copy
        iterations = 10
        start = time.perf_counter()
        
        for _ in range(iterations):
            np.copyto(dst, src)
        
        duration = time.perf_counter() - start
        bandwidth = (size_mb * iterations) / duration
        
        return BenchmarkResult(
            name='memory_bandwidth',
            value=bandwidth,
            unit='MB/second',
            threshold=self.THRESHOLDS['memory_bandwidth'],
            passed=bandwidth >= self.THRESHOLDS['memory_bandwidth']
        )
    
    def benchmark_gc_performance(self) -> List[BenchmarkResult]:
        """Benchmark garbage collection performance"""
        import gc
        
        pause_times = []
        
        for _ in range(50):
            # Create garbage
            garbage = []
            for i in range(10000):
                garbage.append({'index': i, 'data': [0] * 100})
            
            # Force collection and measure
            gc.disable()
            start = time.perf_counter()
            gc.collect()
            pause = time.perf_counter() - start
            gc.enable()
            
            pause_times.append(pause)
        
        avg_pause = statistics.mean(pause_times)
        p99_pause = sorted(pause_times)[int(len(pause_times) * 0.99)]
        
        return [
            BenchmarkResult(
                name='gc_pause_avg',
                value=avg_pause,
                unit='seconds',
                threshold=self.THRESHOLDS['gc_pause_avg'],
                passed=avg_pause <= self.THRESHOLDS['gc_pause_avg']
            ),
            BenchmarkResult(
                name='gc_pause_p99',
                value=p99_pause,
                unit='seconds',
                threshold=self.THRESHOLDS['gc_pause_p99'],
                passed=p99_pause <= self.THRESHOLDS['gc_pause_p99']
            )
        ]
    
    def benchmark_cache_performance(self) -> List[BenchmarkResult]:
        """Benchmark cache performance"""
        from src.core.lru_cache import LRUCache
        
        cache = LRUCache(max_size=1000)
        
        # Populate cache
        for i in range(1000):
            cache.put(f'key_{i}', f'value_{i}')
        
        # Benchmark hit rate
        hits = 0
        total = 10000
        
        for i in range(total):
            key = f'key_{i % 1000}'  # All should hit
            if cache.get(key) is not None:
                hits += 1
        
        hit_rate = hits / total
        
        # Benchmark access latency
        iterations = 100000
        start = time.perf_counter()
        
        for i in range(iterations):
            cache.get(f'key_{i % 1000}')
        
        duration = time.perf_counter() - start
        avg_latency = duration / iterations
        
        return [
            BenchmarkResult(
                name='cache_hit_rate',
                value=hit_rate,
                unit='ratio',
                threshold=self.THRESHOLDS['cache_hit_rate'],
                passed=hit_rate >= self.THRESHOLDS['cache_hit_rate']
            ),
            BenchmarkResult(
                name='cache_access_latency',
                value=avg_latency,
                unit='seconds',
                threshold=self.THRESHOLDS['cache_access_latency'],
                passed=avg_latency <= self.THRESHOLDS['cache_access_latency']
            )
        ]


def test_run_memory_benchmarks():
    """Run and validate all memory benchmarks"""
    benchmarks = MemoryBenchmarks()
    results = benchmarks.run_all_benchmarks()
    
    # Print results
    print("\n=== Memory Optimization Benchmarks ===\n")
    for result in results:
        status = "✓" if result.passed else "✗"
        print(f"{status} {result.name}: {result.value:.2f} {result.unit} "
              f"(threshold: {result.threshold:.2f})")
    
    # Save results to file
    with open('memory_benchmark_results.json', 'w') as f:
        json.dump([r.to_dict() for r in results], f, indent=2)
    
    # Assert all benchmarks pass
    failed = [r for r in results if not r.passed]
    assert not failed, f"Failed benchmarks: {[r.name for r in failed]}"


## Memory Profiling Procedures

### Profiling Tools Integration

1. **memory_profiler**
   - Line-by-line memory usage
   - Function decorators
   - Memory usage over time

2. **tracemalloc**
   - Memory allocation tracking
   - Snapshot comparisons
   - Top memory consumers

### Profiling Implementation

```python
# tests/profiling/test_memory_profiling.py
import pytest
import tracemalloc
import linecache
import os
from memory_profiler import profile, memory_usage
from typing import List, Tuple, Dict
import matplotlib.pyplot as plt
import io


class MemoryProfiler:
    """Advanced memory profiling utilities"""
    
    def __init__(self):
        self.snapshots: List[tracemalloc.Snapshot] = []
        self.memory_timeline: List[Tuple[float, float]] = []
    
    def start_profiling(self):
        """Start memory profiling"""
        tracemalloc.start()
        self.snapshots.clear()
        self.memory_timeline.clear()
    
    def take_snapshot(self, label: str = None):
        """Take a memory snapshot"""
        snapshot = tracemalloc.take_snapshot()
        self.snapshots.append((label or f"snapshot_{len(self.snapshots)}", snapshot))
        
        # Record current memory usage
        current, peak = tracemalloc.get_traced_memory()
        self.memory_timeline.append((len(self.memory_timeline), current / 1024 / 1024))
    
    def stop_profiling(self):
        """Stop memory profiling"""
        tracemalloc.stop()
    
    def get_top_allocations(self, snapshot_idx: int = -1, limit: int = 10) -> List[Dict]:
        """Get top memory allocations"""
        if not self.snapshots:
            return []
        
        label, snapshot = self.snapshots[snapshot_idx]
        top_stats = snapshot.statistics('lineno')[:limit]
        
        results = []
        for stat in top_stats:
            frame = stat.traceback[0]
            filename = frame.filename
            line = linecache.getline(filename, frame.lineno).strip()
            
            results.append({
                'file': filename,
                'line': frame.lineno,
                'code': line,
                'size': stat.size / 1024 / 1024,  # MB
                'count': stat.count
            })
        
        return results
    
    def compare_snapshots(self, idx1: int = 0, idx2: int = -1) -> List[Dict]:
        """Compare two snapshots"""
        if len(self.snapshots) < 2:
            return []
        
        label1, snapshot1 = self.snapshots[idx1]
        label2, snapshot2 = self.snapshots[idx2]
        
        top_stats = snapshot2.compare_to(snapshot1, 'lineno')[:10]
        
        results = []
        for stat in top_stats:
            frame = stat.traceback[0]
            
            results.append({
                'file': frame.filename,
                'line': frame.lineno,
                'size_diff': stat.size_diff / 1024 / 1024,  # MB
                'count_diff': stat.count_diff
            })
        
        return results
    
    def plot_memory_usage(self, output_file: str = None):
        """Plot memory usage over time"""
        if not self.memory_timeline:
            return
        
        times, memory = zip(*self.memory_timeline)
        
        plt.figure(figsize=(10, 6))
        plt.plot(times, memory, 'b-', linewidth=2)
        plt.xlabel('Time (snapshots)')
        plt.ylabel('Memory Usage (MB)')
        plt.title('Memory Usage Over Time')
        plt.grid(True, alpha=0.3)
        
        if output_file:
            plt.savefig(output_file)
        else:
            plt.show()
        
        plt.close()


class TestMemoryProfiling:
    """Test suite demonstrating memory profiling"""
    
    @pytest.fixture
    def profiler(self):
        """Create memory profiler"""
        p = MemoryProfiler()
        p.start_profiling()
        yield p
        p.stop_profiling()
    
    def test_profile_memory_leak(self, profiler):
        """Profile a simulated memory leak"""
        
        class LeakyClass:
            instances = []  # Class variable causing leak
            
            def __init__(self):
                self.data = bytearray(1024 * 100)  # 100KB
                LeakyClass.instances.append(self)  # Leak!
        
        # Take baseline snapshot
        profiler.take_snapshot("baseline")
        
        # Create objects
        for i in range(100):
            obj = LeakyClass()
            if i % 10 == 0:
                profiler.take_snapshot(f"iteration_{i}")
        
        # Final snapshot
        profiler.take_snapshot("final")
        
        # Analyze growth
        comparison = profiler.compare_snapshots(0, -1)
        
        # Find the leak
        leak_found = False
        for diff in comparison:
            if diff['size_diff'] > 5:  # More than 5MB growth
                if 'LeakyClass' in str(diff['file']):
                    leak_found = True
                    break
        
        assert leak_found, "Memory leak not detected in profiling"
        
        # Cleanup
        LeakyClass.instances.clear()
    
    @profile
    def test_line_by_line_profiling(self):
        """Demonstrate line-by-line memory profiling"""
        
        # Allocate small amount
        small_list = [i for i in range(1000)]  # Line will show small memory usage
        
        # Allocate large amount
        large_list = [bytearray(1024) for _ in range(1000)]  # Line will show ~1MB
        
        # Process data
        result = sum(len(b) for b in large_list)  # Should show minimal increase
        
        # Clear memory
        large_list.clear()  # Memory should decrease
        
        return result
    
    def test_memory_usage_tracking(self):
        """Track memory usage of specific functions"""
        
        def memory_intensive_function():
            # Allocate 10MB
            data = bytearray(10 * 1024 * 1024)
            # Process
            for i in range(len(data)):
                data[i] = i % 256
            return len(data)
        
        # Track memory usage
        mem_usage = memory_usage(memory_intensive_function, interval=0.1)
        
        # Analyze usage pattern
        baseline = mem_usage[0]
        peak = max(mem_usage)
        final = mem_usage[-1]
        
        # Should see ~10MB increase at peak
        assert peak - baseline >= 10, f"Expected 10MB increase, got {peak - baseline:.1f}MB"
        
        # Memory should be released
        assert final - baseline < 2, f"Memory not released: {final - baseline:.1f}MB remaining"
    
    def test_profiling_async_code(self, profiler):
        """Profile memory in async code"""
        import asyncio
        
        async def async_memory_user():
            profiler.take_snapshot("async_start")
            
            # Allocate memory in tasks
            tasks = []
            for i in range(10):
                async def allocate(size):
                    data = bytearray(size * 1024 * 1024)
                    await asyncio.sleep(0.1)
                    return len(data)
                
                tasks.append(allocate(1))  # 1MB each
            
            profiler.take_snapshot("tasks_created")
            
            # Wait for all tasks
            results = await asyncio.gather(*tasks)
            
            profiler.take_snapshot("tasks_completed")
            
            return sum(results)
        
        # Run async profiling
        result = asyncio.run(async_memory_user())
        
        # Check memory growth during async operations
        top_allocs = profiler.get_top_allocations()
        
        # Verify we can track async allocations
        assert any('bytearray' in alloc['code'] for alloc in top_allocs)


## Regression Test Suite

### Regression Testing Framework

1. **Baseline Establishment**
   - Record performance baselines
   - Store historical data
   - Define acceptance criteria

2. **Continuous Validation**
   - Automated regression checks
   - Performance trend analysis
   - Alert on degradation

### Test Implementation

```python
# tests/regression/test_memory_regression.py
import pytest
import json
import os
from datetime import datetime
from typing import Dict, List
import statistics


class MemoryRegressionSuite:
    """Memory optimization regression test suite"""
    
    BASELINE_FILE = 'memory_regression_baseline.json'
    HISTORY_FILE = 'memory_regression_history.json'
    
    # Regression thresholds (% degradation allowed)
    THRESHOLDS = {
        'allocation_speed': 0.1,      # 10% degradation
        'gc_pause_time': 0.2,         # 20% degradation
        'memory_efficiency': 0.15,    # 15% degradation
        'cache_performance': 0.1,     # 10% degradation
    }
    
    @classmethod
    def load_baseline(cls) -> Dict:
        """Load performance baseline"""
        if os.path.exists(cls.BASELINE_FILE):
            with open(cls.BASELINE_FILE, 'r') as f:
                return json.load(f)
        return {}
    
    @classmethod
    def save_baseline(cls, metrics: Dict):
        """Save new baseline"""
        with open(cls.BASELINE_FILE, 'w') as f:
            json.dump(metrics, f, indent=2)
    
    @classmethod
    def record_history(cls, metrics: Dict):
        """Record metrics in history"""
        history = []
        if os.path.exists(cls.HISTORY_FILE):
            with open(cls.HISTORY_FILE, 'r') as f:
                history = json.load(f)
        
        entry = {
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics
        }
        history.append(entry)
        
        # Keep last 100 entries
        history = history[-100:]
        
        with open(cls.HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    
    def run_regression_tests(self) -> Dict:
        """Run all regression tests"""
        metrics = {}
        
        # Run each test category
        metrics['allocation_speed'] = self._test_allocation_regression()
        metrics['gc_pause_time'] = self._test_gc_regression()
        metrics['memory_efficiency'] = self._test_memory_efficiency_regression()
        metrics['cache_performance'] = self._test_cache_regression()
        
        # Record in history
        self.record_history(metrics)
        
        # Check against baseline
        baseline = self.load_baseline()
        if baseline:
            self._check_regressions(baseline, metrics)
        else:
            # First run, save as baseline
            self.save_baseline(metrics)
        
        return metrics
    
    def _test_allocation_regression(self) -> float:
        """Test allocation speed regression"""
        from src.core.object_pool import ObjectPool
        import time
        
        class TestObject:
            def __init__(self):
                self.data = [0] * 1000
        
        pool = ObjectPool(TestObject, min_size=10, max_size=100)
        
        # Warmup
        for _ in range(100):
            obj = pool.acquire()
            pool.release(obj)
        
        # Measure
        iterations = 10000
        start = time.perf_counter()
        
        for _ in range(iterations):
            obj = pool.acquire()
            pool.release(obj)
        
        duration = time.perf_counter() - start
        rate = iterations / duration
        
        return rate
    
    def _test_gc_regression(self) -> float:
        """Test GC pause time regression"""
        import gc
        import time
        
        pause_times = []
        
        for _ in range(20):
            # Create garbage
            garbage = [{'data': [0] * 1000} for _ in range(1000)]
            
            # Measure GC pause
            gc.disable()
            start = time.perf_counter()
            gc.collect()
            pause = time.perf_counter() - start
            gc.enable()
            
            pause_times.append(pause)
            del garbage
        
        return statistics.mean(pause_times)
    
    def _test_memory_efficiency_regression(self) -> float:
        """Test memory efficiency regression"""
        import psutil
        import gc
        
        process = psutil.Process()
        
        # Baseline
        gc.collect()
        baseline_memory = process.memory_info().rss
        
        # Allocate and release
        allocations = []
        for _ in range(100):
            data = bytearray(1024 * 1024)  # 1MB
            allocations.append(data)
        
        peak_memory = process.memory_info().rss
        
        # Clear
        allocations.clear()
        gc.collect()
        
        final_memory = process.memory_info().rss
        
        # Calculate efficiency (how well we return to baseline)
        efficiency = 1.0 - ((final_memory - baseline_memory) / (peak_memory - baseline_memory))
        
        return efficiency
    
    def _test_cache_regression(self) -> float:
        """Test cache performance regression"""
        from src.core.lru_cache import LRUCache
        import time
        
        cache = LRUCache(max_size=1000)
        
        # Populate
        for i in range(1000):
            cache.put(f'key_{i}', f'value_{i}')
        
        # Measure access time
        iterations = 100000
        start = time.perf_counter()
        
        hits = 0
        for i in range(iterations):
            if cache.get(f'key_{i % 1000}') is not None:
                hits += 1
        
        duration = time.perf_counter() - start
        
        # Return ops per second
        return iterations / duration
    
    def _check_regressions(self, baseline: Dict, current: Dict):
        """Check for performance regressions"""
        regressions = []
        
        for metric, current_value in current.items():
            if metric in baseline:
                baseline_value = baseline[metric]
                threshold = self.THRESHOLDS.get(metric, 0.1)
                
                # Calculate degradation
                if baseline_value > 0:
                    degradation = (baseline_value - current_value) / baseline_value
                    
                    if degradation > threshold:
                        regressions.append({
                            'metric': metric,
                            'baseline': baseline_value,
                            'current': current_value,
                            'degradation': degradation
                        })
        
        if regressions:
            msg = "Performance regressions detected:\n"
            for reg in regressions:
                msg += f"  - {reg['metric']}: {reg['degradation']:.1%} degradation "
                msg += f"(baseline: {reg['baseline']:.2f}, current: {reg['current']:.2f})\n"
            
            pytest.fail(msg)


def test_memory_regression_suite():
    """Run memory optimization regression tests"""
    suite = MemoryRegressionSuite()
    metrics = suite.run_regression_tests()
    
    print("\n=== Memory Regression Test Results ===")
    for metric, value in metrics.items():
        print(f"{metric}: {value:.2f}")
    
    # Always pass on first run (establishes baseline)
    # Subsequent runs will check for regressions


# Pytest configuration for regression tests
def pytest_configure(config):
    """Configure pytest for regression testing"""
    config.addinivalue_line(
        "markers", 
        "regression: mark test as regression test"
    )


# Mark all tests in this file as regression tests
pytestmark = pytest.mark.regression