#!/usr/bin/env python3
"""
CPU Load Generator
==================

Advanced CPU load generation with multiple algorithms and realistic workload patterns.
Supports multi-threaded execution, various computation types, and adaptive load control.
"""

import asyncio
import multiprocessing
import threading
import time
import math
import random
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import psutil
import numpy as np

logger = logging.getLogger(__name__)

@dataclass
class CPULoadConfiguration:
    """Configuration for CPU load generation"""
    threads: int = multiprocessing.cpu_count()
    algorithm: str = "prime_calculation"  # prime_calculation, matrix_multiplication, fibonacci, pi_calculation
    intensity: float = 0.5  # 0.0 to 1.0
    duration: int = 60  # seconds
    work_cycle: float = 0.1  # seconds of work per cycle
    rest_cycle: float = 0.05  # seconds of rest per cycle
    adaptive: bool = True  # Adapt based on system response

class CPULoadGenerator:
    """
    Advanced CPU Load Generator
    
    Generates realistic CPU workloads using various algorithms and patterns.
    Supports adaptive load control and system monitoring.
    """
    
    def __init__(self, config: Optional[CPULoadConfiguration] = None):
        self.config = config or CPULoadConfiguration()
        self.running = False
        self.current_load = 0.0
        self.target_load = 0.0
        self.workers = []
        self.executor = None
        self.load_history = []
        self.algorithm_functions = {
            'prime_calculation': self._cpu_prime_calculation,
            'matrix_multiplication': self._cpu_matrix_multiplication,
            'fibonacci': self._cpu_fibonacci,
            'pi_calculation': self._cpu_pi_calculation,
            'crypto_hash': self._cpu_crypto_hash,
            'sort_algorithms': self._cpu_sort_algorithms,
            'compression': self._cpu_compression,
            'floating_point': self._cpu_floating_point
        }
        
        # Performance monitoring
        self.performance_samples = []
        self.last_system_check = time.time()
    
    async def execute_pattern(self, pattern):
        """Execute a load pattern"""
        logger.info(f"Starting CPU load pattern: {pattern.name}")
        self.running = True
        
        try:
            # Initialize executor
            self.executor = ThreadPoolExecutor(max_workers=self.config.threads)
            
            # Execute pattern points
            for point in pattern.points:
                if not self.running:
                    break
                
                # Update target load
                self.target_load = point.intensity
                
                # Adjust load
                await self._adjust_load_to_target()
                
                # Wait for next point (minimum 1 second intervals)
                if pattern.points.index(point) < len(pattern.points) - 1:
                    next_point = pattern.points[pattern.points.index(point) + 1]
                    wait_time = next_point.timestamp - point.timestamp
                    await asyncio.sleep(max(1.0, wait_time))
            
            logger.info(f"Completed CPU load pattern: {pattern.name}")
            
        except Exception as e:
            logger.error(f"CPU load pattern execution failed: {e}")
            raise
        finally:
            await self.stop()
    
    async def _adjust_load_to_target(self):
        """Adjust current load to match target load"""
        if self.target_load == 0:
            await self._stop_all_workers()
            return
        
        # Calculate required threads based on target load
        required_threads = max(1, int(self.config.threads * self.target_load))
        current_threads = len(self.workers)
        
        if required_threads > current_threads:
            # Start more workers
            for _ in range(required_threads - current_threads):
                await self._start_worker()
        elif required_threads < current_threads:
            # Stop excess workers
            for _ in range(current_threads - required_threads):
                await self._stop_worker()
        
        # Update work/rest cycles based on intensity
        self._update_work_cycles()
    
    async def _start_worker(self):
        """Start a new CPU worker"""
        algorithm = self.config.algorithm
        algorithm_func = self.algorithm_functions.get(algorithm, self._cpu_prime_calculation)
        
        # Submit worker to executor
        if self.executor:
            future = self.executor.submit(self._worker_loop, algorithm_func)
            self.workers.append(future)
            logger.debug(f"Started CPU worker {len(self.workers)} using {algorithm}")
    
    async def _stop_worker(self):
        """Stop a CPU worker"""
        if self.workers:
            worker = self.workers.pop()
            # Workers will stop automatically when self.running becomes False
            logger.debug(f"Stopped CPU worker, {len(self.workers)} remaining")
    
    async def _stop_all_workers(self):
        """Stop all CPU workers"""
        self.workers.clear()
        logger.debug("Stopped all CPU workers")
    
    def _update_work_cycles(self):
        """Update work/rest cycle timing based on current intensity"""
        base_work_cycle = 0.1
        base_rest_cycle = 0.05
        
        # Higher intensity = more work, less rest
        intensity_factor = max(0.1, self.target_load)
        self.config.work_cycle = base_work_cycle * intensity_factor
        self.config.rest_cycle = base_rest_cycle * (1.0 - intensity_factor * 0.5)
    
    def _worker_loop(self, algorithm_func):
        """Main worker loop for CPU load generation"""
        worker_id = threading.current_thread().ident
        iterations = 0
        
        while self.running:
            start_time = time.time()
            
            # Perform CPU-intensive work
            try:
                algorithm_func(self.config.work_cycle)
                iterations += 1
            except Exception as e:
                logger.error(f"Worker {worker_id} algorithm error: {e}")
            
            # Rest period
            if self.config.rest_cycle > 0:
                time.sleep(self.config.rest_cycle)
            
            # Adaptive control check (every 100 iterations)
            if self.config.adaptive and iterations % 100 == 0:
                self._check_system_performance()
        
        logger.debug(f"CPU worker {worker_id} completed {iterations} iterations")
    
    def _check_system_performance(self):
        """Check system performance and adjust if needed"""
        current_time = time.time()
        if current_time - self.last_system_check < 10:  # Check every 10 seconds
            return
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            self.performance_samples.append({
                'timestamp': current_time,
                'cpu_percent': cpu_percent,
                'target_load': self.target_load,
                'active_workers': len(self.workers)
            })
            
            # Keep only last 100 samples
            if len(self.performance_samples) > 100:
                self.performance_samples = self.performance_samples[-100:]
            
            # Adaptive adjustment
            if cpu_percent > 95 and self.target_load > 0.1:
                # System is overloaded, reduce intensity
                self.target_load *= 0.9
                logger.warning(f"Reducing CPU load target to {self.target_load:.2f} due to high system load")
            
            self.last_system_check = current_time
            
        except Exception as e:
            logger.error(f"Performance check failed: {e}")
    
    # CPU Algorithm Implementations
    
    def _cpu_prime_calculation(self, duration: float):
        """Generate CPU load using prime number calculation"""
        start_time = time.time()
        number = random.randint(10000, 100000)
        
        while time.time() - start_time < duration:
            # Check if number is prime
            is_prime = True
            for i in range(2, int(math.sqrt(number)) + 1):
                if number % i == 0:
                    is_prime = False
                    break
            
            number += 1
            if number > 1000000:
                number = random.randint(10000, 100000)
    
    def _cpu_matrix_multiplication(self, duration: float):
        """Generate CPU load using matrix multiplication"""
        start_time = time.time()
        size = 100
        
        while time.time() - start_time < duration:
            # Generate random matrices
            matrix_a = np.random.rand(size, size)
            matrix_b = np.random.rand(size, size)
            
            # Perform multiplication
            result = np.dot(matrix_a, matrix_b)
            
            # Vary matrix size occasionally
            if random.random() < 0.1:
                size = random.randint(50, 150)
    
    def _cpu_fibonacci(self, duration: float):
        """Generate CPU load using Fibonacci calculation"""
        start_time = time.time()
        
        while time.time() - start_time < duration:
            n = random.randint(20, 35)
            self._fibonacci_recursive(n)
    
    def _fibonacci_recursive(self, n: int) -> int:
        """Recursive Fibonacci calculation (CPU intensive)"""
        if n <= 1:
            return n
        return self._fibonacci_recursive(n-1) + self._fibonacci_recursive(n-2)
    
    def _cpu_pi_calculation(self, duration: float):
        """Generate CPU load using π calculation (Monte Carlo method)"""
        start_time = time.time()
        inside_circle = 0
        total_points = 0
        
        while time.time() - start_time < duration:
            # Generate random points
            for _ in range(1000):
                x = random.uniform(-1, 1)
                y = random.uniform(-1, 1)
                
                if x*x + y*y <= 1:
                    inside_circle += 1
                total_points += 1
            
            # Calculate π approximation
            if total_points > 0:
                pi_approx = 4 * inside_circle / total_points
    
    def _cpu_crypto_hash(self, duration: float):
        """Generate CPU load using cryptographic hash calculation"""
        import hashlib
        start_time = time.time()
        data = b"Load testing data for hash calculation"
        counter = 0
        
        while time.time() - start_time < duration:
            # Multiple hash calculations
            for _ in range(100):
                hash_input = data + str(counter).encode()
                hashlib.sha256(hash_input).hexdigest()
                counter += 1
    
    def _cpu_sort_algorithms(self, duration: float):
        """Generate CPU load using various sorting algorithms"""
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Generate random array
            size = random.randint(1000, 10000)
            arr = [random.randint(1, 1000) for _ in range(size)]
            
            # Apply different sorting algorithms
            algorithm = random.choice(['quicksort', 'mergesort', 'heapsort'])
            
            if algorithm == 'quicksort':
                self._quicksort(arr.copy(), 0, len(arr) - 1)
            elif algorithm == 'mergesort':
                self._mergesort(arr.copy())
            elif algorithm == 'heapsort':
                self._heapsort(arr.copy())
    
    def _quicksort(self, arr: List[int], low: int, high: int):
        """Quicksort implementation"""
        if low < high:
            pi = self._partition(arr, low, high)
            self._quicksort(arr, low, pi - 1)
            self._quicksort(arr, pi + 1, high)
    
    def _partition(self, arr: List[int], low: int, high: int) -> int:
        """Partition function for quicksort"""
        pivot = arr[high]
        i = low - 1
        
        for j in range(low, high):
            if arr[j] <= pivot:
                i += 1
                arr[i], arr[j] = arr[j], arr[i]
        
        arr[i + 1], arr[high] = arr[high], arr[i + 1]
        return i + 1
    
    def _mergesort(self, arr: List[int]) -> List[int]:
        """Mergesort implementation"""
        if len(arr) <= 1:
            return arr
        
        mid = len(arr) // 2
        left = self._mergesort(arr[:mid])
        right = self._mergesort(arr[mid:])
        
        return self._merge(left, right)
    
    def _merge(self, left: List[int], right: List[int]) -> List[int]:
        """Merge function for mergesort"""
        result = []
        i = j = 0
        
        while i < len(left) and j < len(right):
            if left[i] <= right[j]:
                result.append(left[i])
                i += 1
            else:
                result.append(right[j])
                j += 1
        
        result.extend(left[i:])
        result.extend(right[j:])
        return result
    
    def _heapsort(self, arr: List[int]):
        """Heapsort implementation"""
        n = len(arr)
        
        # Build max heap
        for i in range(n // 2 - 1, -1, -1):
            self._heapify(arr, n, i)
        
        # Extract elements
        for i in range(n - 1, 0, -1):
            arr[0], arr[i] = arr[i], arr[0]
            self._heapify(arr, i, 0)
    
    def _heapify(self, arr: List[int], n: int, i: int):
        """Heapify function for heapsort"""
        largest = i
        left = 2 * i + 1
        right = 2 * i + 2
        
        if left < n and arr[left] > arr[largest]:
            largest = left
        
        if right < n and arr[right] > arr[largest]:
            largest = right
        
        if largest != i:
            arr[i], arr[largest] = arr[largest], arr[i]
            self._heapify(arr, n, largest)
    
    def _cpu_compression(self, duration: float):
        """Generate CPU load using data compression"""
        import zlib
        import gzip
        start_time = time.time()
        
        # Generate test data
        test_data = b"This is test data for compression load testing. " * 1000
        
        while time.time() - start_time < duration:
            # Different compression algorithms
            compressed_zlib = zlib.compress(test_data)
            decompressed_zlib = zlib.decompress(compressed_zlib)
            
            compressed_gzip = gzip.compress(test_data)
            decompressed_gzip = gzip.decompress(compressed_gzip)
    
    def _cpu_floating_point(self, duration: float):
        """Generate CPU load using floating-point operations"""
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Complex floating-point calculations
            for _ in range(10000):
                a = random.uniform(-1000, 1000)
                b = random.uniform(-1000, 1000)
                
                # Various mathematical operations
                result = math.sin(a) * math.cos(b)
                result += math.log(abs(a) + 1) * math.sqrt(abs(b))
                result *= math.exp(min(a/1000, 10))  # Prevent overflow
                result = math.atan2(result, b + 1)
    
    async def stop(self):
        """Stop the CPU load generator"""
        logger.info("Stopping CPU load generator")
        self.running = False
        self.current_load = 0.0
        self.target_load = 0.0
        
        if self.executor:
            self.executor.shutdown(wait=True)
            self.executor = None
        
        self.workers.clear()
    
    async def reduce_intensity(self, factor: float):
        """Reduce load intensity by a factor"""
        self.target_load = max(0.0, self.target_load * factor)
        await self._adjust_load_to_target()
        logger.info(f"Reduced CPU load intensity to {self.target_load:.2f}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the CPU load generator"""
        return {
            'generator_id': 'cpu_load_generator',
            'generator_type': 'cpu',
            'status': 'running' if self.running else 'stopped',
            'current_load': self.current_load,
            'target_load': self.target_load,
            'active_workers': len(self.workers),
            'algorithm': self.config.algorithm,
            'threads': self.config.threads,
            'metrics': {
                'performance_samples': len(self.performance_samples),
                'last_check': self.last_system_check,
                'work_cycle': self.config.work_cycle,
                'rest_cycle': self.config.rest_cycle
            }
        }


# Example usage
async def example_usage():
    """Example usage of CPULoadGenerator"""
    config = CPULoadConfiguration(
        threads=4,
        algorithm="prime_calculation",
        intensity=0.7,
        duration=120,
        adaptive=True
    )
    
    generator = CPULoadGenerator(config)
    
    # Create a simple test pattern
    from patterns.pattern_engine import PatternEngine, LoadPoint, LoadPattern, PatternType
    
    pattern_engine = PatternEngine()
    pattern = pattern_engine.generate_pattern("steady_state", 60, 0.5)
    
    # Execute pattern
    await generator.execute_pattern(pattern)
    
    # Get status
    status = generator.get_status()
    print(f"CPU Generator Status: {status}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(example_usage())