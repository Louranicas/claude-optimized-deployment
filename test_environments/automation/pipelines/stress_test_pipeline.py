"""
Stress Test Pipeline - Comprehensive stress testing pipeline configuration.

This module provides specialized pipeline configuration for stress testing
with load generation, resource monitoring, and performance validation.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import concurrent.futures

import psutil
import numpy as np
from prometheus_client import Counter, Histogram, Gauge

logger = logging.getLogger(__name__)

# Metrics
stress_tests_executed = Counter('stress_tests_executed_total', 'Total stress tests executed', ['test_type'])
stress_test_duration = Histogram('stress_test_duration_seconds', 'Stress test duration')
peak_resource_usage = Gauge('peak_resource_usage', 'Peak resource usage during stress tests', ['resource_type'])
stress_failures = Counter('stress_failures_total', 'Stress test failures', ['failure_type'])


class StressTestType(Enum):
    """Types of stress tests."""
    CPU_INTENSIVE = "cpu_intensive"
    MEMORY_PRESSURE = "memory_pressure"
    IO_INTENSIVE = "io_intensive"
    NETWORK_STRESS = "network_stress"
    CONCURRENT_LOAD = "concurrent_load"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SUSTAINED_LOAD = "sustained_load"


class LoadPattern(Enum):
    """Load patterns for stress testing."""
    CONSTANT = "constant"
    RAMP_UP = "ramp_up"
    SPIKE = "spike"
    WAVE = "wave"
    RANDOM = "random"
    BURST = "burst"


@dataclass
class StressTestConfig:
    """Stress test configuration."""
    test_type: StressTestType
    load_pattern: LoadPattern
    duration_seconds: int = 300  # 5 minutes default
    max_concurrent_workers: int = 10
    target_load_percent: float = 80.0  # Target system load
    ramp_up_time: int = 30  # Ramp-up time in seconds
    ramp_down_time: int = 30  # Ramp-down time in seconds
    monitoring_interval: int = 1  # Monitoring interval in seconds
    failure_threshold: float = 0.05  # 5% failure rate threshold
    resource_limits: Dict[str, float] = field(default_factory=lambda: {
        'cpu_percent': 95.0,
        'memory_percent': 90.0,
        'disk_percent': 95.0
    })
    custom_parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StressTestResult:
    """Stress test execution result."""
    test_type: StressTestType
    start_time: datetime
    end_time: datetime
    duration: float
    peak_cpu: float
    peak_memory: float
    peak_disk_io: float
    average_response_time: float
    max_response_time: float
    throughput: float
    error_rate: float
    success_rate: float
    resource_exhaustion_detected: bool
    performance_degradation: float
    recovery_time: float
    detailed_metrics: Dict[str, Any]
    warnings: List[str]
    errors: List[str]


class CPUStressTest:
    """CPU-intensive stress test implementation."""
    
    def __init__(self, config: StressTestConfig):
        self.config = config
        self.stop_event = asyncio.Event()
        
    async def execute(self) -> StressTestResult:
        """Execute CPU stress test."""
        start_time = datetime.now()
        logger.info(f"Starting CPU stress test with {self.config.max_concurrent_workers} workers")
        
        metrics = []
        errors = []
        warnings = []
        
        try:
            # Start resource monitoring
            monitor_task = asyncio.create_task(self._monitor_resources(metrics))
            
            # Start CPU stress workers
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_concurrent_workers) as executor:
                # Submit CPU stress tasks
                futures = []
                for i in range(self.config.max_concurrent_workers):
                    future = executor.submit(self._cpu_stress_worker, i)
                    futures.append(future)
                
                # Apply load pattern
                await self._apply_load_pattern()
                
                # Wait for completion or timeout
                await asyncio.sleep(self.config.duration_seconds)
                self.stop_event.set()
                
                # Collect results
                for future in concurrent.futures.as_completed(futures, timeout=30):
                    try:
                        result = future.result()
                        if result.get('error'):
                            errors.append(result['error'])
                    except Exception as e:
                        errors.append(str(e))
                        
            # Stop monitoring
            monitor_task.cancel()
            
        except Exception as e:
            errors.append(f"CPU stress test execution error: {e}")
            
        end_time = datetime.now()
        
        # Calculate results
        return self._calculate_results(start_time, end_time, metrics, errors, warnings)
        
    def _cpu_stress_worker(self, worker_id: int) -> Dict[str, Any]:
        """CPU stress worker thread."""
        try:
            start_time = time.time()
            iterations = 0
            
            while not self.stop_event.is_set():
                # CPU-intensive calculation
                for i in range(10000):
                    # Prime number calculation
                    n = 1000 + i
                    is_prime = True
                    for j in range(2, int(n ** 0.5) + 1):
                        if n % j == 0:
                            is_prime = False
                            break
                            
                iterations += 1
                
                # Small sleep to allow event checking
                time.sleep(0.001)
                
            duration = time.time() - start_time
            return {
                'worker_id': worker_id,
                'duration': duration,
                'iterations': iterations,
                'rate': iterations / duration if duration > 0 else 0
            }
            
        except Exception as e:
            return {'worker_id': worker_id, 'error': str(e)}
            
    async def _apply_load_pattern(self) -> None:
        """Apply configured load pattern."""
        if self.config.load_pattern == LoadPattern.RAMP_UP:
            await self._ramp_up_load()
        elif self.config.load_pattern == LoadPattern.SPIKE:
            await self._spike_load()
        elif self.config.load_pattern == LoadPattern.WAVE:
            await self._wave_load()
        # Constant load doesn't require special handling
        
    async def _ramp_up_load(self) -> None:
        """Gradually increase load."""
        # Implementation would adjust worker count or intensity over time
        pass
        
    async def _spike_load(self) -> None:
        """Apply sudden load spikes."""
        # Implementation would create periodic load spikes
        pass
        
    async def _wave_load(self) -> None:
        """Apply wave-like load pattern."""
        # Implementation would create sinusoidal load pattern
        pass
        
    async def _monitor_resources(self, metrics: List[Dict[str, Any]]) -> None:
        """Monitor system resources during test."""
        while not self.stop_event.is_set():
            try:
                cpu_percent = psutil.cpu_percent(interval=None)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                metric = {
                    'timestamp': time.time(),
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_mb': memory.used // (1024 * 1024),
                    'disk_percent': (disk.used / disk.total) * 100,
                    'load_average': psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0
                }
                
                metrics.append(metric)
                
                # Update Prometheus metrics
                peak_resource_usage.labels(resource_type='cpu').set(cpu_percent)
                peak_resource_usage.labels(resource_type='memory').set(memory.percent)
                
            except Exception as e:
                logger.warning(f"Resource monitoring error: {e}")
                
            await asyncio.sleep(self.config.monitoring_interval)
            
    def _calculate_results(self, start_time: datetime, end_time: datetime,
                          metrics: List[Dict[str, Any]], errors: List[str],
                          warnings: List[str]) -> StressTestResult:
        """Calculate stress test results."""
        duration = (end_time - start_time).total_seconds()
        
        # Calculate peak metrics
        peak_cpu = max((m['cpu_percent'] for m in metrics), default=0)
        peak_memory = max((m['memory_percent'] for m in metrics), default=0)
        peak_disk_io = max((m['disk_percent'] for m in metrics), default=0)
        
        # Calculate performance metrics
        avg_cpu = np.mean([m['cpu_percent'] for m in metrics]) if metrics else 0
        
        # Detect resource exhaustion
        resource_exhaustion = (
            peak_cpu > self.config.resource_limits['cpu_percent'] or
            peak_memory > self.config.resource_limits['memory_percent']
        )
        
        # Calculate performance degradation
        baseline_cpu = 10.0  # Baseline CPU usage
        performance_degradation = max(0, (avg_cpu - baseline_cpu) / baseline_cpu)
        
        return StressTestResult(
            test_type=self.config.test_type,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            peak_cpu=peak_cpu,
            peak_memory=peak_memory,
            peak_disk_io=peak_disk_io,
            average_response_time=0.0,  # Not applicable for CPU test
            max_response_time=0.0,
            throughput=len(metrics) / duration if duration > 0 else 0,
            error_rate=len(errors) / max(1, len(metrics)),
            success_rate=1.0 - (len(errors) / max(1, len(metrics))),
            resource_exhaustion_detected=resource_exhaustion,
            performance_degradation=performance_degradation,
            recovery_time=0.0,  # Would be calculated in real implementation
            detailed_metrics={
                'total_metrics': len(metrics),
                'total_errors': len(errors),
                'total_warnings': len(warnings),
                'avg_cpu': avg_cpu,
                'metrics_data': metrics[:100]  # Limit data size
            },
            warnings=warnings,
            errors=errors
        )


class MemoryStressTest:
    """Memory pressure stress test implementation."""
    
    def __init__(self, config: StressTestConfig):
        self.config = config
        self.stop_event = asyncio.Event()
        self.memory_blocks = []
        
    async def execute(self) -> StressTestResult:
        """Execute memory stress test."""
        start_time = datetime.now()
        logger.info(f"Starting memory stress test")
        
        metrics = []
        errors = []
        warnings = []
        
        try:
            # Start resource monitoring
            monitor_task = asyncio.create_task(self._monitor_resources(metrics))
            
            # Start memory allocation workers
            allocation_task = asyncio.create_task(self._memory_allocation_worker())
            
            # Wait for completion
            await asyncio.sleep(self.config.duration_seconds)
            self.stop_event.set()
            
            # Cleanup
            allocation_task.cancel()
            monitor_task.cancel()
            
            # Free allocated memory
            self._cleanup_memory()
            
        except Exception as e:
            errors.append(f"Memory stress test execution error: {e}")
            
        end_time = datetime.now()
        
        return self._calculate_results(start_time, end_time, metrics, errors, warnings)
        
    async def _memory_allocation_worker(self) -> None:
        """Memory allocation worker."""
        try:
            block_size = self.config.custom_parameters.get('block_size_mb', 10) * 1024 * 1024
            allocation_rate = self.config.custom_parameters.get('allocation_rate_mb_per_sec', 5)
            
            while not self.stop_event.is_set():
                try:
                    # Allocate memory block
                    memory_block = bytearray(block_size)
                    
                    # Fill with random data to ensure actual allocation
                    for i in range(0, len(memory_block), 1024):
                        memory_block[i:i+4] = (i % 256).to_bytes(4, 'big')
                        
                    self.memory_blocks.append(memory_block)
                    
                    # Control allocation rate
                    await asyncio.sleep(block_size / (allocation_rate * 1024 * 1024))
                    
                except MemoryError:
                    logger.warning("Memory allocation failed - memory exhaustion reached")
                    break
                except Exception as e:
                    logger.error(f"Memory allocation error: {e}")
                    
        except Exception as e:
            logger.error(f"Memory worker error: {e}")
            
    def _cleanup_memory(self) -> None:
        """Cleanup allocated memory."""
        try:
            del self.memory_blocks[:]
            self.memory_blocks = []
            import gc
            gc.collect()
        except Exception as e:
            logger.warning(f"Memory cleanup error: {e}")
            
    async def _monitor_resources(self, metrics: List[Dict[str, Any]]) -> None:
        """Monitor memory usage during test."""
        while not self.stop_event.is_set():
            try:
                memory = psutil.virtual_memory()
                swap = psutil.swap_memory()
                
                metric = {
                    'timestamp': time.time(),
                    'memory_percent': memory.percent,
                    'memory_available_mb': memory.available // (1024 * 1024),
                    'memory_used_mb': memory.used // (1024 * 1024),
                    'swap_percent': swap.percent,
                    'allocated_blocks': len(self.memory_blocks),
                    'allocated_mb': len(self.memory_blocks) * 
                                  self.config.custom_parameters.get('block_size_mb', 10)
                }
                
                metrics.append(metric)
                
                # Update Prometheus metrics
                peak_resource_usage.labels(resource_type='memory').set(memory.percent)
                
            except Exception as e:
                logger.warning(f"Memory monitoring error: {e}")
                
            await asyncio.sleep(self.config.monitoring_interval)
            
    def _calculate_results(self, start_time: datetime, end_time: datetime,
                          metrics: List[Dict[str, Any]], errors: List[str],
                          warnings: List[str]) -> StressTestResult:
        """Calculate memory stress test results."""
        duration = (end_time - start_time).total_seconds()
        
        # Calculate peak memory usage
        peak_memory = max((m['memory_percent'] for m in metrics), default=0)
        max_allocated = max((m['allocated_mb'] for m in metrics), default=0)
        
        # Detect memory exhaustion
        memory_exhaustion = peak_memory > self.config.resource_limits['memory_percent']
        
        return StressTestResult(
            test_type=self.config.test_type,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            peak_cpu=0.0,  # Not primary focus
            peak_memory=peak_memory,
            peak_disk_io=0.0,
            average_response_time=0.0,
            max_response_time=0.0,
            throughput=len(metrics) / duration if duration > 0 else 0,
            error_rate=len(errors) / max(1, len(metrics)),
            success_rate=1.0 - (len(errors) / max(1, len(metrics))),
            resource_exhaustion_detected=memory_exhaustion,
            performance_degradation=0.0,
            recovery_time=0.0,
            detailed_metrics={
                'max_allocated_mb': max_allocated,
                'total_blocks_allocated': len(self.memory_blocks),
                'metrics_data': metrics[:100]
            },
            warnings=warnings,
            errors=errors
        )


class StressTestPipeline:
    """Comprehensive stress testing pipeline."""
    
    def __init__(self):
        self.test_implementations = {
            StressTestType.CPU_INTENSIVE: CPUStressTest,
            StressTestType.MEMORY_PRESSURE: MemoryStressTest,
            # Additional implementations would be added here
        }
        
    async def execute_stress_test(self, config: StressTestConfig) -> StressTestResult:
        """Execute a stress test based on configuration."""
        stress_tests_executed.labels(test_type=config.test_type.value).inc()
        
        test_class = self.test_implementations.get(config.test_type)
        if not test_class:
            raise ValueError(f"Unsupported stress test type: {config.test_type}")
            
        test_instance = test_class(config)
        
        try:
            start_time = time.time()
            result = await test_instance.execute()
            duration = time.time() - start_time
            
            stress_test_duration.observe(duration)
            
            logger.info(f"Stress test {config.test_type.value} completed in {duration:.2f}s")
            return result
            
        except Exception as e:
            stress_failures.labels(failure_type='execution_error').inc()
            logger.error(f"Stress test {config.test_type.value} failed: {e}")
            raise
            
    async def execute_stress_suite(self, configs: List[StressTestConfig]) -> List[StressTestResult]:
        """Execute a suite of stress tests."""
        results = []
        
        for config in configs:
            try:
                result = await self.execute_stress_test(config)
                results.append(result)
                
                # Optional delay between tests
                if len(configs) > 1:
                    await asyncio.sleep(30)  # 30-second recovery time
                    
            except Exception as e:
                logger.error(f"Failed to execute stress test {config.test_type.value}: {e}")
                
        return results
        
    def create_comprehensive_stress_suite(self) -> List[StressTestConfig]:
        """Create a comprehensive stress test suite."""
        return [
            # CPU stress test
            StressTestConfig(
                test_type=StressTestType.CPU_INTENSIVE,
                load_pattern=LoadPattern.RAMP_UP,
                duration_seconds=300,
                max_concurrent_workers=psutil.cpu_count(),
                target_load_percent=80.0
            ),
            
            # Memory stress test
            StressTestConfig(
                test_type=StressTestType.MEMORY_PRESSURE,
                load_pattern=LoadPattern.CONSTANT,
                duration_seconds=240,
                custom_parameters={
                    'block_size_mb': 50,
                    'allocation_rate_mb_per_sec': 10
                }
            ),
            
            # Combined stress test would be added here
        ]
        
    def export_results(self, results: List[StressTestResult], output_path: str) -> None:
        """Export stress test results to JSON."""
        export_data = []
        
        for result in results:
            data = {
                'test_type': result.test_type.value,
                'start_time': result.start_time.isoformat(),
                'end_time': result.end_time.isoformat(),
                'duration': result.duration,
                'peak_cpu': result.peak_cpu,
                'peak_memory': result.peak_memory,
                'peak_disk_io': result.peak_disk_io,
                'throughput': result.throughput,
                'error_rate': result.error_rate,
                'success_rate': result.success_rate,
                'resource_exhaustion_detected': result.resource_exhaustion_detected,
                'performance_degradation': result.performance_degradation,
                'warnings': result.warnings,
                'errors': result.errors,
                'detailed_metrics': result.detailed_metrics
            }
            export_data.append(data)
            
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
            
        logger.info(f"Exported stress test results to {output_path}")


# Example usage and configuration
if __name__ == "__main__":
    async def main():
        pipeline = StressTestPipeline()
        
        # Create and execute comprehensive stress suite
        stress_configs = pipeline.create_comprehensive_stress_suite()
        results = await pipeline.execute_stress_suite(stress_configs)
        
        # Export results
        pipeline.export_results(results, "stress_test_results.json")
        
        # Print summary
        for result in results:
            print(f"Test: {result.test_type.value}")
            print(f"  Duration: {result.duration:.2f}s")
            print(f"  Peak CPU: {result.peak_cpu:.1f}%")
            print(f"  Peak Memory: {result.peak_memory:.1f}%")
            print(f"  Success Rate: {result.success_rate:.1%}")
            print(f"  Resource Exhaustion: {result.resource_exhaustion_detected}")
            print()
            
    asyncio.run(main())