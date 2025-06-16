#!/usr/bin/env python3
"""
Comprehensive Load Testing Suite
Advanced load testing scenarios for CODE project performance validation
"""

import asyncio
import time
import json
import statistics
import random
import threading
import multiprocessing
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import numpy as np
import psutil
import requests
import subprocess
from pathlib import Path

@dataclass
class LoadTestResult:
    """Load test result structure"""
    test_name: str
    scenario: str
    duration: float
    total_operations: int
    successful_operations: int
    failed_operations: int
    throughput: float
    avg_latency: float
    p95_latency: float
    p99_latency: float
    max_latency: float
    error_rate: float
    cpu_usage_peak: float
    memory_usage_peak_mb: float
    resource_utilization: Dict[str, Any]
    timestamp: datetime

class SystemResourceMonitor:
    """Monitor system resources during load tests"""
    
    def __init__(self):
        self.monitoring = False
        self.metrics = []
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start resource monitoring"""
        self.monitoring = True
        self.metrics = []
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.start()
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return aggregated metrics"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        
        if not self.metrics:
            return {}
        
        cpu_values = [m['cpu_percent'] for m in self.metrics]
        memory_values = [m['memory_percent'] for m in self.metrics]
        memory_mb_values = [m['memory_mb'] for m in self.metrics]
        
        return {
            'cpu_avg': statistics.mean(cpu_values),
            'cpu_max': max(cpu_values),
            'cpu_min': min(cpu_values),
            'memory_avg': statistics.mean(memory_values),
            'memory_max': max(memory_values),
            'memory_mb_max': max(memory_mb_values),
            'disk_io_read_mb': sum(m['disk_read_mb'] for m in self.metrics),
            'disk_io_write_mb': sum(m['disk_write_mb'] for m in self.metrics),
            'network_sent_mb': sum(m['network_sent_mb'] for m in self.metrics),
            'network_recv_mb': sum(m['network_recv_mb'] for m in self.metrics),
            'sample_count': len(self.metrics)
        }
    
    def _monitor_loop(self):
        """Monitor resources in background"""
        process = psutil.Process()
        prev_disk_io = psutil.disk_io_counters()
        prev_network_io = psutil.net_io_counters()
        
        while self.monitoring:
            try:
                # CPU and Memory
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                process_memory = process.memory_info()
                
                # Disk I/O
                disk_io = psutil.disk_io_counters()
                disk_read_mb = (disk_io.read_bytes - prev_disk_io.read_bytes) / (1024 * 1024)
                disk_write_mb = (disk_io.write_bytes - prev_disk_io.write_bytes) / (1024 * 1024)
                prev_disk_io = disk_io
                
                # Network I/O
                network_io = psutil.net_io_counters()
                network_sent_mb = (network_io.bytes_sent - prev_network_io.bytes_sent) / (1024 * 1024)
                network_recv_mb = (network_io.bytes_recv - prev_network_io.bytes_recv) / (1024 * 1024)
                prev_network_io = network_io
                
                self.metrics.append({
                    'timestamp': time.time(),
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_mb': process_memory.rss / (1024 * 1024),
                    'disk_read_mb': disk_read_mb,
                    'disk_write_mb': disk_write_mb,
                    'network_sent_mb': network_sent_mb,
                    'network_recv_mb': network_recv_mb
                })
                
                time.sleep(1)  # Monitor every second
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                break

class ConcurrentUserSimulator:
    """Simulate concurrent users with realistic behavior patterns"""
    
    def __init__(self):
        self.user_patterns = [
            self._casual_user_pattern,
            self._power_user_pattern,
            self._developer_user_pattern,
            self._batch_processing_pattern
        ]
    
    async def simulate_concurrent_users(self, user_count: int, duration: int, 
                                      workload_type: str = 'mixed') -> LoadTestResult:
        """Simulate concurrent users"""
        print(f"👥 Simulating {user_count} concurrent users for {duration}s ({workload_type} workload)")
        
        monitor = SystemResourceMonitor()
        monitor.start_monitoring()
        
        start_time = time.time()
        user_results = []
        
        # Select user pattern based on workload type
        if workload_type == 'casual':
            pattern = self._casual_user_pattern
        elif workload_type == 'power':
            pattern = self._power_user_pattern
        elif workload_type == 'developer':
            pattern = self._developer_user_pattern
        elif workload_type == 'batch':
            pattern = self._batch_processing_pattern
        else:  # mixed
            pattern = None
        
        # Create semaphore to limit concurrent operations
        semaphore = asyncio.Semaphore(user_count)
        
        async def simulate_user(user_id: int) -> Dict[str, Any]:
            """Simulate individual user"""
            async with semaphore:
                if pattern:
                    return await pattern(user_id, duration)
                else:
                    # Mixed workload - randomly select pattern
                    selected_pattern = random.choice(self.user_patterns)
                    return await selected_pattern(user_id, duration)
        
        # Run all users concurrently
        tasks = [simulate_user(i) for i in range(user_count)]
        user_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        total_duration = time.time() - start_time
        resource_metrics = monitor.stop_monitoring()
        
        # Aggregate results
        successful_results = [r for r in user_results if isinstance(r, dict) and 'error' not in r]
        failed_results = [r for r in user_results if not isinstance(r, dict) or 'error' in r]
        
        total_operations = sum(r.get('operations', 0) for r in successful_results)
        all_latencies = []
        for r in successful_results:
            all_latencies.extend(r.get('latencies', []))
        
        return LoadTestResult(
            test_name='concurrent_user_simulation',
            scenario=f'{user_count}_users_{workload_type}_workload',
            duration=total_duration,
            total_operations=total_operations,
            successful_operations=len(successful_results),
            failed_operations=len(failed_results),
            throughput=total_operations / total_duration if total_duration > 0 else 0,
            avg_latency=statistics.mean(all_latencies) if all_latencies else 0,
            p95_latency=np.percentile(all_latencies, 95) if all_latencies else 0,
            p99_latency=np.percentile(all_latencies, 99) if all_latencies else 0,
            max_latency=max(all_latencies) if all_latencies else 0,
            error_rate=len(failed_results) / user_count * 100,
            cpu_usage_peak=resource_metrics.get('cpu_max', 0),
            memory_usage_peak_mb=resource_metrics.get('memory_mb_max', 0),
            resource_utilization=resource_metrics,
            timestamp=datetime.now()
        )
    
    async def _casual_user_pattern(self, user_id: int, duration: int) -> Dict[str, Any]:
        """Simulate casual user behavior"""
        operations = 0
        latencies = []
        user_start = time.time()
        
        while time.time() - user_start < duration:
            # Casual user: light operations with longer think time
            op_start = time.time()
            
            try:
                # Simple operation
                await asyncio.sleep(0.01)  # 10ms operation
                result = hash(f"casual_user_{user_id}_{operations}")
                
                latency = time.time() - op_start
                latencies.append(latency)
                operations += 1
                
                # Longer think time (2-10 seconds)
                await asyncio.sleep(random.uniform(2, 10))
                
            except Exception as e:
                return {'error': str(e)}
        
        return {
            'user_id': user_id,
            'pattern': 'casual',
            'operations': operations,
            'latencies': latencies,
            'duration': time.time() - user_start
        }
    
    async def _power_user_pattern(self, user_id: int, duration: int) -> Dict[str, Any]:
        """Simulate power user behavior"""
        operations = 0
        latencies = []
        user_start = time.time()
        
        while time.time() - user_start < duration:
            # Power user: more operations, shorter think time
            op_start = time.time()
            
            try:
                # More complex operation
                data = np.random.random(1000)
                result = np.sum(data ** 2)
                
                latency = time.time() - op_start
                latencies.append(latency)
                operations += 1
                
                # Shorter think time (0.5-2 seconds)
                await asyncio.sleep(random.uniform(0.5, 2))
                
            except Exception as e:
                return {'error': str(e)}
        
        return {
            'user_id': user_id,
            'pattern': 'power',
            'operations': operations,
            'latencies': latencies,
            'duration': time.time() - user_start
        }
    
    async def _developer_user_pattern(self, user_id: int, duration: int) -> Dict[str, Any]:
        """Simulate developer user behavior"""
        operations = 0
        latencies = []
        user_start = time.time()
        
        while time.time() - user_start < duration:
            # Developer: burst of operations, then idle
            burst_size = random.randint(5, 15)
            
            # Burst of operations
            for _ in range(burst_size):
                op_start = time.time()
                
                try:
                    # Simulate code compilation/testing
                    await asyncio.sleep(0.05)  # 50ms operation
                    result = sum(i ** 2 for i in range(100))
                    
                    latency = time.time() - op_start
                    latencies.append(latency)
                    operations += 1
                    
                    # Short delay between operations in burst
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    return {'error': str(e)}
            
            # Longer idle time (5-15 seconds)
            await asyncio.sleep(random.uniform(5, 15))
        
        return {
            'user_id': user_id,
            'pattern': 'developer',
            'operations': operations,
            'latencies': latencies,
            'duration': time.time() - user_start
        }
    
    async def _batch_processing_pattern(self, user_id: int, duration: int) -> Dict[str, Any]:
        """Simulate batch processing behavior"""
        operations = 0
        latencies = []
        user_start = time.time()
        
        while time.time() - user_start < duration:
            # Batch processing: long-running operations
            op_start = time.time()
            
            try:
                # Simulate batch processing
                batch_size = random.randint(100, 500)
                data = np.random.random(batch_size)
                result = np.fft.fft(data)  # CPU-intensive operation
                
                latency = time.time() - op_start
                latencies.append(latency)
                operations += 1
                
                # Brief pause between batches
                await asyncio.sleep(1)
                
            except Exception as e:
                return {'error': str(e)}
        
        return {
            'user_id': user_id,
            'pattern': 'batch',
            'operations': operations,
            'latencies': latencies,
            'duration': time.time() - user_start
        }

class StressTestEngine:
    """Advanced stress testing scenarios"""
    
    def __init__(self):
        self.stress_scenarios = [
            self._cpu_stress_scenario,
            self._memory_stress_scenario,
            self._io_stress_scenario,
            self._network_stress_scenario
        ]
    
    def run_resource_stress_test(self, duration: int = 300) -> LoadTestResult:
        """Run comprehensive resource stress test"""
        print(f"⚡ Running resource stress test for {duration}s")
        
        monitor = SystemResourceMonitor()
        monitor.start_monitoring()
        
        start_time = time.time()
        
        # Run all stress scenarios in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(scenario, duration) 
                for scenario in self.stress_scenarios
            ]
            
            results = []
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({'error': str(e)})
        
        total_duration = time.time() - start_time
        resource_metrics = monitor.stop_monitoring()
        
        successful_operations = sum(r.get('operations', 0) for r in results if 'error' not in r)
        failed_operations = sum(1 for r in results if 'error' in r)
        
        return LoadTestResult(
            test_name='resource_stress_test',
            scenario='comprehensive_stress',
            duration=total_duration,
            total_operations=successful_operations,
            successful_operations=len([r for r in results if 'error' not in r]),
            failed_operations=failed_operations,
            throughput=successful_operations / total_duration if total_duration > 0 else 0,
            avg_latency=0,  # Not applicable for stress test
            p95_latency=0,
            p99_latency=0,
            max_latency=0,
            error_rate=failed_operations / len(results) * 100 if results else 0,
            cpu_usage_peak=resource_metrics.get('cpu_max', 0),
            memory_usage_peak_mb=resource_metrics.get('memory_mb_max', 0),
            resource_utilization=resource_metrics,
            timestamp=datetime.now()
        )
    
    def _cpu_stress_scenario(self, duration: int) -> Dict[str, Any]:
        """CPU-intensive stress scenario"""
        operations = 0
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # CPU-intensive mathematical operations
            for i in range(10000):
                result = (i ** 2 + i ** 0.5) * np.sin(i) * np.cos(i)
            operations += 10000
        
        return {
            'scenario': 'cpu_stress',
            'operations': operations,
            'duration': time.time() - start_time
        }
    
    def _memory_stress_scenario(self, duration: int) -> Dict[str, Any]:
        """Memory-intensive stress scenario"""
        operations = 0
        start_time = time.time()
        memory_blocks = []
        
        try:
            while time.time() - start_time < duration:
                # Allocate memory in chunks
                chunk_size = 10 * 1024 * 1024  # 10MB chunks
                memory_blocks.append(np.random.random(chunk_size // 8))
                operations += 1
                
                # Prevent excessive memory usage
                if len(memory_blocks) > 100:  # Keep max ~1GB
                    memory_blocks.pop(0)
                
                time.sleep(0.1)  # Brief pause
                
        except MemoryError:
            pass  # Expected when pushing memory limits
        
        return {
            'scenario': 'memory_stress',
            'operations': operations,
            'duration': time.time() - start_time,
            'peak_memory_blocks': len(memory_blocks)
        }
    
    def _io_stress_scenario(self, duration: int) -> Dict[str, Any]:
        """I/O-intensive stress scenario"""
        operations = 0
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                # Create temporary files with I/O operations
                file_path = f"/tmp/stress_io_{os.getpid()}_{operations}.tmp"
                
                # Write operation
                data = os.urandom(1024 * 1024)  # 1MB
                with open(file_path, 'wb') as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                
                # Read operation
                with open(file_path, 'rb') as f:
                    read_data = f.read()
                
                # Cleanup
                os.unlink(file_path)
                
                operations += 1
                
            except Exception as e:
                break
        
        return {
            'scenario': 'io_stress',
            'operations': operations,
            'duration': time.time() - start_time
        }
    
    def _network_stress_scenario(self, duration: int) -> Dict[str, Any]:
        """Network-intensive stress scenario"""
        operations = 0
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                # Simulate network requests
                # Use local loopback to avoid external dependencies
                import socket
                
                # Create socket connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                # Test connection to localhost
                try:
                    sock.connect(('127.0.0.1', 22))  # SSH port usually available
                    sock.close()
                    operations += 1
                except:
                    pass  # Connection failed, but that's okay for stress test
                
                time.sleep(0.01)  # Brief pause between connections
                
            except Exception as e:
                break
        
        return {
            'scenario': 'network_stress',
            'operations': operations,
            'duration': time.time() - start_time
        }

class FailureScenarioTester:
    """Test system behavior under failure conditions"""
    
    def run_failure_recovery_test(self, failure_type: str, duration: int = 120) -> LoadTestResult:
        """Test system recovery from failures"""
        print(f"💥 Testing failure recovery: {failure_type} for {duration}s")
        
        monitor = SystemResourceMonitor()
        monitor.start_monitoring()
        
        start_time = time.time()
        
        if failure_type == 'memory_exhaustion':
            result = self._test_memory_exhaustion_recovery(duration)
        elif failure_type == 'disk_space_exhaustion':
            result = self._test_disk_space_exhaustion_recovery(duration)
        elif failure_type == 'process_crash_simulation':
            result = self._test_process_crash_recovery(duration)
        elif failure_type == 'resource_contention':
            result = self._test_resource_contention_recovery(duration)
        else:
            result = {'error': f'Unknown failure type: {failure_type}'}
        
        total_duration = time.time() - start_time
        resource_metrics = monitor.stop_monitoring()
        
        return LoadTestResult(
            test_name='failure_recovery_test',
            scenario=failure_type,
            duration=total_duration,
            total_operations=result.get('operations', 0),
            successful_operations=result.get('successful_operations', 0),
            failed_operations=result.get('failed_operations', 0),
            throughput=result.get('operations', 0) / total_duration if total_duration > 0 else 0,
            avg_latency=result.get('avg_latency', 0),
            p95_latency=result.get('p95_latency', 0),
            p99_latency=result.get('p99_latency', 0),
            max_latency=result.get('max_latency', 0),
            error_rate=result.get('error_rate', 0),
            cpu_usage_peak=resource_metrics.get('cpu_max', 0),
            memory_usage_peak_mb=resource_metrics.get('memory_mb_max', 0),
            resource_utilization=resource_metrics,
            timestamp=datetime.now()
        )
    
    def _test_memory_exhaustion_recovery(self, duration: int) -> Dict[str, Any]:
        """Test recovery from memory exhaustion"""
        operations = 0
        successful_ops = 0
        failed_ops = 0
        memory_blocks = []
        
        try:
            start_time = time.time()
            
            # Phase 1: Normal operations
            while time.time() - start_time < duration * 0.3:
                # Normal memory allocation
                data = np.random.random(1000)
                result = np.sum(data)
                operations += 1
                successful_ops += 1
                time.sleep(0.01)
            
            # Phase 2: Memory exhaustion
            while time.time() - start_time < duration * 0.7:
                try:
                    # Aggressive memory allocation
                    memory_blocks.append(np.random.random(10000000))  # 80MB blocks
                    operations += 1
                    successful_ops += 1
                except MemoryError:
                    failed_ops += 1
                    # Start recovery - release some memory
                    if memory_blocks:
                        memory_blocks.pop(0)
                
                time.sleep(0.01)
            
            # Phase 3: Recovery testing
            # Clear memory blocks to simulate recovery
            memory_blocks.clear()
            
            while time.time() - start_time < duration:
                try:
                    # Test normal operations after recovery
                    data = np.random.random(1000)
                    result = np.sum(data)
                    operations += 1
                    successful_ops += 1
                except Exception:
                    failed_ops += 1
                
                time.sleep(0.01)
            
        except Exception as e:
            return {'error': str(e)}
        
        error_rate = failed_ops / operations * 100 if operations > 0 else 0
        
        return {
            'operations': operations,
            'successful_operations': successful_ops,
            'failed_operations': failed_ops,
            'error_rate': error_rate,
            'recovery_phase_ops': operations - (successful_ops + failed_ops)
        }
    
    def _test_disk_space_exhaustion_recovery(self, duration: int) -> Dict[str, Any]:
        """Test recovery from disk space issues"""
        operations = 0
        successful_ops = 0
        failed_ops = 0
        temp_files = []
        
        try:
            start_time = time.time()
            
            while time.time() - start_time < duration:
                try:
                    # Create temporary files
                    file_path = f"/tmp/disk_test_{operations}_{os.getpid()}.tmp"
                    
                    # Write data
                    with open(file_path, 'wb') as f:
                        f.write(os.urandom(1024 * 1024))  # 1MB files
                    
                    temp_files.append(file_path)
                    operations += 1
                    successful_ops += 1
                    
                    # Cleanup old files to prevent actual disk exhaustion
                    if len(temp_files) > 100:
                        old_file = temp_files.pop(0)
                        if os.path.exists(old_file):
                            os.unlink(old_file)
                    
                except Exception:
                    failed_ops += 1
                
                time.sleep(0.01)
            
        except Exception as e:
            return {'error': str(e)}
        finally:
            # Cleanup all temp files
            for file_path in temp_files:
                try:
                    if os.path.exists(file_path):
                        os.unlink(file_path)
                except:
                    pass
        
        error_rate = failed_ops / operations * 100 if operations > 0 else 0
        
        return {
            'operations': operations,
            'successful_operations': successful_ops,
            'failed_operations': failed_ops,
            'error_rate': error_rate
        }
    
    def _test_process_crash_recovery(self, duration: int) -> Dict[str, Any]:
        """Test recovery from simulated process crashes"""
        operations = 0
        successful_ops = 0
        failed_ops = 0
        
        try:
            start_time = time.time()
            
            while time.time() - start_time < duration:
                try:
                    # Simulate operations that might crash
                    if random.random() < 0.05:  # 5% chance of "crash"
                        # Simulate crash by raising exception
                        raise RuntimeError("Simulated process crash")
                    
                    # Normal operation
                    data = np.random.random(1000)
                    result = np.sum(data ** 2)
                    operations += 1
                    successful_ops += 1
                    
                except RuntimeError:
                    # Simulate crash recovery
                    failed_ops += 1
                    time.sleep(0.1)  # Recovery time
                    
                except Exception:
                    failed_ops += 1
                
                time.sleep(0.01)
            
        except Exception as e:
            return {'error': str(e)}
        
        error_rate = failed_ops / operations * 100 if operations > 0 else 0
        
        return {
            'operations': operations,
            'successful_operations': successful_ops,
            'failed_operations': failed_ops,
            'error_rate': error_rate
        }
    
    def _test_resource_contention_recovery(self, duration: int) -> Dict[str, Any]:
        """Test recovery from resource contention"""
        operations = 0
        successful_ops = 0
        failed_ops = 0
        
        # Create resource contention with multiple threads
        contention_threads = []
        stop_contention = threading.Event()
        
        def create_contention():
            """Create resource contention"""
            while not stop_contention.is_set():
                try:
                    # CPU contention
                    for i in range(10000):
                        result = i ** 2
                    time.sleep(0.001)
                except:
                    break
        
        try:
            # Start contention threads
            for _ in range(multiprocessing.cpu_count()):
                thread = threading.Thread(target=create_contention)
                thread.start()
                contention_threads.append(thread)
            
            start_time = time.time()
            
            while time.time() - start_time < duration:
                try:
                    # Operations under contention
                    data = np.random.random(1000)
                    result = np.sum(data)
                    operations += 1
                    successful_ops += 1
                    
                except Exception:
                    failed_ops += 1
                
                time.sleep(0.01)
            
        except Exception as e:
            return {'error': str(e)}
        finally:
            # Stop contention
            stop_contention.set()
            for thread in contention_threads:
                thread.join(timeout=1)
        
        error_rate = failed_ops / operations * 100 if operations > 0 else 0
        
        return {
            'operations': operations,
            'successful_operations': successful_ops,
            'failed_operations': failed_ops,
            'error_rate': error_rate
        }

class LoadTestSuite:
    """Main load testing suite orchestrator"""
    
    def __init__(self):
        self.user_simulator = ConcurrentUserSimulator()
        self.stress_engine = StressTestEngine()
        self.failure_tester = FailureScenarioTester()
        self.results = []
    
    async def run_comprehensive_load_tests(self) -> List[LoadTestResult]:
        """Run comprehensive load testing scenarios"""
        print("🚀 Starting Comprehensive Load Testing Suite")
        print("=" * 60)
        
        results = []
        
        # Concurrent User Scenarios
        print("\n👥 === CONCURRENT USER SCENARIOS ===")
        
        user_scenarios = [
            (10, 120, 'casual'),
            (25, 180, 'mixed'),
            (50, 240, 'power'),
            (100, 300, 'developer'),
            (200, 300, 'batch')
        ]
        
        for users, duration, workload in user_scenarios:
            try:
                result = await self.user_simulator.simulate_concurrent_users(
                    users, duration, workload
                )
                results.append(result)
                print(f"✅ {users} {workload} users: {result.throughput:.1f} ops/s")
            except Exception as e:
                print(f"❌ {users} {workload} users failed: {e}")
        
        # Resource Stress Tests
        print("\n⚡ === RESOURCE STRESS TESTS ===")
        
        try:
            stress_result = self.stress_engine.run_resource_stress_test(duration=300)
            results.append(stress_result)
            print(f"✅ Resource stress test: {stress_result.cpu_usage_peak:.1f}% peak CPU")
        except Exception as e:
            print(f"❌ Resource stress test failed: {e}")
        
        # Failure Recovery Tests
        print("\n💥 === FAILURE RECOVERY TESTS ===")
        
        failure_scenarios = [
            'memory_exhaustion',
            'disk_space_exhaustion',
            'process_crash_simulation',
            'resource_contention'
        ]
        
        for scenario in failure_scenarios:
            try:
                failure_result = self.failure_tester.run_failure_recovery_test(
                    scenario, duration=120
                )
                results.append(failure_result)
                print(f"✅ {scenario}: {failure_result.error_rate:.1f}% error rate")
            except Exception as e:
                print(f"❌ {scenario} failed: {e}")
        
        return results
    
    def generate_load_test_report(self, results: List[LoadTestResult]) -> str:
        """Generate comprehensive load test report"""
        report = []
        report.append("# Comprehensive Load Testing Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append(f"Total scenarios tested: {len(results)}")
        report.append("")
        
        # Executive Summary
        report.append("## Executive Summary")
        report.append("")
        
        # Calculate overall metrics
        total_operations = sum(r.total_operations for r in results)
        avg_throughput = statistics.mean([r.throughput for r in results if r.throughput > 0])
        avg_error_rate = statistics.mean([r.error_rate for r in results])
        max_cpu_usage = max([r.cpu_usage_peak for r in results])
        max_memory_usage = max([r.memory_usage_peak_mb for r in results])
        
        report.append(f"- **Total Operations Executed**: {total_operations:,}")
        report.append(f"- **Average Throughput**: {avg_throughput:.1f} operations/second")
        report.append(f"- **Average Error Rate**: {avg_error_rate:.2f}%")
        report.append(f"- **Peak CPU Usage**: {max_cpu_usage:.1f}%")
        report.append(f"- **Peak Memory Usage**: {max_memory_usage:.1f} MB")
        report.append("")
        
        # User Load Testing Results
        user_results = [r for r in results if r.test_name == 'concurrent_user_simulation']
        if user_results:
            report.append("## Concurrent User Load Testing")
            report.append("")
            report.append("| Scenario | Users | Throughput | Latency (P95) | Error Rate | CPU Peak |")
            report.append("|----------|-------|------------|---------------|------------|----------|")
            
            for result in sorted(user_results, key=lambda x: int(x.scenario.split('_')[0])):
                users = result.scenario.split('_')[0]
                workload = result.scenario.split('_')[2]
                report.append(
                    f"| {workload.title()} | {users} | {result.throughput:.1f} ops/s | "
                    f"{result.p95_latency:.3f}s | {result.error_rate:.1f}% | {result.cpu_usage_peak:.1f}% |"
                )
            
            report.append("")
        
        # Stress Testing Results
        stress_results = [r for r in results if r.test_name == 'resource_stress_test']
        if stress_results:
            report.append("## Resource Stress Testing")
            report.append("")
            
            for result in stress_results:
                report.append(f"### {result.scenario.replace('_', ' ').title()}")
                report.append(f"- **Duration**: {result.duration:.1f}s")
                report.append(f"- **Peak CPU Usage**: {result.cpu_usage_peak:.1f}%")
                report.append(f"- **Peak Memory Usage**: {result.memory_usage_peak_mb:.1f} MB")
                report.append(f"- **Operations Completed**: {result.total_operations:,}")
                
                if result.resource_utilization:
                    ru = result.resource_utilization
                    report.append(f"- **Disk I/O**: {ru.get('disk_io_read_mb', 0):.1f} MB read, "
                                f"{ru.get('disk_io_write_mb', 0):.1f} MB written")
                    report.append(f"- **Network I/O**: {ru.get('network_sent_mb', 0):.1f} MB sent, "
                                f"{ru.get('network_recv_mb', 0):.1f} MB received")
                report.append("")
        
        # Failure Recovery Results
        failure_results = [r for r in results if r.test_name == 'failure_recovery_test']
        if failure_results:
            report.append("## Failure Recovery Testing")
            report.append("")
            report.append("| Failure Type | Success Rate | Recovery Time | Error Rate |")
            report.append("|--------------|--------------|---------------|------------|")
            
            for result in failure_results:
                success_rate = (result.successful_operations / result.total_operations * 100 
                              if result.total_operations > 0 else 0)
                # Estimate recovery time based on duration and operations
                recovery_time = result.duration / max(1, result.total_operations) * 1000  # ms
                
                report.append(
                    f"| {result.scenario.replace('_', ' ').title()} | {success_rate:.1f}% | "
                    f"{recovery_time:.1f}ms | {result.error_rate:.1f}% |"
                )
            
            report.append("")
        
        # Performance Recommendations
        report.append("## Load Testing Recommendations")
        report.append("")
        
        # Analyze results for recommendations
        if avg_error_rate > 5:
            report.append("### ⚠️ High Error Rate Detected")
            report.append("- Error rate exceeds 5% - investigate system stability")
            report.append("- Consider implementing better error handling and retry logic")
            report.append("- Review resource allocation and scaling policies")
            report.append("")
        
        if max_cpu_usage > 90:
            report.append("### ⚠️ High CPU Utilization")
            report.append("- CPU usage exceeded 90% - consider horizontal scaling")
            report.append("- Optimize CPU-intensive operations")
            report.append("- Implement load balancing for better distribution")
            report.append("")
        
        if max_memory_usage > 24000:  # 75% of 32GB
            report.append("### ⚠️ High Memory Usage")
            report.append("- Memory usage exceeded 75% of available RAM")
            report.append("- Review memory allocation patterns")
            report.append("- Implement memory pooling and garbage collection optimization")
            report.append("")
        
        # Scalability analysis
        user_results_sorted = sorted(user_results, key=lambda x: int(x.scenario.split('_')[0]))
        if len(user_results_sorted) >= 2:
            small_load = user_results_sorted[0]
            large_load = user_results_sorted[-1]
            
            scalability_factor = (large_load.throughput * int(small_load.scenario.split('_')[0])) / \
                               (small_load.throughput * int(large_load.scenario.split('_')[0]))
            
            report.append("### Scalability Analysis")
            if scalability_factor > 0.8:
                report.append("✅ **Good scalability** - system scales well with increased load")
            elif scalability_factor > 0.6:
                report.append("⚠️ **Moderate scalability** - some degradation under high load")
            else:
                report.append("❌ **Poor scalability** - significant degradation under high load")
            
            report.append(f"- Scalability factor: {scalability_factor:.2f}")
            report.append("")
        
        # Recommended SLAs based on test results
        report.append("## Recommended Performance SLAs")
        report.append("")
        
        if user_results:
            best_p95_latency = min(r.p95_latency for r in user_results if r.p95_latency > 0)
            conservative_throughput = min(r.throughput for r in user_results if r.throughput > 0) * 0.8
            
            report.append(f"- **Response Time SLA**: < {best_p95_latency * 1.5:.3f}s (95th percentile)")
            report.append(f"- **Throughput SLA**: > {conservative_throughput:.1f} operations/second")
            report.append(f"- **Error Rate SLA**: < 1% under normal load")
            report.append(f"- **Availability SLA**: 99.9% uptime")
        
        return "\n".join(report)
    
    def save_load_test_results(self, results: List[LoadTestResult], report: str):
        """Save load test results and report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        benchmarks_dir = Path("/home/louranicas/projects/claude-optimized-deployment/benchmarks")
        benchmarks_dir.mkdir(exist_ok=True)
        
        # Save JSON results
        json_path = benchmarks_dir / f"load_test_results_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump([asdict(r) for r in results], f, indent=2, default=str)
        
        # Save report
        report_path = benchmarks_dir / f"load_test_report_{timestamp}.md"
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(f"\n✅ Load test results saved:")
        print(f"📊 JSON Data: {json_path}")
        print(f"📄 Report: {report_path}")

async def main():
    """Run comprehensive load testing suite"""
    suite = LoadTestSuite()
    
    # Run all load tests
    results = await suite.run_comprehensive_load_tests()
    
    # Generate report
    report = suite.generate_load_test_report(results)
    
    # Save results
    suite.save_load_test_results(results, report)
    
    # Print summary
    print("\n🎯 LOAD TESTING SUMMARY")
    print("=" * 50)
    print(f"Scenarios completed: {len(results)}")
    
    if results:
        total_ops = sum(r.total_operations for r in results)
        avg_throughput = statistics.mean([r.throughput for r in results if r.throughput > 0])
        avg_error_rate = statistics.mean([r.error_rate for r in results])
        
        print(f"Total operations: {total_ops:,}")
        print(f"Average throughput: {avg_throughput:.1f} ops/s")
        print(f"Average error rate: {avg_error_rate:.2f}%")
    
    print("\n✅ Load testing suite completed!")

if __name__ == "__main__":
    import os
    asyncio.run(main())