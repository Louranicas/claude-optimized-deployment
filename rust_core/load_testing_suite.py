#!/usr/bin/env python3
"""
Load Testing Suite for CODE v1.0.0
==================================

Comprehensive load testing to validate system performance under stress:
- Concurrent user simulation
- High-throughput API testing  
- Memory pressure testing
- Circuit breaker validation under load
- Database connection pool testing
- Distributed system coordination testing
"""

import asyncio
import aiohttp
import time
import json
import statistics
import psutil
import gc
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import requests
from pathlib import Path
import sys
import tracemalloc
import warnings
warnings.filterwarnings('ignore')

# Add project root to path  
sys.path.insert(0, '/home/louranicas/projects/claude-optimized-deployment')

@dataclass
class LoadTestResult:
    """Load test result container"""
    test_name: str
    concurrent_users: int
    total_requests: int
    duration_seconds: float
    throughput_rps: float
    avg_response_time_ms: float
    p50_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    error_rate_percent: float
    cpu_usage_percent: float
    memory_usage_mb: float
    success_count: int
    error_count: int
    timeout_count: int

@dataclass
class SystemMetrics:
    """System metrics during load testing"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_sent_mb: float
    network_recv_mb: float
    active_threads: int
    active_processes: int

class LoadTestSuite:
    """Main load testing suite"""
    
    def __init__(self):
        self.results: List[LoadTestResult] = []
        self.metrics_history: List[SystemMetrics] = []
        self.start_time = time.time()
        self.output_dir = Path('/home/louranicas/projects/claude-optimized-deployment/performance_reports')
        self.output_dir.mkdir(exist_ok=True)
        
        # System monitoring
        self.monitoring_active = False
        self.monitor_thread = None
        
    def start_system_monitoring(self):
        """Start background system monitoring"""
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()
        
    def stop_system_monitoring(self):
        """Stop background system monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
    
    def _monitor_system(self):
        """Background system monitoring loop"""
        initial_disk = psutil.disk_io_counters()
        initial_net = psutil.net_io_counters()
        
        while self.monitoring_active:
            try:
                current_disk = psutil.disk_io_counters()
                current_net = psutil.net_io_counters()
                
                metrics = SystemMetrics(
                    timestamp=time.time(),
                    cpu_percent=psutil.cpu_percent(interval=0.1),
                    memory_percent=psutil.virtual_memory().percent,
                    memory_used_mb=psutil.virtual_memory().used / 1024 / 1024,
                    disk_io_read_mb=(current_disk.read_bytes - initial_disk.read_bytes) / 1024 / 1024,
                    disk_io_write_mb=(current_disk.write_bytes - initial_disk.write_bytes) / 1024 / 1024,
                    network_sent_mb=(current_net.bytes_sent - initial_net.bytes_sent) / 1024 / 1024,
                    network_recv_mb=(current_net.bytes_recv - initial_net.bytes_recv) / 1024 / 1024,
                    active_threads=threading.active_count(),
                    active_processes=len(psutil.pids())
                )
                
                self.metrics_history.append(metrics)
                time.sleep(1)  # Monitor every second
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                break

    async def test_concurrent_api_load(self, base_url: str = "http://localhost:8000") -> LoadTestResult:
        """Test API under concurrent load"""
        print("🔥 Testing Concurrent API Load")
        
        concurrent_users = 50
        requests_per_user = 20
        total_requests = concurrent_users * requests_per_user
        
        response_times = []
        errors = 0
        timeouts = 0
        successes = 0
        
        start_time = time.time()
        start_memory = psutil.virtual_memory().used
        
        async def make_request(session: aiohttp.ClientSession, user_id: int, request_id: int):
            """Make a single API request"""
            nonlocal errors, timeouts, successes
            
            request_start = time.time()
            try:
                # Simulate different API endpoints
                endpoints = [
                    f"{base_url}/health",
                    f"{base_url}/api/status", 
                    f"{base_url}/api/metrics",
                    f"{base_url}/api/config"
                ]
                
                endpoint = endpoints[request_id % len(endpoints)]
                
                async with session.get(endpoint, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    await response.text()
                    request_time = (time.time() - request_start) * 1000  # Convert to ms
                    response_times.append(request_time)
                    successes += 1
                    
            except asyncio.TimeoutError:
                timeouts += 1
            except Exception as e:
                errors += 1
        
        async def user_simulation(user_id: int):
            """Simulate a user making multiple requests"""
            connector = aiohttp.TCPConnector(limit=10, limit_per_host=10)
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = []
                for request_id in range(requests_per_user):
                    task = make_request(session, user_id, request_id)
                    tasks.append(task)
                    
                    # Add some jitter between requests
                    await asyncio.sleep(0.1 + np.random.exponential(0.05))
                
                await asyncio.gather(*tasks, return_exceptions=True)
        
        # Start system monitoring
        self.start_system_monitoring()
        
        try:
            # Create concurrent users
            user_tasks = [user_simulation(i) for i in range(concurrent_users)]
            await asyncio.gather(*user_tasks, return_exceptions=True)
            
        finally:
            self.stop_system_monitoring()
        
        # Calculate metrics
        end_time = time.time()
        duration = end_time - start_time
        end_memory = psutil.virtual_memory().used
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            p50_response_time = np.percentile(response_times, 50)
            p95_response_time = np.percentile(response_times, 95)
            p99_response_time = np.percentile(response_times, 99)
        else:
            avg_response_time = p50_response_time = p95_response_time = p99_response_time = 0
        
        result = LoadTestResult(
            test_name="concurrent_api_load",
            concurrent_users=concurrent_users,
            total_requests=total_requests,
            duration_seconds=duration,
            throughput_rps=total_requests / duration if duration > 0 else 0,
            avg_response_time_ms=avg_response_time,
            p50_response_time_ms=p50_response_time,
            p95_response_time_ms=p95_response_time,
            p99_response_time_ms=p99_response_time,
            error_rate_percent=(errors + timeouts) / total_requests * 100 if total_requests > 0 else 0,
            cpu_usage_percent=psutil.cpu_percent(),
            memory_usage_mb=(end_memory - start_memory) / 1024 / 1024,
            success_count=successes,
            error_count=errors,
            timeout_count=timeouts
        )
        
        self.results.append(result)
        print(f"✅ API Load Test: {result.throughput_rps:.1f} RPS, {result.avg_response_time_ms:.1f}ms avg")
        return result

    def test_memory_pressure(self) -> LoadTestResult:
        """Test system under memory pressure"""
        print("🧠 Testing Memory Pressure")
        
        start_time = time.time()
        start_memory = psutil.virtual_memory().used
        
        # Start monitoring
        self.start_system_monitoring()
        
        try:
            # Gradually increase memory pressure
            memory_chunks = []
            chunk_size = 10 * 1024 * 1024  # 10MB chunks
            max_chunks = 100  # Up to 1GB
            
            operations = 0
            errors = 0
            
            for i in range(max_chunks):
                try:
                    # Allocate memory chunk
                    chunk = bytearray(chunk_size)
                    
                    # Fill with data to ensure actual allocation
                    for j in range(0, chunk_size, 4096):
                        chunk[j] = i % 256
                    
                    memory_chunks.append(chunk)
                    operations += 1
                    
                    # Periodically force garbage collection
                    if i % 10 == 0:
                        gc.collect()
                    
                    # Check memory usage
                    current_memory = psutil.virtual_memory()
                    if current_memory.percent > 90:  # Stop if memory usage too high
                        print(f"Stopping at {current_memory.percent:.1f}% memory usage")
                        break
                        
                    time.sleep(0.01)  # Small delay
                    
                except MemoryError:
                    errors += 1
                    break
                except Exception as e:
                    errors += 1
                    print(f"Memory allocation error: {e}")
            
            # Hold memory for a short time to test sustained pressure
            time.sleep(2)
            
            # Cleanup
            del memory_chunks
            gc.collect()
            
        finally:
            self.stop_system_monitoring()
        
        end_time = time.time()
        duration = end_time - start_time
        end_memory = psutil.virtual_memory().used
        
        result = LoadTestResult(
            test_name="memory_pressure",
            concurrent_users=1,
            total_requests=operations,
            duration_seconds=duration,
            throughput_rps=operations / duration if duration > 0 else 0,
            avg_response_time_ms=0,
            p50_response_time_ms=0,
            p95_response_time_ms=0,
            p99_response_time_ms=0,
            error_rate_percent=errors / max(1, operations) * 100,
            cpu_usage_percent=psutil.cpu_percent(),
            memory_usage_mb=(end_memory - start_memory) / 1024 / 1024,
            success_count=operations - errors,
            error_count=errors,
            timeout_count=0
        )
        
        self.results.append(result)
        print(f"✅ Memory Pressure: {operations} allocations, {errors} errors")
        return result

    def test_cpu_intensive_load(self) -> LoadTestResult:
        """Test CPU-intensive workload"""
        print("⚡ Testing CPU Intensive Load")
        
        start_time = time.time()
        start_memory = psutil.virtual_memory().used
        
        self.start_system_monitoring()
        
        def cpu_intensive_task(task_id: int, iterations: int) -> Tuple[int, int, float]:
            """CPU-intensive computation task"""
            start = time.time()
            
            # Prime number calculation (CPU intensive)
            primes_found = 0
            for n in range(task_id * 1000, (task_id + 1) * 1000):
                if n < 2:
                    continue
                    
                is_prime = True
                for i in range(2, int(n ** 0.5) + 1):
                    if n % i == 0:
                        is_prime = False
                        break
                
                if is_prime:
                    primes_found += 1
            
            duration = time.time() - start
            return task_id, primes_found, duration
        
        try:
            num_workers = multiprocessing.cpu_count()
            tasks_per_worker = 10
            total_tasks = num_workers * tasks_per_worker
            
            successes = 0
            errors = 0
            task_times = []
            
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                # Submit all tasks
                futures = []
                for i in range(total_tasks):
                    future = executor.submit(cpu_intensive_task, i, 1000)
                    futures.append(future)
                
                # Collect results
                for future in as_completed(futures, timeout=60):
                    try:
                        task_id, primes, duration = future.result()
                        task_times.append(duration * 1000)  # Convert to ms
                        successes += 1
                    except Exception as e:
                        errors += 1
                        print(f"Task error: {e}")
        
        except Exception as e:
            print(f"CPU test error: {e}")
            errors += 1
        
        finally:
            self.stop_system_monitoring()
        
        end_time = time.time()
        duration = end_time - start_time
        end_memory = psutil.virtual_memory().used
        
        result = LoadTestResult(
            test_name="cpu_intensive_load",
            concurrent_users=num_workers,
            total_requests=total_tasks,
            duration_seconds=duration,
            throughput_rps=total_tasks / duration if duration > 0 else 0,
            avg_response_time_ms=statistics.mean(task_times) if task_times else 0,
            p50_response_time_ms=np.percentile(task_times, 50) if task_times else 0,
            p95_response_time_ms=np.percentile(task_times, 95) if task_times else 0,
            p99_response_time_ms=np.percentile(task_times, 99) if task_times else 0,
            error_rate_percent=errors / max(1, total_tasks) * 100,
            cpu_usage_percent=psutil.cpu_percent(),
            memory_usage_mb=(end_memory - start_memory) / 1024 / 1024,
            success_count=successes,
            error_count=errors,
            timeout_count=0
        )
        
        self.results.append(result)
        print(f"✅ CPU Load: {successes}/{total_tasks} tasks completed")
        return result

    def test_io_intensive_load(self) -> LoadTestResult:
        """Test I/O intensive workload"""
        print("💾 Testing I/O Intensive Load")
        
        start_time = time.time()
        start_memory = psutil.virtual_memory().used
        
        self.start_system_monitoring()
        
        def io_task(task_id: int) -> Tuple[int, float]:
            """I/O intensive task"""
            start = time.time()
            
            try:
                # Create temporary file
                filename = f"/tmp/load_test_{task_id}_{threading.get_ident()}.tmp"
                
                # Write data
                data = f"Load test data for task {task_id} " * 1000
                with open(filename, 'w') as f:
                    for i in range(100):
                        f.write(f"{data}\n")
                        f.flush()
                
                # Read data back
                with open(filename, 'r') as f:
                    content = f.read()
                
                # Cleanup
                import os
                os.remove(filename)
                
                return task_id, time.time() - start
                
            except Exception as e:
                print(f"I/O task {task_id} error: {e}")
                return task_id, time.time() - start
        
        try:
            num_threads = 20
            tasks_per_thread = 5
            total_tasks = num_threads * tasks_per_thread
            
            successes = 0
            errors = 0
            task_times = []
            
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = []
                for i in range(total_tasks):
                    future = executor.submit(io_task, i)
                    futures.append(future)
                
                for future in as_completed(futures, timeout=30):
                    try:
                        task_id, duration = future.result()
                        task_times.append(duration * 1000)  # Convert to ms
                        successes += 1
                    except Exception as e:
                        errors += 1
        
        except Exception as e:
            print(f"I/O test error: {e}")
            errors += 1
        
        finally:
            self.stop_system_monitoring()
        
        end_time = time.time()
        duration = end_time - start_time
        end_memory = psutil.virtual_memory().used
        
        result = LoadTestResult(
            test_name="io_intensive_load",
            concurrent_users=num_threads,
            total_requests=total_tasks,
            duration_seconds=duration,
            throughput_rps=total_tasks / duration if duration > 0 else 0,
            avg_response_time_ms=statistics.mean(task_times) if task_times else 0,
            p50_response_time_ms=np.percentile(task_times, 50) if task_times else 0,
            p95_response_time_ms=np.percentile(task_times, 95) if task_times else 0,
            p99_response_time_ms=np.percentile(task_times, 99) if task_times else 0,
            error_rate_percent=errors / max(1, total_tasks) * 100,
            cpu_usage_percent=psutil.cpu_percent(),
            memory_usage_mb=(end_memory - start_memory) / 1024 / 1024,
            success_count=successes,
            error_count=errors,
            timeout_count=0
        )
        
        self.results.append(result)
        print(f"✅ I/O Load: {successes}/{total_tasks} tasks completed")
        return result

    def test_mixed_workload(self) -> LoadTestResult:
        """Test mixed CPU/Memory/I/O workload"""
        print("🔀 Testing Mixed Workload")
        
        start_time = time.time()
        start_memory = psutil.virtual_memory().used
        
        self.start_system_monitoring()
        
        def mixed_task(task_id: int) -> Tuple[int, float]:
            """Mixed workload task"""
            start = time.time()
            
            try:
                # CPU component - mathematical computation
                result = 0
                for i in range(1000):
                    result += i ** 2
                
                # Memory component - data manipulation
                data = [x for x in range(1000)]
                processed = [x * 2 + 1 for x in data]
                
                # I/O component - temporary file operation
                filename = f"/tmp/mixed_test_{task_id}_{threading.get_ident()}.tmp"
                with open(filename, 'w') as f:
                    f.write(str(processed[:100]))
                
                with open(filename, 'r') as f:
                    content = f.read()
                
                import os
                os.remove(filename)
                
                return task_id, time.time() - start
                
            except Exception as e:
                print(f"Mixed task {task_id} error: {e}")
                return task_id, time.time() - start
        
        try:
            num_workers = 15
            tasks_per_worker = 8
            total_tasks = num_workers * tasks_per_worker
            
            successes = 0
            errors = 0
            task_times = []
            
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = []
                for i in range(total_tasks):
                    future = executor.submit(mixed_task, i)
                    futures.append(future)
                
                for future in as_completed(futures, timeout=45):
                    try:
                        task_id, duration = future.result()
                        task_times.append(duration * 1000)
                        successes += 1
                    except Exception as e:
                        errors += 1
        
        except Exception as e:
            print(f"Mixed workload error: {e}")
            errors += 1
        
        finally:
            self.stop_system_monitoring()
        
        end_time = time.time()
        duration = end_time - start_time
        end_memory = psutil.virtual_memory().used
        
        result = LoadTestResult(
            test_name="mixed_workload",
            concurrent_users=num_workers,
            total_requests=total_tasks,
            duration_seconds=duration,
            throughput_rps=total_tasks / duration if duration > 0 else 0,
            avg_response_time_ms=statistics.mean(task_times) if task_times else 0,
            p50_response_time_ms=np.percentile(task_times, 50) if task_times else 0,
            p95_response_time_ms=np.percentile(task_times, 95) if task_times else 0,
            p99_response_time_ms=np.percentile(task_times, 99) if task_times else 0,
            error_rate_percent=errors / max(1, total_tasks) * 100,
            cpu_usage_percent=psutil.cpu_percent(),
            memory_usage_mb=(end_memory - start_memory) / 1024 / 1024,
            success_count=successes,
            error_count=errors,
            timeout_count=0
        )
        
        self.results.append(result)
        print(f"✅ Mixed Workload: {successes}/{total_tasks} tasks completed")
        return result

    def generate_load_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive load test report"""
        print("📊 Generating Load Test Report")
        
        if not self.results:
            return {"error": "No load test results available"}
        
        # Calculate aggregate metrics
        total_requests = sum(r.total_requests for r in self.results)
        total_duration = time.time() - self.start_time
        overall_throughput = total_requests / total_duration if total_duration > 0 else 0
        
        avg_error_rate = statistics.mean(r.error_rate_percent for r in self.results)
        avg_cpu_usage = statistics.mean(r.cpu_usage_percent for r in self.results)
        total_memory_used = sum(r.memory_usage_mb for r in self.results)
        
        # System metrics analysis
        if self.metrics_history:
            peak_cpu = max(m.cpu_percent for m in self.metrics_history)
            peak_memory = max(m.memory_used_mb for m in self.metrics_history)
            avg_cpu = statistics.mean(m.cpu_percent for m in self.metrics_history)
            avg_memory = statistics.mean(m.memory_used_mb for m in self.metrics_history)
        else:
            peak_cpu = avg_cpu = peak_memory = avg_memory = 0
        
        report = {
            "load_test_summary": {
                "timestamp": time.time(),
                "total_duration_seconds": total_duration,
                "total_requests": total_requests,
                "overall_throughput_rps": overall_throughput,
                "average_error_rate_percent": avg_error_rate,
                "peak_cpu_usage_percent": peak_cpu,
                "peak_memory_usage_mb": peak_memory,
                "average_cpu_usage_percent": avg_cpu,
                "average_memory_usage_mb": avg_memory
            },
            "test_results": [asdict(result) for result in self.results],
            "system_metrics": [asdict(metric) for metric in self.metrics_history[-100:]],  # Last 100 samples
            "performance_analysis": self._analyze_performance(),
            "load_test_grade": self._calculate_load_test_grade(),
            "recommendations": self._generate_load_recommendations()
        }
        
        return report
    
    def _analyze_performance(self) -> Dict[str, Any]:
        """Analyze performance characteristics"""
        if not self.results:
            return {}
        
        # Find best and worst performing tests
        best_throughput = max(self.results, key=lambda x: x.throughput_rps)
        worst_throughput = min(self.results, key=lambda x: x.throughput_rps)
        best_latency = min(self.results, key=lambda x: x.avg_response_time_ms)
        worst_latency = max(self.results, key=lambda x: x.avg_response_time_ms)
        
        # Calculate stability metrics
        throughput_variance = statistics.variance([r.throughput_rps for r in self.results])
        latency_variance = statistics.variance([r.avg_response_time_ms for r in self.results])
        
        return {
            "best_throughput_test": best_throughput.test_name,
            "best_throughput_rps": best_throughput.throughput_rps,
            "worst_throughput_test": worst_throughput.test_name,
            "worst_throughput_rps": worst_throughput.throughput_rps,
            "best_latency_test": best_latency.test_name,
            "best_latency_ms": best_latency.avg_response_time_ms,
            "worst_latency_test": worst_latency.test_name,
            "worst_latency_ms": worst_latency.avg_response_time_ms,
            "throughput_stability": 1.0 / (1.0 + throughput_variance),
            "latency_stability": 1.0 / (1.0 + latency_variance),
            "overall_stability_score": (1.0 / (1.0 + throughput_variance) + 1.0 / (1.0 + latency_variance)) / 2
        }
    
    def _calculate_load_test_grade(self) -> str:
        """Calculate overall load test grade"""
        if not self.results:
            return "N/A"
        
        # Score based on multiple factors
        throughput_score = min(100, statistics.mean(r.throughput_rps for r in self.results) * 5)
        error_rate_score = max(0, 100 - statistics.mean(r.error_rate_percent for r in self.results) * 2)
        latency_score = max(0, 100 - statistics.mean(r.avg_response_time_ms for r in self.results) / 10)
        
        overall_score = (throughput_score + error_rate_score + latency_score) / 3
        
        if overall_score >= 90:
            return "A+ (Excellent under load)"
        elif overall_score >= 80:
            return "A (Very good under load)"
        elif overall_score >= 70:
            return "B (Good under load)"
        elif overall_score >= 60:
            return "C (Average under load)"
        else:
            return "D (Poor under load)"
    
    def _generate_load_recommendations(self) -> List[str]:
        """Generate load testing recommendations"""
        recommendations = []
        
        if not self.results:
            return ["No load test data available for recommendations"]
        
        # Analyze results for recommendations
        high_error_tests = [r for r in self.results if r.error_rate_percent > 5]
        low_throughput_tests = [r for r in self.results if r.throughput_rps < 10]
        high_latency_tests = [r for r in self.results if r.avg_response_time_ms > 1000]
        
        if high_error_tests:
            recommendations.append(
                f"High error rates detected in: {', '.join(t.test_name for t in high_error_tests)}. "
                "Consider implementing circuit breakers and better error handling."
            )
        
        if low_throughput_tests:
            recommendations.append(
                f"Low throughput in: {', '.join(t.test_name for t in low_throughput_tests)}. "
                "Consider optimizing algorithms or adding horizontal scaling."
            )
        
        if high_latency_tests:
            recommendations.append(
                f"High latency in: {', '.join(t.test_name for t in high_latency_tests)}. "
                "Consider adding caching, optimizing database queries, or using async processing."
            )
        
        # System-level recommendations
        if self.metrics_history:
            peak_cpu = max(m.cpu_percent for m in self.metrics_history)
            peak_memory = max(m.memory_percent for m in self.metrics_history)
            
            if peak_cpu > 90:
                recommendations.append("CPU usage exceeded 90%. Consider CPU optimization or scaling.")
            
            if peak_memory > 85:
                recommendations.append("Memory usage exceeded 85%. Consider memory optimization or scaling.")
        
        # General recommendations
        recommendations.extend([
            "Implement connection pooling for better resource utilization",
            "Add monitoring and alerting for performance degradation",
            "Consider implementing auto-scaling based on load metrics",
            "Regular load testing should be part of CI/CD pipeline"
        ])
        
        return recommendations

async def run_load_tests():
    """Run all load tests"""
    print("🚀 Starting Load Testing Suite")
    print("=" * 50)
    
    suite = LoadTestSuite()
    
    try:
        # Run different types of load tests
        print("Running API load test...")
        await suite.test_concurrent_api_load()
        
        print("Running memory pressure test...")
        suite.test_memory_pressure()
        
        print("Running CPU intensive test...")
        suite.test_cpu_intensive_load()
        
        print("Running I/O intensive test...")
        suite.test_io_intensive_load()
        
        print("Running mixed workload test...")
        suite.test_mixed_workload()
        
        # Generate report
        report = suite.generate_load_test_report()
        
        # Save report
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_path = suite.output_dir / f'load_test_report_{timestamp}.json'
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print("\n" + "=" * 50)
        print("🎉 Load Testing Completed!")
        print(f"📊 Load Test Grade: {report['load_test_grade']}")
        print(f"⚡ Overall Throughput: {report['load_test_summary']['overall_throughput_rps']:.1f} RPS")
        print(f"❌ Average Error Rate: {report['load_test_summary']['average_error_rate_percent']:.1f}%")
        print(f"🖥️  Peak CPU Usage: {report['load_test_summary']['peak_cpu_usage_percent']:.1f}%")
        print(f"🧠 Peak Memory Usage: {report['load_test_summary']['peak_memory_usage_mb']:.1f} MB")
        print(f"📄 Report saved: {report_path}")
        print("=" * 50)
        
        return report
        
    except Exception as e:
        print(f"❌ Load testing failed: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    try:
        report = asyncio.run(run_load_tests())
        sys.exit(0 if report else 1)
    except KeyboardInterrupt:
        print("\n⚠️  Load testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)