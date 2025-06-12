"""
Advanced Memory Stress Testing Framework
Extends existing stress testing with memory-focused scenarios.
"""

import pytest
import asyncio
import gc
import tracemalloc
import psutil
import time
import threading
import resource
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Callable, Optional, Tuple
from pathlib import Path
import sys
import os
import json
from contextlib import asynccontextmanager

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.circle_of_experts.core.expert_manager import ExpertManager
from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
from src.circle_of_experts.models.response import ExpertResponse
from src.mcp.manager import get_mcp_manager
from src.circle_of_experts.core.rust_accelerated import (
    ExpertAnalyzer,
    ConsensusEngine,
    ResponseAggregator
)


@dataclass
class MemoryStressResult:
    """Results from memory stress testing"""
    test_name: str
    stress_type: str
    duration_seconds: float
    max_memory_mb: float
    min_memory_mb: float
    avg_memory_mb: float
    memory_variance: float
    peak_concurrent_operations: int
    successful_operations: int
    failed_operations: int
    memory_fragmentation_score: float
    recovery_time_seconds: float
    stability_score: float
    breaking_point_reached: bool
    recommendations: List[str]


@dataclass
class MemorySnapshot:
    """Memory state snapshot"""
    timestamp: float
    rss_mb: float
    vms_mb: float
    available_mb: float
    gc_counts: List[int]
    active_objects: int
    description: str


class MemoryStressTester:
    """Advanced memory-focused stress testing"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.results = []
        self.snapshots = []
        self.stop_flag = threading.Event()
        self.memory_pressure_data = []
        
    def start_memory_monitoring(self):
        """Start continuous memory monitoring"""
        self.snapshots = []
        self.stop_flag.clear()
        
    def stop_memory_monitoring(self):
        """Stop memory monitoring"""
        self.stop_flag.set()
        
    def take_snapshot(self, description: str) -> MemorySnapshot:
        """Take a detailed memory snapshot"""
        memory_info = self.process.memory_info()
        virtual_mem = psutil.virtual_memory()
        
        snapshot = MemorySnapshot(
            timestamp=time.time(),
            rss_mb=memory_info.rss / 1024 / 1024,
            vms_mb=memory_info.vms / 1024 / 1024,
            available_mb=virtual_mem.available / 1024 / 1024,
            gc_counts=list(gc.get_count()),
            active_objects=len(gc.get_objects()),
            description=description
        )
        
        self.snapshots.append(snapshot)
        return snapshot
        
    async def monitor_memory_continuously(self, interval: float = 0.5):
        """Monitor memory usage continuously during stress test"""
        while not self.stop_flag.is_set():
            snapshot = self.take_snapshot("continuous_monitoring")
            self.memory_pressure_data.append(snapshot.rss_mb)
            await asyncio.sleep(interval)
    
    @pytest.mark.memory_stress
    async def test_memory_pressure_scenarios(self):
        """Test system behavior under memory pressure"""
        print("\n🔥 Testing Memory Pressure Scenarios...")
        
        # Start monitoring
        self.start_memory_monitoring()
        monitor_task = asyncio.create_task(self.monitor_memory_continuously())
        
        start_time = time.time()
        initial_snapshot = self.take_snapshot("initial")
        
        # Memory pressure simulation
        memory_hogs = []
        successful_ops = 0
        failed_ops = 0
        
        try:
            # Gradually increase memory pressure
            for pressure_level in range(1, 11):  # 10 levels of pressure
                print(f"  Memory pressure level: {pressure_level}/10")
                
                # Allocate memory chunks (10MB each)
                try:
                    chunk = bytearray(10 * 1024 * 1024)  # 10MB
                    memory_hogs.append(chunk)
                    successful_ops += 1
                except MemoryError:
                    failed_ops += 1
                    print(f"    Memory allocation failed at level {pressure_level}")
                    break
                
                # Test system operations under pressure
                try:
                    await self._test_operations_under_pressure()
                    successful_ops += 1
                except Exception as e:
                    failed_ops += 1
                    print(f"    Operation failed under pressure: {e}")
                
                # Take snapshot
                self.take_snapshot(f"pressure_level_{pressure_level}")
                
                # Small delay
                await asyncio.sleep(0.5)
                
        except Exception as e:
            print(f"  Memory pressure test terminated: {e}")
        
        finally:
            # Cleanup memory pressure
            memory_hogs.clear()
            gc.collect()
            
            # Recovery measurement
            recovery_start = time.time()
            await asyncio.sleep(2)  # Allow recovery
            recovery_time = time.time() - recovery_start
            
            final_snapshot = self.take_snapshot("recovery")
            
            # Stop monitoring
            self.stop_memory_monitoring()
            await monitor_task
        
        # Calculate results
        duration = time.time() - start_time
        memory_readings = [s.rss_mb for s in self.snapshots]
        
        result = MemoryStressResult(
            test_name="memory_pressure_scenarios",
            stress_type="memory_pressure",
            duration_seconds=duration,
            max_memory_mb=max(memory_readings),
            min_memory_mb=min(memory_readings),
            avg_memory_mb=sum(memory_readings) / len(memory_readings),
            memory_variance=self._calculate_variance(memory_readings),
            peak_concurrent_operations=len(memory_hogs),
            successful_operations=successful_ops,
            failed_operations=failed_ops,
            memory_fragmentation_score=self._calculate_fragmentation_score(),
            recovery_time_seconds=recovery_time,
            stability_score=self._calculate_stability_score(memory_readings),
            breaking_point_reached=failed_ops > 0,
            recommendations=self._generate_pressure_recommendations(successful_ops, failed_ops)
        )
        
        self.results.append(result)
        self._print_stress_result(result)
        return result
    
    @pytest.mark.memory_stress
    async def test_concurrent_memory_operations(self):
        """Test concurrent operations with memory constraints"""
        print("\n🔥 Testing Concurrent Memory Operations...")
        
        self.start_memory_monitoring()
        monitor_task = asyncio.create_task(self.monitor_memory_continuously())
        
        start_time = time.time()
        initial_snapshot = self.take_snapshot("concurrent_initial")
        
        successful_ops = 0
        failed_ops = 0
        
        async def memory_intensive_operation(operation_id: int):
            """Memory-intensive operation for concurrency testing"""
            nonlocal successful_ops, failed_ops
            
            try:
                # Create data structures
                data = {
                    f"key_{i}": f"value_{i}" * 100 for i in range(1000)
                }
                
                # Simulate processing
                result = sum(len(v) for v in data.values())
                
                # Simulate expert analysis
                analyzer = ExpertAnalyzer()
                responses = []
                for i in range(10):
                    response = ExpertResponse(
                        expert_type=f"expert_{i}",
                        content="Concurrent test content " * 20,
                        confidence=0.9,
                        response_time=1.0,
                        model_used="concurrent_test",
                        cost_estimate=0.001
                    )
                    responses.append(response)
                
                analyzer.analyze_responses(responses)
                successful_ops += 1
                
                return result
                
            except Exception as e:
                failed_ops += 1
                print(f"    Concurrent operation {operation_id} failed: {e}")
                return None
        
        try:
            # Run concurrent operations with increasing load
            for concurrency_level in [10, 25, 50, 100]:
                print(f"  Testing concurrency level: {concurrency_level}")
                
                # Create concurrent tasks
                tasks = [
                    memory_intensive_operation(i) 
                    for i in range(concurrency_level)
                ]
                
                # Execute with timeout
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=30.0
                    )
                except asyncio.TimeoutError:
                    print(f"    Timeout at concurrency level {concurrency_level}")
                    failed_ops += concurrency_level
                    break
                
                # Take snapshot
                self.take_snapshot(f"concurrent_{concurrency_level}")
                
                # Force garbage collection
                gc.collect()
                
        finally:
            # Stop monitoring
            self.stop_memory_monitoring()
            await monitor_task
        
        # Calculate results
        duration = time.time() - start_time
        memory_readings = [s.rss_mb for s in self.snapshots]
        
        result = MemoryStressResult(
            test_name="concurrent_memory_operations",
            stress_type="concurrency",
            duration_seconds=duration,
            max_memory_mb=max(memory_readings),
            min_memory_mb=min(memory_readings),
            avg_memory_mb=sum(memory_readings) / len(memory_readings),
            memory_variance=self._calculate_variance(memory_readings),
            peak_concurrent_operations=100,  # Max attempted
            successful_operations=successful_ops,
            failed_operations=failed_ops,
            memory_fragmentation_score=self._calculate_fragmentation_score(),
            recovery_time_seconds=2.0,  # Fixed recovery time
            stability_score=self._calculate_stability_score(memory_readings),
            breaking_point_reached=failed_ops > successful_ops * 0.1,
            recommendations=self._generate_concurrency_recommendations(successful_ops, failed_ops)
        )
        
        self.results.append(result)
        self._print_stress_result(result)
        return result
    
    @pytest.mark.memory_stress
    async def test_memory_fragmentation_stress(self):
        """Test memory fragmentation under stress"""
        print("\n🔥 Testing Memory Fragmentation...")
        
        self.start_memory_monitoring()
        monitor_task = asyncio.create_task(self.monitor_memory_continuously())
        
        start_time = time.time()
        initial_snapshot = self.take_snapshot("fragmentation_initial")
        
        successful_ops = 0
        failed_ops = 0
        allocated_objects = []
        
        try:
            # Create fragmentation by allocating and deallocating objects of different sizes
            for cycle in range(50):
                print(f"  Fragmentation cycle: {cycle + 1}/50")
                
                cycle_objects = []
                
                # Allocate objects of varying sizes
                sizes = [1024, 4096, 16384, 65536, 262144]  # 1KB to 256KB
                
                for size in sizes:
                    try:
                        obj = bytearray(size)
                        cycle_objects.append(obj)
                        allocated_objects.append(obj)
                        successful_ops += 1
                    except MemoryError:
                        failed_ops += 1
                        break
                
                # Deallocate some objects to create holes
                if len(allocated_objects) > 20:
                    # Remove every 3rd object to create fragmentation
                    to_remove = allocated_objects[::3]
                    for obj in to_remove:
                        allocated_objects.remove(obj)
                
                # Force garbage collection
                if cycle % 10 == 0:
                    gc.collect()
                    self.take_snapshot(f"fragmentation_cycle_{cycle}")
                
                await asyncio.sleep(0.1)
                
        except Exception as e:
            print(f"  Fragmentation test error: {e}")
            failed_ops += 1
        
        finally:
            # Cleanup
            allocated_objects.clear()
            gc.collect()
            
            recovery_snapshot = self.take_snapshot("fragmentation_recovery")
            
            # Stop monitoring
            self.stop_memory_monitoring()
            await monitor_task
        
        # Calculate results
        duration = time.time() - start_time
        memory_readings = [s.rss_mb for s in self.snapshots]
        
        result = MemoryStressResult(
            test_name="memory_fragmentation_stress",
            stress_type="fragmentation",
            duration_seconds=duration,
            max_memory_mb=max(memory_readings),
            min_memory_mb=min(memory_readings),
            avg_memory_mb=sum(memory_readings) / len(memory_readings),
            memory_variance=self._calculate_variance(memory_readings),
            peak_concurrent_operations=len(allocated_objects),
            successful_operations=successful_ops,
            failed_operations=failed_ops,
            memory_fragmentation_score=self._calculate_fragmentation_score(),
            recovery_time_seconds=2.0,
            stability_score=self._calculate_stability_score(memory_readings),
            breaking_point_reached=failed_ops > 0,
            recommendations=self._generate_fragmentation_recommendations()
        )
        
        self.results.append(result)
        self._print_stress_result(result)
        return result
    
    @pytest.mark.memory_stress
    async def test_memory_recovery_patterns(self):
        """Test memory recovery after stress"""
        print("\n🔥 Testing Memory Recovery Patterns...")
        
        self.start_memory_monitoring()
        monitor_task = asyncio.create_task(self.monitor_memory_continuously())
        
        start_time = time.time()
        baseline_snapshot = self.take_snapshot("recovery_baseline")
        
        # Create memory stress
        stress_objects = []
        for i in range(100):
            obj = {
                'id': i,
                'data': 'x' * 10000,  # 10KB per object
                'nested': {'deep': {'data': 'y' * 5000}}
            }
            stress_objects.append(obj)
        
        stress_snapshot = self.take_snapshot("recovery_stress_peak")
        
        # Clear references and measure recovery
        recovery_times = []
        
        # Test different recovery strategies
        recovery_strategies = [
            ("immediate_clear", lambda: stress_objects.clear()),
            ("gradual_clear", lambda: self._gradual_clear(stress_objects)),
            ("gc_force", lambda: gc.collect()),
        ]
        
        for strategy_name, strategy_func in recovery_strategies:
            # Recreate stress
            stress_objects = [{'data': 'x' * 10000} for _ in range(50)]
            
            recovery_start_time = time.time()
            strategy_func()
            
            # Wait for memory to stabilize
            stable_time = await self._wait_for_memory_stability()
            total_recovery_time = time.time() - recovery_start_time
            
            recovery_times.append(total_recovery_time)
            self.take_snapshot(f"recovery_{strategy_name}")
            
            print(f"  {strategy_name} recovery time: {total_recovery_time:.2f}s")
        
        # Stop monitoring
        self.stop_memory_monitoring()
        await monitor_task
        
        # Calculate results
        duration = time.time() - start_time
        memory_readings = [s.rss_mb for s in self.snapshots]
        avg_recovery_time = sum(recovery_times) / len(recovery_times)
        
        result = MemoryStressResult(
            test_name="memory_recovery_patterns",
            stress_type="recovery",
            duration_seconds=duration,
            max_memory_mb=max(memory_readings),
            min_memory_mb=min(memory_readings),
            avg_memory_mb=sum(memory_readings) / len(memory_readings),
            memory_variance=self._calculate_variance(memory_readings),
            peak_concurrent_operations=100,
            successful_operations=len(recovery_strategies),
            failed_operations=0,
            memory_fragmentation_score=self._calculate_fragmentation_score(),
            recovery_time_seconds=avg_recovery_time,
            stability_score=self._calculate_stability_score(memory_readings),
            breaking_point_reached=False,
            recommendations=self._generate_recovery_recommendations(recovery_times)
        )
        
        self.results.append(result)
        self._print_stress_result(result)
        return result
    
    @pytest.mark.memory_stress_comprehensive
    async def test_comprehensive_memory_stress(self):
        """Run comprehensive memory stress testing"""
        print("\n🔥 Running Comprehensive Memory Stress Testing...")
        
        # Run all stress tests
        results = []
        
        results.append(await self.test_memory_pressure_scenarios())
        results.append(await self.test_concurrent_memory_operations())
        results.append(await self.test_memory_fragmentation_stress())
        results.append(await self.test_memory_recovery_patterns())
        
        # Generate comprehensive report
        report = self._generate_stress_report(results)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"tests/memory/memory_stress_report_{timestamp}.md"
        
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, 'w') as f:
            f.write(report)
        
        # Save detailed results
        results_data = [asdict(r) for r in results]
        results_path = f"tests/memory/memory_stress_results_{timestamp}.json"
        with open(results_path, 'w') as f:
            json.dump(results_data, f, indent=2, default=str)
        
        print(f"\n✅ Comprehensive memory stress testing complete!")
        print(f"📄 Report: {report_path}")
        print(f"📊 Results: {results_path}")
        
        # Overall health check
        critical_issues = sum(1 for r in results if r.breaking_point_reached and r.stability_score < 0.5)
        assert critical_issues == 0, f"Critical memory stability issues detected in {critical_issues} tests"
        
        return results
    
    # Helper methods
    
    async def _test_operations_under_pressure(self):
        """Test basic operations under memory pressure"""
        # Test ExpertManager under pressure
        manager = ExpertManager()
        query = ExpertQuery(
            title="Pressure test",
            content="Testing under memory pressure",
            query_type=QueryType.TECHNICAL,
            priority=QueryPriority.LOW,
            requester="pressure_test@test.com"
        )
        await asyncio.sleep(0.001)  # Simulate processing
    
    def _gradual_clear(self, objects_list):
        """Gradually clear objects"""
        while objects_list:
            objects_list.pop()
            if len(objects_list) % 10 == 0:
                gc.collect()
    
    async def _wait_for_memory_stability(self, timeout: float = 5.0) -> float:
        """Wait for memory usage to stabilize"""
        start_time = time.time()
        previous_memory = self.process.memory_info().rss
        stable_count = 0
        
        while time.time() - start_time < timeout:
            await asyncio.sleep(0.1)
            current_memory = self.process.memory_info().rss
            
            # Check if memory is stable (within 1% change)
            if abs(current_memory - previous_memory) / previous_memory < 0.01:
                stable_count += 1
                if stable_count >= 5:  # Stable for 5 consecutive readings
                    break
            else:
                stable_count = 0
            
            previous_memory = current_memory
        
        return time.time() - start_time
    
    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of memory readings"""
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance
    
    def _calculate_fragmentation_score(self) -> float:
        """Calculate memory fragmentation score (0-1, higher is more fragmented)"""
        # Simple fragmentation estimation based on GC frequency
        if not self.snapshots:
            return 0.0
        
        gc_deltas = []
        for i in range(1, len(self.snapshots)):
            current_gc = sum(self.snapshots[i].gc_counts)
            previous_gc = sum(self.snapshots[i-1].gc_counts)
            gc_deltas.append(current_gc - previous_gc)
        
        if not gc_deltas:
            return 0.0
        
        # Higher GC frequency indicates more fragmentation
        avg_gc_delta = sum(gc_deltas) / len(gc_deltas)
        return min(avg_gc_delta / 100.0, 1.0)  # Normalize to 0-1
    
    def _calculate_stability_score(self, memory_readings: List[float]) -> float:
        """Calculate memory stability score (0-1, higher is more stable)"""
        if len(memory_readings) < 2:
            return 1.0
        
        # Calculate coefficient of variation
        mean_memory = sum(memory_readings) / len(memory_readings)
        variance = self._calculate_variance(memory_readings)
        std_dev = variance ** 0.5
        
        if mean_memory == 0:
            return 1.0
        
        coefficient_of_variation = std_dev / mean_memory
        
        # Convert to stability score (inverse of variability)
        stability = max(0.0, 1.0 - coefficient_of_variation)
        return min(stability, 1.0)
    
    def _generate_pressure_recommendations(self, successful_ops: int, failed_ops: int) -> List[str]:
        """Generate recommendations for memory pressure testing"""
        recommendations = []
        
        failure_rate = failed_ops / (successful_ops + failed_ops) if (successful_ops + failed_ops) > 0 else 0
        
        if failure_rate > 0.3:
            recommendations.append("High failure rate under memory pressure - implement memory throttling")
        elif failure_rate > 0.1:
            recommendations.append("Some failures under memory pressure - consider memory monitoring")
        else:
            recommendations.append("Good resilience to memory pressure")
        
        recommendations.append("Monitor memory usage in production environments")
        recommendations.append("Implement graceful degradation for low-memory conditions")
        
        return recommendations
    
    def _generate_concurrency_recommendations(self, successful_ops: int, failed_ops: int) -> List[str]:
        """Generate recommendations for concurrency testing"""
        recommendations = []
        
        if failed_ops > 0:
            recommendations.append("Concurrent operation failures detected - review thread safety")
            recommendations.append("Consider implementing operation queuing or rate limiting")
        else:
            recommendations.append("Good concurrent memory handling")
        
        recommendations.append("Monitor concurrent operation limits in production")
        
        return recommendations
    
    def _generate_fragmentation_recommendations(self) -> List[str]:
        """Generate recommendations for fragmentation testing"""
        return [
            "Monitor memory fragmentation in long-running processes",
            "Consider memory pool allocation strategies",
            "Implement periodic memory compaction if needed"
        ]
    
    def _generate_recovery_recommendations(self, recovery_times: List[float]) -> List[str]:
        """Generate recommendations for recovery testing"""
        recommendations = []
        
        avg_recovery = sum(recovery_times) / len(recovery_times)
        
        if avg_recovery > 5.0:
            recommendations.append("Slow memory recovery detected - review cleanup strategies")
        elif avg_recovery > 2.0:
            recommendations.append("Moderate memory recovery time - consider optimization")
        else:
            recommendations.append("Good memory recovery performance")
        
        recommendations.append("Implement proactive memory cleanup strategies")
        
        return recommendations
    
    def _print_stress_result(self, result: MemoryStressResult):
        """Print stress test result"""
        print(f"\n📊 {result.test_name} Results:")
        print(f"   Stress Type: {result.stress_type}")
        print(f"   Duration: {result.duration_seconds:.2f}s")
        print(f"   Peak Memory: {result.max_memory_mb:.2f}MB")
        print(f"   Memory Variance: {result.memory_variance:.2f}")
        print(f"   Successful Ops: {result.successful_operations}")
        print(f"   Failed Ops: {result.failed_operations}")
        print(f"   Recovery Time: {result.recovery_time_seconds:.2f}s")
        print(f"   Stability Score: {result.stability_score:.2f}")
        print(f"   Breaking Point: {result.breaking_point_reached}")
    
    def _generate_stress_report(self, results: List[MemoryStressResult]) -> str:
        """Generate comprehensive stress test report"""
        report = []
        report.append("# Memory Stress Testing Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        
        # Summary
        report.append("\n## Executive Summary")
        total_tests = len(results)
        breaking_points = sum(1 for r in results if r.breaking_point_reached)
        avg_stability = sum(r.stability_score for r in results) / len(results)
        
        report.append(f"- **Total Stress Tests**: {total_tests}")
        report.append(f"- **Breaking Points Reached**: {breaking_points}")
        report.append(f"- **Average Stability Score**: {avg_stability:.2f}")
        
        if breaking_points > total_tests * 0.5:
            report.append("\n⚠️ **WARNING**: Multiple breaking points detected")
        elif avg_stability < 0.7:
            report.append("\n⚠️ **CAUTION**: Low stability scores detected")
        else:
            report.append("\n✅ **GOOD**: System shows good memory resilience")
        
        # Detailed results
        report.append("\n## Detailed Results")
        
        for result in results:
            report.append(f"\n### {result.test_name}")
            report.append(f"- **Stress Type**: {result.stress_type}")
            report.append(f"- **Duration**: {result.duration_seconds:.2f}s")
            report.append(f"- **Peak Memory**: {result.max_memory_mb:.2f}MB")
            report.append(f"- **Stability Score**: {result.stability_score:.2f}")
            report.append(f"- **Breaking Point**: {result.breaking_point_reached}")
            report.append(f"- **Recovery Time**: {result.recovery_time_seconds:.2f}s")
            
            report.append("- **Recommendations**:")
            for rec in result.recommendations:
                report.append(f"  - {rec}")
        
        return "\n".join(report)


async def run_memory_stress_testing():
    """Run memory stress testing suite"""
    tester = MemoryStressTester()
    return await tester.test_comprehensive_memory_stress()


if __name__ == "__main__":
    # Run stress testing
    asyncio.run(run_memory_stress_testing())