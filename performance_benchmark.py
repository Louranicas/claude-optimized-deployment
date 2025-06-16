#!/usr/bin/env python3
"""
Simplified Performance Benchmark for CODE Project
===============================================

Focus on measuring:
1. SYNTHEX search operations
2. MCP message throughput
3. Memory allocation patterns
4. Concurrent operation performance
"""

import asyncio
import json
import time
import psutil
import gc
import sys
import os
import tracemalloc
import statistics
from typing import Dict, List, Any
from dataclasses import dataclass
from pathlib import Path

# Add project root to path
sys.path.insert(0, '/home/louranicas/projects/claude-optimized-deployment')

@dataclass
class BenchmarkResult:
    """Container for benchmark results"""
    test_name: str
    duration: float
    throughput: float
    memory_used_mb: float
    peak_memory_mb: float
    operations: int
    errors: int
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float

class PerformanceBenchmark:
    """Performance benchmarking for CODE project"""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.start_time = time.time()
        
    def measure_operation(self, name: str, operations: int):
        """Measure performance of an operation"""
        print(f"\n🔄 Benchmarking: {name}")
        
        # Start monitoring
        tracemalloc.start()
        gc.collect()
        start_time = time.perf_counter()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        latencies = []
        errors = 0
        
        # Run the benchmark based on operation type
        if "synthex_search" in name:
            latencies, errors = self._benchmark_synthex_search(operations)
        elif "mcp_message" in name:
            latencies, errors = self._benchmark_mcp_messages(operations)
        elif "memory_allocation" in name:
            latencies, errors = self._benchmark_memory_allocation(operations)
        elif "concurrent" in name:
            latencies, errors = self._benchmark_concurrent_operations(operations)
        else:
            latencies = [0.001] * operations  # Default mock data
        
        # Calculate metrics
        end_time = time.perf_counter()
        end_memory = psutil.Process().memory_info().rss / 1024 / 1024
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        duration = end_time - start_time
        throughput = operations / duration if duration > 0 else 0
        
        # Calculate latency percentiles
        if latencies:
            latencies_ms = [l * 1000 for l in latencies]
            avg_latency = statistics.mean(latencies_ms)
            p95_latency = sorted(latencies_ms)[int(len(latencies_ms) * 0.95)]
            p99_latency = sorted(latencies_ms)[int(len(latencies_ms) * 0.99)]
        else:
            avg_latency = p95_latency = p99_latency = 0
        
        result = BenchmarkResult(
            test_name=name,
            duration=duration,
            throughput=throughput,
            memory_used_mb=end_memory - start_memory,
            peak_memory_mb=peak_mem / 1024 / 1024,
            operations=operations,
            errors=errors,
            avg_latency_ms=avg_latency,
            p95_latency_ms=p95_latency,
            p99_latency_ms=p99_latency
        )
        
        self.results.append(result)
        print(f"✅ {name}: {throughput:.1f} ops/s, {avg_latency:.2f}ms avg latency")
        
        return result
    
    def _benchmark_synthex_search(self, operations: int) -> tuple:
        """Benchmark SYNTHEX search operations"""
        latencies = []
        errors = 0
        
        # Simulate SYNTHEX search patterns
        search_queries = [
            {"query": "infrastructure", "filters": ["type:server", "status:active"]},
            {"query": "deployment", "filters": ["env:production"]},
            {"query": "security", "filters": ["severity:high", "type:vulnerability"]},
            {"query": "performance", "filters": ["metric:cpu", "threshold:>80"]},
            {"query": "config", "filters": ["service:api", "version:latest"]}
        ]
        
        for i in range(operations):
            query = search_queries[i % len(search_queries)]
            start = time.perf_counter()
            
            try:
                # Simulate search operation with varying complexity
                search_complexity = len(query["filters"]) * 0.001
                time.sleep(0.001 + search_complexity)  # Simulate search time
                
                # Simulate data processing
                results = [{"id": j, "score": 0.9 - j*0.01} for j in range(10)]
                sorted_results = sorted(results, key=lambda x: x["score"], reverse=True)
                
                latencies.append(time.perf_counter() - start)
            except Exception:
                errors += 1
                
        return latencies, errors
    
    def _benchmark_mcp_messages(self, operations: int) -> tuple:
        """Benchmark MCP message throughput"""
        latencies = []
        errors = 0
        
        # Simulate different MCP message types
        message_types = [
            {"type": "tool_call", "size": 1024},
            {"type": "response", "size": 2048},
            {"type": "event", "size": 512},
            {"type": "stream", "size": 4096},
            {"type": "error", "size": 256}
        ]
        
        for i in range(operations):
            msg = message_types[i % len(message_types)]
            start = time.perf_counter()
            
            try:
                # Simulate message serialization
                message = {"type": msg["type"], "data": "x" * msg["size"]}
                serialized = json.dumps(message)
                
                # Simulate network latency
                time.sleep(0.0005)
                
                # Simulate deserialization
                json.loads(serialized)
                
                latencies.append(time.perf_counter() - start)
            except Exception:
                errors += 1
                
        return latencies, errors
    
    def _benchmark_memory_allocation(self, operations: int) -> tuple:
        """Benchmark memory allocation patterns"""
        latencies = []
        errors = 0
        
        for i in range(operations):
            start = time.perf_counter()
            
            try:
                # Simulate different allocation patterns
                if i % 3 == 0:
                    # Small allocations
                    data = [list(range(100)) for _ in range(10)]
                elif i % 3 == 1:
                    # Medium allocations
                    data = [list(range(1000)) for _ in range(50)]
                else:
                    # Large allocations
                    data = {"items": [{"id": j, "data": list(range(100))} for j in range(100)]}
                
                # Force garbage collection periodically
                if i % 100 == 0:
                    gc.collect()
                    
                del data
                latencies.append(time.perf_counter() - start)
            except Exception:
                errors += 1
                
        return latencies, errors
    
    def _benchmark_concurrent_operations(self, operations: int) -> tuple:
        """Benchmark concurrent operations"""
        latencies = []
        errors = 0
        
        async def concurrent_task(task_id: int):
            """Simulate concurrent task"""
            await asyncio.sleep(0.001 * (1 + task_id % 3))
            return task_id * 2
        
        async def run_concurrent_batch(batch_size: int):
            """Run a batch of concurrent tasks"""
            tasks = [concurrent_task(i) for i in range(batch_size)]
            start = time.perf_counter()
            
            try:
                results = await asyncio.gather(*tasks)
                return time.perf_counter() - start, 0
            except Exception:
                return time.perf_counter() - start, 1
        
        # Run batches of concurrent operations
        batch_size = 10
        num_batches = operations // batch_size
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        for _ in range(num_batches):
            latency, error = loop.run_until_complete(run_concurrent_batch(batch_size))
            latencies.append(latency)
            errors += error
            
        loop.close()
        
        return latencies, errors
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        if not self.results:
            return {"error": "No benchmark results available"}
        
        # Calculate aggregate metrics
        total_operations = sum(r.operations for r in self.results)
        total_errors = sum(r.errors for r in self.results)
        avg_throughput = statistics.mean(r.throughput for r in self.results)
        total_duration = sum(r.duration for r in self.results)
        
        # Find best and worst performers
        best_throughput = max(self.results, key=lambda x: x.throughput)
        worst_latency = max(self.results, key=lambda x: x.p99_latency_ms)
        highest_memory = max(self.results, key=lambda x: x.peak_memory_mb)
        
        report = {
            "summary": {
                "total_operations": total_operations,
                "total_errors": total_errors,
                "error_rate": (total_errors / total_operations * 100) if total_operations > 0 else 0,
                "average_throughput": avg_throughput,
                "total_duration": total_duration,
                "tests_run": len(self.results)
            },
            "highlights": {
                "best_throughput": {
                    "test": best_throughput.test_name,
                    "value": best_throughput.throughput
                },
                "highest_latency": {
                    "test": worst_latency.test_name,
                    "p99_ms": worst_latency.p99_latency_ms
                },
                "highest_memory": {
                    "test": highest_memory.test_name,
                    "peak_mb": highest_memory.peak_memory_mb
                }
            },
            "detailed_results": [
                {
                    "test_name": r.test_name,
                    "throughput_ops_per_sec": r.throughput,
                    "latency_ms": {
                        "average": r.avg_latency_ms,
                        "p95": r.p95_latency_ms,
                        "p99": r.p99_latency_ms
                    },
                    "memory_mb": {
                        "used": r.memory_used_mb,
                        "peak": r.peak_memory_mb
                    },
                    "errors": r.errors,
                    "duration_sec": r.duration
                }
                for r in self.results
            ],
            "bottlenecks": self._identify_bottlenecks(),
            "optimization_opportunities": self._identify_optimizations()
        }
        
        return report
    
    def _identify_bottlenecks(self) -> List[Dict[str, Any]]:
        """Identify performance bottlenecks"""
        bottlenecks = []
        
        for result in self.results:
            issues = []
            
            # Check for high latency
            if result.p99_latency_ms > 100:
                issues.append({
                    "type": "high_latency",
                    "severity": "high" if result.p99_latency_ms > 200 else "medium",
                    "value": result.p99_latency_ms,
                    "threshold": 100
                })
            
            # Check for low throughput
            if result.throughput < 100:
                issues.append({
                    "type": "low_throughput", 
                    "severity": "high" if result.throughput < 50 else "medium",
                    "value": result.throughput,
                    "threshold": 100
                })
            
            # Check for high memory usage
            if result.peak_memory_mb > 100:
                issues.append({
                    "type": "high_memory",
                    "severity": "high" if result.peak_memory_mb > 200 else "medium",
                    "value": result.peak_memory_mb,
                    "threshold": 100
                })
            
            if issues:
                bottlenecks.append({
                    "test": result.test_name,
                    "issues": issues
                })
        
        return bottlenecks
    
    def _identify_optimizations(self) -> List[str]:
        """Identify optimization opportunities"""
        optimizations = []
        
        # Analyze results for patterns
        avg_latency = statistics.mean(r.avg_latency_ms for r in self.results)
        avg_memory = statistics.mean(r.peak_memory_mb for r in self.results)
        
        if avg_latency > 50:
            optimizations.append("Consider implementing caching to reduce average latency")
        
        if avg_memory > 50:
            optimizations.append("Implement object pooling to reduce memory allocations")
        
        # Check for specific test patterns
        synthex_results = [r for r in self.results if "synthex" in r.test_name]
        if synthex_results and synthex_results[0].throughput < 200:
            optimizations.append("Optimize SYNTHEX search with indexed data structures")
        
        mcp_results = [r for r in self.results if "mcp" in r.test_name]
        if mcp_results and mcp_results[0].avg_latency_ms > 10:
            optimizations.append("Use message batching to improve MCP throughput")
        
        concurrent_results = [r for r in self.results if "concurrent" in r.test_name]
        if concurrent_results and concurrent_results[0].throughput < 500:
            optimizations.append("Increase concurrency limit or use connection pooling")
        
        # General optimizations
        optimizations.extend([
            "Implement Rust acceleration for CPU-intensive operations",
            "Use memory-mapped files for large data processing",
            "Enable HTTP/2 for improved network performance",
            "Implement circuit breakers to prevent cascade failures",
            "Add distributed caching with Redis for frequent queries"
        ])
        
        return optimizations

def main():
    """Run performance benchmarks"""
    print("🚀 CODE Performance Benchmark Suite")
    print("=" * 50)
    
    benchmark = PerformanceBenchmark()
    
    # Run benchmarks
    benchmark.measure_operation("synthex_search_small", 1000)
    benchmark.measure_operation("synthex_search_large", 500)
    benchmark.measure_operation("mcp_message_throughput", 2000)
    benchmark.measure_operation("memory_allocation_patterns", 1000)
    benchmark.measure_operation("concurrent_operations", 500)
    
    # Generate report
    report = benchmark.generate_report()
    
    # Save report
    output_path = Path("/home/louranicas/projects/claude-optimized-deployment/performance_report.json")
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 50)
    print("📊 Performance Benchmark Summary")
    print("=" * 50)
    print(f"Total Operations: {report['summary']['total_operations']:,}")
    print(f"Average Throughput: {report['summary']['average_throughput']:.1f} ops/s")
    print(f"Error Rate: {report['summary']['error_rate']:.2f}%")
    print(f"\n🏆 Best Performer: {report['highlights']['best_throughput']['test']}")
    print(f"   Throughput: {report['highlights']['best_throughput']['value']:.1f} ops/s")
    print(f"\n⚠️  Highest Latency: {report['highlights']['highest_latency']['test']}")
    print(f"   P99 Latency: {report['highlights']['highest_latency']['p99_ms']:.2f} ms")
    
    # Print bottlenecks
    if report['bottlenecks']:
        print("\n🚨 Performance Bottlenecks Detected:")
        for bottleneck in report['bottlenecks']:
            print(f"\n   {bottleneck['test']}:")
            for issue in bottleneck['issues']:
                print(f"   - {issue['type']}: {issue['value']:.2f} (threshold: {issue['threshold']})")
    
    # Print optimization opportunities
    print("\n💡 Optimization Opportunities:")
    for i, opt in enumerate(report['optimization_opportunities'][:5], 1):
        print(f"   {i}. {opt}")
    
    print(f"\n✅ Full report saved to: {output_path}")
    
    return report

if __name__ == "__main__":
    report = main()