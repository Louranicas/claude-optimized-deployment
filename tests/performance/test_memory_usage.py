"""
Memory Usage Profiling Tests
Agent 8C: Comprehensive memory profiling and leak detection
"""

import pytest
import asyncio
import gc
import tracemalloc
import psutil
import time
from memory_profiler import profile, memory_usage
from typing import List, Dict, Any, Tuple
import sys
import os
import json
from datetime import datetime
from dataclasses import dataclass, asdict

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
class MemorySnapshot:
    """Memory usage snapshot"""
    timestamp: float
    rss_mb: float  # Resident Set Size
    vms_mb: float  # Virtual Memory Size
    available_mb: float
    percent_used: float
    python_allocated_mb: float
    python_peak_mb: float
    description: str


@dataclass
class MemoryTestResult:
    """Results from memory testing"""
    test_name: str
    initial_memory_mb: float
    peak_memory_mb: float
    final_memory_mb: float
    memory_leaked_mb: float
    gc_collections: Dict[int, int]
    snapshots: List[MemorySnapshot]
    duration_seconds: float


class MemoryUsageProfiler:
    """Memory usage profiling for the system"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.snapshots: List[MemorySnapshot] = []
        self.results: List[MemoryTestResult] = []
        
    def take_snapshot(self, description: str) -> MemorySnapshot:
        """Take a memory usage snapshot"""
        mem_info = self.process.memory_info()
        virtual_mem = psutil.virtual_memory()
        
        current, peak = 0, 0
        if tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()
            current = current / 1024 / 1024  # Convert to MB
            peak = peak / 1024 / 1024
        
        snapshot = MemorySnapshot(
            timestamp=time.time(),
            rss_mb=mem_info.rss / 1024 / 1024,
            vms_mb=mem_info.vms / 1024 / 1024,
            available_mb=virtual_mem.available / 1024 / 1024,
            percent_used=virtual_mem.percent,
            python_allocated_mb=current,
            python_peak_mb=peak,
            description=description
        )
        
        self.snapshots.append(snapshot)
        return snapshot
    
    def get_gc_stats(self) -> Dict[int, int]:
        """Get garbage collection statistics"""
        return {
            0: gc.get_count()[0],
            1: gc.get_count()[1],
            2: gc.get_count()[2]
        }
    
    @pytest.mark.memory
    async def test_expert_manager_memory(self):
        """Test ExpertManager memory usage"""
        print("\n💾 Testing ExpertManager memory usage...")
        
        # Start memory tracking
        tracemalloc.start()
        gc.collect()
        
        initial_snapshot = self.take_snapshot("Initial")
        initial_gc = self.get_gc_stats()
        start_time = time.time()
        
        # Create and use ExpertManager
        manager = ExpertManager()
        
        # Simulate multiple queries
        queries = []
        for i in range(100):
            query = ExpertQuery(
                title=f"Memory Test Query {i}",
                content=f"Test content for memory profiling iteration {i}",
                query_type=QueryType.TECHNICAL,
                priority=QueryPriority.MEDIUM,
                requester=f"memory_test_{i}@test.com"
            )
            queries.append(query)
        
        self.take_snapshot("After creating 100 queries")
        
        # Process queries (simulated)
        for i, query in enumerate(queries):
            # Simulate processing without actual API calls
            await asyncio.sleep(0.01)
            
            if i % 20 == 0:
                self.take_snapshot(f"After processing {i} queries")
        
        peak_snapshot = self.take_snapshot("Peak usage")
        
        # Cleanup
        del queries
        del manager
        gc.collect()
        
        final_snapshot = self.take_snapshot("After cleanup")
        final_gc = self.get_gc_stats()
        duration = time.time() - start_time
        
        # Stop tracking
        tracemalloc.stop()
        
        # Calculate results
        result = MemoryTestResult(
            test_name="expert_manager_memory",
            initial_memory_mb=initial_snapshot.rss_mb,
            peak_memory_mb=peak_snapshot.rss_mb,
            final_memory_mb=final_snapshot.rss_mb,
            memory_leaked_mb=final_snapshot.rss_mb - initial_snapshot.rss_mb,
            gc_collections={
                0: final_gc[0] - initial_gc[0],
                1: final_gc[1] - initial_gc[1],
                2: final_gc[2] - initial_gc[2]
            },
            snapshots=self.snapshots[-10:],  # Keep last 10 snapshots
            duration_seconds=duration
        )
        
        self.results.append(result)
        self._print_result(result)
    
    @pytest.mark.memory
    async def test_mcp_manager_memory(self):
        """Test MCP Manager memory usage"""
        print("\n💾 Testing MCP Manager memory usage...")
        
        # Start memory tracking
        tracemalloc.start()
        gc.collect()
        
        initial_snapshot = self.take_snapshot("Initial")
        start_time = time.time()
        
        # Initialize MCP Manager
        manager = get_mcp_manager()
        await manager.initialize()
        
        self.take_snapshot("After MCP initialization")
        
        # Execute many tool calls
        tool_calls = [
            ("desktop.execute_command", {"command": "echo 'Memory test'"}),
            ("docker.docker_ps", {}),
            ("desktop.read_file", {"file_path": "README.md", "lines": 10})
        ]
        
        for i in range(300):
            tool_name, params = tool_calls[i % len(tool_calls)]
            try:
                await manager.call_tool(tool_name, params)
            except:
                pass  # Ignore errors for memory testing
            
            if i % 50 == 0:
                self.take_snapshot(f"After {i} tool calls")
        
        peak_snapshot = self.take_snapshot("Peak MCP usage")
        
        # Cleanup
        del manager
        gc.collect()
        
        final_snapshot = self.take_snapshot("After MCP cleanup")
        duration = time.time() - start_time
        
        # Stop tracking
        tracemalloc.stop()
        
        # Calculate results
        result = MemoryTestResult(
            test_name="mcp_manager_memory",
            initial_memory_mb=initial_snapshot.rss_mb,
            peak_memory_mb=peak_snapshot.rss_mb,
            final_memory_mb=final_snapshot.rss_mb,
            memory_leaked_mb=final_snapshot.rss_mb - initial_snapshot.rss_mb,
            gc_collections=self.get_gc_stats(),
            snapshots=self.snapshots[-10:],
            duration_seconds=duration
        )
        
        self.results.append(result)
        self._print_result(result)
    
    @pytest.mark.memory
    async def test_rust_modules_memory(self):
        """Test Rust modules memory efficiency"""
        print("\n💾 Testing Rust modules memory usage...")
        
        # Start memory tracking
        tracemalloc.start()
        gc.collect()
        
        initial_snapshot = self.take_snapshot("Initial")
        start_time = time.time()
        
        # Create large dataset
        large_responses = []
        for i in range(1000):
            response = ExpertResponse(
                expert_type=f"expert_{i % 10}",
                content="x" * 1000,  # 1KB per response
                confidence=0.85,
                response_time=1.5,
                model_used="test_model",
                cost_estimate=0.001,
                metadata={"index": i}
            )
            large_responses.append(response)
        
        self.take_snapshot("After creating 1000 responses (1MB data)")
        
        # Test Rust modules
        analyzer = ExpertAnalyzer()
        consensus = ConsensusEngine()
        aggregator = ResponseAggregator()
        
        # Process with Rust modules
        for i in range(10):
            analyzer.analyze_responses(large_responses[:100])
            consensus.calculate_consensus(large_responses[:50])
            aggregator.aggregate_responses(large_responses[:200])
            
            if i % 2 == 0:
                self.take_snapshot(f"After Rust processing iteration {i}")
        
        peak_snapshot = self.take_snapshot("Peak Rust usage")
        
        # Cleanup
        del large_responses
        del analyzer
        del consensus
        del aggregator
        gc.collect()
        
        final_snapshot = self.take_snapshot("After Rust cleanup")
        duration = time.time() - start_time
        
        # Stop tracking
        tracemalloc.stop()
        
        # Calculate results
        result = MemoryTestResult(
            test_name="rust_modules_memory",
            initial_memory_mb=initial_snapshot.rss_mb,
            peak_memory_mb=peak_snapshot.rss_mb,
            final_memory_mb=final_snapshot.rss_mb,
            memory_leaked_mb=final_snapshot.rss_mb - initial_snapshot.rss_mb,
            gc_collections=self.get_gc_stats(),
            snapshots=self.snapshots[-10:],
            duration_seconds=duration
        )
        
        self.results.append(result)
        self._print_result(result)
    
    @pytest.mark.memory
    async def test_memory_leak_detection(self):
        """Test for memory leaks in repeated operations"""
        print("\n💾 Testing for memory leaks...")
        
        # Start memory tracking
        tracemalloc.start()
        gc.collect()
        
        initial_snapshot = self.take_snapshot("Initial")
        memory_readings = []
        
        # Perform repeated operations
        for iteration in range(10):
            print(f"  Iteration {iteration + 1}/10...")
            
            # Create and destroy objects repeatedly
            queries = []
            for i in range(50):
                query = ExpertQuery(
                    title=f"Leak test {iteration}-{i}",
                    content="Memory leak detection content",
                    query_type=QueryType.TECHNICAL,
                    priority=QueryPriority.LOW,
                    requester="leak_test@test.com"
                )
                queries.append(query)
            
            # Simulate processing
            await asyncio.sleep(0.1)
            
            # Clear references
            del queries
            gc.collect()
            
            # Take memory reading
            snapshot = self.take_snapshot(f"After iteration {iteration}")
            memory_readings.append(snapshot.rss_mb)
        
        # Analyze trend
        memory_increase = memory_readings[-1] - memory_readings[0]
        avg_increase_per_iteration = memory_increase / len(memory_readings)
        
        # Stop tracking
        tracemalloc.stop()
        
        print(f"\n  Memory trend analysis:")
        print(f"    Initial: {memory_readings[0]:.2f} MB")
        print(f"    Final: {memory_readings[-1]:.2f} MB")
        print(f"    Total increase: {memory_increase:.2f} MB")
        print(f"    Avg per iteration: {avg_increase_per_iteration:.2f} MB")
        
        # Flag potential leak if consistent increase
        if avg_increase_per_iteration > 0.5:  # More than 0.5MB per iteration
            print("  ⚠️ Potential memory leak detected!")
        else:
            print("  ✅ No significant memory leak detected")
    
    @pytest.mark.memory
    @profile
    async def test_detailed_memory_profile(self):
        """Detailed memory profiling with line-by-line analysis"""
        print("\n💾 Running detailed memory profile...")
        
        # This function will be profiled line-by-line
        responses = []
        
        # Create responses (memory allocation)
        for i in range(500):
            response = ExpertResponse(
                expert_type=f"expert_{i}",
                content="Test content " * 50,
                confidence=0.9,
                response_time=1.0,
                model_used="test",
                cost_estimate=0.001
            )
            responses.append(response)
        
        # Process with Rust modules
        analyzer = ExpertAnalyzer()
        result = analyzer.analyze_responses(responses)
        
        # Aggregate results
        aggregator = ResponseAggregator()
        aggregated = aggregator.aggregate_responses(responses)
        
        # Cleanup
        del responses
        del analyzer
        del aggregator
        
        return result, aggregated
    
    @pytest.mark.memory
    async def test_concurrent_memory_usage(self):
        """Test memory usage under concurrent load"""
        print("\n💾 Testing concurrent memory usage...")
        
        # Start memory tracking
        tracemalloc.start()
        gc.collect()
        
        initial_snapshot = self.take_snapshot("Initial")
        
        async def memory_intensive_task(task_id: int):
            """Simulate memory-intensive operation"""
            data = []
            for i in range(100):
                data.append({
                    "task_id": task_id,
                    "iteration": i,
                    "data": "x" * 1000  # 1KB per item
                })
            
            # Simulate processing
            await asyncio.sleep(0.1)
            
            # Process data
            result = sum(len(item["data"]) for item in data)
            
            return result
        
        # Run concurrent tasks
        tasks = []
        for i in range(50):
            tasks.append(memory_intensive_task(i))
        
        self.take_snapshot("Before concurrent execution")
        
        # Execute concurrently
        results = await asyncio.gather(*tasks)
        
        peak_snapshot = self.take_snapshot("Peak concurrent usage")
        
        # Cleanup
        del tasks
        del results
        gc.collect()
        
        final_snapshot = self.take_snapshot("After concurrent cleanup")
        
        # Stop tracking
        tracemalloc.stop()
        
        # Calculate results
        result = MemoryTestResult(
            test_name="concurrent_memory_usage",
            initial_memory_mb=initial_snapshot.rss_mb,
            peak_memory_mb=peak_snapshot.rss_mb,
            final_memory_mb=final_snapshot.rss_mb,
            memory_leaked_mb=final_snapshot.rss_mb - initial_snapshot.rss_mb,
            gc_collections=self.get_gc_stats(),
            snapshots=self.snapshots[-10:],
            duration_seconds=0
        )
        
        self.results.append(result)
        self._print_result(result)
    
    def _print_result(self, result: MemoryTestResult):
        """Print memory test result"""
        print(f"\n📊 {result.test_name} Results:")
        print(f"  Initial Memory: {result.initial_memory_mb:.2f} MB")
        print(f"  Peak Memory: {result.peak_memory_mb:.2f} MB")
        print(f"  Final Memory: {result.final_memory_mb:.2f} MB")
        print(f"  Memory Leaked: {result.memory_leaked_mb:.2f} MB")
        print(f"  Duration: {result.duration_seconds:.2f}s")
        print(f"  GC Collections: Gen0={result.gc_collections.get(0, 0)}, "
              f"Gen1={result.gc_collections.get(1, 0)}, "
              f"Gen2={result.gc_collections.get(2, 0)}")
    
    def generate_report(self) -> str:
        """Generate memory profiling report"""
        report = []
        report.append("# Memory Profiling Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("\n## Summary")
        
        if self.results:
            total_leaked = sum(r.memory_leaked_mb for r in self.results)
            avg_peak = sum(r.peak_memory_mb for r in self.results) / len(self.results)
            
            report.append(f"- Total Tests: {len(self.results)}")
            report.append(f"- Total Memory Leaked: {total_leaked:.2f} MB")
            report.append(f"- Average Peak Memory: {avg_peak:.2f} MB")
        
        report.append("\n## Test Results")
        
        for result in self.results:
            report.append(f"\n### {result.test_name}")
            report.append(f"- **Memory Usage**:")
            report.append(f"  - Initial: {result.initial_memory_mb:.2f} MB")
            report.append(f"  - Peak: {result.peak_memory_mb:.2f} MB")
            report.append(f"  - Final: {result.final_memory_mb:.2f} MB")
            report.append(f"  - Leaked: {result.memory_leaked_mb:.2f} MB")
            report.append(f"- **Performance**:")
            report.append(f"  - Duration: {result.duration_seconds:.2f}s")
            report.append(f"- **Garbage Collection**:")
            report.append(f"  - Generation 0: {result.gc_collections.get(0, 0)} collections")
            report.append(f"  - Generation 1: {result.gc_collections.get(1, 0)} collections")
            report.append(f"  - Generation 2: {result.gc_collections.get(2, 0)} collections")
        
        report.append("\n## Memory Usage Timeline")
        
        if self.snapshots:
            report.append("\n| Timestamp | Description | RSS (MB) | Python (MB) | % Used |")
            report.append("|-----------|-------------|----------|-------------|---------|")
            
            for snapshot in self.snapshots[-20:]:  # Last 20 snapshots
                report.append(f"| {snapshot.timestamp:.2f} | {snapshot.description[:30]} | "
                            f"{snapshot.rss_mb:.2f} | {snapshot.python_allocated_mb:.2f} | "
                            f"{snapshot.percent_used:.1f}% |")
        
        report.append("\n## Recommendations")
        
        # Analyze results and provide recommendations
        if any(r.memory_leaked_mb > 10 for r in self.results):
            report.append("- ⚠️ **Memory Leak**: Significant memory leaks detected. "
                         "Review object lifecycle and ensure proper cleanup.")
        
        if any(r.peak_memory_mb > 500 for r in self.results):
            report.append("- ⚠️ **High Memory Usage**: Peak memory usage exceeds 500MB. "
                         "Consider optimizing data structures or processing in smaller batches.")
        
        rust_test = next((r for r in self.results if "rust" in r.test_name), None)
        if rust_test and rust_test.memory_leaked_mb < 5:
            report.append("- ✅ **Rust Efficiency**: Rust modules show excellent memory management.")
        
        return "\n".join(report)


async def run_all_memory_tests():
    """Run all memory profiling tests"""
    profiler = MemoryUsageProfiler()
    
    # Run all tests
    await profiler.test_expert_manager_memory()
    await profiler.test_mcp_manager_memory()
    await profiler.test_rust_modules_memory()
    await profiler.test_memory_leak_detection()
    await profiler.test_concurrent_memory_usage()
    
    # Run detailed profile (this will print to console)
    print("\n" + "="*60)
    await profiler.test_detailed_memory_profile()
    print("="*60)
    
    # Generate report
    report = profiler.generate_report()
    
    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"tests/performance/memory_profile_report_{timestamp}.md"
    
    with open(report_path, 'w') as f:
        f.write(report)
    
    # Save detailed snapshots
    snapshots_data = [asdict(s) for s in profiler.snapshots]
    snapshots_path = f"tests/performance/memory_snapshots_{timestamp}.json"
    
    with open(snapshots_path, 'w') as f:
        json.dump(snapshots_data, f, indent=2)
    
    print(f"\n✅ Memory profiling complete!")
    print(f"📄 Report: {report_path}")
    print(f"📊 Snapshots: {snapshots_path}")


if __name__ == "__main__":
    # Run memory profiling
    asyncio.run(run_all_memory_tests())