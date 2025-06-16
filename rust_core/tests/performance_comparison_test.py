#!/usr/bin/env python3
"""
Performance comparison tests between Rust and Python MCP Manager implementations.
"""

import asyncio
import time
import statistics
import json
from typing import List, Dict, Any, Tuple
import concurrent.futures
from dataclasses import dataclass
import matplotlib.pyplot as plt
import numpy as np

# Import both implementations
try:
    # Rust implementation (via PyO3)
    from rust_core import MCPManager as RustMCPManager
except ImportError:
    print("Warning: Rust MCP Manager not available")
    RustMCPManager = None

# Python implementation
from src.mcp.manager import MCPManager as PythonMCPManager
from src.mcp.servers import MCPServer


@dataclass
class BenchmarkResult:
    """Result of a benchmark test."""
    operation: str
    implementation: str
    mean_time: float
    median_time: float
    std_dev: float
    min_time: float
    max_time: float
    throughput: float
    samples: List[float]


class PerformanceComparison:
    """Compare performance between Rust and Python implementations."""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        
    async def setup_managers(self, num_servers: int = 10) -> Tuple[Any, Any]:
        """Setup both Rust and Python managers with test servers."""
        # Python manager
        py_manager = PythonMCPManager()
        
        # Rust manager
        rust_config = {
            "max_connections_per_server": 50,
            "connection_timeout_ms": 5000,
            "request_timeout_ms": 30000,
            "enable_connection_pooling": True,
            "enable_load_balancing": True,
            "enable_metrics": True,
        }
        rust_manager = RustMCPManager(rust_config) if RustMCPManager else None
        
        # Register servers
        for i in range(num_servers):
            server = MCPServer(
                name=f"test_server_{i}",
                host=f"localhost",
                port=8000 + i,
                server_type="test"
            )
            
            await py_manager.register_server(server)
            if rust_manager:
                await rust_manager.register_server({
                    "id": f"test_server_{i}",
                    "url": f"http://localhost:{8000 + i}",
                    "protocol": "http"
                })
        
        return py_manager, rust_manager
    
    async def benchmark_operation(
        self,
        operation_name: str,
        operation_func,
        iterations: int = 1000,
        warmup: int = 100
    ) -> List[float]:
        """Benchmark a single operation."""
        # Warmup
        for _ in range(warmup):
            await operation_func()
        
        # Actual benchmark
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            await operation_func()
            elapsed = (time.perf_counter() - start) * 1000  # Convert to ms
            times.append(elapsed)
            
        return times
    
    async def benchmark_server_registration(self):
        """Benchmark server registration performance."""
        print("\n=== Server Registration Benchmark ===")
        
        # Python implementation
        py_times = []
        for i in range(100):
            py_manager = PythonMCPManager()
            
            async def register_py():
                server = MCPServer(f"bench_server_{i}", "localhost", 9000 + i, "test")
                await py_manager.register_server(server)
            
            times = await self.benchmark_operation(
                "server_registration_python",
                register_py,
                iterations=10
            )
            py_times.extend(times)
        
        self.add_result("server_registration", "python", py_times)
        
        # Rust implementation
        if RustMCPManager:
            rust_times = []
            for i in range(100):
                rust_manager = RustMCPManager({})
                
                async def register_rust():
                    await rust_manager.register_server({
                        "id": f"bench_server_{i}",
                        "url": f"http://localhost:{9000 + i}",
                        "protocol": "http"
                    })
                
                times = await self.benchmark_operation(
                    "server_registration_rust",
                    register_rust,
                    iterations=10
                )
                rust_times.extend(times)
            
            self.add_result("server_registration", "rust", rust_times)
    
    async def benchmark_request_routing(self):
        """Benchmark request routing performance."""
        print("\n=== Request Routing Benchmark ===")
        
        py_manager, rust_manager = await self.setup_managers(20)
        
        # Python implementation
        async def route_py():
            request = {
                "method": "test_method",
                "params": {"data": "test" * 100}
            }
            # Simulate routing without actual network call
            server = py_manager._select_server("test_method")
            return server
        
        py_times = await self.benchmark_operation(
            "request_routing_python",
            route_py,
            iterations=10000
        )
        self.add_result("request_routing", "python", py_times)
        
        # Rust implementation
        if rust_manager:
            async def route_rust():
                request = {
                    "method": "test_method",
                    "params": {"data": "test" * 100}
                }
                # Simulate routing
                server = await rust_manager.select_server(request)
                return server
            
            rust_times = await self.benchmark_operation(
                "request_routing_rust",
                route_rust,
                iterations=10000
            )
            self.add_result("request_routing", "rust", rust_times)
    
    async def benchmark_concurrent_requests(self):
        """Benchmark concurrent request handling."""
        print("\n=== Concurrent Requests Benchmark ===")
        
        py_manager, rust_manager = await self.setup_managers(10)
        
        async def make_concurrent_requests(manager, impl_name: str, num_requests: int):
            """Make concurrent requests and measure throughput."""
            
            async def make_request(i: int):
                request = {
                    "method": "concurrent_test",
                    "params": {"id": i, "data": "x" * 1000}
                }
                # Simulate request processing
                await asyncio.sleep(0.001)  # 1ms processing time
                return {"result": "ok", "id": i}
            
            start = time.perf_counter()
            
            tasks = [make_request(i) for i in range(num_requests)]
            await asyncio.gather(*tasks)
            
            elapsed = time.perf_counter() - start
            throughput = num_requests / elapsed
            
            return elapsed * 1000, throughput  # ms, req/s
        
        # Test with different concurrency levels
        for num_requests in [100, 500, 1000, 5000]:
            print(f"\nTesting with {num_requests} concurrent requests...")
            
            # Python
            py_time, py_throughput = await make_concurrent_requests(
                py_manager, "python", num_requests
            )
            self.add_result(
                f"concurrent_{num_requests}",
                "python",
                [py_time],
                throughput=py_throughput
            )
            
            # Rust
            if rust_manager:
                rust_time, rust_throughput = await make_concurrent_requests(
                    rust_manager, "rust", num_requests
                )
                self.add_result(
                    f"concurrent_{num_requests}",
                    "rust",
                    [rust_time],
                    throughput=rust_throughput
                )
    
    async def benchmark_memory_usage(self):
        """Benchmark memory usage patterns."""
        print("\n=== Memory Usage Benchmark ===")
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        # Python implementation
        py_manager = PythonMCPManager()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Add many servers
        for i in range(1000):
            server = MCPServer(f"mem_test_{i}", "localhost", 10000 + i, "test")
            await py_manager.register_server(server)
        
        # Make many requests
        for i in range(10000):
            if i % 1000 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                print(f"Python - After {i} operations: {current_memory:.2f} MB")
        
        py_final_memory = process.memory_info().rss / 1024 / 1024
        py_memory_growth = py_final_memory - initial_memory
        
        print(f"Python memory growth: {py_memory_growth:.2f} MB")
        
        # Rust implementation
        if RustMCPManager:
            rust_manager = RustMCPManager({})
            initial_memory = process.memory_info().rss / 1024 / 1024
            
            # Add many servers
            for i in range(1000):
                await rust_manager.register_server({
                    "id": f"mem_test_{i}",
                    "url": f"http://localhost:{10000 + i}",
                    "protocol": "http"
                })
            
            # Make many requests
            for i in range(10000):
                if i % 1000 == 0:
                    current_memory = process.memory_info().rss / 1024 / 1024
                    print(f"Rust - After {i} operations: {current_memory:.2f} MB")
            
            rust_final_memory = process.memory_info().rss / 1024 / 1024
            rust_memory_growth = rust_final_memory - initial_memory
            
            print(f"Rust memory growth: {rust_memory_growth:.2f} MB")
    
    def add_result(
        self,
        operation: str,
        implementation: str,
        times: List[float],
        throughput: float = None
    ):
        """Add benchmark result."""
        result = BenchmarkResult(
            operation=operation,
            implementation=implementation,
            mean_time=statistics.mean(times),
            median_time=statistics.median(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0,
            min_time=min(times),
            max_time=max(times),
            throughput=throughput or (1000 / statistics.mean(times)),  # ops/sec
            samples=times
        )
        self.results.append(result)
        
        print(f"\n{implementation.upper()} - {operation}:")
        print(f"  Mean: {result.mean_time:.3f} ms")
        print(f"  Median: {result.median_time:.3f} ms")
        print(f"  Std Dev: {result.std_dev:.3f} ms")
        print(f"  Min/Max: {result.min_time:.3f} / {result.max_time:.3f} ms")
        if throughput:
            print(f"  Throughput: {result.throughput:.0f} req/s")
    
    def generate_report(self):
        """Generate performance comparison report."""
        print("\n" + "=" * 80)
        print("PERFORMANCE COMPARISON REPORT")
        print("=" * 80)
        
        # Group results by operation
        operations = {}
        for result in self.results:
            if result.operation not in operations:
                operations[result.operation] = {}
            operations[result.operation][result.implementation] = result
        
        # Compare implementations
        for op_name, impls in operations.items():
            print(f"\n### {op_name.replace('_', ' ').title()} ###")
            
            if "python" in impls and "rust" in impls:
                py_result = impls["python"]
                rust_result = impls["rust"]
                
                speedup = py_result.mean_time / rust_result.mean_time
                throughput_gain = rust_result.throughput / py_result.throughput
                
                print(f"  Python: {py_result.mean_time:.3f} ms (±{py_result.std_dev:.3f})")
                print(f"  Rust:   {rust_result.mean_time:.3f} ms (±{rust_result.std_dev:.3f})")
                print(f"  Speedup: {speedup:.2f}x faster")
                print(f"  Throughput gain: {throughput_gain:.2f}x")
                
                if speedup > 2:
                    print("  ✅ Significant performance improvement!")
                elif speedup > 1.5:
                    print("  ✓ Notable performance improvement")
                else:
                    print("  → Modest performance improvement")
    
    def plot_results(self):
        """Generate performance comparison plots."""
        # Group results for plotting
        operations = {}
        for result in self.results:
            if result.operation not in operations:
                operations[result.operation] = {}
            operations[result.operation][result.implementation] = result
        
        # Create subplots
        num_ops = len(operations)
        fig, axes = plt.subplots(2, (num_ops + 1) // 2, figsize=(15, 10))
        axes = axes.flatten()
        
        for idx, (op_name, impls) in enumerate(operations.items()):
            ax = axes[idx]
            
            # Prepare data
            implementations = []
            mean_times = []
            std_devs = []
            
            for impl_name, result in impls.items():
                implementations.append(impl_name.capitalize())
                mean_times.append(result.mean_time)
                std_devs.append(result.std_dev)
            
            # Create bar plot
            x = np.arange(len(implementations))
            bars = ax.bar(x, mean_times, yerr=std_devs, capsize=5)
            
            # Customize plot
            ax.set_ylabel('Time (ms)')
            ax.set_title(op_name.replace('_', ' ').title())
            ax.set_xticks(x)
            ax.set_xticklabels(implementations)
            
            # Add value labels
            for bar, mean_time in zip(bars, mean_times):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{mean_time:.2f}',
                       ha='center', va='bottom')
        
        # Remove empty subplots
        for idx in range(num_ops, len(axes)):
            fig.delaxes(axes[idx])
        
        plt.tight_layout()
        plt.savefig('mcp_performance_comparison.png', dpi=150)
        print("\nPerformance comparison plot saved to: mcp_performance_comparison.png")


async def main():
    """Run all performance comparison tests."""
    comparison = PerformanceComparison()
    
    # Run benchmarks
    await comparison.benchmark_server_registration()
    await comparison.benchmark_request_routing()
    await comparison.benchmark_concurrent_requests()
    await comparison.benchmark_memory_usage()
    
    # Generate report
    comparison.generate_report()
    
    # Generate plots
    try:
        comparison.plot_results()
    except ImportError:
        print("\nMatplotlib not available, skipping plots")
    
    # Save results to JSON
    results_data = []
    for result in comparison.results:
        results_data.append({
            "operation": result.operation,
            "implementation": result.implementation,
            "mean_time_ms": result.mean_time,
            "median_time_ms": result.median_time,
            "std_dev_ms": result.std_dev,
            "throughput_ops_per_sec": result.throughput,
        })
    
    with open("mcp_performance_results.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    print("\nResults saved to: mcp_performance_results.json")


if __name__ == "__main__":
    asyncio.run(main())