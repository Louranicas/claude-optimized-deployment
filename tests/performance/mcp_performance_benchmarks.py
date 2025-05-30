"""
MCP Performance Benchmarking Suite
Agent 7: Comprehensive performance testing for all MCP modules
"""

import asyncio
import time
import psutil
import statistics
import json
import tracemalloc
from datetime import datetime
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.mcp.manager import get_mcp_manager
from src.mcp.infrastructure_servers import DockerMCPServer, KubernetesMCPServer, DesktopCommanderMCPServer
from src.mcp.devops_servers import AzureDevOpsMCPServer, WindowsSystemMCPServer
from src.mcp.monitoring.prometheus_server import PrometheusMonitoringMCP
from src.mcp.security.scanner_server import SecurityScannerMCPServer
from src.mcp.communication.slack_server import SlackNotificationMCPServer
from src.mcp.storage.s3_server import S3StorageMCPServer
from src.mcp.servers import BraveMCPServer


@dataclass
class PerformanceMetrics:
    """Performance metrics for a single test run"""
    tool_name: str
    module_name: str
    execution_time: float
    memory_before: float
    memory_after: float
    memory_delta: float
    cpu_percent: float
    io_read_bytes: int
    io_write_bytes: int
    success: bool
    error: str = None
    timestamp: str = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class BenchmarkResults:
    """Aggregated benchmark results"""
    tool_name: str
    module_name: str
    total_runs: int
    successful_runs: int
    failed_runs: int
    avg_execution_time: float
    min_execution_time: float
    max_execution_time: float
    std_deviation: float
    avg_memory_delta: float
    avg_cpu_percent: float
    total_io_read_mb: float
    total_io_write_mb: float
    p50_execution_time: float
    p95_execution_time: float
    p99_execution_time: float


class MCPPerformanceBenchmark:
    """Performance benchmarking for MCP modules"""
    
    def __init__(self):
        self.metrics: List[PerformanceMetrics] = []
        self.process = psutil.Process()
        
    async def benchmark_tool(self, server_name: str, tool_name: str, 
                            params: Dict[str, Any], runs: int = 10) -> BenchmarkResults:
        """Benchmark a specific tool with multiple runs"""
        print(f"\n🔍 Benchmarking {server_name}.{tool_name} ({runs} runs)...")
        
        tool_metrics = []
        manager = get_mcp_manager()
        
        for i in range(runs):
            print(f"  Run {i+1}/{runs}...", end='', flush=True)
            
            # Collect pre-execution metrics
            tracemalloc.start()
            memory_before = self.process.memory_info().rss / 1024 / 1024  # MB
            io_before = self.process.io_counters()
            cpu_before = self.process.cpu_percent(interval=0.1)
            
            # Execute tool
            start_time = time.time()
            success = True
            error = None
            
            try:
                result = await manager.call_tool(f"{server_name}.{tool_name}", params)
            except Exception as e:
                success = False
                error = str(e)
                
            execution_time = time.time() - start_time
            
            # Collect post-execution metrics
            memory_after = self.process.memory_info().rss / 1024 / 1024  # MB
            memory_delta = memory_after - memory_before
            cpu_percent = self.process.cpu_percent(interval=0.1)
            io_after = self.process.io_counters()
            
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            
            # Create metrics
            metric = PerformanceMetrics(
                tool_name=tool_name,
                module_name=server_name,
                execution_time=execution_time,
                memory_before=memory_before,
                memory_after=memory_after,
                memory_delta=memory_delta,
                cpu_percent=cpu_percent,
                io_read_bytes=io_after.read_bytes - io_before.read_bytes,
                io_write_bytes=io_after.write_bytes - io_before.write_bytes,
                success=success,
                error=error
            )
            
            tool_metrics.append(metric)
            self.metrics.append(metric)
            
            print(f" ✓ ({execution_time:.3f}s)")
            
            # Small delay between runs
            await asyncio.sleep(0.5)
        
        # Calculate aggregated results
        return self._calculate_results(tool_metrics, server_name, tool_name)
    
    def _calculate_results(self, metrics: List[PerformanceMetrics], 
                          server_name: str, tool_name: str) -> BenchmarkResults:
        """Calculate aggregated benchmark results"""
        successful_metrics = [m for m in metrics if m.success]
        execution_times = [m.execution_time for m in successful_metrics]
        
        if not execution_times:
            execution_times = [0]  # Avoid division by zero
        
        # Calculate percentiles
        sorted_times = sorted(execution_times)
        p50_idx = int(len(sorted_times) * 0.5)
        p95_idx = int(len(sorted_times) * 0.95)
        p99_idx = int(len(sorted_times) * 0.99)
        
        return BenchmarkResults(
            tool_name=tool_name,
            module_name=server_name,
            total_runs=len(metrics),
            successful_runs=len(successful_metrics),
            failed_runs=len(metrics) - len(successful_metrics),
            avg_execution_time=statistics.mean(execution_times) if execution_times else 0,
            min_execution_time=min(execution_times) if execution_times else 0,
            max_execution_time=max(execution_times) if execution_times else 0,
            std_deviation=statistics.stdev(execution_times) if len(execution_times) > 1 else 0,
            avg_memory_delta=statistics.mean([m.memory_delta for m in successful_metrics]) if successful_metrics else 0,
            avg_cpu_percent=statistics.mean([m.cpu_percent for m in successful_metrics]) if successful_metrics else 0,
            total_io_read_mb=sum([m.io_read_bytes for m in metrics]) / 1024 / 1024,
            total_io_write_mb=sum([m.io_write_bytes for m in metrics]) / 1024 / 1024,
            p50_execution_time=sorted_times[p50_idx] if sorted_times else 0,
            p95_execution_time=sorted_times[p95_idx] if sorted_times else 0,
            p99_execution_time=sorted_times[p99_idx] if sorted_times else 0
        )
    
    async def run_module_benchmarks(self) -> Dict[str, List[BenchmarkResults]]:
        """Run benchmarks for all modules"""
        results = {}
        
        # Desktop Commander benchmarks
        desktop_tests = [
            ("desktop", "execute_command", {"command": "echo 'Performance test'"}),
            ("desktop", "make_command", {"target": "help"}),
            ("desktop", "read_file", {"file_path": "README.md", "lines": 10}),
        ]
        
        # Docker benchmarks
        docker_tests = [
            ("docker", "docker_ps", {}),
            ("docker", "docker_images", {}),
            ("docker", "docker_version", {}),
        ]
        
        # Kubernetes benchmarks
        k8s_tests = [
            ("kubernetes", "kubectl_version", {}),
            ("kubernetes", "kubectl_get", {"resource_type": "pods", "namespace": "default"}),
            ("kubernetes", "kubectl_describe", {"resource_type": "node", "resource_name": "minikube"}),
        ]
        
        # Security Scanner benchmarks
        security_tests = [
            ("security-scanner", "file_security_scan", {"file_path": "src/mcp/servers.py"}),
            ("security-scanner", "npm_audit", {"package_json_path": "package.json"}),
            ("security-scanner", "python_safety_check", {"requirements_path": "requirements.txt"}),
        ]
        
        # Azure DevOps benchmarks (lightweight tests)
        azure_tests = [
            ("azure-devops", "list_projects", {}),
            ("azure-devops", "get_project", {"project_id": "test-project"}),
        ]
        
        all_tests = [
            ("Desktop Commander", desktop_tests),
            ("Docker", docker_tests),
            ("Kubernetes", k8s_tests),
            ("Security Scanner", security_tests),
            ("Azure DevOps", azure_tests),
        ]
        
        # Initialize manager
        manager = get_mcp_manager()
        await manager.initialize()
        
        # Run benchmarks for each module
        for module_name, tests in all_tests:
            print(f"\n📊 Benchmarking {module_name} Module")
            print("=" * 60)
            
            module_results = []
            for server, tool, params in tests:
                try:
                    result = await self.benchmark_tool(server, tool, params, runs=10)
                    module_results.append(result)
                except Exception as e:
                    print(f"  ❌ Error benchmarking {server}.{tool}: {e}")
            
            results[module_name] = module_results
        
        return results
    
    async def run_concurrent_benchmarks(self) -> Dict[str, Any]:
        """Test concurrent execution performance"""
        print("\n🔄 Running Concurrent Execution Benchmarks")
        print("=" * 60)
        
        manager = get_mcp_manager()
        concurrent_results = {}
        
        # Test different concurrency levels
        concurrency_levels = [1, 5, 10, 20]
        
        for level in concurrency_levels:
            print(f"\n  Testing concurrency level: {level}")
            
            # Create concurrent tasks
            tasks = []
            for i in range(level):
                # Mix of different tools
                if i % 4 == 0:
                    tasks.append(manager.call_tool("desktop.execute_command", 
                                                 {"command": f"echo 'Concurrent test {i}'"}))
                elif i % 4 == 1:
                    tasks.append(manager.call_tool("docker.docker_ps", {}))
                elif i % 4 == 2:
                    tasks.append(manager.call_tool("security-scanner.file_security_scan",
                                                 {"file_path": "README.md"}))
                else:
                    tasks.append(manager.call_tool("kubernetes.kubectl_version", {}))
            
            # Execute concurrently
            start_time = time.time()
            memory_before = self.process.memory_info().rss / 1024 / 1024
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            execution_time = time.time() - start_time
            memory_after = self.process.memory_info().rss / 1024 / 1024
            
            successful = sum(1 for r in results if not isinstance(r, Exception))
            
            concurrent_results[f"level_{level}"] = {
                "concurrency_level": level,
                "total_tasks": len(tasks),
                "successful_tasks": successful,
                "failed_tasks": len(tasks) - successful,
                "total_execution_time": execution_time,
                "avg_task_time": execution_time / level,
                "memory_delta_mb": memory_after - memory_before,
                "throughput_tasks_per_second": level / execution_time
            }
            
            print(f"    ✓ Completed in {execution_time:.3f}s")
            print(f"    ✓ Throughput: {level / execution_time:.2f} tasks/second")
        
        return concurrent_results
    
    def generate_report(self, module_results: Dict[str, List[BenchmarkResults]], 
                       concurrent_results: Dict[str, Any]) -> str:
        """Generate comprehensive performance report"""
        report = []
        report.append("# MCP Performance Benchmark Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("\n## Executive Summary")
        
        # Calculate overall statistics
        total_tests = sum(len(results) for results in module_results.values())
        total_successful = sum(sum(r.successful_runs for r in results) 
                             for results in module_results.values())
        total_runs = sum(sum(r.total_runs for r in results) 
                        for results in module_results.values())
        
        report.append(f"- Total Tests: {total_tests}")
        report.append(f"- Total Runs: {total_runs}")
        report.append(f"- Success Rate: {(total_successful/total_runs)*100:.2f}%")
        
        # Module-level results
        report.append("\n## Module Performance Results")
        
        for module_name, results in module_results.items():
            report.append(f"\n### {module_name}")
            
            for result in results:
                report.append(f"\n#### {result.tool_name}")
                report.append(f"- **Success Rate**: {(result.successful_runs/result.total_runs)*100:.2f}%")
                report.append(f"- **Avg Execution Time**: {result.avg_execution_time:.3f}s")
                report.append(f"- **Min/Max Time**: {result.min_execution_time:.3f}s / {result.max_execution_time:.3f}s")
                report.append(f"- **Std Deviation**: {result.std_deviation:.3f}s")
                report.append(f"- **P50/P95/P99**: {result.p50_execution_time:.3f}s / {result.p95_execution_time:.3f}s / {result.p99_execution_time:.3f}s")
                report.append(f"- **Avg Memory Delta**: {result.avg_memory_delta:.2f} MB")
                report.append(f"- **Avg CPU**: {result.avg_cpu_percent:.2f}%")
                report.append(f"- **Total I/O**: {result.total_io_read_mb:.2f} MB read, {result.total_io_write_mb:.2f} MB write")
        
        # Concurrent execution results
        report.append("\n## Concurrent Execution Performance")
        
        for level_name, results in concurrent_results.items():
            level = results["concurrency_level"]
            report.append(f"\n### Concurrency Level: {level}")
            report.append(f"- **Total Execution Time**: {results['total_execution_time']:.3f}s")
            report.append(f"- **Throughput**: {results['throughput_tasks_per_second']:.2f} tasks/second")
            report.append(f"- **Success Rate**: {(results['successful_tasks']/results['total_tasks'])*100:.2f}%")
            report.append(f"- **Memory Delta**: {results['memory_delta_mb']:.2f} MB")
        
        # Performance bottlenecks
        report.append("\n## Identified Bottlenecks")
        
        # Find slowest operations
        slowest_tools = []
        for module_name, results in module_results.items():
            for result in results:
                slowest_tools.append((result.avg_execution_time, result.tool_name, module_name))
        
        slowest_tools.sort(reverse=True)
        report.append("\n### Slowest Operations:")
        for time, tool, module in slowest_tools[:5]:
            report.append(f"- {module}.{tool}: {time:.3f}s average")
        
        # Find memory-intensive operations
        memory_tools = []
        for module_name, results in module_results.items():
            for result in results:
                memory_tools.append((result.avg_memory_delta, result.tool_name, module_name))
        
        memory_tools.sort(reverse=True)
        report.append("\n### Memory-Intensive Operations:")
        for memory, tool, module in memory_tools[:5]:
            report.append(f"- {module}.{tool}: {memory:.2f} MB average delta")
        
        return "\n".join(report)


async def main():
    """Run comprehensive performance benchmarks"""
    print("🚀 MCP Performance Benchmarking Suite")
    print("Agent 7: Comprehensive Performance Testing")
    print("=" * 60)
    
    benchmark = MCPPerformanceBenchmark()
    
    # Run module benchmarks
    module_results = await benchmark.run_module_benchmarks()
    
    # Run concurrent benchmarks
    concurrent_results = await benchmark.run_concurrent_benchmarks()
    
    # Generate report
    report = benchmark.generate_report(module_results, concurrent_results)
    
    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"tests/performance/benchmark_report_{timestamp}.md"
    
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, 'w') as f:
        f.write(report)
    
    # Save raw metrics
    metrics_data = {
        "timestamp": datetime.now().isoformat(),
        "module_results": {
            module: [asdict(r) for r in results]
            for module, results in module_results.items()
        },
        "concurrent_results": concurrent_results,
        "raw_metrics": [asdict(m) for m in benchmark.metrics]
    }
    
    metrics_path = f"tests/performance/benchmark_metrics_{timestamp}.json"
    with open(metrics_path, 'w') as f:
        json.dump(metrics_data, f, indent=2)
    
    print(f"\n✅ Performance benchmarking complete!")
    print(f"📄 Report saved to: {report_path}")
    print(f"📊 Metrics saved to: {metrics_path}")
    
    # Print summary
    print("\n📈 Quick Summary:")
    total_tests = sum(len(results) for results in module_results.values())
    print(f"  - Total tests run: {total_tests}")
    print(f"  - Total executions: {len(benchmark.metrics)}")
    
    # Find best and worst performers
    all_results = []
    for module_results_list in module_results.values():
        all_results.extend(module_results_list)
    
    fastest = min(all_results, key=lambda r: r.avg_execution_time)
    slowest = max(all_results, key=lambda r: r.avg_execution_time)
    
    print(f"  - Fastest tool: {fastest.module_name}.{fastest.tool_name} ({fastest.avg_execution_time:.3f}s)")
    print(f"  - Slowest tool: {slowest.module_name}.{slowest.tool_name} ({slowest.avg_execution_time:.3f}s)")


if __name__ == "__main__":
    asyncio.run(main())