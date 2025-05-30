"""
MCP Stress Testing and Load Simulation
Agent 7: System limits and bottleneck identification
"""

import asyncio
import time
import psutil
import resource
import gc
import threading
from datetime import datetime
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
import sys
import os
import json

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.mcp.manager import get_mcp_manager


@dataclass
class StressTestResult:
    """Results from a stress test run"""
    test_name: str
    duration_seconds: float
    total_operations: int
    successful_operations: int
    failed_operations: int
    operations_per_second: float
    avg_response_time: float
    max_response_time: float
    min_response_time: float
    memory_usage_mb: float
    cpu_usage_percent: float
    error_types: Dict[str, int]
    breaking_point: bool
    notes: str


class MCPStressTester:
    """Stress testing for MCP infrastructure"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.results: List[StressTestResult] = []
        self.stop_flag = threading.Event()
        
    async def stress_test_tool(self, server_name: str, tool_name: str, 
                              params: Dict[str, Any], duration_seconds: int = 60,
                              max_concurrent: int = 50) -> StressTestResult:
        """Stress test a specific tool"""
        print(f"\n🔥 Stress Testing {server_name}.{tool_name}")
        print(f"   Duration: {duration_seconds}s, Max Concurrent: {max_concurrent}")
        
        manager = get_mcp_manager()
        
        # Metrics tracking
        start_time = time.time()
        response_times = []
        errors = {}
        successful = 0
        failed = 0
        active_tasks = set()
        
        # Memory and CPU tracking
        memory_samples = []
        cpu_samples = []
        
        async def monitor_resources():
            """Monitor system resources during test"""
            while not self.stop_flag.is_set():
                memory_samples.append(self.process.memory_info().rss / 1024 / 1024)
                cpu_samples.append(self.process.cpu_percent(interval=0.1))
                await asyncio.sleep(1)
        
        # Start resource monitoring
        monitor_task = asyncio.create_task(monitor_resources())
        
        async def execute_operation():
            """Execute a single operation"""
            nonlocal successful, failed
            
            op_start = time.time()
            try:
                result = await manager.call_tool(f"{server_name}.{tool_name}", params)
                successful += 1
                response_times.append(time.time() - op_start)
            except Exception as e:
                failed += 1
                error_type = type(e).__name__
                errors[error_type] = errors.get(error_type, 0) + 1
                response_times.append(time.time() - op_start)
        
        # Run stress test
        breaking_point = False
        notes = []
        
        try:
            while time.time() - start_time < duration_seconds:
                # Maintain concurrent operations
                while len(active_tasks) < max_concurrent:
                    task = asyncio.create_task(execute_operation())
                    active_tasks.add(task)
                    task.add_done_callback(active_tasks.discard)
                
                # Check for breaking point indicators
                if memory_samples and memory_samples[-1] > 1000:  # 1GB memory
                    notes.append("High memory usage detected")
                    
                if cpu_samples and cpu_samples[-1] > 90:  # 90% CPU
                    notes.append("High CPU usage detected")
                
                if failed > successful and (successful + failed) > 100:
                    breaking_point = True
                    notes.append("Failure rate exceeded 50%")
                    break
                
                await asyncio.sleep(0.1)
            
            # Wait for remaining tasks
            if active_tasks:
                await asyncio.gather(*active_tasks, return_exceptions=True)
                
        except Exception as e:
            notes.append(f"Test terminated: {e}")
            breaking_point = True
        
        # Stop monitoring
        self.stop_flag.set()
        await monitor_task
        
        # Calculate results
        duration = time.time() - start_time
        total_ops = successful + failed
        
        result = StressTestResult(
            test_name=f"{server_name}.{tool_name}",
            duration_seconds=duration,
            total_operations=total_ops,
            successful_operations=successful,
            failed_operations=failed,
            operations_per_second=total_ops / duration if duration > 0 else 0,
            avg_response_time=sum(response_times) / len(response_times) if response_times else 0,
            max_response_time=max(response_times) if response_times else 0,
            min_response_time=min(response_times) if response_times else 0,
            memory_usage_mb=max(memory_samples) if memory_samples else 0,
            cpu_usage_percent=max(cpu_samples) if cpu_samples else 0,
            error_types=errors,
            breaking_point=breaking_point,
            notes="; ".join(notes)
        )
        
        self.results.append(result)
        self.stop_flag.clear()
        
        return result
    
    async def find_breaking_points(self) -> Dict[str, Any]:
        """Find breaking points for each module"""
        print("\n💥 Finding Breaking Points")
        print("=" * 60)
        
        breaking_points = {}
        
        # Test configurations with increasing load
        test_configs = [
            ("desktop", "execute_command", {"command": "echo 'stress test'"}, "Desktop Commander"),
            ("docker", "docker_ps", {}, "Docker"),
            ("security-scanner", "file_security_scan", {"file_path": "README.md"}, "Security Scanner"),
        ]
        
        for server, tool, params, module_name in test_configs:
            print(f"\n🔍 Testing {module_name} breaking point...")
            
            # Gradually increase load
            concurrent_levels = [10, 25, 50, 100, 200]
            module_results = []
            
            for level in concurrent_levels:
                print(f"  Testing concurrency: {level}")
                
                result = await self.stress_test_tool(
                    server, tool, params,
                    duration_seconds=30,
                    max_concurrent=level
                )
                
                module_results.append({
                    "concurrency": level,
                    "ops_per_second": result.operations_per_second,
                    "failure_rate": result.failed_operations / result.total_operations if result.total_operations > 0 else 0,
                    "avg_response_time": result.avg_response_time,
                    "memory_mb": result.memory_usage_mb,
                    "cpu_percent": result.cpu_usage_percent,
                    "breaking_point": result.breaking_point
                })
                
                print(f"    ✓ OPS: {result.operations_per_second:.2f}, "
                      f"Failure Rate: {(result.failed_operations/result.total_operations)*100:.2f}%")
                
                # Stop if breaking point reached
                if result.breaking_point:
                    print(f"    ⚠️  Breaking point reached at concurrency: {level}")
                    break
                
                # Small delay between tests
                await asyncio.sleep(5)
                gc.collect()
            
            breaking_points[module_name] = module_results
        
        return breaking_points
    
    async def test_resource_exhaustion(self) -> Dict[str, Any]:
        """Test behavior under resource exhaustion"""
        print("\n🔋 Testing Resource Exhaustion Scenarios")
        print("=" * 60)
        
        exhaustion_results = {}
        
        # Memory exhaustion test
        print("\n📊 Memory Exhaustion Test")
        memory_results = []
        
        # Create memory pressure by allocating large objects
        memory_hogs = []
        try:
            for i in range(10):
                # Allocate 100MB chunks
                memory_hogs.append(bytearray(100 * 1024 * 1024))
                
                # Test tool performance under memory pressure
                result = await self.stress_test_tool(
                    "desktop", "execute_command", 
                    {"command": "echo 'memory test'"},
                    duration_seconds=10,
                    max_concurrent=20
                )
                
                memory_results.append({
                    "allocated_mb": (i + 1) * 100,
                    "ops_per_second": result.operations_per_second,
                    "failure_rate": result.failed_operations / result.total_operations if result.total_operations > 0 else 0,
                    "response_time": result.avg_response_time
                })
                
                print(f"  Allocated: {(i+1)*100}MB, OPS: {result.operations_per_second:.2f}")
                
        except MemoryError:
            print("  ⚠️  Memory exhaustion reached")
        finally:
            # Clean up
            memory_hogs.clear()
            gc.collect()
        
        exhaustion_results["memory_exhaustion"] = memory_results
        
        # CPU exhaustion test
        print("\n🔥 CPU Exhaustion Test")
        cpu_results = []
        
        # Create CPU-intensive background tasks
        async def cpu_burner():
            """CPU-intensive task"""
            while not self.stop_flag.is_set():
                _ = sum(i * i for i in range(10000))
                await asyncio.sleep(0)
        
        cpu_tasks = []
        for num_burners in [0, 5, 10, 20]:
            # Start CPU burners
            for _ in range(num_burners):
                cpu_tasks.append(asyncio.create_task(cpu_burner()))
            
            # Test performance under CPU load
            result = await self.stress_test_tool(
                "security-scanner", "file_security_scan",
                {"file_path": "src/mcp/servers.py"},
                duration_seconds=10,
                max_concurrent=10
            )
            
            cpu_results.append({
                "cpu_burners": num_burners,
                "ops_per_second": result.operations_per_second,
                "failure_rate": result.failed_operations / result.total_operations if result.total_operations > 0 else 0,
                "response_time": result.avg_response_time,
                "cpu_usage": result.cpu_usage_percent
            })
            
            print(f"  CPU Burners: {num_burners}, OPS: {result.operations_per_second:.2f}")
            
            # Stop CPU burners
            self.stop_flag.set()
            await asyncio.gather(*cpu_tasks, return_exceptions=True)
            cpu_tasks.clear()
            self.stop_flag.clear()
        
        exhaustion_results["cpu_exhaustion"] = cpu_results
        
        return exhaustion_results
    
    async def test_connection_limits(self) -> Dict[str, Any]:
        """Test connection and file descriptor limits"""
        print("\n🔌 Testing Connection and Resource Limits")
        print("=" * 60)
        
        limit_results = {}
        
        # Test file descriptor limits
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f"  File descriptor limits - Soft: {soft}, Hard: {hard}")
        
        # Test with many concurrent file operations
        file_ops_result = await self.stress_test_tool(
            "desktop", "read_file",
            {"file_path": "README.md", "lines": 10},
            duration_seconds=30,
            max_concurrent=100
        )
        
        limit_results["file_operations"] = {
            "fd_limit_soft": soft,
            "fd_limit_hard": hard,
            "max_concurrent": 100,
            "ops_per_second": file_ops_result.operations_per_second,
            "failure_rate": file_ops_result.failed_operations / file_ops_result.total_operations if file_ops_result.total_operations > 0 else 0
        }
        
        # Test with many concurrent network-like operations
        network_ops_result = await self.stress_test_tool(
            "docker", "docker_ps",
            {},
            duration_seconds=30,
            max_concurrent=50
        )
        
        limit_results["network_operations"] = {
            "max_concurrent": 50,
            "ops_per_second": network_ops_result.operations_per_second,
            "failure_rate": network_ops_result.failed_operations / network_ops_result.total_operations if network_ops_result.total_operations > 0 else 0,
            "errors": network_ops_result.error_types
        }
        
        return limit_results
    
    def generate_stress_report(self, breaking_points: Dict[str, Any],
                              exhaustion_results: Dict[str, Any],
                              limit_results: Dict[str, Any]) -> str:
        """Generate comprehensive stress test report"""
        report = []
        report.append("# MCP Stress Testing Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        
        # Breaking Points Analysis
        report.append("\n## Breaking Points Analysis")
        
        for module, results in breaking_points.items():
            report.append(f"\n### {module}")
            
            # Find the breaking point
            breaking_concurrency = None
            max_ops = 0
            
            for result in results:
                if result["ops_per_second"] > max_ops:
                    max_ops = result["ops_per_second"]
                
                if result["breaking_point"]:
                    breaking_concurrency = result["concurrency"]
                    break
            
            report.append(f"- **Peak Performance**: {max_ops:.2f} ops/second")
            report.append(f"- **Breaking Point**: {breaking_concurrency or 'Not reached'} concurrent operations")
            
            # Performance table
            report.append("\n| Concurrency | OPS | Failure Rate | Avg Response Time | Memory (MB) | CPU (%) |")
            report.append("|-------------|-----|--------------|-------------------|-------------|---------|")
            
            for result in results:
                report.append(f"| {result['concurrency']} | {result['ops_per_second']:.2f} | "
                            f"{result['failure_rate']*100:.2f}% | {result['avg_response_time']:.3f}s | "
                            f"{result['memory_mb']:.2f} | {result['cpu_percent']:.2f} |")
        
        # Resource Exhaustion Results
        report.append("\n## Resource Exhaustion Testing")
        
        report.append("\n### Memory Exhaustion")
        report.append("| Allocated (MB) | OPS | Failure Rate | Response Time |")
        report.append("|----------------|-----|--------------|---------------|")
        
        for result in exhaustion_results.get("memory_exhaustion", []):
            report.append(f"| {result['allocated_mb']} | {result['ops_per_second']:.2f} | "
                        f"{result['failure_rate']*100:.2f}% | {result['response_time']:.3f}s |")
        
        report.append("\n### CPU Exhaustion")
        report.append("| CPU Burners | OPS | Failure Rate | Response Time | CPU Usage |")
        report.append("|-------------|-----|--------------|---------------|-----------|")
        
        for result in exhaustion_results.get("cpu_exhaustion", []):
            report.append(f"| {result['cpu_burners']} | {result['ops_per_second']:.2f} | "
                        f"{result['failure_rate']*100:.2f}% | {result['response_time']:.3f}s | "
                        f"{result['cpu_usage']:.2f}% |")
        
        # Connection Limits
        report.append("\n## Connection and Resource Limits")
        
        file_ops = limit_results.get("file_operations", {})
        report.append(f"\n### File Operations")
        report.append(f"- **File Descriptor Limit**: {file_ops.get('fd_limit_soft', 'N/A')} (soft), "
                     f"{file_ops.get('fd_limit_hard', 'N/A')} (hard)")
        report.append(f"- **Performance at 100 concurrent**: {file_ops.get('ops_per_second', 0):.2f} ops/second")
        report.append(f"- **Failure Rate**: {file_ops.get('failure_rate', 0)*100:.2f}%")
        
        network_ops = limit_results.get("network_operations", {})
        report.append(f"\n### Network-like Operations")
        report.append(f"- **Performance at 50 concurrent**: {network_ops.get('ops_per_second', 0):.2f} ops/second")
        report.append(f"- **Failure Rate**: {network_ops.get('failure_rate', 0)*100:.2f}%")
        if network_ops.get("errors"):
            report.append("- **Error Types**:")
            for error, count in network_ops.get("errors", {}).items():
                report.append(f"  - {error}: {count}")
        
        # Recommendations
        report.append("\n## Performance Recommendations")
        
        # Analyze results and provide recommendations
        recommendations = []
        
        # Check for low breaking points
        for module, results in breaking_points.items():
            for result in results:
                if result["breaking_point"] and result["concurrency"] <= 50:
                    recommendations.append(f"- {module} shows early breaking point at {result['concurrency']} concurrent operations. Consider connection pooling or rate limiting.")
        
        # Check for memory issues
        mem_results = exhaustion_results.get("memory_exhaustion", [])
        if mem_results and any(r["failure_rate"] > 0.1 for r in mem_results[:3]):
            recommendations.append("- System shows sensitivity to memory pressure. Implement memory-aware throttling.")
        
        # Check for CPU issues
        cpu_results = exhaustion_results.get("cpu_exhaustion", [])
        if cpu_results and cpu_results[0]["ops_per_second"] > 0:
            cpu_degradation = 1 - (cpu_results[-1]["ops_per_second"] / cpu_results[0]["ops_per_second"])
            if cpu_degradation > 0.5:
                recommendations.append(f"- Significant CPU sensitivity detected ({cpu_degradation*100:.0f}% degradation). Consider async I/O optimization.")
        
        if not recommendations:
            recommendations.append("- System shows good resilience under stress conditions.")
            recommendations.append("- Consider implementing rate limiting for production use.")
            recommendations.append("- Monitor resource usage in production environments.")
        
        for rec in recommendations:
            report.append(rec)
        
        return "\n".join(report)


async def main():
    """Run comprehensive stress testing"""
    print("💪 MCP Stress Testing Suite")
    print("Agent 7: System Limits and Bottleneck Identification")
    print("=" * 60)
    
    tester = MCPStressTester()
    
    # Initialize MCP manager
    manager = get_mcp_manager()
    await manager.initialize()
    
    # Run stress tests
    breaking_points = await tester.find_breaking_points()
    exhaustion_results = await tester.test_resource_exhaustion()
    limit_results = await tester.test_connection_limits()
    
    # Generate report
    report = tester.generate_stress_report(breaking_points, exhaustion_results, limit_results)
    
    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"tests/performance/stress_test_report_{timestamp}.md"
    
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, 'w') as f:
        f.write(report)
    
    # Save raw results
    raw_results = {
        "timestamp": datetime.now().isoformat(),
        "breaking_points": breaking_points,
        "exhaustion_results": exhaustion_results,
        "limit_results": limit_results,
        "individual_results": [
            {
                "test_name": r.test_name,
                "duration_seconds": r.duration_seconds,
                "total_operations": r.total_operations,
                "successful_operations": r.successful_operations,
                "failed_operations": r.failed_operations,
                "operations_per_second": r.operations_per_second,
                "avg_response_time": r.avg_response_time,
                "max_response_time": r.max_response_time,
                "memory_usage_mb": r.memory_usage_mb,
                "cpu_usage_percent": r.cpu_usage_percent,
                "error_types": r.error_types,
                "breaking_point": r.breaking_point,
                "notes": r.notes
            }
            for r in tester.results
        ]
    }
    
    results_path = f"tests/performance/stress_test_results_{timestamp}.json"
    with open(results_path, 'w') as f:
        json.dump(raw_results, f, indent=2)
    
    print(f"\n✅ Stress testing complete!")
    print(f"📄 Report saved to: {report_path}")
    print(f"📊 Results saved to: {results_path}")


if __name__ == "__main__":
    asyncio.run(main())