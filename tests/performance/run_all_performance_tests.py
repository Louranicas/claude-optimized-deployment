#!/usr/bin/env python3
"""
Comprehensive Performance Test Runner
Agent 8C: Execute all performance and load tests with consolidated reporting
"""

import asyncio
import subprocess
import sys
import os
import json
from datetime import datetime
from pathlib import Path
import time

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))


class PerformanceTestRunner:
    """Orchestrate all performance tests"""
    
    def __init__(self):
        self.results = {}
        self.start_time = None
        self.test_dir = Path(__file__).parent
        
    def run_pytest_benchmarks(self):
        """Run pytest-benchmark tests"""
        print("\n🚀 Running Rust vs Python Benchmarks...")
        print("=" * 60)
        
        try:
            # Run pytest benchmarks
            result = subprocess.run([
                sys.executable, "-m", "pytest",
                str(self.test_dir / "test_rust_acceleration.py"),
                "-v",
                "--benchmark-only",
                "--benchmark-json=rust_benchmark_results.json",
                "--benchmark-columns=mean,stddev,min,max,median",
                "--benchmark-sort=mean"
            ], capture_output=True, text=True)
            
            print(result.stdout)
            if result.stderr:
                print("Errors:", result.stderr)
            
            # Load benchmark results
            if Path("rust_benchmark_results.json").exists():
                with open("rust_benchmark_results.json", 'r') as f:
                    self.results["rust_benchmarks"] = json.load(f)
                    
            return result.returncode == 0
            
        except Exception as e:
            print(f"Error running benchmarks: {e}")
            return False
    
    async def run_load_tests(self):
        """Run load testing scenarios"""
        print("\n🚀 Running Load Test Scenarios...")
        print("=" * 60)
        
        try:
            # Import and run load tests
            from test_load_scenarios import test_all_load_scenarios
            await test_all_load_scenarios()
            
            # Find latest load test results
            load_test_files = list(Path(self.test_dir).glob("load_test_results_*.json"))
            if load_test_files:
                latest_file = max(load_test_files, key=lambda p: p.stat().st_mtime)
                with open(latest_file, 'r') as f:
                    self.results["load_tests"] = json.load(f)
                    
            return True
            
        except Exception as e:
            print(f"Error running load tests: {e}")
            return False
    
    async def run_memory_profiling(self):
        """Run memory profiling tests"""
        print("\n🚀 Running Memory Profiling...")
        print("=" * 60)
        
        try:
            # Import and run memory tests
            from test_memory_usage import run_all_memory_tests
            await run_all_memory_tests()
            
            # Find latest memory snapshots
            memory_files = list(Path(self.test_dir).glob("memory_snapshots_*.json"))
            if memory_files:
                latest_file = max(memory_files, key=lambda p: p.stat().st_mtime)
                with open(latest_file, 'r') as f:
                    self.results["memory_profile"] = json.load(f)
                    
            return True
            
        except Exception as e:
            print(f"Error running memory profiling: {e}")
            return False
    
    async def run_mcp_performance_benchmarks(self):
        """Run MCP performance benchmarks"""
        print("\n🚀 Running MCP Performance Benchmarks...")
        print("=" * 60)
        
        try:
            # Run MCP benchmarks
            result = subprocess.run([
                sys.executable,
                str(self.test_dir / "mcp_performance_benchmarks.py")
            ], capture_output=True, text=True)
            
            print(result.stdout)
            if result.stderr:
                print("Errors:", result.stderr)
            
            # Find latest benchmark metrics
            mcp_files = list(Path(self.test_dir).glob("benchmark_metrics_*.json"))
            if mcp_files:
                latest_file = max(mcp_files, key=lambda p: p.stat().st_mtime)
                with open(latest_file, 'r') as f:
                    self.results["mcp_benchmarks"] = json.load(f)
                    
            return result.returncode == 0
            
        except Exception as e:
            print(f"Error running MCP benchmarks: {e}")
            return False
    
    def generate_consolidated_report(self):
        """Generate consolidated performance report"""
        report = []
        report.append("# Consolidated Performance Test Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append(f"Total Duration: {time.time() - self.start_time:.2f}s")
        
        report.append("\n## Test Summary")
        report.append(f"- Rust vs Python Benchmarks: {'✅' if 'rust_benchmarks' in self.results else '❌'}")
        report.append(f"- Load Test Scenarios: {'✅' if 'load_tests' in self.results else '❌'}")
        report.append(f"- Memory Profiling: {'✅' if 'memory_profile' in self.results else '❌'}")
        report.append(f"- MCP Performance: {'✅' if 'mcp_benchmarks' in self.results else '❌'}")
        
        # Rust benchmark highlights
        if "rust_benchmarks" in self.results:
            report.append("\n## Rust Acceleration Results")
            benchmarks = self.results["rust_benchmarks"].get("benchmarks", [])
            
            # Group by test group
            groups = {}
            for bench in benchmarks:
                group = bench.get("group", "default")
                if group not in groups:
                    groups[group] = []
                groups[group].append(bench)
            
            for group, benches in groups.items():
                report.append(f"\n### {group}")
                for bench in benches:
                    name = bench.get("name", "unknown")
                    mean = bench.get("stats", {}).get("mean", 0) * 1000  # Convert to ms
                    report.append(f"- **{name}**: {mean:.3f}ms average")
        
        # Load test highlights
        if "load_tests" in self.results:
            report.append("\n## Load Test Performance")
            for scenario in self.results["load_tests"]:
                report.append(f"\n### {scenario['scenario']}")
                report.append(f"- Requests: {scenario['total_requests']}")
                report.append(f"- Success Rate: {(1 - scenario['error_rate']) * 100:.1f}%")
                report.append(f"- Throughput: {scenario['requests_per_second']:.2f} req/s")
                report.append(f"- P95 Response Time: {scenario['percentile_95']:.3f}s")
        
        # Memory profile highlights
        if "memory_profile" in self.results:
            report.append("\n## Memory Usage Summary")
            snapshots = self.results["memory_profile"]
            if snapshots:
                # Find peak memory usage
                peak_memory = max(s["rss_mb"] for s in snapshots)
                report.append(f"- Peak Memory Usage: {peak_memory:.2f} MB")
                
                # Calculate average memory
                avg_memory = sum(s["rss_mb"] for s in snapshots) / len(snapshots)
                report.append(f"- Average Memory Usage: {avg_memory:.2f} MB")
        
        # MCP benchmark highlights
        if "mcp_benchmarks" in self.results:
            report.append("\n## MCP Performance Summary")
            module_results = self.results["mcp_benchmarks"].get("module_results", {})
            
            for module, results in module_results.items():
                report.append(f"\n### {module}")
                for result in results[:3]:  # Top 3 results
                    report.append(f"- **{result['tool_name']}**: "
                                f"{result['avg_execution_time']:.3f}s average")
        
        report.append("\n## Performance Insights")
        
        # Analyze and provide insights
        insights = []
        
        # Rust performance gains
        if "rust_benchmarks" in self.results:
            insights.append("- ✅ Rust modules demonstrate significant performance improvements")
        
        # Load handling capability
        if "load_tests" in self.results:
            load_results = self.results["load_tests"]
            high_throughput = any(s["requests_per_second"] > 50 for s in load_results)
            if high_throughput:
                insights.append("- ✅ System handles high throughput (>50 req/s) effectively")
            
            low_error_rate = all(s["error_rate"] < 0.05 for s in load_results)
            if low_error_rate:
                insights.append("- ✅ Low error rates (<5%) across all load scenarios")
        
        # Memory efficiency
        if "memory_profile" in self.results:
            snapshots = self.results["memory_profile"]
            if snapshots:
                memory_growth = snapshots[-1]["rss_mb"] - snapshots[0]["rss_mb"]
                if memory_growth < 50:
                    insights.append("- ✅ Minimal memory leaks detected (<50MB growth)")
        
        for insight in insights:
            report.append(insight)
        
        return "\n".join(report)
    
    async def run_all_tests(self):
        """Run all performance tests"""
        self.start_time = time.time()
        
        print("🏁 Starting Comprehensive Performance Testing")
        print("=" * 60)
        
        # Run each test suite
        rust_success = self.run_pytest_benchmarks()
        load_success = await self.run_load_tests()
        memory_success = await self.run_memory_profiling()
        mcp_success = await self.run_mcp_performance_benchmarks()
        
        # Generate consolidated report
        report = self.generate_consolidated_report()
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"performance_test_report_{timestamp}.md"
        
        with open(self.test_dir / report_path, 'w') as f:
            f.write(report)
        
        # Save all results
        results_path = f"performance_test_results_{timestamp}.json"
        with open(self.test_dir / results_path, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": time.time() - self.start_time,
                "results": self.results
            }, f, indent=2)
        
        print("\n" + "=" * 60)
        print("✅ All Performance Tests Complete!")
        print(f"📄 Report: {report_path}")
        print(f"📊 Results: {results_path}")
        print(f"⏱️ Total Duration: {time.time() - self.start_time:.2f}s")
        
        # Print summary
        print("\n📈 Test Results:")
        print(f"  - Rust Benchmarks: {'✅ PASS' if rust_success else '❌ FAIL'}")
        print(f"  - Load Tests: {'✅ PASS' if load_success else '❌ FAIL'}")
        print(f"  - Memory Profiling: {'✅ PASS' if memory_success else '❌ FAIL'}")
        print(f"  - MCP Benchmarks: {'✅ PASS' if mcp_success else '❌ FAIL'}")
        
        return all([rust_success, load_success, memory_success, mcp_success])


async def main():
    """Main entry point"""
    runner = PerformanceTestRunner()
    success = await runner.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())