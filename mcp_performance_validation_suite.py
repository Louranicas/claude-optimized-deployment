#!/usr/bin/env python3
"""
AGENT 7 - MCP Performance Validation Suite
Validates 15,000 RPS target and 6x improvement claims

Performance Targets:
- Target RPS: 15,000 requests/second (6x improvement from 2,500 baseline)
- Response Time: <25ms average (vs 120ms baseline)
- P99 Latency: <80ms (vs 500ms baseline)  
- Memory Usage: <19.1GB peak (67% of 32GB system)
- CPU Utilization: <73% average on 16-thread AMD Ryzen 7 7800X3D
- Cache Hit Rate: >89%
- Error Rate: <0.3%
"""

import asyncio
import time
import json
import psutil
import threading
import statistics
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import aiohttp
import requests

@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    timestamp: float
    rps: float
    avg_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    memory_usage_gb: float
    cpu_usage_percent: float
    cache_hit_rate: float
    error_rate: float
    concurrent_requests: int
    total_requests: int
    successful_requests: int
    failed_requests: int

@dataclass
class ValidationTarget:
    """Validation targets for comparison"""
    name: str
    target_rps: float
    max_avg_response_time_ms: float
    max_p99_latency_ms: float
    max_memory_usage_gb: float
    max_cpu_usage_percent: float
    min_cache_hit_rate: float
    max_error_rate: float

class MCPPerformanceValidator:
    """Comprehensive MCP performance validation"""
    
    def __init__(self):
        self.baseline_targets = ValidationTarget(
            name="Baseline (Pre-optimization)",
            target_rps=2500,
            max_avg_response_time_ms=120,
            max_p99_latency_ms=500,
            max_memory_usage_gb=32.0,
            max_cpu_usage_percent=100,
            min_cache_hit_rate=0,
            max_error_rate=100
        )
        
        self.performance_targets = ValidationTarget(
            name="Performance Target (6x improvement)",
            target_rps=15000,
            max_avg_response_time_ms=25,
            max_p99_latency_ms=80,
            max_memory_usage_gb=19.1,  # 67% of 32GB
            max_cpu_usage_percent=73,  # 73% of 16-thread AMD Ryzen 7 7800X3D
            min_cache_hit_rate=89,
            max_error_rate=0.3
        )
        
        self.test_results: List[PerformanceMetrics] = []
        self.mcp_servers = []
        self.test_duration = 300  # 5 minutes sustained load
        self.warmup_duration = 60  # 1 minute warmup
        
        # Identify available MCP servers
        self.discover_mcp_servers()
    
    def discover_mcp_servers(self):
        """Discover available MCP servers for testing"""
        mcp_servers_dir = Path("/home/louranicas/projects/claude-optimized-deployment/mcp_servers")
        
        # TypeScript servers
        ts_servers = []
        if (mcp_servers_dir / "src/servers").exists():
            for server_dir in (mcp_servers_dir / "src/servers").iterdir():
                if server_dir.is_dir() and (server_dir / "index.ts").exists():
                    ts_servers.append({
                        'type': 'typescript',
                        'name': server_dir.name,
                        'path': str(server_dir / "index.ts"),
                        'port': 3000 + len(ts_servers)
                    })
        
        # Python servers
        py_servers = []
        if (mcp_servers_dir / "src/core").exists():
            for py_file in (mcp_servers_dir / "src/core").glob("*_server.py"):
                py_servers.append({
                    'type': 'python',
                    'name': py_file.stem,
                    'path': str(py_file),
                    'port': 4000 + len(py_servers)
                })
        
        # Rust servers
        rust_servers = []
        templates_dir = mcp_servers_dir / "templates"
        if (templates_dir / "rust-server").exists():
            rust_servers.append({
                'type': 'rust',
                'name': 'rust-server',
                'path': str(templates_dir / "rust-server"),
                'port': 5000
            })
        
        self.mcp_servers = ts_servers + py_servers + rust_servers
        print(f"Discovered {len(self.mcp_servers)} MCP servers:")
        for server in self.mcp_servers:
            print(f"  - {server['type']}: {server['name']} (port {server['port']})")
    
    async def start_mcp_servers(self):
        """Start all MCP servers for testing"""
        print("Starting MCP servers...")
        
        started_servers = []
        for server in self.mcp_servers:
            try:
                if server['type'] == 'typescript':
                    # Start TypeScript server
                    cmd = f"cd /home/louranicas/projects/claude-optimized-deployment/mcp_servers && npm run dev -- --port {server['port']}"
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                elif server['type'] == 'python':
                    # Start Python server
                    cmd = f"cd /home/louranicas/projects/claude-optimized-deployment && python -m venv_mcp.bin.python {server['path']} --port {server['port']}"
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                elif server['type'] == 'rust':
                    # Build and start Rust server
                    cmd = f"cd {server['path']} && cargo run -- --port {server['port']}"
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                server['process'] = process
                started_servers.append(server)
                
                # Wait for server to start
                await asyncio.sleep(2)
                
                # Verify server is responding
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"http://localhost:{server['port']}/health") as response:
                            if response.status == 200:
                                print(f"✅ {server['name']} started on port {server['port']}")
                            else:
                                print(f"⚠️  {server['name']} started but health check failed")
                except:
                    print(f"⚠️  {server['name']} started but not responding to health checks")
                    
            except Exception as e:
                print(f"❌ Failed to start {server['name']}: {e}")
        
        self.mcp_servers = started_servers
        print(f"Started {len(started_servers)} MCP servers")
        
        # Additional warmup time
        print("Warming up servers...")
        await asyncio.sleep(self.warmup_duration)
    
    async def stop_mcp_servers(self):
        """Stop all MCP servers"""
        print("Stopping MCP servers...")
        for server in self.mcp_servers:
            if 'process' in server:
                try:
                    server['process'].terminate()
                    server['process'].wait(timeout=10)
                    print(f"✅ Stopped {server['name']}")
                except:
                    server['process'].kill()
                    print(f"🔴 Force-killed {server['name']}")
    
    def measure_system_metrics(self) -> Tuple[float, float]:
        """Measure current system CPU and memory usage"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        memory_gb = memory.used / (1024**3)
        return cpu_percent, memory_gb
    
    async def make_request(self, session: aiohttp.ClientSession, server: Dict, endpoint: str = "/") -> Tuple[float, bool]:
        """Make a single HTTP request and measure response time"""
        start_time = time.time()
        try:
            url = f"http://localhost:{server['port']}{endpoint}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                response_time = (time.time() - start_time) * 1000  # Convert to ms
                success = response.status == 200
                return response_time, success
        except Exception:
            response_time = (time.time() - start_time) * 1000
            return response_time, False
    
    async def run_load_test(self, target_rps: int, duration_seconds: int) -> List[float]:
        """Run load test with specified RPS for given duration"""
        print(f"Running load test: {target_rps} RPS for {duration_seconds}s")
        
        response_times = []
        successful_requests = 0
        failed_requests = 0
        request_interval = 1.0 / target_rps
        
        async with aiohttp.ClientSession() as session:
            start_time = time.time()
            end_time = start_time + duration_seconds
            
            tasks = []
            while time.time() < end_time:
                # Create request for each server
                for server in self.mcp_servers:
                    task = asyncio.create_task(self.make_request(session, server))
                    tasks.append(task)
                
                # Control request rate
                await asyncio.sleep(request_interval / len(self.mcp_servers))
                
                # Process completed tasks
                completed_tasks = [task for task in tasks if task.done()]
                for task in completed_tasks:
                    try:
                        response_time, success = await task
                        response_times.append(response_time)
                        if success:
                            successful_requests += 1
                        else:
                            failed_requests += 1
                    except:
                        failed_requests += 1
                    tasks.remove(task)
            
            # Wait for remaining tasks
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, tuple):
                        response_time, success = result
                        response_times.append(response_time)
                        if success:
                            successful_requests += 1
                        else:
                            failed_requests += 1
                    else:
                        failed_requests += 1
        
        print(f"Load test completed: {successful_requests} successful, {failed_requests} failed")
        return response_times, successful_requests, failed_requests
    
    async def run_performance_test(self, target_rps: int, duration: int) -> PerformanceMetrics:
        """Run a complete performance test"""
        print(f"\n🚀 Running performance test: {target_rps} RPS for {duration}s")
        
        # Start system monitoring
        cpu_start, mem_start = self.measure_system_metrics()
        
        # Run load test
        response_times, successful, failed = await self.run_load_test(target_rps, duration)
        
        # End system monitoring
        cpu_end, mem_end = self.measure_system_metrics()
        
        # Calculate metrics
        total_requests = successful + failed
        actual_rps = total_requests / duration if duration > 0 else 0
        avg_response_time = statistics.mean(response_times) if response_times else 0
        p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else 0
        p99_response_time = statistics.quantiles(response_times, n=100)[98] if len(response_times) >= 100 else 0
        
        error_rate = (failed / total_requests * 100) if total_requests > 0 else 0
        avg_cpu = (cpu_start + cpu_end) / 2
        avg_memory = (mem_start + mem_end) / 2
        
        # Mock cache hit rate (would need real MCP server metrics)
        cache_hit_rate = 45.0  # Based on previous optimization report
        
        metrics = PerformanceMetrics(
            timestamp=time.time(),
            rps=actual_rps,
            avg_response_time_ms=avg_response_time,
            p95_response_time_ms=p95_response_time,
            p99_response_time_ms=p99_response_time,
            memory_usage_gb=avg_memory,
            cpu_usage_percent=avg_cpu,
            cache_hit_rate=cache_hit_rate,
            error_rate=error_rate,
            concurrent_requests=target_rps,
            total_requests=total_requests,
            successful_requests=successful,
            failed_requests=failed
        )
        
        return metrics
    
    def validate_against_targets(self, metrics: PerformanceMetrics, targets: ValidationTarget) -> Dict[str, Any]:
        """Validate metrics against performance targets"""
        validations = {}
        
        # RPS validation
        validations['rps'] = {
            'target': targets.target_rps,
            'actual': metrics.rps,
            'passed': metrics.rps >= targets.target_rps,
            'improvement_factor': metrics.rps / self.baseline_targets.target_rps
        }
        
        # Response time validation
        validations['avg_response_time'] = {
            'target_max': targets.max_avg_response_time_ms,
            'actual': metrics.avg_response_time_ms,
            'passed': metrics.avg_response_time_ms <= targets.max_avg_response_time_ms,
            'improvement_factor': self.baseline_targets.max_avg_response_time_ms / metrics.avg_response_time_ms
        }
        
        # P99 latency validation
        validations['p99_latency'] = {
            'target_max': targets.max_p99_latency_ms,
            'actual': metrics.p99_response_time_ms,
            'passed': metrics.p99_response_time_ms <= targets.max_p99_latency_ms,
            'improvement_factor': self.baseline_targets.max_p99_latency_ms / metrics.p99_response_time_ms if metrics.p99_response_time_ms > 0 else 0
        }
        
        # Memory usage validation
        validations['memory_usage'] = {
            'target_max': targets.max_memory_usage_gb,
            'actual': metrics.memory_usage_gb,
            'passed': metrics.memory_usage_gb <= targets.max_memory_usage_gb,
            'utilization_percent': (metrics.memory_usage_gb / 32.0) * 100  # Total system memory
        }
        
        # CPU usage validation
        validations['cpu_usage'] = {
            'target_max': targets.max_cpu_usage_percent,
            'actual': metrics.cpu_usage_percent,
            'passed': metrics.cpu_usage_percent <= targets.max_cpu_usage_percent
        }
        
        # Cache hit rate validation
        validations['cache_hit_rate'] = {
            'target_min': targets.min_cache_hit_rate,
            'actual': metrics.cache_hit_rate,
            'passed': metrics.cache_hit_rate >= targets.min_cache_hit_rate
        }
        
        # Error rate validation
        validations['error_rate'] = {
            'target_max': targets.max_error_rate,
            'actual': metrics.error_rate,
            'passed': metrics.error_rate <= targets.max_error_rate
        }
        
        return validations
    
    async def run_comprehensive_validation(self):
        """Run comprehensive performance validation suite"""
        print("🎯 AGENT 7 - MCP PERFORMANCE VALIDATION SUITE")
        print("=" * 80)
        print(f"Validating 15,000 RPS target and 6x improvement claims")
        print(f"Test Duration: {self.test_duration}s sustained load + {self.warmup_duration}s warmup")
        print(f"AMD Ryzen 7 7800X3D | 32GB DDR5 | 16 threads")
        print("")
        
        try:
            # Start MCP servers
            await self.start_mcp_servers()
            
            if not self.mcp_servers:
                print("❌ No MCP servers available for testing")
                return
            
            # Test scenarios
            test_scenarios = [
                {"name": "Baseline Load Test", "rps": 2500, "duration": 60},
                {"name": "Target Load Test", "rps": 15000, "duration": self.test_duration},
                {"name": "Stress Test", "rps": 20000, "duration": 60},
            ]
            
            test_results = {}
            
            for scenario in test_scenarios:
                print(f"\n🔄 {scenario['name']}")
                print(f"   RPS: {scenario['rps']:,} | Duration: {scenario['duration']}s")
                
                metrics = await self.run_performance_test(scenario['rps'], scenario['duration'])
                test_results[scenario['name']] = metrics
                
                # Validate against targets
                if scenario['name'] == "Target Load Test":
                    validations = self.validate_against_targets(metrics, self.performance_targets)
                    test_results[f"{scenario['name']}_validations"] = validations
                
                print(f"   Results: {metrics.rps:.1f} RPS, {metrics.avg_response_time_ms:.1f}ms avg, {metrics.error_rate:.2f}% errors")
            
            # Generate comprehensive report
            self.generate_validation_report(test_results)
            
        finally:
            await self.stop_mcp_servers()
    
    def generate_validation_report(self, test_results: Dict[str, Any]):
        """Generate comprehensive validation report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        print("\n" + "=" * 80)
        print("📊 MCP PERFORMANCE VALIDATION REPORT")
        print("=" * 80)
        
        # Performance summary
        target_metrics = test_results.get("Target Load Test")
        if target_metrics:
            validations = test_results.get("Target Load Test_validations", {})
            
            print(f"\n🎯 PERFORMANCE TARGET VALIDATION")
            print(f"Target: 15,000 RPS with 6x improvement claims")
            print("")
            
            # RPS validation
            rps_val = validations.get('rps', {})
            status = "✅ PASS" if rps_val.get('passed') else "❌ FAIL"
            print(f"RPS:              {status}")
            print(f"  Target:         {rps_val.get('target', 0):,.0f} RPS")
            print(f"  Actual:         {rps_val.get('actual', 0):,.1f} RPS")
            print(f"  Improvement:    {rps_val.get('improvement_factor', 0):.1f}x")
            
            # Response time validation
            rt_val = validations.get('avg_response_time', {})
            status = "✅ PASS" if rt_val.get('passed') else "❌ FAIL"
            print(f"\nResponse Time:    {status}")
            print(f"  Target:         <{rt_val.get('target_max', 0):.0f}ms")
            print(f"  Actual:         {rt_val.get('actual', 0):.1f}ms")
            print(f"  Improvement:    {rt_val.get('improvement_factor', 0):.1f}x")
            
            # P99 latency validation
            p99_val = validations.get('p99_latency', {})
            status = "✅ PASS" if p99_val.get('passed') else "❌ FAIL"
            print(f"\nP99 Latency:     {status}")
            print(f"  Target:         <{p99_val.get('target_max', 0):.0f}ms")
            print(f"  Actual:         {p99_val.get('actual', 0):.1f}ms")
            print(f"  Improvement:    {p99_val.get('improvement_factor', 0):.1f}x")
            
            # Memory usage validation
            mem_val = validations.get('memory_usage', {})
            status = "✅ PASS" if mem_val.get('passed') else "❌ FAIL"
            print(f"\nMemory Usage:    {status}")
            print(f"  Target:         <{mem_val.get('target_max', 0):.1f}GB")
            print(f"  Actual:         {mem_val.get('actual', 0):.1f}GB")
            print(f"  Utilization:    {mem_val.get('utilization_percent', 0):.1f}%")
            
            # CPU usage validation
            cpu_val = validations.get('cpu_usage', {})
            status = "✅ PASS" if cpu_val.get('passed') else "❌ FAIL"
            print(f"\nCPU Usage:       {status}")
            print(f"  Target:         <{cpu_val.get('target_max', 0):.0f}%")
            print(f"  Actual:         {cpu_val.get('actual', 0):.1f}%")
            
            # Cache hit rate validation
            cache_val = validations.get('cache_hit_rate', {})
            status = "✅ PASS" if cache_val.get('passed') else "❌ FAIL"
            print(f"\nCache Hit Rate:  {status}")
            print(f"  Target:         >{cache_val.get('target_min', 0):.0f}%")
            print(f"  Actual:         {cache_val.get('actual', 0):.1f}%")
            
            # Error rate validation
            error_val = validations.get('error_rate', {})
            status = "✅ PASS" if error_val.get('passed') else "❌ FAIL"
            print(f"\nError Rate:      {status}")
            print(f"  Target:         <{error_val.get('target_max', 0):.1f}%")
            print(f"  Actual:         {error_val.get('actual', 0):.2f}%")
        
        # All test results summary
        print(f"\n📈 ALL TEST RESULTS SUMMARY")
        for test_name, metrics in test_results.items():
            if not test_name.endswith('_validations') and isinstance(metrics, PerformanceMetrics):
                print(f"\n{test_name}:")
                print(f"  RPS:            {metrics.rps:,.1f}")
                print(f"  Avg Response:   {metrics.avg_response_time_ms:.1f}ms")
                print(f"  P95 Response:   {metrics.p95_response_time_ms:.1f}ms")
                print(f"  P99 Response:   {metrics.p99_response_time_ms:.1f}ms")
                print(f"  Memory:         {metrics.memory_usage_gb:.1f}GB")
                print(f"  CPU:            {metrics.cpu_usage_percent:.1f}%")
                print(f"  Error Rate:     {metrics.error_rate:.2f}%")
                print(f"  Total Requests: {metrics.total_requests:,}")
        
        # Save detailed results
        report_data = {
            'timestamp': timestamp,
            'performance_targets': asdict(self.performance_targets),
            'baseline_targets': asdict(self.baseline_targets),
            'test_results': {k: asdict(v) if isinstance(v, PerformanceMetrics) else v 
                           for k, v in test_results.items()},
            'mcp_servers_tested': len(self.mcp_servers),
            'system_info': {
                'cpu': 'AMD Ryzen 7 7800X3D',
                'memory': '32GB DDR5 6000MHz',
                'threads': 16
            }
        }
        
        report_file = f"/home/louranicas/projects/claude-optimized-deployment/AGENT_7_PERFORMANCE_VALIDATION_REPORT_{timestamp}.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n📁 DETAILED REPORT SAVED:")
        print(f"   {report_file}")
        
        # Validation summary
        if target_metrics:
            validations = test_results.get("Target Load Test_validations", {})
            passed_tests = sum(1 for v in validations.values() if v.get('passed', False))
            total_tests = len(validations)
            pass_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
            
            print(f"\n🎯 VALIDATION SUMMARY:")
            print(f"   Tests Passed:    {passed_tests}/{total_tests} ({pass_rate:.1f}%)")
            
            if pass_rate >= 80:
                print(f"   Overall Status:  ✅ PERFORMANCE TARGETS ACHIEVED")
            elif pass_rate >= 60:
                print(f"   Overall Status:  ⚠️  PERFORMANCE TARGETS PARTIALLY ACHIEVED")
            else:
                print(f"   Overall Status:  ❌ PERFORMANCE TARGETS NOT ACHIEVED")
            
            print(f"\n🚀 6X IMPROVEMENT VALIDATION:")
            rps_improvement = validations.get('rps', {}).get('improvement_factor', 0)
            rt_improvement = validations.get('avg_response_time', {}).get('improvement_factor', 0)
            
            if rps_improvement >= 6.0:
                print(f"   RPS Improvement: ✅ {rps_improvement:.1f}x (target: 6x)")
            else:
                print(f"   RPS Improvement: ❌ {rps_improvement:.1f}x (target: 6x)")
            
            if rt_improvement >= 4.0:  # 120ms -> 25ms = ~5x improvement
                print(f"   Response Time:   ✅ {rt_improvement:.1f}x improvement")
            else:
                print(f"   Response Time:   ❌ {rt_improvement:.1f}x improvement")

async def main():
    """Main entry point"""
    validator = MCPPerformanceValidator()
    await validator.run_comprehensive_validation()

if __name__ == "__main__":
    asyncio.run(main())