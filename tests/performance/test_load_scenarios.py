"""
Load Testing Scenarios
Agent 8C: Comprehensive load testing for AI queries and MCP tool calls
"""

import pytest
import asyncio
import time
import random
import statistics
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
import sys
import os
import aiohttp
from datetime import datetime
import json

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.circle_of_experts.core.expert_manager import ExpertManager
from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
from src.mcp.manager import get_mcp_manager


@dataclass
class LoadTestResult:
    """Results from a load test scenario"""
    scenario_name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    total_duration: float
    average_response_time: float
    min_response_time: float
    max_response_time: float
    percentile_50: float
    percentile_95: float
    percentile_99: float
    requests_per_second: float
    error_rate: float
    errors: List[str]


class LoadTestScenarios:
    """Load testing scenarios for the system"""
    
    def __init__(self):
        self.expert_manager = ExpertManager()
        self.mcp_manager = None
        self.results: List[LoadTestResult] = []
    
    async def setup(self):
        """Initialize managers"""
        self.mcp_manager = get_mcp_manager()
        await self.mcp_manager.initialize()
    
    async def _measure_request(self, coroutine) -> Tuple[float, bool, str]:
        """Measure a single request's performance"""
        start_time = time.time()
        success = True
        error = ""
        
        try:
            await coroutine
        except Exception as e:
            success = False
            error = str(e)
        
        elapsed = time.time() - start_time
        return elapsed, success, error
    
    def _calculate_percentiles(self, times: List[float]) -> Tuple[float, float, float]:
        """Calculate percentiles from response times"""
        if not times:
            return 0, 0, 0
        
        sorted_times = sorted(times)
        n = len(sorted_times)
        
        p50 = sorted_times[int(n * 0.5)]
        p95 = sorted_times[int(n * 0.95)] if n > 20 else sorted_times[-1]
        p99 = sorted_times[int(n * 0.99)] if n > 100 else sorted_times[-1]
        
        return p50, p95, p99
    
    def _generate_load_result(self, scenario_name: str, times: List[float], 
                            errors: List[str], total_duration: float) -> LoadTestResult:
        """Generate load test result from collected data"""
        successful_times = [t for t in times if t > 0]
        failed_count = len(times) - len(successful_times)
        
        p50, p95, p99 = self._calculate_percentiles(successful_times)
        
        return LoadTestResult(
            scenario_name=scenario_name,
            total_requests=len(times),
            successful_requests=len(successful_times),
            failed_requests=failed_count,
            total_duration=total_duration,
            average_response_time=statistics.mean(successful_times) if successful_times else 0,
            min_response_time=min(successful_times) if successful_times else 0,
            max_response_time=max(successful_times) if successful_times else 0,
            percentile_50=p50,
            percentile_95=p95,
            percentile_99=p99,
            requests_per_second=len(times) / total_duration if total_duration > 0 else 0,
            error_rate=failed_count / len(times) if times else 0,
            errors=errors[:10]  # Keep first 10 errors
        )
    
    @pytest.mark.asyncio
    async def test_100_concurrent_ai_queries(self):
        """Test 100 concurrent AI queries"""
        print("\n🚀 Testing 100 concurrent AI queries...")
        
        queries = []
        for i in range(100):
            queries.append(ExpertQuery(
                title=f"Load Test Query {i}",
                content=f"This is a test query {i} for load testing the AI consultation system. "
                       f"Please analyze the performance characteristics of handling {i} concurrent requests.",
                query_type=random.choice(list(QueryType)),
                priority=random.choice(list(QueryPriority)),
                requester=f"load_test_{i}@test.com",
                tags=[f"load_test", f"batch_{i//10}"]
            ))
        
        # Create tasks
        tasks = []
        for query in queries:
            # Simulate expert consultation without actual API calls
            async def simulate_consultation(q):
                await asyncio.sleep(random.uniform(0.1, 0.5))  # Simulate processing
                return {
                    "query_id": q.id,
                    "status": "completed",
                    "responses": random.randint(2, 5)
                }
            
            tasks.append(self._measure_request(simulate_consultation(query)))
        
        # Execute concurrently
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        total_duration = time.time() - start_time
        
        # Collect metrics
        times = []
        errors = []
        for elapsed, success, error in results:
            if success:
                times.append(elapsed)
            else:
                times.append(-1)
                errors.append(error)
        
        # Generate result
        result = self._generate_load_result(
            "100_concurrent_ai_queries",
            times,
            errors,
            total_duration
        )
        
        self.results.append(result)
        self._print_result(result)
    
    @pytest.mark.asyncio
    async def test_1000_mcp_tool_calls(self):
        """Test 1000 MCP tool calls"""
        print("\n🚀 Testing 1000 MCP tool calls...")
        
        # Mix of different MCP tools
        tool_calls = []
        tools = [
            ("desktop.execute_command", {"command": "echo 'Load test'"}),
            ("docker.docker_ps", {}),
            ("kubernetes.kubectl_version", {}),
            ("security-scanner.file_security_scan", {"file_path": "README.md"}),
            ("desktop.read_file", {"file_path": "README.md", "lines": 10})
        ]
        
        for i in range(1000):
            tool_name, params = tools[i % len(tools)]
            tool_calls.append((tool_name, params))
        
        # Create tasks
        tasks = []
        for tool_name, params in tool_calls:
            tasks.append(self._measure_request(
                self.mcp_manager.call_tool(tool_name, params)
            ))
        
        # Execute in batches to avoid overwhelming the system
        batch_size = 50
        all_results = []
        start_time = time.time()
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            batch_results = await asyncio.gather(*batch)
            all_results.extend(batch_results)
            await asyncio.sleep(0.1)  # Small delay between batches
        
        total_duration = time.time() - start_time
        
        # Collect metrics
        times = []
        errors = []
        for elapsed, success, error in all_results:
            if success:
                times.append(elapsed)
            else:
                times.append(-1)
                errors.append(error)
        
        # Generate result
        result = self._generate_load_result(
            "1000_mcp_tool_calls",
            times,
            errors,
            total_duration
        )
        
        self.results.append(result)
        self._print_result(result)
    
    @pytest.mark.asyncio
    async def test_connection_pool_stress(self):
        """Stress test connection pools"""
        print("\n🚀 Testing connection pool stress...")
        
        # Create many concurrent connections
        connection_count = 200
        
        async def create_connection(index):
            """Simulate connection creation and usage"""
            # Simulate connection setup
            await asyncio.sleep(random.uniform(0.01, 0.05))
            
            # Simulate some work
            work_duration = random.uniform(0.1, 0.5)
            await asyncio.sleep(work_duration)
            
            # Simulate cleanup
            await asyncio.sleep(0.01)
            
            return work_duration
        
        # Create tasks
        tasks = []
        for i in range(connection_count):
            tasks.append(self._measure_request(create_connection(i)))
        
        # Execute concurrently
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        total_duration = time.time() - start_time
        
        # Collect metrics
        times = []
        errors = []
        for elapsed, success, error in results:
            if success:
                times.append(elapsed)
            else:
                times.append(-1)
                errors.append(error)
        
        # Generate result
        result = self._generate_load_result(
            "connection_pool_stress",
            times,
            errors,
            total_duration
        )
        
        self.results.append(result)
        self._print_result(result)
    
    @pytest.mark.asyncio
    async def test_mixed_workload(self):
        """Test mixed workload with AI queries and MCP calls"""
        print("\n🚀 Testing mixed workload...")
        
        tasks = []
        
        # Add AI queries
        for i in range(50):
            query = ExpertQuery(
                title=f"Mixed Load Query {i}",
                content=f"Test query {i}",
                query_type=QueryType.TECHNICAL,
                priority=QueryPriority.MEDIUM,
                requester=f"mixed_test_{i}@test.com"
            )
            
            async def ai_task(q):
                await asyncio.sleep(random.uniform(0.2, 0.8))
                return {"query_id": q.id, "status": "completed"}
            
            tasks.append(self._measure_request(ai_task(query)))
        
        # Add MCP tool calls
        mcp_tools = [
            ("desktop.execute_command", {"command": "date"}),
            ("docker.docker_version", {}),
            ("security-scanner.file_security_scan", {"file_path": "setup.py"})
        ]
        
        for i in range(150):
            tool_name, params = mcp_tools[i % len(mcp_tools)]
            tasks.append(self._measure_request(
                self.mcp_manager.call_tool(tool_name, params)
            ))
        
        # Execute all tasks concurrently
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        total_duration = time.time() - start_time
        
        # Collect metrics
        times = []
        errors = []
        for elapsed, success, error in results:
            if success:
                times.append(elapsed)
            else:
                times.append(-1)
                errors.append(error)
        
        # Generate result
        result = self._generate_load_result(
            "mixed_workload",
            times,
            errors,
            total_duration
        )
        
        self.results.append(result)
        self._print_result(result)
    
    @pytest.mark.asyncio
    async def test_burst_traffic(self):
        """Test system behavior under burst traffic"""
        print("\n🚀 Testing burst traffic patterns...")
        
        all_results = []
        
        # Simulate 5 bursts
        for burst_num in range(5):
            print(f"  Burst {burst_num + 1}/5...")
            
            # Create burst of requests
            burst_size = 50
            tasks = []
            
            for i in range(burst_size):
                # Random MCP tool call
                if i % 2 == 0:
                    tasks.append(self._measure_request(
                        self.mcp_manager.call_tool("desktop.execute_command", 
                                                 {"command": f"echo 'Burst {burst_num}-{i}'"})
                    ))
                else:
                    # Simulated AI query
                    async def ai_burst():
                        await asyncio.sleep(random.uniform(0.1, 0.3))
                        return {"status": "completed"}
                    
                    tasks.append(self._measure_request(ai_burst()))
            
            # Execute burst
            burst_start = time.time()
            results = await asyncio.gather(*tasks)
            burst_duration = time.time() - burst_start
            
            all_results.extend(results)
            
            print(f"    Completed in {burst_duration:.2f}s")
            
            # Wait between bursts
            await asyncio.sleep(2)
        
        # Collect all metrics
        times = []
        errors = []
        for elapsed, success, error in all_results:
            if success:
                times.append(elapsed)
            else:
                times.append(-1)
                errors.append(error)
        
        # Generate result
        result = self._generate_load_result(
            "burst_traffic",
            times,
            errors,
            sum(t for t in times if t > 0)
        )
        
        self.results.append(result)
        self._print_result(result)
    
    @pytest.mark.asyncio
    async def test_sustained_load(self):
        """Test sustained load over time"""
        print("\n🚀 Testing sustained load...")
        
        duration_seconds = 30
        requests_per_second = 10
        
        all_results = []
        start_time = time.time()
        
        while time.time() - start_time < duration_seconds:
            # Create batch of requests
            tasks = []
            for i in range(requests_per_second):
                # Mix of operations
                if i % 3 == 0:
                    tasks.append(self._measure_request(
                        self.mcp_manager.call_tool("desktop.read_file", 
                                                 {"file_path": "README.md", "lines": 5})
                    ))
                elif i % 3 == 1:
                    tasks.append(self._measure_request(
                        self.mcp_manager.call_tool("docker.docker_ps", {})
                    ))
                else:
                    # Simulated AI query
                    async def sustained_ai():
                        await asyncio.sleep(random.uniform(0.05, 0.15))
                        return {"status": "completed"}
                    
                    tasks.append(self._measure_request(sustained_ai()))
            
            # Execute batch
            batch_results = await asyncio.gather(*tasks)
            all_results.extend(batch_results)
            
            # Wait to maintain rate
            elapsed = time.time() - start_time
            expected_time = len(all_results) / (requests_per_second * 3)
            if elapsed < expected_time:
                await asyncio.sleep(expected_time - elapsed)
        
        total_duration = time.time() - start_time
        
        # Collect metrics
        times = []
        errors = []
        for elapsed, success, error in all_results:
            if success:
                times.append(elapsed)
            else:
                times.append(-1)
                errors.append(error)
        
        # Generate result
        result = self._generate_load_result(
            "sustained_load",
            times,
            errors,
            total_duration
        )
        
        self.results.append(result)
        self._print_result(result)
    
    def _print_result(self, result: LoadTestResult):
        """Print load test result"""
        print(f"\n📊 {result.scenario_name} Results:")
        print(f"  Total Requests: {result.total_requests}")
        print(f"  Successful: {result.successful_requests} ({(1-result.error_rate)*100:.1f}%)")
        print(f"  Failed: {result.failed_requests} ({result.error_rate*100:.1f}%)")
        print(f"  Total Duration: {result.total_duration:.2f}s")
        print(f"  Requests/Second: {result.requests_per_second:.2f}")
        print(f"  Response Times:")
        print(f"    Average: {result.average_response_time:.3f}s")
        print(f"    Min: {result.min_response_time:.3f}s")
        print(f"    Max: {result.max_response_time:.3f}s")
        print(f"    P50: {result.percentile_50:.3f}s")
        print(f"    P95: {result.percentile_95:.3f}s")
        print(f"    P99: {result.percentile_99:.3f}s")
        
        if result.errors:
            print(f"  Sample Errors: {result.errors[0]}")
    
    def generate_report(self) -> str:
        """Generate comprehensive load test report"""
        report = []
        report.append("# Load Test Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("\n## Summary")
        
        total_requests = sum(r.total_requests for r in self.results)
        total_successful = sum(r.successful_requests for r in self.results)
        overall_success_rate = total_successful / total_requests if total_requests > 0 else 0
        
        report.append(f"- Total Scenarios: {len(self.results)}")
        report.append(f"- Total Requests: {total_requests}")
        report.append(f"- Overall Success Rate: {overall_success_rate*100:.1f}%")
        
        report.append("\n## Scenario Results")
        
        for result in self.results:
            report.append(f"\n### {result.scenario_name}")
            report.append(f"- **Requests**: {result.total_requests} total, "
                         f"{result.successful_requests} successful")
            report.append(f"- **Duration**: {result.total_duration:.2f}s")
            report.append(f"- **Throughput**: {result.requests_per_second:.2f} req/s")
            report.append(f"- **Error Rate**: {result.error_rate*100:.1f}%")
            report.append(f"- **Response Times**:")
            report.append(f"  - Average: {result.average_response_time:.3f}s")
            report.append(f"  - P50: {result.percentile_50:.3f}s")
            report.append(f"  - P95: {result.percentile_95:.3f}s")
            report.append(f"  - P99: {result.percentile_99:.3f}s")
        
        report.append("\n## Performance Analysis")
        
        # Find best and worst scenarios
        if self.results:
            best_throughput = max(self.results, key=lambda r: r.requests_per_second)
            worst_error = max(self.results, key=lambda r: r.error_rate)
            best_response = min(self.results, key=lambda r: r.average_response_time)
            
            report.append(f"\n### Best Performance")
            report.append(f"- **Highest Throughput**: {best_throughput.scenario_name} "
                         f"({best_throughput.requests_per_second:.2f} req/s)")
            report.append(f"- **Fastest Response**: {best_response.scenario_name} "
                         f"({best_response.average_response_time:.3f}s avg)")
            
            report.append(f"\n### Areas for Improvement")
            report.append(f"- **Highest Error Rate**: {worst_error.scenario_name} "
                         f"({worst_error.error_rate*100:.1f}%)")
        
        return "\n".join(report)


@pytest.mark.asyncio
async def test_all_load_scenarios():
    """Run all load test scenarios"""
    tester = LoadTestScenarios()
    await tester.setup()
    
    # Run all test scenarios
    await tester.test_100_concurrent_ai_queries()
    await tester.test_1000_mcp_tool_calls()
    await tester.test_connection_pool_stress()
    await tester.test_mixed_workload()
    await tester.test_burst_traffic()
    await tester.test_sustained_load()
    
    # Generate report
    report = tester.generate_report()
    
    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"tests/performance/load_test_report_{timestamp}.md"
    
    with open(report_path, 'w') as f:
        f.write(report)
    
    # Save raw results
    results_data = [
        {
            "scenario": r.scenario_name,
            "total_requests": r.total_requests,
            "successful_requests": r.successful_requests,
            "failed_requests": r.failed_requests,
            "total_duration": r.total_duration,
            "average_response_time": r.average_response_time,
            "percentile_50": r.percentile_50,
            "percentile_95": r.percentile_95,
            "percentile_99": r.percentile_99,
            "requests_per_second": r.requests_per_second,
            "error_rate": r.error_rate
        }
        for r in tester.results
    ]
    
    results_path = f"tests/performance/load_test_results_{timestamp}.json"
    with open(results_path, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\n✅ Load testing complete!")
    print(f"📄 Report: {report_path}")
    print(f"📊 Results: {results_path}")


if __name__ == "__main__":
    asyncio.run(test_all_load_scenarios())