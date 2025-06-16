#!/usr/bin/env python3
"""
API Performance Benchmark Suite
Tests API integrations under various load conditions and scenarios.
"""

import asyncio
import aiohttp
import json
import logging
import time
import statistics
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Test API keys
TAVILY_KEY = "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"
BRAVE_KEY = "BSAigVAUU4-V72PjB48t8_CqN00Hh5z"


@dataclass
class BenchmarkResult:
    """Benchmark test result."""
    test_name: str
    success_count: int
    failure_count: int
    total_requests: int
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    requests_per_second: float
    error_rate: float
    errors: List[str]


class APIBenchmark:
    """Performance benchmark suite for API integrations."""
    
    def __init__(self):
        self.results = {}
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            connector=aiohttp.TCPConnector(limit=100)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def make_tavily_request(self, query: str) -> Dict[str, Any]:
        """Make a single Tavily API request."""
        url = "https://api.tavily.com/search"
        payload = {
            "api_key": TAVILY_KEY,
            "query": query,
            "search_depth": "basic",
            "max_results": 3
        }
        
        start_time = time.time()
        try:
            async with self.session.post(url, json=payload) as response:
                response_time = time.time() - start_time
                data = await response.json()
                
                return {
                    'success': response.status == 200,
                    'response_time': response_time,
                    'status_code': response.status,
                    'data': data,
                    'error': None
                }
        except Exception as e:
            response_time = time.time() - start_time
            return {
                'success': False,
                'response_time': response_time,
                'status_code': None,
                'data': None,
                'error': str(e)
            }
    
    async def make_brave_request(self, query: str) -> Dict[str, Any]:
        """Make a single Brave API request."""
        url = "https://api.search.brave.com/res/v1/web/search"
        headers = {
            'X-Subscription-Token': BRAVE_KEY,
            'Accept': 'application/json'
        }
        params = {
            'q': query,
            'count': 3,
            'safesearch': 'moderate'
        }
        
        start_time = time.time()
        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                response_time = time.time() - start_time
                data = await response.json()
                
                return {
                    'success': response.status == 200,
                    'response_time': response_time,
                    'status_code': response.status,
                    'data': data,
                    'error': None
                }
        except Exception as e:
            response_time = time.time() - start_time
            return {
                'success': False,
                'response_time': response_time,
                'status_code': None,
                'data': None,
                'error': str(e)
            }
    
    async def benchmark_sequential_requests(self, api_name: str, num_requests: int = 10) -> BenchmarkResult:
        """Benchmark sequential API requests."""
        logger.info(f"Starting sequential benchmark: {api_name} ({num_requests} requests)")
        
        queries = [f"test query {i}" for i in range(num_requests)]
        results = []
        errors = []
        
        start_time = time.time()
        
        for i, query in enumerate(queries):
            if api_name == "tavily":
                result = await self.make_tavily_request(query)
            elif api_name == "brave":
                result = await self.make_brave_request(query)
            else:
                continue
            
            results.append(result)
            if not result['success']:
                errors.append(f"Request {i+1}: {result['error']}")
            
            logger.info(f"  Request {i+1}/{num_requests}: {'✓' if result['success'] else '✗'} "
                       f"({result['response_time']:.2f}s)")
            
            # Add small delay to respect rate limits
            await asyncio.sleep(1.5)
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        success_count = sum(1 for r in results if r['success'])
        failure_count = len(results) - success_count
        response_times = [r['response_time'] for r in results if r['success']]
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
        else:
            avg_response_time = min_response_time = max_response_time = 0
        
        requests_per_second = len(results) / total_time if total_time > 0 else 0
        error_rate = (failure_count / len(results)) * 100 if results else 0
        
        return BenchmarkResult(
            test_name=f"{api_name}_sequential_{num_requests}",
            success_count=success_count,
            failure_count=failure_count,
            total_requests=len(results),
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            errors=errors
        )
    
    async def benchmark_concurrent_requests(self, api_name: str, num_requests: int = 5) -> BenchmarkResult:
        """Benchmark concurrent API requests."""
        logger.info(f"Starting concurrent benchmark: {api_name} ({num_requests} concurrent requests)")
        
        queries = [f"concurrent test {i}" for i in range(num_requests)]
        
        start_time = time.time()
        
        if api_name == "tavily":
            tasks = [self.make_tavily_request(query) for query in queries]
        elif api_name == "brave":
            tasks = [self.make_brave_request(query) for query in queries]
        else:
            return BenchmarkResult("invalid", 0, 0, 0, 0, 0, 0, 0, 100, ["Invalid API name"])
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.time() - start_time
        
        # Process results
        processed_results = []
        errors = []
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    'success': False,
                    'response_time': 0,
                    'error': str(result)
                })
                errors.append(f"Request {i+1}: {str(result)}")
            else:
                processed_results.append(result)
                if not result['success']:
                    errors.append(f"Request {i+1}: {result['error']}")
        
        # Calculate statistics
        success_count = sum(1 for r in processed_results if r['success'])
        failure_count = len(processed_results) - success_count
        response_times = [r['response_time'] for r in processed_results if r['success']]
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
        else:
            avg_response_time = min_response_time = max_response_time = 0
        
        requests_per_second = len(processed_results) / total_time if total_time > 0 else 0
        error_rate = (failure_count / len(processed_results)) * 100 if processed_results else 0
        
        return BenchmarkResult(
            test_name=f"{api_name}_concurrent_{num_requests}",
            success_count=success_count,
            failure_count=failure_count,
            total_requests=len(processed_results),
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            errors=errors
        )
    
    async def benchmark_rate_limit_testing(self, api_name: str) -> BenchmarkResult:
        """Test rate limiting behavior."""
        logger.info(f"Starting rate limit test: {api_name}")
        
        # Make rapid requests to trigger rate limiting
        num_requests = 3 if api_name == "brave" else 10  # Brave has very low limits
        queries = [f"rate limit test {i}" for i in range(num_requests)]
        
        results = []
        errors = []
        rate_limited_count = 0
        
        start_time = time.time()
        
        for i, query in enumerate(queries):
            if api_name == "tavily":
                result = await self.make_tavily_request(query)
            elif api_name == "brave":
                result = await self.make_brave_request(query)
            else:
                continue
            
            results.append(result)
            
            # Check for rate limiting
            if result.get('status_code') == 429:
                rate_limited_count += 1
                errors.append(f"Request {i+1}: Rate limited")
                logger.info(f"  Request {i+1}/{num_requests}: ⚠️ Rate limited")
            elif result['success']:
                logger.info(f"  Request {i+1}/{num_requests}: ✓ Success")
            else:
                errors.append(f"Request {i+1}: {result['error']}")
                logger.info(f"  Request {i+1}/{num_requests}: ✗ Failed")
            
            # Very short delay to trigger rate limiting
            await asyncio.sleep(0.1)
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        success_count = sum(1 for r in results if r['success'])
        failure_count = len(results) - success_count
        response_times = [r['response_time'] for r in results if r['success']]
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
        else:
            avg_response_time = min_response_time = max_response_time = 0
        
        requests_per_second = len(results) / total_time if total_time > 0 else 0
        error_rate = (failure_count / len(results)) * 100 if results else 0
        
        # Add rate limiting info
        errors.append(f"Rate limited requests: {rate_limited_count}/{num_requests}")
        
        return BenchmarkResult(
            test_name=f"{api_name}_rate_limit",
            success_count=success_count,
            failure_count=failure_count,
            total_requests=len(results),
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            errors=errors
        )
    
    async def benchmark_error_recovery(self) -> BenchmarkResult:
        """Test error handling and recovery."""
        logger.info("Starting error recovery test")
        
        results = []
        errors = []
        
        start_time = time.time()
        
        # Test 1: Invalid API key
        invalid_session = aiohttp.ClientSession()
        try:
            async with invalid_session.post(
                "https://api.tavily.com/search",
                json={"api_key": "invalid", "query": "test"}
            ) as response:
                result = {
                    'success': response.status == 200,
                    'response_time': 0.1,
                    'test': 'invalid_key'
                }
                results.append(result)
                if not result['success']:
                    errors.append("Invalid key correctly rejected")
        except Exception as e:
            results.append({'success': False, 'response_time': 0.1, 'test': 'invalid_key'})
            errors.append(f"Invalid key test: {str(e)}")
        finally:
            await invalid_session.close()
        
        # Test 2: Non-existent endpoint
        try:
            async with self.session.get("https://api.tavily.com/nonexistent") as response:
                result = {
                    'success': response.status == 200,
                    'response_time': 0.1,
                    'test': 'bad_endpoint'
                }
                results.append(result)
                if not result['success']:
                    errors.append("Bad endpoint correctly rejected")
        except Exception as e:
            results.append({'success': False, 'response_time': 0.1, 'test': 'bad_endpoint'})
            errors.append(f"Bad endpoint test: {str(e)}")
        
        # Test 3: Malformed request
        try:
            async with self.session.post(
                "https://api.tavily.com/search",
                json={"malformed": "request"}
            ) as response:
                result = {
                    'success': response.status == 200,
                    'response_time': 0.1,
                    'test': 'malformed_request'
                }
                results.append(result)
                if not result['success']:
                    errors.append("Malformed request correctly rejected")
        except Exception as e:
            results.append({'success': False, 'response_time': 0.1, 'test': 'malformed_request'})
            errors.append(f"Malformed request test: {str(e)}")
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        success_count = sum(1 for r in results if r['success'])
        failure_count = len(results) - success_count
        response_times = [r['response_time'] for r in results]
        
        avg_response_time = statistics.mean(response_times) if response_times else 0
        min_response_time = min(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0
        requests_per_second = len(results) / total_time if total_time > 0 else 0
        error_rate = (failure_count / len(results)) * 100 if results else 0
        
        return BenchmarkResult(
            test_name="error_recovery",
            success_count=success_count,
            failure_count=failure_count,
            total_requests=len(results),
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            errors=errors
        )
    
    def format_result(self, result: BenchmarkResult) -> str:
        """Format benchmark result for display."""
        return f"""
Test: {result.test_name}
  Requests: {result.total_requests} (✓{result.success_count} ✗{result.failure_count})
  Success Rate: {100 - result.error_rate:.1f}%
  Avg Response Time: {result.avg_response_time:.3f}s
  Min/Max Response Time: {result.min_response_time:.3f}s / {result.max_response_time:.3f}s
  Requests/Second: {result.requests_per_second:.2f}
  Errors: {len(result.errors)}
"""
    
    async def run_all_benchmarks(self):
        """Run comprehensive benchmark suite."""
        logger.info("🚀 Starting API Performance Benchmark Suite")
        logger.info("="*60)
        
        benchmark_start = time.time()
        
        # List of benchmark tests
        tests = [
            ("tavily", "sequential", 5),
            ("brave", "sequential", 3),  # Lower for rate limits
            ("tavily", "concurrent", 3),
            ("brave", "concurrent", 2),  # Very low for rate limits
            ("tavily", "rate_limit", None),
            ("brave", "rate_limit", None),
            ("error_recovery", None, None)
        ]
        
        results = []
        
        for test_config in tests:
            api_name, test_type, count = test_config
            
            try:
                if test_type == "sequential":
                    result = await self.benchmark_sequential_requests(api_name, count)
                elif test_type == "concurrent":
                    result = await self.benchmark_concurrent_requests(api_name, count)
                elif test_type == "rate_limit":
                    result = await self.benchmark_rate_limit_testing(api_name)
                elif api_name == "error_recovery":
                    result = await self.benchmark_error_recovery()
                else:
                    continue
                
                results.append(result)
                logger.info(self.format_result(result))
                
                # Delay between tests to avoid overwhelming APIs
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.error(f"Benchmark {api_name}_{test_type} failed: {e}")
                results.append(BenchmarkResult(
                    test_name=f"{api_name}_{test_type}_error",
                    success_count=0,
                    failure_count=1,
                    total_requests=1,
                    avg_response_time=0,
                    min_response_time=0,
                    max_response_time=0,
                    requests_per_second=0,
                    error_rate=100,
                    errors=[str(e)]
                ))
        
        total_benchmark_time = time.time() - benchmark_start
        
        # Generate summary
        logger.info("="*60)
        logger.info("BENCHMARK SUMMARY")
        logger.info("="*60)
        
        total_requests = sum(r.total_requests for r in results)
        total_successes = sum(r.success_count for r in results)
        overall_success_rate = (total_successes / total_requests * 100) if total_requests > 0 else 0
        
        logger.info(f"Total Tests: {len(results)}")
        logger.info(f"Total Requests: {total_requests}")
        logger.info(f"Overall Success Rate: {overall_success_rate:.1f}%")
        logger.info(f"Total Benchmark Time: {total_benchmark_time:.2f}s")
        
        # Save results
        benchmark_data = {
            'timestamp': time.time(),
            'total_benchmark_time': total_benchmark_time,
            'total_tests': len(results),
            'total_requests': total_requests,
            'overall_success_rate': f"{overall_success_rate:.1f}%",
            'results': [
                {
                    'test_name': r.test_name,
                    'success_count': r.success_count,
                    'failure_count': r.failure_count,
                    'total_requests': r.total_requests,
                    'avg_response_time': r.avg_response_time,
                    'min_response_time': r.min_response_time,
                    'max_response_time': r.max_response_time,
                    'requests_per_second': r.requests_per_second,
                    'error_rate': r.error_rate,
                    'errors': r.errors
                }
                for r in results
            ]
        }
        
        with open('api_performance_benchmark_results.json', 'w') as f:
            json.dump(benchmark_data, f, indent=2)
        
        logger.info("\\n📊 Benchmark results saved to: api_performance_benchmark_results.json")
        logger.info("🎉 Benchmark suite completed!")
        
        return results


async def main():
    """Main function to run the benchmark suite."""
    print("🔧 API Performance Benchmark Suite")
    print("Testing performance characteristics of API integrations")
    print("-" * 60)
    
    async with APIBenchmark() as benchmark:
        await benchmark.run_all_benchmarks()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\\n⚠️  Benchmark interrupted by user")
    except Exception as e:
        print(f"\\n❌ Benchmark failed with error: {e}")
        import traceback
        traceback.print_exc()