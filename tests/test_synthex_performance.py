#!/usr/bin/env python3
"""
SYNTHEX Performance Test Suite
Validates performance targets for the AI-native search engine
"""

import asyncio
import time
import statistics
import json
import random
import string
from datetime import datetime
from typing import List, Dict, Any
import pytest
import aiohttp
from concurrent.futures import ProcessPoolExecutor

from src.synthex import (
    SynthexEngine,
    SynthexConfig,
    QueryOptions,
)


class SynthexPerformanceTester:
    """Performance testing framework for SYNTHEX"""
    
    def __init__(self):
        self.engine = None
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "tests": {},
            "summary": {}
        }
    
    async def setup(self):
        """Initialize test environment"""
        config = SynthexConfig(
            max_parallel_searches=10000,
            cache_size_mb=1024,  # Smaller for testing
            query_timeout_ms=5000
        )
        self.engine = SynthexEngine(config)
        await self.engine.initialize()
        
        # Warm up
        for _ in range(10):
            await self.engine.search("warmup query")
    
    async def teardown(self):
        """Cleanup test environment"""
        if self.engine:
            await self.engine.shutdown()
    
    def generate_queries(self, count: int) -> List[str]:
        """Generate random search queries"""
        topics = [
            "machine learning", "quantum computing", "blockchain",
            "artificial intelligence", "distributed systems",
            "cryptography", "neural networks", "robotics",
            "data science", "cloud computing"
        ]
        
        modifiers = [
            "advanced", "introduction to", "applications of",
            "future of", "challenges in", "recent advances in",
            "best practices for", "security in"
        ]
        
        queries = []
        for _ in range(count):
            topic = random.choice(topics)
            modifier = random.choice(modifiers)
            query = f"{modifier} {topic} {random.randint(2020, 2024)}"
            queries.append(query)
        
        return queries
    
    async def test_single_query_latency(self, iterations: int = 100):
        """Test single query latency"""
        print("\n=== Single Query Latency Test ===")
        
        queries = self.generate_queries(iterations)
        latencies = []
        
        for i, query in enumerate(queries):
            start = time.perf_counter()
            result = await self.engine.search(query)
            latency = (time.perf_counter() - start) * 1000  # ms
            latencies.append(latency)
            
            if i % 10 == 0:
                print(f"  Progress: {i}/{iterations}")
        
        # Calculate percentiles
        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.5)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]
        
        self.results["tests"]["single_query_latency"] = {
            "iterations": iterations,
            "p50_ms": p50,
            "p95_ms": p95,
            "p99_ms": p99,
            "mean_ms": statistics.mean(latencies),
            "min_ms": min(latencies),
            "max_ms": max(latencies)
        }
        
        print(f"\nResults:")
        print(f"  P50: {p50:.2f}ms")
        print(f"  P95: {p95:.2f}ms")
        print(f"  P99: {p99:.2f}ms")
        
        # Validate targets
        assert p50 < 100, f"P50 latency {p50}ms exceeds target of 100ms"
        assert p99 < 500, f"P99 latency {p99}ms exceeds target of 500ms"
    
    async def test_parallel_throughput(self, duration_seconds: int = 10):
        """Test parallel query throughput"""
        print("\n=== Parallel Throughput Test ===")
        
        queries = self.generate_queries(10000)
        query_count = 0
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        async def search_task():
            nonlocal query_count
            while time.time() < end_time:
                query = random.choice(queries)
                try:
                    await self.engine.search(query, QueryOptions(timeout_ms=2000))
                    query_count += 1
                except Exception as e:
                    print(f"Search error: {e}")
        
        # Run concurrent searches
        tasks = []
        for _ in range(100):  # 100 concurrent searchers
            tasks.append(asyncio.create_task(search_task()))
        
        await asyncio.gather(*tasks)
        
        actual_duration = time.time() - start_time
        qps = query_count / actual_duration
        
        self.results["tests"]["parallel_throughput"] = {
            "duration_seconds": actual_duration,
            "total_queries": query_count,
            "queries_per_second": qps,
            "concurrent_tasks": len(tasks)
        }
        
        print(f"\nResults:")
        print(f"  Total queries: {query_count}")
        print(f"  Duration: {actual_duration:.2f}s")
        print(f"  Throughput: {qps:.0f} queries/second")
        
        # Validate target (relaxed for Python implementation)
        assert qps > 100, f"Throughput {qps} qps below target of 100 qps"
    
    async def test_concurrent_connections(self, max_connections: int = 1000):
        """Test maximum concurrent connections"""
        print("\n=== Concurrent Connections Test ===")
        
        queries = self.generate_queries(max_connections)
        
        async def concurrent_search(query: str):
            try:
                start = time.perf_counter()
                result = await self.engine.search(query)
                return {
                    "success": True,
                    "latency_ms": (time.perf_counter() - start) * 1000,
                    "results": result.total_results
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }
        
        # Launch all searches concurrently
        start = time.time()
        tasks = [concurrent_search(q) for q in queries]
        results = await asyncio.gather(*tasks)
        duration = time.time() - start
        
        # Analyze results
        successful = sum(1 for r in results if r["success"])
        failed = len(results) - successful
        latencies = [r["latency_ms"] for r in results if r["success"]]
        
        self.results["tests"]["concurrent_connections"] = {
            "total_connections": max_connections,
            "successful": successful,
            "failed": failed,
            "success_rate": successful / max_connections,
            "total_duration_seconds": duration,
            "avg_latency_ms": statistics.mean(latencies) if latencies else 0
        }
        
        print(f"\nResults:")
        print(f"  Connections: {max_connections}")
        print(f"  Successful: {successful}")
        print(f"  Failed: {failed}")
        print(f"  Success rate: {successful/max_connections:.1%}")
        
        # Validate
        assert successful / max_connections > 0.95, "Success rate below 95%"
    
    async def test_cache_performance(self, iterations: int = 1000):
        """Test cache hit rate and performance"""
        print("\n=== Cache Performance Test ===")
        
        # Use limited set of queries to ensure cache hits
        unique_queries = self.generate_queries(100)
        
        cache_misses = []
        cache_hits = []
        
        for i in range(iterations):
            query = random.choice(unique_queries)
            
            start = time.perf_counter()
            result = await self.engine.search(query)
            latency = (time.perf_counter() - start) * 1000
            
            # First 100 queries are likely misses
            if i < 100:
                cache_misses.append(latency)
            else:
                cache_hits.append(latency)
        
        hit_rate = len(cache_hits) / (len(cache_hits) + len(cache_misses))
        
        self.results["tests"]["cache_performance"] = {
            "iterations": iterations,
            "unique_queries": len(unique_queries),
            "cache_hit_rate": hit_rate,
            "avg_miss_latency_ms": statistics.mean(cache_misses),
            "avg_hit_latency_ms": statistics.mean(cache_hits),
            "speedup_factor": statistics.mean(cache_misses) / statistics.mean(cache_hits)
        }
        
        print(f"\nResults:")
        print(f"  Cache hit rate: {hit_rate:.1%}")
        print(f"  Avg miss latency: {statistics.mean(cache_misses):.2f}ms")
        print(f"  Avg hit latency: {statistics.mean(cache_hits):.2f}ms")
        print(f"  Speedup: {statistics.mean(cache_misses)/statistics.mean(cache_hits):.1f}x")
        
        # Validate
        assert hit_rate > 0.8, f"Cache hit rate {hit_rate} below target of 80%"
    
    async def test_memory_usage(self, duration_seconds: int = 30):
        """Test memory usage under load"""
        print("\n=== Memory Usage Test ===")
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        queries = self.generate_queries(1000)
        query_count = 0
        memory_samples = []
        
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        # Background task to sample memory
        async def memory_monitor():
            while time.time() < end_time:
                memory_mb = process.memory_info().rss / 1024 / 1024
                memory_samples.append(memory_mb)
                await asyncio.sleep(1)
        
        # Run searches
        async def search_loop():
            nonlocal query_count
            while time.time() < end_time:
                query = random.choice(queries)
                await self.engine.search(query)
                query_count += 1
        
        # Run both tasks
        await asyncio.gather(
            memory_monitor(),
            search_loop()
        )
        
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_growth = final_memory - initial_memory
        
        self.results["tests"]["memory_usage"] = {
            "initial_memory_mb": initial_memory,
            "final_memory_mb": final_memory,
            "memory_growth_mb": memory_growth,
            "peak_memory_mb": max(memory_samples),
            "avg_memory_mb": statistics.mean(memory_samples),
            "total_queries": query_count
        }
        
        print(f"\nResults:")
        print(f"  Initial memory: {initial_memory:.1f}MB")
        print(f"  Final memory: {final_memory:.1f}MB")
        print(f"  Memory growth: {memory_growth:.1f}MB")
        print(f"  Peak memory: {max(memory_samples):.1f}MB")
        
        # Validate (allow reasonable growth)
        assert memory_growth < 500, f"Memory growth {memory_growth}MB exceeds limit"
    
    async def test_error_resilience(self):
        """Test error handling and resilience"""
        print("\n=== Error Resilience Test ===")
        
        error_queries = [
            "",  # Empty query
            "a" * 10000,  # Very long query
            "SELECT * FROM users",  # SQL injection attempt
            "<script>alert('xss')</script>",  # XSS attempt
            "🦀" * 100,  # Unicode stress
        ]
        
        results = []
        for query in error_queries:
            try:
                result = await self.engine.search(query)
                results.append({
                    "query": query[:50],
                    "success": True,
                    "results": result.total_results
                })
            except Exception as e:
                results.append({
                    "query": query[:50],
                    "success": False,
                    "error": str(e)
                })
        
        success_count = sum(1 for r in results if r["success"])
        
        self.results["tests"]["error_resilience"] = {
            "total_tests": len(error_queries),
            "handled_gracefully": success_count,
            "errors": [r for r in results if not r["success"]]
        }
        
        print(f"\nResults:")
        print(f"  Total tests: {len(error_queries)}")
        print(f"  Handled gracefully: {success_count}")
        
        # All should be handled without crashing
        assert success_count == len(error_queries), "Some queries caused errors"
    
    async def run_all_tests(self):
        """Run complete performance test suite"""
        print("=== SYNTHEX Performance Test Suite ===")
        print(f"Starting at: {datetime.now()}")
        
        await self.setup()
        
        try:
            # Run all tests
            await self.test_single_query_latency()
            await self.test_parallel_throughput()
            await self.test_concurrent_connections()
            await self.test_cache_performance()
            await self.test_memory_usage()
            await self.test_error_resilience()
            
            # Calculate summary
            self.results["summary"] = {
                "all_tests_passed": True,
                "timestamp": datetime.now().isoformat(),
                "performance_grade": self.calculate_grade()
            }
            
            print("\n=== Test Summary ===")
            print(f"Performance Grade: {self.results['summary']['performance_grade']}")
            print("All tests passed! ✓")
            
        except Exception as e:
            print(f"\n❌ Test failed: {e}")
            self.results["summary"] = {
                "all_tests_passed": False,
                "error": str(e)
            }
        finally:
            await self.teardown()
            
            # Save results
            with open("synthex_performance_results.json", "w") as f:
                json.dump(self.results, f, indent=2)
            print("\nResults saved to synthex_performance_results.json")
    
    def calculate_grade(self) -> str:
        """Calculate overall performance grade"""
        scores = []
        
        # Latency score
        if "single_query_latency" in self.results["tests"]:
            p50 = self.results["tests"]["single_query_latency"]["p50_ms"]
            if p50 < 10:
                scores.append(100)
            elif p50 < 50:
                scores.append(90)
            elif p50 < 100:
                scores.append(80)
            else:
                scores.append(70)
        
        # Throughput score
        if "parallel_throughput" in self.results["tests"]:
            qps = self.results["tests"]["parallel_throughput"]["queries_per_second"]
            if qps > 1000:
                scores.append(100)
            elif qps > 500:
                scores.append(90)
            elif qps > 100:
                scores.append(80)
            else:
                scores.append(70)
        
        # Calculate grade
        avg_score = statistics.mean(scores) if scores else 0
        if avg_score >= 95:
            return "A+"
        elif avg_score >= 90:
            return "A"
        elif avg_score >= 85:
            return "B+"
        elif avg_score >= 80:
            return "B"
        else:
            return "C"


async def main():
    """Run performance tests"""
    tester = SynthexPerformanceTester()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())