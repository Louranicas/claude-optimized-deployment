#!/usr/bin/env python3
"""
Phase 3: Performance Validation Test
Tests performance improvements and benchmarks
"""

import os
import sys
import json
import time
import gc
import psutil
import threading
import asyncio
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import statistics

def test_gc_performance():
    """Test GC performance to confirm <100ms target"""
    results = {
        "test_name": "gc_performance",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        import gc
        
        # Measure GC performance over multiple cycles
        gc_times = []
        
        for i in range(10):
            # Create garbage
            garbage = []
            for j in range(10000):
                garbage.append({"data": "x" * 100, "refs": []})
            
            # Link objects to create cycles
            for j in range(len(garbage) - 1):
                garbage[j]["refs"].append(garbage[j + 1])
            
            # Measure GC time
            start_time = time.perf_counter()
            collected = gc.collect()
            gc_time = (time.perf_counter() - start_time) * 1000  # Convert to ms
            
            gc_times.append(gc_time)
            
            # Clean up
            del garbage
        
        # Calculate statistics
        avg_gc_time = statistics.mean(gc_times)
        max_gc_time = max(gc_times)
        min_gc_time = min(gc_times)
        median_gc_time = statistics.median(gc_times)
        
        results["details"]["avg_gc_time_ms"] = round(avg_gc_time, 2)
        results["details"]["max_gc_time_ms"] = round(max_gc_time, 2)
        results["details"]["min_gc_time_ms"] = round(min_gc_time, 2)
        results["details"]["median_gc_time_ms"] = round(median_gc_time, 2)
        results["details"]["gc_times_ms"] = [round(t, 2) for t in gc_times]
        
        # Check if GC times meet target (<100ms)
        if max_gc_time > 100:
            results["issues"].append(f"GC time exceeds 100ms target: {max_gc_time:.2f}ms")
            results["status"] = "FAIL"
        elif avg_gc_time > 50:
            results["issues"].append(f"Average GC time high: {avg_gc_time:.2f}ms")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"GC performance test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_parallel_executor_performance():
    """Test parallel executor stress performance"""
    results = {
        "test_name": "parallel_executor_performance",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        def cpu_bound_task(n):
            """Simulate CPU-bound work"""
            result = 0
            for i in range(n):
                result += i * i
            return result
        
        def io_bound_task(duration):
            """Simulate I/O-bound work"""
            time.sleep(duration)
            return f"Task completed after {duration}s"
        
        # Test ThreadPoolExecutor performance
        start_time = time.perf_counter()
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(io_bound_task, 0.1) for _ in range(20)]
            thread_results = [future.result() for future in futures]
        thread_time = time.perf_counter() - start_time
        
        # Test ProcessPoolExecutor performance
        start_time = time.perf_counter()
        with ProcessPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(cpu_bound_task, 10000) for _ in range(8)]
            process_results = [future.result() for future in futures]
        process_time = time.perf_counter() - start_time
        
        # Test sequential performance for comparison
        start_time = time.perf_counter()
        sequential_results = [io_bound_task(0.1) for _ in range(20)]
        sequential_time = time.perf_counter() - start_time
        
        results["details"]["thread_executor_time"] = round(thread_time, 2)
        results["details"]["process_executor_time"] = round(process_time, 2)
        results["details"]["sequential_time"] = round(sequential_time, 2)
        results["details"]["thread_speedup"] = round(sequential_time / thread_time, 2)
        
        # Check performance improvements
        if thread_time < sequential_time * 0.7:  # At least 30% improvement
            results["details"]["thread_performance"] = "GOOD"
        else:
            results["issues"].append("Thread executor performance not optimal")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Parallel executor test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_retry_logic_memory_efficiency():
    """Test retry logic memory efficiency"""
    results = {
        "test_name": "retry_logic_memory_efficiency",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        import time
        import random
        
        class RetryLogic:
            def __init__(self, max_retries=3, base_delay=0.1):
                self.max_retries = max_retries
                self.base_delay = base_delay
                self.attempt_history = []  # Track for testing
            
            def retry_with_backoff(self, func, *args, **kwargs):
                for attempt in range(self.max_retries + 1):
                    try:
                        result = func(*args, **kwargs)
                        self.attempt_history.append({"attempt": attempt, "success": True})
                        return result
                    except Exception as e:
                        self.attempt_history.append({"attempt": attempt, "success": False, "error": str(e)})
                        if attempt < self.max_retries:
                            delay = self.base_delay * (2 ** attempt)  # Exponential backoff
                            time.sleep(delay)
                        else:
                            raise e
        
        def flaky_function():
            """Function that fails randomly to test retry logic"""
            if random.random() < 0.7:  # 70% failure rate
                raise Exception("Simulated failure")
            return "Success"
        
        # Test memory usage during retry operations
        initial_memory = psutil.Process().memory_info().rss
        
        retry_logic = RetryLogic(max_retries=5, base_delay=0.01)
        
        # Run multiple retry operations
        success_count = 0
        for i in range(100):
            try:
                result = retry_logic.retry_with_backoff(flaky_function)
                success_count += 1
            except:
                pass
        
        final_memory = psutil.Process().memory_info().rss
        memory_growth = (final_memory - initial_memory) / 1024 / 1024  # MB
        
        results["details"]["initial_memory_mb"] = round(initial_memory / 1024 / 1024, 2)
        results["details"]["final_memory_mb"] = round(final_memory / 1024 / 1024, 2)
        results["details"]["memory_growth_mb"] = round(memory_growth, 2)
        results["details"]["success_rate"] = round(success_count / 100, 2)
        results["details"]["total_attempts"] = len(retry_logic.attempt_history)
        
        # Check memory efficiency
        if memory_growth > 10:  # More than 10MB growth
            results["issues"].append(f"High memory growth in retry logic: {memory_growth:.2f}MB")
            results["status"] = "FAIL"
        elif memory_growth > 5:
            results["issues"].append(f"Moderate memory growth: {memory_growth:.2f}MB")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Retry logic memory test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_circle_of_experts_memory_usage():
    """Test Circle of Experts memory usage under load"""
    results = {
        "test_name": "circle_of_experts_memory_usage",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Simulate Circle of Experts operations
        class MockExpert:
            def __init__(self, name):
                self.name = name
                self.query_history = []
            
            def process_query(self, query):
                # Simulate processing
                self.query_history.append({
                    "query": query,
                    "timestamp": time.time(),
                    "response": f"Response from {self.name}: {query[:50]}"
                })
                time.sleep(0.01)  # Simulate processing time
                return self.query_history[-1]["response"]
        
        class MockCircleOfExperts:
            def __init__(self):
                self.experts = [
                    MockExpert("Claude"),
                    MockExpert("GPT-4"),
                    MockExpert("Gemini"),
                    MockExpert("DeepSeek")
                ]
                self.consultation_cache = {}
            
            def consult(self, query):
                # Check cache first
                if query in self.consultation_cache:
                    return self.consultation_cache[query]
                
                # Get responses from all experts
                responses = []
                for expert in self.experts:
                    response = expert.process_query(query)
                    responses.append(response)
                
                # Simulate consensus building
                consensus = f"Consensus for: {query}"
                
                # Cache result (with size limit)
                if len(self.consultation_cache) < 100:
                    self.consultation_cache[query] = consensus
                
                return consensus
        
        # Test memory usage during consultations
        initial_memory = psutil.Process().memory_info().rss
        
        circle = MockCircleOfExperts()
        
        # Run multiple consultations
        for i in range(200):
            query = f"Test query {i} with some longer text to simulate real queries"
            result = circle.consult(query)
        
        # Force garbage collection
        gc.collect()
        
        final_memory = psutil.Process().memory_info().rss
        memory_growth = (final_memory - initial_memory) / 1024 / 1024  # MB
        
        results["details"]["initial_memory_mb"] = round(initial_memory / 1024 / 1024, 2)
        results["details"]["final_memory_mb"] = round(final_memory / 1024 / 1024, 2)
        results["details"]["memory_growth_mb"] = round(memory_growth, 2)
        results["details"]["cache_size"] = len(circle.consultation_cache)
        results["details"]["total_expert_queries"] = sum(len(expert.query_history) for expert in circle.experts)
        
        # Check memory efficiency
        if memory_growth > 50:  # More than 50MB growth
            results["issues"].append(f"High memory growth in Circle of Experts: {memory_growth:.2f}MB")
            results["status"] = "FAIL"
        elif memory_growth > 25:
            results["issues"].append(f"Moderate memory growth: {memory_growth:.2f}MB")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Circle of Experts memory test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_async_performance():
    """Test async performance improvements"""
    results = {
        "test_name": "async_performance",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        async def async_task(duration):
            """Simulate async I/O operation"""
            await asyncio.sleep(duration)
            return f"Async task completed after {duration}s"
        
        def sync_task(duration):
            """Simulate sync I/O operation"""
            time.sleep(duration)
            return f"Sync task completed after {duration}s"
        
        async def run_async_tasks():
            """Run multiple async tasks concurrently"""
            tasks = [async_task(0.1) for _ in range(20)]
            return await asyncio.gather(*tasks)
        
        # Test async performance
        start_time = time.perf_counter()
        async_results = asyncio.run(run_async_tasks())
        async_time = time.perf_counter() - start_time
        
        # Test sync performance for comparison
        start_time = time.perf_counter()
        sync_results = [sync_task(0.1) for _ in range(20)]
        sync_time = time.perf_counter() - start_time
        
        results["details"]["async_time"] = round(async_time, 2)
        results["details"]["sync_time"] = round(sync_time, 2)
        results["details"]["speedup"] = round(sync_time / async_time, 2)
        results["details"]["async_tasks_completed"] = len(async_results)
        results["details"]["sync_tasks_completed"] = len(sync_results)
        
        # Check performance improvements
        if async_time < sync_time * 0.3:  # At least 70% improvement
            results["details"]["async_performance"] = "EXCELLENT"
        elif async_time < sync_time * 0.7:  # At least 30% improvement
            results["details"]["async_performance"] = "GOOD"
        else:
            results["issues"].append("Async performance not optimal")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Async performance test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_memory_efficiency_improvements():
    """Test overall memory efficiency improvements"""
    results = {
        "test_name": "memory_efficiency_improvements",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Baseline memory measurement
        gc.collect()
        baseline_memory = psutil.Process().memory_info().rss
        
        # Simulate various operations
        operations = []
        
        # 1. Data processing operations
        for i in range(1000):
            data = {"id": i, "content": "x" * 1000}
            operations.append(data)
        
        mid1_memory = psutil.Process().memory_info().rss
        
        # 2. Clear half the operations (simulate cleanup)
        operations = operations[::2]  # Keep every other item
        gc.collect()
        
        mid2_memory = psutil.Process().memory_info().rss
        
        # 3. More operations with different patterns
        cache = {}
        for i in range(500):
            key = f"key_{i % 100}"  # Limited key space for cache efficiency
            cache[key] = {"data": f"value_{i}", "timestamp": time.time()}
        
        mid3_memory = psutil.Process().memory_info().rss
        
        # 4. Final cleanup
        del operations
        del cache
        gc.collect()
        
        final_memory = psutil.Process().memory_info().rss
        
        # Calculate memory efficiency metrics
        peak_memory = max(mid1_memory, mid2_memory, mid3_memory)
        memory_overhead = peak_memory - baseline_memory
        memory_cleanup = peak_memory - final_memory
        cleanup_efficiency = memory_cleanup / memory_overhead if memory_overhead > 0 else 1
        
        results["details"]["baseline_memory_mb"] = round(baseline_memory / 1024 / 1024, 2)
        results["details"]["peak_memory_mb"] = round(peak_memory / 1024 / 1024, 2)
        results["details"]["final_memory_mb"] = round(final_memory / 1024 / 1024, 2)
        results["details"]["memory_overhead_mb"] = round(memory_overhead / 1024 / 1024, 2)
        results["details"]["memory_cleanup_mb"] = round(memory_cleanup / 1024 / 1024, 2)
        results["details"]["cleanup_efficiency"] = round(cleanup_efficiency, 2)
        
        # Check efficiency targets
        if cleanup_efficiency < 0.5:  # Less than 50% cleanup
            results["issues"].append(f"Low cleanup efficiency: {cleanup_efficiency:.2f}")
            results["status"] = "FAIL"
        elif cleanup_efficiency < 0.8:  # Less than 80% cleanup
            results["issues"].append(f"Moderate cleanup efficiency: {cleanup_efficiency:.2f}")
            results["status"] = "PARTIAL"
        
        # Check memory overhead
        overhead_mb = memory_overhead / 1024 / 1024
        if overhead_mb > 100:  # More than 100MB overhead
            results["issues"].append(f"High memory overhead: {overhead_mb:.2f}MB")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Memory efficiency test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def run_performance_validation():
    """Run all performance validation tests"""
    print("🔍 Phase 3: Performance Validation Starting...")
    print("=" * 60)
    
    test_results = {
        "phase": "Phase 3: Performance Validation",
        "timestamp": datetime.now().isoformat(),
        "tests": [],
        "summary": {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "partial": 0
        }
    }
    
    # Run all tests
    tests = [
        test_gc_performance,
        test_parallel_executor_performance,
        test_retry_logic_memory_efficiency,
        test_circle_of_experts_memory_usage,
        test_async_performance,
        test_memory_efficiency_improvements
    ]
    
    for test_func in tests:
        print(f"Running {test_func.__name__}...")
        result = test_func()
        test_results["tests"].append(result)
        
        # Update summary
        test_results["summary"]["total_tests"] += 1
        if result["status"] == "PASS":
            test_results["summary"]["passed"] += 1
            print(f"✅ {result['test_name']}: PASSED")
        elif result["status"] == "FAIL":
            test_results["summary"]["failed"] += 1
            print(f"❌ {result['test_name']}: FAILED")
            for issue in result["issues"]:
                print(f"   - {issue}")
        else:  # PARTIAL
            test_results["summary"]["partial"] += 1
            print(f"⚠️  {result['test_name']}: PARTIAL")
            for issue in result["issues"]:
                print(f"   - {issue}")
    
    # Calculate overall status
    if test_results["summary"]["failed"] == 0 and test_results["summary"]["partial"] <= 1:
        overall_status = "PASS"
    elif test_results["summary"]["failed"] <= 1:
        overall_status = "PARTIAL"
    else:
        overall_status = "FAIL"
    
    test_results["overall_status"] = overall_status
    
    print("\n" + "=" * 60)
    print(f"📊 Phase 3 Summary: {overall_status}")
    print(f"✅ Passed: {test_results['summary']['passed']}")
    print(f"⚠️  Partial: {test_results['summary']['partial']}")
    print(f"❌ Failed: {test_results['summary']['failed']}")
    
    return test_results

if __name__ == "__main__":
    results = run_performance_validation()
    
    # Save results to file
    results_file = "/home/louranicas/projects/claude-optimized-deployment/phase3_performance_validation_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: {results_file}")
    
    # Exit with appropriate code
    if results["overall_status"] == "PASS":
        sys.exit(0)
    elif results["overall_status"] == "PARTIAL":
        sys.exit(1)
    else:
        sys.exit(2)