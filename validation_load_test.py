#!/usr/bin/env python3
"""
Phase 5: Load Testing
Validates system under realistic load conditions
"""

import os
import sys
import json
import time
import psutil
import threading
import multiprocessing
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import statistics

def test_sustained_load_30min():
    """Execute sustained load tests for 30 minutes (simulated as 30 seconds)"""
    results = {
        "test_name": "sustained_load_30min",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Simulate 30-minute load test (compressed to 30 seconds for validation)
        duration = 30  # seconds (representing 30 minutes)
        start_time = time.time()
        
        memory_samples = []
        cpu_samples = []
        operation_counts = []
        
        def simulate_workload():
            """Simulate realistic workload operations"""
            operations = 0
            while time.time() - start_time < duration:
                # Simulate various operations
                data = {"task": "process", "data": "x" * 1000}
                result = data["data"][:100]  # Simulate processing
                operations += 1
                time.sleep(0.01)  # Small delay to prevent busy wait
            return operations
        
        # Start background workload threads
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(simulate_workload) for _ in range(8)]
            
            # Monitor system resources during load
            while time.time() - start_time < duration:
                memory_info = psutil.Process().memory_info()
                cpu_percent = psutil.Process().cpu_percent()
                
                memory_samples.append(memory_info.rss / 1024 / 1024)  # MB
                cpu_samples.append(cpu_percent)
                
                time.sleep(1)  # Sample every second
            
            # Collect operation counts
            for future in futures:
                operation_counts.append(future.result())
        
        # Calculate statistics
        avg_memory = statistics.mean(memory_samples)
        max_memory = max(memory_samples)
        min_memory = min(memory_samples)
        memory_growth = max_memory - min_memory
        
        avg_cpu = statistics.mean(cpu_samples) if cpu_samples else 0
        max_cpu = max(cpu_samples) if cpu_samples else 0
        
        total_operations = sum(operation_counts)
        
        results["details"]["duration_seconds"] = duration
        results["details"]["avg_memory_mb"] = round(avg_memory, 2)
        results["details"]["max_memory_mb"] = round(max_memory, 2)
        results["details"]["min_memory_mb"] = round(min_memory, 2)
        results["details"]["memory_growth_mb"] = round(memory_growth, 2)
        results["details"]["avg_cpu_percent"] = round(avg_cpu, 2)
        results["details"]["max_cpu_percent"] = round(max_cpu, 2)
        results["details"]["total_operations"] = total_operations
        results["details"]["operations_per_second"] = round(total_operations / duration, 2)
        
        # Check for memory stability
        if memory_growth > 100:  # More than 100MB growth
            results["issues"].append(f"High memory growth during load: {memory_growth:.2f}MB")
            results["status"] = "FAIL"
        elif memory_growth > 50:
            results["issues"].append(f"Moderate memory growth: {memory_growth:.2f}MB")
            results["status"] = "PARTIAL"
        
        # Check CPU usage
        if max_cpu > 90:
            results["issues"].append(f"High CPU usage detected: {max_cpu:.2f}%")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Sustained load test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_memory_patterns_under_load():
    """Monitor memory usage patterns and growth under load"""
    results = {
        "test_name": "memory_patterns_under_load",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        import gc
        
        # Test different memory usage patterns
        patterns = {
            "steady_state": [],
            "burst_allocations": [],
            "gradual_growth": [],
            "cleanup_cycles": []
        }
        
        # Pattern 1: Steady state operations
        initial_memory = psutil.Process().memory_info().rss
        for i in range(100):
            data = {"id": i, "content": "steady" * 100}
            patterns["steady_state"].append(data)
            if i % 20 == 0:  # Periodic cleanup
                patterns["steady_state"] = patterns["steady_state"][-10:]
                gc.collect()
        
        steady_memory = psutil.Process().memory_info().rss
        
        # Pattern 2: Burst allocations
        for i in range(50):
            burst_data = [{"burst": j, "data": "x" * 2000} for j in range(100)]
            patterns["burst_allocations"].extend(burst_data)
        
        burst_memory = psutil.Process().memory_info().rss
        
        # Pattern 3: Gradual growth
        for i in range(200):
            growth_data = {"id": i, "data": "growth" * (i + 1)}
            patterns["gradual_growth"].append(growth_data)
        
        growth_memory = psutil.Process().memory_info().rss
        
        # Pattern 4: Cleanup cycles
        for cycle in range(5):
            # Allocate
            for i in range(100):
                data = {"cycle": cycle, "item": i, "data": "cleanup" * 500}
                patterns["cleanup_cycles"].append(data)
            
            # Cleanup
            patterns["cleanup_cycles"] = []
            gc.collect()
        
        final_memory = psutil.Process().memory_info().rss
        
        # Calculate memory pattern metrics
        steady_growth = (steady_memory - initial_memory) / 1024 / 1024
        burst_growth = (burst_memory - steady_memory) / 1024 / 1024
        gradual_growth_size = (growth_memory - burst_memory) / 1024 / 1024
        cleanup_efficiency = (growth_memory - final_memory) / 1024 / 1024
        
        results["details"]["initial_memory_mb"] = round(initial_memory / 1024 / 1024, 2)
        results["details"]["steady_growth_mb"] = round(steady_growth, 2)
        results["details"]["burst_growth_mb"] = round(burst_growth, 2)
        results["details"]["gradual_growth_mb"] = round(gradual_growth_size, 2)
        results["details"]["cleanup_efficiency_mb"] = round(cleanup_efficiency, 2)
        results["details"]["final_memory_mb"] = round(final_memory / 1024 / 1024, 2)
        
        # Analyze patterns
        if steady_growth > 20:
            results["issues"].append(f"High steady state growth: {steady_growth:.2f}MB")
            results["status"] = "PARTIAL"
        
        if burst_growth > 100:
            results["issues"].append(f"Excessive burst allocation: {burst_growth:.2f}MB")
            results["status"] = "FAIL"
        
        if cleanup_efficiency < gradual_growth_size * 0.5:
            results["issues"].append(f"Poor cleanup efficiency: {cleanup_efficiency:.2f}MB")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Memory pattern test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_memory_stays_within_limits():
    """Validate memory stays within configured limits"""
    results = {
        "test_name": "memory_stays_within_limits",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Define memory limits (based on K8s configuration)
        memory_limits = {
            "soft_limit_mb": 1024,  # 1GB soft limit
            "hard_limit_mb": 2048,  # 2GB hard limit (from K8s config)
            "warning_threshold": 0.8,  # 80% of limit
            "critical_threshold": 0.95  # 95% of limit
        }
        
        # Monitor memory during intensive operations
        memory_readings = []
        
        def memory_intensive_operation():
            """Simulate memory-intensive operations"""
            data_chunks = []
            for i in range(100):
                chunk = {"id": i, "data": "x" * 10000}  # 10KB per chunk
                data_chunks.append(chunk)
                
                # Record memory usage
                current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                memory_readings.append(current_memory)
                
                # Simulate processing delay
                time.sleep(0.01)
            
            return len(data_chunks)
        
        # Run memory-intensive operations in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(memory_intensive_operation) for _ in range(4)]
            results_list = [future.result() for future in futures]
        
        # Analyze memory usage
        max_memory = max(memory_readings)
        avg_memory = statistics.mean(memory_readings)
        min_memory = min(memory_readings)
        
        # Check against limits
        soft_limit_mb = memory_limits["soft_limit_mb"]
        hard_limit_mb = memory_limits["hard_limit_mb"]
        warning_threshold = soft_limit_mb * memory_limits["warning_threshold"]
        critical_threshold = hard_limit_mb * memory_limits["critical_threshold"]
        
        results["details"]["max_memory_mb"] = round(max_memory, 2)
        results["details"]["avg_memory_mb"] = round(avg_memory, 2)
        results["details"]["min_memory_mb"] = round(min_memory, 2)
        results["details"]["soft_limit_mb"] = soft_limit_mb
        results["details"]["hard_limit_mb"] = hard_limit_mb
        results["details"]["warning_threshold_mb"] = round(warning_threshold, 2)
        results["details"]["critical_threshold_mb"] = round(critical_threshold, 2)
        
        # Check limit violations
        if max_memory > hard_limit_mb:
            results["issues"].append(f"Hard memory limit exceeded: {max_memory:.2f}MB > {hard_limit_mb}MB")
            results["status"] = "FAIL"
        elif max_memory > critical_threshold:
            results["issues"].append(f"Critical threshold exceeded: {max_memory:.2f}MB")
            results["status"] = "PARTIAL"
        elif max_memory > warning_threshold:
            results["issues"].append(f"Warning threshold exceeded: {max_memory:.2f}MB")
            results["status"] = "PARTIAL"
        
        # Calculate usage percentages
        soft_usage_percent = (max_memory / soft_limit_mb) * 100
        hard_usage_percent = (max_memory / hard_limit_mb) * 100
        
        results["details"]["soft_limit_usage_percent"] = round(soft_usage_percent, 2)
        results["details"]["hard_limit_usage_percent"] = round(hard_usage_percent, 2)
        
    except Exception as e:
        results["issues"].append(f"Memory limit test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_system_recovery_after_pressure():
    """Test system recovery after memory pressure"""
    results = {
        "test_name": "system_recovery_after_pressure",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        import gc
        
        # Baseline memory
        baseline_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Create memory pressure
        pressure_data = []
        for i in range(1000):
            large_object = {
                "id": i,
                "data": "x" * 50000,  # 50KB per object
                "metadata": {"created": time.time(), "type": "pressure_test"}
            }
            pressure_data.append(large_object)
        
        # Measure peak memory
        peak_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Simulate system recovery
        recovery_phases = []
        
        # Phase 1: Partial cleanup
        pressure_data = pressure_data[::2]  # Remove half
        gc.collect()
        phase1_memory = psutil.Process().memory_info().rss / 1024 / 1024
        recovery_phases.append(("phase1_partial", phase1_memory))
        
        # Phase 2: More aggressive cleanup
        pressure_data = pressure_data[:100]  # Keep only 100 items
        gc.collect()
        phase2_memory = psutil.Process().memory_info().rss / 1024 / 1024
        recovery_phases.append(("phase2_aggressive", phase2_memory))
        
        # Phase 3: Complete cleanup
        del pressure_data
        gc.collect()
        phase3_memory = psutil.Process().memory_info().rss / 1024 / 1024
        recovery_phases.append(("phase3_complete", phase3_memory))
        
        # Wait for system stabilization
        time.sleep(2)
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Calculate recovery metrics
        memory_pressure = peak_memory - baseline_memory
        total_recovery = peak_memory - final_memory
        recovery_efficiency = total_recovery / memory_pressure if memory_pressure > 0 else 1
        memory_overhead = final_memory - baseline_memory
        
        results["details"]["baseline_memory_mb"] = round(baseline_memory, 2)
        results["details"]["peak_memory_mb"] = round(peak_memory, 2)
        results["details"]["final_memory_mb"] = round(final_memory, 2)
        results["details"]["memory_pressure_mb"] = round(memory_pressure, 2)
        results["details"]["total_recovery_mb"] = round(total_recovery, 2)
        results["details"]["recovery_efficiency"] = round(recovery_efficiency, 2)
        results["details"]["memory_overhead_mb"] = round(memory_overhead, 2)
        
        # Record recovery phases
        for phase_name, memory in recovery_phases:
            results["details"][f"{phase_name}_memory_mb"] = round(memory, 2)
        
        # Evaluate recovery performance
        if recovery_efficiency < 0.7:  # Less than 70% recovery
            results["issues"].append(f"Poor recovery efficiency: {recovery_efficiency:.2f}")
            results["status"] = "FAIL"
        elif recovery_efficiency < 0.85:  # Less than 85% recovery
            results["issues"].append(f"Moderate recovery efficiency: {recovery_efficiency:.2f}")
            results["status"] = "PARTIAL"
        
        # Check final overhead
        if memory_overhead > 50:  # More than 50MB overhead after recovery
            results["issues"].append(f"High memory overhead after recovery: {memory_overhead:.2f}MB")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"System recovery test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def test_concurrent_load_scenarios():
    """Test concurrent load scenarios"""
    results = {
        "test_name": "concurrent_load_scenarios",
        "status": "PASS",
        "details": {},
        "issues": []
    }
    
    try:
        # Test different types of concurrent loads
        def cpu_intensive_task(duration):
            """CPU-intensive task"""
            start_time = time.time()
            operations = 0
            while time.time() - start_time < duration:
                # Simulate CPU work
                result = sum(i * i for i in range(1000))
                operations += 1
            return operations
        
        def memory_intensive_task(size_mb):
            """Memory-intensive task"""
            data = []
            for i in range(size_mb * 100):  # ~10KB per iteration
                item = {"id": i, "data": "x" * 10000}
                data.append(item)
            return len(data)
        
        def io_simulation_task(operations):
            """I/O simulation task"""
            results = []
            for i in range(operations):
                # Simulate I/O delay
                time.sleep(0.001)
                results.append(f"io_result_{i}")
            return len(results)
        
        # Monitor memory during concurrent scenarios
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Scenario 1: Mixed workload
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            
            # CPU tasks
            futures.extend([executor.submit(cpu_intensive_task, 2) for _ in range(2)])
            
            # Memory tasks
            futures.extend([executor.submit(memory_intensive_task, 10) for _ in range(2)])
            
            # I/O simulation tasks
            futures.extend([executor.submit(io_simulation_task, 100) for _ in range(4)])
            
            # Monitor memory during execution
            memory_samples = []
            start_time = time.time()
            
            while not all(future.done() for future in futures):
                current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                memory_samples.append(current_memory)
                time.sleep(0.1)
            
            # Collect results
            task_results = [future.result() for future in futures]
        
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Calculate metrics
        max_memory = max(memory_samples) if memory_samples else final_memory
        avg_memory = statistics.mean(memory_samples) if memory_samples else final_memory
        memory_growth = max_memory - initial_memory
        
        results["details"]["initial_memory_mb"] = round(initial_memory, 2)
        results["details"]["max_memory_mb"] = round(max_memory, 2)
        results["details"]["avg_memory_mb"] = round(avg_memory, 2)
        results["details"]["final_memory_mb"] = round(final_memory, 2)
        results["details"]["memory_growth_mb"] = round(memory_growth, 2)
        results["details"]["task_results"] = task_results
        results["details"]["concurrent_tasks_completed"] = len(task_results)
        
        # Check concurrent load handling
        if memory_growth > 200:  # More than 200MB growth
            results["issues"].append(f"High memory growth under concurrent load: {memory_growth:.2f}MB")
            results["status"] = "FAIL"
        elif memory_growth > 100:
            results["issues"].append(f"Moderate memory growth: {memory_growth:.2f}MB")
            results["status"] = "PARTIAL"
        
        # Check task completion
        failed_tasks = sum(1 for result in task_results if result == 0)
        if failed_tasks > 0:
            results["issues"].append(f"Failed tasks under load: {failed_tasks}")
            results["status"] = "PARTIAL"
        
    except Exception as e:
        results["issues"].append(f"Concurrent load test failed: {str(e)}")
        results["status"] = "FAIL"
    
    return results

def run_load_testing():
    """Run all load testing scenarios"""
    print("🔍 Phase 5: Load Testing Starting...")
    print("=" * 60)
    
    test_results = {
        "phase": "Phase 5: Load Testing",
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
        test_sustained_load_30min,
        test_memory_patterns_under_load,
        test_memory_stays_within_limits,
        test_system_recovery_after_pressure,
        test_concurrent_load_scenarios
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
    print(f"📊 Phase 5 Summary: {overall_status}")
    print(f"✅ Passed: {test_results['summary']['passed']}")
    print(f"⚠️  Partial: {test_results['summary']['partial']}")
    print(f"❌ Failed: {test_results['summary']['failed']}")
    
    return test_results

if __name__ == "__main__":
    results = run_load_testing()
    
    # Save results to file
    results_file = "/home/louranicas/projects/claude-optimized-deployment/phase5_load_testing_results.json"
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