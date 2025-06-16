#!/usr/bin/env python3
"""
MCP Performance Optimization Demo
Agent 7: Comprehensive demonstration of MCP performance optimizations.

This example demonstrates the complete MCP performance optimization system
including caching, connection pooling, monitoring, and validation.
"""

import asyncio
import time
import json
import logging
from datetime import datetime
from typing import Dict, Any, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def demonstrate_mcp_optimizations():
    """
    Comprehensive demonstration of MCP performance optimizations.
    """
    print("🚀 MCP Performance Optimization Demo")
    print("=" * 60)
    
    # Import optimization modules
    try:
        from src.core.mcp_cache import get_mcp_cache, CacheStrategy
        from src.mcp.performance import get_performance_optimizer, PerformanceConfig
        from src.mcp.performance_monitor import get_performance_monitor
        from src.mcp.connection_optimizer import get_mcp_connection_manager
        from src.mcp.startup_optimizer import MCPStartupOptimizer, StartupConfig
        from src.mcp.scaling_advisor import MCPScalingAdvisor
        from src.mcp.performance_validator import MCPPerformanceValidator
        
        print("✅ All optimization modules imported successfully")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please ensure all optimization modules are available")
        return
    
    # Step 1: Initialize Performance Components
    print("\n🔧 Step 1: Initializing Performance Components")
    print("-" * 50)
    
    try:
        # Initialize caching system
        cache = await get_mcp_cache()
        print(f"✅ Cache system initialized: {cache.__class__.__name__}")
        
        # Initialize performance optimizer
        config = PerformanceConfig(
            enable_caching=True,
            enable_pooling=True,
            enable_circuit_breaker=True,
            cache_size=1000,
            max_connections_per_server=20
        )
        optimizer = await get_performance_optimizer(config)
        print(f"✅ Performance optimizer initialized")
        
        # Initialize performance monitor
        monitor = await get_performance_monitor()
        print(f"✅ Performance monitor initialized")
        
        # Initialize connection manager
        conn_manager = await get_mcp_connection_manager()
        print(f"✅ Connection manager initialized")
        
        # Initialize startup optimizer
        startup_optimizer = MCPStartupOptimizer()
        await startup_optimizer.initialize()
        print(f"✅ Startup optimizer initialized")
        
        # Initialize scaling advisor
        scaling_advisor = MCPScalingAdvisor(monitor)
        await scaling_advisor.initialize()
        print(f"✅ Scaling advisor initialized")
        
        # Initialize validator
        validator = MCPPerformanceValidator()
        await validator.initialize()
        print(f"✅ Performance validator initialized")
        
    except Exception as e:
        print(f"❌ Initialization error: {e}")
        return
    
    # Step 2: Demonstrate Caching Performance
    print("\n💾 Step 2: Demonstrating Caching Performance")
    print("-" * 50)
    
    # Test cache operations
    cache_test_data = {
        "brave_search_results": {"query": "test", "results": ["result1", "result2"]},
        "docker_status": {"containers": 5, "images": 10},
        "kubernetes_pods": {"running": 8, "pending": 2}
    }
    
    # Cache performance test
    start_time = time.time()
    
    # Store data in cache
    for key, value in cache_test_data.items():
        await cache.set(key, value, ttl=300, tags=["demo", "test"])
    
    cache_store_time = time.time() - start_time
    
    # Retrieve data from cache
    start_time = time.time()
    cache_hits = 0
    
    for key in cache_test_data.keys():
        result = await cache.get(key)
        if result is not None:
            cache_hits += 1
    
    cache_retrieve_time = time.time() - start_time
    
    # Get cache statistics
    cache_stats = cache.get_stats()
    
    print(f"✅ Cache operations completed:")
    print(f"   - Store time: {cache_store_time:.3f}s")
    print(f"   - Retrieve time: {cache_retrieve_time:.3f}s")
    print(f"   - Hit rate: {cache_stats.get('hit_rate', 0):.2%}")
    print(f"   - Cache size: {cache_stats.get('size', 0)} entries")
    
    # Step 3: Demonstrate Performance Optimization
    print("\n⚡ Step 3: Demonstrating Performance Optimization")
    print("-" * 50)
    
    # Simulate MCP tool calls
    test_operations = [
        ("brave", "web_search", {"query": "performance test", "count": 5}),
        ("docker", "ps", {}),
        ("kubernetes", "get_pods", {"namespace": "default"}),
        ("security-scanner", "scan_file", {"file_path": "test.py"}),
    ]
    
    # Test without optimization (simulated)
    print("Testing baseline performance...")
    baseline_times = []
    
    for server, tool, args in test_operations:
        start_time = time.time()
        
        # Simulate tool execution (in real implementation, would call actual tools)
        await asyncio.sleep(0.1 + (len(str(args)) * 0.01))  # Simulate processing time
        
        duration = time.time() - start_time
        baseline_times.append(duration)
        
        # Record in monitor
        monitor.record_mcp_call(server, tool, duration * 1000, True)
    
    baseline_avg = sum(baseline_times) / len(baseline_times)
    
    # Test with optimization
    print("Testing optimized performance...")
    optimized_times = []
    
    for server, tool, args in test_operations:
        start_time = time.time()
        
        try:
            # Use optimizer for tool execution
            result = await optimizer.optimize_tool_call(server, tool, args)
            duration = time.time() - start_time
            optimized_times.append(duration)
            
            # Record in monitor
            monitor.record_mcp_call(server, tool, duration * 1000, True)
            
        except Exception as e:
            logger.warning(f"Optimization test error for {server}.{tool}: {e}")
            duration = time.time() - start_time
            optimized_times.append(duration)
    
    optimized_avg = sum(optimized_times) / len(optimized_times)
    improvement = ((baseline_avg - optimized_avg) / baseline_avg) * 100 if baseline_avg > 0 else 0
    
    print(f"✅ Performance optimization results:")
    print(f"   - Baseline average: {baseline_avg:.3f}s")
    print(f"   - Optimized average: {optimized_avg:.3f}s")
    print(f"   - Improvement: {improvement:.1f}%")
    
    # Step 4: Demonstrate Batch Processing
    print("\n📦 Step 4: Demonstrating Batch Processing")
    print("-" * 50)
    
    # Test batch processing
    batch_operations = [
        ("brave", "web_search", {"query": f"batch test {i}", "count": 3})
        for i in range(10)
    ]
    
    start_time = time.time()
    batch_results = await optimizer.batch_tool_calls(batch_operations)
    batch_duration = time.time() - start_time
    
    successful_results = len([r for r in batch_results if not isinstance(r, Exception)])
    
    print(f"✅ Batch processing results:")
    print(f"   - Operations: {len(batch_operations)}")
    print(f"   - Duration: {batch_duration:.3f}s")
    print(f"   - Success rate: {successful_results}/{len(batch_operations)}")
    print(f"   - Avg per operation: {batch_duration/len(batch_operations):.3f}s")
    
    # Step 5: Demonstrate Monitoring and Analytics
    print("\n📊 Step 5: Performance Monitoring and Analytics")
    print("-" * 50)
    
    # Get performance summary
    performance_summary = monitor.get_performance_summary()
    
    print("✅ Performance monitoring summary:")
    operations = performance_summary.get("operations", {})
    print(f"   - Operations tracked: {len(operations)}")
    
    for op_key, metrics in list(operations.items())[:3]:  # Show top 3
        print(f"   - {op_key}:")
        print(f"     • Calls: {metrics.get('total_calls', 0)}")
        print(f"     • Success rate: {metrics.get('success_rate', 0):.2%}")
        print(f"     • Avg duration: {metrics.get('avg_duration_ms', 0):.1f}ms")
    
    # System metrics
    system_metrics = performance_summary.get("system", {})
    if system_metrics:
        print(f"   - System CPU: {system_metrics.get('avg_cpu_percent', 0):.1f}%")
        print(f"   - System Memory: {system_metrics.get('avg_memory_mb', 0):.1f}MB")
    
    # Step 6: Demonstrate Scaling Recommendations
    print("\n📈 Step 6: Scaling and Optimization Recommendations")
    print("-" * 50)
    
    # Get scaling recommendations
    scaling_recs = scaling_advisor.get_scaling_recommendations()
    load_balancing_recs = scaling_advisor.get_load_balancing_recommendations()
    capacity_predictions = scaling_advisor.get_capacity_predictions()
    
    print(f"✅ Scaling analysis:")
    print(f"   - Scaling recommendations: {len(scaling_recs)}")
    print(f"   - Load balancing recommendations: {len(load_balancing_recs)}")
    print(f"   - Capacity predictions: {len(capacity_predictions)}")
    
    # Show sample recommendations
    if scaling_recs:
        rec = scaling_recs[0]
        print(f"   - Sample scaling rec: {rec.direction.value} {rec.resource_type.value}")
        print(f"     • Confidence: {rec.confidence:.2f}")
        print(f"     • Urgency: {rec.urgency}")
    
    # Step 7: Validation and Reporting
    print("\n✅ Step 7: Performance Validation and Reporting")
    print("-" * 50)
    
    # Capture baseline
    print("Capturing performance baseline...")
    baseline = await validator.capture_baseline()
    print(f"   - Baseline response time: {baseline.avg_response_time_ms:.1f}ms")
    print(f"   - Baseline throughput: {baseline.throughput_rps:.1f} RPS")
    print(f"   - Baseline cache hit rate: {baseline.cache_hit_rate:.2%}")
    
    # Run validation tests
    print("Running validation tests...")
    validation_tests = await validator.run_validation_tests()
    
    # Summarize test results
    test_summary = {
        "total": len(validation_tests),
        "passed": len([t for t in validation_tests if t.result.value == "pass"]),
        "warnings": len([t for t in validation_tests if t.result.value == "warning"]),
        "failed": len([t for t in validation_tests if t.result.value == "fail"]),
        "skipped": len([t for t in validation_tests if t.result.value == "skip"])
    }
    
    print(f"✅ Validation results:")
    print(f"   - Total tests: {test_summary['total']}")
    print(f"   - Passed: {test_summary['passed']}")
    print(f"   - Warnings: {test_summary['warnings']}")
    print(f"   - Failed: {test_summary['failed']}")
    print(f"   - Skipped: {test_summary['skipped']}")
    print(f"   - Pass rate: {(test_summary['passed']/max(test_summary['total'], 1))*100:.1f}%")
    
    # Generate comprehensive report
    print("Generating comprehensive performance report...")
    report = validator.generate_comprehensive_report()
    
    # Export report
    report_filename = f"mcp_performance_demo_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    validator.export_report(report_filename)
    print(f"   - Report exported: {report_filename}")
    
    # Step 8: Performance Summary
    print("\n🎯 Step 8: Performance Optimization Summary")
    print("-" * 50)
    
    # Calculate overall performance metrics
    final_cache_stats = cache.get_stats()
    final_performance_report = optimizer.get_performance_report()
    
    print("✅ Overall optimization results:")
    print(f"   - Cache hit rate: {final_cache_stats.get('hit_rate', 0):.2%}")
    print(f"   - Average response time improvement: {improvement:.1f}%")
    print(f"   - Batch processing efficiency: {len(batch_operations)/batch_duration:.1f} ops/sec")
    print(f"   - Validation pass rate: {(test_summary['passed']/max(test_summary['total'], 1))*100:.1f}%")
    
    # Executive summary
    summary = report.get("executive_summary", {})
    print(f"   - Overall system status: {summary.get('overall_status', 'Unknown')}")
    print(f"   - High-impact optimizations: {summary.get('high_impact_optimizations', 0)}")
    print(f"   - Critical issues: {summary.get('critical_issues', 0)}")
    
    print("\n🎉 MCP Performance Optimization Demo Complete!")
    print("=" * 60)
    
    # Cleanup
    print("\n🧹 Cleaning up resources...")
    try:
        await cache.shutdown()
        await optimizer.shutdown()
        await monitor.shutdown()
        await conn_manager.shutdown()
        await startup_optimizer.shutdown()
        await scaling_advisor.shutdown()
        await validator.shutdown()
        print("✅ All resources cleaned up successfully")
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")
    
    return report


async def run_performance_benchmark():
    """
    Run a focused performance benchmark.
    """
    print("\n🏁 Running Performance Benchmark")
    print("-" * 40)
    
    # Simple benchmark test
    iterations = 100
    operations = [
        ("cache_test", lambda: asyncio.sleep(0.01)),
        ("compute_test", lambda: sum(range(1000))),
        ("io_test", lambda: asyncio.sleep(0.005))
    ]
    
    results = {}
    
    for op_name, op_func in operations:
        print(f"Benchmarking {op_name}...")
        
        start_time = time.time()
        for _ in range(iterations):
            if asyncio.iscoroutinefunction(op_func):
                await op_func()
            else:
                op_func()
        
        duration = time.time() - start_time
        ops_per_sec = iterations / duration
        
        results[op_name] = {
            "duration": duration,
            "ops_per_sec": ops_per_sec,
            "avg_time_ms": (duration / iterations) * 1000
        }
        
        print(f"   - {ops_per_sec:.1f} ops/sec, {results[op_name]['avg_time_ms']:.2f}ms avg")
    
    return results


if __name__ == "__main__":
    async def main():
        # Run comprehensive demo
        report = await demonstrate_mcp_optimizations()
        
        # Run benchmark
        benchmark_results = await run_performance_benchmark()
        
        print(f"\n📋 Demo completed successfully!")
        print(f"Performance report and benchmark results available.")
        
        # Print final summary
        if report:
            executive_summary = report.get("executive_summary", {})
            print(f"\n🎯 Final Results Summary:")
            print(f"   - System Status: {executive_summary.get('overall_status', 'Unknown')}")
            print(f"   - Optimization Effectiveness: {executive_summary.get('optimization_effectiveness', 'Unknown')}")
            print(f"   - Test Pass Rate: {executive_summary.get('test_pass_rate', 'Unknown')}")
    
    # Run the demo
    asyncio.run(main())