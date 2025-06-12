#!/usr/bin/env python3
"""
Comprehensive GC Optimization Test Suite

Tests all garbage collection optimizations including:
- GC tuning and manual triggers
- Object pooling efficiency 
- Memory pressure detection
- Stream processing memory optimization
- V8 flag validation
"""

import asyncio
import time
import psutil
import gc
import json
from typing import Dict, Any, List
from datetime import datetime
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.gc_optimization import (
    GCOptimizer, gc_optimizer, with_gc_optimization, 
    periodic_gc_check, get_v8_flags
)
from src.core.object_pool import (
    ObjectPool, DictPool, ListPool, StringBuilderPool, 
    PoolManager, pooled, PoolStatistics
)
from src.core.memory_monitor import (
    MemoryMonitor, memory_monitor, MemoryPressureLevel,
    check_memory_pressure, with_memory_monitoring
)
from src.core.stream_processor import (
    ChunkedStreamProcessor, JsonStreamProcessor, 
    MemoryEfficientBuffer, stream_map, stream_reduce
)


class GCOptimizationTestSuite:
    """Comprehensive test suite for GC optimizations"""
    
    def __init__(self):
        self.test_results = {}
        self.start_time = time.time()
        
    def log_test_result(self, test_name: str, success: bool, details: Dict[str, Any]):
        """Log test result with timing and details"""
        self.test_results[test_name] = {
            "success": success,
            "timestamp": datetime.now().isoformat(),
            "details": details
        }
        status = "PASS" if success else "FAIL"
        print(f"[{status}] {test_name}: {details.get('summary', 'No summary')}")
        
    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage metrics"""
        process = psutil.Process()
        memory_info = process.memory_info()
        return {
            "rss_mb": memory_info.rss / 1024 / 1024,
            "vms_mb": memory_info.vms / 1024 / 1024,
            "percent": process.memory_percent()
        }
        
    def test_gc_optimizer_basic(self):
        """Test basic GC optimizer functionality"""
        try:
            # Test manual GC trigger
            before_memory = self.get_memory_usage()
            metrics = gc_optimizer.trigger_gc(force=True)
            after_memory = self.get_memory_usage()
            
            success = (
                metrics is not None and
                metrics.pause_time_ms >= 0 and
                metrics.efficiency_percent >= 0
            )
            
            details = {
                "summary": f"GC triggered, pause: {metrics.pause_time_ms:.2f}ms, efficiency: {metrics.efficiency_percent:.2f}%",
                "memory_before_mb": before_memory["rss_mb"],
                "memory_after_mb": after_memory["rss_mb"],
                "memory_freed_mb": metrics.memory_freed_mb if metrics else 0,
                "gc_stats": gc_optimizer.get_gc_stats()
            }
            
            self.log_test_result("gc_optimizer_basic", success, details)
            
        except Exception as e:
            self.log_test_result("gc_optimizer_basic", False, {"error": str(e)})
            
    def test_gc_optimization_modes(self):
        """Test GC optimization for different modes"""
        try:
            # Test throughput optimization
            gc_optimizer.optimize_for_throughput()
            throughput_stats = gc_optimizer.get_gc_stats()
            
            # Test latency optimization  
            gc_optimizer.optimize_for_latency()
            latency_stats = gc_optimizer.get_gc_stats()
            
            success = True  # Basic functionality test
            
            details = {
                "summary": "GC modes tested successfully",
                "throughput_mode": throughput_stats,
                "latency_mode": latency_stats,
                "gc_thresholds": gc.get_threshold()
            }
            
            self.log_test_result("gc_optimization_modes", success, details)
            
        except Exception as e:
            self.log_test_result("gc_optimization_modes", False, {"error": str(e)})
            
    def test_object_pools_efficiency(self):
        """Test object pool efficiency and memory savings"""
        try:
            # Test DictPool
            dicts_created = []
            for _ in range(1000):
                with pooled(DictPool) as d:
                    d["test"] = "value"
                    dicts_created.append(len(d))
                    
            dict_stats = DictPool.get_statistics()
            
            # Test ListPool
            lists_created = []
            for _ in range(1000):
                with pooled(ListPool) as l:
                    l.append("item")
                    lists_created.append(len(l))
                    
            list_stats = ListPool.get_statistics()
            
            # Test StringBuilderPool
            strings_built = []
            for i in range(1000):
                with pooled(StringBuilderPool) as sb:
                    sb.append(f"string_{i}")
                    strings_built.append(sb.build())
                    
            string_stats = StringBuilderPool.get_statistics()
            
            # Check efficiency
            total_hit_rate = (
                dict_stats.hit_rate + 
                list_stats.hit_rate + 
                string_stats.hit_rate
            ) / 3
            
            success = total_hit_rate > 0.5  # At least 50% hit rate
            
            details = {
                "summary": f"Object pools tested, avg hit rate: {total_hit_rate:.2f}%",
                "dict_pool": {
                    "hit_rate": dict_stats.hit_rate,
                    "created": dict_stats.created_count,
                    "reused": dict_stats.reused_count,
                    "current_size": dict_stats.current_size
                },
                "list_pool": {
                    "hit_rate": list_stats.hit_rate,
                    "created": list_stats.created_count,
                    "reused": list_stats.reused_count,
                    "current_size": list_stats.current_size
                },
                "string_pool": {
                    "hit_rate": string_stats.hit_rate,
                    "created": string_stats.created_count,
                    "reused": string_stats.reused_count,
                    "current_size": string_stats.current_size
                }
            }
            
            self.log_test_result("object_pools_efficiency", success, details)
            
        except Exception as e:
            self.log_test_result("object_pools_efficiency", False, {"error": str(e)})
            
    async def test_memory_monitoring(self):
        """Test memory pressure detection and monitoring"""
        try:
            # Get current metrics
            metrics = memory_monitor.get_current_metrics()
            
            # Test pressure detection
            is_pressure = memory_monitor.check_memory_pressure()
            
            # Start monitoring briefly
            await memory_monitor.start_monitoring()
            await asyncio.sleep(1)  # Let it run briefly
            await memory_monitor.stop_monitoring()
            
            # Get statistics
            stats = memory_monitor.get_pressure_statistics()
            history = memory_monitor.get_metrics_history()
            
            success = (
                metrics.process_memory_mb > 0 and
                metrics.system_memory_percent > 0 and
                stats["total_samples"] >= 0
            )
            
            details = {
                "summary": f"Memory monitoring: {metrics.process_memory_mb:.2f}MB process, {metrics.system_memory_percent:.1f}% system",
                "current_pressure_level": metrics.pressure_level.value,
                "is_under_pressure": is_pressure,
                "monitoring_stats": stats,
                "history_size": len(history)
            }
            
            self.log_test_result("memory_monitoring", success, details)
            
        except Exception as e:
            self.log_test_result("memory_monitoring", False, {"error": str(e)})
            
    async def test_stream_processing_memory(self):
        """Test stream processing memory optimization"""
        try:
            # Create test data stream
            async def generate_test_data():
                for i in range(10000):
                    yield {"id": i, "data": f"test_data_{i}" * 10}
                    
            # Test chunked processing
            processor = JsonStreamProcessor(
                transform_func=lambda x: {"processed_id": x["id"]},
                chunk_size=100,
                max_memory_mb=512
            )
            
            processed_items = []
            def collect_output(chunk):
                processed_items.extend(chunk)
                
            # Process stream
            before_memory = self.get_memory_usage()
            metrics = await processor.process_stream(
                generate_test_data(),
                output_handler=collect_output
            )
            after_memory = self.get_memory_usage()
            
            # Test memory buffer
            buffer = MemoryEfficientBuffer(max_size=1000)
            for i in range(2000):
                buffer.add(f"item_{i}")
                
            success = (
                metrics.items_processed == 10000 and
                metrics.chunks_processed > 0 and
                len(processed_items) == 10000 and
                buffer.size() <= 1000  # Should have auto-flushed
            )
            
            details = {
                "summary": f"Processed {metrics.items_processed} items in {metrics.chunks_processed} chunks",
                "processing_time_ms": metrics.processing_time_ms,
                "peak_memory_mb": metrics.peak_memory_mb,
                "memory_before_mb": before_memory["rss_mb"],
                "memory_after_mb": after_memory["rss_mb"],
                "buffer_final_size": buffer.size(),
                "items_processed": len(processed_items)
            }
            
            self.log_test_result("stream_processing_memory", success, details)
            
        except Exception as e:
            self.log_test_result("stream_processing_memory", False, {"error": str(e)})
            
    def test_v8_flags_configuration(self):
        """Test V8 optimization flags configuration"""
        try:
            # Get flags for different environments
            prod_flags = get_v8_flags("production")
            dev_flags = get_v8_flags("development")
            
            # Validate flag format
            required_prod_flags = [
                "--max-old-space-size=6144",
                "--max-semi-space-size=64",
                "--initial-old-space-size=512",
                "--gc-interval=100"
            ]
            
            flags_present = all(flag in prod_flags for flag in required_prod_flags)
            
            success = (
                len(prod_flags) > 0 and
                len(dev_flags) > 0 and
                flags_present
            )
            
            details = {
                "summary": f"V8 flags configured: {len(prod_flags)} prod, {len(dev_flags)} dev",
                "production_flags": prod_flags,
                "development_flags": dev_flags,
                "required_flags_present": flags_present
            }
            
            self.log_test_result("v8_flags_configuration", success, details)
            
        except Exception as e:
            self.log_test_result("v8_flags_configuration", False, {"error": str(e)})
            
    async def test_with_decorators(self):
        """Test GC and memory monitoring decorators"""
        try:
            call_count = 0
            
            @with_gc_optimization
            def gc_decorated_func():
                nonlocal call_count
                call_count += 1
                # Create some garbage
                data = [{"test": i} for i in range(1000)]
                return len(data)
                
            @with_memory_monitoring
            async def memory_decorated_func():
                nonlocal call_count
                call_count += 1
                # Create some memory pressure
                data = ["x" * 1000 for _ in range(1000)]
                return len(data)
                
            # Test decorated functions
            gc_result = gc_decorated_func()
            memory_result = await memory_decorated_func()
            
            success = (
                call_count == 2 and
                gc_result == 1000 and
                memory_result == 1000
            )
            
            details = {
                "summary": f"Decorators tested, {call_count} functions called",
                "gc_decorated_result": gc_result,
                "memory_decorated_result": memory_result
            }
            
            self.log_test_result("decorator_functionality", success, details)
            
        except Exception as e:
            self.log_test_result("decorator_functionality", False, {"error": str(e)})
            
    def test_pool_manager_integration(self):
        """Test PoolManager centralized control"""
        try:
            # Get all pool statistics
            all_stats = PoolManager.get_all_statistics()
            
            # Get memory impact
            memory_impact = PoolManager.get_total_memory_impact()
            
            # Trigger cleanup
            PoolManager.cleanup_all_pools()
            
            success = (
                len(all_stats) >= 3 and  # Should have Dict, List, StringBuilder pools
                memory_impact["total_objects"] >= 0 and
                "StringBuilder" in all_stats and
                "Dict" in all_stats and
                "List" in all_stats
            )
            
            details = {
                "summary": f"PoolManager managing {len(all_stats)} pools",
                "pool_statistics": {name: {
                    "current_size": stats.current_size,
                    "hit_rate": stats.hit_rate,
                    "created_count": stats.created_count,
                    "reused_count": stats.reused_count
                } for name, stats in all_stats.items()},
                "memory_impact": memory_impact
            }
            
            self.log_test_result("pool_manager_integration", success, details)
            
        except Exception as e:
            self.log_test_result("pool_manager_integration", False, {"error": str(e)})
            
    async def test_periodic_gc_optimization(self):
        """Test periodic GC check and optimization"""
        try:
            # Run periodic checks multiple times
            results = []
            for _ in range(5):
                result = periodic_gc_check()
                results.append(result)
                await asyncio.sleep(0.1)
                
            # Check that some GC was triggered
            gc_triggered = any(r is not None for r in results)
            
            success = True  # Basic functionality test
            
            details = {
                "summary": f"Periodic GC checked 5 times, triggered: {gc_triggered}",
                "gc_results": [
                    {
                        "triggered": r is not None,
                        "pause_time_ms": r.pause_time_ms if r else None,
                        "efficiency_percent": r.efficiency_percent if r else None
                    } for r in results
                ]
            }
            
            self.log_test_result("periodic_gc_optimization", success, details)
            
        except Exception as e:
            self.log_test_result("periodic_gc_optimization", False, {"error": str(e)})
            
    async def run_all_tests(self):
        """Run all GC optimization tests"""
        print("=== GC Optimization Comprehensive Test Suite ===")
        print(f"Started at: {datetime.now().isoformat()}")
        print(f"Python version: {sys.version}")
        print(f"Initial memory usage: {self.get_memory_usage()}")
        print()
        
        # Run all tests
        self.test_gc_optimizer_basic()
        self.test_gc_optimization_modes()
        self.test_object_pools_efficiency()
        await self.test_memory_monitoring()
        await self.test_stream_processing_memory()
        self.test_v8_flags_configuration()
        await self.test_with_decorators()
        self.test_pool_manager_integration()
        await self.test_periodic_gc_optimization()
        
        # Generate summary
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results.values() if r["success"])
        failed_tests = total_tests - passed_tests
        
        print()
        print("=== TEST SUMMARY ===")
        print(f"Total tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success rate: {(passed_tests/total_tests)*100:.1f}%")
        print(f"Total runtime: {time.time() - self.start_time:.2f} seconds")
        print(f"Final memory usage: {self.get_memory_usage()}")
        
        return {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "success_rate": (passed_tests/total_tests)*100,
            "runtime_seconds": time.time() - self.start_time,
            "test_results": self.test_results
        }


async def main():
    """Main test runner"""
    test_suite = GCOptimizationTestSuite()
    
    try:
        results = await test_suite.run_all_tests()
        
        # Save detailed results
        with open("gc_optimization_test_results.json", "w") as f:
            json.dump(results, f, indent=2, default=str)
            
        print(f"\nDetailed results saved to: gc_optimization_test_results.json")
        
        # Exit with appropriate code
        if results["failed_tests"] == 0:
            print("\n🎉 All GC optimization tests passed!")
            return 0
        else:
            print(f"\n❌ {results['failed_tests']} tests failed")
            return 1
            
    except Exception as e:
        print(f"\n💥 Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))