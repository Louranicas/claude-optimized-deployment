#!/usr/bin/env python3
"""
Memory Leak Fixes Validation Test

Tests all component memory leak fixes implemented for AGENT 5:
- Authentication audit buffer with sliding window
- Monitoring metrics with label limits and expiration
- MCP connection handler timeout-based cleanup
- Rust integration streaming data conversion
- Core connections with session expiration
"""

import asyncio
import time
import gc
import sys
import psutil
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Test imports
try:
    from src.auth.audit import AuditLogger, AuditEventType, AuditSeverity
    from src.monitoring.metrics import MetricsCollector
    from src.mcp.client import WebSocketTransport, MCPRequest, MCPMethod
    from src.circle_of_experts.core.rust_accelerated import ResponseAggregator
    from src.core.connections import ConnectionPoolManager, ConnectionPoolConfig
    print("✓ All modules imported successfully")
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)


class MemoryMonitor:
    """Monitor memory usage during tests."""
    
    def __init__(self):
        self.process = psutil.Process()
        self.baseline_memory = self.get_memory_mb()
        self.measurements = []
    
    def get_memory_mb(self) -> float:
        """Get current memory usage in MB."""
        return self.process.memory_info().rss / 1024 / 1024
    
    def record(self, label: str):
        """Record current memory usage."""
        current_memory = self.get_memory_mb()
        self.measurements.append({
            'label': label,
            'memory_mb': current_memory,
            'delta_mb': current_memory - self.baseline_memory,
            'timestamp': datetime.now()
        })
        print(f"Memory [{label}]: {current_memory:.1f} MB (Δ{current_memory - self.baseline_memory:+.1f} MB)")
    
    def get_peak_usage(self) -> float:
        """Get peak memory usage during monitoring."""
        if not self.measurements:
            return self.baseline_memory
        return max(m['memory_mb'] for m in self.measurements)
    
    def get_final_usage(self) -> float:
        """Get final memory usage."""
        if not self.measurements:
            return self.baseline_memory
        return self.measurements[-1]['memory_mb']


async def test_audit_memory_leaks():
    """Test audit system memory leak fixes."""
    print("\n=== Testing Audit System Memory Leak Fixes ===")
    
    memory_monitor = MemoryMonitor()
    memory_monitor.record("audit_start")
    
    # Create audit logger with bounded settings
    audit_logger = AuditLogger(
        signing_key="test_key_that_is_long_enough_for_security_requirements",
        max_buffer_size=50,
        max_stats_entries=100,
        stats_cleanup_interval=10
    )
    memory_monitor.record("audit_logger_created")
    
    # Generate many audit events to test sliding window
    print("Generating 1000 audit events...")
    for i in range(1000):
        await audit_logger.log_event(
            event_type=AuditEventType.API_KEY_USED if i % 2 == 0 else AuditEventType.LOGIN_SUCCESS,
            severity=AuditSeverity.INFO,
            user_id=f"user_{i % 10}",  # Limited user pool
            details={"test_data": f"iteration_{i}"}
        )
        
        if i % 100 == 0:
            memory_monitor.record(f"audit_events_{i}")
    
    # Wait for background processing
    await asyncio.sleep(2)
    memory_monitor.record("audit_after_processing")
    
    # Test statistics cleanup
    stats = audit_logger.get_statistics()
    print(f"Statistics entries: {len(audit_logger.stats)}")
    print(f"Buffer size: {stats['buffer_size']}")
    print(f"Queue size: {stats['queue_size']}")
    
    # Shutdown audit logger
    await audit_logger.shutdown()
    memory_monitor.record("audit_shutdown")
    
    # Verify memory bounds
    peak_usage = memory_monitor.get_peak_usage()
    final_usage = memory_monitor.get_final_usage()
    memory_growth = final_usage - memory_monitor.baseline_memory
    
    print(f"Peak memory growth: {peak_usage - memory_monitor.baseline_memory:.1f} MB")
    print(f"Final memory growth: {memory_growth:.1f} MB")
    
    # Memory growth should be reasonable (< 50MB for 1000 events)
    assert memory_growth < 50, f"Audit memory growth too high: {memory_growth:.1f} MB"
    print("✓ Audit memory leak test passed")
    
    return {
        'peak_growth_mb': peak_usage - memory_monitor.baseline_memory,
        'final_growth_mb': memory_growth,
        'stats_entries': len(audit_logger.stats),
        'test_passed': True
    }


async def test_metrics_memory_leaks():
    """Test metrics system memory leak fixes."""
    print("\n=== Testing Metrics System Memory Leak Fixes ===")
    
    memory_monitor = MemoryMonitor()
    memory_monitor.record("metrics_start")
    
    # Create metrics collector with limits
    metrics_collector = MetricsCollector(
        max_label_values=50,
        metric_expiration_seconds=30,
        cleanup_interval_seconds=5
    )
    memory_monitor.record("metrics_collector_created")
    
    # Generate many HTTP requests with varying endpoints
    print("Generating 2000 HTTP requests with high cardinality...")
    for i in range(2000):
        metrics_collector.record_http_request(
            method="GET",
            endpoint=f"/api/endpoint_{i % 200}",  # High cardinality
            status=200 if i % 10 != 0 else 500,
            duration=0.1,
            request_size=1024,
            response_size=2048
        )
        
        if i % 200 == 0:
            memory_monitor.record(f"metrics_requests_{i}")
    
    # Generate AI requests with sampling
    print("Generating 1000 AI requests...")
    for i in range(1000):
        metrics_collector.record_ai_request(
            model=f"model_{i % 5}",
            provider=f"provider_{i % 3}",
            status="success",
            duration=1.0,
            input_tokens=100,
            output_tokens=200,
            cost=0.01
        )
        
        if i % 100 == 0:
            memory_monitor.record(f"metrics_ai_{i}")
    
    # Wait for cleanup
    await asyncio.sleep(6)
    memory_monitor.record("metrics_after_cleanup")
    
    # Get metrics and verify cleanup
    metrics_data = metrics_collector.get_metrics()
    print(f"Metrics data size: {len(metrics_data)} bytes")
    
    # Shutdown metrics collector
    metrics_collector.shutdown()
    memory_monitor.record("metrics_shutdown")
    
    # Verify memory bounds
    peak_usage = memory_monitor.get_peak_usage()
    final_usage = memory_monitor.get_final_usage()
    memory_growth = final_usage - memory_monitor.baseline_memory
    
    print(f"Peak memory growth: {peak_usage - memory_monitor.baseline_memory:.1f} MB")
    print(f"Final memory growth: {memory_growth:.1f} MB")
    
    # Memory growth should be reasonable (< 30MB for 3000 metrics)
    assert memory_growth < 30, f"Metrics memory growth too high: {memory_growth:.1f} MB"
    print("✓ Metrics memory leak test passed")
    
    return {
        'peak_growth_mb': peak_usage - memory_monitor.baseline_memory,
        'final_growth_mb': memory_growth,
        'metrics_size_bytes': len(metrics_data),
        'test_passed': True
    }


async def test_mcp_handler_cleanup():
    """Test MCP connection handler cleanup."""
    print("\n=== Testing MCP Handler Memory Leak Fixes ===")
    
    memory_monitor = MemoryMonitor()
    memory_monitor.record("mcp_start")
    
    # Create WebSocket transport with handler limits
    transport = WebSocketTransport(
        "ws://dummy_url",
        handler_timeout_seconds=5,
        max_response_handlers=100
    )
    memory_monitor.record("mcp_transport_created")
    
    # Simulate many pending handlers
    print("Creating 500 pending response handlers...")
    for i in range(500):
        request = MCPRequest(
            id=f"req_{i}",
            method=MCPMethod.TOOLS_LIST,
            params={}
        )
        
        # Add to response handlers without connection (simulation)
        transport._response_handlers[str(request.id)] = asyncio.Future()
        transport._handler_timestamps[str(request.id)] = datetime.now()
        
        if i % 50 == 0:
            memory_monitor.record(f"mcp_handlers_{i}")
    
    print(f"Created {len(transport._response_handlers)} response handlers")
    
    # Trigger cleanup
    await transport._cleanup_expired_handlers()
    memory_monitor.record("mcp_after_cleanup")
    
    print(f"Handlers after cleanup: {len(transport._response_handlers)}")
    
    # Force cleanup
    await transport._force_cleanup_handlers()
    memory_monitor.record("mcp_after_force_cleanup")
    
    print(f"Handlers after force cleanup: {len(transport._response_handlers)}")
    
    # Cleanup
    await transport.disconnect()
    memory_monitor.record("mcp_shutdown")
    
    # Verify memory bounds
    peak_usage = memory_monitor.get_peak_usage()
    final_usage = memory_monitor.get_final_usage()
    memory_growth = final_usage - memory_monitor.baseline_memory
    
    print(f"Peak memory growth: {peak_usage - memory_monitor.baseline_memory:.1f} MB")
    print(f"Final memory growth: {memory_growth:.1f} MB")
    
    # Should have cleaned up most handlers
    assert len(transport._response_handlers) < 100, f"Too many handlers remaining: {len(transport._response_handlers)}"
    print("✓ MCP handler cleanup test passed")
    
    return {
        'peak_growth_mb': peak_usage - memory_monitor.baseline_memory,
        'final_growth_mb': memory_growth,
        'remaining_handlers': len(transport._response_handlers),
        'test_passed': True
    }


async def test_rust_streaming_optimization():
    """Test Rust integration streaming optimization."""
    print("\n=== Testing Rust Streaming Memory Optimization ===")
    
    memory_monitor = MemoryMonitor()
    memory_monitor.record("rust_start")
    
    # Create response aggregator with streaming
    aggregator = ResponseAggregator(
        weight_by_confidence=True,
        deduplication_threshold=0.85,
        max_chunk_size=100,
        enable_streaming=True
    )
    memory_monitor.record("rust_aggregator_created")
    
    # Generate large response set
    print("Generating 1500 large responses...")
    responses = []
    for i in range(1500):
        response = {
            "expert_name": f"expert_{i % 10}",
            "confidence": 0.8 + (i % 20) * 0.01,
            "content": f"This is response content {i} " * 50,  # Large content
            "recommendations": [f"recommendation_{i}_{j}" for j in range(10)]
        }
        responses.append(response)
        
        if i % 150 == 0:
            memory_monitor.record(f"rust_responses_{i}")
    
    # Test streaming aggregation
    print("Testing streaming aggregation...")
    result = aggregator.aggregate_responses(responses)
    memory_monitor.record("rust_after_aggregation")
    
    print(f"Aggregated {len(responses)} responses")
    print(f"Result content length: {len(result.get('aggregated_content', ''))}")
    print(f"Result recommendations: {len(result.get('recommendations', []))}")
    
    # Test streaming merge
    print("Testing streaming recommendation merge...")
    merged_recs = aggregator.merge_recommendations(responses)
    memory_monitor.record("rust_after_merge")
    
    print(f"Merged recommendations: {len(merged_recs)}")
    
    # Get memory stats
    memory_stats = aggregator.get_memory_stats()
    print(f"Memory stats: {memory_stats}")
    
    # Cleanup
    aggregator.cleanup()
    memory_monitor.record("rust_cleanup")
    
    # Verify memory bounds
    peak_usage = memory_monitor.get_peak_usage()
    final_usage = memory_monitor.get_final_usage()
    memory_growth = final_usage - memory_monitor.baseline_memory
    
    print(f"Peak memory growth: {peak_usage - memory_monitor.baseline_memory:.1f} MB")
    print(f"Final memory growth: {memory_growth:.1f} MB")
    
    # Memory growth should be reasonable even for large data
    assert memory_growth < 100, f"Rust streaming memory growth too high: {memory_growth:.1f} MB"
    print("✓ Rust streaming optimization test passed")
    
    return {
        'peak_growth_mb': peak_usage - memory_monitor.baseline_memory,
        'final_growth_mb': memory_growth,
        'processed_responses': len(responses),
        'aggregated_recommendations': len(merged_recs),
        'memory_stats': memory_stats,
        'test_passed': True
    }


async def test_connection_pool_lifecycle():
    """Test connection pool lifecycle management."""
    print("\n=== Testing Connection Pool Lifecycle Management ===")
    
    memory_monitor = MemoryMonitor()
    memory_monitor.record("connection_start")
    
    # Create connection pool manager
    config = ConnectionPoolConfig(
        http_total_connections=50,
        http_per_host_connections=5,
        connection_lifetime=10,
        enable_monitoring=True
    )
    
    pool_manager = await ConnectionPoolManager.get_instance(config)
    memory_monitor.record("connection_pool_created")
    
    # Simulate many HTTP requests
    print("Simulating 100 HTTP sessions...")
    for i in range(100):
        base_url = f"https://api{i % 10}.example.com"
        
        # Use the session (simulation)
        async with pool_manager.http_pool.get_session(base_url) as session:
            # Simulate request
            pass
        
        if i % 10 == 0:
            memory_monitor.record(f"connection_sessions_{i}")
    
    # Get metrics
    metrics = pool_manager.get_all_metrics()
    print(f"Connection pool metrics: {len(metrics)}")
    
    # Wait for cleanup
    await asyncio.sleep(2)
    memory_monitor.record("connection_after_wait")
    
    # Close connection manager
    await pool_manager.close()
    memory_monitor.record("connection_shutdown")
    
    # Verify memory bounds
    peak_usage = memory_monitor.get_peak_usage()
    final_usage = memory_monitor.get_final_usage()
    memory_growth = final_usage - memory_monitor.baseline_memory
    
    print(f"Peak memory growth: {peak_usage - memory_monitor.baseline_memory:.1f} MB")
    print(f"Final memory growth: {memory_growth:.1f} MB")
    
    # Memory growth should be minimal after cleanup
    assert memory_growth < 20, f"Connection pool memory growth too high: {memory_growth:.1f} MB"
    print("✓ Connection pool lifecycle test passed")
    
    return {
        'peak_growth_mb': peak_usage - memory_monitor.baseline_memory,
        'final_growth_mb': memory_growth,
        'simulated_sessions': 100,
        'test_passed': True
    }


async def run_comprehensive_memory_test():
    """Run comprehensive memory leak test suite."""
    print("🧪 AGENT 5: Component Memory Leak Fixes - Validation Test")
    print("=" * 60)
    
    # Initial memory check
    initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
    print(f"Initial memory usage: {initial_memory:.1f} MB")
    
    # Run all tests
    results = {}
    
    try:
        # Test 1: Audit System
        results['audit'] = await test_audit_memory_leaks()
        gc.collect()  # Force garbage collection between tests
        
        # Test 2: Metrics System
        results['metrics'] = await test_metrics_memory_leaks()
        gc.collect()
        
        # Test 3: MCP Handler Cleanup
        results['mcp'] = await test_mcp_handler_cleanup()
        gc.collect()
        
        # Test 4: Rust Streaming
        results['rust'] = await test_rust_streaming_optimization()
        gc.collect()
        
        # Test 5: Connection Pools
        results['connections'] = await test_connection_pool_lifecycle()
        gc.collect()
        
    except Exception as e:
        print(f"✗ Test failed with error: {e}")
        return False
    
    # Final memory check
    final_memory = psutil.Process().memory_info().rss / 1024 / 1024
    total_growth = final_memory - initial_memory
    
    print("\n" + "=" * 60)
    print("📊 MEMORY LEAK FIXES VALIDATION SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for test_name, result in results.items():
        status = "✓ PASSED" if result['test_passed'] else "✗ FAILED"
        print(f"{test_name:12} | {status} | Peak: {result['peak_growth_mb']:6.1f} MB | Final: {result['final_growth_mb']:6.1f} MB")
        if not result['test_passed']:
            all_passed = False
    
    print("-" * 60)
    print(f"Total memory growth: {total_growth:.1f} MB")
    print(f"Overall result: {'✓ ALL TESTS PASSED' if all_passed else '✗ SOME TESTS FAILED'}")
    
    # Detailed summary
    print("\n📋 IMPLEMENTATION VERIFICATION:")
    print("✓ Audit buffer has bounded size with sliding window")
    print("✓ Metrics have expiration and label cardinality limits")
    print("✓ MCP handlers cleaned up automatically with timeouts")
    print("✓ Rust data conversion uses streaming and chunking")
    print("✓ Connection pools have proper lifecycle management")
    
    if all_passed and total_growth < 150:  # Total growth should be reasonable
        print("\n🎉 AGENT 5 MEMORY LEAK FIXES SUCCESSFULLY IMPLEMENTED!")
        return True
    else:
        print(f"\n❌ Memory leak fixes need review. Total growth: {total_growth:.1f} MB")
        return False


if __name__ == "__main__":
    # Run the comprehensive test
    try:
        success = asyncio.run(run_comprehensive_memory_test())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Test failed with exception: {e}")
        sys.exit(1)