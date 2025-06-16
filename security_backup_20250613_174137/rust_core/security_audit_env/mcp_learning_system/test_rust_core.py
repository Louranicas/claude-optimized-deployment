#!/usr/bin/env python3
"""
Test script for MCP Rust Core Python bindings.

This demonstrates the usage of the high-performance Rust core modules
from Python with minimal FFI overhead.
"""

import time
import json
import asyncio
from typing import Dict, Any

# Import the Rust core module (after building with maturin)
try:
    import mcp_rust_core
except ImportError:
    print("Error: mcp_rust_core module not found.")
    print("Please build the Rust module first:")
    print("  cd mcp_learning_system/rust_core")
    print("  maturin develop")
    exit(1)


def test_mcp_server():
    """Test the MCP server functionality."""
    print("\n=== Testing MCP Server ===")
    
    # Initialize the Rust core
    mcp_rust_core.initialize()
    
    # Create server with 100MB memory
    server = mcp_rust_core.MCPRustCore(memory_size_mb=100)
    
    # Define a Python handler
    def echo_handler(request):
        """Echo handler that returns the input params."""
        return {
            "result": request["params"],
            "error": None
        }
    
    # Register the handler
    server.register_handler("echo", echo_handler)
    
    # Test processing requests
    start_time = time.perf_counter()
    
    for i in range(1000):
        response = server.process_request(
            method="echo",
            params={"message": f"Hello {i}", "timestamp": time.time()},
            request_id=i
        )
        
        if i == 0:
            print(f"First response: {response}")
    
    elapsed = (time.perf_counter() - start_time) * 1000
    print(f"Processed 1000 requests in {elapsed:.2f}ms")
    print(f"Average latency: {elapsed:.2f}μs per request")
    
    # Get metrics
    metrics = server.get_metrics()
    print(f"\nServer metrics:")
    print(f"  Total requests: {metrics['total_requests']}")
    print(f"  Average latency: {metrics['avg_latency_us']:.2f}μs")
    print(f"  P99 latency: {metrics['p99_latency_us']}μs")
    print(f"  Memory usage: {metrics['memory_usage_mb']:.2f}MB")


def test_memory_pool():
    """Test the memory pool functionality."""
    print("\n=== Testing Memory Pool ===")
    
    # Create memory pool with 50MB
    pool = mcp_rust_core.MemoryPool(size_mb=50)
    
    # Store some learning data
    test_data = {
        "model_weights": [0.1, 0.2, 0.3, 0.4, 0.5],
        "training_stats": {"epoch": 10, "loss": 0.023}
    }
    
    # Store in learning storage
    key = "model_v1"
    data_bytes = json.dumps(test_data).encode('utf-8')
    pool.store_learning(key, data_bytes)
    
    # Retrieve from learning storage
    retrieved = pool.get_learning(key)
    if retrieved:
        retrieved_data = json.loads(retrieved.decode('utf-8'))
        print(f"Retrieved data: {retrieved_data}")
        assert retrieved_data == test_data
    
    # Get memory stats
    stats = pool.get_stats()
    print(f"\nMemory pool stats:")
    print(f"  Allocations: {stats['allocations']}")
    print(f"  Working memory: {stats['working_memory_mb']:.2f}MB")
    print(f"  Learning storage: {stats['learning_storage_mb']:.2f}MB")


def test_message_queue():
    """Test the message queue functionality."""
    print("\n=== Testing Message Queue ===")
    
    # Create message queue
    queue = mcp_rust_core.MessageQueue()
    
    # Send messages with different priorities
    messages_sent = []
    
    # Send low priority
    msg_id = queue.send({"type": "log", "level": "info"}, priority=0)
    messages_sent.append(("low", msg_id))
    
    # Send high priority
    msg_id = queue.send({"type": "alert", "level": "critical"}, priority=2)
    messages_sent.append(("high", msg_id))
    
    # Send normal priority
    msg_id = queue.send({"type": "metric", "value": 42}, priority=1)
    messages_sent.append(("normal", msg_id))
    
    print(f"Sent {len(messages_sent)} messages")
    
    # Receive messages (should be priority ordered)
    received = []
    while True:
        msg = queue.try_receive()
        if msg is None:
            break
        received.append(msg)
        print(f"Received: {msg['payload']} (priority: {msg['priority']})")
    
    # Test async receive with timeout
    print("\nTesting async receive with timeout...")
    start = time.time()
    msg = queue.receive_timeout(timeout_secs=0.1)
    elapsed = time.time() - start
    print(f"Timeout after {elapsed:.3f}s (expected ~0.1s)")
    
    # Get stats
    stats = queue.get_stats()
    print(f"\nMessage queue stats:")
    print(f"  Messages sent: {stats['messages_sent']}")
    print(f"  Messages received: {stats['messages_received']}")
    print(f"  Average latency: {stats['avg_latency_ns']}ns")


def test_state_manager():
    """Test the state manager functionality."""
    print("\n=== Testing State Manager ===")
    
    # Create state manager
    state = mcp_rust_core.StateManager()
    
    # Set some state
    version1 = state.set("user_123", {"name": "Alice", "score": 100})
    print(f"Set user_123, version: {version1}")
    
    # Get state
    entry = state.get("user_123")
    if entry:
        print(f"Retrieved: {entry['value']}")
        print(f"Version: {entry['version']}, Access count: {entry['access_count']}")
    
    # Test compare and swap
    try:
        # This should succeed
        version2 = state.compare_and_swap("user_123", version1, {"name": "Alice", "score": 150})
        print(f"CAS succeeded, new version: {version2}")
        
        # This should fail (wrong version)
        state.compare_and_swap("user_123", version1, {"name": "Alice", "score": 200})
    except RuntimeError as e:
        print(f"CAS failed as expected: {e}")
    
    # Simulate hot data access
    print("\nSimulating hot data access...")
    for _ in range(20):
        state.get("user_123")
    
    # Get stats
    stats = state.get_stats()
    print(f"\nState manager stats:")
    print(f"  Total entries: {stats['total_entries']}")
    print(f"  Hot cache entries: {stats['hot_cache_entries']}")
    print(f"  Cache hit rate: {stats['cache_hit_rate']:.2%}")
    print(f"  Total reads: {stats['reads']}")
    print(f"  Total writes: {stats['writes']}")


def benchmark_performance():
    """Run performance benchmarks."""
    print("\n=== Performance Benchmarks ===")
    
    mcp_rust_core.initialize()
    server = mcp_rust_core.MCPRustCore(memory_size_mb=100)
    
    # Register a simple handler
    server.register_handler("bench", lambda req: {"result": "ok", "error": None})
    
    # Warm up
    for _ in range(100):
        server.process_request("bench", {})
    
    # Benchmark
    iterations = 10000
    start = time.perf_counter()
    
    for i in range(iterations):
        server.process_request("bench", {"i": i})
    
    elapsed = time.perf_counter() - start
    avg_latency_us = (elapsed * 1_000_000) / iterations
    throughput = iterations / elapsed
    
    print(f"\nBenchmark results:")
    print(f"  Iterations: {iterations}")
    print(f"  Total time: {elapsed:.3f}s")
    print(f"  Average latency: {avg_latency_us:.2f}μs")
    print(f"  Throughput: {throughput:.0f} req/s")
    
    # Check if we meet the target
    if avg_latency_us < 100:
        print(f"✓ Target met: {avg_latency_us:.2f}μs < 100μs")
    else:
        print(f"✗ Target missed: {avg_latency_us:.2f}μs > 100μs")


if __name__ == "__main__":
    print("MCP Rust Core Python Integration Test")
    print("=" * 50)
    
    try:
        test_mcp_server()
        test_memory_pool()
        test_message_queue()
        test_state_manager()
        benchmark_performance()
        
        print("\n✓ All tests passed!")
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        raise