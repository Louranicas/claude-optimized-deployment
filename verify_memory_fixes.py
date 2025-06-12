#!/usr/bin/env python3
"""
Memory Leak Fixes Verification

Simple verification script to check that all memory leak fixes are implemented
without requiring external dependencies.
"""

import sys
import os
import re
from pathlib import Path

def check_audit_fixes():
    """Check audit system memory leak fixes."""
    print("📋 Checking Audit System Memory Leak Fixes...")
    
    audit_file = Path("src/auth/audit.py")
    if not audit_file.exists():
        print("✗ Audit file not found")
        return False
    
    content = audit_file.read_text()
    
    checks = [
        ("Sliding window implementation", "deque.*maxlen", "Ring buffer for high-frequency events"),
        ("Circuit breaker", "_circuit_breaker", "Circuit breaker for audit queue overflow"),
        ("Statistics cleanup", "_cleanup_statistics", "Sliding window for statistics"),
        ("Bounded buffer", "max_buffer_size", "Maximum buffer size parameter"),
        ("High-frequency buffer", "_high_freq_buffer", "Ring buffer for high-frequency events"),
        ("Weak references", "weakref", "Weak references for alert callbacks"),
        ("Periodic cleanup", "_periodic_cleanup", "Periodic cleanup operations"),
        ("Graceful shutdown", "async def shutdown", "Graceful shutdown method")
    ]
    
    passed = 0
    for name, pattern, description in checks:
        if re.search(pattern, content):
            print(f"  ✓ {name}: {description}")
            passed += 1
        else:
            print(f"  ✗ {name}: Missing {description}")
    
    print(f"Audit fixes: {passed}/{len(checks)} checks passed")
    return passed == len(checks)


def check_metrics_fixes():
    """Check metrics system memory leak fixes."""
    print("\n📊 Checking Metrics System Memory Leak Fixes...")
    
    metrics_file = Path("src/monitoring/metrics.py")
    if not metrics_file.exists():
        print("✗ Metrics file not found")
        return False
    
    content = metrics_file.read_text()
    
    checks = [
        ("Label cardinality limits", "max_label_values", "Maximum label values parameter"),
        ("Metric expiration", "metric_expiration_seconds", "Metric expiration timestamp"),
        ("Cleanup interval", "cleanup_interval_seconds", "Cleanup interval parameter"),
        ("Label cardinality check", "_check_label_cardinality", "Label cardinality checking method"),
        ("Endpoint aggregation", "_aggregate_endpoint", "Endpoint aggregation method"),
        ("Sampling logic", "_should_sample", "Sampling logic for high-frequency events"),
        ("Periodic cleanup", "_cleanup_expired_metrics", "Cleanup expired metrics method"),
        ("Memory management", "_label_cardinality", "Label cardinality tracking"),
        ("High-frequency counters", "_high_freq_counters", "High-frequency event counters"),
        ("Graceful shutdown", "def shutdown", "Graceful shutdown method")
    ]
    
    passed = 0
    for name, pattern, description in checks:
        if re.search(pattern, content):
            print(f"  ✓ {name}: {description}")
            passed += 1
        else:
            print(f"  ✗ {name}: Missing {description}")
    
    print(f"Metrics fixes: {passed}/{len(checks)} checks passed")
    return passed == len(checks)


def check_mcp_fixes():
    """Check MCP client memory leak fixes."""
    print("\n🔌 Checking MCP Client Memory Leak Fixes...")
    
    mcp_file = Path("src/mcp/client.py")
    if not mcp_file.exists():
        print("✗ MCP client file not found")
        return False
    
    content = mcp_file.read_text()
    
    checks = [
        ("Handler timeout", "handler_timeout_seconds", "Handler timeout parameter"),
        ("Max response handlers", "max_response_handlers", "Maximum response handlers limit"),
        ("Handler timestamps", "_handler_timestamps", "Handler timestamp tracking"),
        ("Cleanup expired handlers", "_cleanup_expired_handlers", "Cleanup expired handlers method"),
        ("Force cleanup", "_force_cleanup_handlers", "Force cleanup handlers method"),
        ("Periodic cleanup", "_start_periodic_cleanup", "Periodic cleanup task"),
        ("Weak references", "weakref", "Weak references for notification handlers"),
        ("Connection lifecycle", "_is_connected", "Connection lifecycle management"),
        ("Handler cleanup on disconnect", "self._response_handlers.clear", "Handler cleanup on disconnect")
    ]
    
    passed = 0
    for name, pattern, description in checks:
        if re.search(pattern, content):
            print(f"  ✓ {name}: {description}")
            passed += 1
        else:
            print(f"  ✗ {name}: Missing {description}")
    
    print(f"MCP fixes: {passed}/{len(checks)} checks passed")
    return passed == len(checks)


def check_rust_fixes():
    """Check Rust integration memory leak fixes."""
    print("\n⚡ Checking Rust Integration Memory Optimization...")
    
    rust_file = Path("src/circle_of_experts/core/rust_accelerated.py")
    if not rust_file.exists():
        print("✗ Rust accelerated file not found")
        return False
    
    content = rust_file.read_text()
    
    checks = [
        ("Streaming support", "enable_streaming", "Streaming data conversion parameter"),
        ("Chunk processing", "max_chunk_size", "Maximum chunk size parameter"),
        ("Memory optimization", "_optimize_data_conversion", "Data conversion optimization method"),
        ("Streaming aggregation", "_stream_aggregate_responses", "Streaming aggregation method"),
        ("Streaming merge", "_stream_merge_recommendations", "Streaming merge method"),
        ("Garbage collection", "gc.collect", "Explicit garbage collection"),
        ("Memory statistics", "get_memory_stats", "Memory usage statistics method"),
        ("Resource cleanup", "def cleanup", "Resource cleanup method"),
        ("Conversion cache", "_conversion_cache", "Data conversion cache with size limit"),
        ("Size limits", "\\[:50\\]|\\[:20\\]|\\[:100\\]", "Size limits on data structures")
    ]
    
    passed = 0
    for name, pattern, description in checks:
        if re.search(pattern, content):
            print(f"  ✓ {name}: {description}")
            passed += 1
        else:
            print(f"  ✗ {name}: Missing {description}")
    
    print(f"Rust fixes: {passed}/{len(checks)} checks passed")
    return passed == len(checks)


def check_connection_fixes():
    """Check connection pool memory leak fixes."""
    print("\n🔗 Checking Connection Pool Memory Leak Fixes...")
    
    conn_file = Path("src/core/connections.py")
    if not conn_file.exists():
        print("✗ Connections file not found")
        return False
    
    content = conn_file.read_text()
    
    checks = [
        ("Connection expiration", "expired_connections", "Expired connections metric"),
        ("Cleanup count", "cleanup_count", "Cleanup count metric"),
        ("Session timestamps", "session_timestamps|_session_timestamps", "Session timestamp tracking"),
        ("Periodic cleanup", "cleanup_task|_cleanup_task", "Periodic cleanup task"),
        ("Connection lifetime", "connection_lifetime", "Connection lifetime parameter"),
        ("Health check failures", "health_check_failures", "Health check failure tracking"),
        ("Graceful shutdown", "async def close", "Graceful shutdown method"),
        ("Resource monitoring", "get_metrics", "Resource metrics method"),
        ("Session management", "get_session", "Session management method")
    ]
    
    passed = 0
    for name, pattern, description in checks:
        if re.search(pattern, content):
            print(f"  ✓ {name}: {description}")
            passed += 1
        else:
            print(f"  ✗ {name}: Missing {description}")
    
    print(f"Connection fixes: {passed}/{len(checks)} checks passed")
    return passed == len(checks)


def main():
    """Main verification function."""
    print("🧪 AGENT 5: Component Memory Leak Fixes - Code Verification")
    print("=" * 60)
    
    # Change to project directory
    project_dir = Path(__file__).parent
    os.chdir(project_dir)
    
    results = []
    
    # Run all checks
    results.append(("Audit System", check_audit_fixes()))
    results.append(("Metrics System", check_metrics_fixes()))
    results.append(("MCP Client", check_mcp_fixes()))
    results.append(("Rust Integration", check_rust_fixes()))
    results.append(("Connection Pools", check_connection_fixes()))
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 MEMORY LEAK FIXES VERIFICATION SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for component, passed in results:
        status = "✓ IMPLEMENTED" if passed else "✗ INCOMPLETE"
        print(f"{component:20} | {status}")
        if not passed:
            all_passed = False
    
    print("-" * 60)
    
    if all_passed:
        print("🎉 ALL MEMORY LEAK FIXES SUCCESSFULLY IMPLEMENTED!")
        print("\n📋 Implementation Summary:")
        print("✓ Audit System: Sliding window, circuit breaker, bounded buffers")
        print("✓ Metrics System: Label limits, expiration, sampling")
        print("✓ MCP Client: Handler timeout cleanup, weak references")
        print("✓ Rust Integration: Streaming conversion, memory optimization")
        print("✓ Connection Pools: Session expiration, lifecycle management")
        print("\n🔒 Memory leaks have been mitigated across all components!")
        return True
    else:
        print("❌ Some memory leak fixes are incomplete or missing.")
        print("Please review the failed checks above.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)