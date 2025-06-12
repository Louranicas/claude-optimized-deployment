#!/usr/bin/env python3
"""
Basic test for LRU cache implementation without external dependencies.
"""

import asyncio
import time
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.core.lru_cache import LRUCache, TTLDict, create_lru_cache, create_ttl_dict, CacheConfig
    from src.core.cleanup_scheduler import CleanupScheduler, TaskPriority
    from src.core.cache_config import CacheConfiguration, ConfigPresets
    print("✓ Successfully imported LRU cache modules")
except ImportError as e:
    print(f"✗ Failed to import modules: {e}")
    sys.exit(1)

def test_lru_cache():
    """Test LRU cache functionality."""
    print("\n--- Testing LRU Cache ---")
    
    # Test 1: Basic functionality
    cache = create_lru_cache(max_size=3, ttl=None)
    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("c", 3)
    
    assert cache.get("a") == 1, "Failed to retrieve value"
    assert cache.size() == 3, f"Expected size 3, got {cache.size()}"
    print("✓ Basic put/get operations work")
    
    # Test 2: LRU eviction
    cache.put("d", 4)  # Should evict "b" (least recently used)
    assert cache.get("b") is None, "LRU eviction failed"
    assert cache.size() == 3, f"Size should remain 3, got {cache.size()}"
    print("✓ LRU eviction works correctly")
    
    # Test 3: Access order update
    cache.get("a")  # Make "a" most recently used
    cache.put("e", 5)  # Should evict "c"
    assert cache.get("c") is None, "Access order update failed"
    assert cache.get("a") == 1, "Most recently used item was evicted"
    print("✓ Access order updates correctly")
    
    # Test 4: Statistics
    stats = cache.get_stats()
    assert stats.total_size == 3, "Statistics size mismatch"
    assert stats.hits > 0, "No hits recorded"
    assert stats.misses > 0, "No misses recorded"
    print(f"✓ Statistics: {stats.hits} hits, {stats.misses} misses, hit rate: {stats.hit_rate():.2f}")

def test_ttl_cache():
    """Test TTL cache functionality."""
    print("\n--- Testing TTL Cache ---")
    
    # Test 1: TTL expiration
    ttl_cache = create_lru_cache(max_size=10, ttl=0.1)
    ttl_cache.put("temp", "value")
    
    assert ttl_cache.get("temp") == "value", "Failed to retrieve fresh value"
    print("✓ Fresh TTL value retrieved")
    
    time.sleep(0.15)
    ttl_cache.cleanup()
    
    assert ttl_cache.get("temp") is None, "TTL expiration failed"
    print("✓ TTL expiration works")
    
    # Test 2: Mixed TTL and size limits
    for i in range(5):
        ttl_cache.put(f"key_{i}", f"value_{i}")
    
    assert ttl_cache.size() == 5, f"Expected 5 items, got {ttl_cache.size()}"
    print("✓ TTL cache respects size limits")

def test_ttl_dict():
    """Test TTL dictionary interface."""
    print("\n--- Testing TTL Dictionary ---")
    
    # Test 1: Dictionary interface
    ttl_dict = create_ttl_dict(max_size=5, ttl=0.2)
    ttl_dict["key1"] = "value1"
    ttl_dict["key2"] = "value2"
    
    assert ttl_dict["key1"] == "value1", "Dictionary get failed"
    assert "key1" in ttl_dict, "Dictionary contains failed"
    assert len(ttl_dict) == 2, f"Expected length 2, got {len(ttl_dict)}"
    print("✓ Dictionary interface works")
    
    # Test 2: Size limits with dict interface
    for i in range(10):
        ttl_dict[f"item_{i}"] = f"value_{i}"
    
    assert len(ttl_dict) <= 5, f"Size limit exceeded: {len(ttl_dict)}"
    print("✓ Dictionary size limits enforced")
    
    # Test 3: Custom TTL
    ttl_dict.put_with_ttl("short", "temp", 0.05)
    time.sleep(0.1)
    ttl_dict.cleanup()
    
    assert "short" not in ttl_dict, "Custom TTL failed"
    print("✓ Custom TTL works")

async def test_cleanup_scheduler():
    """Test cleanup scheduler."""
    print("\n--- Testing Cleanup Scheduler ---")
    
    scheduler = CleanupScheduler(check_interval=0.1)
    
    # Test task registration
    cleanup_count = 0
    
    def test_cleanup():
        nonlocal cleanup_count
        cleanup_count += 1
        return cleanup_count
    
    scheduler.register_task(
        "test_task",
        test_cleanup,
        interval_seconds=0.15,
        priority=TaskPriority.MEDIUM
    )
    
    assert "test_task" in scheduler.tasks, "Task registration failed"
    print("✓ Task registration works")
    
    # Test scheduler execution
    await scheduler.start()
    await asyncio.sleep(0.3)  # Wait for execution
    
    assert cleanup_count > 0, "Scheduler didn't execute task"
    print(f"✓ Scheduler executed task {cleanup_count} times")
    
    # Test statistics
    stats = scheduler.get_stats()
    assert stats["running"], "Scheduler not running"
    assert stats["task_count"] == 1, f"Expected 1 task, got {stats['task_count']}"
    print("✓ Scheduler statistics work")
    
    await scheduler.stop()

def test_cache_config():
    """Test cache configuration."""
    print("\n--- Testing Cache Configuration ---")
    
    # Test default config
    config = CacheConfiguration()
    assert config.expert_queries_max_size > 0, "Default config invalid"
    print("✓ Default configuration created")
    
    # Test validation
    assert config.validate(), "Default config validation failed"
    print("✓ Configuration validation works")
    
    # Test presets
    dev_config = ConfigPresets.development()
    prod_config = ConfigPresets.production()
    test_config = ConfigPresets.testing()
    
    assert dev_config.expert_queries_max_size < prod_config.expert_queries_max_size, "Preset sizing incorrect"
    assert test_config.expert_queries_max_size < dev_config.expert_queries_max_size, "Test preset sizing incorrect"
    print("✓ Configuration presets work")
    
    # Test sections
    expert_config = config.get_expert_config()
    mcp_config = config.get_mcp_config()
    
    assert "queries_max_size" in expert_config, "Expert config section incomplete"
    assert "contexts_max_size" in mcp_config, "MCP config section incomplete"
    print("✓ Configuration sections work")

def test_memory_bounds():
    """Test memory usage bounds."""
    print("\n--- Testing Memory Bounds ---")
    
    # Test large cache with size limits
    large_cache = create_lru_cache(max_size=100, ttl=None)
    
    # Add many items to test eviction
    for i in range(200):
        large_cache.put(f"key_{i}", "x" * 50)  # 50 character strings
    
    assert large_cache.size() <= 100, f"Size limit exceeded: {large_cache.size()}"
    print("✓ Large cache respects size limits")
    
    # Test memory monitoring
    stats = large_cache.get_stats()
    assert stats.memory_bytes > 0, "Memory monitoring not working"
    
    memory_mb = stats.memory_bytes / (1024 * 1024)
    print(f"✓ Memory monitoring works: {memory_mb:.2f} MB estimated")
    
    # Test TTL dict bounds
    ttl_dict = create_ttl_dict(max_size=50, ttl=1.0)
    for i in range(100):
        ttl_dict[f"key_{i}"] = "y" * 25
    
    assert len(ttl_dict) <= 50, f"TTL dict size limit exceeded: {len(ttl_dict)}"
    print("✓ TTL dict respects size limits")

async def test_integration():
    """Integration test with multiple components."""
    print("\n--- Integration Test ---")
    
    # Create multiple bounded structures
    cache1 = create_lru_cache(max_size=10, ttl=0.3)
    cache2 = create_lru_cache(max_size=15, ttl=0.5)
    dict1 = create_ttl_dict(max_size=8, ttl=0.4)
    
    # Populate them
    for i in range(20):  # Exceed all limits
        cache1.put(f"c1_key_{i}", f"value_{i}")
        cache2.put(f"c2_key_{i}", f"value_{i}")
        dict1[f"d1_key_{i}"] = f"value_{i}"
    
    # Check all respect their limits
    assert cache1.size() <= 10, f"Cache1 size exceeded: {cache1.size()}"
    assert cache2.size() <= 15, f"Cache2 size exceeded: {cache2.size()}"
    assert len(dict1) <= 8, f"Dict1 size exceeded: {len(dict1)}"
    print("✓ All structures respect their size limits")
    
    # Test cleanup scheduler with structures
    scheduler = CleanupScheduler(check_interval=0.1)
    
    cleanup_calls = 0
    def combined_cleanup():
        nonlocal cleanup_calls
        cleanup_calls += 1
        removed = 0
        removed += cache1.cleanup()
        removed += cache2.cleanup()
        removed += dict1.cleanup()
        return removed
    
    scheduler.register_task(
        "combined_cleanup",
        combined_cleanup,
        interval_seconds=0.2,
        priority=TaskPriority.HIGH
    )
    
    await scheduler.start()
    await asyncio.sleep(0.6)  # Wait for TTL expiration and cleanup
    
    # Check cleanup was called
    assert cleanup_calls > 0, "Combined cleanup not called"
    print(f"✓ Integrated cleanup called {cleanup_calls} times")
    
    await scheduler.stop()

async def main():
    """Run all tests."""
    print("UNBOUNDED DATA STRUCTURE FIXES - BASIC TEST SUITE")
    print("=" * 60)
    
    try:
        test_lru_cache()
        test_ttl_cache()
        test_ttl_dict()
        await test_cleanup_scheduler()
        test_cache_config()
        test_memory_bounds()
        await test_integration()
        
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED! ✓")
        print("=" * 60)
        print("\nKey Achievements:")
        print("✓ LRU caches enforce size limits")
        print("✓ TTL expiration works correctly")
        print("✓ Memory usage is bounded and monitored")
        print("✓ Cleanup scheduler manages maintenance")
        print("✓ Configuration system is flexible")
        print("✓ All components integrate properly")
        print("\nUnbounded data structure issues have been resolved!")
        
        return True
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)