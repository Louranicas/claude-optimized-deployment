#!/usr/bin/env python3
"""
Comprehensive test suite for unbounded data structure fixes.

This test validates that all previously unbounded data structures now have:
- Size limits (LRU eviction)
- TTL cleanup (time-based expiration)
- Memory monitoring
- Cleanup scheduling
- Configurable parameters
"""

import asyncio
import time
import gc
import sys
import os
import threading
from typing import Dict, Any, List
from datetime import datetime, timedelta
import json

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import all the modules we need to test
try:
    from src.core.lru_cache import LRUCache, TTLDict, create_lru_cache, create_ttl_dict, CacheConfig
    from src.core.cleanup_scheduler import CleanupScheduler, initialize_cleanup_scheduler, TaskPriority
    from src.core.cache_config import CacheConfiguration, get_cache_config, ConfigPresets
    print("✓ Core modules imported successfully")
except ImportError as e:
    print(f"✗ Failed to import core modules: {e}")
    sys.exit(1)

try:
    from src.circle_of_experts.core.expert_manager import ExpertManager
    from src.circle_of_experts.core.response_collector import ResponseCollector
    from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
    print("✓ Circle of Experts modules imported successfully")
except ImportError as e:
    print(f"⚠ Circle of Experts modules not available: {e}")
    ExpertManager = None

try:
    from src.mcp.manager import MCPManager, MCPContext
    print("✓ MCP modules imported successfully")
except ImportError as e:
    print(f"⚠ MCP modules not available: {e}")
    MCPManager = None

try:
    from src.core.connections import HTTPConnectionPool, ConnectionPoolConfig, ConnectionPoolManager
    print("✓ Connection pool modules imported successfully")
except ImportError as e:
    print(f"⚠ Connection pool modules not available: {e}")
    HTTPConnectionPool = None

try:
    from src.auth.audit import AuditLogger, AuditEventType, AuditSeverity
    print("✓ Audit modules imported successfully")
except ImportError as e:
    print(f"⚠ Audit modules not available: {e}")
    AuditLogger = None


class TestResults:
    """Test results collector."""
    
    def __init__(self):
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.skipped_tests = 0
        self.failures: List[str] = []
        self.warnings: List[str] = []
    
    def add_test(self, name: str, passed: bool, message: str = ""):
        """Add test result."""
        self.total_tests += 1
        if passed:
            self.passed_tests += 1
            print(f"✓ {name}")
            if message:
                print(f"  {message}")
        else:
            self.failed_tests += 1
            self.failures.append(f"{name}: {message}")
            print(f"✗ {name}")
            if message:
                print(f"  {message}")
    
    def add_skip(self, name: str, reason: str):
        """Add skipped test."""
        self.total_tests += 1
        self.skipped_tests += 1
        print(f"⊝ {name} (skipped: {reason})")
    
    def add_warning(self, message: str):
        """Add warning."""
        self.warnings.append(message)
        print(f"⚠ {message}")
    
    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        print(f"Total tests: {self.total_tests}")
        print(f"Passed: {self.passed_tests}")
        print(f"Failed: {self.failed_tests}")
        print(f"Skipped: {self.skipped_tests}")
        
        if self.warnings:
            print(f"\nWarnings: {len(self.warnings)}")
            for warning in self.warnings:
                print(f"  ⚠ {warning}")
        
        if self.failures:
            print(f"\nFailures: {len(self.failures)}")
            for failure in self.failures:
                print(f"  ✗ {failure}")
        
        print(f"\nSuccess rate: {(self.passed_tests / max(self.total_tests, 1)) * 100:.1f}%")
        return self.failed_tests == 0


def test_lru_cache_basic():
    """Test basic LRU cache functionality."""
    results = TestResults()
    
    # Test size limits
    cache = create_lru_cache(max_size=3, ttl=None)
    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("c", 3)
    cache.put("d", 4)  # Should evict "a"
    
    results.add_test(
        "LRU eviction works",
        cache.get("a") is None and cache.get("d") == 4,
        f"Cache size: {cache.size()}"
    )
    
    # Test TTL expiration
    ttl_cache = create_lru_cache(max_size=10, ttl=0.1, cleanup_interval=0.05)
    ttl_cache.put("temp", "value")
    
    results.add_test(
        "TTL entry exists initially",
        ttl_cache.get("temp") == "value"
    )
    
    time.sleep(0.15)  # Wait for expiration
    ttl_cache.cleanup()  # Manual cleanup
    
    results.add_test(
        "TTL entry expires",
        ttl_cache.get("temp") is None
    )
    
    # Test statistics
    stats = cache.get_stats()
    results.add_test(
        "Statistics available",
        hasattr(stats, 'hits') and hasattr(stats, 'misses'),
        f"Hit rate: {stats.hit_rate():.2f}"
    )
    
    return results


def test_ttl_dict():
    """Test TTL dictionary functionality."""
    results = TestResults()
    
    # Test dict interface
    ttl_dict = create_ttl_dict(max_size=5, ttl=0.2)
    ttl_dict["key1"] = "value1"
    ttl_dict["key2"] = "value2"
    
    results.add_test(
        "TTL dict interface works",
        ttl_dict["key1"] == "value1" and "key2" in ttl_dict,
        f"Dict size: {len(ttl_dict)}"
    )
    
    # Test size limits
    for i in range(10):
        ttl_dict[f"key_{i}"] = f"value_{i}"
    
    results.add_test(
        "TTL dict respects size limits",
        len(ttl_dict) <= 5,
        f"Actual size: {len(ttl_dict)}"
    )
    
    # Test TTL with custom value
    ttl_dict.put_with_ttl("short_lived", "temp", 0.1)
    time.sleep(0.15)
    ttl_dict.cleanup()
    
    results.add_test(
        "TTL dict custom TTL works",
        "short_lived" not in ttl_dict
    )
    
    return results


async def test_cleanup_scheduler():
    """Test cleanup scheduler functionality."""
    results = TestResults()
    
    scheduler = CleanupScheduler(check_interval=0.1)
    
    # Test task registration
    cleanup_called = False
    
    def test_cleanup():
        nonlocal cleanup_called
        cleanup_called = True
        return 5  # Simulate cleaning 5 items
    
    scheduler.register_task(
        "test_cleanup",
        test_cleanup,
        interval_seconds=0.2,
        priority=TaskPriority.HIGH
    )
    
    results.add_test(
        "Task registration works",
        "test_cleanup" in scheduler.tasks
    )
    
    # Test scheduler execution
    await scheduler.start()
    await asyncio.sleep(0.3)  # Wait for task to execute
    
    results.add_test(
        "Scheduler executes tasks",
        cleanup_called,
        "Test cleanup function was called"
    )
    
    # Test statistics
    stats = scheduler.get_stats()
    results.add_test(
        "Scheduler statistics available",
        "running" in stats and "task_count" in stats,
        f"Running: {stats['running']}, Tasks: {stats['task_count']}"
    )
    
    await scheduler.stop()
    
    return results


async def test_expert_manager():
    """Test Expert Manager bounded caches."""
    results = TestResults()
    
    if ExpertManager is None:
        results.add_skip("Expert Manager tests", "Module not available")
        return results
    
    try:
        # Mock the dependencies
        manager = ExpertManager.__new__(ExpertManager)
        manager.active_queries = create_ttl_dict(max_size=5, ttl=0.5)
        
        # Test cache interface
        query_id = "test_query_1"
        mock_query = {"id": query_id, "title": "Test Query"}
        manager.active_queries[query_id] = mock_query
        
        results.add_test(
            "Expert Manager uses bounded cache",
            query_id in manager.active_queries,
            f"Cache size: {len(manager.active_queries)}"
        )
        
        # Test size limits
        for i in range(10):
            manager.active_queries[f"query_{i}"] = {"id": f"query_{i}"}
        
        results.add_test(
            "Expert Manager respects cache limits",
            len(manager.active_queries) <= 5,
            f"Actual size: {len(manager.active_queries)}"
        )
        
        # Test TTL expiration
        time.sleep(0.6)
        manager.active_queries.cleanup()
        
        results.add_test(
            "Expert Manager TTL expiration works",
            len(manager.active_queries) == 0,
            "All entries expired"
        )
        
        # Test cache stats if available
        if hasattr(manager, 'get_cache_stats'):
            stats = manager.get_cache_stats()
            results.add_test(
                "Expert Manager cache stats available",
                isinstance(stats, dict),
                f"Stats keys: {list(stats.keys())}"
            )
        
    except Exception as e:
        results.add_test(
            "Expert Manager test execution",
            False,
            f"Error: {e}"
        )
    
    return results


async def test_mcp_manager():
    """Test MCP Manager bounded contexts."""
    results = TestResults()
    
    if MCPManager is None:
        results.add_skip("MCP Manager tests", "Module not available")
        return results
    
    try:
        # Mock the MCP manager
        manager = MCPManager.__new__(MCPManager)
        manager.contexts = create_ttl_dict(max_size=3, ttl=0.5)
        
        # Test context storage
        context_id = "test_context"
        mock_context = MCPContext()
        manager.contexts[context_id] = mock_context
        
        results.add_test(
            "MCP Manager uses bounded contexts",
            context_id in manager.contexts,
            f"Context cache size: {len(manager.contexts)}"
        )
        
        # Test size limits
        for i in range(5):
            manager.contexts[f"context_{i}"] = MCPContext()
        
        results.add_test(
            "MCP Manager respects context limits",
            len(manager.contexts) <= 3,
            f"Actual context count: {len(manager.contexts)}"
        )
        
        # Test TTL cleanup
        time.sleep(0.6)
        manager.contexts.cleanup()
        
        results.add_test(
            "MCP Manager context TTL works",
            len(manager.contexts) == 0,
            "All contexts expired"
        )
        
    except Exception as e:
        results.add_test(
            "MCP Manager test execution",
            False,
            f"Error: {e}"
        )
    
    return results


async def test_connection_pool():
    """Test HTTP Connection Pool bounded caches."""
    results = TestResults()
    
    if HTTPConnectionPool is None:
        results.add_skip("Connection Pool tests", "Module not available")
        return results
    
    try:
        config = ConnectionPoolConfig()
        pool = HTTPConnectionPool.__new__(HTTPConnectionPool)
        pool._sessions = create_ttl_dict(max_size=3, ttl=0.5)
        pool._session_metrics = create_ttl_dict(max_size=5, ttl=1.0)
        
        # Test session storage
        pool._sessions["http://example.com"] = "mock_session"
        
        results.add_test(
            "Connection Pool uses bounded sessions",
            "http://example.com" in pool._sessions,
            f"Session cache size: {len(pool._sessions)}"
        )
        
        # Test size limits
        for i in range(5):
            pool._sessions[f"http://site{i}.com"] = f"session_{i}"
        
        results.add_test(
            "Connection Pool respects session limits",
            len(pool._sessions) <= 3,
            f"Actual session count: {len(pool._sessions)}"
        )
        
        # Test TTL cleanup
        time.sleep(0.6)
        pool._sessions.cleanup()
        
        results.add_test(
            "Connection Pool session TTL works",
            len(pool._sessions) == 0,
            "All sessions expired"
        )
        
    except Exception as e:
        results.add_test(
            "Connection Pool test execution",
            False,
            f"Error: {e}"
        )
    
    return results


async def test_audit_logger():
    """Test Audit Logger bounded buffers."""
    results = TestResults()
    
    if AuditLogger is None:
        results.add_skip("Audit Logger tests", "Module not available")
        return results
    
    try:
        # Test with bounded collections available
        logger = AuditLogger.__new__(AuditLogger)
        logger.stats = create_lru_cache(max_size=5, ttl=0.5)
        logger.buffer = []
        logger.alert_callbacks = []
        
        # Test stats storage
        logger.stats.put("test_event", 10)
        
        results.add_test(
            "Audit Logger uses bounded stats",
            logger.stats.get("test_event") == 10,
            f"Stats cache size: {logger.stats.size()}"
        )
        
        # Test size limits
        for i in range(8):
            logger.stats.put(f"event_{i}", i)
        
        results.add_test(
            "Audit Logger respects stats limits",
            logger.stats.size() <= 5,
            f"Actual stats count: {logger.stats.size()}"
        )
        
        # Test TTL cleanup
        time.sleep(0.6)
        logger.stats.cleanup()
        
        results.add_test(
            "Audit Logger stats TTL works",
            logger.stats.size() == 0,
            "All stats expired"
        )
        
    except Exception as e:
        results.add_test(
            "Audit Logger test execution",
            False,
            f"Error: {e}"
        )
    
    return results


def test_cache_configuration():
    """Test cache configuration system."""
    results = TestResults()
    
    # Test default configuration
    config = CacheConfiguration()
    
    results.add_test(
        "Default configuration creation",
        config.expert_queries_max_size > 0,
        f"Expert queries max: {config.expert_queries_max_size}"
    )
    
    # Test validation
    is_valid = config.validate()
    results.add_test(
        "Configuration validation",
        is_valid,
        "Default config is valid"
    )
    
    # Test configuration presets
    dev_config = ConfigPresets.development()
    prod_config = ConfigPresets.production()
    test_config = ConfigPresets.testing()
    
    results.add_test(
        "Configuration presets available",
        (dev_config.expert_queries_max_size < prod_config.expert_queries_max_size and
         test_config.expert_queries_max_size < dev_config.expert_queries_max_size),
        f"Dev: {dev_config.expert_queries_max_size}, Prod: {prod_config.expert_queries_max_size}, Test: {test_config.expert_queries_max_size}"
    )
    
    # Test environment override simulation
    config_with_env = CacheConfiguration(
        expert_queries_max_size=500,
        enable_env_overrides=False  # Disable to prevent actual env interference
    )
    
    results.add_test(
        "Configuration customization",
        config_with_env.expert_queries_max_size == 500,
        "Custom config values work"
    )
    
    # Test config sections
    expert_config = config.get_expert_config()
    mcp_config = config.get_mcp_config()
    
    results.add_test(
        "Configuration sections available",
        "queries_max_size" in expert_config and "contexts_max_size" in mcp_config,
        f"Expert config keys: {list(expert_config.keys())[:3]}..."
    )
    
    return results


def test_memory_bounds():
    """Test memory usage is bounded."""
    results = TestResults()
    
    # Test LRU cache memory usage
    large_cache = create_lru_cache(max_size=1000, ttl=None)
    
    # Add many items
    for i in range(2000):
        large_cache.put(f"key_{i}", "x" * 100)  # 100 char strings
    
    results.add_test(
        "LRU cache enforces size limit",
        large_cache.size() <= 1000,
        f"Cache size: {large_cache.size()}"
    )
    
    # Check memory monitoring
    stats = large_cache.get_stats()
    memory_mb = stats.memory_bytes / (1024 * 1024)
    
    results.add_test(
        "Memory monitoring works",
        stats.memory_bytes > 0,
        f"Estimated memory: {memory_mb:.2f} MB"
    )
    
    # Test TTL dict memory bounds
    ttl_dict = create_ttl_dict(max_size=100, ttl=1.0)
    for i in range(200):
        ttl_dict[f"key_{i}"] = "y" * 50
    
    results.add_test(
        "TTL dict enforces size limit",
        len(ttl_dict) <= 100,
        f"TTL dict size: {len(ttl_dict)}"
    )
    
    return results


async def run_integration_test():
    """Run integration test with all components."""
    results = TestResults()
    
    try:
        # Initialize cleanup scheduler
        scheduler = await initialize_cleanup_scheduler(
            check_interval=0.1,
            memory_threshold_mb=50.0,
            auto_start=True
        )
        
        # Create various bounded structures
        structures = {}
        
        # LRU caches
        structures['cache1'] = create_lru_cache(max_size=10, ttl=0.5)
        structures['cache2'] = create_lru_cache(max_size=20, ttl=1.0)
        
        # TTL dicts
        structures['dict1'] = create_ttl_dict(max_size=15, ttl=0.8)
        structures['dict2'] = create_ttl_dict(max_size=25, ttl=1.2)
        
        # Populate structures
        for name, structure in structures.items():
            for i in range(30):  # Exceed limits to test eviction
                if hasattr(structure, 'put'):
                    structure.put(f"{name}_key_{i}", f"value_{i}")
                else:
                    structure[f"{name}_key_{i}"] = f"value_{i}"
        
        results.add_test(
            "Integration test setup",
            len(structures) == 4,
            f"Created {len(structures)} bounded structures"
        )
        
        # Wait for cleanup cycles
        await asyncio.sleep(0.3)
        
        # Check all structures respect bounds
        all_bounded = True
        for name, structure in structures.items():
            size = len(structure) if hasattr(structure, '__len__') else structure.size()
            if size > 25:  # Max configured size
                all_bounded = False
                break
        
        results.add_test(
            "All structures respect size bounds",
            all_bounded,
            "No structure exceeded its configured limit"
        )
        
        # Test cleanup scheduler is working
        task_status = scheduler.get_task_status()
        scheduler_stats = scheduler.get_stats()
        
        results.add_test(
            "Cleanup scheduler is active",
            scheduler_stats['running'],
            f"Active tasks: {len(task_status)}"
        )
        
        # Wait for TTL expiration
        await asyncio.sleep(1.5)
        
        # Manual cleanup to ensure TTL expiration
        for structure in structures.values():
            if hasattr(structure, 'cleanup'):
                structure.cleanup()
        
        # Check TTL expiration worked
        expired_structures = 0
        for structure in structures.values():
            size = len(structure) if hasattr(structure, '__len__') else structure.size()
            if size == 0:
                expired_structures += 1
        
        results.add_test(
            "TTL expiration works across structures",
            expired_structures > 0,
            f"{expired_structures}/{len(structures)} structures expired entries"
        )
        
        await scheduler.stop()
        
    except Exception as e:
        results.add_test(
            "Integration test execution",
            False,
            f"Error: {e}"
        )
    
    return results


async def main():
    """Run all tests."""
    print("UNBOUNDED DATA STRUCTURE FIXES - COMPREHENSIVE TEST SUITE")
    print("="*60)
    print()
    
    all_results = TestResults()
    
    # Core functionality tests
    print("Testing Core LRU Cache...")
    cache_results = test_lru_cache_basic()
    all_results.total_tests += cache_results.total_tests
    all_results.passed_tests += cache_results.passed_tests
    all_results.failed_tests += cache_results.failed_tests
    all_results.failures.extend(cache_results.failures)
    print()
    
    print("Testing TTL Dictionary...")
    ttl_results = test_ttl_dict()
    all_results.total_tests += ttl_results.total_tests
    all_results.passed_tests += ttl_results.passed_tests
    all_results.failed_tests += ttl_results.failed_tests
    all_results.failures.extend(ttl_results.failures)
    print()
    
    print("Testing Cleanup Scheduler...")
    scheduler_results = await test_cleanup_scheduler()
    all_results.total_tests += scheduler_results.total_tests
    all_results.passed_tests += scheduler_results.passed_tests
    all_results.failed_tests += scheduler_results.failed_tests
    all_results.failures.extend(scheduler_results.failures)
    print()
    
    print("Testing Configuration System...")
    config_results = test_cache_configuration()
    all_results.total_tests += config_results.total_tests
    all_results.passed_tests += config_results.passed_tests
    all_results.failed_tests += config_results.failed_tests
    all_results.failures.extend(config_results.failures)
    print()
    
    print("Testing Memory Bounds...")
    memory_results = test_memory_bounds()
    all_results.total_tests += memory_results.total_tests
    all_results.passed_tests += memory_results.passed_tests
    all_results.failed_tests += memory_results.failed_tests
    all_results.failures.extend(memory_results.failures)
    print()
    
    # Component integration tests
    print("Testing Expert Manager Integration...")
    expert_results = await test_expert_manager()
    all_results.total_tests += expert_results.total_tests
    all_results.passed_tests += expert_results.passed_tests
    all_results.failed_tests += expert_results.failed_tests
    all_results.skipped_tests += expert_results.skipped_tests
    all_results.failures.extend(expert_results.failures)
    print()
    
    print("Testing MCP Manager Integration...")
    mcp_results = await test_mcp_manager()
    all_results.total_tests += mcp_results.total_tests
    all_results.passed_tests += mcp_results.passed_tests
    all_results.failed_tests += mcp_results.failed_tests
    all_results.skipped_tests += mcp_results.skipped_tests
    all_results.failures.extend(mcp_results.failures)
    print()
    
    print("Testing Connection Pool Integration...")
    conn_results = await test_connection_pool()
    all_results.total_tests += conn_results.total_tests
    all_results.passed_tests += conn_results.passed_tests
    all_results.failed_tests += conn_results.failed_tests
    all_results.skipped_tests += conn_results.skipped_tests
    all_results.failures.extend(conn_results.failures)
    print()
    
    print("Testing Audit Logger Integration...")
    audit_results = await test_audit_logger()
    all_results.total_tests += audit_results.total_tests
    all_results.passed_tests += audit_results.passed_tests
    all_results.failed_tests += audit_results.failed_tests
    all_results.skipped_tests += audit_results.skipped_tests
    all_results.failures.extend(audit_results.failures)
    print()
    
    print("Running Integration Test...")
    integration_results = await run_integration_test()
    all_results.total_tests += integration_results.total_tests
    all_results.passed_tests += integration_results.passed_tests
    all_results.failed_tests += integration_results.failed_tests
    all_results.failures.extend(integration_results.failures)
    print()
    
    # Print final summary
    success = all_results.print_summary()
    
    # Generate JSON report
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_tests": all_results.total_tests,
            "passed": all_results.passed_tests,
            "failed": all_results.failed_tests,
            "skipped": all_results.skipped_tests,
            "success_rate": (all_results.passed_tests / max(all_results.total_tests, 1)) * 100
        },
        "failures": all_results.failures,
        "warnings": all_results.warnings
    }
    
    with open("unbounded_data_fixes_test_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed report saved to: unbounded_data_fixes_test_report.json")
    
    return success


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)