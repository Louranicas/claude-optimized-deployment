#!/usr/bin/env python3
"""
Example script demonstrating the enhanced database connection management system.

This script shows how to use the new database pool manager with:
- Async context managers for all database operations
- Connection pool monitoring with metrics
- Explicit timeouts on all database queries
- Circuit breakers for database connections
- Automatic connection leak detection and cleanup
- Pod-aware connection pool sizing
"""

import asyncio
import os
import logging
from typing import Optional

from src.database.pool_manager import (
    DatabasePoolConfig,
    DatabasePoolManager,
    get_pool_manager,
    close_pool_manager
)
from src.database.monitoring import (
    DatabaseMonitorConfig,
    DatabaseMonitor,
    DatabaseAlert,
    start_database_monitoring,
    stop_database_monitoring
)
from src.database.repositories.user_repository import UserRepository
from src.database.models import UserRole
from src.core.logging_config import get_logger

logger = get_logger(__name__)


def alert_handler(alert: DatabaseAlert):
    """Handle database alerts."""
    print(f"🚨 DATABASE ALERT [{alert.severity.upper()}]: {alert.message}")
    if alert.metrics:
        print(f"   Metrics: {alert.metrics}")


async def demonstrate_pool_configuration():
    """Demonstrate various pool configuration options."""
    print("\\n=== Pool Configuration Examples ===")
    
    # Example 1: Development configuration
    dev_config = DatabasePoolConfig(
        connection_string="postgresql+asyncpg://postgres:postgres@localhost/dev_db",
        min_pool_size=2,
        max_pool_size=5,
        pod_count=1,
        enable_monitoring=True,
        connect_timeout=5,
        command_timeout=10
    )
    print(f"Development config: min={dev_config.min_pool_size}, max={dev_config.max_pool_size}")
    
    # Example 2: Production configuration with pod awareness
    prod_config = DatabasePoolConfig(
        connection_string="postgresql+asyncpg://postgres:postgres@localhost/prod_db",
        pod_count=3,  # This will auto-calculate pool sizes
        connections_per_pod=15,
        enable_monitoring=True,
        connect_timeout=10,
        command_timeout=30,
        health_check_interval=60
    )
    print(f"Production config: min={prod_config.min_pool_size}, max={prod_config.max_pool_size}")
    
    # Example 3: High-load configuration
    high_load_config = DatabasePoolConfig(
        connection_string="postgresql+asyncpg://postgres:postgres@localhost/high_load_db",
        min_pool_size=10,
        max_pool_size=50,
        max_overflow=20,
        pool_recycle=1800,  # 30 minutes
        enable_monitoring=True,
        circuit_failure_threshold=10,
        circuit_recovery_timeout=120
    )
    print(f"High-load config: min={high_load_config.min_pool_size}, max={high_load_config.max_pool_size}")


async def demonstrate_basic_usage():
    """Demonstrate basic database operations with the pool manager."""
    print("\\n=== Basic Database Operations ===")
    
    # Get pool manager (uses environment variables or defaults)
    pool_manager = await get_pool_manager()
    
    try:
        # Example 1: Simple query with timeout
        print("1. Executing simple query with timeout...")
        result = await pool_manager.execute_query(
            "SELECT 1 as test_value",
            timeout=5
        )
        print(f"   Result: {result.scalar()}")
        
        # Example 2: Using session context manager
        print("2. Using session context manager...")
        async with pool_manager.get_session() as session:
            from sqlalchemy import text
            result = await session.execute(text("SELECT 'Hello from session' as message"))
            message = result.scalar()
            print(f"   Message: {message}")
        
        # Example 3: Repository pattern with auto-session management
        print("3. Using repository pattern...")
        user_repo = UserRepository()  # No session needed - uses pool manager
        
        # The repository will automatically handle sessions and timeouts
        user_count = await user_repo.count()
        print(f"   Current user count: {user_count}")
        
    except Exception as e:
        logger.error(f"Database operation failed: {e}")


async def demonstrate_monitoring():
    """Demonstrate database monitoring capabilities."""
    print("\\n=== Database Monitoring ===")
    
    # Configure monitoring
    monitor_config = DatabaseMonitorConfig(
        health_check_interval=30,
        metrics_collection_interval=15,
        max_checkout_time_threshold=2.0,
        connection_failure_rate_threshold=0.05,
        alert_cooldown_minutes=5
    )
    
    # Start monitoring
    pool_manager = await get_pool_manager()
    monitor = DatabaseMonitor(monitor_config)
    monitor.add_alert_callback(alert_handler)
    
    await monitor.start_monitoring(pool_manager)
    
    try:
        print("Monitoring started. Collecting metrics for 60 seconds...")
        
        # Simulate some database activity
        for i in range(10):
            async with pool_manager.get_session() as session:
                from sqlalchemy import text
                await session.execute(text("SELECT pg_sleep(0.1)"))  # Short delay
            await asyncio.sleep(1)
        
        # Get monitoring status
        status = monitor.get_status()
        print(f"Monitoring status: {status}")
        
        # Get metrics summary
        metrics = monitor.get_metrics_summary()
        print(f"\\nMetrics summary:")
        print(f"  - Total queries: {metrics.get('queries', {}).get('total', 0)}")
        print(f"  - Average query time: {metrics.get('queries', {}).get('average_time', 0):.3f}s")
        print(f"  - Active connections: {metrics.get('connections', {}).get('active', 0)}")
        print(f"  - Total checkouts: {metrics.get('checkouts', {}).get('total', 0)}")
        
        # Check for alerts
        alerts = monitor.get_alerts()
        print(f"\\nActive alerts: {len(alerts)}")
        for alert in alerts:
            print(f"  - {alert.alert_type}: {alert.message}")
        
    finally:
        await monitor.stop_monitoring()
        print("Monitoring stopped.")


async def demonstrate_error_handling():
    """Demonstrate error handling and recovery."""
    print("\\n=== Error Handling and Recovery ===")
    
    pool_manager = await get_pool_manager()
    
    # Example 1: Query timeout
    print("1. Testing query timeout...")
    try:
        await pool_manager.execute_query(
            "SELECT pg_sleep(10)",  # 10-second sleep
            timeout=2  # 2-second timeout
        )
    except Exception as e:
        print(f"   Expected timeout error: {type(e).__name__}: {e}")
    
    # Example 2: Invalid query
    print("2. Testing invalid query handling...")
    try:
        await pool_manager.execute_query("SELECT * FROM nonexistent_table")
    except Exception as e:
        print(f"   Expected query error: {type(e).__name__}")
    
    # Example 3: Connection recovery
    print("3. Testing connection recovery...")
    health_before = await pool_manager.health_check()
    print(f"   Health before: {health_before['status']}")
    
    # The pool should recover automatically
    await asyncio.sleep(1)
    health_after = await pool_manager.health_check()
    print(f"   Health after: {health_after['status']}")


async def demonstrate_repository_usage():
    """Demonstrate enhanced repository usage with timeouts and connection management."""
    print("\\n=== Enhanced Repository Usage ===")
    
    user_repo = UserRepository()  # Automatically uses pool manager
    
    try:
        # Example 1: Create user with automatic connection management
        print("1. Creating test user...")
        test_user = await user_repo.create_user(
            username=f"test_user_{int(asyncio.get_event_loop().time())}",
            email="test@example.com",
            full_name="Test User",
            role=UserRole.VIEWER
        )
        print(f"   Created user: {test_user.username} (ID: {test_user.id})")
        
        # Example 2: Search with timeout
        print("2. Searching users...")
        users = await user_repo.search_users("test", limit=10)
        print(f"   Found {len(users)} users matching 'test'")
        
        # Example 3: Get user statistics
        print("3. Getting user statistics...")
        stats = await user_repo.get_user_statistics()
        print(f"   Total users: {stats['total_users']}")
        print(f"   Active users: {stats['active_users']}")
        print(f"   Users by role: {stats['users_by_role']}")
        
        # Example 4: Cleanup test user
        print("4. Cleaning up test user...")
        deleted = await user_repo.delete(test_user.id)
        print(f"   User deleted: {deleted}")
        
    except Exception as e:
        logger.error(f"Repository operation failed: {e}")


async def demonstrate_health_monitoring():
    """Demonstrate comprehensive health monitoring."""
    print("\\n=== Health Monitoring ===")
    
    pool_manager = await get_pool_manager()
    
    # Perform health check
    health_status = await pool_manager.health_check()
    
    print(f"Overall status: {health_status['status']}")
    print(f"Engine check: {health_status['checks'].get('engine', 'N/A')}")
    
    if 'pool' in health_status:
        pool_info = health_status['pool']
        print(f"Pool status:")
        print(f"  - Size: {pool_info['size']}")
        print(f"  - Checked in: {pool_info['checked_in']}")
        print(f"  - Overflow: {pool_info['overflow']}")
        print(f"  - Total: {pool_info['total']}")
    
    if 'circuit_breaker' in health_status:
        cb_info = health_status['circuit_breaker']
        print(f"Circuit breaker:")
        print(f"  - State: {cb_info['state']}")
        print(f"  - Failure count: {cb_info['failure_count']}")
    
    # Check for connection leaks
    if 'connection_leaks' in health_status:
        leaks = health_status['connection_leaks']
        if leaks:
            print(f"⚠️  Connection leaks detected: {len(leaks)}")
            for leak in leaks[:3]:  # Show first 3
                print(f"   - Session {leak['session_id']}: {leak['age_seconds']:.1f}s old")
        else:
            print("✅ No connection leaks detected")
    
    # Show metrics
    if 'metrics' in health_status:
        metrics = health_status['metrics']
        connections = metrics.get('connections', {})
        checkouts = metrics.get('checkouts', {})
        queries = metrics.get('queries', {})
        
        print(f"\\nMetrics summary:")
        print(f"  Connections: {connections.get('active', 0)} active, {connections.get('idle', 0)} idle")
        print(f"  Checkouts: {checkouts.get('total', 0)} total, {checkouts.get('average_wait_time', 0):.3f}s avg wait")
        print(f"  Queries: {queries.get('total', 0)} total, {queries.get('average_time', 0):.3f}s avg time")


async def main():
    """Main demonstration function."""
    print("🚀 Enhanced Database Connection Management Demo")
    print("=" * 60)
    
    # Set up basic logging
    logging.basicConfig(level=logging.INFO)
    
    # Set environment variables for demo
    os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost/claude_demo")
    os.environ.setdefault("POD_COUNT", "2")
    os.environ.setdefault("DB_MIN_POOL_SIZE", "3")
    os.environ.setdefault("DB_MAX_POOL_SIZE", "10")
    os.environ.setdefault("DB_ENABLE_MONITORING", "true")
    
    try:
        # Demonstrate pool configuration
        await demonstrate_pool_configuration()
        
        # Wait a moment for dramatic effect
        await asyncio.sleep(1)
        
        # Demonstrate basic usage
        await demonstrate_basic_usage()
        await asyncio.sleep(1)
        
        # Demonstrate health monitoring
        await demonstrate_health_monitoring()
        await asyncio.sleep(1)
        
        # Demonstrate repository usage
        await demonstrate_repository_usage()
        await asyncio.sleep(1)
        
        # Demonstrate error handling
        await demonstrate_error_handling()
        await asyncio.sleep(1)
        
        # Demonstrate monitoring (shorter version for demo)
        print("\\n=== Quick Monitoring Demo ===")
        monitor_config = DatabaseMonitorConfig(
            health_check_interval=5,
            metrics_collection_interval=2
        )
        monitor = DatabaseMonitor(monitor_config)
        monitor.add_alert_callback(alert_handler)
        
        await monitor.start_monitoring()
        print("Monitoring for 10 seconds...")
        await asyncio.sleep(10)
        
        status = monitor.get_status()
        print(f"Final monitoring status: {status}")
        
        await monitor.stop_monitoring()
        
        print("\\n✅ Demo completed successfully!")
        
    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        print(f"\\n❌ Demo failed: {e}")
    
    finally:
        # Clean up
        try:
            await stop_database_monitoring()
            await close_pool_manager()
            print("\\n🧹 Cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


if __name__ == "__main__":
    # For demonstration purposes, we'll catch any import errors
    # and provide helpful messages
    try:
        asyncio.run(main())
    except ImportError as e:
        print(f"Import error: {e}")
        print("\\nMake sure you have all required dependencies installed:")
        print("pip install asyncpg sqlalchemy tortoise-orm aioredis")
    except Exception as e:
        print(f"Demo error: {e}")
        print("\\nMake sure PostgreSQL is running and accessible with the demo connection string.")