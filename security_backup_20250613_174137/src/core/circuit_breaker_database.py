"""
Circuit breaker implementations for database connections.

This module provides circuit breaker protection for database operations including:
- Connection pool management with circuit breaker
- Query-level protection
- Transaction management
- Health checking for database connections
- Automatic failover and recovery
"""

import asyncio
import time
import logging
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, AsyncContextManager
from dataclasses import dataclass
from contextlib import asynccontextmanager
import traceback
from datetime import datetime

from src.core.circuit_breaker_standard import (
    StandardizedCircuitBreaker,
    StandardCircuitBreakerConfig,
    CircuitBreakerType,
    BulkheadConfig,
    HealthCheckConfig,
    CircuitOpenError
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class DatabaseCircuitBreakerConfig:
    """Configuration for database circuit breakers."""
    database_name: str = "default"
    connection_timeout: float = 30.0
    query_timeout: float = 60.0
    max_connections: int = 50
    min_connections: int = 5
    health_check_query: str = "SELECT 1"
    health_check_interval: float = 30.0
    enable_query_logging: bool = True
    enable_slow_query_detection: bool = True
    slow_query_threshold: float = 5.0
    enable_connection_retry: bool = True
    max_connection_retries: int = 3
    retry_delay: float = 1.0


class DatabaseCircuitBreaker:
    """
    Circuit breaker specifically designed for database operations.
    
    Features:
    - Connection-level protection
    - Query-level protection
    - Transaction management
    - Health monitoring
    - Automatic recovery
    """
    
    def __init__(self, config: DatabaseCircuitBreakerConfig):
        """Initialize database circuit breaker."""
        self.config = config
        self.name = f"database_{config.database_name}"
        
        # Create standardized circuit breakers for different operations
        self._connection_breaker = self._create_connection_breaker()
        self._query_breaker = self._create_query_breaker()
        self._transaction_breaker = self._create_transaction_breaker()
        
        # Database-specific metrics
        self._connection_metrics = {
            'active_connections': 0,
            'total_connections_created': 0,
            'connection_failures': 0,
            'connection_timeouts': 0,
            'pool_exhausted_count': 0
        }
        
        self._query_metrics = {
            'total_queries': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'slow_queries': 0,
            'query_timeouts': 0,
            'average_query_time': 0.0
        }
        
        # Health monitoring
        self._last_health_check = None
        self._health_check_failures = 0
        self._is_healthy = True
        
        logger.info(f"Initialized database circuit breaker for '{config.database_name}'")
    
    def _create_connection_breaker(self) -> StandardizedCircuitBreaker:
        """Create circuit breaker for database connections."""
        config = StandardCircuitBreakerConfig(
            name=f"{self.name}_connections",
            circuit_type=CircuitBreakerType.COUNT_BASED,
            failure_threshold=3,
            timeout=30.0,
            failure_rate_threshold=0.3,
            minimum_calls=5,
            service_category="database",
            priority=1,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=self.config.max_connections,
                isolation_pool_name=f"db_connections_{self.config.database_name}",
                queue_timeout=self.config.connection_timeout
            ),
            health_check_config=HealthCheckConfig(
                health_check_interval=self.config.health_check_interval,
                health_check_timeout=5.0,
                health_check_function=self._perform_health_check
            )
        )
        
        return StandardizedCircuitBreaker(config)
    
    def _create_query_breaker(self) -> StandardizedCircuitBreaker:
        """Create circuit breaker for database queries."""
        config = StandardCircuitBreakerConfig(
            name=f"{self.name}_queries",
            circuit_type=CircuitBreakerType.PERCENTAGE_BASED,
            failure_threshold=5,
            timeout=60.0,
            failure_rate_threshold=0.5,
            minimum_calls=10,
            service_category="database",
            priority=1,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=100,
                isolation_pool_name=f"db_queries_{self.config.database_name}",
                queue_timeout=self.config.query_timeout
            )
        )
        
        return StandardizedCircuitBreaker(config)
    
    def _create_transaction_breaker(self) -> StandardizedCircuitBreaker:
        """Create circuit breaker for database transactions."""
        config = StandardCircuitBreakerConfig(
            name=f"{self.name}_transactions",
            circuit_type=CircuitBreakerType.ADAPTIVE,
            failure_threshold=3,
            timeout=45.0,
            failure_rate_threshold=0.4,
            minimum_calls=5,
            service_category="database",
            priority=1,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=50,
                isolation_pool_name=f"db_transactions_{self.config.database_name}",
                queue_timeout=30.0
            )
        )
        
        return StandardizedCircuitBreaker(config)
    
    async def _perform_health_check(self) -> bool:
        """Perform database health check."""
        try:
            # This would be implemented with actual database connection
            # For now, return True as placeholder
            self._last_health_check = datetime.now()
            self._health_check_failures = 0
            self._is_healthy = True
            return True
            
        except Exception as e:
            self._health_check_failures += 1
            if self._health_check_failures >= 3:
                self._is_healthy = False
            logger.error(f"Database health check failed for '{self.config.database_name}': {e}")
            return False
    
    @asynccontextmanager
    async def get_connection(self):
        """
        Get database connection with circuit breaker protection.
        
        Usage:
            async with db_breaker.get_connection() as conn:
                # Use connection
                result = await conn.execute("SELECT * FROM users")
        """
        connection = None
        start_time = time.time()
        
        try:
            # Get connection through circuit breaker
            connection = await self._connection_breaker.call(self._create_connection)
            
            self._connection_metrics['active_connections'] += 1
            connection_time = time.time() - start_time
            
            if connection_time > self.config.connection_timeout:
                self._connection_metrics['connection_timeouts'] += 1
                logger.warning(
                    f"Database connection took {connection_time:.3f}s "
                    f"(threshold: {self.config.connection_timeout}s)"
                )
            
            yield connection
            
        except CircuitOpenError:
            self._connection_metrics['connection_failures'] += 1
            logger.error(f"Database circuit breaker is open for '{self.config.database_name}'")
            raise
            
        except Exception as e:
            self._connection_metrics['connection_failures'] += 1
            logger.error(f"Database connection failed for '{self.config.database_name}': {e}")
            raise
            
        finally:
            if connection:
                try:
                    await self._close_connection(connection)
                except Exception as e:
                    logger.error(f"Error closing database connection: {e}")
                finally:
                    self._connection_metrics['active_connections'] -= 1
    
    async def _create_connection(self):
        """Create a new database connection."""
        # Placeholder for actual database connection logic
        # This would use the appropriate database driver (asyncpg, aiomysql, etc.)
        await asyncio.sleep(0.1)  # Simulate connection time
        self._connection_metrics['total_connections_created'] += 1
        return {"connection_id": time.time(), "database": self.config.database_name}
    
    async def _close_connection(self, connection):
        """Close a database connection."""
        # Placeholder for actual connection closing logic
        await asyncio.sleep(0.01)  # Simulate cleanup time
    
    async def execute_query(
        self,
        query: str,
        parameters: Optional[List[Any]] = None,
        connection=None
    ) -> Any:
        """
        Execute database query with circuit breaker protection.
        
        Args:
            query: SQL query to execute
            parameters: Query parameters
            connection: Existing connection (optional)
        
        Returns:
            Query result
        """
        start_time = time.time()
        
        async def _execute_query_internal():
            if connection:
                return await self._execute_on_connection(connection, query, parameters)
            else:
                async with self.get_connection() as conn:
                    return await self._execute_on_connection(conn, query, parameters)
        
        try:
            result = await self._query_breaker.call(_execute_query_internal)
            
            # Record metrics
            duration = time.time() - start_time
            self._query_metrics['total_queries'] += 1
            self._query_metrics['successful_queries'] += 1
            
            # Update average query time
            total_queries = self._query_metrics['total_queries']
            current_avg = self._query_metrics['average_query_time']
            self._query_metrics['average_query_time'] = (
                (current_avg * (total_queries - 1) + duration) / total_queries
            )
            
            # Check for slow query
            if duration > self.config.slow_query_threshold:
                self._query_metrics['slow_queries'] += 1
                if self.config.enable_slow_query_detection:
                    logger.warning(
                        f"Slow query detected (duration: {duration:.3f}s): {query[:100]}..."
                    )
            
            if self.config.enable_query_logging:
                logger.debug(f"Query executed in {duration:.3f}s: {query[:50]}...")
            
            return result
            
        except CircuitOpenError:
            self._query_metrics['total_queries'] += 1
            self._query_metrics['failed_queries'] += 1
            logger.error(f"Query circuit breaker is open for '{self.config.database_name}'")
            raise
            
        except Exception as e:
            duration = time.time() - start_time
            self._query_metrics['total_queries'] += 1
            self._query_metrics['failed_queries'] += 1
            
            if duration > self.config.query_timeout:
                self._query_metrics['query_timeouts'] += 1
            
            logger.error(
                f"Query failed for '{self.config.database_name}' "
                f"(duration: {duration:.3f}s): {e}"
            )
            raise
    
    async def _execute_on_connection(self, connection, query: str, parameters: Optional[List[Any]]):
        """Execute query on a specific connection."""
        # Placeholder for actual query execution
        await asyncio.sleep(0.05)  # Simulate query time
        return {"query": query, "parameters": parameters, "rows_affected": 1}
    
    @asynccontextmanager
    async def transaction(self, connection=None):
        """
        Database transaction with circuit breaker protection.
        
        Usage:
            async with db_breaker.transaction() as tx:
                await tx.execute("INSERT INTO users ...")
                await tx.execute("UPDATE accounts ...")
                # Transaction automatically committed on success
        """
        if connection:
            # Use existing connection
            async with self._transaction_context(connection) as tx:
                yield tx
        else:
            # Create new connection for transaction
            async with self.get_connection() as conn:
                async with self._transaction_context(conn) as tx:
                    yield tx
    
    @asynccontextmanager
    async def _transaction_context(self, connection):
        """Internal transaction context manager."""
        start_time = time.time()
        transaction = None
        
        try:
            # Start transaction through circuit breaker
            transaction = await self._transaction_breaker.call(
                self._begin_transaction, connection
            )
            
            yield TransactionWrapper(self, connection, transaction)
            
            # Commit transaction
            await self._commit_transaction(connection, transaction)
            
            duration = time.time() - start_time
            logger.debug(f"Transaction committed in {duration:.3f}s")
            
        except CircuitOpenError:
            logger.error(f"Transaction circuit breaker is open for '{self.config.database_name}'")
            if transaction:
                await self._rollback_transaction(connection, transaction)
            raise
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"Transaction failed for '{self.config.database_name}' "
                f"(duration: {duration:.3f}s): {e}"
            )
            if transaction:
                await self._rollback_transaction(connection, transaction)
            raise
    
    async def _begin_transaction(self, connection):
        """Begin a database transaction."""
        # Placeholder for actual transaction begin
        await asyncio.sleep(0.01)
        return {"transaction_id": time.time(), "connection": connection}
    
    async def _commit_transaction(self, connection, transaction):
        """Commit a database transaction."""
        # Placeholder for actual transaction commit
        await asyncio.sleep(0.01)
    
    async def _rollback_transaction(self, connection, transaction):
        """Rollback a database transaction."""
        # Placeholder for actual transaction rollback
        await asyncio.sleep(0.01)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive database circuit breaker metrics."""
        return {
            "database_name": self.config.database_name,
            "is_healthy": self._is_healthy,
            "last_health_check": self._last_health_check.isoformat() if self._last_health_check else None,
            "health_check_failures": self._health_check_failures,
            "connection_metrics": dict(self._connection_metrics),
            "query_metrics": dict(self._query_metrics),
            "circuit_breakers": {
                "connections": self._connection_breaker.get_metrics(),
                "queries": self._query_breaker.get_metrics(),
                "transactions": self._transaction_breaker.get_metrics()
            }
        }
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status summary."""
        connection_state = self._connection_breaker.get_state()
        query_state = self._query_breaker.get_state()
        transaction_state = self._transaction_breaker.get_state()
        
        overall_healthy = (
            self._is_healthy and
            connection_state.value == "closed" and
            query_state.value == "closed" and
            transaction_state.value == "closed"
        )
        
        return {
            "overall_healthy": overall_healthy,
            "database_healthy": self._is_healthy,
            "circuit_states": {
                "connections": connection_state.value,
                "queries": query_state.value,
                "transactions": transaction_state.value
            },
            "active_connections": self._connection_metrics['active_connections'],
            "recent_query_failures": self._query_metrics['failed_queries']
        }


class TransactionWrapper:
    """Wrapper for database transaction operations."""
    
    def __init__(self, breaker: DatabaseCircuitBreaker, connection, transaction):
        self.breaker = breaker
        self.connection = connection
        self.transaction = transaction
    
    async def execute(self, query: str, parameters: Optional[List[Any]] = None) -> Any:
        """Execute query within the transaction."""
        return await self.breaker.execute_query(query, parameters, self.connection)
    
    async def executemany(self, query: str, parameter_list: List[List[Any]]) -> Any:
        """Execute query multiple times with different parameters."""
        results = []
        for parameters in parameter_list:
            result = await self.execute(query, parameters)
            results.append(result)
        return results


class DatabaseCircuitBreakerManager:
    """Manager for multiple database circuit breakers."""
    
    def __init__(self):
        self._database_breakers: Dict[str, DatabaseCircuitBreaker] = {}
        self._configs: Dict[str, DatabaseCircuitBreakerConfig] = {}
    
    def register_database(
        self,
        database_name: str,
        config: Optional[DatabaseCircuitBreakerConfig] = None
    ) -> DatabaseCircuitBreaker:
        """Register a database with circuit breaker protection."""
        if config is None:
            config = DatabaseCircuitBreakerConfig(database_name=database_name)
        
        breaker = DatabaseCircuitBreaker(config)
        self._database_breakers[database_name] = breaker
        self._configs[database_name] = config
        
        logger.info(f"Registered database circuit breaker for '{database_name}'")
        return breaker
    
    def get_database_breaker(self, database_name: str) -> Optional[DatabaseCircuitBreaker]:
        """Get circuit breaker for a database."""
        return self._database_breakers.get(database_name)
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get metrics for all database circuit breakers."""
        return {
            db_name: breaker.get_metrics()
            for db_name, breaker in self._database_breakers.items()
        }
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary for all databases."""
        all_healthy = True
        database_health = {}
        
        for db_name, breaker in self._database_breakers.items():
            health_status = breaker.get_health_status()
            database_health[db_name] = health_status
            
            if not health_status["overall_healthy"]:
                all_healthy = False
        
        return {
            "all_databases_healthy": all_healthy,
            "total_databases": len(self._database_breakers),
            "databases": database_health
        }


# Global database circuit breaker manager
_database_manager = DatabaseCircuitBreakerManager()


def get_database_circuit_breaker_manager() -> DatabaseCircuitBreakerManager:
    """Get the global database circuit breaker manager."""
    return _database_manager


def get_database_circuit_breaker(
    database_name: str,
    config: Optional[DatabaseCircuitBreakerConfig] = None
) -> DatabaseCircuitBreaker:
    """
    Get or create a database circuit breaker.
    
    Args:
        database_name: Name of the database
        config: Database circuit breaker configuration
    
    Returns:
        Database circuit breaker instance
    """
    manager = get_database_circuit_breaker_manager()
    breaker = manager.get_database_breaker(database_name)
    
    if breaker is None:
        breaker = manager.register_database(database_name, config)
    
    return breaker


# Convenience decorator for database operations
def database_operation(database_name: str = "default"):
    """
    Decorator for database operations with circuit breaker protection.
    
    Usage:
        @database_operation("user_db")
        async def get_user(user_id: int):
            async with get_database_connection() as conn:
                return await conn.fetch("SELECT * FROM users WHERE id = $1", user_id)
    """
    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            breaker = get_database_circuit_breaker(database_name)
            return await breaker._query_breaker.call(func, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    return decorator


# Export public API
__all__ = [
    'DatabaseCircuitBreaker',
    'DatabaseCircuitBreakerConfig',
    'DatabaseCircuitBreakerManager',
    'TransactionWrapper',
    'get_database_circuit_breaker_manager',
    'get_database_circuit_breaker',
    'database_operation',
]