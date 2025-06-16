"""
Database management module for comprehensive database operations and administration.

This module consolidates functionality from database management scripts:
- scripts/db_manager.py
- Database migration tools
- Connection management utilities
- Performance monitoring tools

Provides unified interface for database operations, migrations, monitoring,
and administration following enterprise database management standards.
"""

import asyncio
import sqlite3
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import asynccontextmanager
import psutil

# Import database libraries with fallbacks
try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False
    asyncpg = None

# Import database libraries with fallbacks
try:
    from tortoise import Tortoise
    from tortoise.models import Model
    from tortoise.transactions import in_transaction
    HAS_TORTOISE = True
except ImportError:
    HAS_TORTOISE = False

try:
    from alembic.config import Config
    from alembic import command
    from alembic.script import ScriptDirectory
    from alembic.runtime.migration import MigrationContext
    HAS_ALEMBIC = True
except ImportError:
    HAS_ALEMBIC = False

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    url: str
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False
    
    
@dataclass
class QueryResult:
    """Result from a database query."""
    rows: List[Dict[str, Any]]
    row_count: int
    execution_time_ms: float
    query: str
    success: bool = True
    error: Optional[str] = None
    
    
@dataclass
class MigrationResult:
    """Result from a database migration."""
    migration_id: str
    description: str
    success: bool
    execution_time_ms: float
    error: Optional[str] = None
    sql_executed: List[str] = field(default_factory=list)
    
    
@dataclass
class DatabaseStats:
    """Database performance and usage statistics."""
    connection_count: int
    active_connections: int
    idle_connections: int
    query_count: int
    average_query_time_ms: float
    slow_query_count: int
    error_count: int
    database_size_mb: float
    table_count: int
    index_count: int
    uptime_seconds: float
    cache_hit_ratio: float = 0.0
    
    
class DatabaseManager:
    """
    Comprehensive database management and administration.
    
    Provides unified interface for database operations, migrations,
    monitoring, and performance optimization.
    """
    
    def __init__(self, config: DatabaseConfig):
        """
        Initialize DatabaseManager.
        
        Args:
            config: Database configuration
        """
        self.config = config
        self._connection_pool: Optional[asyncpg.Pool] = None
        self._is_connected = False
        
        # Performance tracking
        self.query_history: List[Dict[str, Any]] = []
        self.slow_query_threshold_ms = 1000
        self.error_count = 0
        
        # Migration tracking
        self.migration_directory: Optional[Path] = None
        self.alembic_config: Optional[Any] = None
        
    async def initialize(self):
        """Initialize database connection and setup."""
        if not HAS_ASYNCPG:
            logger.warning("asyncpg not available, database functionality limited")
            self._is_connected = False
            return
            
        try:
            # Create connection pool
            self._connection_pool = await asyncpg.create_pool(
                self.config.url,
                min_size=1,
                max_size=self.config.pool_size,
                command_timeout=self.config.pool_timeout
            )
            
            self._is_connected = True
            logger.info("Database connection pool initialized")
            
            # Initialize Tortoise ORM if available
            if HAS_TORTOISE:
                await self._initialize_tortoise()
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
            
    async def _initialize_tortoise(self):
        """Initialize Tortoise ORM."""
        try:
            await Tortoise.init(
                db_url=self.config.url,
                modules={"models": ["src.database.models"]}
            )
            logger.info("Tortoise ORM initialized")
        except Exception as e:
            logger.warning(f"Tortoise ORM initialization failed: {e}")
            
    async def close(self):
        """Close database connections."""
        if self._connection_pool:
            await self._connection_pool.close()
            self._is_connected = False
            
        if HAS_TORTOISE:
            await Tortoise.close_connections()
            
        logger.info("Database connections closed")
        
    @asynccontextmanager
    async def get_connection(self):
        """
        Get a database connection from the pool.
        
        Usage:
            async with db_manager.get_connection() as conn:
                result = await conn.fetch("SELECT * FROM users")
        """
        if not HAS_ASYNCPG:
            raise RuntimeError("asyncpg not available")
            
        if not self._connection_pool:
            raise RuntimeError("Database not initialized")
            
        async with self._connection_pool.acquire() as connection:
            yield connection
            
    async def execute_query(self, 
                          query: str, 
                          params: Optional[Tuple] = None,
                          fetch_results: bool = True) -> QueryResult:
        """
        Execute a database query.
        
        Args:
            query: SQL query to execute
            params: Query parameters
            fetch_results: Whether to fetch and return results
            
        Returns:
            QueryResult with query results and metadata
        """
        start_time = time.time()
        
        try:
            async with self.get_connection() as conn:
                if fetch_results:
                    if params:
                        rows = await conn.fetch(query, *params)
                    else:
                        rows = await conn.fetch(query)
                        
                    # Convert to list of dicts
                    result_rows = [dict(row) for row in rows]
                    row_count = len(result_rows)
                else:
                    if params:
                        await conn.execute(query, *params)
                    else:
                        await conn.execute(query)
                    result_rows = []
                    row_count = 0
                    
                execution_time = (time.time() - start_time) * 1000
                
                # Track query performance
                self._track_query_performance(query, execution_time, True)
                
                return QueryResult(
                    rows=result_rows,
                    row_count=row_count,
                    execution_time_ms=execution_time,
                    query=query,
                    success=True
                )
                
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            self.error_count += 1
            self._track_query_performance(query, execution_time, False, str(e))
            
            logger.error(f"Query execution failed: {e}")
            logger.error(f"Query: {query}")
            
            return QueryResult(
                rows=[],
                row_count=0,
                execution_time_ms=execution_time,
                query=query,
                success=False,
                error=str(e)
            )
            
    def _track_query_performance(self, 
                               query: str, 
                               execution_time: float,
                               success: bool,
                               error: Optional[str] = None):
        """Track query performance metrics."""
        query_info = {
            'timestamp': datetime.now().isoformat(),
            'query': query[:200] + '...' if len(query) > 200 else query,
            'execution_time_ms': execution_time,
            'success': success,
            'error': error
        }
        
        self.query_history.append(query_info)
        
        # Keep only last 1000 queries
        if len(self.query_history) > 1000:
            self.query_history = self.query_history[-1000:]
            
    async def execute_transaction(self, queries: List[Tuple[str, Optional[Tuple]]]) -> List[QueryResult]:
        """
        Execute multiple queries in a transaction.
        
        Args:
            queries: List of (query, params) tuples
            
        Returns:
            List of QueryResult objects
        """
        results = []
        
        try:
            async with self.get_connection() as conn:
                async with conn.transaction():
                    for query, params in queries:
                        result = await self.execute_query(query, params)
                        results.append(result)
                        
                        # If any query fails, transaction will be rolled back
                        if not result.success:
                            break
                            
        except Exception as e:
            logger.error(f"Transaction failed: {e}")
            # Add error result if transaction fails
            results.append(QueryResult(
                rows=[],
                row_count=0,
                execution_time_ms=0,
                query="TRANSACTION",
                success=False,
                error=str(e)
            ))
            
        return results
        
    async def get_table_info(self, table_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a table.
        
        Args:
            table_name: Name of the table
            
        Returns:
            Dictionary with table information
        """
        queries = {
            'columns': """
                SELECT column_name, data_type, is_nullable, column_default,
                       character_maximum_length, numeric_precision, numeric_scale
                FROM information_schema.columns 
                WHERE table_name = $1
                ORDER BY ordinal_position
            """,
            'indexes': """
                SELECT indexname, indexdef
                FROM pg_indexes 
                WHERE tablename = $1
            """,
            'constraints': """
                SELECT constraint_name, constraint_type
                FROM information_schema.table_constraints
                WHERE table_name = $1
            """,
            'size': """
                SELECT pg_size_pretty(pg_total_relation_size($1)) as size,
                       pg_size_pretty(pg_relation_size($1)) as table_size,
                       pg_size_pretty(pg_total_relation_size($1) - pg_relation_size($1)) as index_size
            """
        }
        
        table_info = {'table_name': table_name}
        
        for info_type, query in queries.items():
            result = await self.execute_query(query, (table_name,))
            if result.success:
                table_info[info_type] = result.rows
            else:
                table_info[info_type] = []
                logger.warning(f"Failed to get {info_type} for table {table_name}: {result.error}")
                
        return table_info
        
    async def get_database_stats(self) -> DatabaseStats:
        """
        Get comprehensive database statistics.
        
        Returns:
            DatabaseStats with current database metrics
        """
        stats_queries = {
            'connections': """
                SELECT count(*) as total,
                       count(*) FILTER (WHERE state = 'active') as active,
                       count(*) FILTER (WHERE state = 'idle') as idle
                FROM pg_stat_activity
                WHERE datname = current_database()
            """,
            'database_info': """
                SELECT pg_database_size(current_database()) as size_bytes,
                       (SELECT count(*) FROM information_schema.tables 
                        WHERE table_schema = 'public') as table_count,
                       (SELECT count(*) FROM pg_indexes 
                        WHERE schemaname = 'public') as index_count
            """,
            'query_stats': """
                SELECT calls, mean_exec_time, total_exec_time
                FROM pg_stat_statements
                WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
                LIMIT 1
            """
        }
        
        # Default stats
        stats = DatabaseStats(
            connection_count=0,
            active_connections=0,
            idle_connections=0,
            query_count=len(self.query_history),
            average_query_time_ms=0,
            slow_query_count=0,
            error_count=self.error_count,
            database_size_mb=0,
            table_count=0,
            index_count=0,
            uptime_seconds=0
        )
        
        # Get connection stats
        result = await self.execute_query(stats_queries['connections'])
        if result.success and result.rows:
            conn_stats = result.rows[0]
            stats.connection_count = conn_stats.get('total', 0)
            stats.active_connections = conn_stats.get('active', 0)
            stats.idle_connections = conn_stats.get('idle', 0)
            
        # Get database info
        result = await self.execute_query(stats_queries['database_info'])
        if result.success and result.rows:
            db_info = result.rows[0]
            stats.database_size_mb = db_info.get('size_bytes', 0) / 1024 / 1024
            stats.table_count = db_info.get('table_count', 0)
            stats.index_count = db_info.get('index_count', 0)
            
        # Calculate query stats from history
        if self.query_history:
            execution_times = [q['execution_time_ms'] for q in self.query_history if q['success']]
            if execution_times:
                stats.average_query_time_ms = sum(execution_times) / len(execution_times)
                
            stats.slow_query_count = len([
                q for q in self.query_history 
                if q['execution_time_ms'] > self.slow_query_threshold_ms
            ])
            
        return stats
        
    async def backup_database(self, backup_path: Path, format: str = 'sql') -> bool:
        """
        Create a database backup.
        
        Args:
            backup_path: Path to save backup file
            format: Backup format (sql, custom, tar)
            
        Returns:
            True if backup successful
        """
        try:
            import subprocess
            
            # Extract database info from URL
            # This is a simplified version - production would parse URL properly
            if format == 'sql':
                cmd = [
                    'pg_dump',
                    '--no-password',
                    '--format=plain',
                    '--file', str(backup_path),
                    self.config.url
                ]
            else:
                cmd = [
                    'pg_dump',
                    '--no-password',
                    f'--format={format}',
                    '--file', str(backup_path),
                    self.config.url
                ]
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Database backup created: {backup_path}")
                return True
            else:
                logger.error(f"Backup failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False
            
    async def restore_database(self, backup_path: Path) -> bool:
        """
        Restore database from backup.
        
        Args:
            backup_path: Path to backup file
            
        Returns:
            True if restore successful
        """
        try:
            import subprocess
            
            # Determine format from file extension
            if backup_path.suffix == '.sql':
                cmd = [
                    'psql',
                    '--no-password',
                    '--file', str(backup_path),
                    self.config.url
                ]
            else:
                cmd = [
                    'pg_restore',
                    '--no-password',
                    '--clean',
                    '--create',
                    '--dbname', self.config.url,
                    str(backup_path)
                ]
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Database restored from: {backup_path}")
                return True
            else:
                logger.error(f"Restore failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
            
    def setup_migrations(self, migrations_dir: Path):
        """
        Setup database migrations using Alembic.
        
        Args:
            migrations_dir: Directory containing migration files
        """
        if not HAS_ALEMBIC:
            logger.error("Alembic not available for migrations")
            return
            
        self.migration_directory = migrations_dir
        
        # Create alembic.ini if it doesn't exist
        alembic_ini = migrations_dir.parent / 'alembic.ini'
        
        if not alembic_ini.exists():
            self._create_alembic_config(alembic_ini, migrations_dir)
            
        self.alembic_config = Config(str(alembic_ini))
        
    def _create_alembic_config(self, config_path: Path, migrations_dir: Path):
        """Create default Alembic configuration."""
        config_content = f"""[alembic]
script_location = {migrations_dir}
sqlalchemy.url = {self.config.url}

[post_write_hooks]

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"""
        
        with open(config_path, 'w') as f:
            f.write(config_content)
            
    async def run_migrations(self, target_revision: str = 'head') -> List[MigrationResult]:
        """
        Run database migrations.
        
        Args:
            target_revision: Target migration revision
            
        Returns:
            List of MigrationResult objects
        """
        if not self.alembic_config:
            raise RuntimeError("Migrations not setup. Call setup_migrations() first.")
            
        results = []
        
        try:
            start_time = time.time()
            
            # Run migrations
            command.upgrade(self.alembic_config, target_revision)
            
            execution_time = (time.time() - start_time) * 1000
            
            results.append(MigrationResult(
                migration_id=target_revision,
                description=f"Upgrade to {target_revision}",
                success=True,
                execution_time_ms=execution_time
            ))
            
            logger.info(f"Migrations completed successfully to {target_revision}")
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            
            results.append(MigrationResult(
                migration_id=target_revision,
                description=f"Failed upgrade to {target_revision}",
                success=False,
                execution_time_ms=execution_time,
                error=str(e)
            ))
            
            logger.error(f"Migration failed: {e}")
            
        return results
        
    async def create_migration(self, message: str) -> Optional[str]:
        """
        Create a new migration file.
        
        Args:
            message: Migration description
            
        Returns:
            Migration file path if successful
        """
        if not self.alembic_config:
            raise RuntimeError("Migrations not setup. Call setup_migrations() first.")
            
        try:
            # Generate migration
            command.revision(self.alembic_config, message=message, autogenerate=True)
            
            logger.info(f"Migration created: {message}")
            return message
            
        except Exception as e:
            logger.error(f"Failed to create migration: {e}")
            return None
            
    async def get_migration_status(self) -> Dict[str, Any]:
        """
        Get current migration status.
        
        Returns:
            Dictionary with migration information
        """
        if not self.alembic_config:
            return {'error': 'Migrations not configured'}
            
        try:
            script_dir = ScriptDirectory.from_config(self.alembic_config)
            
            # Get current revision
            async with self.get_connection() as conn:
                context = MigrationContext.configure(conn)
                current_rev = context.get_current_revision()
                
            # Get all revisions
            revisions = list(script_dir.walk_revisions())
            
            return {
                'current_revision': current_rev,
                'head_revision': script_dir.get_current_head(),
                'total_migrations': len(revisions),
                'pending_migrations': [
                    rev.revision for rev in revisions 
                    if rev.revision != current_rev
                ]
            }
            
        except Exception as e:
            logger.error(f"Failed to get migration status: {e}")
            return {'error': str(e)}
            
    async def optimize_database(self) -> Dict[str, Any]:
        """
        Perform database optimization operations.
        
        Returns:
            Dictionary with optimization results
        """
        optimization_results = {
            'vacuum': False,
            'analyze': False,
            'reindex': False,
            'cleanup': False
        }
        
        try:
            # VACUUM to reclaim space
            result = await self.execute_query("VACUUM", fetch_results=False)
            optimization_results['vacuum'] = result.success
            
            # ANALYZE to update statistics
            result = await self.execute_query("ANALYZE", fetch_results=False)
            optimization_results['analyze'] = result.success
            
            # REINDEX to rebuild indexes
            result = await self.execute_query("REINDEX DATABASE CURRENT", fetch_results=False)
            optimization_results['reindex'] = result.success
            
            # Cleanup old data (example - customize based on needs)
            cleanup_query = """
                DELETE FROM audit_logs 
                WHERE created_at < NOW() - INTERVAL '90 days'
            """
            result = await self.execute_query(cleanup_query, fetch_results=False)
            optimization_results['cleanup'] = result.success
            
            logger.info("Database optimization completed")
            
        except Exception as e:
            logger.error(f"Database optimization failed: {e}")
            optimization_results['error'] = str(e)
            
        return optimization_results
        
    async def monitor_performance(self, duration_seconds: int = 60) -> Dict[str, Any]:
        """
        Monitor database performance for specified duration.
        
        Args:
            duration_seconds: Monitoring duration
            
        Returns:
            Performance monitoring results
        """
        monitoring_results = {
            'start_time': datetime.now().isoformat(),
            'duration_seconds': duration_seconds,
            'snapshots': [],
            'summary': {}
        }
        
        start_time = time.time()
        
        while time.time() - start_time < duration_seconds:
            try:
                stats = await self.get_database_stats()
                
                snapshot = {
                    'timestamp': datetime.now().isoformat(),
                    'active_connections': stats.active_connections,
                    'query_count': stats.query_count,
                    'average_query_time_ms': stats.average_query_time_ms,
                    'slow_queries': stats.slow_query_count,
                    'errors': stats.error_count
                }
                
                monitoring_results['snapshots'].append(snapshot)
                
                # Wait before next snapshot
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Error during performance monitoring: {e}")
                break
                
        # Calculate summary
        if monitoring_results['snapshots']:
            snapshots = monitoring_results['snapshots']
            
            monitoring_results['summary'] = {
                'peak_connections': max(s['active_connections'] for s in snapshots),
                'average_connections': sum(s['active_connections'] for s in snapshots) / len(snapshots),
                'total_queries': sum(s['query_count'] for s in snapshots),
                'average_query_time': sum(s['average_query_time_ms'] for s in snapshots) / len(snapshots),
                'total_slow_queries': sum(s['slow_queries'] for s in snapshots),
                'total_errors': sum(s['errors'] for s in snapshots)
            }
            
        return monitoring_results
        
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get database health status.
        
        Returns:
            Health status information
        """
        health = {
            'status': 'healthy',
            'connected': self._is_connected,
            'pool_size': self.config.pool_size if self._connection_pool else 0,
            'recent_errors': self.error_count,
            'slow_queries': len([
                q for q in self.query_history[-100:]  # Last 100 queries
                if q['execution_time_ms'] > self.slow_query_threshold_ms
            ]),
            'last_query_time': None
        }
        
        if self.query_history:
            health['last_query_time'] = self.query_history[-1]['timestamp']
            
        # Determine overall health status
        if not self._is_connected:
            health['status'] = 'unhealthy'
        elif self.error_count > 10:
            health['status'] = 'degraded'
        elif health['slow_queries'] > 5:
            health['status'] = 'degraded'
            
        return health


# CLI interface for backward compatibility
def main():
    """Command-line interface for database management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Database management tool")
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')
    stats_parser.add_argument('--url', required=True, help='Database URL')
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Execute SQL query')
    query_parser.add_argument('--url', required=True, help='Database URL')
    query_parser.add_argument('--sql', required=True, help='SQL query to execute')
    query_parser.add_argument('--params', help='Query parameters (JSON)')
    
    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Create database backup')
    backup_parser.add_argument('--url', required=True, help='Database URL')
    backup_parser.add_argument('--output', required=True, help='Backup file path')
    backup_parser.add_argument('--format', choices=['sql', 'custom', 'tar'], 
                              default='sql', help='Backup format')
    
    # Migration commands
    migrate_parser = subparsers.add_parser('migrate', help='Run database migrations')
    migrate_parser.add_argument('--url', required=True, help='Database URL')
    migrate_parser.add_argument('--migrations-dir', required=True, help='Migrations directory')
    migrate_parser.add_argument('--target', default='head', help='Target revision')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor database performance')
    monitor_parser.add_argument('--url', required=True, help='Database URL')
    monitor_parser.add_argument('--duration', type=int, default=60, 
                               help='Monitoring duration in seconds')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    async def run_command():
        config = DatabaseConfig(url=args.url)
        db_manager = DatabaseManager(config)
        
        try:
            await db_manager.initialize()
            
            if args.command == 'stats':
                stats = await db_manager.get_database_stats()
                print(f"Database Statistics:")
                print(f"  Connections: {stats.active_connections}/{stats.connection_count}")
                print(f"  Queries: {stats.query_count}")
                print(f"  Average query time: {stats.average_query_time_ms:.2f}ms")
                print(f"  Slow queries: {stats.slow_query_count}")
                print(f"  Errors: {stats.error_count}")
                print(f"  Database size: {stats.database_size_mb:.2f}MB")
                print(f"  Tables: {stats.table_count}")
                print(f"  Indexes: {stats.index_count}")
                
            elif args.command == 'query':
                params = None
                if args.params:
                    params = tuple(json.loads(args.params))
                    
                result = await db_manager.execute_query(args.sql, params)
                
                if result.success:
                    print(f"Query executed successfully in {result.execution_time_ms:.2f}ms")
                    print(f"Rows returned: {result.row_count}")
                    
                    if result.rows and result.row_count <= 10:
                        print("\nResults:")\n                        for row in result.rows:\n                            print(f"  {row}")\n                else:\n                    print(f"Query failed: {result.error}")\n\n            elif args.command == 'backup':\n                success = await db_manager.backup_database(\n                    Path(args.output),\n                    args.format\n                )\n\n                if success:\n                    print(f"✅ Backup created: {args.output}")\n                else:\n                    print(f"❌ Backup failed")\n\n            elif args.command == 'migrate':\n                db_manager.setup_migrations(Path(args.migrations_dir))\n\n                results = await db_manager.run_migrations(args.target)\n\n                for result in results:\n                    status = "✅" if result.success else "❌"\n                    print(f"{status} {result.migration_id}: {result.description}")\n                    if not result.success:\n                        print(f"    Error: {result.error}")\n\n            elif args.command == 'monitor':\n                print(f"📊 Monitoring database for {args.duration} seconds...")\n\n                results = await db_manager.monitor_performance(args.duration)\n\n                print(f"\nMonitoring Results:")\n                print(f"  Duration: {results['duration_seconds']}s")\n                print(f"  Snapshots: {len(results['snapshots'])}")\n\n                if 'summary' in results:\n                    summary = results['summary']\n                    print(f"  Peak connections: {summary['peak_connections']}")\n                    print(f"  Average connections: {summary['average_connections']:.1f}")\n                    print(f"  Total queries: {summary['total_queries']}")\n                    print(f"  Average query time: {summary['average_query_time']:.2f}ms")\n                    print(f"  Slow queries: {summary['total_slow_queries']}")\n                    print(f"  Errors: {summary['total_errors']}")\n\n            else:\n                parser.print_help()\n\n        finally:\n            await db_manager.close()\n\n    # Run the async command\n    asyncio.run(run_command())\n\n\nif __name__ == "__main__":\n    main()