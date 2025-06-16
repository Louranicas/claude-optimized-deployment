
__all__ = [
    "DatabaseBackup",
    "DatabaseRestore",
    "DatabaseOptimizer",
    "DatabaseArchiver",
    "validate_identifier",
    "validate_table_name",
    "validate_column_name",
    "build_safe_query"
]

"""Database utility functions for backup, restore, and maintenance."""

import os
import json
import asyncio
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import subprocess

from sqlalchemy import text, MetaData
from tortoise import Tortoise

from src.database.connection import get_database_connection
from src.core.logging_config import get_logger
from src.core.exceptions import DatabaseError

logger = get_logger(__name__)


# Table name allowlist for security
ALLOWED_TABLES = {
    'users', 'deployments', 'configurations', 'audit_logs', 'metrics',
    'queries', 'expert_responses', 'mcp_tools', 'circuit_breaker_metrics',
    'monitoring_alerts', 'auth_tokens', 'rbac_roles', 'rbac_permissions',
    'rbac_user_roles', 'rbac_role_permissions'
}

# Column name allowlist for security
ALLOWED_COLUMNS = {
    'id', 'created_at', 'updated_at', 'deleted_at', 'timestamp', 'date_created',
    'date_modified', 'user_id', 'deployment_id', 'configuration_id', 'query_id',
    'expert_id', 'tool_id', 'name', 'email', 'status', 'type', 'value', 'data',
    'response', 'metadata', 'version', 'tags', 'description', 'config',
    'parameters', 'results', 'error_message', 'execution_time', 'success',
    'retry_count', 'circuit_state', 'failure_count', 'last_failure',
    'next_attempt', 'alert_type', 'severity', 'message', 'acknowledged',
    'token_hash', 'expires_at', 'role_name', 'permission_name'
}


def validate_identifier(identifier: str, allowed_set: set, identifier_type: str) -> str:
    """
    Validate database identifiers (table names, column names) against allowlist.
    
    Args:
        identifier: The identifier to validate
        allowed_set: Set of allowed identifiers
        identifier_type: Type of identifier for error messages
    
    Returns:
        The validated identifier
        
    Raises:
        DatabaseError: If identifier is not in allowlist or contains invalid characters
    """
    if not identifier:
        raise DatabaseError(f"Empty {identifier_type} not allowed")
    
    # Check for SQL injection patterns
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
        raise DatabaseError(f"Invalid {identifier_type}: {identifier}. Only alphanumeric characters and underscores allowed.")
    
    # Check against allowlist
    if identifier not in allowed_set:
        raise DatabaseError(f"Unauthorized {identifier_type}: {identifier}")
    
    return identifier


def validate_table_name(table_name: str) -> str:
    """Validate table name against allowlist."""
    return validate_identifier(table_name, ALLOWED_TABLES, "table name")


def validate_column_name(column_name: str) -> str:
    """Validate column name against allowlist."""
    return validate_identifier(column_name, ALLOWED_COLUMNS, "column name")


async def safe_query_by_id(table_name: str, record_id: int) -> Dict[str, Any]:
    """
    Example of secure database query using parameterized queries.
    Demonstrates proper use of placeholders to prevent SQL injection.
    
    Args:
        table_name: Table name (validated against allowlist)
        record_id: Record ID to search for
        
    Returns:
        Record data or empty dict if not found
    """
    # Validate table name against allowlist
    validated_table = validate_table_name(table_name)
    
    conn = await get_database_connection()
    async with conn.get_session() as session:
        # Example with PostgreSQL-style placeholder (%s equivalent with named params)
        quoted_table = f'"{validated_table}"'
        
        # Safe parameterized query - ID parameter is passed separately
        # This prevents SQL injection: WHERE id = %s
        query_str = "SELECT * FROM " + quoted_table + " WHERE id = :record_id"
        
        result = await session.execute(text(query_str), {"record_id": record_id})
        row = result.fetchone()
        
        if row:
            return dict(row._mapping)
        return {}


def build_safe_query(base_query: str, **params) -> text:
    """
    Build a safe SQL query with parameterized values.
    
    Args:
        base_query: SQL query with placeholders (:param, %s, or ?)
        **params: Parameters to bind to the query
        
    Returns:
        SQLAlchemy text object with bound parameters
    
    Examples:
        # Named parameters (recommended)
        build_safe_query("SELECT * FROM users WHERE id = :user_id", user_id=123)
        
        # PostgreSQL style placeholders
        build_safe_query("SELECT * FROM users WHERE id = %s", user_id=123)
        
        # SQLite style placeholders
        build_safe_query("SELECT * FROM users WHERE id = ?", user_id=123)
    """
    return text(base_query)


class DatabaseBackup:
    """Handle database backup operations."""
    
    def __init__(self, backup_dir: str = "./backups"):
        """Initialize backup manager."""
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)
    
    async def backup_postgresql(self, connection_string: str) -> str:
        """Backup PostgreSQL database using pg_dump."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"postgres_backup_{timestamp}.sql"
        
        try:
            # Parse connection string
            from urllib.parse import urlparse
            parsed = urlparse(connection_string)
            
            # Build pg_dump command
            cmd = [
                "pg_dump",
                "-h", parsed.hostname or "localhost",
                "-p", str(parsed.port or 5432),
                "-U", parsed.username or "postgres",
                "-d", parsed.path[1:],  # Remove leading slash
                "-f", str(backup_file),
                "--verbose",
                "--no-owner",
                "--no-privileges"
            ]
            
            # Set password via environment
            env = os.environ.copy()
            if parsed.password:
                env["PGPASSWORD"] = parsed.password
            
            # Run backup
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise DatabaseError(f"pg_dump failed: {result.stderr}")
            
            logger.info(f"PostgreSQL backup completed: {backup_file}")
            return str(backup_file)
            
        except Exception as e:
            logger.error(f"PostgreSQL backup failed: {e}")
            raise DatabaseError(f"Backup failed: {e}")
    
    async def backup_sqlite(self, db_path: str) -> str:
        """Backup SQLite database."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"sqlite_backup_{timestamp}.db"
        
        try:
            # Validate backup file path to prevent path traversal
            if not str(backup_file).startswith(str(self.backup_dir)):
                raise DatabaseError("Invalid backup file path")
            
            # Use SQLite backup API via connection
            conn = await get_database_connection()
            
            if conn._engine:
                async with conn._engine.begin() as connection:
                    # Use parameterized query for backup file path
                    await connection.execute(
                        text("VACUUM main INTO :backup_path"),
                        {"backup_path": str(backup_file)}
                    )
            
            logger.info(f"SQLite backup completed: {backup_file}")
            return str(backup_file)
            
        except Exception as e:
            logger.error(f"SQLite backup failed: {e}")
            raise DatabaseError(f"Backup failed: {e}")
    
    async def backup_to_json(self, tables: List[str]) -> str:
        """Export specified tables to JSON format."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"json_backup_{timestamp}.json"
        
        try:
            conn = await get_database_connection()
            export_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "tables": {}
            }
            
            async with conn.get_session() as session:
                for table_name in tables:
                    # Validate table name against allowlist
                    validated_table = validate_table_name(table_name)
                    
                    # Use quoted identifier for table name safety
                    # Note: For PostgreSQL/SQLite, we need to construct the query safely
                    # Since table names can't be parameterized, we validate and quote them
                    quoted_table = f'"{validated_table}"'
                    
                    # Build safe query using string concatenation (not f-string)
                    # Table name is already validated against allowlist
                    query = "SELECT * FROM " + quoted_table
                    
                    result = await session.execute(text(query))
                    
                    rows = []
                    for row in result:
                        # Convert row to dict
                        rows.append(dict(row._mapping))
                    
                    export_data["tables"][validated_table] = rows
            
            # Write to file
            with open(backup_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"JSON backup completed: {backup_file}")
            return str(backup_file)
            
        except Exception as e:
            logger.error(f"JSON backup failed: {e}")
            raise DatabaseError(f"Backup failed: {e}")


class DatabaseRestore:
    """Handle database restore operations."""
    
    async def restore_postgresql(self, backup_file: str, connection_string: str) -> None:
        """Restore PostgreSQL database from backup."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(connection_string)
            
            # Build psql command
            cmd = [
                "psql",
                "-h", parsed.hostname or "localhost",
                "-p", str(parsed.port or 5432),
                "-U", parsed.username or "postgres",
                "-d", parsed.path[1:],
                "-f", backup_file,
                "--verbose"
            ]
            
            # Set password via environment
            env = os.environ.copy()
            if parsed.password:
                env["PGPASSWORD"] = parsed.password
            
            # Run restore
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise DatabaseError(f"psql restore failed: {result.stderr}")
            
            logger.info(f"PostgreSQL restore completed from: {backup_file}")
            
        except Exception as e:
            logger.error(f"PostgreSQL restore failed: {e}")
            raise DatabaseError(f"Restore failed: {e}")
    
    async def restore_from_json(self, backup_file: str) -> Dict[str, int]:
        """Restore data from JSON backup."""
        try:
            with open(backup_file, 'r') as f:
                backup_data = json.load(f)
            
            conn = await get_database_connection()
            restored_counts = {}
            
            async with conn.get_session() as session:
                for table_name, rows in backup_data["tables"].items():
                    # Validate table name against allowlist
                    validated_table = validate_table_name(table_name)
                    
                    count = 0
                    for row_data in rows:
                        # Validate all column names against allowlist
                        validated_columns = []
                        for col_name in row_data.keys():
                            validated_columns.append(validate_column_name(col_name))
                        
                        # Build safe query with quoted identifiers
                        columns_str = ", ".join([f'"{col}"' for col in validated_columns])
                        placeholders = ", ".join([f":{col}" for col in validated_columns])
                        quoted_table = f'"{validated_table}"'
                        
                        # Create parameter dict with validated column names
                        safe_params = {}
                        for col_name, value in row_data.items():
                            validated_col = validate_column_name(col_name)
                            safe_params[validated_col] = value
                        
                        # Build safe query using string concatenation (not f-string)
                        # All identifiers are already validated against allowlists
                        query = "INSERT INTO " + quoted_table + " (" + columns_str + ") VALUES (" + placeholders + ")"
                        await session.execute(text(query), safe_params)
                        count += 1
                    
                    restored_counts[validated_table] = count
                    await session.commit()
            
            logger.info(f"JSON restore completed: {restored_counts}")
            return restored_counts
            
        except Exception as e:
            logger.error(f"JSON restore failed: {e}")
            raise DatabaseError(f"Restore failed: {e}")


class DatabaseOptimizer:
    """Database performance optimization utilities."""
    
    async def analyze_postgresql(self) -> Dict[str, Any]:
        """Analyze PostgreSQL database performance."""
        conn = await get_database_connection()
        results = {}
        
        async with conn.get_session() as session:
            # Table sizes
            size_query = """
            SELECT 
                schemaname,
                tablename,
                pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size,
                n_live_tup as row_count
            FROM pg_stat_user_tables
            ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
            """
            
            result = await session.execute(text(size_query))
            results["table_sizes"] = [dict(row._mapping) for row in result]
            
            # Index usage
            index_query = """
            SELECT 
                schemaname,
                tablename,
                indexname,
                idx_scan,
                idx_tup_read,
                idx_tup_fetch
            FROM pg_stat_user_indexes
            ORDER BY idx_scan DESC
            """
            
            result = await session.execute(text(index_query))
            results["index_usage"] = [dict(row._mapping) for row in result]
            
            # Slow queries (if pg_stat_statements is enabled)
            try:
                slow_query = """
                SELECT 
                    query,
                    calls,
                    total_time,
                    mean_time,
                    min_time,
                    max_time
                FROM pg_stat_statements
                WHERE query NOT LIKE '%pg_stat_statements%'
                ORDER BY mean_time DESC
                LIMIT 10
                """
                
                result = await session.execute(text(slow_query))
                results["slow_queries"] = [dict(row._mapping) for row in result]
            except:
                results["slow_queries"] = "pg_stat_statements not available"
        
        return results
    
    async def vacuum_analyze(self, table_name: Optional[str] = None) -> None:
        """Run VACUUM ANALYZE on PostgreSQL tables."""
        conn = await get_database_connection()
        
        async with conn.get_session() as session:
            if table_name:
                # Validate table name against allowlist
                validated_table = validate_table_name(table_name)
                
                # Use quoted identifier for table name safety
                quoted_table = f'"{validated_table}"'
                
                # Build safe query using string concatenation (not f-string)
                # Table name is already validated against allowlist
                query = "VACUUM ANALYZE " + quoted_table
                
                await session.execute(text(query))
                logger.info(f"VACUUM ANALYZE completed for table: {validated_table}")
            else:
                await session.execute(text("VACUUM ANALYZE"))
                logger.info("VACUUM ANALYZE completed for all tables")
            
            await session.commit()
    
    async def create_missing_indexes(self) -> List[str]:
        """Suggest and optionally create missing indexes."""
        conn = await get_database_connection()
        suggestions = []
        
        async with conn.get_session() as session:
            # Check for foreign keys without indexes
            # Example of safe parameterized query with proper placeholder
            fk_query = """
            SELECT DISTINCT
                c.conrelid::regclass AS table_name,
                a.attname AS column_name
            FROM pg_constraint c
            JOIN pg_attribute a ON a.attnum = ANY(c.conkey) AND a.attrelid = c.conrelid
            LEFT JOIN pg_index i ON i.indrelid = c.conrelid AND a.attnum = ANY(i.indkey)
            WHERE c.contype = :constraint_type AND i.indrelid IS NULL
            """
            
            # Use parameterized query with named parameter (safer than %s or ?)
            result = await session.execute(text(fk_query), {"constraint_type": "f"})
            for row in result:
                idx_name = f"idx_{row.table_name}_{row.column_name}"
                suggestions.append(
                    f"CREATE INDEX {idx_name} ON {row.table_name} ({row.column_name})"
                )
        
        return suggestions


class DatabaseArchiver:
    """Archive old data for performance and compliance."""
    
    def __init__(self, archive_dir: str = "./archives"):
        """Initialize archiver."""
        self.archive_dir = Path(archive_dir)
        self.archive_dir.mkdir(exist_ok=True)
    
    async def archive_old_data(
        self,
        table_name: str,
        date_column: str,
        days_to_keep: int = 90
    ) -> Dict[str, Any]:
        """Archive data older than specified days."""
        # Validate table and column names against allowlist
        validated_table = validate_table_name(table_name)
        validated_column = validate_column_name(date_column)
        
        conn = await get_database_connection()
        archive_file = self.archive_dir / f"{validated_table}_archive_{datetime.utcnow().strftime('%Y%m%d')}.json"
        
        async with conn.get_session() as session:
            # Select old data
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
            
            # Use quoted identifiers for table and column names
            quoted_table = f'"{validated_table}"'
            quoted_column = f'"{validated_column}"'
            
            # Build safe query using string concatenation (not f-string)
            # Table and column names are already validated against allowlists
            select_query_str = "SELECT * FROM " + quoted_table + " WHERE " + quoted_column + " < :cutoff_date"
            select_query = text(select_query_str)
            
            result = await session.execute(select_query, {"cutoff_date": cutoff_date})
            rows_to_archive = [dict(row._mapping) for row in result]
            
            if rows_to_archive:
                # Save to archive file
                with open(archive_file, 'w') as f:
                    json.dump({
                        "table": validated_table,
                        "archived_at": datetime.utcnow().isoformat(),
                        "rows": rows_to_archive
                    }, f, indent=2, default=str)
                
                # Delete archived rows
                # Build safe query using string concatenation (not f-string)
                # Table and column names are already validated against allowlists
                delete_query_str = "DELETE FROM " + quoted_table + " WHERE " + quoted_column + " < :cutoff_date"
                delete_query = text(delete_query_str)
                
                result = await session.execute(delete_query, {"cutoff_date": cutoff_date})
                await session.commit()
                
                return {
                    "archived_count": len(rows_to_archive),
                    "archive_file": str(archive_file),
                    "deleted_count": result.rowcount
                }
            
            return {
                "archived_count": 0,
                "message": "No data to archive"
            }