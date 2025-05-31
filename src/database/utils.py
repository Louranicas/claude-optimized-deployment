"""Database utility functions for backup, restore, and maintenance."""

import os
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import subprocess

from sqlalchemy import text
from tortoise import Tortoise

from src.database.connection import get_database_connection
from src.core.logging_config import get_logger
from src.core.exceptions import DatabaseError

logger = get_logger(__name__)


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
            # Use SQLite backup API via connection
            conn = await get_database_connection()
            
            if conn._engine:
                async with conn._engine.begin() as connection:
                    await connection.execute(
                        text(f"VACUUM main INTO '{backup_file}'")
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
                    # Execute raw SQL to get table data
                    result = await session.execute(
                        text(f"SELECT * FROM {table_name}")
                    )
                    
                    rows = []
                    for row in result:
                        # Convert row to dict
                        rows.append(dict(row._mapping))
                    
                    export_data["tables"][table_name] = rows
            
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
                    count = 0
                    for row_data in rows:
                        # Insert row (this is simplified - real implementation
                        # would need to handle conflicts and data types)
                        columns = ", ".join(row_data.keys())
                        placeholders = ", ".join([f":{k}" for k in row_data.keys()])
                        
                        await session.execute(
                            text(f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"),
                            row_data
                        )
                        count += 1
                    
                    restored_counts[table_name] = count
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
                await session.execute(text(f"VACUUM ANALYZE {table_name}"))
                logger.info(f"VACUUM ANALYZE completed for table: {table_name}")
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
            fk_query = """
            SELECT DISTINCT
                c.conrelid::regclass AS table_name,
                a.attname AS column_name
            FROM pg_constraint c
            JOIN pg_attribute a ON a.attnum = ANY(c.conkey) AND a.attrelid = c.conrelid
            LEFT JOIN pg_index i ON i.indrelid = c.conrelid AND a.attnum = ANY(i.indkey)
            WHERE c.contype = 'f' AND i.indrelid IS NULL
            """
            
            result = await session.execute(text(fk_query))
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
        conn = await get_database_connection()
        archive_file = self.archive_dir / f"{table_name}_archive_{datetime.utcnow().strftime('%Y%m%d')}.json"
        
        async with conn.get_session() as session:
            # Select old data
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
            
            select_query = text(
                f"SELECT * FROM {table_name} WHERE {date_column} < :cutoff_date"
            )
            
            result = await session.execute(select_query, {"cutoff_date": cutoff_date})
            rows_to_archive = [dict(row._mapping) for row in result]
            
            if rows_to_archive:
                # Save to archive file
                with open(archive_file, 'w') as f:
                    json.dump({
                        "table": table_name,
                        "archived_at": datetime.utcnow().isoformat(),
                        "rows": rows_to_archive
                    }, f, indent=2, default=str)
                
                # Delete archived rows
                delete_query = text(
                    f"DELETE FROM {table_name} WHERE {date_column} < :cutoff_date"
                )
                
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