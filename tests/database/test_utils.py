"""Comprehensive tests for database utilities.

Tests cover:
- Database backup and restore operations
- Database optimization and maintenance
- Data archiving and cleanup
- Security validation and SQL injection prevention
- Performance analysis and indexing
- Utility functions and helpers
"""

import pytest
import asyncio
import tempfile
import os
import json
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
from pathlib import Path

from src.database.utils import (
    DatabaseBackup,
    DatabaseRestore,
    DatabaseOptimizer,
    DatabaseArchiver,
    validate_identifier,
    validate_table_name,
    validate_column_name,
    build_safe_query,
    safe_query_by_id,
    ALLOWED_TABLES,
    ALLOWED_COLUMNS
)
from src.core.exceptions import DatabaseError


class TestSecurityValidation:
    """Test security validation functions."""
    
    def test_validate_identifier_valid(self):
        """Test validation of valid identifiers."""
        # Valid table names
        assert validate_identifier("users", ALLOWED_TABLES, "table name") == "users"
        assert validate_identifier("audit_logs", ALLOWED_TABLES, "table name") == "audit_logs"
        
        # Valid column names
        assert validate_identifier("id", ALLOWED_COLUMNS, "column name") == "id"
        assert validate_identifier("created_at", ALLOWED_COLUMNS, "column name") == "created_at"
    
    def test_validate_identifier_invalid_characters(self):
        """Test validation rejects invalid characters."""
        # SQL injection attempts
        with pytest.raises(DatabaseError, match="Invalid.*Only alphanumeric"):
            validate_identifier("users; DROP TABLE", ALLOWED_TABLES, "table name")
        
        with pytest.raises(DatabaseError, match="Invalid.*Only alphanumeric"):
            validate_identifier("id' OR '1'='1", ALLOWED_COLUMNS, "column name")
        
        # Special characters
        with pytest.raises(DatabaseError, match="Invalid.*Only alphanumeric"):
            validate_identifier("user$table", ALLOWED_TABLES, "table name")
        
        with pytest.raises(DatabaseError, match="Invalid.*Only alphanumeric"):
            validate_identifier("column-name", ALLOWED_COLUMNS, "column name")
    
    def test_validate_identifier_not_in_allowlist(self):
        """Test validation rejects identifiers not in allowlist."""
        with pytest.raises(DatabaseError, match="Unauthorized table name"):
            validate_identifier("malicious_table", ALLOWED_TABLES, "table name")
        
        with pytest.raises(DatabaseError, match="Unauthorized column name"):
            validate_identifier("secret_column", ALLOWED_COLUMNS, "column name")
    
    def test_validate_identifier_empty(self):
        """Test validation rejects empty identifiers."""
        with pytest.raises(DatabaseError, match="Empty.*not allowed"):
            validate_identifier("", ALLOWED_TABLES, "table name")
        
        with pytest.raises(DatabaseError, match="Empty.*not allowed"):
            validate_identifier("", ALLOWED_COLUMNS, "column name")
    
    def test_validate_table_name(self):
        """Test table name validation wrapper."""
        assert validate_table_name("users") == "users"
        
        with pytest.raises(DatabaseError, match="Unauthorized table name"):
            validate_table_name("invalid_table")
    
    def test_validate_column_name(self):
        """Test column name validation wrapper."""
        assert validate_column_name("id") == "id"
        
        with pytest.raises(DatabaseError, match="Unauthorized column name"):
            validate_column_name("invalid_column")
    
    def test_build_safe_query(self):
        """Test safe query building."""
        # Basic query
        query = build_safe_query("SELECT * FROM users WHERE id = :user_id", user_id=123)
        assert str(query) == "SELECT * FROM users WHERE id = :user_id"
        
        # Complex query
        query = build_safe_query(
            "SELECT * FROM users WHERE name = :name AND age > :min_age",
            name="John",
            min_age=18
        )
        assert str(query) == "SELECT * FROM users WHERE name = :name AND age > :min_age"
    
    async def test_safe_query_by_id(self, test_connection):
        """Test safe query by ID function."""
        # This test requires a test connection with actual data
        # For now, we'll mock the connection
        with patch('src.database.utils.get_database_connection') as mock_get_conn:
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_row = MagicMock()
            mock_row._mapping = {"id": 1, "name": "test"}
            mock_result.fetchone.return_value = mock_row
            mock_session.execute.return_value = mock_result
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            
            mock_conn = MagicMock()
            mock_conn.get_session.return_value = mock_session
            mock_get_conn.return_value = mock_conn
            
            result = await safe_query_by_id("users", 1)
            
            assert result == {"id": 1, "name": "test"}
            mock_session.execute.assert_called_once()
    
    async def test_safe_query_by_id_invalid_table(self):
        """Test safe query with invalid table name."""
        with pytest.raises(DatabaseError, match="Unauthorized table name"):
            await safe_query_by_id("malicious_table", 1)
    
    async def test_safe_query_by_id_not_found(self, test_connection):
        """Test safe query when record not found."""
        with patch('src.database.utils.get_database_connection') as mock_get_conn:
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.fetchone.return_value = None
            mock_session.execute.return_value = mock_result
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            
            mock_conn = MagicMock()
            mock_conn.get_session.return_value = mock_session
            mock_get_conn.return_value = mock_conn
            
            result = await safe_query_by_id("users", 99999)
            
            assert result == {}


class TestDatabaseBackup:
    """Test database backup functionality."""
    
    def test_backup_initialization(self):
        """Test backup manager initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup = DatabaseBackup(temp_dir)
            assert backup.backup_dir == Path(temp_dir)
            assert backup.backup_dir.exists()
    
    def test_backup_default_directory(self):
        """Test backup manager with default directory."""
        backup = DatabaseBackup()
        assert backup.backup_dir == Path("./backups")
    
    async def test_backup_postgresql_success(self):
        """Test successful PostgreSQL backup."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup = DatabaseBackup(temp_dir)
            connection_string = "postgresql://user:pass@localhost:5432/testdb"
            
            # Mock subprocess.run to simulate successful pg_dump
            with patch('src.database.utils.subprocess.run') as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stderr = ""
                
                backup_file = await backup.backup_postgresql(connection_string)
                
                assert backup_file.startswith(temp_dir)
                assert "postgres_backup_" in backup_file
                assert backup_file.endswith(".sql")
                
                # Verify pg_dump was called with correct arguments
                mock_run.assert_called_once()
                call_args = mock_run.call_args[0][0]
                assert "pg_dump" in call_args
                assert "-h" in call_args
                assert "localhost" in call_args
                assert "-p" in call_args
                assert "5432" in call_args
                assert "-U" in call_args
                assert "user" in call_args
                assert "-d" in call_args
                assert "testdb" in call_args
    
    async def test_backup_postgresql_failure(self):
        """Test PostgreSQL backup failure handling."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup = DatabaseBackup(temp_dir)
            connection_string = "postgresql://user:pass@localhost:5432/testdb"
            
            # Mock subprocess.run to simulate failed pg_dump
            with patch('src.database.utils.subprocess.run') as mock_run:
                mock_run.return_value.returncode = 1
                mock_run.return_value.stderr = "pg_dump: error: database not found"
                
                with pytest.raises(DatabaseError, match="pg_dump failed"):
                    await backup.backup_postgresql(connection_string)
    
    async def test_backup_postgresql_with_password(self):
        """Test PostgreSQL backup with password in environment."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup = DatabaseBackup(temp_dir)
            connection_string = "postgresql://user:secret@localhost:5432/testdb"
            
            with patch('src.database.utils.subprocess.run') as mock_run:
                mock_run.return_value.returncode = 0
                
                await backup.backup_postgresql(connection_string)
                
                # Verify password was set in environment
                call_kwargs = mock_run.call_args[1]
                assert "env" in call_kwargs
                assert "PGPASSWORD" in call_kwargs["env"]
                assert call_kwargs["env"]["PGPASSWORD"] == "secret"
    
    async def test_backup_sqlite_success(self):
        """Test successful SQLite backup."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup = DatabaseBackup(temp_dir)
            
            with patch('src.database.utils.get_database_connection') as mock_get_conn:
                mock_engine = MagicMock()
                mock_connection = AsyncMock()
                mock_engine.begin.return_value.__aenter__ = AsyncMock(return_value=mock_connection)
                mock_engine.begin.return_value.__aexit__ = AsyncMock(return_value=None)
                
                mock_conn = MagicMock()
                mock_conn._engine = mock_engine
                mock_get_conn.return_value = mock_conn
                
                backup_file = await backup.backup_sqlite("/path/to/test.db")
                
                assert backup_file.startswith(temp_dir)
                assert "sqlite_backup_" in backup_file
                assert backup_file.endswith(".db")
                
                # Verify VACUUM INTO was called
                mock_connection.execute.assert_called_once()
    
    async def test_backup_sqlite_path_traversal_prevention(self):
        """Test SQLite backup prevents path traversal attacks."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup = DatabaseBackup(temp_dir)
            
            # Mock connection but test should fail before reaching it
            with patch('src.database.utils.get_database_connection'):
                # Simulate path traversal attempt by manipulating backup_dir
                backup.backup_dir = Path("/tmp/safe_backup")
                
                # Mock the backup file path to be outside the backup directory
                with patch.object(backup, 'backup_dir') as mock_backup_dir:
                    mock_backup_dir.__truediv__ = lambda self, other: Path("/../../../etc/passwd")
                    
                    with pytest.raises(DatabaseError, match="Invalid backup file path"):
                        await backup.backup_sqlite("/path/to/test.db")
    
    async def test_backup_to_json_success(self):
        """Test successful JSON backup."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup = DatabaseBackup(temp_dir)
            tables = ["users", "audit_logs"]
            
            with patch('src.database.utils.get_database_connection') as mock_get_conn:
                mock_session = AsyncMock()
                mock_result = MagicMock()
                
                # Mock query results for each table
                mock_rows = [
                    MagicMock(_mapping={"id": 1, "name": "user1"}),
                    MagicMock(_mapping={"id": 2, "name": "user2"})
                ]
                mock_result.__iter__ = lambda self: iter(mock_rows)
                mock_session.execute.return_value = mock_result
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=None)
                
                mock_conn = MagicMock()
                mock_conn.get_session.return_value = mock_session
                mock_get_conn.return_value = mock_conn
                
                backup_file = await backup.backup_to_json(tables)
                
                assert backup_file.startswith(temp_dir)
                assert "json_backup_" in backup_file
                assert backup_file.endswith(".json")
                
                # Verify file was created and contains expected data
                assert Path(backup_file).exists()
                with open(backup_file, 'r') as f:
                    data = json.load(f)
                
                assert "timestamp" in data
                assert "tables" in data
                assert "users" in data["tables"]
                assert "audit_logs" in data["tables"]
    
    async def test_backup_to_json_invalid_table(self):
        """Test JSON backup with invalid table name."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup = DatabaseBackup(temp_dir)
            
            with pytest.raises(DatabaseError, match="Unauthorized table name"):
                await backup.backup_to_json(["invalid_table"])


class TestDatabaseRestore:
    """Test database restore functionality."""
    
    async def test_restore_postgresql_success(self):
        """Test successful PostgreSQL restore."""
        restore = DatabaseRestore()
        backup_file = "/path/to/backup.sql"
        connection_string = "postgresql://user:pass@localhost:5432/testdb"
        
        with patch('src.database.utils.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            
            await restore.restore_postgresql(backup_file, connection_string)
            
            # Verify psql was called with correct arguments
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "psql" in call_args
            assert "-h" in call_args
            assert "localhost" in call_args
            assert "-f" in call_args
            assert backup_file in call_args
    
    async def test_restore_postgresql_failure(self):
        """Test PostgreSQL restore failure handling."""
        restore = DatabaseRestore()
        backup_file = "/path/to/backup.sql"
        connection_string = "postgresql://user:pass@localhost:5432/testdb"
        
        with patch('src.database.utils.subprocess.run') as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "psql: error: connection failed"
            
            with pytest.raises(DatabaseError, match="psql restore failed"):
                await restore.restore_postgresql(backup_file, connection_string)
    
    async def test_restore_from_json_success(self):
        """Test successful JSON restore."""
        restore = DatabaseRestore()
        
        # Create test backup data
        backup_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "tables": {
                "users": [
                    {"id": 1, "username": "user1", "email": "user1@example.com"},
                    {"id": 2, "username": "user2", "email": "user2@example.com"}
                ],
                "audit_logs": [
                    {"id": 1, "action": "create", "user_id": 1}
                ]
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(backup_data, f)
            backup_file = f.name
        
        try:
            with patch('src.database.utils.get_database_connection') as mock_get_conn:
                mock_session = AsyncMock()
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=None)
                
                mock_conn = MagicMock()
                mock_conn.get_session.return_value = mock_session
                mock_get_conn.return_value = mock_conn
                
                restored_counts = await restore.restore_from_json(backup_file)
                
                assert "users" in restored_counts
                assert "audit_logs" in restored_counts
                assert restored_counts["users"] == 2
                assert restored_counts["audit_logs"] == 1
                
                # Verify correct number of execute calls
                assert mock_session.execute.call_count == 3  # 2 users + 1 audit log
                assert mock_session.commit.call_count == 2   # Once per table
        finally:
            os.unlink(backup_file)
    
    async def test_restore_from_json_invalid_table(self):
        """Test JSON restore with invalid table name."""
        restore = DatabaseRestore()
        
        backup_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "tables": {
                "invalid_table": [{"id": 1, "data": "test"}]
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(backup_data, f)
            backup_file = f.name
        
        try:
            with pytest.raises(DatabaseError, match="Unauthorized table name"):
                await restore.restore_from_json(backup_file)
        finally:
            os.unlink(backup_file)
    
    async def test_restore_from_json_invalid_column(self):
        """Test JSON restore with invalid column name."""
        restore = DatabaseRestore()
        
        backup_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "tables": {
                "users": [{"id": 1, "invalid_column": "test"}]
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(backup_data, f)
            backup_file = f.name
        
        try:
            with pytest.raises(DatabaseError, match="Unauthorized column name"):
                await restore.restore_from_json(backup_file)
        finally:
            os.unlink(backup_file)


class TestDatabaseOptimizer:
    """Test database optimization functionality."""
    
    async def test_analyze_postgresql_success(self):
        """Test successful PostgreSQL analysis."""
        optimizer = DatabaseOptimizer()
        
        with patch('src.database.utils.get_database_connection') as mock_get_conn:
            mock_session = AsyncMock()
            
            # Mock results for different queries
            mock_results = {
                "table_sizes": [
                    MagicMock(_mapping={
                        "schemaname": "public",
                        "tablename": "users",
                        "size": "1024 KB",
                        "row_count": 1000
                    })
                ],
                "index_usage": [
                    MagicMock(_mapping={
                        "schemaname": "public",
                        "tablename": "users",
                        "indexname": "users_pkey",
                        "idx_scan": 500,
                        "idx_tup_read": 1000,
                        "idx_tup_fetch": 800
                    })
                ],
                "slow_queries": [
                    MagicMock(_mapping={
                        "query": "SELECT * FROM users WHERE name LIKE '%test%'",
                        "calls": 100,
                        "total_time": 5000.0,
                        "mean_time": 50.0,
                        "min_time": 10.0,
                        "max_time": 200.0
                    })
                ]
            }
            
            def mock_execute(query):
                query_str = str(query)
                if "pg_stat_user_tables" in query_str:
                    result = MagicMock()
                    result.__iter__ = lambda self: iter(mock_results["table_sizes"])
                    return result
                elif "pg_stat_user_indexes" in query_str:
                    result = MagicMock()
                    result.__iter__ = lambda self: iter(mock_results["index_usage"])
                    return result
                elif "pg_stat_statements" in query_str:
                    result = MagicMock()
                    result.__iter__ = lambda self: iter(mock_results["slow_queries"])
                    return result
                else:
                    return MagicMock()
            
            mock_session.execute.side_effect = mock_execute
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            
            mock_conn = MagicMock()
            mock_conn.get_session.return_value = mock_session
            mock_get_conn.return_value = mock_conn
            
            results = await optimizer.analyze_postgresql()
            
            assert "table_sizes" in results
            assert "index_usage" in results
            assert "slow_queries" in results
            
            assert len(results["table_sizes"]) == 1
            assert results["table_sizes"][0]["tablename"] == "users"
            
            assert len(results["index_usage"]) == 1
            assert results["index_usage"][0]["indexname"] == "users_pkey"
            
            assert len(results["slow_queries"]) == 1
    
    async def test_analyze_postgresql_no_pg_stat_statements(self):
        """Test PostgreSQL analysis when pg_stat_statements is not available."""
        optimizer = DatabaseOptimizer()
        
        with patch('src.database.utils.get_database_connection') as mock_get_conn:
            mock_session = AsyncMock()
            
            def mock_execute(query):
                query_str = str(query)
                if "pg_stat_statements" in query_str:
                    raise Exception("relation pg_stat_statements does not exist")
                else:
                    result = MagicMock()
                    result.__iter__ = lambda self: iter([])
                    return result
            
            mock_session.execute.side_effect = mock_execute
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            
            mock_conn = MagicMock()
            mock_conn.get_session.return_value = mock_session
            mock_get_conn.return_value = mock_conn
            
            results = await optimizer.analyze_postgresql()
            
            assert "slow_queries" in results
            assert results["slow_queries"] == "pg_stat_statements not available"
    
    async def test_vacuum_analyze_all_tables(self):
        """Test VACUUM ANALYZE on all tables."""
        optimizer = DatabaseOptimizer()
        
        with patch('src.database.utils.get_database_connection') as mock_get_conn:
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            
            mock_conn = MagicMock()
            mock_conn.get_session.return_value = mock_session
            mock_get_conn.return_value = mock_conn
            
            await optimizer.vacuum_analyze()
            
            mock_session.execute.assert_called_once()
            call_args = mock_session.execute.call_args[0][0]
            assert "VACUUM ANALYZE" in str(call_args)
            mock_session.commit.assert_called_once()
    
    async def test_vacuum_analyze_specific_table(self):
        """Test VACUUM ANALYZE on specific table."""
        optimizer = DatabaseOptimizer()
        
        with patch('src.database.utils.get_database_connection') as mock_get_conn:
            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            
            mock_conn = MagicMock()
            mock_conn.get_session.return_value = mock_session
            mock_get_conn.return_value = mock_conn
            
            await optimizer.vacuum_analyze("users")
            
            mock_session.execute.assert_called_once()
            call_args = mock_session.execute.call_args[0][0]
            assert 'VACUUM ANALYZE "users"' in str(call_args)
    
    async def test_vacuum_analyze_invalid_table(self):
        """Test VACUUM ANALYZE with invalid table name."""
        optimizer = DatabaseOptimizer()
        
        with pytest.raises(DatabaseError, match="Unauthorized table name"):
            await optimizer.vacuum_analyze("invalid_table")
    
    async def test_create_missing_indexes(self):
        """Test creating missing indexes suggestions."""
        optimizer = DatabaseOptimizer()
        
        with patch('src.database.utils.get_database_connection') as mock_get_conn:
            mock_session = AsyncMock()
            
            # Mock foreign keys without indexes
            mock_fk_results = [
                MagicMock(table_name="user_profiles", column_name="user_id"),
                MagicMock(table_name="orders", column_name="customer_id")
            ]
            
            mock_result = MagicMock()
            mock_result.__iter__ = lambda self: iter(mock_fk_results)
            mock_session.execute.return_value = mock_result
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)
            
            mock_conn = MagicMock()
            mock_conn.get_session.return_value = mock_session
            mock_get_conn.return_value = mock_conn
            
            suggestions = await optimizer.create_missing_indexes()
            
            assert len(suggestions) == 2
            assert "CREATE INDEX idx_user_profiles_user_id ON user_profiles (user_id)" in suggestions
            assert "CREATE INDEX idx_orders_customer_id ON orders (customer_id)" in suggestions


class TestDatabaseArchiver:
    """Test database archiving functionality."""
    
    def test_archiver_initialization(self):
        """Test archiver initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            archiver = DatabaseArchiver(temp_dir)
            assert archiver.archive_dir == Path(temp_dir)
            assert archiver.archive_dir.exists()
    
    async def test_archive_old_data_success(self):
        """Test successful data archiving."""
        with tempfile.TemporaryDirectory() as temp_dir:
            archiver = DatabaseArchiver(temp_dir)
            
            with patch('src.database.utils.get_database_connection') as mock_get_conn:
                mock_session = AsyncMock()
                
                # Mock old data to be archived
                old_data = [
                    MagicMock(_mapping={"id": 1, "name": "old_record_1", "created_at": "2023-01-01"}),
                    MagicMock(_mapping={"id": 2, "name": "old_record_2", "created_at": "2023-01-02"})
                ]
                
                # Mock execute to return old data for SELECT and rowcount for DELETE
                def mock_execute(query, params=None):
                    query_str = str(query)
                    if query_str.startswith("SELECT"):
                        result = MagicMock()
                        result.__iter__ = lambda self: iter(old_data)
                        return result
                    elif query_str.startswith("DELETE"):
                        result = MagicMock()
                        result.rowcount = 2
                        return result
                    else:
                        return MagicMock()
                
                mock_session.execute.side_effect = mock_execute
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=None)
                
                mock_conn = MagicMock()
                mock_conn.get_session.return_value = mock_session
                mock_get_conn.return_value = mock_conn
                
                result = await archiver.archive_old_data(
                    table_name="audit_logs",
                    date_column="timestamp",
                    days_to_keep=30
                )
                
                assert result["archived_count"] == 2
                assert result["deleted_count"] == 2
                assert "archive_file" in result
                
                # Verify archive file was created
                archive_file = Path(result["archive_file"])
                assert archive_file.exists()
                
                # Verify archive file content
                with open(archive_file, 'r') as f:
                    archive_data = json.load(f)
                
                assert archive_data["table"] == "audit_logs"
                assert len(archive_data["rows"]) == 2
                assert "archived_at" in archive_data
    
    async def test_archive_old_data_no_data(self):
        """Test archiving when no old data exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            archiver = DatabaseArchiver(temp_dir)
            
            with patch('src.database.utils.get_database_connection') as mock_get_conn:
                mock_session = AsyncMock()
                
                # Mock empty result set
                mock_result = MagicMock()
                mock_result.__iter__ = lambda self: iter([])
                mock_session.execute.return_value = mock_result
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=None)
                
                mock_conn = MagicMock()
                mock_conn.get_session.return_value = mock_session
                mock_get_conn.return_value = mock_conn
                
                result = await archiver.archive_old_data(
                    table_name="audit_logs",
                    date_column="timestamp",
                    days_to_keep=30
                )
                
                assert result["archived_count"] == 0
                assert result["message"] == "No data to archive"
    
    async def test_archive_old_data_invalid_table(self):
        """Test archiving with invalid table name."""
        with tempfile.TemporaryDirectory() as temp_dir:
            archiver = DatabaseArchiver(temp_dir)
            
            with pytest.raises(DatabaseError, match="Unauthorized table name"):
                await archiver.archive_old_data(
                    table_name="invalid_table",
                    date_column="timestamp",
                    days_to_keep=30
                )
    
    async def test_archive_old_data_invalid_column(self):
        """Test archiving with invalid column name."""
        with tempfile.TemporaryDirectory() as temp_dir:
            archiver = DatabaseArchiver(temp_dir)
            
            with pytest.raises(DatabaseError, match="Unauthorized column name"):
                await archiver.archive_old_data(
                    table_name="audit_logs",
                    date_column="invalid_column",
                    days_to_keep=30
                )


class TestDatabaseUtilsIntegration:
    """Test database utilities integration scenarios."""
    
    async def test_complete_backup_restore_cycle(self):
        """Test complete backup and restore cycle."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_manager = DatabaseBackup(temp_dir)
            restore_manager = DatabaseRestore()
            
            # Create test data structure
            test_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "tables": {
                    "users": [
                        {"id": 1, "username": "alice", "email": "alice@example.com"},
                        {"id": 2, "username": "bob", "email": "bob@example.com"}
                    ],
                    "audit_logs": [
                        {"id": 1, "action": "login", "user_id": 1, "success": True},
                        {"id": 2, "action": "logout", "user_id": 1, "success": True}
                    ]
                }
            }
            
            # Create backup file
            backup_file = os.path.join(temp_dir, "test_backup.json")
            with open(backup_file, 'w') as f:
                json.dump(test_data, f)
            
            # Mock database connection for restore
            with patch('src.database.utils.get_database_connection') as mock_get_conn:
                mock_session = AsyncMock()
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=None)
                
                mock_conn = MagicMock()
                mock_conn.get_session.return_value = mock_session
                mock_get_conn.return_value = mock_conn
                
                # Perform restore
                restore_counts = await restore_manager.restore_from_json(backup_file)
                
                # Verify restore results
                assert restore_counts["users"] == 2
                assert restore_counts["audit_logs"] == 2
                
                # Verify correct number of database operations
                total_inserts = restore_counts["users"] + restore_counts["audit_logs"]
                assert mock_session.execute.call_count == total_inserts
                assert mock_session.commit.call_count == 2  # Once per table
    
    async def test_maintenance_workflow(self):
        """Test complete database maintenance workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            optimizer = DatabaseOptimizer()
            archiver = DatabaseArchiver(temp_dir)
            
            # Mock database connection
            with patch('src.database.utils.get_database_connection') as mock_get_conn:
                mock_session = AsyncMock()
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock(return_value=None)
                
                # Mock analysis results
                def mock_execute(query, params=None):
                    query_str = str(query)
                    if "pg_stat_user_tables" in query_str:
                        return MagicMock(__iter__=lambda self: iter([
                            MagicMock(_mapping={
                                "schemaname": "public",
                                "tablename": "audit_logs",
                                "size": "10 MB",
                                "row_count": 100000
                            })
                        ]))
                    elif "VACUUM ANALYZE" in query_str:
                        return MagicMock()
                    elif query_str.startswith("SELECT"):
                        # Mock old data for archiving
                        return MagicMock(__iter__=lambda self: iter([
                            MagicMock(_mapping={
                                "id": 1,
                                "action": "old_action",
                                "timestamp": "2023-01-01"
                            })
                        ]))
                    elif query_str.startswith("DELETE"):
                        result = MagicMock()
                        result.rowcount = 1
                        return result
                    else:
                        return MagicMock()
                
                mock_session.execute.side_effect = mock_execute
                
                mock_conn = MagicMock()
                mock_conn.get_session.return_value = mock_session
                mock_get_conn.return_value = mock_conn
                
                # Step 1: Analyze database
                analysis = await optimizer.analyze_postgresql()
                assert "table_sizes" in analysis
                
                # Step 2: Optimize database
                await optimizer.vacuum_analyze("audit_logs")
                
                # Step 3: Archive old data
                archive_result = await archiver.archive_old_data(
                    table_name="audit_logs",
                    date_column="timestamp",
                    days_to_keep=90
                )
                
                assert archive_result["archived_count"] == 1
                assert archive_result["deleted_count"] == 1
    
    async def test_security_validation_integration(self):
        """Test security validation across all utilities."""
        # Test that all utilities properly validate input
        
        # Backup utility
        backup = DatabaseBackup()
        with pytest.raises(DatabaseError):
            await backup.backup_to_json(["malicious_table"])
        
        # Restore utility
        restore = DatabaseRestore()
        malicious_data = {
            "tables": {
                "users; DROP TABLE users; --": [{"id": 1}]
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(malicious_data, f)
            backup_file = f.name
        
        try:
            with pytest.raises(DatabaseError):
                await restore.restore_from_json(backup_file)
        finally:
            os.unlink(backup_file)
        
        # Optimizer utility
        optimizer = DatabaseOptimizer()
        with pytest.raises(DatabaseError):
            await optimizer.vacuum_analyze("malicious_table")
        
        # Archiver utility
        with tempfile.TemporaryDirectory() as temp_dir:
            archiver = DatabaseArchiver(temp_dir)
            
            with pytest.raises(DatabaseError):
                await archiver.archive_old_data("malicious_table", "timestamp", 30)
            
            with pytest.raises(DatabaseError):
                await archiver.archive_old_data("users", "malicious_column", 30)
    
    async def test_error_handling_and_recovery(self):
        """Test error handling and recovery scenarios."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup = DatabaseBackup(temp_dir)
            
            # Test PostgreSQL backup with connection failure
            with patch('src.database.utils.subprocess.run') as mock_run:
                mock_run.side_effect = Exception("Connection failed")
                
                with pytest.raises(DatabaseError):
                    await backup.backup_postgresql("postgresql://invalid")
            
            # Test SQLite backup with database error
            with patch('src.database.utils.get_database_connection') as mock_get_conn:
                mock_get_conn.side_effect = Exception("Database not available")
                
                with pytest.raises(DatabaseError):
                    await backup.backup_sqlite("/invalid/path")
            
            # Test JSON backup with file system error
            with patch('builtins.open', side_effect=PermissionError("Permission denied")):
                with patch('src.database.utils.get_database_connection'):
                    with pytest.raises(DatabaseError):
                        await backup.backup_to_json(["users"])