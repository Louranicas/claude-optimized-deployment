"""
SQL Injection Prevention Tests

Tests for SQL injection vulnerabilities following OWASP guidelines.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from typing import List, Dict, Any
import re

from src.database.repositories.base import BaseRepository
from src.database.repositories.user_repository import UserRepository
from src.database.repositories.query_repository import QueryRepository
from src.core.exceptions import SecurityError, ValidationError


class TestSQLInjectionPrevention:
    """Test suite for SQL injection prevention."""
    
    @pytest.fixture
    async def user_repo(self):
        """Create UserRepository instance for testing."""
        repo = UserRepository()
        await repo.initialize()
        return repo
    
    @pytest.fixture
    async def query_repo(self):
        """Create QueryRepository instance for testing."""
        repo = QueryRepository()
        await repo.initialize()
        return repo
    
    @pytest.mark.asyncio
    async def test_classic_sql_injection_attempts(self, user_repo):
        """Test classic SQL injection attempts in user queries."""
        sql_injection_payloads = [
            "admin' OR '1'='1",
            "admin'--",
            "admin' OR 1=1--",
            "admin' OR 'a'='a",
            "admin'; DROP TABLE users;--",
            "admin' UNION SELECT * FROM users--",
            "admin' UNION SELECT NULL, NULL, NULL--",
            "admin' AND 1=0 UNION SELECT * FROM passwords--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND LENGTH(password)>5)--",
            "admin' AND ASCII(SUBSTRING(password,1,1))>65--"
        ]
        
        for payload in sql_injection_payloads:
            # Should either sanitize or raise error
            result = await user_repo.get_by_username(payload)
            assert result is None  # No user found with injection attempt
    
    @pytest.mark.asyncio
    async def test_blind_sql_injection_attempts(self, user_repo):
        """Test blind SQL injection attempts."""
        blind_injection_payloads = [
            {
                "username": "admin' AND SLEEP(5)--",
                "detection": "time_based"
            },
            {
                "username": "admin' AND IF(1=1, SLEEP(5), 0)--",
                "detection": "conditional_time"
            },
            {
                "username": "admin' AND (SELECT COUNT(*) FROM users) > 0--",
                "detection": "boolean_based"
            },
            {
                "username": "admin' AND EXISTS(SELECT * FROM information_schema.tables)--",
                "detection": "error_based"
            }
        ]
        
        import time
        for payload in blind_injection_payloads:
            start_time = time.time()
            result = await user_repo.get_by_username(payload["username"])
            elapsed = time.time() - start_time
            
            # Should not take longer than 1 second (no SLEEP execution)
            assert elapsed < 1.0
            assert result is None
    
    @pytest.mark.asyncio
    async def test_second_order_injection(self, user_repo):
        """Test second-order SQL injection prevention."""
        # First, try to insert malicious data
        malicious_data = {
            "username": "test_user",
            "email": "test@example.com",
            "first_name": "admin'--",
            "last_name": "'; DROP TABLE users;--"
        }
        
        # Create user with potentially malicious data
        user = await user_repo.create(malicious_data)
        
        # Now try to use this data in another query
        # Should be properly escaped when used
        search_result = await user_repo.search_by_name(user.first_name)
        
        # Should find the user without executing injection
        assert len(search_result) >= 1
        assert search_result[0].first_name == malicious_data["first_name"]
    
    @pytest.mark.asyncio
    async def test_numeric_field_injection(self, query_repo):
        """Test SQL injection in numeric fields."""
        numeric_injection_attempts = [
            "1 OR 1=1",
            "1; DROP TABLE queries;",
            "1 UNION SELECT * FROM users",
            "1 AND (SELECT COUNT(*) FROM users) > 0",
            "-1 UNION SELECT 1,2,3,4,5",
            "9999999999 OR 1=1"
        ]
        
        for payload in numeric_injection_attempts:
            # Should validate numeric input
            with pytest.raises((ValueError, ValidationError)):
                await query_repo.get_by_id(payload)
    
    @pytest.mark.asyncio
    async def test_like_operator_injection(self, user_repo):
        """Test SQL injection in LIKE queries."""
        like_injection_attempts = [
            "%' OR '1'='1",
            "%'; DROP TABLE users;--",
            "_' OR '1'='1",
            "[^a]' OR '1'='1"
        ]
        
        for payload in like_injection_attempts:
            result = await user_repo.search_users(payload)
            # Should escape special characters in LIKE
            assert isinstance(result, list)
            # Should not return all users
            assert len(result) == 0
    
    @pytest.mark.asyncio
    async def test_order_by_injection(self, user_repo):
        """Test SQL injection in ORDER BY clauses."""
        order_injection_attempts = [
            "username; DROP TABLE users;--",
            "(SELECT * FROM users)",
            "1, (SELECT password FROM users LIMIT 1)",
            "CASE WHEN (1=1) THEN username ELSE password END"
        ]
        
        for payload in order_injection_attempts:
            # Should validate ORDER BY input
            with pytest.raises((ValueError, SecurityError)):
                await user_repo.get_all_ordered(order_by=payload)
    
    @pytest.mark.asyncio
    async def test_insert_statement_injection(self, user_repo):
        """Test SQL injection in INSERT statements."""
        insert_injection_attempts = [
            {
                "username": "test'); DROP TABLE users;--",
                "email": "test@test.com",
                "password": "password"
            },
            {
                "username": "test",
                "email": "test@test.com'); DELETE FROM users;--",
                "password": "password"
            },
            {
                "username": "test",
                "email": "test@test.com",
                "password": "pass'); INSERT INTO users (username, role) VALUES ('hacker', 'admin');--"
            }
        ]
        
        for payload in insert_injection_attempts:
            # Should use parameterized queries
            user = await user_repo.create(payload)
            
            # Verify data was inserted safely
            assert user.username == payload["username"]
            assert user.email == payload["email"]
            
            # Verify no additional operations were performed
            all_users = await user_repo.get_all()
            assert all(u.role != 'admin' or u.username != 'hacker' for u in all_users)
    
    @pytest.mark.asyncio
    async def test_update_statement_injection(self, user_repo):
        """Test SQL injection in UPDATE statements."""
        # Create a test user first
        user = await user_repo.create({
            "username": "testuser",
            "email": "test@test.com",
            "password": "password"
        })
        
        update_injection_attempts = [
            {
                "email": "newemail@test.com' WHERE username='admin' OR '1'='1"
            },
            {
                "email": "newemail@test.com'; UPDATE users SET role='admin' WHERE username='testuser';--"
            }
        ]
        
        for payload in update_injection_attempts:
            # Should use parameterized queries
            await user_repo.update(user.id, payload)
            
            # Verify only intended user was updated
            updated_user = await user_repo.get_by_id(user.id)
            assert updated_user.email == payload["email"]
            
            # Verify no other users were affected
            admin_user = await user_repo.get_by_username("admin")
            if admin_user:
                assert admin_user.email != payload["email"]
    
    @pytest.mark.asyncio
    async def test_stored_procedure_injection(self, user_repo):
        """Test SQL injection in stored procedure calls."""
        stored_proc_injections = [
            "exec('DROP TABLE users')",
            "'); EXEC xp_cmdshell('net user hacker password /add');--",
            "'; EXEC sp_configure 'show advanced options', 1;--"
        ]
        
        for payload in stored_proc_injections:
            with pytest.raises((SecurityError, ValueError)):
                await user_repo.call_stored_procedure("get_user_stats", payload)
    
    @pytest.mark.asyncio
    async def test_column_name_injection(self, user_repo):
        """Test SQL injection through column names."""
        column_injection_attempts = [
            "username FROM users UNION SELECT password",
            "username; DROP TABLE users;--",
            "* FROM users WHERE 1=1--"
        ]
        
        for payload in column_injection_attempts:
            with pytest.raises((SecurityError, ValueError)):
                await user_repo.get_by_column(payload, "testvalue")
    
    @pytest.mark.asyncio
    async def test_multi_query_injection(self, user_repo):
        """Test prevention of multi-query execution."""
        multi_query_attempts = [
            "admin'; INSERT INTO users (username, role) VALUES ('hacker', 'admin'); SELECT '",
            "admin'; UPDATE users SET role='admin' WHERE username='hacker'; SELECT '"
        ]
        
        for payload in multi_query_attempts:
            result = await user_repo.get_by_username(payload)
            assert result is None
            
            # Verify no additional queries were executed
            hacker_user = await user_repo.get_by_username("hacker")
            assert hacker_user is None
    
    @pytest.mark.asyncio
    async def test_hex_encoding_bypass(self, user_repo):
        """Test hex encoding bypass attempts."""
        hex_payloads = [
            "0x61646d696e27204f522027313d31",  # "admin' OR '1=1" in hex
            "CHAR(97,100,109,105,110,39,32,79,82,32,39,49,61,49)"  # Same using CHAR
        ]
        
        for payload in hex_payloads:
            result = await user_repo.get_by_username(payload)
            assert result is None
    
    @pytest.mark.asyncio
    async def test_comment_syntax_injection(self, user_repo):
        """Test various SQL comment syntax injections."""
        comment_injections = [
            "admin'/*comment*/OR/*comment*/'1'='1",
            "admin'--comment\nOR '1'='1",
            "admin'#comment\nOR '1'='1",
            "admin'/**/OR/**/1=1"
        ]
        
        for payload in comment_injections:
            result = await user_repo.get_by_username(payload)
            assert result is None
    
    @pytest.mark.asyncio
    async def test_unicode_bypass_attempts(self, user_repo):
        """Test Unicode-based SQL injection bypass."""
        unicode_payloads = [
            "admin'%00OR%001=1",  # Null byte
            "admin'%0aOR%0a'1'='1",  # Line feed
            "admin'%0dOR%0d'1'='1",  # Carriage return
            "admin'\\u0027OR\\u00271=1"  # Unicode apostrophe
        ]
        
        for payload in unicode_payloads:
            result = await user_repo.get_by_username(payload)
            assert result is None
    
    @pytest.mark.asyncio
    async def test_parameterized_query_verification(self):
        """Verify that all queries use parameterized statements."""
        # Mock the database execution
        with patch('tortoise.models.Model.filter') as mock_filter:
            mock_filter.return_value.first.return_value = None
            
            repo = UserRepository()
            await repo.get_by_username("test_user")
            
            # Verify parameterized query was used
            mock_filter.assert_called_once()
            # Should use kwargs, not string formatting
            call_kwargs = mock_filter.call_args[1]
            assert "username" in call_kwargs
            assert call_kwargs["username"] == "test_user"
    
    def test_sql_pattern_detection(self):
        """Test SQL injection pattern detection."""
        from src.core.validation import detect_sql_injection_patterns
        
        malicious_inputs = [
            "' OR '1'='1",
            "'; DROP TABLE users;--",
            "' UNION SELECT * FROM users--",
            "admin' AND 1=1--"
        ]
        
        for input_str in malicious_inputs:
            assert detect_sql_injection_patterns(input_str) is True
        
        # Clean inputs should pass
        clean_inputs = [
            "john.doe@example.com",
            "user123",
            "Test User's Name"  # Apostrophe in legitimate context
        ]
        
        for input_str in clean_inputs:
            assert detect_sql_injection_patterns(input_str) is False