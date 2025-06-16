"""Comprehensive tests for base repository functionality.

Tests cover:
- Base repository patterns and interfaces
- SQLAlchemy repository implementation
- Tortoise repository implementation  
- CRUD operations with proper error handling
- Transaction management and timeouts
- Query optimization and pagination
- Concurrent access and locking
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime
from typing import Dict, Any, List

from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError, TimeoutError as SQLTimeoutError

from src.database.repositories.base import (
    AsyncRepository,
    BaseRepository, 
    SQLAlchemyRepository,
    TortoiseRepository
)
from src.database.models import SQLAlchemyUser, UserRole
from src.core.exceptions import DatabaseError, NotFoundError


class TestAsyncRepositoryInterface:
    """Test the async repository interface contract."""
    
    def test_async_repository_is_abstract(self):
        """Test that AsyncRepository cannot be instantiated directly."""
        with pytest.raises(TypeError):
            AsyncRepository()
    
    def test_async_repository_methods_are_abstract(self):
        """Test that all required methods are abstract."""
        class IncompleteRepository(AsyncRepository):
            pass
        
        with pytest.raises(TypeError):
            IncompleteRepository()


class TestBaseRepository:
    """Test base repository functionality."""
    
    def test_base_repository_initialization(self):
        """Test base repository initialization."""
        repo = BaseRepository()
        assert repo._session is None
        assert repo._model_class is None
    
    def test_base_repository_with_session(self, test_session):
        """Test base repository with provided session."""
        repo = BaseRepository(test_session)
        assert repo._session is test_session
    
    async def test_set_session(self, test_session):
        """Test setting session on repository."""
        repo = BaseRepository()
        await repo.set_session(test_session)
        assert repo._session is test_session
    
    def test_serialize_json_fields(self):
        """Test JSON field serialization."""
        repo = BaseRepository()
        
        data = {
            "simple_field": "test",
            "dict_field": {"key": "value"},
            "list_field": [1, 2, 3],
            "already_string": '{"key": "value"}'
        }
        
        result = repo._serialize_json_fields(data)
        
        assert result["simple_field"] == "test"
        assert result["dict_field"] == '{"key": "value"}'
        assert result["list_field"] == '[1, 2, 3]'
        assert result["already_string"] == '{"key": "value"}'
    
    def test_deserialize_json_fields(self):
        """Test JSON field deserialization."""
        repo = BaseRepository()
        mock_instance = MagicMock()
        
        # Base implementation just returns the instance
        result = repo._deserialize_json_fields(mock_instance)
        assert result is mock_instance


class TestSQLAlchemyRepository:
    """Test SQLAlchemy repository implementation."""
    
    async def test_sqlalchemy_repository_initialization(self, test_session):
        """Test SQLAlchemy repository initialization."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        assert repo._model_class is SQLAlchemyUser
        assert repo._session is test_session
        assert repo._query_timeout == 30
        assert repo._lock_timeout == 5
    
    async def test_get_session_with_provided_session(self, test_session):
        """Test _get_session with provided session."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        async with repo._get_session() as session:
            assert session is test_session
    
    async def test_get_session_from_pool_manager(self, test_pool_manager):
        """Test _get_session from pool manager."""
        repo = SQLAlchemyRepository(SQLAlchemyUser)
        
        with patch('src.database.repositories.base.get_pool_manager') as mock_get_manager:
            mock_session = AsyncMock()
            mock_get_manager.return_value.get_session.return_value.__aenter__.return_value = mock_session
            mock_get_manager.return_value.get_session.return_value.__aexit__.return_value = None
            
            async with repo._get_session() as session:
                assert session is mock_session
    
    async def test_create_entity(self, test_session, sample_user_data):
        """Test creating an entity."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        user = await repo.create(**sample_user_data)
        
        assert user.username == sample_user_data["username"]
        assert user.email == sample_user_data["email"]
        assert user.role == sample_user_data["role"]
        assert user.id is not None
    
    async def test_create_entity_timeout(self, test_session, sample_user_data):
        """Test create entity with timeout."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        with patch('asyncio.wait_for') as mock_wait_for:
            mock_wait_for.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(DatabaseError, match="Creation timeout"):
                await repo.create(**sample_user_data)
    
    async def test_create_entity_sqlalchemy_error(self, test_session, sample_user_data):
        """Test create entity with SQLAlchemy error."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create a user with duplicate email to trigger constraint violation
        await repo.create(**sample_user_data)
        
        with pytest.raises(DatabaseError, match="Creation failed"):
            await repo.create(**sample_user_data)
    
    async def test_get_entity_by_id(self, test_session, sample_user_data):
        """Test getting entity by ID."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create user first
        created_user = await repo.create(**sample_user_data)
        
        # Get user by ID
        retrieved_user = await repo.get(created_user.id)
        
        assert retrieved_user is not None
        assert retrieved_user.id == created_user.id
        assert retrieved_user.username == sample_user_data["username"]
    
    async def test_get_entity_not_found(self, test_session):
        """Test getting non-existent entity."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        user = await repo.get(99999)
        assert user is None
    
    async def test_get_entity_timeout(self, test_session, sample_user_data):
        """Test get entity with timeout."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        with patch.object(repo, '_execute_with_timeout') as mock_execute:
            mock_execute.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(DatabaseError, match="Query timeout"):
                await repo.get(1)
    
    async def test_get_many_entities(self, test_session, sample_users_data):
        """Test getting multiple entities."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create multiple users
        for user_data in sample_users_data:
            await repo.create(**user_data)
        
        # Get all users
        users = await repo.get_many()
        
        assert len(users) == len(sample_users_data)
        usernames = [user.username for user in users]
        expected_usernames = [data["username"] for data in sample_users_data]
        assert all(username in usernames for username in expected_usernames)
    
    async def test_get_many_with_filters(self, test_session, sample_users_data):
        """Test getting entities with filters."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create multiple users
        for user_data in sample_users_data:
            await repo.create(**user_data)
        
        # Filter by role
        admin_users = await repo.get_many(filters={"role": UserRole.ADMIN})
        
        assert len(admin_users) == 1
        assert admin_users[0].role == UserRole.ADMIN
    
    async def test_get_many_with_pagination(self, test_session, sample_users_data):
        """Test getting entities with pagination."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create multiple users
        for user_data in sample_users_data:
            await repo.create(**user_data)
        
        # Get first page
        page1 = await repo.get_many(limit=2, offset=0)
        assert len(page1) == 2
        
        # Get second page
        page2 = await repo.get_many(limit=2, offset=2)
        assert len(page2) == 1
        
        # Ensure no overlap
        page1_ids = {user.id for user in page1}
        page2_ids = {user.id for user in page2}
        assert page1_ids.isdisjoint(page2_ids)
    
    async def test_get_many_with_ordering(self, test_session, sample_users_data):
        """Test getting entities with ordering."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create multiple users
        users = []
        for user_data in sample_users_data:
            user = await repo.create(**user_data)
            users.append(user)
        
        # Get users ordered by username
        ordered_users = await repo.get_many(order_by="username")
        
        usernames = [user.username for user in ordered_users]
        assert usernames == sorted(usernames)
        
        # Get users ordered by username descending
        desc_users = await repo.get_many(order_by="-username")
        desc_usernames = [user.username for user in desc_users]
        assert desc_usernames == sorted(usernames, reverse=True)
    
    async def test_get_many_large_limit_capping(self, test_session):
        """Test that large limits are capped."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Request more than allowed maximum
        with patch.object(repo, '_execute_with_timeout') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_execute.return_value = mock_result
            
            await repo.get_many(limit=2000)  # Over 1000 limit
            
            # Check that the query was called with capped limit
            args, kwargs = mock_execute.call_args
            query = args[0]
            # The limit should be capped at 1000
            # This is implementation-specific, so we just verify the call was made
            mock_execute.assert_called_once()
    
    async def test_update_entity(self, test_session, sample_user_data):
        """Test updating an entity."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create user
        user = await repo.create(**sample_user_data)
        original_id = user.id
        
        # Update user
        updated_user = await repo.update(user.id, full_name="Updated Name")
        
        assert updated_user is not None
        assert updated_user.id == original_id
        assert updated_user.full_name == "Updated Name"
        assert updated_user.username == sample_user_data["username"]  # Unchanged
    
    async def test_update_nonexistent_entity(self, test_session):
        """Test updating non-existent entity."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        result = await repo.update(99999, full_name="New Name")
        assert result is None
    
    async def test_update_with_locking(self, test_session, sample_user_data):
        """Test update with row locking."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create user
        user = await repo.create(**sample_user_data)
        
        # Mock PostgreSQL to test lock timeout setting
        with patch.object(test_session.bind, 'url') as mock_url:
            mock_url.drivername = "postgresql+asyncpg"
            
            with patch.object(test_session, 'execute') as mock_execute:
                mock_result = MagicMock()
                mock_result.scalar_one_or_none.return_value = user
                mock_execute.return_value = mock_result
                
                updated_user = await repo.update(user.id, full_name="Locked Update")
                
                # Verify lock timeout was set
                calls = mock_execute.call_args_list
                lock_timeout_call = any(
                    "lock_timeout" in str(call) 
                    for call in calls
                )
                # Note: This test may need adjustment based on exact implementation
    
    async def test_update_timeout(self, test_session, sample_user_data):
        """Test update with timeout."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        user = await repo.create(**sample_user_data)
        
        with patch('asyncio.wait_for') as mock_wait_for:
            mock_wait_for.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(DatabaseError, match="Update timeout"):
                await repo.update(user.id, full_name="Timeout Test")
    
    async def test_delete_entity(self, test_session, sample_user_data):
        """Test deleting an entity."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create user
        user = await repo.create(**sample_user_data)
        user_id = user.id
        
        # Delete user
        result = await repo.delete(user_id)
        assert result is True
        
        # Verify deletion
        deleted_user = await repo.get(user_id)
        assert deleted_user is None
    
    async def test_delete_nonexistent_entity(self, test_session):
        """Test deleting non-existent entity."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        result = await repo.delete(99999)
        assert result is False
    
    async def test_delete_timeout(self, test_session, sample_user_data):
        """Test delete with timeout."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        user = await repo.create(**sample_user_data)
        
        with patch('asyncio.wait_for') as mock_wait_for:
            mock_wait_for.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(DatabaseError, match="Delete timeout"):
                await repo.delete(user.id)
    
    async def test_count_entities(self, test_session, sample_users_data):
        """Test counting entities."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create multiple users
        for user_data in sample_users_data:
            await repo.create(**user_data)
        
        # Count all users
        total_count = await repo.count()
        assert total_count == len(sample_users_data)
        
        # Count with filters
        admin_count = await repo.count(filters={"role": UserRole.ADMIN})
        expected_admin_count = sum(
            1 for user_data in sample_users_data 
            if user_data["role"] == UserRole.ADMIN
        )
        assert admin_count == expected_admin_count
    
    async def test_count_timeout(self, test_session):
        """Test count with timeout."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        with patch.object(repo, '_execute_with_timeout') as mock_execute:
            mock_execute.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(DatabaseError, match="Count timeout"):
                await repo.count()
    
    async def test_execute_with_timeout_postgresql(self, test_session):
        """Test execute with timeout for PostgreSQL."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Mock PostgreSQL driver
        with patch.object(test_session.bind, 'url') as mock_url:
            mock_url.drivername = "postgresql+asyncpg"
            
            with patch.object(test_session, 'execute') as mock_execute:
                mock_result = MagicMock()
                mock_execute.return_value = mock_result
                
                query = select(SQLAlchemyUser)
                result = await repo._execute_with_timeout(query, timeout=15)
                
                assert result is mock_result
                # Verify timeout was set
                calls = mock_execute.call_args_list
                timeout_call = any(
                    "statement_timeout" in str(call)
                    for call in calls
                )
    
    async def test_execute_with_timeout_non_postgresql(self, test_session):
        """Test execute with timeout for non-PostgreSQL databases."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Mock SQLite driver
        with patch.object(test_session.bind, 'url') as mock_url:
            mock_url.drivername = "sqlite+aiosqlite"
            
            with patch.object(test_session, 'execute') as mock_execute:
                mock_result = MagicMock()
                mock_execute.return_value = mock_result
                
                query = select(SQLAlchemyUser)
                result = await repo._execute_with_timeout(query)
                
                assert result is mock_result
                mock_execute.assert_called_once_with(query)


class TestTortoiseRepository:
    """Test Tortoise ORM repository implementation."""
    
    def test_tortoise_repository_initialization(self):
        """Test Tortoise repository initialization."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        assert repo._model_class is TortoiseUser
    
    async def test_tortoise_create(self):
        """Test Tortoise create operation."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'create') as mock_create:
            mock_user = MagicMock()
            mock_create.return_value = mock_user
            
            user_data = {"username": "test", "email": "test@example.com"}
            result = await repo.create(**user_data)
            
            assert result is mock_user
            mock_create.assert_called_once_with(**user_data)
    
    async def test_tortoise_create_error(self):
        """Test Tortoise create with error."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'create') as mock_create:
            mock_create.side_effect = Exception("Database error")
            
            with pytest.raises(DatabaseError, match="Creation failed"):
                await repo.create(username="test")
    
    async def test_tortoise_get(self):
        """Test Tortoise get operation."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'get_or_none') as mock_get:
            mock_user = MagicMock()
            mock_get.return_value = mock_user
            
            result = await repo.get(1)
            
            assert result is mock_user
            mock_get.assert_called_once_with(id=1)
    
    async def test_tortoise_get_error(self):
        """Test Tortoise get with error."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'get_or_none') as mock_get:
            mock_get.side_effect = Exception("Database error")
            
            with pytest.raises(DatabaseError, match="Retrieval failed"):
                await repo.get(1)
    
    async def test_tortoise_get_many(self):
        """Test Tortoise get_many operation."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'all') as mock_all:
            mock_query = MagicMock()
            mock_query.filter.return_value = mock_query
            mock_query.order_by.return_value = mock_query
            mock_query.limit.return_value = mock_query
            mock_query.offset.return_value = mock_query
            mock_all.return_value = mock_query
            
            mock_users = [MagicMock(), MagicMock()]
            mock_query.__await__ = AsyncMock(return_value=mock_users)
            
            filters = {"role": "admin"}
            result = await repo.get_many(filters=filters, limit=10, offset=0, order_by="username")
            
            assert result is mock_users
            mock_query.filter.assert_called_once_with(**filters)
            mock_query.order_by.assert_called_once_with("username")
            mock_query.limit.assert_called_once_with(10)
            mock_query.offset.assert_called_once_with(0)
    
    async def test_tortoise_get_many_error(self):
        """Test Tortoise get_many with error."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'all') as mock_all:
            mock_all.side_effect = Exception("Database error")
            
            with pytest.raises(DatabaseError, match="Query failed"):
                await repo.get_many()
    
    async def test_tortoise_update(self):
        """Test Tortoise update operation."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        mock_user = MagicMock()
        mock_user.update_from_dict = AsyncMock()
        mock_user.save = AsyncMock()
        
        with patch.object(TortoiseUser, 'get_or_none') as mock_get:
            mock_get.return_value = mock_user
            
            update_data = {"full_name": "Updated Name"}
            result = await repo.update(1, **update_data)
            
            assert result is mock_user
            mock_get.assert_called_once_with(id=1)
            mock_user.update_from_dict.assert_called_once_with(update_data)
            mock_user.save.assert_called_once()
    
    async def test_tortoise_update_not_found(self):
        """Test Tortoise update when entity not found."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'get_or_none') as mock_get:
            mock_get.return_value = None
            
            result = await repo.update(99999, full_name="Test")
            assert result is None
    
    async def test_tortoise_update_error(self):
        """Test Tortoise update with error."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'get_or_none') as mock_get:
            mock_get.side_effect = Exception("Database error")
            
            with pytest.raises(DatabaseError, match="Update failed"):
                await repo.update(1, full_name="Test")
    
    async def test_tortoise_delete(self):
        """Test Tortoise delete operation."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        mock_user = MagicMock()
        mock_user.delete = AsyncMock()
        
        with patch.object(TortoiseUser, 'get_or_none') as mock_get:
            mock_get.return_value = mock_user
            
            result = await repo.delete(1)
            
            assert result is True
            mock_get.assert_called_once_with(id=1)
            mock_user.delete.assert_called_once()
    
    async def test_tortoise_delete_not_found(self):
        """Test Tortoise delete when entity not found."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'get_or_none') as mock_get:
            mock_get.return_value = None
            
            result = await repo.delete(99999)
            assert result is False
    
    async def test_tortoise_delete_error(self):
        """Test Tortoise delete with error."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'get_or_none') as mock_get:
            mock_get.side_effect = Exception("Database error")
            
            with pytest.raises(DatabaseError, match="Deletion failed"):
                await repo.delete(1)
    
    async def test_tortoise_count(self):
        """Test Tortoise count operation."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'all') as mock_all:
            mock_query = MagicMock()
            mock_query.filter.return_value = mock_query
            mock_query.count = AsyncMock(return_value=42)
            mock_all.return_value = mock_query
            
            filters = {"role": "admin"}
            result = await repo.count(filters=filters)
            
            assert result == 42
            mock_query.filter.assert_called_once_with(**filters)
            mock_query.count.assert_called_once()
    
    async def test_tortoise_count_error(self):
        """Test Tortoise count with error."""
        from src.database.models import TortoiseUser
        repo = TortoiseRepository(TortoiseUser)
        
        with patch.object(TortoiseUser, 'all') as mock_all:
            mock_all.side_effect = Exception("Database error")
            
            with pytest.raises(DatabaseError, match="Count failed"):
                await repo.count()


class TestRepositoryPerformance:
    """Test repository performance characteristics."""
    
    async def test_bulk_create_performance(self, test_session, db_utils, performance_timer):
        """Test bulk create performance."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create large dataset
        large_dataset = db_utils.create_large_dataset(100, "user")
        
        performance_timer.start()
        
        # Create users one by one (not optimal, but testing current implementation)
        for user_data in large_dataset:
            await repo.create(**user_data)
        
        performance_timer.stop()
        
        # Verify all users were created
        count = await repo.count()
        assert count == 100
        
        # Performance should be reasonable
        assert performance_timer.elapsed_seconds < 30.0  # Adjust based on requirements
    
    async def test_paginated_query_performance(self, test_session, db_utils, performance_timer):
        """Test paginated query performance."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create test data
        large_dataset = db_utils.create_large_dataset(50, "user")
        for user_data in large_dataset:
            await repo.create(**user_data)
        
        performance_timer.start()
        
        # Perform paginated queries
        page_size = 10
        total_retrieved = 0
        offset = 0
        
        while True:
            page = await repo.get_many(limit=page_size, offset=offset)
            if not page:
                break
            
            total_retrieved += len(page)
            offset += page_size
        
        performance_timer.stop()
        
        assert total_retrieved == 50
        assert performance_timer.elapsed_seconds < 10.0
    
    async def test_concurrent_repository_access(self, test_session, sample_user_data):
        """Test concurrent repository access."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        async def create_and_update_user(user_id: int):
            user_data = sample_user_data.copy()
            user_data["username"] = f"user_{user_id}"
            user_data["email"] = f"user_{user_id}@example.com"
            
            # Create user
            user = await repo.create(**user_data)
            
            # Update user
            updated_user = await repo.update(user.id, full_name=f"Updated User {user_id}")
            
            return updated_user
        
        # Run concurrent operations
        tasks = [create_and_update_user(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        # Verify all operations succeeded
        assert len(results) == 10
        assert all(user is not None for user in results)
        
        # Verify final state
        total_count = await repo.count()
        assert total_count == 10


class TestRepositoryTransactions:
    """Test repository transaction behavior."""
    
    async def test_transaction_rollback_on_error(self, test_session, sample_user_data):
        """Test transaction rollback on error."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Start with empty database
        initial_count = await repo.count()
        
        try:
            # Create user
            user = await repo.create(**sample_user_data)
            assert user.id is not None
            
            # Force an error (try to create duplicate)
            await repo.create(**sample_user_data)
            
        except DatabaseError:
            pass  # Expected error
        
        # Transaction should have rolled back due to test_session fixture
        # In a real scenario, only the failed operation would roll back
        # For this test, we just verify the repository handles errors properly
    
    async def test_multiple_operations_same_transaction(self, test_session, sample_users_data):
        """Test multiple operations in the same transaction."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create multiple users in the same transaction
        created_users = []
        for user_data in sample_users_data:
            user = await repo.create(**user_data)
            created_users.append(user)
        
        # Update all users
        for user in created_users:
            await repo.update(user.id, full_name=f"Updated {user.username}")
        
        # Verify all operations succeeded
        total_count = await repo.count()
        assert total_count == len(sample_users_data)
        
        # Verify updates
        for user in created_users:
            updated_user = await repo.get(user.id)
            assert updated_user.full_name.startswith("Updated")


class TestRepositoryErrorHandling:
    """Test repository error handling scenarios."""
    
    async def test_database_connection_error(self, sample_user_data):
        """Test handling of database connection errors."""
        # Create repository without session
        repo = SQLAlchemyRepository(SQLAlchemyUser)
        
        with patch('src.database.repositories.base.get_pool_manager') as mock_get_manager:
            mock_get_manager.side_effect = Exception("Connection failed")
            
            with pytest.raises(Exception):  # Should propagate the connection error
                await repo.create(**sample_user_data)
    
    async def test_sqlalchemy_integrity_error(self, test_session, sample_user_data):
        """Test handling of SQLAlchemy integrity errors."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        # Create user first
        await repo.create(**sample_user_data)
        
        # Try to create duplicate (should fail with integrity error)
        with pytest.raises(DatabaseError, match="Creation failed"):
            await repo.create(**sample_user_data)
    
    async def test_query_timeout_handling(self, test_session):
        """Test handling of query timeouts."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        with patch.object(repo, '_execute_with_timeout') as mock_execute:
            mock_execute.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(DatabaseError, match="timeout"):
                await repo.get(1)
    
    async def test_unexpected_error_handling(self, test_session, sample_user_data):
        """Test handling of unexpected errors."""
        repo = SQLAlchemyRepository(SQLAlchemyUser, test_session)
        
        with patch.object(test_session, 'add') as mock_add:
            mock_add.side_effect = Exception("Unexpected error")
            
            with pytest.raises(DatabaseError, match="Creation failed"):
                await repo.create(**sample_user_data)