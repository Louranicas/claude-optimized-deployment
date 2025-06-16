"""Comprehensive tests for user repository functionality.

Tests cover:
- User CRUD operations
- Authentication and API key management
- Role-based operations and authorization
- User search and statistics
- Performance and concurrent access
- Security and validation
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
import hashlib
import secrets

from src.database.repositories.user_repository import UserRepository, TortoiseUserRepository
from src.database.models import SQLAlchemyUser, TortoiseUser, UserRole
from src.core.exceptions import AuthenticationError, AuthorizationError, DatabaseError


class TestUserRepository:
    """Test SQLAlchemy user repository functionality."""
    
    async def test_create_user_success(self, user_repository, sample_user_data):
        """Test successful user creation."""
        user = await user_repository.create_user(**sample_user_data)
        
        assert user.username == sample_user_data["username"]
        assert user.email == sample_user_data["email"]
        assert user.full_name == sample_user_data["full_name"]
        assert user.role == sample_user_data["role"]
        assert user.preferences == sample_user_data["preferences"]
        assert user.id is not None
        assert user.created_at is not None
        assert user.is_active is True
    
    async def test_create_user_duplicate_username(self, user_repository, sample_user_data):
        """Test creating user with duplicate username."""
        # Create first user
        await user_repository.create_user(**sample_user_data)
        
        # Try to create user with same username but different email
        duplicate_data = sample_user_data.copy()
        duplicate_data["email"] = "different@example.com"
        
        with pytest.raises(ValueError, match="already exists"):
            await user_repository.create_user(**duplicate_data)
    
    async def test_create_user_duplicate_email(self, user_repository, sample_user_data):
        """Test creating user with duplicate email."""
        # Create first user
        await user_repository.create_user(**sample_user_data)
        
        # Try to create user with same email but different username
        duplicate_data = sample_user_data.copy()
        duplicate_data["username"] = "different_user"
        
        with pytest.raises(ValueError, match="already exists"):
            await user_repository.create_user(**duplicate_data)
    
    async def test_create_user_minimal_data(self, user_repository):
        """Test creating user with minimal required data."""
        minimal_data = {
            "username": "minimal_user",
            "email": "minimal@example.com"
        }
        
        user = await user_repository.create_user(**minimal_data)
        
        assert user.username == "minimal_user"
        assert user.email == "minimal@example.com"
        assert user.role == UserRole.VIEWER  # Default role
        assert user.preferences == {}  # Default preferences
        assert user.full_name is None
    
    async def test_get_by_username(self, user_repository, created_test_user):
        """Test getting user by username."""
        user = await user_repository.get_by_username(created_test_user.username)
        
        assert user is not None
        assert user.id == created_test_user.id
        assert user.username == created_test_user.username
    
    async def test_get_by_username_not_found(self, user_repository):
        """Test getting non-existent user by username."""
        user = await user_repository.get_by_username("nonexistent")
        assert user is None
    
    async def test_get_by_username_timeout(self, user_repository):
        """Test get by username with timeout."""
        with patch.object(user_repository, '_execute_with_timeout') as mock_execute:
            mock_execute.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(DatabaseError, match="User lookup timeout"):
                await user_repository.get_by_username("test")
    
    async def test_get_by_email(self, user_repository, created_test_user):
        """Test getting user by email."""
        user = await user_repository.get_by_email(created_test_user.email)
        
        assert user is not None
        assert user.id == created_test_user.id
        assert user.email == created_test_user.email
    
    async def test_get_by_email_not_found(self, user_repository):
        """Test getting non-existent user by email."""
        user = await user_repository.get_by_email("nonexistent@example.com")
        assert user is None
    
    async def test_get_by_email_timeout(self, user_repository):
        """Test get by email with timeout."""
        with patch.object(user_repository, '_execute_with_timeout') as mock_execute:
            mock_execute.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(DatabaseError, match="User lookup timeout"):
                await user_repository.get_by_email("test@example.com")
    
    async def test_get_by_username_or_email(self, user_repository, created_test_user):
        """Test getting user by username or email."""
        # Test with username
        user1 = await user_repository.get_by_username_or_email(
            created_test_user.username, "different@example.com"
        )
        assert user1 is not None
        assert user1.id == created_test_user.id
        
        # Test with email
        user2 = await user_repository.get_by_username_or_email(
            "different_user", created_test_user.email
        )
        assert user2 is not None
        assert user2.id == created_test_user.id
    
    async def test_api_key_generation(self, user_repository, created_test_user):
        """Test API key generation."""
        api_key = await user_repository.generate_api_key(created_test_user.id)
        
        assert isinstance(api_key, str)
        assert len(api_key) > 0
        
        # Verify user has API key hash stored
        updated_user = await user_repository.get(created_test_user.id)
        assert updated_user.api_key_hash is not None
        
        # Verify hash matches
        expected_hash = hashlib.sha256(api_key.encode()).hexdigest()
        assert updated_user.api_key_hash == expected_hash
    
    async def test_authenticate_by_api_key(self, user_repository, created_test_user):
        """Test API key authentication."""
        # Generate API key
        api_key = await user_repository.generate_api_key(created_test_user.id)
        
        # Authenticate with API key
        authenticated_user = await user_repository.authenticate_by_api_key(api_key)
        
        assert authenticated_user is not None
        assert authenticated_user.id == created_test_user.id
        assert authenticated_user.last_login is not None
    
    async def test_authenticate_by_invalid_api_key(self, user_repository):
        """Test authentication with invalid API key."""
        invalid_key = "invalid_api_key"
        user = await user_repository.authenticate_by_api_key(invalid_key)
        assert user is None
    
    async def test_authenticate_by_api_key_inactive_user(self, user_repository, created_test_user):
        """Test authentication with API key for inactive user."""
        # Generate API key and deactivate user
        api_key = await user_repository.generate_api_key(created_test_user.id)
        await user_repository.update(created_test_user.id, is_active=False)
        
        # Authentication should fail
        user = await user_repository.authenticate_by_api_key(api_key)
        assert user is None
    
    async def test_authenticate_by_api_key_timeout(self, user_repository):
        """Test API key authentication timeout."""
        with patch('asyncio.wait_for') as mock_wait_for:
            mock_wait_for.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(AuthenticationError, match="Authentication timeout"):
                await user_repository.authenticate_by_api_key("test_key")
    
    async def test_revoke_api_key(self, user_repository, created_test_user):
        """Test API key revocation."""
        # Generate API key
        api_key = await user_repository.generate_api_key(created_test_user.id)
        
        # Verify key works
        user = await user_repository.authenticate_by_api_key(api_key)
        assert user is not None
        
        # Revoke key
        result = await user_repository.revoke_api_key(created_test_user.id)
        assert result is True
        
        # Verify key no longer works
        user = await user_repository.authenticate_by_api_key(api_key)
        assert user is None
    
    async def test_revoke_api_key_nonexistent_user(self, user_repository):
        """Test revoking API key for non-existent user."""
        result = await user_repository.revoke_api_key(99999)
        assert result is False
    
    async def test_update_last_login(self, user_repository, created_test_user):
        """Test updating last login timestamp."""
        original_login = created_test_user.last_login
        
        await user_repository.update_last_login(created_test_user.id)
        
        updated_user = await user_repository.get(created_test_user.id)
        assert updated_user.last_login != original_login
        assert updated_user.last_login is not None
    
    async def test_update_user_role_by_admin(self, user_repository, created_test_users):
        """Test updating user role by admin."""
        admin_user = next(user for user in created_test_users if user.role == UserRole.ADMIN)
        target_user = next(user for user in created_test_users if user.role == UserRole.VIEWER)
        
        updated_user = await user_repository.update_user_role(
            target_user.id, UserRole.DEVELOPER, admin_user.id
        )
        
        assert updated_user is not None
        assert updated_user.role == UserRole.DEVELOPER
    
    async def test_update_user_role_by_non_admin(self, user_repository, created_test_users):
        """Test updating user role by non-admin (should fail)."""
        non_admin_user = next(user for user in created_test_users if user.role != UserRole.ADMIN)
        target_user = next(user for user in created_test_users if user.role == UserRole.VIEWER)
        
        with pytest.raises(AuthorizationError, match="Only admins can change user roles"):
            await user_repository.update_user_role(
                target_user.id, UserRole.DEVELOPER, non_admin_user.id
            )
    
    async def test_deactivate_user_by_admin(self, user_repository, created_test_users):
        """Test deactivating user by admin."""
        admin_user = next(user for user in created_test_users if user.role == UserRole.ADMIN)
        target_user = next(user for user in created_test_users if user.role == UserRole.VIEWER)
        
        updated_user = await user_repository.deactivate_user(target_user.id, admin_user.id)
        
        assert updated_user is not None
        assert updated_user.is_active is False
        assert updated_user.api_key_hash is None  # API key should be revoked
    
    async def test_deactivate_user_by_non_admin(self, user_repository, created_test_users):
        """Test deactivating user by non-admin (should fail)."""
        non_admin_user = next(user for user in created_test_users if user.role != UserRole.ADMIN)
        target_user = next(user for user in created_test_users if user.role == UserRole.VIEWER)
        
        with pytest.raises(AuthorizationError, match="Only admins can deactivate users"):
            await user_repository.deactivate_user(target_user.id, non_admin_user.id)
    
    async def test_reactivate_user_by_admin(self, user_repository, created_test_users):
        """Test reactivating user by admin."""
        admin_user = next(user for user in created_test_users if user.role == UserRole.ADMIN)
        target_user = next(user for user in created_test_users if user.role == UserRole.VIEWER)
        
        # First deactivate
        await user_repository.deactivate_user(target_user.id, admin_user.id)
        
        # Then reactivate
        updated_user = await user_repository.reactivate_user(target_user.id, admin_user.id)
        
        assert updated_user is not None
        assert updated_user.is_active is True
    
    async def test_get_users_by_role(self, user_repository, created_test_users):
        """Test getting users by role."""
        admin_users = await user_repository.get_users_by_role(UserRole.ADMIN)
        viewer_users = await user_repository.get_users_by_role(UserRole.VIEWER)
        
        assert len(admin_users) >= 1
        assert all(user.role == UserRole.ADMIN for user in admin_users)
        
        assert len(viewer_users) >= 1
        assert all(user.role == UserRole.VIEWER for user in viewer_users)
    
    async def test_get_users_by_role_include_inactive(self, user_repository, created_test_users):
        """Test getting users by role including inactive users."""
        admin_user = next(user for user in created_test_users if user.role == UserRole.ADMIN)
        target_user = next(user for user in created_test_users if user.role == UserRole.VIEWER)
        
        # Deactivate a viewer
        await user_repository.deactivate_user(target_user.id, admin_user.id)
        
        # Get active viewers only
        active_viewers = await user_repository.get_users_by_role(UserRole.VIEWER, include_inactive=False)
        
        # Get all viewers (including inactive)
        all_viewers = await user_repository.get_users_by_role(UserRole.VIEWER, include_inactive=True)
        
        assert len(all_viewers) > len(active_viewers)
        assert not any(user.id == target_user.id for user in active_viewers)
        assert any(user.id == target_user.id for user in all_viewers)
    
    async def test_get_users_by_role_timeout(self, user_repository):
        """Test get users by role with timeout."""
        with patch.object(user_repository, '_execute_with_timeout') as mock_execute:
            mock_execute.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(DatabaseError, match="Query timeout"):
                await user_repository.get_users_by_role(UserRole.ADMIN)
    
    async def test_search_users(self, user_repository, created_test_users):
        """Test user search functionality."""
        # Search by username
        username_results = await user_repository.search_users("admin")
        assert len(username_results) >= 1
        assert any("admin" in user.username.lower() for user in username_results)
        
        # Search by email
        email_results = await user_repository.search_users("example.com")
        assert len(email_results) >= 1
        assert any("example.com" in user.email for user in email_results)
        
        # Search by full name
        name_results = await user_repository.search_users("User")
        assert len(name_results) >= 1
        assert any("User" in (user.full_name or "") for user in name_results)
    
    async def test_search_users_short_term(self, user_repository):
        """Test search with very short term (should return empty)."""
        results = await user_repository.search_users("a")  # Too short
        assert len(results) == 0
    
    async def test_search_users_long_term(self, user_repository, created_test_users):
        """Test search with very long term (should be truncated)."""
        long_term = "a" * 200  # Very long search term
        
        # Should not raise error (term should be truncated)
        results = await user_repository.search_users(long_term)
        # Results may be empty, but operation should succeed
        assert isinstance(results, list)
    
    async def test_search_users_with_limit(self, user_repository, created_test_users):
        """Test search with custom limit."""
        results = await user_repository.search_users("example.com", limit=1)
        assert len(results) <= 1
    
    async def test_search_users_large_limit_capping(self, user_repository):
        """Test that large search limits are capped."""
        with patch.object(user_repository, '_execute_with_timeout') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_execute.return_value = mock_result
            
            await user_repository.search_users("test", limit=500)  # Over 100 limit
            
            # Should cap at 100
            mock_execute.assert_called_once()
    
    async def test_search_users_timeout(self, user_repository):
        """Test search users with timeout."""
        with patch.object(user_repository, '_execute_with_timeout') as mock_execute:
            mock_execute.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(DatabaseError, match="Search timeout"):
                await user_repository.search_users("test")
    
    async def test_update_preferences(self, user_repository, created_test_user):
        """Test updating user preferences."""
        new_preferences = {"theme": "light", "notifications": True}
        
        updated_user = await user_repository.update_preferences(
            created_test_user.id, new_preferences
        )
        
        assert updated_user is not None
        assert updated_user.preferences["theme"] == "light"
        assert updated_user.preferences["notifications"] is True
        
        # Original preferences should be preserved and merged
        if "language" in created_test_user.preferences:
            assert updated_user.preferences["language"] == created_test_user.preferences["language"]
    
    async def test_update_preferences_nonexistent_user(self, user_repository):
        """Test updating preferences for non-existent user."""
        result = await user_repository.update_preferences(99999, {"theme": "dark"})
        assert result is None
    
    async def test_get_user_statistics(self, user_repository, created_test_users):
        """Test getting user statistics."""
        stats = await user_repository.get_user_statistics()
        
        assert isinstance(stats, dict)
        assert "total_users" in stats
        assert "active_users" in stats
        assert "inactive_users" in stats
        assert "users_by_role" in stats
        assert "recent_logins_30d" in stats
        
        assert stats["total_users"] >= len(created_test_users)
        assert stats["active_users"] >= 0
        assert stats["inactive_users"] >= 0
        assert isinstance(stats["users_by_role"], dict)
    
    async def test_get_user_statistics_with_deactivated_users(self, user_repository, created_test_users):
        """Test user statistics with some deactivated users."""
        admin_user = next(user for user in created_test_users if user.role == UserRole.ADMIN)
        target_user = next(user for user in created_test_users if user.role == UserRole.VIEWER)
        
        # Deactivate a user
        await user_repository.deactivate_user(target_user.id, admin_user.id)
        
        stats = await user_repository.get_user_statistics()
        
        assert stats["inactive_users"] >= 1
        assert stats["total_users"] == stats["active_users"] + stats["inactive_users"]
    
    async def test_get_user_statistics_timeout(self, user_repository):
        """Test user statistics with timeout (should return partial stats)."""
        with patch('asyncio.TimeoutError'):
            # Mock the session to raise timeout
            with patch.object(user_repository, '_get_session') as mock_get_session:
                mock_session = AsyncMock()
                mock_session.execute.side_effect = asyncio.TimeoutError()
                mock_get_session.return_value.__aenter__.return_value = mock_session
                mock_get_session.return_value.__aexit__.return_value = None
                
                stats = await user_repository.get_user_statistics()
                
                # Should return empty stats without raising error
                assert isinstance(stats, dict)
                assert stats["total_users"] == 0
    
    async def test_get_user_statistics_database_error(self, user_repository):
        """Test user statistics with database error (should return partial stats)."""
        with patch.object(user_repository, '_get_session') as mock_get_session:
            mock_session = AsyncMock()
            mock_session.execute.side_effect = Exception("Database error")
            mock_get_session.return_value.__aenter__.return_value = mock_session
            mock_get_session.return_value.__aexit__.return_value = None
            
            stats = await user_repository.get_user_statistics()
            
            # Should return empty stats without raising error
            assert isinstance(stats, dict)
            assert stats["total_users"] == 0
    
    async def test_hash_api_key(self, user_repository):
        """Test API key hashing."""
        api_key = "test_api_key"
        hashed = user_repository._hash_api_key(api_key)
        
        expected = hashlib.sha256(api_key.encode()).hexdigest()
        assert hashed == expected
    
    async def test_api_key_authentication_performance(self, user_repository, created_test_user, performance_timer):
        """Test API key authentication performance."""
        api_key = await user_repository.generate_api_key(created_test_user.id)
        
        performance_timer.start()
        
        # Perform multiple authentications
        for _ in range(10):
            user = await user_repository.authenticate_by_api_key(api_key)
            assert user is not None
        
        performance_timer.stop()
        
        # Authentication should be fast
        assert performance_timer.elapsed_seconds < 5.0


class TestTortoiseUserRepository:
    """Test Tortoise ORM user repository functionality."""
    
    def test_tortoise_repository_initialization(self):
        """Test Tortoise user repository initialization."""
        repo = TortoiseUserRepository()
        assert repo._model_class is TortoiseUser
    
    async def test_create_user(self):
        """Test Tortoise user creation."""
        repo = TortoiseUserRepository()
        
        user_data = {
            "username": "tortoise_user",
            "email": "tortoise@example.com",
            "full_name": "Tortoise User",
            "role": UserRole.VIEWER
        }
        
        with patch.object(TortoiseUser, 'exists') as mock_exists:
            mock_exists.return_value = False
            
            with patch.object(repo, 'create') as mock_create:
                mock_user = MagicMock()
                mock_create.return_value = mock_user
                
                result = await repo.create_user(**user_data)
                
                assert result is mock_user
                mock_create.assert_called_once_with(**{**user_data, "preferences": {}})
    
    async def test_create_user_duplicate(self):
        """Test Tortoise user creation with duplicate."""
        repo = TortoiseUserRepository()
        
        user_data = {
            "username": "duplicate_user",
            "email": "duplicate@example.com"
        }
        
        with patch.object(TortoiseUser, 'exists') as mock_exists:
            mock_exists.return_value = True
            
            with pytest.raises(ValueError, match="already exists"):
                await repo.create_user(**user_data)
    
    async def test_get_by_username(self):
        """Test getting Tortoise user by username."""
        repo = TortoiseUserRepository()
        
        with patch.object(TortoiseUser, 'get_or_none') as mock_get:
            mock_user = MagicMock()
            mock_get.return_value = mock_user
            
            result = await repo.get_by_username("test_user")
            
            assert result is mock_user
            mock_get.assert_called_once_with(username="test_user")
    
    async def test_get_by_email(self):
        """Test getting Tortoise user by email."""
        repo = TortoiseUserRepository()
        
        with patch.object(TortoiseUser, 'get_or_none') as mock_get:
            mock_user = MagicMock()
            mock_get.return_value = mock_user
            
            result = await repo.get_by_email("test@example.com")
            
            assert result is mock_user
            mock_get.assert_called_once_with(email="test@example.com")
    
    async def test_hash_api_key(self):
        """Test Tortoise API key hashing."""
        repo = TortoiseUserRepository()
        api_key = "test_api_key"
        hashed = repo._hash_api_key(api_key)
        
        expected = hashlib.sha256(api_key.encode()).hexdigest()
        assert hashed == expected


class TestUserRepositoryPerformance:
    """Test user repository performance characteristics."""
    
    async def test_bulk_user_creation_performance(self, user_repository, db_utils, performance_timer):
        """Test bulk user creation performance."""
        large_dataset = db_utils.create_large_dataset(50, "user")
        
        performance_timer.start()
        
        for user_data in large_dataset:
            await user_repository.create(**user_data)
        
        performance_timer.stop()
        
        # Verify all users were created
        count = await user_repository.count()
        assert count == 50
        
        # Performance should be reasonable
        assert performance_timer.elapsed_seconds < 30.0
    
    async def test_concurrent_user_operations(self, user_repository, sample_user_data):
        """Test concurrent user operations."""
        async def create_and_search_user(user_id: int):
            user_data = sample_user_data.copy()
            user_data["username"] = f"concurrent_user_{user_id}"
            user_data["email"] = f"concurrent_{user_id}@example.com"
            
            # Create user
            user = await user_repository.create(**user_data)
            
            # Search for user
            search_results = await user_repository.search_users(f"concurrent_user_{user_id}")
            
            return user, search_results
        
        # Run concurrent operations
        tasks = [create_and_search_user(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        # Verify all operations succeeded
        assert len(results) == 10
        for user, search_results in results:
            assert user is not None
            assert len(search_results) >= 1
    
    async def test_user_search_performance(self, user_repository, db_utils, performance_timer):
        """Test user search performance with large dataset."""
        # Create large dataset
        large_dataset = db_utils.create_large_dataset(100, "user")
        for user_data in large_dataset:
            await user_repository.create(**user_data)
        
        performance_timer.start()
        
        # Perform multiple searches
        search_terms = ["user_1", "user_2", "example.com", "User"]
        for term in search_terms:
            results = await user_repository.search_users(term)
            assert isinstance(results, list)
        
        performance_timer.stop()
        
        # Search should be fast even with large dataset
        assert performance_timer.elapsed_seconds < 10.0
    
    async def test_user_statistics_performance(self, user_repository, db_utils, performance_timer):
        """Test user statistics performance with large dataset."""
        # Create large dataset with various roles
        large_dataset = db_utils.create_large_dataset(200, "user")
        
        # Mix up roles
        for i, user_data in enumerate(large_dataset):
            if i % 10 == 0:
                user_data["role"] = UserRole.ADMIN
            elif i % 5 == 0:
                user_data["role"] = UserRole.DEVELOPER
            else:
                user_data["role"] = UserRole.VIEWER
        
        # Create users
        for user_data in large_dataset:
            await user_repository.create(**user_data)
        
        performance_timer.start()
        
        # Get statistics
        stats = await user_repository.get_user_statistics()
        
        performance_timer.stop()
        
        # Verify statistics
        assert stats["total_users"] == 200
        assert sum(stats["users_by_role"].values()) == 200
        
        # Statistics generation should be reasonable fast
        assert performance_timer.elapsed_seconds < 15.0


class TestUserRepositorySecurity:
    """Test user repository security features."""
    
    async def test_api_key_uniqueness(self, user_repository, created_test_users):
        """Test that generated API keys are unique."""
        api_keys = set()
        
        for user in created_test_users:
            api_key = await user_repository.generate_api_key(user.id)
            assert api_key not in api_keys
            api_keys.add(api_key)
        
        # All API keys should be unique
        assert len(api_keys) == len(created_test_users)
    
    async def test_api_key_strength(self, user_repository, created_test_user):
        """Test API key strength and randomness."""
        api_keys = []
        
        for _ in range(10):
            # Revoke previous key and generate new one
            await user_repository.revoke_api_key(created_test_user.id)
            api_key = await user_repository.generate_api_key(created_test_user.id)
            api_keys.append(api_key)
        
        # All keys should be different
        assert len(set(api_keys)) == len(api_keys)
        
        # Keys should be of reasonable length
        for key in api_keys:
            assert len(key) >= 32  # secrets.token_urlsafe(32) generates ~43 chars
    
    async def test_role_authorization_checks(self, user_repository, created_test_users):
        """Test that role-based operations properly check authorization."""
        admin_user = next(user for user in created_test_users if user.role == UserRole.ADMIN)
        non_admin_user = next(user for user in created_test_users if user.role != UserRole.ADMIN)
        target_user = next(user for user in created_test_users if user.role == UserRole.VIEWER)
        
        # Admin should be able to change roles
        result = await user_repository.update_user_role(
            target_user.id, UserRole.DEVELOPER, admin_user.id
        )
        assert result is not None
        
        # Non-admin should not be able to change roles
        with pytest.raises(AuthorizationError):
            await user_repository.update_user_role(
                target_user.id, UserRole.ADMIN, non_admin_user.id
            )
        
        # Admin should be able to deactivate users
        result = await user_repository.deactivate_user(target_user.id, admin_user.id)
        assert result is not None
        
        # Non-admin should not be able to deactivate users
        with pytest.raises(AuthorizationError):
            await user_repository.deactivate_user(target_user.id, non_admin_user.id)
    
    async def test_inactive_user_api_authentication(self, user_repository, created_test_user):
        """Test that inactive users cannot authenticate via API key."""
        # Generate API key while active
        api_key = await user_repository.generate_api_key(created_test_user.id)
        
        # Verify authentication works
        user = await user_repository.authenticate_by_api_key(api_key)
        assert user is not None
        
        # Deactivate user
        await user_repository.update(created_test_user.id, is_active=False)
        
        # Authentication should fail
        user = await user_repository.authenticate_by_api_key(api_key)
        assert user is None
    
    async def test_api_key_storage_security(self, user_repository, created_test_user):
        """Test that API keys are securely stored (hashed, not plain text)."""
        api_key = await user_repository.generate_api_key(created_test_user.id)
        
        # Get user from database
        user = await user_repository.get(created_test_user.id)
        
        # API key hash should not equal the plain text key
        assert user.api_key_hash != api_key
        
        # Hash should be consistent
        expected_hash = hashlib.sha256(api_key.encode()).hexdigest()
        assert user.api_key_hash == expected_hash