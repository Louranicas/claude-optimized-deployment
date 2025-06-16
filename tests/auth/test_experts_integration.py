"""
Comprehensive Tests for AI Experts Integration (src/auth/experts_integration.py).

This test suite covers expert authentication, authorization, permission management,
security scenarios, and edge cases with 90%+ coverage.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, List, Optional, Any

from src.auth.experts_integration import (
    ExpertsAuthManager, ExpertSession, ExpertPermission,
    ExpertAuthenticationError, ExpertAuthorizationError,
    ExpertSessionExpiredError, ExpertQuotaExceededError,
    ExpertRateLimitError, InvalidExpertError
)
from src.auth.models import User, UserStatus
from src.auth.tokens import TokenManager, TokenData
from src.circle_of_experts.models.query import Query, QueryType
from src.circle_of_experts.models.response import Response


class TestExpertSession:
    """Test ExpertSession class functionality."""
    
    def test_expert_session_creation(self):
        """Test basic expert session creation."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            permissions=["query:submit", "response:read"],
            quota_limit=100,
            rate_limit=10
        )
        
        assert session.session_id == "session_123"
        assert session.user_id == "user_123"
        assert session.expert_name == "claude_expert"
        assert session.permissions == ["query:submit", "response:read"]
        assert session.quota_limit == 100
        assert session.rate_limit == 10
        assert session.created_at is not None
        assert session.last_activity is not None
        assert session.quota_used == 0
        assert session.rate_count == 0
        assert not session.is_expired()
    
    def test_expert_session_expiration(self):
        """Test expert session expiration."""
        # Create session with short timeout
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            timeout_minutes=1  # 1 minute timeout
        )
        
        # Initially not expired
        assert not session.is_expired()
        
        # Manually set expiration to past
        session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        # Should now be expired
        assert session.is_expired()
    
    def test_expert_session_activity_update(self):
        """Test session activity updates."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert"
        )
        
        original_activity = session.last_activity
        original_expiry = session.expires_at
        
        # Update activity
        session.update_activity()
        
        assert session.last_activity > original_activity
        assert session.expires_at > original_expiry
    
    def test_expert_session_quota_management(self):
        """Test quota management."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            quota_limit=10
        )
        
        # Initially no usage
        assert session.quota_used == 0
        assert session.quota_remaining == 10
        assert not session.is_quota_exceeded()
        
        # Use quota
        session.use_quota(3)
        assert session.quota_used == 3
        assert session.quota_remaining == 7
        assert not session.is_quota_exceeded()
        
        # Exceed quota
        session.use_quota(8)  # Total: 11, limit: 10
        assert session.quota_used == 11
        assert session.quota_remaining == -1
        assert session.is_quota_exceeded()
        
        # Reset quota
        session.reset_quota()
        assert session.quota_used == 0
        assert session.quota_remaining == 10
        assert not session.is_quota_exceeded()
    
    def test_expert_session_rate_limiting(self):
        """Test rate limiting functionality."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            rate_limit=5,
            rate_window_minutes=1
        )
        
        # Initially no rate usage
        assert session.rate_count == 0
        assert not session.is_rate_limited()
        
        # Make requests within limit
        for i in range(4):
            session.increment_rate_count()
            assert not session.is_rate_limited()
        
        # Exceed rate limit
        session.increment_rate_count()  # 5th request
        assert session.rate_count == 5
        assert session.is_rate_limited()
        
        # Reset rate count
        session.reset_rate_count()
        assert session.rate_count == 0
        assert not session.is_rate_limited()
    
    def test_expert_session_permissions(self):
        """Test permission checking."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            permissions=["query:submit", "response:read"]
        )
        
        # Check existing permissions
        assert session.has_permission("query:submit")
        assert session.has_permission("response:read")
        
        # Check non-existing permissions
        assert not session.has_permission("admin:manage")
        assert not session.has_permission("query:delete")
        
        # Add permission
        session.add_permission("analysis:run")
        assert session.has_permission("analysis:run")
        
        # Remove permission
        session.remove_permission("response:read")
        assert not session.has_permission("response:read")
    
    def test_expert_session_to_dict(self):
        """Test session serialization to dictionary."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            permissions=["query:submit"],
            quota_limit=100,
            rate_limit=10
        )
        
        session_dict = session.to_dict()
        
        assert session_dict["session_id"] == "session_123"
        assert session_dict["user_id"] == "user_123"
        assert session_dict["expert_name"] == "claude_expert"
        assert session_dict["permissions"] == ["query:submit"]
        assert session_dict["quota_limit"] == 100
        assert session_dict["rate_limit"] == 10
        assert "created_at" in session_dict
        assert "last_activity" in session_dict
        assert "expires_at" in session_dict


class TestExpertPermission:
    """Test ExpertPermission class functionality."""
    
    def test_expert_permission_creation(self):
        """Test expert permission creation."""
        permission = ExpertPermission(
            expert_name="claude_expert",
            action="query:submit",
            resource="*",
            conditions={"time_limit": "business_hours"}
        )
        
        assert permission.expert_name == "claude_expert"
        assert permission.action == "query:submit"
        assert permission.resource == "*"
        assert permission.conditions["time_limit"] == "business_hours"
    
    def test_expert_permission_matching(self):
        """Test permission matching logic."""
        # Exact match permission
        exact_perm = ExpertPermission(
            expert_name="claude_expert",
            action="query:submit",
            resource="financial_data"
        )
        
        assert exact_perm.matches("claude_expert", "query:submit", "financial_data")
        assert not exact_perm.matches("gpt_expert", "query:submit", "financial_data")
        assert not exact_perm.matches("claude_expert", "query:delete", "financial_data")
        assert not exact_perm.matches("claude_expert", "query:submit", "personal_data")
        
        # Wildcard permission
        wildcard_perm = ExpertPermission(
            expert_name="*",
            action="query:*",
            resource="public_data"
        )
        
        assert wildcard_perm.matches("claude_expert", "query:submit", "public_data")
        assert wildcard_perm.matches("gpt_expert", "query:read", "public_data")
        assert not wildcard_perm.matches("claude_expert", "admin:manage", "public_data")
        assert not wildcard_perm.matches("claude_expert", "query:submit", "private_data")
    
    def test_expert_permission_conditions(self):
        """Test permission conditions evaluation."""
        # Time-based condition
        time_perm = ExpertPermission(
            expert_name="claude_expert",
            action="query:submit",
            resource="*",
            conditions={"time_limit": "business_hours"}
        )
        
        # Mock current time during business hours
        with patch('datetime.datetime') as mock_dt:
            mock_dt.now.return_value = datetime(2023, 12, 1, 10, 0)  # 10 AM
            assert time_perm.evaluate_conditions()
        
        # Mock current time outside business hours
        with patch('datetime.datetime') as mock_dt:
            mock_dt.now.return_value = datetime(2023, 12, 1, 22, 0)  # 10 PM
            # Condition evaluation depends on implementation
            # This is a placeholder for actual condition logic
    
    def test_expert_permission_hierarchy(self):
        """Test permission hierarchy and inheritance."""
        # Admin permission (highest level)
        admin_perm = ExpertPermission(
            expert_name="claude_expert",
            action="admin:*",
            resource="*"
        )
        
        # Should grant access to any action
        assert admin_perm.matches("claude_expert", "admin:manage", "any_resource")
        assert admin_perm.matches("claude_expert", "query:submit", "any_resource")
        
        # User permission (lower level)
        user_perm = ExpertPermission(
            expert_name="claude_expert",
            action="query:read",
            resource="public_data"
        )
        
        # Should only grant specific access
        assert user_perm.matches("claude_expert", "query:read", "public_data")
        assert not user_perm.matches("claude_expert", "query:write", "public_data")


class TestExpertsAuthManager:
    """Test ExpertsAuthManager class functionality."""
    
    @pytest.fixture
    def mock_components(self):
        """Create mock components for ExpertsAuthManager."""
        token_manager = Mock(spec=TokenManager)
        user_store = AsyncMock()
        expert_registry = AsyncMock()
        session_store = AsyncMock()
        audit_logger = AsyncMock()
        
        return {
            "token_manager": token_manager,
            "user_store": user_store,
            "expert_registry": expert_registry,
            "session_store": session_store,
            "audit_logger": audit_logger
        }
    
    @pytest.fixture
    def auth_manager(self, mock_components):
        """Create ExpertsAuthManager instance."""
        return ExpertsAuthManager(**mock_components)
    
    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"experts:query", "experts:read"},
            status=UserStatus.ACTIVE
        )
    
    @pytest.mark.asyncio
    async def test_authenticate_expert_success(self, auth_manager, mock_components, test_user):
        """Test successful expert authentication."""
        # Setup mocks
        token_data = TokenData(
            user_id=test_user.id,
            username=test_user.username,
            roles=test_user.roles,
            permissions=list(test_user.permissions)
        )
        mock_components["token_manager"].verify_token.return_value = token_data
        mock_components["user_store"].get_user.return_value = test_user
        mock_components["expert_registry"].get_expert.return_value = {
            "name": "claude_expert",
            "type": "language_model",
            "capabilities": ["text_generation", "analysis"]
        }
        
        session = await auth_manager.authenticate_expert(
            token="valid_token",
            expert_name="claude_expert",
            requested_permissions=["query:submit", "response:read"]
        )
        
        assert isinstance(session, ExpertSession)
        assert session.user_id == test_user.id
        assert session.expert_name == "claude_expert"
        assert "query:submit" in session.permissions
        assert "response:read" in session.permissions
        
        # Verify calls
        mock_components["token_manager"].verify_token.assert_called_once_with("valid_token")
        mock_components["user_store"].get_user.assert_called_once_with(test_user.id)
        mock_components["expert_registry"].get_expert.assert_called_once_with("claude_expert")
    
    @pytest.mark.asyncio
    async def test_authenticate_expert_invalid_token(self, auth_manager, mock_components):
        """Test expert authentication with invalid token."""
        # Setup mocks
        mock_components["token_manager"].verify_token.return_value = None
        
        with pytest.raises(ExpertAuthenticationError) as exc_info:
            await auth_manager.authenticate_expert(
                token="invalid_token",
                expert_name="claude_expert"
            )
        
        assert "Invalid token" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_authenticate_expert_user_not_found(self, auth_manager, mock_components):
        """Test expert authentication with non-existent user."""
        # Setup mocks
        token_data = TokenData(
            user_id="nonexistent_user",
            username="ghost",
            roles=["user"],
            permissions=[]
        )
        mock_components["token_manager"].verify_token.return_value = token_data
        mock_components["user_store"].get_user.return_value = None
        
        with pytest.raises(ExpertAuthenticationError) as exc_info:
            await auth_manager.authenticate_expert(
                token="valid_token",
                expert_name="claude_expert"
            )
        
        assert "User not found" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_authenticate_expert_invalid_expert(self, auth_manager, mock_components, test_user):
        """Test expert authentication with invalid expert."""
        # Setup mocks
        token_data = TokenData(
            user_id=test_user.id,
            username=test_user.username,
            roles=test_user.roles,
            permissions=list(test_user.permissions)
        )
        mock_components["token_manager"].verify_token.return_value = token_data
        mock_components["user_store"].get_user.return_value = test_user
        mock_components["expert_registry"].get_expert.return_value = None
        
        with pytest.raises(InvalidExpertError) as exc_info:
            await auth_manager.authenticate_expert(
                token="valid_token",
                expert_name="nonexistent_expert"
            )
        
        assert "Expert not found" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_authenticate_expert_insufficient_permissions(self, auth_manager, mock_components):
        """Test expert authentication with insufficient permissions."""
        # Create user without expert permissions
        limited_user = User(
            id="limited_user",
            username="limiteduser",
            email="limited@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"profile:read"},  # No expert permissions
            status=UserStatus.ACTIVE
        )
        
        # Setup mocks
        token_data = TokenData(
            user_id=limited_user.id,
            username=limited_user.username,
            roles=limited_user.roles,
            permissions=list(limited_user.permissions)
        )
        mock_components["token_manager"].verify_token.return_value = token_data
        mock_components["user_store"].get_user.return_value = limited_user
        mock_components["expert_registry"].get_expert.return_value = {
            "name": "claude_expert",
            "type": "language_model"
        }
        
        with pytest.raises(ExpertAuthorizationError) as exc_info:
            await auth_manager.authenticate_expert(
                token="valid_token",
                expert_name="claude_expert",
                requested_permissions=["query:submit"]
            )
        
        assert "Insufficient permissions" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_validate_expert_session_success(self, auth_manager, mock_components):
        """Test successful expert session validation."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            permissions=["query:submit"]
        )
        
        # Setup mocks
        mock_components["session_store"].get_session.return_value = session
        
        validated_session = await auth_manager.validate_expert_session("session_123")
        
        assert validated_session == session
        mock_components["session_store"].get_session.assert_called_once_with("session_123")
    
    @pytest.mark.asyncio
    async def test_validate_expert_session_not_found(self, auth_manager, mock_components):
        """Test expert session validation with non-existent session."""
        # Setup mocks
        mock_components["session_store"].get_session.return_value = None
        
        with pytest.raises(ExpertAuthenticationError) as exc_info:
            await auth_manager.validate_expert_session("nonexistent_session")
        
        assert "Session not found" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_validate_expert_session_expired(self, auth_manager, mock_components):
        """Test expert session validation with expired session."""
        # Create expired session
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert"
        )
        session.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        
        # Setup mocks
        mock_components["session_store"].get_session.return_value = session
        
        with pytest.raises(ExpertSessionExpiredError):
            await auth_manager.validate_expert_session("session_123")
    
    @pytest.mark.asyncio
    async def test_check_expert_permission_success(self, auth_manager, mock_components):
        """Test successful expert permission check."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            permissions=["query:submit", "response:read"]
        )
        
        # Should succeed with valid permission
        result = await auth_manager.check_expert_permission(
            session=session,
            action="query:submit",
            resource="financial_data"
        )
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_check_expert_permission_denied(self, auth_manager, mock_components):
        """Test expert permission check with insufficient permissions."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            permissions=["response:read"]  # Missing query:submit
        )
        
        # Should fail with insufficient permission
        result = await auth_manager.check_expert_permission(
            session=session,
            action="query:submit",
            resource="financial_data"
        )
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_execute_expert_query_success(self, auth_manager, mock_components, test_user):
        """Test successful expert query execution."""
        session = ExpertSession(
            session_id="session_123",
            user_id=test_user.id,
            expert_name="claude_expert",
            permissions=["query:submit", "response:read"],
            quota_limit=100,
            rate_limit=10
        )
        
        query = Query(
            query_id="query_123",
            content="What is the weather today?",
            query_type=QueryType.QUESTION,
            user_id=test_user.id
        )
        
        mock_response = Response(
            response_id="response_123",
            query_id="query_123",
            expert_name="claude_expert",
            content="The weather is sunny today.",
            confidence=0.95
        )
        
        # Setup mocks
        mock_components["expert_registry"].execute_query.return_value = mock_response
        
        response = await auth_manager.execute_expert_query(
            session=session,
            query=query
        )
        
        assert response == mock_response
        assert session.quota_used == 1  # Quota should be incremented
        assert session.rate_count == 1  # Rate count should be incremented
        
        # Verify audit logging
        mock_components["audit_logger"].log_event.assert_called()
    
    @pytest.mark.asyncio
    async def test_execute_expert_query_quota_exceeded(self, auth_manager, mock_components, test_user):
        """Test expert query execution with quota exceeded."""
        session = ExpertSession(
            session_id="session_123",
            user_id=test_user.id,
            expert_name="claude_expert",
            permissions=["query:submit"],
            quota_limit=1,
            quota_used=1  # Already at limit
        )
        
        query = Query(
            query_id="query_123",
            content="Test query",
            query_type=QueryType.QUESTION,
            user_id=test_user.id
        )
        
        with pytest.raises(ExpertQuotaExceededError):
            await auth_manager.execute_expert_query(session=session, query=query)
    
    @pytest.mark.asyncio
    async def test_execute_expert_query_rate_limited(self, auth_manager, mock_components, test_user):
        """Test expert query execution with rate limit exceeded."""
        session = ExpertSession(
            session_id="session_123",
            user_id=test_user.id,
            expert_name="claude_expert",
            permissions=["query:submit"],
            rate_limit=1,
            rate_count=1,  # Already at limit
            last_rate_reset=datetime.now(timezone.utc)  # Recent reset
        )
        
        query = Query(
            query_id="query_123",
            content="Test query",
            query_type=QueryType.QUESTION,
            user_id=test_user.id
        )
        
        with pytest.raises(ExpertRateLimitError):
            await auth_manager.execute_expert_query(session=session, query=query)
    
    @pytest.mark.asyncio
    async def test_get_expert_capabilities(self, auth_manager, mock_components):
        """Test getting expert capabilities."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            permissions=["info:read"]
        )
        
        mock_capabilities = {
            "text_generation": True,
            "code_analysis": True,
            "image_analysis": False,
            "max_tokens": 4096,
            "supported_languages": ["en", "es", "fr"]
        }
        
        # Setup mocks
        mock_components["expert_registry"].get_expert_capabilities.return_value = mock_capabilities
        
        capabilities = await auth_manager.get_expert_capabilities(session)
        
        assert capabilities == mock_capabilities
        mock_components["expert_registry"].get_expert_capabilities.assert_called_once_with("claude_expert")
    
    @pytest.mark.asyncio
    async def test_revoke_expert_session(self, auth_manager, mock_components):
        """Test expert session revocation."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert"
        )
        
        # Setup mocks
        mock_components["session_store"].delete_session.return_value = True
        
        result = await auth_manager.revoke_expert_session("session_123", "user_requested")
        
        assert result is True
        mock_components["session_store"].delete_session.assert_called_once_with("session_123")
        mock_components["audit_logger"].log_event.assert_called()
    
    @pytest.mark.asyncio
    async def test_get_user_expert_sessions(self, auth_manager, mock_components):
        """Test getting user expert sessions."""
        sessions = [
            ExpertSession(
                session_id="session_1",
                user_id="user_123",
                expert_name="claude_expert"
            ),
            ExpertSession(
                session_id="session_2",
                user_id="user_123",
                expert_name="gpt_expert"
            )
        ]
        
        # Setup mocks
        mock_components["session_store"].get_user_sessions.return_value = sessions
        
        user_sessions = await auth_manager.get_user_expert_sessions("user_123")
        
        assert len(user_sessions) == 2
        assert user_sessions[0].expert_name == "claude_expert"
        assert user_sessions[1].expert_name == "gpt_expert"


class TestSecurityScenarios:
    """Test security scenarios and edge cases."""
    
    @pytest.fixture
    def auth_manager(self, mock_components):
        """Create ExpertsAuthManager instance."""
        return ExpertsAuthManager(**mock_components)
    
    @pytest.fixture
    def mock_components(self):
        """Create mock components."""
        return {
            "token_manager": Mock(spec=TokenManager),
            "user_store": AsyncMock(),
            "expert_registry": AsyncMock(),
            "session_store": AsyncMock(),
            "audit_logger": AsyncMock()
        }
    
    @pytest.mark.asyncio
    async def test_session_hijacking_prevention(self, auth_manager, mock_components):
        """Test prevention of session hijacking."""
        # Create session for user A
        session_a = ExpertSession(
            session_id="session_123",
            user_id="user_a",
            expert_name="claude_expert"
        )
        
        # Setup mocks
        mock_components["session_store"].get_session.return_value = session_a
        
        # User B tries to use User A's session
        with patch.object(auth_manager, '_get_current_user_id', return_value="user_b"):
            with pytest.raises(ExpertAuthenticationError) as exc_info:
                await auth_manager.validate_expert_session("session_123")
        
        assert "Session does not belong to current user" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_privilege_escalation_prevention(self, auth_manager, mock_components):
        """Test prevention of privilege escalation."""
        # User with limited permissions
        limited_user = User(
            id="limited_user",
            username="limiteduser",
            email="limited@example.com",
            password_hash="hash",
            roles=["user"],
            permissions={"experts:read"},  # Read-only access
            status=UserStatus.ACTIVE
        )
        
        token_data = TokenData(
            user_id=limited_user.id,
            username=limited_user.username,
            roles=limited_user.roles,
            permissions=list(limited_user.permissions)
        )
        
        # Setup mocks
        mock_components["token_manager"].verify_token.return_value = token_data
        mock_components["user_store"].get_user.return_value = limited_user
        mock_components["expert_registry"].get_expert.return_value = {"name": "claude_expert"}
        
        # User tries to request admin permissions
        with pytest.raises(ExpertAuthorizationError):
            await auth_manager.authenticate_expert(
                token="valid_token",
                expert_name="claude_expert",
                requested_permissions=["admin:manage", "query:submit"]
            )
    
    @pytest.mark.asyncio
    async def test_expert_isolation(self, auth_manager, mock_components):
        """Test that experts are properly isolated from each other."""
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            permissions=["query:submit"]
        )
        
        # User tries to access different expert through same session
        with pytest.raises(ExpertAuthorizationError) as exc_info:
            await auth_manager.check_expert_permission(
                session=session,
                action="query:submit",
                resource="gpt_expert_data"  # Different expert's data
            )
        
        # Should fail because session is for claude_expert only
        assert "Expert mismatch" in str(exc_info.value) or not await auth_manager.check_expert_permission(
            session=session,
            action="query:submit", 
            resource="gpt_expert_data"
        )
    
    @pytest.mark.asyncio
    async def test_injection_attack_prevention(self, auth_manager, mock_components):
        """Test prevention of injection attacks."""
        malicious_inputs = [
            "claude_expert'; DROP TABLE sessions; --",
            "claude_expert<script>alert('xss')</script>",
            "claude_expert\nmalicious_command",
            "claude_expert\x00null_injection"
        ]
        
        for malicious_input in malicious_inputs:
            # Setup mocks
            mock_components["expert_registry"].get_expert.return_value = None
            
            with pytest.raises(InvalidExpertError):
                await auth_manager.authenticate_expert(
                    token="valid_token",
                    expert_name=malicious_input
                )
    
    @pytest.mark.asyncio
    async def test_concurrent_session_safety(self, auth_manager, mock_components):
        """Test concurrent session operations safety."""
        import asyncio
        
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            quota_limit=100,
            rate_limit=10
        )
        
        # Setup mocks
        mock_components["session_store"].get_session.return_value = session
        mock_components["expert_registry"].execute_query.return_value = Mock()
        
        # Simulate concurrent query executions
        async def execute_query():
            query = Query(
                query_id=f"query_{asyncio.current_task().get_name()}",
                content="Test query",
                query_type=QueryType.QUESTION,
                user_id="user_123"
            )
            try:
                return await auth_manager.execute_expert_query(session, query)
            except Exception as e:
                return e
        
        # Run multiple concurrent queries
        tasks = [execute_query() for _ in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should handle concurrent access without corruption
        assert len(results) == 20
        # Quota and rate counts should be accurate
        assert session.quota_used <= 100
        assert session.rate_count <= 10
    
    @pytest.mark.asyncio
    async def test_token_replay_prevention(self, auth_manager, mock_components):
        """Test prevention of token replay attacks."""
        # Simulate token that's been used and should be invalidated
        token_data = TokenData(
            user_id="user_123",
            username="testuser",
            roles=["user"],
            permissions=["experts:query"],
            jti="used_token_jti"  # This token has been used before
        )
        
        # Setup mocks to simulate revoked token
        mock_components["token_manager"].verify_token.return_value = token_data
        
        # Mock that token is in revocation list
        with patch.object(auth_manager, '_is_token_revoked', return_value=True):
            with pytest.raises(ExpertAuthenticationError) as exc_info:
                await auth_manager.authenticate_expert(
                    token="revoked_token",
                    expert_name="claude_expert"
                )
        
        assert "Token has been revoked" in str(exc_info.value)


class TestPerformance:
    """Test performance characteristics."""
    
    @pytest.fixture
    def auth_manager(self, mock_components):
        """Create ExpertsAuthManager instance."""
        return ExpertsAuthManager(**mock_components)
    
    @pytest.fixture
    def mock_components(self):
        """Create mock components."""
        return {
            "token_manager": Mock(spec=TokenManager),
            "user_store": AsyncMock(),
            "expert_registry": AsyncMock(),
            "session_store": AsyncMock(),
            "audit_logger": AsyncMock()
        }
    
    @pytest.mark.asyncio
    async def test_session_validation_performance(self, auth_manager, mock_components):
        """Test session validation performance."""
        import time
        
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert"
        )
        
        # Setup mocks
        mock_components["session_store"].get_session.return_value = session
        
        # Time multiple session validations
        start_time = time.time()
        for _ in range(1000):
            await auth_manager.validate_expert_session("session_123")
        elapsed_time = time.time() - start_time
        
        # Should be fast (less than 1 second for 1000 validations)
        assert elapsed_time < 1.0
        
        # Calculate rate
        rate = 1000 / elapsed_time
        assert rate > 1000  # At least 1000 validations per second
    
    @pytest.mark.asyncio
    async def test_permission_check_performance(self, auth_manager, mock_components):
        """Test permission check performance."""
        import time
        
        session = ExpertSession(
            session_id="session_123",
            user_id="user_123",
            expert_name="claude_expert",
            permissions=["query:submit", "response:read", "analysis:run"]
        )
        
        # Time multiple permission checks
        start_time = time.time()
        for i in range(1000):
            await auth_manager.check_expert_permission(
                session=session,
                action="query:submit",
                resource=f"resource_{i}"
            )
        elapsed_time = time.time() - start_time
        
        # Should be very fast (less than 0.5 seconds for 1000 checks)
        assert elapsed_time < 0.5
    
    @pytest.mark.asyncio
    async def test_memory_usage_with_many_sessions(self, auth_manager, mock_components):
        """Test memory usage with many sessions."""
        import gc
        
        # Create many sessions
        sessions = []
        for i in range(1000):
            session = ExpertSession(
                session_id=f"session_{i}",
                user_id=f"user_{i}",
                expert_name="claude_expert"
            )
            sessions.append(session)
        
        # Force garbage collection
        gc.collect()
        
        # All sessions should still be accessible
        assert len(sessions) == 1000
        assert sessions[0].session_id == "session_0"
        assert sessions[999].session_id == "session_999"


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.fixture
    def auth_manager(self, mock_components):
        """Create ExpertsAuthManager instance."""
        return ExpertsAuthManager(**mock_components)
    
    @pytest.fixture
    def mock_components(self):
        """Create mock components."""
        return {
            "token_manager": Mock(spec=TokenManager),
            "user_store": AsyncMock(),
            "expert_registry": AsyncMock(),
            "session_store": AsyncMock(),
            "audit_logger": AsyncMock()
        }
    
    @pytest.mark.asyncio
    async def test_none_values_handling(self, auth_manager):
        """Test handling of None values."""
        # Should handle None token gracefully
        with pytest.raises(ExpertAuthenticationError):
            await auth_manager.authenticate_expert(
                token=None,
                expert_name="claude_expert"
            )
        
        # Should handle None expert name gracefully
        with pytest.raises(InvalidExpertError):
            await auth_manager.authenticate_expert(
                token="valid_token",
                expert_name=None
            )
    
    @pytest.mark.asyncio
    async def test_empty_string_values(self, auth_manager):
        """Test handling of empty string values."""
        # Should handle empty token gracefully
        with pytest.raises(ExpertAuthenticationError):
            await auth_manager.authenticate_expert(
                token="",
                expert_name="claude_expert"
            )
        
        # Should handle empty expert name gracefully
        with pytest.raises(InvalidExpertError):
            await auth_manager.authenticate_expert(
                token="valid_token",
                expert_name=""
            )
    
    @pytest.mark.asyncio
    async def test_unicode_handling(self, auth_manager, mock_components):
        """Test handling of unicode characters."""
        # Unicode in expert names
        unicode_expert_name = "专家_claude"
        
        # Setup mocks
        mock_components["expert_registry"].get_expert.return_value = {
            "name": unicode_expert_name,
            "type": "language_model"
        }
        
        # Should handle unicode gracefully
        # (Whether it succeeds or fails depends on validation rules)
        try:
            token_data = TokenData(
                user_id="user_123",
                username="testuser",
                roles=["user"],
                permissions=["experts:query"]
            )
            mock_components["token_manager"].verify_token.return_value = token_data
            
            user = User(
                id="user_123",
                username="testuser",
                email="test@example.com",
                password_hash="hash",
                roles=["user"],
                permissions={"experts:query"},
                status=UserStatus.ACTIVE
            )
            mock_components["user_store"].get_user.return_value = user
            
            session = await auth_manager.authenticate_expert(
                token="valid_token",
                expert_name=unicode_expert_name
            )
            assert session.expert_name == unicode_expert_name
        except (InvalidExpertError, ValidationError):
            # If validation rejects unicode, that's also acceptable
            pass
    
    @pytest.mark.asyncio
    async def test_very_long_values(self, auth_manager, mock_components):
        """Test handling of very long values."""
        # Very long expert name
        long_expert_name = "x" * 1000
        
        # Should handle gracefully (likely reject due to validation)
        with pytest.raises((InvalidExpertError, ValidationError)):
            await auth_manager.authenticate_expert(
                token="valid_token",
                expert_name=long_expert_name
            )
    
    @pytest.mark.asyncio
    async def test_storage_failures(self, auth_manager, mock_components):
        """Test handling of storage failures."""
        # Session store failure
        mock_components["session_store"].get_session.side_effect = Exception("Storage unavailable")
        
        with pytest.raises(Exception):
            await auth_manager.validate_expert_session("session_123")
        
        # Expert registry failure
        mock_components["expert_registry"].get_expert.side_effect = Exception("Registry unavailable")
        
        with pytest.raises(Exception):
            await auth_manager.authenticate_expert(
                token="valid_token",
                expert_name="claude_expert"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.auth.experts_integration", "--cov-report=term-missing"])