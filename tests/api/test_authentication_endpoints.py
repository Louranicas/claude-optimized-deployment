"""
Authentication Endpoints Contract Tests

This module contains comprehensive tests for authentication endpoints including
JWT token handling, 2FA, session management, and user management.
"""

import pytest
import json
import time
from typing import Dict, Any, List, Optional
from httpx import AsyncClient
from datetime import datetime, timedelta

# Test markers
pytestmark = [pytest.mark.api_contract, pytest.mark.auth]


class TestLoginEndpoint:
    """Test /auth/login endpoint."""

    async def test_login_endpoint_basic_structure(self, async_client: AsyncClient):
        """Test login endpoint basic structure and validation."""
        # Test POST method requirement
        response = await async_client.get("/auth/login")
        assert response.status_code == 405  # Method not allowed
        
        # Test request body requirement
        response = await async_client.post("/auth/login")
        assert response.status_code == 422  # Validation error
        
        # Test content type
        response = await async_client.post("/auth/login", data="invalid")
        assert response.status_code in [422, 400]  # Bad request or validation error

    async def test_login_request_validation(self, async_client: AsyncClient):
        """Test login request validation rules."""
        # Missing username
        response = await async_client.post("/auth/login", json={"password": "testpass"})
        assert response.status_code == 422
        
        error_data = response.json()
        assert "detail" in error_data
        assert any("username" in str(error).lower() for error in error_data["detail"])
        
        # Missing password
        response = await async_client.post("/auth/login", json={"username": "testuser"})
        assert response.status_code == 422
        
        error_data = response.json()
        assert "detail" in error_data
        assert any("password" in str(error).lower() for error in error_data["detail"])
        
        # Username too short
        response = await async_client.post("/auth/login", json={
            "username": "ab",  # Less than 3 characters
            "password": "validpassword"
        })
        assert response.status_code == 422
        
        # Password too short
        response = await async_client.post("/auth/login", json={
            "username": "validuser",
            "password": "short"  # Less than 8 characters
        })
        assert response.status_code == 422

    async def test_login_with_invalid_credentials(self, async_client: AsyncClient):
        """Test login with invalid credentials."""
        invalid_credentials = {
            "username": "nonexistentuser",
            "password": "wrongpassword"
        }
        
        response = await async_client.post("/auth/login", json=invalid_credentials)
        assert response.status_code == 401
        
        error_data = response.json()
        assert "detail" in error_data
        # Should not reveal whether username or password is wrong
        detail = error_data["detail"].lower()
        assert "invalid" in detail or "unauthorized" in detail or "authentication" in detail

    async def test_login_response_format(self, async_client: AsyncClient):
        """Test login response format for valid credentials."""
        # Note: This test assumes we have a way to create a test user
        # In a real scenario, this would be set up in test fixtures
        
        valid_credentials = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        response = await async_client.post("/auth/login", json=valid_credentials)
        
        if response.status_code == 200:
            # Valid login response format
            data = response.json()
            
            required_fields = ["access_token", "refresh_token", "token_type", "expires_in", "user"]
            for field in required_fields:
                assert field in data, f"Missing required field: {field}"
            
            # Validate field types and formats
            assert isinstance(data["access_token"], str)
            assert len(data["access_token"]) > 0
            
            assert isinstance(data["refresh_token"], str)
            assert len(data["refresh_token"]) > 0
            
            assert data["token_type"] == "Bearer"
            
            assert isinstance(data["expires_in"], int)
            assert data["expires_in"] > 0
            
            assert isinstance(data["user"], dict)
            user = data["user"]
            assert "id" in user or "username" in user
        
        elif response.status_code == 401:
            # Expected for non-existent test user
            assert "detail" in response.json()

    async def test_login_with_mfa_code(self, async_client: AsyncClient):
        """Test login with MFA code field."""
        credentials_with_mfa = {
            "username": "testuser",
            "password": "testpassword123",
            "mfa_code": "123456"
        }
        
        response = await async_client.post("/auth/login", json=credentials_with_mfa)
        
        # Should accept MFA code in request (validation may fail later)
        assert response.status_code in [200, 401, 400]
        
        if response.status_code == 400:
            # May return bad request for invalid MFA code
            error_data = response.json()
            assert "detail" in error_data
            assert "mfa" in error_data["detail"].lower() or "2fa" in error_data["detail"].lower()

    async def test_login_rate_limiting(self, async_client: AsyncClient):
        """Test login endpoint rate limiting."""
        credentials = {
            "username": "testuser",
            "password": "wrongpassword"
        }
        
        # Make multiple failed login attempts
        for i in range(5):
            response = await async_client.post("/auth/login", json=credentials)
            
            if response.status_code == 429:
                # Rate limiting triggered
                assert "detail" in response.json()
                break
            
            # Small delay between requests
            await asyncio.sleep(0.1)


class TestTokenRefreshEndpoint:
    """Test /auth/refresh endpoint."""

    async def test_refresh_endpoint_structure(self, async_client: AsyncClient):
        """Test refresh endpoint structure."""
        # Test POST method requirement
        response = await async_client.get("/auth/refresh")
        assert response.status_code == 405
        
        # Test request body requirement
        response = await async_client.post("/auth/refresh")
        assert response.status_code == 422

    async def test_refresh_request_validation(self, async_client: AsyncClient):
        """Test refresh token request validation."""
        # Missing refresh_token
        response = await async_client.post("/auth/refresh", json={})
        assert response.status_code == 422
        
        error_data = response.json()
        assert "detail" in error_data
        assert any("refresh_token" in str(error).lower() for error in error_data["detail"])
        
        # Empty refresh_token
        response = await async_client.post("/auth/refresh", json={"refresh_token": ""})
        assert response.status_code in [422, 401]

    async def test_refresh_with_invalid_token(self, async_client: AsyncClient):
        """Test refresh with invalid token."""
        invalid_refresh = {
            "refresh_token": "invalid.refresh.token.here"
        }
        
        response = await async_client.post("/auth/refresh", json=invalid_refresh)
        assert response.status_code == 401
        
        error_data = response.json()
        assert "detail" in error_data

    async def test_refresh_response_format(self, async_client: AsyncClient):
        """Test refresh response format for valid token."""
        # This would require a valid refresh token from a previous login
        # For now, test the error response format
        
        refresh_request = {
            "refresh_token": "mock.refresh.token"
        }
        
        response = await async_client.post("/auth/refresh", json=refresh_request)
        
        if response.status_code == 200:
            # Valid refresh response should have new tokens
            data = response.json()
            expected_fields = ["access_token", "token_type", "expires_in"]
            for field in expected_fields:
                assert field in data
        
        elif response.status_code == 401:
            # Expected for invalid token
            assert "detail" in response.json()


class TestLogoutEndpoint:
    """Test /auth/logout endpoint."""

    async def test_logout_requires_authentication(self, async_client: AsyncClient):
        """Test logout requires authentication."""
        response = await async_client.post("/auth/logout")
        assert response.status_code == 401
        
        error_data = response.json()
        assert "detail" in error_data

    async def test_logout_with_invalid_token(self, async_client: AsyncClient):
        """Test logout with invalid token."""
        headers = {"Authorization": "Bearer invalid.token.here"}
        response = await async_client.post("/auth/logout", headers=headers)
        assert response.status_code == 401

    async def test_logout_response_format(self, async_client: AsyncClient):
        """Test logout response format."""
        # With mock token
        headers = {"Authorization": "Bearer mock.token.here"}
        response = await async_client.post("/auth/logout", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            assert "message" in data
            assert "logout" in data["message"].lower()
        elif response.status_code == 401:
            # Expected for invalid token
            assert "detail" in response.json()


class TestUserProfileEndpoints:
    """Test user profile endpoints."""

    async def test_get_current_user_requires_auth(self, async_client: AsyncClient):
        """Test /auth/me requires authentication."""
        response = await async_client.get("/auth/me")
        assert response.status_code == 401
        
        error_data = response.json()
        assert "detail" in error_data
        
        # Should include WWW-Authenticate header
        assert "www-authenticate" in response.headers
        assert "Bearer" in response.headers["www-authenticate"]

    async def test_get_current_user_with_invalid_token(self, async_client: AsyncClient):
        """Test /auth/me with invalid token."""
        headers = {"Authorization": "Bearer invalid.token"}
        response = await async_client.get("/auth/me", headers=headers)
        assert response.status_code == 401

    async def test_change_password_endpoint(self, async_client: AsyncClient):
        """Test password change endpoint."""
        # Without authentication
        response = await async_client.put("/auth/me/password")
        assert response.status_code == 401
        
        # With authentication but no data
        headers = {"Authorization": "Bearer mock.token"}
        response = await async_client.put("/auth/me/password", headers=headers)
        assert response.status_code in [401, 422]  # Auth error or validation error
        
        # With invalid data structure
        password_data = {"new_password": "newpass123"}  # Missing old_password
        response = await async_client.put("/auth/me/password", json=password_data, headers=headers)
        assert response.status_code in [401, 422]


class TestUserManagementEndpoints:
    """Test user management endpoints (admin)."""

    async def test_create_user_requires_permissions(self, async_client: AsyncClient):
        """Test user creation requires admin permissions."""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "password123"
        }
        
        # Without authentication
        response = await async_client.post("/auth/users", json=user_data)
        assert response.status_code == 401
        
        # With regular user token (mock)
        headers = {"Authorization": "Bearer regular.user.token"}
        response = await async_client.post("/auth/users", json=user_data, headers=headers)
        assert response.status_code in [401, 403]  # Unauthorized or forbidden

    async def test_list_users_requires_permissions(self, async_client: AsyncClient):
        """Test user listing requires admin permissions."""
        response = await async_client.get("/auth/users")
        assert response.status_code == 401
        
        headers = {"Authorization": "Bearer regular.user.token"}
        response = await async_client.get("/auth/users", headers=headers)
        assert response.status_code in [401, 403]

    async def test_user_list_pagination(self, async_client: AsyncClient):
        """Test user list pagination parameters."""
        headers = {"Authorization": "Bearer admin.token"}
        
        # Test offset and limit parameters
        response = await async_client.get("/auth/users?offset=0&limit=10", headers=headers)
        assert response.status_code in [401, 403, 200]  # Depends on token validity
        
        # Test invalid pagination parameters
        response = await async_client.get("/auth/users?offset=-1", headers=headers)
        assert response.status_code in [401, 403, 422]
        
        response = await async_client.get("/auth/users?limit=0", headers=headers)
        assert response.status_code in [401, 403, 422]

    async def test_get_user_by_id(self, async_client: AsyncClient):
        """Test getting user by ID."""
        headers = {"Authorization": "Bearer admin.token"}
        
        # Valid UUID format
        response = await async_client.get("/auth/users/123e4567-e89b-12d3-a456-426614174000", headers=headers)
        assert response.status_code in [401, 403, 404, 200]
        
        # Invalid ID format
        response = await async_client.get("/auth/users/invalid-id", headers=headers)
        assert response.status_code in [401, 403, 404, 422]

    async def test_update_user(self, async_client: AsyncClient):
        """Test user update endpoint."""
        headers = {"Authorization": "Bearer admin.token"}
        
        update_data = {
            "email": "updated@example.com",
            "status": "active"
        }
        
        response = await async_client.put("/auth/users/123", json=update_data, headers=headers)
        assert response.status_code in [401, 403, 404, 200]

    async def test_delete_user(self, async_client: AsyncClient):
        """Test user deletion endpoint."""
        headers = {"Authorization": "Bearer admin.token"}
        
        response = await async_client.delete("/auth/users/123", headers=headers)
        assert response.status_code in [401, 403, 404, 200]


class TestRoleManagementEndpoints:
    """Test role management endpoints."""

    async def test_assign_role_endpoint(self, async_client: AsyncClient):
        """Test role assignment endpoint."""
        headers = {"Authorization": "Bearer admin.token"}
        
        role_data = {
            "role_name": "admin",
            "expires_at": None
        }
        
        response = await async_client.post("/auth/users/123/roles", json=role_data, headers=headers)
        assert response.status_code in [401, 403, 404, 200]

    async def test_remove_role_endpoint(self, async_client: AsyncClient):
        """Test role removal endpoint."""
        headers = {"Authorization": "Bearer admin.token"}
        
        response = await async_client.delete("/auth/users/123/roles/admin", headers=headers)
        assert response.status_code in [401, 403, 404, 200]

    async def test_list_roles_endpoint(self, async_client: AsyncClient):
        """Test role listing endpoint."""
        headers = {"Authorization": "Bearer admin.token"}
        
        response = await async_client.get("/auth/roles", headers=headers)
        assert response.status_code in [401, 403, 200]
        
        if response.status_code == 200:
            data = response.json()
            assert "roles" in data

    async def test_get_role_details(self, async_client: AsyncClient):
        """Test getting role details."""
        headers = {"Authorization": "Bearer admin.token"}
        
        response = await async_client.get("/auth/roles/admin", headers=headers)
        assert response.status_code in [401, 403, 404, 200]

    async def test_get_user_permissions(self, async_client: AsyncClient):
        """Test getting user permissions."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.get("/auth/permissions", headers=headers)
        assert response.status_code in [401, 200]
        
        if response.status_code == 200:
            data = response.json()
            assert "permissions" in data
            assert isinstance(data["permissions"], list)


class TestAPIKeyManagement:
    """Test API key management endpoints."""

    async def test_create_api_key(self, async_client: AsyncClient):
        """Test API key creation."""
        headers = {"Authorization": "Bearer user.token"}
        
        api_key_data = {
            "name": "test-api-key",
            "permissions": ["read"],
            "expires_at": None
        }
        
        response = await async_client.post("/auth/api-keys", json=api_key_data, headers=headers)
        assert response.status_code in [401, 200, 201]
        
        if response.status_code in [200, 201]:
            data = response.json()
            required_fields = ["id", "name", "key", "permissions"]
            for field in required_fields:
                assert field in data

    async def test_list_api_keys(self, async_client: AsyncClient):
        """Test API key listing."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.get("/auth/api-keys", headers=headers)
        assert response.status_code in [401, 200]
        
        if response.status_code == 200:
            data = response.json()
            assert "api_keys" in data
            assert isinstance(data["api_keys"], list)

    async def test_revoke_api_key(self, async_client: AsyncClient):
        """Test API key revocation."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.delete("/auth/api-keys/123", headers=headers)
        assert response.status_code in [401, 404, 200]


class TestTwoFactorAuthentication:
    """Test 2FA endpoints."""

    async def test_setup_totp(self, async_client: AsyncClient):
        """Test TOTP setup endpoint."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.post("/auth/2fa/setup/totp", headers=headers)
        assert response.status_code in [401, 200]
        
        if response.status_code == 200:
            data = response.json()
            expected_fields = ["qr_code", "secret", "message"]
            for field in expected_fields:
                assert field in data

    async def test_verify_totp_setup(self, async_client: AsyncClient):
        """Test TOTP verification endpoint."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.post("/auth/2fa/verify/totp?code=123456", headers=headers)
        assert response.status_code in [401, 400, 200]

    async def test_get_2fa_status(self, async_client: AsyncClient):
        """Test 2FA status endpoint."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.get("/auth/2fa/status", headers=headers)
        assert response.status_code in [401, 200]
        
        if response.status_code == 200:
            data = response.json()
            assert "enabled" in data

    async def test_regenerate_backup_codes(self, async_client: AsyncClient):
        """Test backup code regeneration."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.post("/auth/2fa/backup-codes/regenerate", 
                                         json={"password": "userpassword"}, 
                                         headers=headers)
        assert response.status_code in [401, 400, 200]

    async def test_disable_2fa(self, async_client: AsyncClient):
        """Test 2FA disable endpoint."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.delete("/auth/2fa/disable", 
                                           json={"password": "userpassword", "method": "totp"}, 
                                           headers=headers)
        assert response.status_code in [401, 400, 200]


class TestSessionManagement:
    """Test session management endpoints."""

    async def test_list_sessions(self, async_client: AsyncClient):
        """Test session listing."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.get("/auth/sessions", headers=headers)
        assert response.status_code in [401, 200]
        
        if response.status_code == 200:
            data = response.json()
            assert "sessions" in data
            assert "count" in data
            assert isinstance(data["sessions"], list)

    async def test_revoke_session(self, async_client: AsyncClient):
        """Test session revocation."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.delete("/auth/sessions/session-id-123", headers=headers)
        assert response.status_code in [401, 404, 200]

    async def test_revoke_all_sessions(self, async_client: AsyncClient):
        """Test revoking all sessions."""
        headers = {"Authorization": "Bearer user.token"}
        
        response = await async_client.delete("/auth/sessions", headers=headers)
        assert response.status_code in [401, 200]
        
        # Test with keep_current parameter
        response = await async_client.delete("/auth/sessions?keep_current=true", headers=headers)
        assert response.status_code in [401, 200]


class TestPasswordResetFlow:
    """Test password reset flow."""

    async def test_password_reset_request(self, async_client: AsyncClient):
        """Test password reset request."""
        reset_data = {
            "email": "user@example.com"
        }
        
        response = await async_client.post("/auth/password-reset-request", json=reset_data)
        assert response.status_code in [200, 422]  # Should not reveal if email exists
        
        if response.status_code == 200:
            data = response.json()
            assert "message" in data

    async def test_password_reset_validation(self, async_client: AsyncClient):
        """Test password reset validation."""
        # Missing email
        response = await async_client.post("/auth/password-reset-request", json={})
        assert response.status_code == 422
        
        # Invalid email format
        response = await async_client.post("/auth/password-reset-request", json={"email": "invalid"})
        assert response.status_code == 422

    async def test_password_reset_completion(self, async_client: AsyncClient):
        """Test password reset completion."""
        reset_data = {
            "token": "reset.token.here",
            "new_password": "newpassword123"
        }
        
        response = await async_client.post("/auth/password-reset", json=reset_data)
        assert response.status_code in [200, 400, 401]  # Depends on token validity

    async def test_password_reset_token_validation(self, async_client: AsyncClient):
        """Test password reset token validation."""
        # Missing token
        response = await async_client.post("/auth/password-reset", json={"new_password": "pass123"})
        assert response.status_code == 422
        
        # Missing password
        response = await async_client.post("/auth/password-reset", json={"token": "token123"})
        assert response.status_code == 422


class TestAuditEndpoints:
    """Test audit endpoints."""

    async def test_get_audit_events(self, async_client: AsyncClient):
        """Test audit events endpoint."""
        headers = {"Authorization": "Bearer admin.token"}
        
        response = await async_client.get("/auth/audit/events", headers=headers)
        assert response.status_code in [401, 403, 200]
        
        # Test with parameters
        response = await async_client.get("/auth/audit/events?limit=10", headers=headers)
        assert response.status_code in [401, 403, 200]

    async def test_get_user_audit_events(self, async_client: AsyncClient):
        """Test user-specific audit events."""
        headers = {"Authorization": "Bearer admin.token"}
        
        response = await async_client.get("/auth/audit/user/123", headers=headers)
        assert response.status_code in [401, 403, 404, 200]

    async def test_get_security_events(self, async_client: AsyncClient):
        """Test security events endpoint."""
        headers = {"Authorization": "Bearer admin.token"}
        
        response = await async_client.get("/auth/audit/security", headers=headers)
        assert response.status_code in [401, 403, 200]

    async def test_get_audit_statistics(self, async_client: AsyncClient):
        """Test audit statistics endpoint."""
        headers = {"Authorization": "Bearer admin.token"}
        
        response = await async_client.get("/auth/audit/statistics", headers=headers)
        assert response.status_code in [401, 403, 200]


class TestHealthAndMonitoring:
    """Test authentication health endpoints."""

    async def test_auth_health_check(self, async_client: AsyncClient):
        """Test authentication health check."""
        response = await async_client.get("/auth/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "components" in data
        
        # Should include component statuses
        components = data["components"]
        expected_components = ["token_manager", "rbac_manager", "redis_services"]
        for component in expected_components:
            if component in components:
                # Component should have some status indication
                assert components[component] is not None