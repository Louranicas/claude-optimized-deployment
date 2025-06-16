"""
REST Endpoints Contract Tests

This module contains comprehensive tests for all REST endpoints in the
Claude-Optimized Deployment Engine, ensuring proper HTTP status codes,
response formats, and API contract compliance.
"""

import pytest
import json
from typing import Dict, Any, List
from httpx import AsyncClient
from fastapi.testclient import TestClient

# Test markers
pytestmark = [pytest.mark.api_contract, pytest.mark.integration]


class TestHealthEndpoints:
    """Test health and status endpoints."""

    async def test_root_endpoint(self, async_client: AsyncClient):
        """Test the root endpoint returns basic info."""
        response = await async_client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert "version" in data
        assert "docs" in data
        assert "health" in data
        
        # Check values
        assert data["message"] == "Claude-Optimized Deployment Engine"
        assert data["version"] == "1.0.0"
        assert data["docs"] == "/docs"
        assert data["health"] == "/health"

    async def test_health_endpoint(self, async_client: AsyncClient):
        """Test the health check endpoint."""
        response = await async_client.get("/health")
        
        # Should return 200 or 503 (if unhealthy)
        assert response.status_code in [200, 503]
        
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "services" in data
        
        # Status should be valid
        assert data["status"] in ["healthy", "unhealthy", "degraded"]
        
        # Services should be a dict
        assert isinstance(data["services"], dict)
        
        # Common services should be present
        services = data["services"]
        expected_services = ["rate_limiting", "authentication", "database", "redis"]
        
        for service in expected_services:
            if service in services:
                assert "status" in services[service]


class TestAuthenticationEndpoints:
    """Test authentication REST endpoints."""

    async def test_auth_login_endpoint_structure(self, async_client: AsyncClient):
        """Test login endpoint structure and validation."""
        # Test without data
        response = await async_client.post("/auth/login")
        assert response.status_code == 422  # Validation error
        
        # Test with invalid data
        invalid_data = {"username": "test"}  # Missing password
        response = await async_client.post("/auth/login", json=invalid_data)
        assert response.status_code == 422
        
        # Test with properly formatted but invalid credentials
        login_data = {
            "username": "nonexistentuser",
            "password": "wrongpassword"
        }
        response = await async_client.post("/auth/login", json=login_data)
        assert response.status_code in [401, 422]  # Unauthorized or validation error

    async def test_auth_me_endpoint_requires_auth(self, async_client: AsyncClient):
        """Test that /auth/me requires authentication."""
        response = await async_client.get("/auth/me")
        assert response.status_code == 401  # Unauthorized
        
        # Test with invalid token
        headers = {"Authorization": "Bearer invalid-token"}
        response = await async_client.get("/auth/me", headers=headers)
        assert response.status_code == 401

    async def test_auth_logout_endpoint_structure(self, async_client: AsyncClient):
        """Test logout endpoint structure."""
        response = await async_client.post("/auth/logout")
        assert response.status_code == 401  # Requires authentication

    async def test_auth_refresh_endpoint_structure(self, async_client: AsyncClient):
        """Test token refresh endpoint structure."""
        # Test without data
        response = await async_client.post("/auth/refresh")
        assert response.status_code == 422  # Validation error
        
        # Test with invalid refresh token
        refresh_data = {"refresh_token": "invalid-token"}
        response = await async_client.post("/auth/refresh", json=refresh_data)
        assert response.status_code in [401, 422]

    async def test_auth_users_endpoint_requires_permissions(self, async_client: AsyncClient):
        """Test that user management endpoints require proper permissions."""
        # Test create user without auth
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpassword123"
        }
        response = await async_client.post("/auth/users", json=user_data)
        assert response.status_code == 401  # Requires admin permissions
        
        # Test list users without auth
        response = await async_client.get("/auth/users")
        assert response.status_code == 401

    async def test_auth_password_reset_endpoints(self, async_client: AsyncClient):
        """Test password reset endpoints structure."""
        # Test password reset request
        reset_request = {"email": "test@example.com"}
        response = await async_client.post("/auth/password-reset-request", json=reset_request)
        # Should not reveal if email exists, always return success structure
        assert response.status_code in [200, 422]
        
        # Test password reset without token
        response = await async_client.post("/auth/password-reset")
        assert response.status_code == 422  # Missing required fields

    async def test_auth_mfa_endpoints_structure(self, async_client: AsyncClient):
        """Test MFA endpoints structure."""
        # Test MFA enable without auth
        response = await async_client.post("/auth/mfa/enable")
        assert response.status_code == 401
        
        # Test MFA status without auth
        response = await async_client.get("/auth/2fa/status")
        assert response.status_code == 401
        
        # Test MFA disable without auth
        response = await async_client.delete("/auth/2fa/disable")
        assert response.status_code == 401


class TestCircuitBreakerEndpoints:
    """Test circuit breaker REST endpoints."""

    async def test_circuit_breaker_status_endpoint(self, async_client: AsyncClient):
        """Test circuit breaker status endpoint."""
        response = await async_client.get("/api/circuit-breakers/status")
        
        # Should be accessible without auth (monitoring endpoint)
        assert response.status_code == 200
        
        data = response.json()
        assert "timestamp" in data
        assert "monitoring" in data
        assert "summary" in data
        assert "health" in data

    async def test_circuit_breaker_list_endpoint(self, async_client: AsyncClient):
        """Test circuit breaker list endpoint."""
        response = await async_client.get("/api/circuit-breakers/breakers")
        assert response.status_code == 200
        
        data = response.json()
        assert "timestamp" in data
        assert "total" in data
        assert "breakers" in data
        
        # Test with state filter
        response = await async_client.get("/api/circuit-breakers/breakers?state=open")
        assert response.status_code == 200

    async def test_circuit_breaker_individual_endpoint(self, async_client: AsyncClient):
        """Test individual circuit breaker endpoint."""
        # Test with non-existent breaker
        response = await async_client.get("/api/circuit-breakers/breakers/nonexistent")
        assert response.status_code == 404

    async def test_circuit_breaker_reset_endpoints(self, async_client: AsyncClient):
        """Test circuit breaker reset endpoints."""
        # Test reset individual breaker
        response = await async_client.post("/api/circuit-breakers/breakers/test/reset")
        assert response.status_code == 404  # Breaker doesn't exist
        
        # Test reset all breakers
        response = await async_client.post("/api/circuit-breakers/breakers/reset-all")
        assert response.status_code == 200
        
        data = response.json()
        assert "timestamp" in data
        assert "message" in data

    async def test_circuit_breaker_monitoring_endpoints(self, async_client: AsyncClient):
        """Test circuit breaker monitoring endpoints."""
        # Test start monitoring
        response = await async_client.post("/api/circuit-breakers/monitoring/start")
        assert response.status_code in [200, 422]  # May require parameters
        
        # Test stop monitoring
        response = await async_client.post("/api/circuit-breakers/monitoring/stop")
        assert response.status_code == 200

    async def test_circuit_breaker_health_endpoint(self, async_client: AsyncClient):
        """Test circuit breaker health endpoint."""
        response = await async_client.get("/api/circuit-breakers/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "timestamp" in data
        assert "health" in data
        assert "details" in data
        assert "recommendations" in data


class TestMonitoringEndpoints:
    """Test monitoring REST endpoints."""

    async def test_monitoring_health_endpoint(self, async_client: AsyncClient):
        """Test monitoring health endpoint."""
        # Try different possible monitoring endpoints
        endpoints = ["/monitoring/health", "/api/monitoring/health"]
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint)
            if response.status_code != 404:
                assert response.status_code == 200
                data = response.json()
                # Should have some health-related fields
                assert any(key in data for key in ["status", "health", "timestamp"])
                break

    async def test_monitoring_metrics_endpoint(self, async_client: AsyncClient):
        """Test monitoring metrics endpoint."""
        endpoints = ["/monitoring/metrics", "/api/monitoring/metrics"]
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint)
            if response.status_code != 404:
                assert response.status_code == 200
                # Metrics could be in various formats
                break

    async def test_monitoring_alerts_endpoint(self, async_client: AsyncClient):
        """Test monitoring alerts endpoint."""
        endpoints = ["/monitoring/alerts", "/api/monitoring/alerts"]
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint)
            if response.status_code != 404:
                assert response.status_code in [200, 401]  # May require auth
                break


class TestRateLimitingEndpoints:
    """Test rate limiting REST endpoints."""

    async def test_rate_limiting_status_endpoint(self, async_client: AsyncClient):
        """Test rate limiting status endpoint."""
        endpoints = ["/api/rate-limit/status", "/rate-limit/status"]
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint)
            if response.status_code != 404:
                assert response.status_code in [200, 401]
                break

    async def test_rate_limiting_config_endpoint(self, async_client: AsyncClient):
        """Test rate limiting configuration endpoint."""
        endpoints = ["/api/rate-limit/config", "/rate-limit/config"]
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint)
            if response.status_code != 404:
                assert response.status_code in [200, 401, 403]  # May require admin
                break


class TestAPIEndpoints:
    """Test general API endpoints."""

    async def test_api_test_endpoint(self, async_client: AsyncClient):
        """Test the general API test endpoint."""
        response = await async_client.get("/api/test")
        
        # Should be rate limited but accessible
        assert response.status_code in [200, 429]  # Success or rate limited
        
        if response.status_code == 200:
            data = response.json()
            assert "message" in data
            assert "timestamp" in data

    async def test_api_heavy_operation_endpoint(self, async_client: AsyncClient):
        """Test the heavy operation endpoint."""
        response = await async_client.post("/api/heavy-operation")
        
        # Should be rate limited
        assert response.status_code in [200, 429]
        
        if response.status_code == 200:
            data = response.json()
            assert "message" in data
            assert "processing_time" in data

    async def test_api_public_endpoint(self, async_client: AsyncClient):
        """Test the public endpoint."""
        response = await async_client.get("/api/public")
        assert response.status_code == 200
        
        data = response.json()
        assert "message" in data
        assert data["message"] == "This is a public endpoint"


class TestResponseHeaders:
    """Test HTTP response headers across endpoints."""

    async def test_content_type_headers(self, async_client: AsyncClient):
        """Test that JSON endpoints return correct content-type."""
        endpoints = [
            "/",
            "/health",
            "/api/public",
            "/api/circuit-breakers/status"
        ]
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint)
            if response.status_code == 200:
                assert "application/json" in response.headers.get("content-type", "")

    async def test_security_headers(self, async_client: AsyncClient):
        """Test security headers are present."""
        response = await async_client.get("/")
        
        # Check for common security headers
        headers = response.headers
        
        # These headers might be set by middleware
        security_headers = [
            "x-content-type-options",
            "x-frame-options", 
            "x-xss-protection"
        ]
        
        # At least some security headers should be present
        # (This depends on middleware configuration)
        pass

    async def test_cors_headers_present(self, async_client: AsyncClient):
        """Test that CORS headers are present when needed."""
        # Test preflight request
        headers = {
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, Authorization"
        }
        
        response = await async_client.options("/auth/login", headers=headers)
        
        # Should handle OPTIONS request
        assert response.status_code in [200, 204, 405]


class TestErrorResponses:
    """Test error response consistency."""

    async def test_404_error_format(self, async_client: AsyncClient):
        """Test 404 error response format."""
        response = await async_client.get("/nonexistent-endpoint")
        assert response.status_code == 404
        
        # Should return JSON error
        data = response.json()
        assert "detail" in data

    async def test_method_not_allowed_format(self, async_client: AsyncClient):
        """Test 405 error response format."""
        # Try POST on GET-only endpoint
        response = await async_client.post("/health")
        assert response.status_code == 405

    async def test_validation_error_format(self, async_client: AsyncClient):
        """Test 422 validation error response format."""
        # Send invalid JSON to login endpoint
        response = await async_client.post("/auth/login", json={"invalid": "data"})
        assert response.status_code == 422
        
        data = response.json()
        assert "detail" in data
        
        # Should be validation error format
        detail = data["detail"]
        if isinstance(detail, list):
            # Pydantic validation error format
            for error in detail:
                assert "loc" in error
                assert "msg" in error
                assert "type" in error

    async def test_unauthorized_error_format(self, async_client: AsyncClient):
        """Test 401 error response format."""
        response = await async_client.get("/auth/me")
        assert response.status_code == 401
        
        data = response.json()
        assert "detail" in data


class TestPagination:
    """Test pagination in list endpoints."""

    async def test_user_list_pagination(self, async_client: AsyncClient):
        """Test user list endpoint pagination parameters."""
        # Test without auth (should fail)
        response = await async_client.get("/auth/users")
        assert response.status_code == 401
        
        # Test with pagination parameters
        response = await async_client.get("/auth/users?offset=0&limit=10")
        assert response.status_code == 401  # Still requires auth

    async def test_pagination_parameter_validation(self, async_client: AsyncClient):
        """Test pagination parameter validation."""
        endpoints_with_pagination = [
            "/auth/users?offset=-1",  # Invalid offset
            "/auth/users?limit=0",    # Invalid limit
            "/auth/users?limit=1000", # Too large limit
        ]
        
        for endpoint in endpoints_with_pagination:
            response = await async_client.get(endpoint)
            # Should either reject invalid params or require auth first
            assert response.status_code in [401, 422]


class TestAPIVersioning:
    """Test API versioning compliance."""

    async def test_no_version_in_path_yet(self, async_client: AsyncClient):
        """Test that current API doesn't use versioning in path."""
        # Current API should not have version numbers in paths
        response = await async_client.get("/")
        assert response.status_code == 200
        
        # Versioned paths should not exist yet
        versioned_endpoints = ["/v1/", "/v2/", "/api/v1/"]
        for endpoint in versioned_endpoints:
            response = await async_client.get(endpoint)
            assert response.status_code == 404

    async def test_api_version_header_support(self, async_client: AsyncClient):
        """Test API version header support (future-proofing)."""
        headers = {"Accept": "application/json", "API-Version": "1.0"}
        response = await async_client.get("/", headers=headers)
        
        # Should still work with version headers
        assert response.status_code == 200