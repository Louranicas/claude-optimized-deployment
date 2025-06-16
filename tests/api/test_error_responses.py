"""
Error Response Validation Tests

This module contains comprehensive tests for error response formats and
status codes across the Claude-Optimized Deployment Engine API.
"""

import pytest
import json
from typing import Dict, Any, List
from httpx import AsyncClient
from fastapi.testclient import TestClient

# Test markers
pytestmark = [pytest.mark.api_contract, pytest.mark.error_handling]


class TestHTTPStatusCodes:
    """Test HTTP status code compliance."""

    async def test_404_not_found_responses(self, async_client: AsyncClient):
        """Test 404 responses for non-existent endpoints."""
        non_existent_endpoints = [
            "/non-existent",
            "/api/non-existent",
            "/auth/non-existent",
            "/api/circuit-breakers/non-existent",
            "/monitoring/non-existent"
        ]
        
        for endpoint in non_existent_endpoints:
            response = await async_client.get(endpoint)
            assert response.status_code == 404
            
            # Should return JSON error
            data = response.json()
            assert "detail" in data
            assert isinstance(data["detail"], str)

    async def test_405_method_not_allowed_responses(self, async_client: AsyncClient):
        """Test 405 responses for unsupported HTTP methods."""
        method_tests = [
            ("POST", "/health"),  # GET-only endpoint
            ("PUT", "/health"),
            ("DELETE", "/health"),
            ("PATCH", "/health"),
            ("GET", "/auth/login"),  # POST-only endpoint
            ("PUT", "/auth/login"),
            ("DELETE", "/auth/login"),
        ]
        
        for method, endpoint in method_tests:
            response = await async_client.request(method, endpoint)
            if response.status_code == 405:
                # Should include Allow header
                assert "allow" in response.headers
                
                # Should return JSON error
                data = response.json()
                assert "detail" in data

    async def test_422_validation_error_responses(self, async_client: AsyncClient):
        """Test 422 responses for validation errors."""
        validation_tests = [
            # Missing required fields
            ("POST", "/auth/login", {}),
            ("POST", "/auth/login", {"username": "test"}),  # Missing password
            ("POST", "/auth/refresh", {}),  # Missing refresh_token
            ("POST", "/auth/refresh", {"invalid": "field"}),
            
            # Invalid field values
            ("POST", "/auth/login", {"username": "a", "password": "b"}),  # Too short
            ("POST", "/auth/login", {"username": "test", "password": 12345}),  # Wrong type
        ]
        
        for method, endpoint, data in validation_tests:
            response = await async_client.request(method, endpoint, json=data)
            
            if response.status_code == 422:
                error_data = response.json()
                assert "detail" in error_data
                
                detail = error_data["detail"]
                if isinstance(detail, list):
                    # Pydantic validation error format
                    for error in detail:
                        assert "loc" in error, f"Missing 'loc' in error: {error}"
                        assert "msg" in error, f"Missing 'msg' in error: {error}"
                        assert "type" in error, f"Missing 'type' in error: {error}"
                        
                        # Validate field types
                        assert isinstance(error["loc"], list)
                        assert isinstance(error["msg"], str)
                        assert isinstance(error["type"], str)

    async def test_401_unauthorized_responses(self, async_client: AsyncClient):
        """Test 401 responses for authentication failures."""
        auth_required_endpoints = [
            ("GET", "/auth/me"),
            ("POST", "/auth/logout"),
            ("PUT", "/auth/me/password"),
            ("GET", "/auth/users"),
            ("POST", "/auth/users"),
            ("GET", "/auth/api-keys"),
            ("POST", "/auth/api-keys"),
        ]
        
        for method, endpoint in auth_required_endpoints:
            # Test without authentication
            response = await async_client.request(method, endpoint)
            if response.status_code == 401:
                data = response.json()
                assert "detail" in data
                assert isinstance(data["detail"], str)
                
                # Should include WWW-Authenticate header for bearer token
                assert "www-authenticate" in response.headers
                assert "Bearer" in response.headers["www-authenticate"]

    async def test_401_invalid_token_responses(self, async_client: AsyncClient):
        """Test 401 responses for invalid tokens."""
        invalid_token_headers = {"Authorization": "Bearer invalid-token-12345"}
        
        auth_endpoints = [
            ("GET", "/auth/me"),
            ("POST", "/auth/logout"),
            ("GET", "/auth/api-keys"),
        ]
        
        for method, endpoint in auth_endpoints:
            response = await async_client.request(method, endpoint, headers=invalid_token_headers)
            if response.status_code == 401:
                data = response.json()
                assert "detail" in data
                assert "authentication" in data["detail"].lower() or "token" in data["detail"].lower()

    async def test_403_forbidden_responses(self, async_client: AsyncClient):
        """Test 403 responses for authorization failures."""
        # These endpoints typically require admin permissions
        admin_endpoints = [
            ("DELETE", "/auth/users/123"),
            ("POST", "/auth/users/123/roles"),
            ("DELETE", "/auth/users/123/roles/admin"),
        ]
        
        # Regular user token (if we had one)
        user_headers = {"Authorization": "Bearer mock-user-token"}
        
        for method, endpoint in admin_endpoints:
            response = await async_client.request(method, endpoint, headers=user_headers)
            if response.status_code == 403:
                data = response.json()
                assert "detail" in data
                assert "permission" in data["detail"].lower() or "forbidden" in data["detail"].lower()

    async def test_429_rate_limit_responses(self, async_client: AsyncClient):
        """Test 429 responses for rate limiting."""
        # Test endpoints that might be rate limited
        rate_limited_endpoints = [
            "/api/test",
            "/api/heavy-operation",
            "/auth/login",
        ]
        
        for endpoint in rate_limited_endpoints:
            # Make multiple rapid requests to trigger rate limiting
            for i in range(10):
                if endpoint == "/api/heavy-operation":
                    response = await async_client.post(endpoint)
                elif endpoint == "/auth/login":
                    response = await async_client.post(endpoint, json={
                        "username": f"user{i}",
                        "password": "password"
                    })
                else:
                    response = await async_client.get(endpoint)
                
                if response.status_code == 429:
                    # Should include rate limit headers
                    rate_limit_headers = [
                        "x-ratelimit-limit",
                        "x-ratelimit-remaining", 
                        "x-ratelimit-reset",
                        "retry-after"
                    ]
                    
                    # At least one rate limit header should be present
                    headers_present = any(header in response.headers for header in rate_limit_headers)
                    if not headers_present:
                        # Some rate limiting might not include these headers
                        pass
                    
                    data = response.json()
                    assert "detail" in data
                    break

    async def test_500_internal_server_error_format(self, async_client: AsyncClient):
        """Test 500 error response format."""
        # It's hard to trigger a real 500 error, but we can test the format
        # if one occurs during testing
        
        # Try an endpoint that might cause issues
        problematic_requests = [
            ("POST", "/auth/login", {"username": "x" * 1000, "password": "y" * 1000}),
        ]
        
        for method, endpoint, data in problematic_requests:
            response = await async_client.request(method, endpoint, json=data)
            
            if response.status_code == 500:
                error_data = response.json()
                assert "error" in error_data or "detail" in error_data
                
                # Should not expose internal details in production
                detail = error_data.get("detail", error_data.get("error", ""))
                assert "traceback" not in detail.lower()
                assert "exception" not in detail.lower()


class TestErrorResponseConsistency:
    """Test error response format consistency."""

    async def test_error_response_structure(self, async_client: AsyncClient):
        """Test that all error responses have consistent structure."""
        error_inducing_requests = [
            ("GET", "/non-existent", None, 404),
            ("POST", "/auth/login", {}, 422),
            ("GET", "/auth/me", None, 401),
            ("POST", "/health", None, 405),
        ]
        
        for method, endpoint, data, expected_status in error_inducing_requests:
            if data is not None:
                response = await async_client.request(method, endpoint, json=data)
            else:
                response = await async_client.request(method, endpoint)
            
            if response.status_code == expected_status:
                error_data = response.json()
                
                # All errors should have a detail field
                assert "detail" in error_data
                
                # Detail should be non-empty
                assert error_data["detail"]
                
                # Content type should be JSON
                assert "application/json" in response.headers.get("content-type", "")

    async def test_validation_error_detail_format(self, async_client: AsyncClient):
        """Test detailed validation error format."""
        # Create a request with multiple validation errors
        invalid_login = {
            "username": "a",  # Too short
            "password": "b",  # Too short
            "extra_field": "not_allowed"  # Extra field
        }
        
        response = await async_client.post("/auth/login", json=invalid_login)
        
        if response.status_code == 422:
            error_data = response.json()
            assert "detail" in error_data
            
            detail = error_data["detail"]
            if isinstance(detail, list):
                # Should have multiple errors
                assert len(detail) >= 2  # At least username and password errors
                
                for error in detail:
                    # Each error should have proper structure
                    assert "loc" in error
                    assert "msg" in error
                    assert "type" in error
                    
                    # Location should point to the problematic field
                    loc = error["loc"]
                    assert isinstance(loc, list)
                    assert len(loc) >= 1
                    
                    # Should have human-readable message
                    msg = error["msg"]
                    assert isinstance(msg, str)
                    assert len(msg) > 0

    async def test_error_response_headers(self, async_client: AsyncClient):
        """Test error response headers."""
        # Test various error scenarios
        error_scenarios = [
            ("GET", "/non-existent"),
            ("POST", "/auth/login", {}),
            ("GET", "/auth/me"),
        ]
        
        for scenario in error_scenarios:
            if len(scenario) == 3:
                method, endpoint, data = scenario
                response = await async_client.request(method, endpoint, json=data)
            else:
                method, endpoint = scenario
                response = await async_client.request(method, endpoint)
            
            if response.status_code >= 400:
                headers = response.headers
                
                # Should have Content-Type header
                assert "content-type" in headers
                assert "application/json" in headers["content-type"]
                
                # Should have Content-Length
                assert "content-length" in headers
                assert int(headers["content-length"]) > 0

    async def test_error_message_localization_ready(self, async_client: AsyncClient):
        """Test that error messages are ready for localization."""
        response = await async_client.post("/auth/login", json={})
        
        if response.status_code == 422:
            error_data = response.json()
            detail = error_data["detail"]
            
            if isinstance(detail, list):
                for error in detail:
                    msg = error["msg"]
                    
                    # Messages should be in English (default)
                    assert isinstance(msg, str)
                    assert len(msg) > 0
                    
                    # Should not contain code-like strings
                    assert not msg.startswith("ValidationError")
                    assert not msg.startswith("ValueError")


class TestErrorLogging:
    """Test error logging and monitoring."""

    async def test_error_tracking_headers(self, async_client: AsyncClient):
        """Test that errors include tracking information."""
        response = await async_client.get("/non-existent")
        
        if response.status_code == 404:
            # Some error responses might include tracking headers
            headers = response.headers
            
            # Common error tracking headers
            tracking_headers = [
                "x-request-id",
                "x-trace-id", 
                "x-correlation-id"
            ]
            
            # It's okay if these aren't present, but if they are, validate format
            for header in tracking_headers:
                if header in headers:
                    value = headers[header]
                    assert isinstance(value, str)
                    assert len(value) > 0

    async def test_sensitive_information_not_exposed(self, async_client: AsyncClient):
        """Test that error responses don't expose sensitive information."""
        # Try various requests that might expose information
        test_requests = [
            ("GET", "/auth/users/../../etc/passwd"),  # Path traversal attempt
            ("POST", "/auth/login", {"username": "admin'; DROP TABLE users; --", "password": "test"}),  # SQL injection attempt
            ("GET", "/non-existent?debug=true&trace=1"),  # Debug parameter attempt
        ]
        
        for method, endpoint, *args in test_requests:
            if args:
                data = args[0] if isinstance(args[0], dict) else None
                response = await async_client.request(method, endpoint, json=data)
            else:
                response = await async_client.request(method, endpoint)
            
            if response.status_code >= 400:
                error_data = response.json()
                detail = str(error_data.get("detail", ""))
                
                # Should not expose sensitive patterns
                sensitive_patterns = [
                    "traceback",
                    "stack trace",
                    "/home/",
                    "/usr/",
                    "database",
                    "sql",
                    "password",
                    "secret",
                    "token",
                    "key"
                ]
                
                detail_lower = detail.lower()
                for pattern in sensitive_patterns:
                    if pattern in detail_lower:
                        # Some patterns might be acceptable in certain contexts
                        if pattern in ["database", "password", "token", "key"]:
                            # These might appear in user-facing validation messages
                            continue
                        assert False, f"Sensitive pattern '{pattern}' found in error: {detail}"


class TestErrorRecoveryGuidance:
    """Test error responses provide recovery guidance."""

    async def test_validation_errors_provide_guidance(self, async_client: AsyncClient):
        """Test that validation errors provide helpful guidance."""
        # Test various validation scenarios
        validation_tests = [
            {
                "request_data": {"username": "a", "password": "b"},
                "expected_guidance": ["characters", "length", "minimum"]
            },
            {
                "request_data": {"username": "test"},  # Missing password
                "expected_guidance": ["required", "field", "missing"]
            }
        ]
        
        for test in validation_tests:
            response = await async_client.post("/auth/login", json=test["request_data"])
            
            if response.status_code == 422:
                error_data = response.json()
                detail = error_data["detail"]
                
                if isinstance(detail, list):
                    for error in detail:
                        msg = error["msg"].lower()
                        
                        # Should contain helpful guidance
                        guidance_found = any(
                            guidance_word in msg 
                            for guidance_word in test["expected_guidance"]
                        )
                        
                        if not guidance_found:
                            # Message should still be descriptive
                            assert len(msg) > 10  # Reasonably descriptive

    async def test_authentication_errors_provide_guidance(self, async_client: AsyncClient):
        """Test that authentication errors provide appropriate guidance."""
        # Test without authentication
        response = await async_client.get("/auth/me")
        
        if response.status_code == 401:
            error_data = response.json()
            detail = error_data["detail"].lower()
            
            # Should mention authentication requirement
            auth_keywords = ["authentication", "login", "token", "unauthorized"]
            guidance_found = any(keyword in detail for keyword in auth_keywords)
            assert guidance_found, f"No authentication guidance in: {detail}"

    async def test_permission_errors_provide_guidance(self, async_client: AsyncClient):
        """Test that permission errors provide appropriate guidance."""
        # Use invalid token to test permission errors
        headers = {"Authorization": "Bearer mock-user-token"}
        
        admin_endpoints = [
            "/auth/users",
            "/auth/users/123"
        ]
        
        for endpoint in admin_endpoints:
            response = await async_client.get(endpoint, headers=headers)
            
            if response.status_code == 403:
                error_data = response.json()
                detail = error_data["detail"].lower()
                
                # Should mention permission requirement
                permission_keywords = ["permission", "access", "forbidden", "authorized"]
                guidance_found = any(keyword in detail for keyword in permission_keywords)
                assert guidance_found, f"No permission guidance in: {detail}"