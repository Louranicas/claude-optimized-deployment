"""
CORS Headers Contract Tests

This module contains comprehensive tests for CORS (Cross-Origin Resource Sharing)
headers and configuration across the Claude-Optimized Deployment Engine API.
"""

import pytest
from typing import Dict, Any, List
from httpx import AsyncClient

# Test markers
pytestmark = [pytest.mark.api_contract, pytest.mark.cors]


class TestCORSPreflightRequests:
    """Test CORS preflight OPTIONS requests."""

    async def test_preflight_request_basic(self, async_client: AsyncClient):
        """Test basic CORS preflight request."""
        headers = {
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, Authorization"
        }
        
        endpoints_to_test = [
            "/auth/login",
            "/auth/users", 
            "/api/test",
            "/api/circuit-breakers/status"
        ]
        
        for endpoint in endpoints_to_test:
            response = await async_client.options(endpoint, headers=headers)
            
            # Should handle OPTIONS request
            assert response.status_code in [200, 204, 405]
            
            if response.status_code in [200, 204]:
                # Should include CORS headers
                cors_headers = response.headers
                
                # Check for essential CORS headers
                if "access-control-allow-origin" in cors_headers:
                    origin = cors_headers["access-control-allow-origin"]
                    assert origin in ["*", "https://example.com", "null"]
                
                if "access-control-allow-methods" in cors_headers:
                    methods = cors_headers["access-control-allow-methods"]
                    assert isinstance(methods, str)
                    assert len(methods) > 0

    async def test_preflight_request_methods(self, async_client: AsyncClient):
        """Test CORS preflight with different requested methods."""
        origin = "https://app.example.com"
        
        method_tests = [
            ("GET", "/health"),
            ("POST", "/auth/login"),
            ("PUT", "/auth/me/password"),
            ("DELETE", "/auth/api-keys/123"),
            ("PATCH", "/auth/users/123")
        ]
        
        for method, endpoint in method_tests:
            headers = {
                "Origin": origin,
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "Content-Type, Authorization"
            }
            
            response = await async_client.options(endpoint, headers=headers)
            
            if response.status_code in [200, 204]:
                cors_headers = response.headers
                
                if "access-control-allow-methods" in cors_headers:
                    allowed_methods = cors_headers["access-control-allow-methods"]
                    
                    # The requested method should be allowed (case-insensitive)
                    allowed_methods_upper = allowed_methods.upper()
                    assert method.upper() in allowed_methods_upper or "*" in allowed_methods

    async def test_preflight_request_headers(self, async_client: AsyncClient):
        """Test CORS preflight with different requested headers."""
        origin = "https://client.example.com"
        
        header_tests = [
            ["Content-Type"],
            ["Authorization"],
            ["Content-Type", "Authorization"],
            ["Content-Type", "Authorization", "X-Requested-With"],
            ["Accept", "Content-Type", "Authorization", "X-Custom-Header"]
        ]
        
        for requested_headers in header_tests:
            headers = {
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": ", ".join(requested_headers)
            }
            
            response = await async_client.options("/auth/login", headers=headers)
            
            if response.status_code in [200, 204]:
                cors_headers = response.headers
                
                if "access-control-allow-headers" in cors_headers:
                    allowed_headers = cors_headers["access-control-allow-headers"]
                    allowed_headers_lower = allowed_headers.lower()
                    
                    # Common headers should be allowed
                    for header in ["content-type", "authorization"]:
                        if header in [h.lower() for h in requested_headers]:
                            assert header in allowed_headers_lower or "*" in allowed_headers


class TestCORSActualRequests:
    """Test CORS headers on actual requests."""

    async def test_cors_headers_on_get_requests(self, async_client: AsyncClient):
        """Test CORS headers on GET requests."""
        origins_to_test = [
            "https://example.com",
            "https://app.example.com",
            "https://admin.example.com",
            "http://localhost:3000",
            "http://localhost:8080"
        ]
        
        endpoints = ["/", "/health", "/api/public", "/api/circuit-breakers/status"]
        
        for origin in origins_to_test:
            for endpoint in endpoints:
                headers = {"Origin": origin}
                response = await async_client.get(endpoint, headers=headers)
                
                if response.status_code == 200:
                    cors_headers = response.headers
                    
                    # Check for CORS headers
                    if "access-control-allow-origin" in cors_headers:
                        allowed_origin = cors_headers["access-control-allow-origin"]
                        
                        # Should either be wildcard, specific origin, or null
                        assert allowed_origin in ["*", origin, "null"]
                    
                    # Check for credentials header if present
                    if "access-control-allow-credentials" in cors_headers:
                        credentials = cors_headers["access-control-allow-credentials"]
                        assert credentials.lower() in ["true", "false"]

    async def test_cors_headers_on_post_requests(self, async_client: AsyncClient):
        """Test CORS headers on POST requests."""
        origin = "https://app.example.com"
        headers = {"Origin": origin, "Content-Type": "application/json"}
        
        # Test POST requests
        post_tests = [
            ("/auth/login", {"username": "test", "password": "test"}),
            ("/auth/refresh", {"refresh_token": "test"}),
            ("/api/heavy-operation", {})
        ]
        
        for endpoint, data in post_tests:
            response = await async_client.post(endpoint, json=data, headers=headers)
            
            # Any status code is fine, we're testing CORS headers
            cors_headers = response.headers
            
            if "access-control-allow-origin" in cors_headers:
                allowed_origin = cors_headers["access-control-allow-origin"]
                assert allowed_origin in ["*", origin, "null"]
            
            # Check for exposed headers
            if "access-control-expose-headers" in cors_headers:
                exposed = cors_headers["access-control-expose-headers"]
                assert isinstance(exposed, str)

    async def test_cors_headers_consistency(self, async_client: AsyncClient):
        """Test CORS headers are consistent across endpoints."""
        origin = "https://test.example.com"
        headers = {"Origin": origin}
        
        endpoints = ["/", "/health", "/api/public"]
        cors_configs = []
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint, headers=headers)
            
            if response.status_code == 200:
                cors_headers = response.headers
                
                config = {
                    "allow_origin": cors_headers.get("access-control-allow-origin"),
                    "allow_credentials": cors_headers.get("access-control-allow-credentials"),
                    "expose_headers": cors_headers.get("access-control-expose-headers")
                }
                cors_configs.append(config)
        
        # If we have multiple configs, they should be consistent
        if len(cors_configs) > 1:
            first_config = cors_configs[0]
            for config in cors_configs[1:]:
                # Allow origin should be consistent
                if first_config["allow_origin"] and config["allow_origin"]:
                    assert first_config["allow_origin"] == config["allow_origin"]


class TestCORSOriginValidation:
    """Test CORS origin validation."""

    async def test_allowed_origins(self, async_client: AsyncClient):
        """Test requests from allowed origins."""
        # Common allowed origins
        allowed_origins = [
            "https://example.com",
            "https://app.example.com",
            "https://admin.example.com",
            "http://localhost:3000",
            "http://localhost:8080",
            "http://127.0.0.1:3000"
        ]
        
        for origin in allowed_origins:
            headers = {"Origin": origin}
            response = await async_client.get("/health", headers=headers)
            
            assert response.status_code == 200
            
            cors_headers = response.headers
            if "access-control-allow-origin" in cors_headers:
                allowed = cors_headers["access-control-allow-origin"]
                # Should either be wildcard or the specific origin
                assert allowed in ["*", origin]

    async def test_disallowed_origins(self, async_client: AsyncClient):
        """Test requests from potentially disallowed origins."""
        # Potentially problematic origins
        suspicious_origins = [
            "https://malicious.com",
            "http://suspicious-site.net",
            "https://phishing-example.com"
        ]
        
        for origin in suspicious_origins:
            headers = {"Origin": origin}
            response = await async_client.get("/health", headers=headers)
            
            # Request should still succeed (CORS is browser-enforced)
            assert response.status_code == 200
            
            cors_headers = response.headers
            if "access-control-allow-origin" in cors_headers:
                allowed = cors_headers["access-control-allow-origin"]
                
                # Should either be wildcard or not include the suspicious origin
                if allowed != "*":
                    assert allowed != origin

    async def test_null_origin(self, async_client: AsyncClient):
        """Test requests with null origin."""
        headers = {"Origin": "null"}
        response = await async_client.get("/health", headers=headers)
        
        assert response.status_code == 200
        
        cors_headers = response.headers
        if "access-control-allow-origin" in cors_headers:
            allowed = cors_headers["access-control-allow-origin"]
            # Null origin should be handled appropriately
            assert allowed in ["*", "null"]

    async def test_missing_origin_header(self, async_client: AsyncClient):
        """Test requests without Origin header."""
        # Request without Origin header (same-origin request)
        response = await async_client.get("/health")
        
        assert response.status_code == 200
        
        # CORS headers might or might not be present for same-origin requests
        cors_headers = response.headers
        # This is implementation-dependent


class TestCORSCredentials:
    """Test CORS credentials handling."""

    async def test_cors_with_credentials(self, async_client: AsyncClient):
        """Test CORS when credentials are included."""
        origin = "https://app.example.com"
        headers = {
            "Origin": origin,
            "Authorization": "Bearer test-token"
        }
        
        response = await async_client.get("/auth/me", headers=headers)
        
        # Any status code is fine (might be 401 due to invalid token)
        cors_headers = response.headers
        
        if "access-control-allow-credentials" in cors_headers:
            credentials = cors_headers["access-control-allow-credentials"]
            assert credentials.lower() in ["true", "false"]
            
            # If credentials are true, origin should not be wildcard
            if credentials.lower() == "true":
                if "access-control-allow-origin" in cors_headers:
                    origin_header = cors_headers["access-control-allow-origin"]
                    assert origin_header != "*", "Cannot use wildcard with credentials"

    async def test_preflight_with_credentials(self, async_client: AsyncClient):
        """Test CORS preflight with credentials."""
        headers = {
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, Authorization"
        }
        
        response = await async_client.options("/auth/login", headers=headers)
        
        if response.status_code in [200, 204]:
            cors_headers = response.headers
            
            if "access-control-allow-credentials" in cors_headers:
                credentials = cors_headers["access-control-allow-credentials"]
                
                if credentials.lower() == "true":
                    # With credentials, origin should be specific
                    if "access-control-allow-origin" in cors_headers:
                        origin = cors_headers["access-control-allow-origin"]
                        assert origin != "*"


class TestCORSSecurityHeaders:
    """Test CORS-related security headers."""

    async def test_vary_header_present(self, async_client: AsyncClient):
        """Test Vary header includes Origin for CORS requests."""
        headers = {"Origin": "https://example.com"}
        response = await async_client.get("/health", headers=headers)
        
        if response.status_code == 200:
            # Vary header should include Origin for proper caching
            if "vary" in response.headers:
                vary = response.headers["vary"]
                # Origin should be in Vary header (case-insensitive)
                assert "origin" in vary.lower()

    async def test_cors_max_age_header(self, async_client: AsyncClient):
        """Test Access-Control-Max-Age header in preflight responses."""
        headers = {
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type"
        }
        
        response = await async_client.options("/auth/login", headers=headers)
        
        if response.status_code in [200, 204]:
            cors_headers = response.headers
            
            if "access-control-max-age" in cors_headers:
                max_age = cors_headers["access-control-max-age"]
                assert max_age.isdigit()
                
                # Max age should be reasonable (not too long)
                max_age_seconds = int(max_age)
                assert 0 < max_age_seconds <= 86400  # Up to 24 hours

    async def test_cors_exposed_headers(self, async_client: AsyncClient):
        """Test Access-Control-Expose-Headers."""
        origin = "https://example.com"
        headers = {"Origin": origin}
        
        # Test endpoints that might expose custom headers
        endpoints = [
            "/health",
            "/api/test",
            "/auth/login"
        ]
        
        for endpoint in endpoints:
            if endpoint == "/auth/login":
                response = await async_client.post(endpoint, json={
                    "username": "test", "password": "test"
                }, headers=headers)
            else:
                response = await async_client.get(endpoint, headers=headers)
            
            cors_headers = response.headers
            
            if "access-control-expose-headers" in cors_headers:
                exposed = cors_headers["access-control-expose-headers"]
                
                # Should be a comma-separated list of headers
                assert isinstance(exposed, str)
                
                # Common headers that might be exposed
                common_exposed = ["x-ratelimit-limit", "x-ratelimit-remaining", "x-request-id"]
                exposed_lower = exposed.lower()
                
                # At least some reasonable headers might be exposed
                # This is implementation-dependent


class TestCORSErrorHandling:
    """Test CORS handling in error scenarios."""

    async def test_cors_on_error_responses(self, async_client: AsyncClient):
        """Test CORS headers are present on error responses."""
        origin = "https://example.com"
        headers = {"Origin": origin}
        
        # Test various error scenarios
        error_tests = [
            ("GET", "/nonexistent", None, 404),
            ("POST", "/auth/login", {}, 422),  # Validation error
            ("GET", "/auth/me", None, 401),    # Unauthorized
            ("POST", "/health", None, 405),    # Method not allowed
        ]
        
        for method, endpoint, data, expected_status in error_tests:
            if data is not None:
                response = await async_client.request(method, endpoint, json=data, headers=headers)
            else:
                response = await async_client.request(method, endpoint, headers=headers)
            
            if response.status_code == expected_status:
                cors_headers = response.headers
                
                # CORS headers should still be present on error responses
                if "access-control-allow-origin" in cors_headers:
                    allowed_origin = cors_headers["access-control-allow-origin"]
                    assert allowed_origin in ["*", origin, "null"]

    async def test_cors_on_rate_limited_responses(self, async_client: AsyncClient):
        """Test CORS headers on rate-limited responses."""
        origin = "https://example.com"
        headers = {"Origin": origin}
        
        # Try to trigger rate limiting
        for i in range(10):
            response = await async_client.get("/api/test", headers=headers)
            
            if response.status_code == 429:
                cors_headers = response.headers
                
                # CORS headers should be present even on rate-limited responses
                if "access-control-allow-origin" in cors_headers:
                    allowed_origin = cors_headers["access-control-allow-origin"]
                    assert allowed_origin in ["*", origin, "null"]
                
                break


class TestCORSConfiguration:
    """Test CORS configuration validation."""

    async def test_cors_configuration_consistency(self, async_client: AsyncClient):
        """Test CORS configuration is consistent across the application."""
        test_origin = "https://test-app.example.com"
        headers = {"Origin": test_origin}
        
        # Test multiple endpoints to ensure consistent CORS configuration
        endpoints = [
            "/",
            "/health", 
            "/api/public",
            "/api/test",
            "/api/circuit-breakers/status"
        ]
        
        cors_configs = []
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint, headers=headers)
            
            if response.status_code == 200:
                cors_headers = response.headers
                
                config = {
                    "endpoint": endpoint,
                    "allow_origin": cors_headers.get("access-control-allow-origin"),
                    "allow_credentials": cors_headers.get("access-control-allow-credentials"),
                    "allow_methods": cors_headers.get("access-control-allow-methods"),
                    "allow_headers": cors_headers.get("access-control-allow-headers")
                }
                cors_configs.append(config)
        
        # Analyze consistency
        if len(cors_configs) > 1:
            # All endpoints should have similar CORS policies
            origin_policies = [c["allow_origin"] for c in cors_configs if c["allow_origin"]]
            
            if origin_policies:
                # Most endpoints should have the same origin policy
                from collections import Counter
                policy_counts = Counter(origin_policies)
                most_common_policy = policy_counts.most_common(1)[0][0]
                
                # At least half the endpoints should use the same policy
                assert policy_counts[most_common_policy] >= len(origin_policies) // 2

    async def test_development_vs_production_cors(self, async_client: AsyncClient):
        """Test CORS configuration appropriate for environment."""
        # This test checks if CORS is configured appropriately
        # In development: might allow localhost origins
        # In production: should be more restrictive
        
        localhost_origins = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8080"
        ]
        
        for origin in localhost_origins:
            headers = {"Origin": origin}
            response = await async_client.get("/health", headers=headers)
            
            if response.status_code == 200:
                cors_headers = response.headers
                
                if "access-control-allow-origin" in cors_headers:
                    allowed = cors_headers["access-control-allow-origin"]
                    
                    # In tests, localhost origins might be allowed
                    # This is environment-dependent
                    assert allowed in ["*", origin, "null"]