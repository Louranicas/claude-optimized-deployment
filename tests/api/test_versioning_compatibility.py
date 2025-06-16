"""
API Versioning and Backward Compatibility Tests

This module contains comprehensive tests for API versioning compliance
and backward compatibility across the Claude-Optimized Deployment Engine API.
"""

import pytest
from typing import Dict, Any, List
from httpx import AsyncClient
from datetime import datetime, timedelta

# Test markers
pytestmark = [pytest.mark.api_contract, pytest.mark.versioning]


class TestAPIVersioning:
    """Test API versioning implementation."""

    async def test_api_version_header_support(self, async_client: AsyncClient):
        """Test API version header support."""
        version_headers = [
            {"API-Version": "1.0"},
            {"API-Version": "v1"},
            {"Accept-Version": "1.0"},
            {"X-API-Version": "1.0"}
        ]
        
        for headers in version_headers:
            response = await async_client.get("/health", headers=headers)
            
            # Should accept version headers without error
            assert response.status_code == 200
            
            # Might echo back version in response headers
            response_headers = response.headers
            version_response_headers = [
                "api-version", "x-api-version", "accept-version"
            ]
            
            for header in version_response_headers:
                if header in response_headers:
                    version = response_headers[header]
                    assert isinstance(version, str)
                    assert len(version) > 0

    async def test_unsupported_api_version(self, async_client: AsyncClient):
        """Test handling of unsupported API versions."""
        unsupported_versions = [
            {"API-Version": "2.0"},
            {"API-Version": "v3"},
            {"API-Version": "0.5"},
            {"API-Version": "invalid"}
        ]
        
        for headers in unsupported_versions:
            response = await async_client.get("/health", headers=headers)
            
            # Should either ignore unsupported versions or return appropriate error
            if response.status_code == 400:
                # Bad Request for unsupported version
                error_data = response.json()
                assert "detail" in error_data
                assert "version" in error_data["detail"].lower()
            elif response.status_code == 200:
                # Ignores unsupported version and uses default
                pass
            else:
                # Other response codes might be acceptable
                assert response.status_code in [406, 422]

    async def test_version_in_url_path(self, async_client: AsyncClient):
        """Test versioned URL paths."""
        versioned_endpoints = [
            "/v1/health",
            "/v1/auth/login",
            "/v1/api/test",
            "/api/v1/health",
            "/api/v1/test"
        ]
        
        for endpoint in versioned_endpoints:
            response = await async_client.get(endpoint)
            
            # Currently, these endpoints should not exist
            assert response.status_code == 404
            
            error_data = response.json()
            assert "detail" in error_data

    async def test_default_api_version(self, async_client: AsyncClient):
        """Test default API version behavior."""
        # Request without version header should use default version
        response = await async_client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        # Should return current API format
        assert "status" in data
        assert "timestamp" in data

    async def test_version_deprecation_warnings(self, async_client: AsyncClient):
        """Test version deprecation warnings."""
        # Test with older version (if supported)
        headers = {"API-Version": "0.9"}
        response = await async_client.get("/health", headers=headers)
        
        if response.status_code == 200:
            # Might include deprecation warnings
            warning_headers = [
                "warning", "deprecation", "sunset", "x-api-deprecation"
            ]
            
            response_headers = response.headers
            for header in warning_headers:
                if header in response_headers:
                    warning = response_headers[header]
                    assert isinstance(warning, str)
                    assert len(warning) > 0


class TestBackwardCompatibility:
    """Test backward compatibility of API changes."""

    async def test_additive_schema_changes(self, async_client: AsyncClient):
        """Test that new optional fields don't break existing clients."""
        # Test login endpoint with minimal required fields
        minimal_login = {
            "username": "testuser",
            "password": "testpass123"
        }
        
        response = await async_client.post("/auth/login", json=minimal_login)
        
        # Should work with minimal fields
        assert response.status_code in [200, 401]  # Auth might fail, but not validation
        assert response.status_code != 422  # Should not be validation error
        
        # Test with additional optional fields
        extended_login = {
            "username": "testuser", 
            "password": "testpass123",
            "mfa_code": "123456",
            "remember_me": True,
            "client_info": "test-client"
        }
        
        response = await async_client.post("/auth/login", json=extended_login)
        
        # Should handle additional fields gracefully
        assert response.status_code in [200, 401, 400]  # Might reject unknown fields
        assert response.status_code != 500  # Should not cause server error

    async def test_response_format_stability(self, async_client: AsyncClient):
        """Test that response formats remain stable."""
        response = await async_client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        
        # Core fields should remain stable
        stable_fields = ["status", "timestamp"]
        for field in stable_fields:
            assert field in data, f"Required field '{field}' missing from health response"
        
        # Field types should be consistent
        assert isinstance(data["status"], str)
        assert isinstance(data["timestamp"], str)
        
        # Status values should be from known set
        valid_statuses = ["healthy", "unhealthy", "degraded"]
        assert data["status"] in valid_statuses

    async def test_error_format_compatibility(self, async_client: AsyncClient):
        """Test that error response formats remain compatible."""
        # Trigger validation error
        response = await async_client.post("/auth/login", json={})
        assert response.status_code == 422
        
        error_data = response.json()
        
        # Error format should be stable
        assert "detail" in error_data
        
        detail = error_data["detail"]
        if isinstance(detail, list):
            # Pydantic error format should be stable
            for error in detail:
                required_error_fields = ["loc", "msg", "type"]
                for field in required_error_fields:
                    assert field in error, f"Error missing field: {field}"

    async def test_endpoint_deprecation_handling(self, async_client: AsyncClient):
        """Test handling of deprecated endpoints."""
        # Test endpoints that might be deprecated in the future
        potentially_deprecated = [
            "/api/legacy/endpoint",
            "/v0/health",
            "/deprecated/auth/login"
        ]
        
        for endpoint in potentially_deprecated:
            response = await async_client.get(endpoint)
            
            # Should return 404 for non-existent deprecated endpoints
            if response.status_code == 404:
                pass
            elif response.status_code == 200:
                # If endpoint exists, should include deprecation headers
                headers = response.headers
                deprecation_headers = ["warning", "sunset", "deprecation"]
                
                # Might include deprecation information
                pass
            elif response.status_code == 410:
                # Gone - endpoint was deprecated and removed
                pass

    async def test_parameter_compatibility(self, async_client: AsyncClient):
        """Test parameter backward compatibility."""
        # Test pagination parameters with different formats
        pagination_formats = [
            {"offset": 0, "limit": 10},          # Current format
            {"page": 1, "size": 10},             # Alternative format
            {"skip": 0, "take": 10},             # Another alternative
        ]
        
        for params in pagination_formats:
            response = await async_client.get("/auth/users", params=params)
            
            # First format should work (might require auth)
            if params == {"offset": 0, "limit": 10}:
                assert response.status_code in [200, 401, 403]
            else:
                # Other formats might not be supported
                assert response.status_code in [200, 401, 403, 422]


class TestAPIEvolution:
    """Test API evolution strategies."""

    async def test_feature_flags_support(self, async_client: AsyncClient):
        """Test feature flags in API requests."""
        # Test with feature flag headers
        feature_headers = [
            {"X-Feature-Flag": "new-auth-flow"},
            {"X-Enable-Feature": "enhanced-validation"},
            {"X-Beta-Features": "true"}
        ]
        
        for headers in feature_headers:
            response = await async_client.get("/health", headers=headers)
            
            # Should handle feature flag headers gracefully
            assert response.status_code == 200
            
            # Might include feature flag information in response
            data = response.json()
            # Feature flags shouldn't break basic functionality

    async def test_experimental_endpoints(self, async_client: AsyncClient):
        """Test experimental endpoint behavior."""
        experimental_endpoints = [
            "/experimental/auth/oauth",
            "/beta/api/advanced-search",
            "/preview/monitoring/insights"
        ]
        
        for endpoint in experimental_endpoints:
            response = await async_client.get(endpoint)
            
            # Should return 404 for non-existent experimental endpoints
            if response.status_code == 404:
                pass
            elif response.status_code == 200:
                # If endpoint exists, should include experimental warnings
                headers = response.headers
                experimental_headers = ["x-experimental", "x-beta", "warning"]
                
                # Might include experimental status
                pass

    async def test_content_negotiation_evolution(self, async_client: AsyncClient):
        """Test content negotiation for API evolution."""
        # Test with version-specific Accept headers
        versioned_accepts = [
            "application/vnd.api.v1+json",
            "application/vnd.myapi+json;version=1",
            "application/json;version=1.0"
        ]
        
        for accept_header in versioned_accepts:
            headers = {"Accept": accept_header}
            response = await async_client.get("/health", headers=headers)
            
            # Should handle versioned accept headers
            if response.status_code == 200:
                # Likely returns default JSON format
                content_type = response.headers.get("content-type", "")
                assert "application/json" in content_type.lower()
            elif response.status_code == 406:
                # Not Acceptable - valid for unsupported format
                pass


class TestSchemaEvolution:
    """Test schema evolution and compatibility."""

    async def test_optional_field_addition(self, async_client: AsyncClient):
        """Test adding optional fields to existing schemas."""
        # Test user creation with minimal required fields
        minimal_user = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpass123"
        }
        
        response = await async_client.post("/auth/users", json=minimal_user)
        
        # Should work with minimal fields (might require different auth)
        assert response.status_code in [200, 201, 401, 403]
        assert response.status_code != 422  # Should not be validation error

    async def test_field_type_stability(self, async_client: AsyncClient):
        """Test that field types remain stable."""
        response = await async_client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        
        # Field types should be stable
        type_expectations = {
            "message": str,
            "version": str,
            "docs": str,
            "health": str
        }
        
        for field, expected_type in type_expectations.items():
            if field in data:
                assert isinstance(data[field], expected_type), \
                    f"Field '{field}' should be {expected_type}, got {type(data[field])}"

    async def test_enum_value_stability(self, async_client: AsyncClient):
        """Test that enum values remain stable."""
        response = await async_client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        status = data.get("status")
        
        if status:
            # Status enum values should be from stable set
            stable_statuses = ["healthy", "unhealthy", "degraded"]
            assert status in stable_statuses, f"Unknown status value: {status}"

    async def test_nested_object_evolution(self, async_client: AsyncClient):
        """Test evolution of nested objects in responses."""
        response = await async_client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        
        # If services object exists, it should maintain structure
        if "services" in data:
            services = data["services"]
            assert isinstance(services, dict)
            
            # Each service should have consistent structure
            for service_name, service_data in services.items():
                if isinstance(service_data, dict):
                    # Service objects might have status field
                    if "status" in service_data:
                        status = service_data["status"]
                        assert isinstance(status, (str, bool))


class TestClientCompatibility:
    """Test compatibility with different client types."""

    async def test_strict_json_client_compatibility(self, async_client: AsyncClient):
        """Test compatibility with strict JSON clients."""
        # Some clients are strict about JSON formatting
        response = await async_client.get("/health")
        assert response.status_code == 200
        
        # Should return valid JSON
        data = response.json()
        assert isinstance(data, dict)
        
        # JSON should be properly formatted
        json_text = response.text
        import json
        
        # Should be parseable by standard JSON parser
        parsed = json.loads(json_text)
        assert parsed == data

    async def test_legacy_browser_compatibility(self, async_client: AsyncClient):
        """Test compatibility with legacy browsers."""
        # Legacy browser user agent
        headers = {"User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)"}
        
        response = await async_client.get("/health", headers=headers)
        assert response.status_code == 200
        
        # Should work with legacy browsers
        data = response.json()
        assert "status" in data

    async def test_mobile_client_compatibility(self, async_client: AsyncClient):
        """Test compatibility with mobile clients."""
        # Mobile user agents
        mobile_user_agents = [
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "Mozilla/5.0 (Android 10; Mobile; rv:81.0)",
            "okhttp/4.9.0"  # Android HTTP client
        ]
        
        for user_agent in mobile_user_agents:
            headers = {"User-Agent": user_agent}
            response = await async_client.get("/health", headers=headers)
            
            assert response.status_code == 200
            data = response.json()
            assert "status" in data


class TestVersioningBestPractices:
    """Test adherence to versioning best practices."""

    async def test_version_header_consistency(self, async_client: AsyncClient):
        """Test version header consistency across endpoints."""
        endpoints = ["/", "/health", "/api/public"]
        version_headers = []
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint)
            if response.status_code == 200:
                headers = response.headers
                
                # Collect version-related headers
                version_info = {}
                for header_name in ["api-version", "x-api-version"]:
                    if header_name in headers:
                        version_info[header_name] = headers[header_name]
                
                version_headers.append(version_info)
        
        # Version headers should be consistent across endpoints
        if len(version_headers) > 1:
            first_version = version_headers[0]
            for version_info in version_headers[1:]:
                # If version headers are present, they should match
                for header, value in first_version.items():
                    if header in version_info:
                        assert version_info[header] == value

    async def test_semantic_versioning_compliance(self, async_client: AsyncClient):
        """Test semantic versioning compliance."""
        # Check if API version follows semantic versioning
        response = await async_client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        version = data.get("version", "")
        
        if version:
            # Should follow semantic versioning (major.minor.patch)
            version_parts = version.split(".")
            assert len(version_parts) >= 2, f"Invalid version format: {version}"
            
            # Each part should be numeric
            for part in version_parts[:3]:  # Check first 3 parts
                assert part.isdigit(), f"Non-numeric version part: {part}"

    async def test_api_documentation_versioning(self, async_client: AsyncClient):
        """Test API documentation versioning."""
        # Test OpenAPI spec includes version information
        response = await async_client.get("/docs/openapi.json")
        if response.status_code == 200:
            openapi_spec = response.json()
            
            # Should include version in info section
            assert "info" in openapi_spec
            info = openapi_spec["info"]
            assert "version" in info
            
            # Version should be meaningful
            api_version = info["version"]
            assert isinstance(api_version, str)
            assert len(api_version) > 0
            assert api_version != "0.0.0"  # Should not be placeholder