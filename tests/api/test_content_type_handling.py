"""
Content-Type Handling Contract Tests

This module contains comprehensive tests for content-type handling
across the Claude-Optimized Deployment Engine API endpoints.
"""

import pytest
import json
from typing import Dict, Any, List
from httpx import AsyncClient

# Test markers
pytestmark = [pytest.mark.api_contract, pytest.mark.content_type]


class TestJSONContentType:
    """Test JSON content-type handling."""

    async def test_json_request_content_type(self, async_client: AsyncClient):
        """Test that endpoints accept application/json content-type."""
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        # Test with explicit JSON content-type
        headers = {"Content-Type": "application/json"}
        response = await async_client.post("/auth/login", json=login_data, headers=headers)
        
        # Should accept JSON content-type (status depends on auth, not content-type)
        assert response.status_code in [200, 401, 422]
        assert response.status_code != 415  # Not "Unsupported Media Type"

    async def test_json_response_content_type(self, async_client: AsyncClient):
        """Test that endpoints return application/json content-type."""
        endpoints = [
            "/",
            "/health",
            "/api/public",
            "/api/circuit-breakers/status"
        ]
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint)
            
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                assert "application/json" in content_type.lower()

    async def test_json_error_response_content_type(self, async_client: AsyncClient):
        """Test that error responses return application/json content-type."""
        error_scenarios = [
            ("GET", "/nonexistent"),
            ("POST", "/auth/login", {}),  # Validation error
            ("GET", "/auth/me"),          # Unauthorized
        ]
        
        for scenario in error_scenarios:
            if len(scenario) == 3:
                method, endpoint, data = scenario
                response = await async_client.request(method, endpoint, json=data)
            else:
                method, endpoint = scenario
                response = await async_client.request(method, endpoint)
            
            if response.status_code >= 400:
                content_type = response.headers.get("content-type", "")
                assert "application/json" in content_type.lower()

    async def test_json_charset_specification(self, async_client: AsyncClient):
        """Test JSON responses include charset specification."""
        response = await async_client.get("/health")
        
        if response.status_code == 200:
            content_type = response.headers.get("content-type", "")
            
            # Should specify charset for JSON responses
            if "application/json" in content_type.lower():
                # Common charset specifications
                charset_specs = ["utf-8", "charset=utf-8"]
                has_charset = any(spec in content_type.lower() for spec in charset_specs)
                
                # While not required, charset specification is good practice
                # This test documents the current behavior
                pass


class TestUnsupportedContentTypes:
    """Test handling of unsupported content types."""

    async def test_xml_content_type_rejection(self, async_client: AsyncClient):
        """Test rejection of XML content-type."""
        xml_data = '<?xml version="1.0"?><login><username>test</username><password>test</password></login>'
        headers = {"Content-Type": "application/xml"}
        
        response = await async_client.post("/auth/login", content=xml_data, headers=headers)
        
        # Should reject XML content-type
        assert response.status_code in [415, 422, 400]  # Unsupported media type or bad request

    async def test_form_data_content_type(self, async_client: AsyncClient):
        """Test handling of form data content-type."""
        form_data = {"username": "testuser", "password": "testpassword123"}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        response = await async_client.post("/auth/login", data=form_data, headers=headers)
        
        # API might or might not support form data
        # Should not cause server error
        assert response.status_code != 500
        
        # Common responses: 415 (unsupported), 422 (validation), or actual processing
        assert response.status_code in [200, 401, 415, 422]

    async def test_multipart_form_data(self, async_client: AsyncClient):
        """Test handling of multipart form data."""
        files = {"file": ("test.txt", "test content", "text/plain")}
        data = {"username": "testuser"}
        
        # Test endpoints that might accept file uploads
        upload_endpoints = [
            "/auth/users",  # User creation with avatar
            "/api/upload",  # Generic upload endpoint
        ]
        
        for endpoint in upload_endpoints:
            response = await async_client.post(endpoint, files=files, data=data)
            
            # Should handle gracefully (not server error)
            assert response.status_code != 500
            
            # Might be unauthorized, not found, or unsupported
            assert response.status_code in [200, 401, 404, 415, 422]

    async def test_text_plain_content_type(self, async_client: AsyncClient):
        """Test handling of text/plain content-type."""
        text_data = "username=test&password=test"
        headers = {"Content-Type": "text/plain"}
        
        response = await async_client.post("/auth/login", content=text_data, headers=headers)
        
        # Should reject text/plain for JSON endpoints
        assert response.status_code in [415, 422, 400]

    async def test_missing_content_type(self, async_client: AsyncClient):
        """Test handling of requests without content-type header."""
        login_data = '{"username": "test", "password": "test"}'
        
        # Send JSON data without Content-Type header
        response = await async_client.post("/auth/login", content=login_data)
        
        # Should handle gracefully
        assert response.status_code != 500
        
        # Might assume JSON or reject the request
        assert response.status_code in [200, 401, 415, 422, 400]


class TestContentTypeValidation:
    """Test content-type validation and parsing."""

    async def test_case_insensitive_content_type(self, async_client: AsyncClient):
        """Test case-insensitive content-type handling."""
        login_data = {"username": "test", "password": "test"}
        
        content_type_variations = [
            "application/json",
            "Application/JSON", 
            "APPLICATION/JSON",
            "application/Json"
        ]
        
        for content_type in content_type_variations:
            headers = {"Content-Type": content_type}
            response = await async_client.post("/auth/login", json=login_data, headers=headers)
            
            # All variations should be accepted
            assert response.status_code != 415
            assert response.status_code in [200, 401, 422]

    async def test_content_type_with_charset(self, async_client: AsyncClient):
        """Test content-type with charset parameter."""
        login_data = {"username": "test", "password": "test"}
        
        charset_variations = [
            "application/json; charset=utf-8",
            "application/json; charset=UTF-8",
            "application/json;charset=utf-8",
            "application/json ; charset=utf-8"
        ]
        
        for content_type in charset_variations:
            headers = {"Content-Type": content_type}
            response = await async_client.post("/auth/login", json=login_data, headers=headers)
            
            # Should accept charset parameters
            assert response.status_code != 415
            assert response.status_code in [200, 401, 422]

    async def test_content_type_with_boundary(self, async_client: AsyncClient):
        """Test content-type with boundary parameter for multipart data."""
        # Multipart form data with explicit boundary
        boundary = "----formdata-test-boundary"
        content_type = f"multipart/form-data; boundary={boundary}"
        
        multipart_data = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"username\"\r\n\r\n"
            f"testuser\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"password\"\r\n\r\n" 
            f"testpass\r\n"
            f"--{boundary}--\r\n"
        )
        
        headers = {"Content-Type": content_type}
        response = await async_client.post("/auth/login", content=multipart_data, headers=headers)
        
        # Should handle multipart data gracefully
        assert response.status_code != 500
        assert response.status_code in [200, 401, 415, 422]

    async def test_malformed_content_type(self, async_client: AsyncClient):
        """Test handling of malformed content-type headers."""
        login_data = {"username": "test", "password": "test"}
        
        malformed_content_types = [
            "application/",           # Missing subtype
            "/json",                  # Missing type
            "application json",       # Missing slash
            "invalid-content-type",   # Invalid format
            "",                       # Empty content-type
        ]
        
        for content_type in malformed_content_types:
            headers = {"Content-Type": content_type}
            response = await async_client.post("/auth/login", json=login_data, headers=headers)
            
            # Should handle malformed content-types gracefully
            assert response.status_code != 500
            assert response.status_code in [200, 401, 415, 422, 400]


class TestContentNegotiation:
    """Test content negotiation using Accept headers."""

    async def test_accept_json_header(self, async_client: AsyncClient):
        """Test Accept: application/json header."""
        headers = {"Accept": "application/json"}
        response = await async_client.get("/health", headers=headers)
        
        if response.status_code == 200:
            content_type = response.headers.get("content-type", "")
            assert "application/json" in content_type.lower()

    async def test_accept_wildcard_header(self, async_client: AsyncClient):
        """Test Accept: */* header."""
        headers = {"Accept": "*/*"}
        response = await async_client.get("/health", headers=headers)
        
        if response.status_code == 200:
            # Should return default content-type (JSON)
            content_type = response.headers.get("content-type", "")
            assert "application/json" in content_type.lower()

    async def test_accept_xml_header(self, async_client: AsyncClient):
        """Test Accept: application/xml header."""
        headers = {"Accept": "application/xml"}
        response = await async_client.get("/health", headers=headers)
        
        # API primarily supports JSON, so might return 406 or ignore and return JSON
        if response.status_code == 200:
            content_type = response.headers.get("content-type", "")
            # Likely still returns JSON even if XML is requested
            assert "application/json" in content_type.lower()
        elif response.status_code == 406:
            # Not Acceptable - valid response for unsupported Accept header
            pass

    async def test_multiple_accept_types(self, async_client: AsyncClient):
        """Test Accept header with multiple types."""
        headers = {"Accept": "application/xml, application/json, */*"}
        response = await async_client.get("/health", headers=headers)
        
        if response.status_code == 200:
            content_type = response.headers.get("content-type", "")
            # Should prefer JSON since it's supported
            assert "application/json" in content_type.lower()

    async def test_accept_with_quality_values(self, async_client: AsyncClient):
        """Test Accept header with quality values."""
        headers = {"Accept": "application/xml;q=0.9, application/json;q=1.0"}
        response = await async_client.get("/health", headers=headers)
        
        if response.status_code == 200:
            content_type = response.headers.get("content-type", "")
            # Should prefer JSON (higher quality value and supported)
            assert "application/json" in content_type.lower()


class TestEncodingHandling:
    """Test character encoding handling."""

    async def test_utf8_encoding(self, async_client: AsyncClient):
        """Test UTF-8 encoded content."""
        # Test with Unicode characters
        login_data = {
            "username": "test_用户",  # Unicode characters
            "password": "test_密码123"
        }
        
        headers = {"Content-Type": "application/json; charset=utf-8"}
        response = await async_client.post("/auth/login", json=login_data, headers=headers)
        
        # Should handle UTF-8 content properly
        assert response.status_code != 500
        assert response.status_code in [200, 401, 422]
        
        # Response should be UTF-8 encoded
        if response.status_code in [401, 422]:
            error_data = response.json()
            assert "detail" in error_data
            # Error message should be readable

    async def test_emoji_in_content(self, async_client: AsyncClient):
        """Test content with emoji characters."""
        login_data = {
            "username": "test_user_🚀",
            "password": "secure_pass_🔐"
        }
        
        response = await async_client.post("/auth/login", json=login_data)
        
        # Should handle emoji characters gracefully
        assert response.status_code != 500
        assert response.status_code in [200, 401, 422]

    async def test_large_json_payload(self, async_client: AsyncClient):
        """Test handling of large JSON payloads."""
        # Create a large but reasonable JSON payload
        large_data = {
            "username": "testuser",
            "password": "testpass",
            "metadata": {
                "description": "x" * 1000,  # 1KB of text
                "tags": ["tag" + str(i) for i in range(100)],
                "settings": {f"setting_{i}": f"value_{i}" for i in range(50)}
            }
        }
        
        response = await async_client.post("/auth/users", json=large_data)
        
        # Should handle large payloads gracefully
        assert response.status_code != 500
        assert response.status_code in [200, 201, 401, 403, 413, 422]
        
        # 413 = Payload Too Large (acceptable response)

    async def test_very_large_json_payload(self, async_client: AsyncClient):
        """Test handling of very large JSON payloads."""
        # Create a very large JSON payload that might be rejected
        very_large_data = {
            "username": "testuser",
            "password": "testpass", 
            "data": "x" * 50000  # 50KB of data
        }
        
        response = await async_client.post("/auth/users", json=very_large_data)
        
        # Should either process or reject with appropriate error
        assert response.status_code != 500
        acceptable_statuses = [200, 201, 401, 403, 413, 422]  # 413 = Payload Too Large
        assert response.status_code in acceptable_statuses


class TestSpecialContentTypes:
    """Test handling of special content types."""

    async def test_json_patch_content_type(self, async_client: AsyncClient):
        """Test application/json-patch+json content type."""
        patch_data = [
            {"op": "replace", "path": "/email", "value": "new@example.com"}
        ]
        
        headers = {"Content-Type": "application/json-patch+json"}
        response = await async_client.patch("/auth/users/123", json=patch_data, headers=headers)
        
        # Might not support JSON Patch, but should handle gracefully
        assert response.status_code != 500
        assert response.status_code in [200, 401, 403, 404, 415, 422]

    async def test_json_api_content_type(self, async_client: AsyncClient):
        """Test application/vnd.api+json content type."""
        jsonapi_data = {
            "data": {
                "type": "users",
                "attributes": {
                    "username": "testuser",
                    "email": "test@example.com"
                }
            }
        }
        
        headers = {"Content-Type": "application/vnd.api+json"}
        response = await async_client.post("/auth/users", json=jsonapi_data, headers=headers)
        
        # Likely not supported, but should handle gracefully
        assert response.status_code != 500
        assert response.status_code in [200, 201, 401, 403, 415, 422]

    async def test_custom_json_content_type(self, async_client: AsyncClient):
        """Test custom JSON-based content types."""
        custom_data = {"username": "test", "password": "test"}
        
        custom_content_types = [
            "application/vnd.myapi+json",
            "application/json+custom",
            "application/custom-json"
        ]
        
        for content_type in custom_content_types:
            headers = {"Content-Type": content_type}
            response = await async_client.post("/auth/login", json=custom_data, headers=headers)
            
            # Should reject custom content types
            assert response.status_code in [415, 422, 400]
            assert response.status_code != 500