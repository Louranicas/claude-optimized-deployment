"""
OpenAPI Schema Validation Tests

This module contains comprehensive tests for OpenAPI schema validation
across all FastAPI endpoints in the Claude-Optimized Deployment Engine.
"""

import pytest
import json
from typing import Dict, Any, List
from httpx import AsyncClient
from fastapi.testclient import TestClient
from jsonschema import validate, ValidationError
from jsonschema.validators import Draft7Validator

# Test markers
pytestmark = [pytest.mark.api_contract, pytest.mark.schema]


class TestOpenAPISchemaValidation:
    """Test OpenAPI schema validation for all endpoints."""

    @pytest.fixture
    def openapi_spec(self, sync_client: TestClient) -> Dict[str, Any]:
        """Get the OpenAPI specification."""
        response = sync_client.get("/docs/openapi.json")
        assert response.status_code == 200
        return response.json()

    @pytest.fixture
    def validator(self, openapi_spec: Dict[str, Any]) -> Draft7Validator:
        """Create a JSON schema validator for OpenAPI spec."""
        return Draft7Validator(openapi_spec)

    def test_openapi_spec_is_valid(self, openapi_spec: Dict[str, Any]):
        """Test that the OpenAPI specification itself is valid."""
        # Check required OpenAPI fields
        assert "openapi" in openapi_spec
        assert "info" in openapi_spec
        assert "paths" in openapi_spec
        
        # Validate OpenAPI version
        assert openapi_spec["openapi"].startswith("3.0")
        
        # Validate info section
        info = openapi_spec["info"]
        assert "title" in info
        assert "version" in info
        assert info["title"] == "Claude-Optimized Deployment Engine"

    def test_all_endpoints_have_schemas(self, openapi_spec: Dict[str, Any]):
        """Test that all endpoints have proper request/response schemas."""
        paths = openapi_spec.get("paths", {})
        
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method in ["get", "post", "put", "delete", "patch"]:
                    # Check operation has operationId
                    assert "operationId" in operation, f"Missing operationId for {method.upper()} {path}"
                    
                    # Check responses are defined
                    assert "responses" in operation, f"Missing responses for {method.upper()} {path}"
                    
                    # Check 200 response exists (except for DELETE operations)
                    responses = operation["responses"]
                    if method != "delete":
                        assert "200" in responses or "201" in responses, \
                            f"Missing success response for {method.upper()} {path}"

    def test_authentication_endpoints_schema(self, openapi_spec: Dict[str, Any]):
        """Test authentication endpoints have proper schemas."""
        paths = openapi_spec.get("paths", {})
        
        auth_endpoints = [
            "/auth/login",
            "/auth/refresh",
            "/auth/logout",
            "/auth/me",
            "/auth/users",
        ]
        
        for endpoint in auth_endpoints:
            assert endpoint in paths, f"Auth endpoint {endpoint} not found in OpenAPI spec"
            
            endpoint_spec = paths[endpoint]
            
            # Test POST /auth/login
            if endpoint == "/auth/login" and "post" in endpoint_spec:
                post_spec = endpoint_spec["post"]
                
                # Should have request body
                assert "requestBody" in post_spec
                request_body = post_spec["requestBody"]
                assert "content" in request_body
                assert "application/json" in request_body["content"]
                
                # Should have schema reference or inline schema
                content = request_body["content"]["application/json"]
                assert "schema" in content
                
                # Should have responses
                responses = post_spec["responses"]
                assert "200" in responses  # Success response
                assert "401" in responses  # Unauthorized response

    def test_circuit_breaker_endpoints_schema(self, openapi_spec: Dict[str, Any]):
        """Test circuit breaker endpoints have proper schemas."""
        paths = openapi_spec.get("paths", {})
        
        cb_endpoints = [
            "/api/circuit-breakers/status",
            "/api/circuit-breakers/breakers",
            "/api/circuit-breakers/health",
        ]
        
        for endpoint in cb_endpoints:
            if endpoint in paths:
                endpoint_spec = paths[endpoint]
                
                # Test GET endpoints
                if "get" in endpoint_spec:
                    get_spec = endpoint_spec["get"]
                    
                    # Should have responses
                    assert "responses" in get_spec
                    responses = get_spec["responses"]
                    assert "200" in responses
                    
                    # Response should have content
                    success_response = responses["200"]
                    assert "content" in success_response
                    assert "application/json" in success_response["content"]

    def test_monitoring_endpoints_schema(self, openapi_spec: Dict[str, Any]):
        """Test monitoring endpoints have proper schemas."""
        paths = openapi_spec.get("paths", {})
        
        monitoring_endpoints = [
            "/monitoring/health",
            "/monitoring/metrics",
            "/monitoring/alerts",
        ]
        
        for endpoint in monitoring_endpoints:
            if endpoint in paths:
                endpoint_spec = paths[endpoint]
                
                # All monitoring endpoints should be GET
                if "get" in endpoint_spec:
                    get_spec = endpoint_spec["get"]
                    
                    # Should have proper tags
                    assert "tags" in get_spec
                    tags = get_spec["tags"]
                    assert any("monitoring" in tag.lower() for tag in tags)

    def test_error_responses_schema(self, openapi_spec: Dict[str, Any]):
        """Test that error responses have consistent schemas."""
        paths = openapi_spec.get("paths", {})
        
        common_error_codes = ["400", "401", "403", "404", "422", "429", "500"]
        
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method in ["get", "post", "put", "delete", "patch"]:
                    responses = operation.get("responses", {})
                    
                    for error_code in common_error_codes:
                        if error_code in responses:
                            error_response = responses[error_code]
                            
                            # Error responses should have description
                            assert "description" in error_response, \
                                f"Missing description for {error_code} response in {method.upper()} {path}"
                            
                            # Should have content for most error responses
                            if error_code not in ["204", "304"]:
                                if "content" in error_response:
                                    content = error_response["content"]
                                    assert "application/json" in content

    def test_pydantic_models_in_components(self, openapi_spec: Dict[str, Any]):
        """Test that Pydantic models are properly defined in components."""
        components = openapi_spec.get("components", {})
        schemas = components.get("schemas", {})
        
        # Check for expected Pydantic models
        expected_models = [
            "LoginRequest",
            "LoginResponse",
            "User",
            "HTTPValidationError",
            "ValidationError",
        ]
        
        for model in expected_models:
            if model in schemas:
                schema = schemas[model]
                
                # Should have type or properties
                assert "type" in schema or "properties" in schema, \
                    f"Schema {model} missing type or properties"
                
                # If it has properties, should specify required fields
                if "properties" in schema:
                    properties = schema["properties"]
                    assert isinstance(properties, dict), \
                        f"Properties in {model} should be a dict"

    def test_security_schemes_defined(self, openapi_spec: Dict[str, Any]):
        """Test that security schemes are properly defined."""
        components = openapi_spec.get("components", {})
        
        if "securitySchemes" in components:
            security_schemes = components["securitySchemes"]
            
            # Should have bearer token authentication
            bearer_found = False
            for scheme_name, scheme in security_schemes.items():
                if scheme.get("type") == "http" and scheme.get("scheme") == "bearer":
                    bearer_found = True
                    assert "bearerFormat" in scheme, f"Bearer scheme {scheme_name} missing bearerFormat"
            
            assert bearer_found, "No bearer token authentication scheme found"

    def test_parameter_validation_schemas(self, openapi_spec: Dict[str, Any]):
        """Test that path and query parameters have proper validation schemas."""
        paths = openapi_spec.get("paths", {})
        
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method in ["get", "post", "put", "delete", "patch"]:
                    parameters = operation.get("parameters", [])
                    
                    for param in parameters:
                        # Each parameter should have required fields
                        assert "name" in param, f"Parameter missing name in {method.upper()} {path}"
                        assert "in" in param, f"Parameter missing 'in' field in {method.upper()} {path}"
                        
                        # Should have schema for validation
                        if "schema" in param:
                            schema = param["schema"]
                            assert "type" in schema, \
                                f"Parameter {param['name']} missing type in {method.upper()} {path}"

    @pytest.mark.slow
    async def test_openapi_json_endpoint(self, async_client: AsyncClient):
        """Test that the OpenAPI JSON endpoint is accessible."""
        response = await async_client.get("/docs/openapi.json")
        assert response.status_code == 200
        
        # Should return valid JSON
        openapi_spec = response.json()
        assert isinstance(openapi_spec, dict)
        
        # Should have correct content type
        assert response.headers["content-type"] == "application/json"

    async def test_docs_endpoints_accessible(self, async_client: AsyncClient):
        """Test that documentation endpoints are accessible."""
        # Test Swagger UI
        docs_response = await async_client.get("/docs")
        assert docs_response.status_code == 200
        
        # Test ReDoc
        redoc_response = await async_client.get("/redoc")
        assert redoc_response.status_code == 200

    def test_consistent_response_format(self, openapi_spec: Dict[str, Any]):
        """Test that response formats are consistent across endpoints."""
        paths = openapi_spec.get("paths", {})
        
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method in ["get", "post", "put", "delete", "patch"]:
                    responses = operation.get("responses", {})
                    
                    # Check success responses
                    for status_code in ["200", "201"]:
                        if status_code in responses:
                            response = responses[status_code]
                            
                            if "content" in response:
                                content = response["content"]
                                
                                # Should primarily use application/json
                                assert "application/json" in content, \
                                    f"Missing JSON content type for {status_code} in {method.upper()} {path}"

    def test_required_vs_optional_fields(self, openapi_spec: Dict[str, Any]):
        """Test that required and optional fields are properly marked."""
        components = openapi_spec.get("components", {})
        schemas = components.get("schemas", {})
        
        for schema_name, schema in schemas.items():
            if "properties" in schema and "required" in schema:
                properties = schema["properties"]
                required_fields = schema["required"]
                
                # All required fields should exist in properties
                for required_field in required_fields:
                    assert required_field in properties, \
                        f"Required field {required_field} not found in properties of {schema_name}"
                
                # Properties not in required should be optional
                for prop_name in properties:
                    if prop_name not in required_fields:
                        # Optional fields might have default values or be nullable
                        prop_schema = properties[prop_name]
                        # This is just a structural check
                        assert isinstance(prop_schema, dict), \
                            f"Property {prop_name} in {schema_name} should be an object"

    def test_endpoint_tags_consistency(self, openapi_spec: Dict[str, Any]):
        """Test that endpoint tags are consistent and meaningful."""
        paths = openapi_spec.get("paths", {})
        all_tags = set()
        
        for path, methods in paths.items():
            for method, operation in methods.items():
                if method in ["get", "post", "put", "delete", "patch"]:
                    tags = operation.get("tags", [])
                    
                    # Each operation should have at least one tag
                    assert len(tags) > 0, f"No tags for {method.upper()} {path}"
                    
                    all_tags.update(tags)
        
        # Common expected tags
        expected_tags = {
            "Authentication",
            "circuit-breakers",
            "Monitoring",
        }
        
        # Check that some expected tags exist
        found_tags = all_tags.intersection(expected_tags)
        assert len(found_tags) > 0, f"Expected tags not found. Found: {all_tags}"

    def test_openapi_version_compliance(self, openapi_spec: Dict[str, Any]):
        """Test OpenAPI specification version compliance."""
        openapi_version = openapi_spec.get("openapi", "")
        
        # Should be OpenAPI 3.0.x
        assert openapi_version.startswith("3.0"), f"Unsupported OpenAPI version: {openapi_version}"
        
        # Parse version parts
        version_parts = openapi_version.split(".")
        assert len(version_parts) >= 2, f"Invalid version format: {openapi_version}"
        
        major, minor = int(version_parts[0]), int(version_parts[1])
        assert major == 3, f"Expected OpenAPI v3, got v{major}"
        assert minor >= 0, f"Invalid minor version: {minor}"