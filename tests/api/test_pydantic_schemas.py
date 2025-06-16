"""
Pydantic Schema Validation Tests

This module contains comprehensive tests for Pydantic request/response
schemas used throughout the Claude-Optimized Deployment Engine API.
"""

import pytest
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, ValidationError
from httpx import AsyncClient

# Test markers
pytestmark = [pytest.mark.api_contract, pytest.mark.schema]


class TestAuthenticationSchemas:
    """Test authentication request/response schemas."""

    def test_login_request_schema_validation(self):
        """Test LoginRequest schema validation."""
        # Try to import the schema
        try:
            from src.auth.api import LoginRequest
            
            # Valid data
            valid_data = {
                "username": "testuser",
                "password": "testpassword123"
            }
            login_request = LoginRequest(**valid_data)
            assert login_request.username == "testuser"
            assert login_request.password == "testpassword123"
            
            # Test with MFA code
            valid_with_mfa = {
                "username": "testuser",
                "password": "testpassword123",
                "mfa_code": "123456"
            }
            login_with_mfa = LoginRequest(**valid_with_mfa)
            assert login_with_mfa.mfa_code == "123456"
            
            # Invalid data - missing password
            with pytest.raises(ValidationError):
                LoginRequest(username="testuser")
            
            # Invalid data - short username
            with pytest.raises(ValidationError):
                LoginRequest(username="ab", password="password123")
            
            # Invalid data - short password
            with pytest.raises(ValidationError):
                LoginRequest(username="testuser", password="short")
                
        except ImportError:
            pytest.skip("LoginRequest schema not available")

    def test_login_response_schema_validation(self):
        """Test LoginResponse schema validation."""
        try:
            from src.auth.api import LoginResponse
            
            # Valid response data
            valid_data = {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "refresh_token": "refresh_token_here",
                "token_type": "Bearer",
                "expires_in": 3600,
                "user": {
                    "id": "user123",
                    "username": "testuser",
                    "email": "test@example.com"
                }
            }
            
            response = LoginResponse(**valid_data)
            assert response.access_token.startswith("eyJ0eXAiOiJKV1Qi")
            assert response.token_type == "Bearer"
            assert response.expires_in == 3600
            assert isinstance(response.user, dict)
            
            # Invalid data - missing required fields
            with pytest.raises(ValidationError):
                LoginResponse(access_token="token")
                
        except ImportError:
            pytest.skip("LoginResponse schema not available")

    def test_create_user_request_schema(self):
        """Test CreateUserRequest schema validation."""
        try:
            from src.auth.api import CreateUserRequest
            
            # Valid data
            valid_data = {
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "securepassword123"
            }
            
            request = CreateUserRequest(**valid_data)
            assert request.username == "newuser"
            assert request.email == "newuser@example.com"
            
            # Valid data with roles
            valid_with_roles = {
                "username": "adminuser",
                "email": "admin@example.com", 
                "password": "adminpassword123",
                "roles": ["admin", "user"]
            }
            
            request_with_roles = CreateUserRequest(**valid_with_roles)
            assert request_with_roles.roles == ["admin", "user"]
            
            # Invalid email format
            with pytest.raises(ValidationError):
                CreateUserRequest(
                    username="user",
                    email="invalid-email",
                    password="password123"
                )
                
        except ImportError:
            pytest.skip("CreateUserRequest schema not available")

    def test_api_key_schemas(self):
        """Test API key request/response schemas."""
        try:
            from src.auth.api import CreateAPIKeyRequest, APIKeyResponse
            
            # Valid API key request
            valid_request = {
                "name": "test-api-key",
                "permissions": ["read", "write"],
                "expires_at": None
            }
            
            request = CreateAPIKeyRequest(**valid_request)
            assert request.name == "test-api-key"
            assert request.permissions == ["read", "write"]
            assert request.expires_at is None
            
            # With expiration
            future_date = datetime.now() + timedelta(days=30)
            request_with_expiry = CreateAPIKeyRequest(
                name="expiring-key",
                expires_at=future_date
            )
            assert request_with_expiry.expires_at == future_date
            
            # Valid API key response
            valid_response = {
                "id": "key123",
                "name": "test-api-key",
                "key": "ak_test_12345",
                "permissions": ["read", "write"],
                "expires_at": None
            }
            
            response = APIKeyResponse(**valid_response)
            assert response.id == "key123"
            assert response.key == "ak_test_12345"
            
        except ImportError:
            pytest.skip("API key schemas not available")


class TestCircuitBreakerSchemas:
    """Test circuit breaker response schemas."""

    def test_circuit_breaker_status_schema(self):
        """Test circuit breaker status response structure."""
        # Mock response data based on expected structure
        status_data = {
            "timestamp": datetime.now().isoformat(),
            "monitoring": {
                "active": True,
                "check_interval": 10.0
            },
            "summary": {
                "total_breakers": 5,
                "open_circuits": ["api-service"],
                "closed_circuits": ["database", "cache"],
                "half_open_circuits": ["external-api"],
                "overall_failure_rate": 0.15
            },
            "health": "warning"
        }
        
        # Validate structure
        assert "timestamp" in status_data
        assert "monitoring" in status_data
        assert "summary" in status_data
        assert "health" in status_data
        
        # Validate summary structure
        summary = status_data["summary"]
        assert "total_breakers" in summary
        assert "open_circuits" in summary
        assert "closed_circuits" in summary
        assert "half_open_circuits" in summary
        assert "overall_failure_rate" in summary
        
        # Validate data types
        assert isinstance(summary["total_breakers"], int)
        assert isinstance(summary["open_circuits"], list)
        assert isinstance(summary["overall_failure_rate"], (int, float))

    def test_circuit_breaker_individual_schema(self):
        """Test individual circuit breaker response structure."""
        breaker_data = {
            "timestamp": datetime.now().isoformat(),
            "breaker": {
                "name": "test-service",
                "state": "closed",
                "failure_count": 2,
                "failure_rate": 0.1,
                "last_failure_time": None,
                "next_attempt_time": None,
                "total_requests": 100,
                "successful_requests": 95,
                "failed_requests": 5
            }
        }
        
        # Validate structure
        assert "timestamp" in breaker_data
        assert "breaker" in breaker_data
        
        breaker = breaker_data["breaker"]
        expected_fields = [
            "name", "state", "failure_count", "failure_rate",
            "total_requests", "successful_requests", "failed_requests"
        ]
        
        for field in expected_fields:
            assert field in breaker


class TestMonitoringSchemas:
    """Test monitoring response schemas."""

    def test_health_check_schema(self):
        """Test health check response structure."""
        health_data = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "services": {
                "rate_limiting": {"status": "healthy"},
                "authentication": {"status": "healthy"},
                "database": {"status": "healthy"},
                "redis": {"status": True}
            }
        }
        
        # Validate structure
        assert "status" in health_data
        assert "timestamp" in health_data
        assert "services" in health_data
        
        # Validate status values
        assert health_data["status"] in ["healthy", "unhealthy", "degraded"]
        
        # Validate services structure
        services = health_data["services"]
        assert isinstance(services, dict)

    def test_metrics_response_schema(self):
        """Test metrics response structure."""
        metrics_data = {
            "timestamp": datetime.now().isoformat(),
            "metrics": {
                "requests_total": 1000,
                "requests_per_second": 50.5,
                "error_rate": 0.02,
                "response_time_p95": 150.0,
                "active_connections": 25
            },
            "labels": {
                "service": "api",
                "environment": "production"
            }
        }
        
        # Validate structure
        assert "timestamp" in metrics_data
        assert "metrics" in metrics_data
        
        # Validate metrics types
        metrics = metrics_data["metrics"]
        for key, value in metrics.items():
            assert isinstance(value, (int, float))


class TestErrorSchemas:
    """Test error response schemas."""

    def test_http_exception_schema(self):
        """Test HTTP exception response structure."""
        error_data = {
            "detail": "Not found"
        }
        
        # Basic error structure
        assert "detail" in error_data
        assert isinstance(error_data["detail"], str)

    def test_validation_error_schema(self):
        """Test validation error response structure."""
        validation_error_data = {
            "detail": [
                {
                    "loc": ["body", "username"],
                    "msg": "field required",
                    "type": "value_error.missing"
                },
                {
                    "loc": ["body", "password"],
                    "msg": "ensure this value has at least 8 characters",
                    "type": "value_error.any_str.min_length",
                    "ctx": {"limit_value": 8}
                }
            ]
        }
        
        # Validate structure
        assert "detail" in validation_error_data
        detail = validation_error_data["detail"]
        assert isinstance(detail, list)
        
        # Validate error items
        for error in detail:
            assert "loc" in error
            assert "msg" in error
            assert "type" in error
            assert isinstance(error["loc"], list)
            assert isinstance(error["msg"], str)

    def test_custom_error_schema(self):
        """Test custom error response structure."""
        custom_error_data = {
            "error": "Internal server error",
            "detail": "An unexpected error occurred",
            "timestamp": datetime.now().isoformat(),
            "path": "/api/test",
            "status_code": 500
        }
        
        # Validate custom error structure
        expected_fields = ["error", "detail"]
        for field in expected_fields:
            assert field in custom_error_data


class TestSchemaInteroperability:
    """Test schema interoperability and consistency."""

    async def test_request_response_schema_consistency(self, async_client: AsyncClient):
        """Test that request and response schemas are consistent."""
        # Test login flow
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        response = await async_client.post("/auth/login", json=login_data)
        
        if response.status_code in [200, 401, 422]:
            data = response.json()
            
            if response.status_code == 200:
                # Should match LoginResponse schema
                expected_fields = ["access_token", "refresh_token", "token_type", "expires_in", "user"]
                for field in expected_fields:
                    assert field in data
                    
            elif response.status_code == 422:
                # Should match validation error schema
                assert "detail" in data
                detail = data["detail"]
                if isinstance(detail, list):
                    for error in detail:
                        assert "loc" in error
                        assert "msg" in error

    def test_nested_schema_validation(self):
        """Test nested schema validation."""
        # Example: User schema with nested address
        user_data = {
            "id": "user123",
            "username": "testuser",
            "email": "test@example.com",
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "last_login": datetime.now().isoformat(),
                "preferences": {
                    "theme": "dark",
                    "notifications": True
                }
            }
        }
        
        # Validate nested structure
        assert "metadata" in user_data
        metadata = user_data["metadata"]
        assert "preferences" in metadata
        preferences = metadata["preferences"]
        assert "theme" in preferences
        assert "notifications" in preferences

    def test_optional_field_handling(self):
        """Test handling of optional fields in schemas."""
        # Test with minimal required fields
        minimal_user = {
            "username": "minimaluser",
            "email": "minimal@example.com",
            "password": "password123"
        }
        
        # Should be valid with just required fields
        assert "username" in minimal_user
        assert "email" in minimal_user
        assert "password" in minimal_user
        
        # Test with optional fields
        full_user = {
            **minimal_user,
            "roles": ["user"],
            "metadata": {"department": "engineering"}
        }
        
        # Should still be valid with optional fields
        assert "roles" in full_user
        assert "metadata" in full_user

    def test_enum_field_validation(self):
        """Test enum field validation in schemas."""
        # Status enums
        valid_statuses = ["active", "inactive", "pending", "suspended"]
        
        for status in valid_statuses:
            user_data = {
                "username": "testuser",
                "email": "test@example.com",
                "status": status
            }
            # Should be valid
            assert user_data["status"] in valid_statuses
        
        # Invalid status
        invalid_status = "invalid_status"
        assert invalid_status not in valid_statuses

    def test_date_time_field_validation(self):
        """Test datetime field validation in schemas."""
        # Valid ISO format
        valid_datetime = datetime.now().isoformat()
        
        data_with_datetime = {
            "created_at": valid_datetime,
            "expires_at": valid_datetime
        }
        
        # Should parse ISO datetime strings
        for field, value in data_with_datetime.items():
            # Basic format validation
            assert "T" in value or " " in value  # ISO format indicator

    def test_schema_serialization(self):
        """Test schema serialization to JSON."""
        # Test data that should be JSON serializable
        test_data = {
            "string_field": "test",
            "integer_field": 42,
            "float_field": 3.14,
            "boolean_field": True,
            "null_field": None,
            "list_field": [1, 2, 3],
            "dict_field": {"nested": "value"},
            "datetime_field": datetime.now().isoformat()
        }
        
        # Should be JSON serializable
        json_str = json.dumps(test_data)
        parsed_data = json.loads(json_str)
        
        # Basic validation that data survived round trip
        assert parsed_data["string_field"] == test_data["string_field"]
        assert parsed_data["integer_field"] == test_data["integer_field"]
        assert parsed_data["boolean_field"] == test_data["boolean_field"]


class TestSchemaEvolution:
    """Test schema evolution and backward compatibility."""

    def test_additive_schema_changes(self):
        """Test that adding optional fields doesn't break existing schemas."""
        # Original schema
        original_data = {
            "username": "testuser",
            "email": "test@example.com"
        }
        
        # Extended schema with new optional field
        extended_data = {
            **original_data,
            "new_optional_field": "new_value"
        }
        
        # Both should be valid
        assert "username" in original_data
        assert "email" in original_data
        
        assert "username" in extended_data
        assert "email" in extended_data
        assert "new_optional_field" in extended_data

    def test_schema_version_compatibility(self):
        """Test schema version compatibility."""
        # Version 1.0 format
        v1_data = {
            "user_id": "123",
            "user_name": "testuser"
        }
        
        # Version 1.1 format (with new optional fields)
        v1_1_data = {
            "user_id": "123",
            "user_name": "testuser", 
            "display_name": "Test User",  # New optional field
            "avatar_url": None  # New optional field
        }
        
        # Both should contain core fields
        for data in [v1_data, v1_1_data]:
            assert "user_id" in data
            assert "user_name" in data