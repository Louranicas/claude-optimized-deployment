"""
API Contract Tests Package

This package contains comprehensive API contract tests for the
Claude-Optimized Deployment Engine, including:

- OpenAPI schema validation
- REST endpoint compliance
- Pydantic schema validation  
- Error response validation
- Authentication flow testing
- Rate limiting enforcement
- CORS header validation
- Content-type handling
- API versioning and backward compatibility
- Property-based testing with schemathesis

Test Modules:
- test_openapi_schema_validation.py: OpenAPI schema compliance tests
- test_rest_endpoints.py: REST endpoint contract tests
- test_pydantic_schemas.py: Pydantic model validation tests
- test_error_responses.py: Error response format tests
- test_authentication_endpoints.py: Authentication flow tests
- test_rate_limiting.py: Rate limiting enforcement tests
- test_cors_headers.py: CORS configuration tests
- test_content_type_handling.py: Content-type validation tests
- test_versioning_compatibility.py: API versioning tests
- test_schemathesis_integration.py: Property-based API tests

Usage:
    pytest tests/api/ -m api_contract
    pytest tests/api/test_openapi_schema_validation.py
    pytest tests/api/ -m "not slow"  # Skip slow property-based tests
"""

__version__ = "1.0.0"
__author__ = "Claude-Optimized Deployment Team"

# Test categories
API_CONTRACT_TESTS = [
    "test_openapi_schema_validation",
    "test_rest_endpoints", 
    "test_pydantic_schemas",
    "test_error_responses",
    "test_authentication_endpoints",
    "test_rate_limiting",
    "test_cors_headers",
    "test_content_type_handling",
    "test_versioning_compatibility",
    "test_schemathesis_integration"
]

# Test markers
MARKERS = {
    "api_contract": "API contract compliance tests",
    "schema": "Schema validation tests",
    "auth": "Authentication tests",
    "rate_limit": "Rate limiting tests", 
    "cors": "CORS tests",
    "content_type": "Content-type handling tests",
    "versioning": "API versioning tests",
    "schemathesis": "Property-based API tests",
    "slow": "Slow running tests",
    "integration": "Integration tests"
}

# Test configuration
DEFAULT_TEST_CONFIG = {
    "timeout": 30,
    "max_examples": 50,
    "hypothesis_deadline": 5000,
    "rate_limit_test_requests": 10,
    "schemathesis_max_examples": 25
}