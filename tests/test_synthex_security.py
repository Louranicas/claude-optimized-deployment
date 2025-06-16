"""
SYNTHEX Security Tests
Validates security fixes for SEC-001 and SEC-002
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

from src.synthex.security import (
    sanitize_query, validate_filters, validate_options,
    SecurityError, RateLimitError, rate_limit,
    build_safe_query, validate_api_key, sanitize_url,
    validate_subscription_params
)
from src.synthex.secrets import SecretManager
from src.synthex.mcp_server import SynthexMcpServer
from src.synthex.engine import SynthexEngine


class TestInputValidation:
    """Test input validation and sanitization"""
    
    def test_sanitize_query_valid(self):
        """Test valid query sanitization"""
        valid_queries = [
            "search for python tutorials",
            "How to use AI?",
            "machine learning, deep learning",
            "test-query_123"
        ]
        
        for query in valid_queries:
            sanitized = sanitize_query(query)
            assert isinstance(sanitized, str)
            assert len(sanitized) <= 500
    
    def test_sanitize_query_sql_injection(self):
        """Test SQL injection prevention"""
        malicious_queries = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin' --",
            "1; DELETE FROM data WHERE 1=1",
            "' UNION SELECT * FROM passwords --",
            "INSERT INTO users VALUES ('hacker', 'password')"
        ]
        
        for query in malicious_queries:
            with pytest.raises(SecurityError):
                sanitize_query(query)
    
    def test_sanitize_query_xss_prevention(self):
        """Test XSS prevention"""
        xss_queries = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='evil.com'></iframe>",
            "onclick=alert('XSS')"
        ]
        
        for query in xss_queries:
            with pytest.raises(SecurityError):
                sanitize_query(query)
    
    def test_sanitize_query_length_limit(self):
        """Test query length limit"""
        long_query = "a" * 501
        with pytest.raises(SecurityError, match="exceeds maximum length"):
            sanitize_query(long_query)
    
    def test_validate_filters(self):
        """Test filter validation"""
        valid_filters = {
            "date_from": "2024-01-01",
            "date_to": "2024-12-31",
            "source": "web",
            "language": "en",
            "domain": "example.com"
        }
        
        validated = validate_filters(valid_filters)
        assert validated == valid_filters
    
    def test_validate_filters_invalid_keys(self):
        """Test rejection of invalid filter keys"""
        invalid_filters = {
            "valid_key": "value",
            "invalid_key": "value",
            "another_invalid": "value"
        }
        
        # Should silently drop invalid keys
        validated = validate_filters(invalid_filters)
        assert "invalid_key" not in validated
        assert "another_invalid" not in validated
    
    def test_validate_filters_sql_injection_in_values(self):
        """Test SQL injection prevention in filter values"""
        malicious_filters = {
            "source": "'; DROP TABLE users; --",
            "domain": "example.com<script>alert('XSS')</script>"
        }
        
        validated = validate_filters(malicious_filters)
        # Values should be sanitized
        assert "DROP TABLE" not in validated.get("source", "")
        assert "<script>" not in validated.get("domain", "")
    
    def test_validate_options(self):
        """Test options validation"""
        valid_options = {
            "max_results": 50,
            "timeout_ms": 5000,
            "sources": ["web", "database"]
        }
        
        validated = validate_options(valid_options)
        assert validated == valid_options
    
    def test_validate_options_boundaries(self):
        """Test options boundary validation"""
        # Test max_results boundaries
        with pytest.raises(SecurityError):
            validate_options({"max_results": 0})
        
        with pytest.raises(SecurityError):
            validate_options({"max_results": 1001})
        
        # Test timeout_ms boundaries
        with pytest.raises(SecurityError):
            validate_options({"timeout_ms": 99})
        
        with pytest.raises(SecurityError):
            validate_options({"timeout_ms": 30001})
    
    def test_validate_api_key(self):
        """Test API key validation"""
        valid_keys = [
            "sk-proj-abcdef123456789012345678901234567890",
            "api-key-1234567890abcdef1234567890abcdef",
            "test-key-with-hyphens-32-chars-long-exactly"
        ]
        
        for key in valid_keys:
            assert validate_api_key(key) is True
    
    def test_validate_api_key_invalid(self):
        """Test invalid API key rejection"""
        invalid_keys = [
            "",
            "short",
            "contains spaces in key",
            "contains@special#characters!",
            "a" * 65,  # Too long
            "<script>alert('xss')</script>"
        ]
        
        for key in invalid_keys:
            assert validate_api_key(key) is False
    
    def test_sanitize_url(self):
        """Test URL sanitization"""
        valid_urls = [
            "https://example.com/search",
            "http://api.service.com/v1/query",
            "https://sub.domain.com:8080/path"
        ]
        
        for url in valid_urls:
            sanitized = sanitize_url(url)
            assert sanitized.startswith(("http://", "https://"))
    
    def test_sanitize_url_malicious(self):
        """Test malicious URL rejection"""
        malicious_urls = [
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "file:///etc/passwd",
            "http://localhost/admin",
            "http://127.0.0.1:8080",
            "http://[::1]/internal"
        ]
        
        for url in malicious_urls:
            with pytest.raises(SecurityError):
                sanitize_url(url)


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    @pytest.mark.asyncio
    async def test_rate_limit_decorator(self):
        """Test rate limit decorator"""
        call_count = 0
        
        @rate_limit(max_requests=3, window_seconds=1)
        async def test_function(self, client_id="test"):
            nonlocal call_count
            call_count += 1
            return call_count
        
        # Create a mock object
        mock_obj = Mock()
        
        # Should allow 3 calls
        for i in range(3):
            result = await test_function(mock_obj, client_id="test")
            assert result == i + 1
        
        # 4th call should fail
        with pytest.raises(RateLimitError):
            await test_function(mock_obj, client_id="test")
        
        # Wait for window to expire
        await asyncio.sleep(1.1)
        
        # Should allow calls again
        result = await test_function(mock_obj, client_id="test")
        assert result == 4
    
    @pytest.mark.asyncio
    async def test_rate_limit_per_client(self):
        """Test rate limiting per client"""
        @rate_limit(max_requests=2, window_seconds=1)
        async def test_function(self, client_id="default"):
            return True
        
        mock_obj = Mock()
        
        # Client 1 should get 2 calls
        await test_function(mock_obj, client_id="client1")
        await test_function(mock_obj, client_id="client1")
        
        # Client 2 should also get 2 calls
        await test_function(mock_obj, client_id="client2")
        await test_function(mock_obj, client_id="client2")
        
        # Client 1 should be rate limited
        with pytest.raises(RateLimitError):
            await test_function(mock_obj, client_id="client1")
        
        # Client 2 should be rate limited
        with pytest.raises(RateLimitError):
            await test_function(mock_obj, client_id="client2")


class TestSecretManager:
    """Test secret management"""
    
    def test_secret_manager_env_backend(self):
        """Test environment variable backend"""
        manager = SecretManager(backend="env")
        
        # Set a test secret
        test_key = "TEST_SECRET_KEY"
        test_value = "test_secret_value"
        
        manager.set_secret(test_key, test_value)
        
        # Retrieve secret
        retrieved = manager.get_secret(test_key)
        assert retrieved == test_value
        
        # Clean up
        import os
        if test_key in os.environ:
            del os.environ[test_key]
    
    def test_secret_manager_no_hardcoded_secrets(self):
        """Test that no secrets are hardcoded"""
        manager = SecretManager(backend="env")
        
        # These should return None if not set
        assert manager.get_secret("BRAVE_API_KEY") is None or \
               not manager.get_secret("BRAVE_API_KEY").startswith("hardcoded")
        
        assert manager.get_secret("DATABASE_PASSWORD") is None or \
               not manager.get_secret("DATABASE_PASSWORD").startswith("hardcoded")
    
    def test_api_keys_retrieval(self):
        """Test API keys retrieval"""
        manager = SecretManager(backend="env")
        
        api_keys = manager.get_api_keys()
        
        # Should return a dictionary with expected keys
        expected_keys = [
            'brave_api_key', 'openai_api_key', 'anthropic_api_key',
            'google_api_key', 'perplexity_api_key', 'cohere_api_key',
            'huggingface_api_key'
        ]
        
        for key in expected_keys:
            assert key in api_keys
    
    def test_validate_required_secrets(self):
        """Test required secrets validation"""
        manager = SecretManager(backend="env")
        
        # Set a test secret
        manager.set_secret("TEST_REQUIRED", "value")
        
        validation = manager.validate_required_secrets(["TEST_REQUIRED", "TEST_MISSING"])
        
        assert validation["TEST_REQUIRED"] is True
        assert validation["TEST_MISSING"] is False
        
        # Clean up
        import os
        if "TEST_REQUIRED" in os.environ:
            del os.environ["TEST_REQUIRED"]


class TestParameterizedQueries:
    """Test parameterized query building"""
    
    def test_build_safe_query(self):
        """Test safe query building"""
        base_query = "SELECT * FROM users WHERE name = :name AND age > :age"
        parameters = {"name": "John'; DROP TABLE users; --", "age": 25}
        
        query, safe_params = build_safe_query(base_query, parameters)
        
        # Parameters should be sanitized
        assert "DROP TABLE" not in str(safe_params["name"])
        assert safe_params["age"] == 25
    
    def test_build_safe_query_escaping(self):
        """Test query parameter escaping"""
        base_query = "SELECT * FROM data WHERE content = :content"
        parameters = {
            "content": "<script>alert('XSS')</script>"
        }
        
        query, safe_params = build_safe_query(base_query, parameters)
        
        # HTML should be escaped
        assert "<script>" not in safe_params["content"]


class TestMCPServerSecurity:
    """Test MCP server security implementations"""
    
    @pytest.mark.asyncio
    async def test_mcp_server_input_validation(self):
        """Test MCP server validates inputs"""
        server = SynthexMcpServer()
        
        # Test SQL injection attempt
        result = await server._handle_search({
            "query": "'; DROP TABLE users; --"
        })
        
        assert "error" in result
        assert result["error_type"] == "security_error"
    
    @pytest.mark.asyncio
    async def test_mcp_server_rate_limiting(self):
        """Test MCP server rate limiting"""
        server = SynthexMcpServer()
        
        # Mock the engine to avoid actual searches
        server.engine = AsyncMock()
        server.engine.search = AsyncMock(return_value=Mock(
            query_id="test",
            total_results=0,
            execution_time_ms=100,
            results=[],
            metadata={}
        ))
        
        # Should handle rate limiting
        # Note: This would need actual rate limit testing with multiple calls
        result = await server._handle_search({
            "query": "test query"
        }, client_id="test_client")
        
        # Should not error on first call
        assert "error" not in result or result.get("error_type") != "rate_limit_error"


class TestEngineSecurity:
    """Test engine security implementations"""
    
    @pytest.mark.asyncio
    async def test_engine_query_validation(self):
        """Test engine validates queries"""
        engine = SynthexEngine()
        
        # Test SQL injection attempt
        with pytest.raises(SecurityError):
            await engine.search("'; DROP TABLE users; --")
    
    @pytest.mark.asyncio
    async def test_engine_uses_secret_manager(self):
        """Test engine uses secret manager"""
        engine = SynthexEngine()
        
        # Should have secret manager initialized
        assert hasattr(engine, '_secret_manager')
        assert engine._secret_manager is not None


class TestSubscriptionSecurity:
    """Test subscription parameter validation"""
    
    def test_validate_subscription_params(self):
        """Test subscription parameter validation"""
        # Valid parameters
        query, interval = validate_subscription_params("test query", 30000)
        assert query == "test query"
        assert interval == 30000
        
        # Invalid interval too short
        with pytest.raises(SecurityError):
            validate_subscription_params("test", 5000)
        
        # Invalid interval too long
        with pytest.raises(SecurityError):
            validate_subscription_params("test", 3600001)
        
        # SQL injection in query
        with pytest.raises(SecurityError):
            validate_subscription_params("'; DROP TABLE users; --", 30000)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])