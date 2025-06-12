"""
Comprehensive unit tests for SSRF protection utilities.

Tests URL validation, IP blocking, metadata endpoint protection,
and integration with HTTP clients.
"""

import pytest
import asyncio
import aiohttp
from unittest.mock import patch, MagicMock, AsyncMock
from src.core.ssrf_protection import (
    SSRFProtector,
    SSRFValidationResult,
    SSRFThreatLevel,
    SSRFProtectedSession,
    get_ssrf_protector,
    validate_url_safe,
    is_url_safe,
    STRICT_SSRF_CONFIG,
    MODERATE_SSRF_CONFIG,
    DEVELOPMENT_SSRF_CONFIG
)


class TestSSRFProtector:
    """Test the core SSRF protection functionality."""
    
    def test_init_default_config(self):
        """Test initialization with default configuration."""
        protector = SSRFProtector()
        assert not protector.allow_private_networks
        assert not protector.allow_metadata_endpoints
        assert protector.max_redirects == 0
        assert protector.dns_timeout == 5.0
    
    def test_init_custom_config(self):
        """Test initialization with custom configuration."""
        protector = SSRFProtector(
            allow_private_networks=True,
            allow_metadata_endpoints=True,
            custom_blocked_networks=["203.0.113.0/24"],
            custom_allowed_domains=["api.example.com"],
            max_redirects=3,
            dns_timeout=10.0
        )
        assert protector.allow_private_networks
        assert protector.allow_metadata_endpoints
        assert protector.max_redirects == 3
        assert protector.dns_timeout == 10.0
        assert "api.example.com" in protector.allowed_domains
    
    def test_validate_safe_public_url(self):
        """Test validation of safe public URLs."""
        protector = SSRFProtector()
        
        with patch.object(protector, '_resolve_hostname', return_value='8.8.8.8'):
            result = protector.validate_url("https://api.example.com/data")
            assert result.is_safe
            assert result.threat_level == SSRFThreatLevel.SAFE
            assert result.resolved_ip == '8.8.8.8'
    
    def test_validate_blocked_scheme(self):
        """Test blocking of dangerous schemes."""
        protector = SSRFProtector()
        
        test_cases = [
            "ftp://example.com/file.txt",
            "file:///etc/passwd",
            "ldap://internal.server/",
            "gopher://old.server/"
        ]
        
        for url in test_cases:
            result = protector.validate_url(url)
            assert not result.is_safe
            assert result.threat_level == SSRFThreatLevel.BLOCKED
            assert "scheme" in result.blocked_category
    
    def test_validate_private_networks(self):
        """Test blocking of private network access."""
        protector = SSRFProtector(allow_private_networks=False)
        
        test_cases = [
            ("http://192.168.1.1/", "192.168.1.1"),
            ("https://10.0.0.1/", "10.0.0.1"),
            ("http://172.16.0.1/", "172.16.0.1"),
            ("http://127.0.0.1/", "127.0.0.1"),
            ("https://localhost/", "127.0.0.1"),
        ]
        
        for url, resolved_ip in test_cases:
            with patch.object(protector, '_resolve_hostname', return_value=resolved_ip):
                result = protector.validate_url(url)
                assert not result.is_safe
                assert result.threat_level == SSRFThreatLevel.BLOCKED
                assert "network" in result.blocked_category
    
    def test_validate_metadata_endpoints(self):
        """Test blocking of cloud metadata endpoints."""
        protector = SSRFProtector(allow_metadata_endpoints=False)
        
        test_cases = [
            ("http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
            ("http://metadata.google.internal/", "169.254.169.254"),
            ("http://100.100.100.200/latest/meta-data/", "100.100.100.200"),
        ]
        
        for url, resolved_ip in test_cases:
            with patch.object(protector, '_resolve_hostname', return_value=resolved_ip):
                result = protector.validate_url(url)
                assert not result.is_safe
                assert result.threat_level == SSRFThreatLevel.BLOCKED
                assert "metadata" in result.blocked_category
    
    def test_validate_dangerous_ports(self):
        """Test blocking of dangerous ports."""
        protector = SSRFProtector()
        
        test_cases = [
            "http://example.com:22/",  # SSH
            "http://example.com:3306/",  # MySQL
            "http://example.com:6379/",  # Redis
            "http://example.com:9200/",  # Elasticsearch
        ]
        
        for url in test_cases:
            with patch.object(protector, '_resolve_hostname', return_value='8.8.8.8'):
                result = protector.validate_url(url)
                assert not result.is_safe
                assert result.threat_level == SSRFThreatLevel.BLOCKED
                assert "port" in result.blocked_category
    
    def test_validate_suspicious_patterns(self):
        """Test detection of suspicious URL patterns."""
        protector = SSRFProtector()
        
        test_cases = [
            "http://user:pass@example.com/",  # Credentials
            "http://example.com/%2e%2e/",  # URL-encoded traversal
            "http://example.com/../../../etc/passwd",  # Directory traversal
            "http://0x7f000001/",  # Hex IP notation
        ]
        
        for url in test_cases:
            result = protector.validate_url(url)
            assert not result.is_safe
            assert result.threat_level == SSRFThreatLevel.BLOCKED
            assert "pattern" in result.blocked_category
    
    def test_validate_allowed_domains(self):
        """Test allowed domains bypass validation."""
        protector = SSRFProtector(
            custom_allowed_domains=["trusted.api.com"],
            allow_private_networks=False
        )
        
        # Even if it resolves to private IP, allowed domains should pass
        with patch.object(protector, '_resolve_hostname', return_value='192.168.1.1'):
            result = protector.validate_url("https://trusted.api.com/endpoint")
            assert result.is_safe
            assert result.threat_level == SSRFThreatLevel.SAFE
            assert "allowed list" in result.reason
    
    def test_validate_ipv6_addresses(self):
        """Test IPv6 address validation."""
        protector = SSRFProtector(allow_private_networks=False)
        
        test_cases = [
            ("http://[::1]/", "::1"),  # Loopback
            ("http://[fe80::1]/", "fe80::1"),  # Link-local
            ("http://[fc00::1]/", "fc00::1"),  # Unique local
        ]
        
        for url, resolved_ip in test_cases:
            with patch.object(protector, '_resolve_hostname', return_value=resolved_ip):
                result = protector.validate_url(url)
                assert not result.is_safe
                assert result.threat_level == SSRFThreatLevel.BLOCKED
    
    def test_dns_resolution_failure(self):
        """Test handling of DNS resolution failures."""
        protector = SSRFProtector()
        
        with patch.object(protector, '_resolve_hostname', side_effect=Exception("DNS lookup failed")):
            result = protector.validate_url("https://nonexistent.domain.example/")
            assert not result.is_safe
            assert result.threat_level == SSRFThreatLevel.BLOCKED
            assert "dns" in result.blocked_category
    
    def test_malformed_urls(self):
        """Test handling of malformed URLs."""
        protector = SSRFProtector()
        
        test_cases = [
            "",  # Empty URL
            "not-a-url",  # Invalid format
            "http://",  # Missing hostname
            "://example.com",  # Missing scheme
        ]
        
        for url in test_cases:
            result = protector.validate_url(url)
            assert not result.is_safe
            assert result.threat_level == SSRFThreatLevel.BLOCKED
    
    def test_config_presets(self):
        """Test predefined configuration presets."""
        # Test strict config
        strict_protector = SSRFProtector(**STRICT_SSRF_CONFIG)
        assert not strict_protector.allow_private_networks
        assert not strict_protector.allow_metadata_endpoints
        assert strict_protector.max_redirects == 0
        
        # Test moderate config
        moderate_protector = SSRFProtector(**MODERATE_SSRF_CONFIG)
        assert not moderate_protector.allow_private_networks
        assert not moderate_protector.allow_metadata_endpoints
        assert moderate_protector.max_redirects == 2
        
        # Test development config
        dev_protector = SSRFProtector(**DEVELOPMENT_SSRF_CONFIG)
        assert dev_protector.allow_private_networks
        assert not dev_protector.allow_metadata_endpoints
        assert dev_protector.max_redirects == 3


class TestSSRFProtectedSession:
    """Test the SSRF-protected HTTP session wrapper."""
    
    @pytest.mark.asyncio
    async def test_session_initialization(self):
        """Test session initialization and cleanup."""
        protector = SSRFProtector()
        session = SSRFProtectedSession(protector)
        
        async with session:
            assert session.session is not None
            assert session.protector is protector
        
        # Session should be cleaned up after context exit
    
    @pytest.mark.asyncio
    async def test_safe_request_allowed_url(self):
        """Test making requests to allowed URLs."""
        protector = SSRFProtector()
        
        with patch.object(protector, 'validate_url') as mock_validate:
            mock_validate.return_value = SSRFValidationResult(
                is_safe=True,
                threat_level=SSRFThreatLevel.SAFE,
                reason="Safe URL",
                original_url="https://api.example.com/data"
            )
            
            # Mock aiohttp session
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_session.request.return_value.__aenter__.return_value = mock_response
            
            session = SSRFProtectedSession(protector)
            session.session = mock_session
            
            await session._validate_and_request("GET", "https://api.example.com/data")
            
            mock_validate.assert_called_once_with("https://api.example.com/data")
            mock_session.request.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_safe_request_blocked_url(self):
        """Test blocking requests to dangerous URLs."""
        protector = SSRFProtector()
        
        with patch.object(protector, 'validate_url') as mock_validate:
            mock_validate.return_value = SSRFValidationResult(
                is_safe=False,
                threat_level=SSRFThreatLevel.BLOCKED,
                reason="Private network access blocked",
                original_url="http://192.168.1.1/",
                blocked_category="network"
            )
            
            session = SSRFProtectedSession(protector)
            
            with pytest.raises(Exception, match="SSRF protection"):
                await session._validate_and_request("GET", "http://192.168.1.1/")
    
    @pytest.mark.asyncio
    async def test_http_methods(self):
        """Test all HTTP method wrappers."""
        protector = SSRFProtector()
        
        with patch.object(protector, 'validate_url') as mock_validate:
            mock_validate.return_value = SSRFValidationResult(
                is_safe=True,
                threat_level=SSRFThreatLevel.SAFE,
                reason="Safe URL",
                original_url="https://api.example.com/data"
            )
            
            # Mock the _validate_and_request method
            session = SSRFProtectedSession(protector)
            session._validate_and_request = AsyncMock()
            
            # Test all HTTP methods
            await session.get("https://api.example.com/data")
            await session.post("https://api.example.com/data", json={"test": "data"})
            await session.put("https://api.example.com/data")
            await session.delete("https://api.example.com/data")
            await session.patch("https://api.example.com/data")
            
            # Verify all methods were called
            assert session._validate_and_request.call_count == 5


class TestGlobalFunctions:
    """Test global convenience functions."""
    
    def test_get_ssrf_protector_singleton(self):
        """Test global SSRF protector singleton."""
        protector1 = get_ssrf_protector()
        protector2 = get_ssrf_protector()
        assert protector1 is protector2
    
    def test_validate_url_safe_function(self):
        """Test global URL validation function."""
        with patch('src.core.ssrf_protection.get_ssrf_protector') as mock_get:
            mock_protector = MagicMock()
            mock_result = SSRFValidationResult(
                is_safe=True,
                threat_level=SSRFThreatLevel.SAFE,
                reason="Test",
                original_url="https://example.com"
            )
            mock_protector.validate_url.return_value = mock_result
            mock_get.return_value = mock_protector
            
            result = validate_url_safe("https://example.com")
            assert result is mock_result
            mock_protector.validate_url.assert_called_once_with("https://example.com")
    
    def test_is_url_safe_function(self):
        """Test global URL safety check function."""
        with patch('src.core.ssrf_protection.get_ssrf_protector') as mock_get:
            mock_protector = MagicMock()
            mock_protector.is_url_safe.return_value = True
            mock_get.return_value = mock_protector
            
            result = is_url_safe("https://example.com")
            assert result is True
            mock_protector.is_url_safe.assert_called_once_with("https://example.com")


class TestSSRFIntegrationScenarios:
    """Test real-world integration scenarios."""
    
    def test_ai_api_endpoints(self):
        """Test validation of AI API endpoints."""
        protector = SSRFProtector(**STRICT_SSRF_CONFIG)
        
        # These should be allowed (public AI APIs)
        safe_urls = [
            "https://api.openai.com/v1/chat/completions",
            "https://api.anthropic.com/v1/messages",
            "https://generativelanguage.googleapis.com/v1beta/models",
            "https://api.groq.com/openai/v1/chat/completions",
        ]
        
        for url in safe_urls:
            with patch.object(protector, '_resolve_hostname', return_value='8.8.8.8'):
                result = protector.validate_url(url)
                assert result.is_safe, f"AI API URL should be safe: {url}"
    
    def test_monitoring_endpoints(self):
        """Test validation of monitoring endpoints."""
        protector = SSRFProtector(**MODERATE_SSRF_CONFIG)
        
        # These should be blocked if pointing to internal networks
        internal_urls = [
            "http://localhost:9090/api/v1/query",  # Prometheus
            "http://127.0.0.1:3000/api/dashboards",  # Grafana
            "http://10.0.0.100:9093/api/v1/alerts",  # Alertmanager
        ]
        
        for url in internal_urls:
            with patch.object(protector, '_resolve_hostname', return_value='127.0.0.1'):
                result = protector.validate_url(url)
                assert not result.is_safe, f"Internal monitoring URL should be blocked: {url}"
    
    def test_communication_webhooks(self):
        """Test validation of communication webhook URLs."""
        protector = SSRFProtector(**MODERATE_SSRF_CONFIG)
        
        # These should be allowed (external webhooks)
        safe_webhooks = [
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            "https://outlook.office.com/webhook/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "https://discord.com/api/webhooks/123456789/abcdefghijk",
        ]
        
        for url in safe_webhooks:
            with patch.object(protector, '_resolve_hostname', return_value='52.1.2.3'):
                result = protector.validate_url(url)
                assert result.is_safe, f"External webhook should be safe: {url}"
    
    def test_bypass_attacks(self):
        """Test protection against common SSRF bypass techniques."""
        protector = SSRFProtector(**STRICT_SSRF_CONFIG)
        
        # Common bypass attempts that should be blocked
        bypass_attempts = [
            "http://127.0.0.1.xip.io/",  # DNS wildcard bypass
            "http://2130706433/",  # Decimal IP representation
            "http://017700000001/",  # Octal IP representation
            "http://0x7f000001/",  # Hexadecimal IP representation
            "http://[::ffff:127.0.0.1]/",  # IPv4-mapped IPv6
            "http://127.1/",  # Short form IP
            "http://google.com@127.0.0.1/",  # URL with auth
        ]
        
        for url in bypass_attempts:
            # Mock resolution to localhost for bypass attempts
            with patch.object(protector, '_resolve_hostname', return_value='127.0.0.1'):
                result = protector.validate_url(url)
                assert not result.is_safe, f"Bypass attempt should be blocked: {url}"


@pytest.mark.asyncio
class TestAsyncSSRFIntegration:
    """Test async integration with real HTTP libraries."""
    
    async def test_aiohttp_session_integration(self):
        """Test integration with aiohttp sessions."""
        protector = SSRFProtector()
        
        # Mock aiohttp ClientSession
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value = mock_session
            
            async with SSRFProtectedSession(protector) as session:
                # Should not raise for safe URLs
                with patch.object(protector, 'validate_url') as mock_validate:
                    mock_validate.return_value = SSRFValidationResult(
                        is_safe=True,
                        threat_level=SSRFThreatLevel.SAFE,
                        reason="Safe",
                        original_url="https://api.example.com"
                    )
                    
                    # Mock the session request method
                    session.session.request = AsyncMock()
                    
                    await session.get("https://api.example.com/data")
                    session.session.request.assert_called_once()
    
    async def test_concurrent_requests(self):
        """Test SSRF protection with concurrent requests."""
        protector = SSRFProtector()
        
        urls = [
            "https://api1.example.com/data",
            "https://api2.example.com/data",
            "https://api3.example.com/data",
        ]
        
        # Mock all URLs as safe
        with patch.object(protector, 'validate_url') as mock_validate:
            mock_validate.return_value = SSRFValidationResult(
                is_safe=True,
                threat_level=SSRFThreatLevel.SAFE,
                reason="Safe",
                original_url=""
            )
            
            async with SSRFProtectedSession(protector) as session:
                session.session = AsyncMock()
                session.session.request = AsyncMock()
                
                # Make concurrent requests
                tasks = [session.get(url) for url in urls]
                await asyncio.gather(*tasks)
                
                # Verify all URLs were validated
                assert mock_validate.call_count == len(urls)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])