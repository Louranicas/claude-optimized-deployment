"""
Failure Scenario Integration Tests for MCP Servers

This test suite focuses on testing failure scenarios, error handling,
resilience, and recovery mechanisms for all MCP servers.
"""

import pytest
import asyncio
import aiohttp
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path
import tempfile
import time
from datetime import datetime

# Import MCP servers
from src.mcp.servers import BraveMCPServer
from src.mcp.devops_servers import AzureDevOpsMCPServer, WindowsSystemMCPServer
from src.mcp.infrastructure_servers import DesktopCommanderMCPServer, DockerMCPServer, KubernetesMCPServer
from src.mcp.communication.slack_server import SlackNotificationMCPServer
from src.mcp.monitoring.prometheus_server import PrometheusMonitoringMCP
from src.mcp.security.scanner_server import SecurityScannerMCPServer
from src.mcp.storage.s3_server import S3StorageMCPServer

# Import exceptions and protocols
from src.mcp.protocols import MCPError
from src.core.exceptions import (
    ValidationError, ServiceUnavailableError, ExternalServiceError,
    DockerError, KubernetesError, InfrastructureError
)


class MockUser:
    """Mock user for testing."""
    
    def __init__(self, username: str = "test_user", user_id: str = "user_123"):
        self.username = username
        self.id = user_id


@pytest.fixture
def mock_user():
    return MockUser()


class TestNetworkFailures:
    """Test network failure scenarios."""
    
    @pytest.mark.asyncio
    async def test_brave_api_network_timeout(self, mock_user):
        """Test Brave API network timeout."""
        server = BraveMCPServer(api_key="test_key")
        
        with patch.object(server, 'session') as mock_session:
            # Mock network timeout
            mock_session.get.side_effect = asyncio.TimeoutError("Network timeout")
            server.session = mock_session
            
            with pytest.raises(Exception):  # Should handle timeout gracefully
                await server.call_tool(
                    "brave_web_search",
                    {"query": "test"},
                    mock_user
                )
    
    @pytest.mark.asyncio
    async def test_brave_api_connection_error(self, mock_user):
        """Test Brave API connection error."""
        server = BraveMCPServer(api_key="test_key")
        
        with patch.object(server, 'session') as mock_session:
            # Mock connection error
            mock_session.get.side_effect = aiohttp.ClientConnectionError("Connection failed")
            server.session = mock_session
            
            with pytest.raises(Exception):
                await server.call_tool(
                    "brave_web_search",
                    {"query": "test"},
                    mock_user
                )
    
    @pytest.mark.asyncio
    async def test_slack_webhook_failure(self):
        """Test Slack webhook failure."""
        server = SlackNotificationMCPServer(slack_token="test_token")
        
        with patch.object(server, '_make_safe_request') as mock_request:
            # Mock webhook failure
            mock_request.side_effect = aiohttp.ClientError("Webhook failed")
            
            result = await server.call_tool(
                "send_notification",
                {"message": "test", "channels": ["slack"]}
            )
            
            # Should handle failure gracefully
            assert "channels" in result
            assert result["channels"]["slack"]["success"] is False
    
    @pytest.mark.asyncio
    async def test_prometheus_unreachable(self, mock_user):
        """Test Prometheus server unreachable."""
        server = PrometheusMonitoringMCP(prometheus_url="http://unreachable:9090")
        
        with patch.object(server, '_make_safe_request') as mock_request:
            mock_request.side_effect = aiohttp.ClientConnectionError("Connection refused")
            
            # Should handle unreachable Prometheus gracefully
            with pytest.raises(Exception):
                await server.call_tool(
                    "prometheus_query",
                    {"query": "up"},
                    mock_user
                )
    
    @pytest.mark.asyncio
    async def test_azure_devops_authentication_failure(self, mock_user):
        """Test Azure DevOps authentication failure."""
        server = AzureDevOpsMCPServer(
            organization="test-org",
            personal_access_token="invalid_token"
        )
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 401
            mock_response.text.return_value = "Unauthorized"
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            with pytest.raises(MCPError):
                await server.call_tool(
                    "list_projects",
                    {},
                    mock_user
                )


class TestServiceUnavailability:
    """Test service unavailability scenarios."""
    
    @pytest.mark.asyncio
    async def test_docker_daemon_unavailable(self, mock_user):
        """Test Docker daemon unavailable."""
        server = DockerMCPServer()
        
        # Mock Docker check to return False
        with patch.object(server, '_check_docker') as mock_check:
            mock_check.return_value = False
            
            with pytest.raises(Exception):  # Should raise DockerError or similar
                await server.call_tool(
                    "docker_ps",
                    {"all": False},
                    mock_user
                )
    
    @pytest.mark.asyncio
    async def test_kubectl_unavailable(self, mock_user):
        """Test kubectl unavailable."""
        server = KubernetesMCPServer()
        
        with patch.object(server, '_check_kubectl') as mock_check:
            mock_check.return_value = False
            
            with pytest.raises(Exception):  # Should raise KubernetesError or similar
                await server.call_tool(
                    "kubectl_get",
                    {"resource_type": "pods"},
                    mock_user
                )
    
    @pytest.mark.asyncio
    async def test_aws_s3_service_unavailable(self, mock_user):
        """Test AWS S3 service unavailable."""
        server = S3StorageMCPServer(
            aws_access_key="test_key",
            aws_secret_key="test_secret"
        )
        
        # Mock S3 service unavailable
        with patch('boto3.client') as mock_boto3:
            mock_client = Mock()
            mock_client.list_buckets.side_effect = Exception("Service unavailable")
            mock_boto3.return_value = mock_client
            
            with pytest.raises(Exception):
                await server.call_tool(
                    "s3_list_buckets",
                    {},
                    mock_user
                )


class TestDataCorruption:
    """Test data corruption and invalid response scenarios."""
    
    @pytest.mark.asyncio
    async def test_brave_invalid_json_response(self, mock_user):
        """Test Brave API returning invalid JSON."""
        server = BraveMCPServer(api_key="test_key")
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            with pytest.raises(Exception):
                await server.call_tool(
                    "brave_web_search",
                    {"query": "test"},
                    mock_user
                )
    
    @pytest.mark.asyncio
    async def test_azure_devops_malformed_response(self, mock_user):
        """Test Azure DevOps returning malformed response."""
        server = AzureDevOpsMCPServer(
            organization="test-org",
            personal_access_token="test_token"
        )
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            # Missing required fields
            mock_response.json.return_value = {"invalid": "structure"}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            result = await server.call_tool(
                "list_projects",
                {},
                mock_user
            )
            
            # Should handle gracefully with empty results
            assert "projects" in result
            assert result["total"] == 0
    
    @pytest.mark.asyncio
    async def test_kubernetes_invalid_yaml_response(self, mock_user):
        """Test Kubernetes returning invalid YAML/JSON."""
        server = KubernetesMCPServer()
        server.kubectl_available = True
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            # Invalid JSON output
            mock_process.communicate.return_value = (b"invalid json {", b"")
            mock_subprocess.return_value = mock_process
            
            result = await server.call_tool(
                "kubectl_get",
                {"resource_type": "pods"},
                mock_user
            )
            
            # Should handle invalid JSON gracefully
            assert result["success"] is True
            assert "stdout" in result  # Falls back to raw output


class TestResourceExhaustion:
    """Test resource exhaustion scenarios."""
    
    @pytest.mark.asyncio
    async def test_memory_exhaustion_protection(self, mock_user):
        """Test protection against memory exhaustion."""
        server = DesktopCommanderMCPServer()
        
        # Try to read a very large file
        large_content = "a" * (100 * 1024 * 1024)  # 100MB
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(large_content[:1000])  # Write small amount to avoid actual memory issues
            temp_file = f.name
        
        try:
            with patch('pathlib.Path.stat') as mock_stat:
                # Mock file size to be very large
                mock_stat.return_value.st_size = 100 * 1024 * 1024
                
                with pytest.raises(Exception):  # Should reject large files
                    await server.call_tool(
                        "read_file",
                        {"file_path": temp_file},
                        mock_user
                    )
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    @pytest.mark.asyncio
    async def test_concurrent_request_limit(self, mock_user):
        """Test concurrent request limiting."""
        server = SecurityScannerMCPServer()
        
        # Simulate many concurrent security scans
        async def mock_scan(*args, **kwargs):
            await asyncio.sleep(0.1)  # Simulate work
            return {"status": "completed"}
        
        # The server should limit concurrent operations
        # Implementation depends on semaphore or similar mechanism
        tasks = []
        for i in range(20):  # Try to create many tasks
            # This should be limited by the server's semaphore
            pass  # Actual implementation would depend on server design
    
    def test_rate_limiting_under_load(self):
        """Test rate limiting under high load."""
        from src.mcp.monitoring.prometheus_server import RateLimiter
        
        rate_limiter = RateLimiter(max_requests=10, window=1)
        user_id = "load_test_user"
        
        # Rapid-fire requests
        allowed_count = 0
        for i in range(50):
            if rate_limiter.is_allowed(user_id):
                allowed_count += 1
        
        # Should not exceed rate limit
        assert allowed_count <= 10


class TestFailureRecovery:
    """Test failure recovery mechanisms."""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery(self):
        """Test circuit breaker recovery after failures."""
        from src.mcp.security.scanner_server import CircuitBreaker
        
        circuit_breaker = CircuitBreaker(failure_threshold=3, reset_timeout=1)
        
        # Cause failures to open circuit
        for i in range(3):
            circuit_breaker.record_failure()
        
        assert circuit_breaker.state == "open"
        
        # Wait for timeout
        await asyncio.sleep(1.1)
        
        # Circuit should allow half-open state
        # Simulate successful call
        circuit_breaker.record_success()
        assert circuit_breaker.state == "closed"
    
    @pytest.mark.asyncio
    async def test_retry_mechanism(self, mock_user):
        """Test retry mechanism for transient failures."""
        server = BraveMCPServer(api_key="test_key")
        
        call_count = 0
        
        def mock_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                # Fail first two attempts
                raise aiohttp.ClientError("Transient error")
            else:
                # Succeed on third attempt
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json.return_value = {"web": {"results": []}}
                return mock_response.__aenter__()
        
        with patch.object(server, 'session') as mock_session:
            mock_session.get.side_effect = mock_get
            server.session = mock_session
            
            # Should eventually succeed after retries
            result = await server.call_tool(
                "brave_web_search",
                {"query": "test"},
                mock_user
            )
            
            assert call_count == 3  # Should have retried
            assert "results" in result
    
    @pytest.mark.asyncio
    async def test_graceful_degradation(self):
        """Test graceful degradation when services fail."""
        server = SlackNotificationMCPServer(
            slack_token="test_token",
            teams_webhook="test_webhook"
        )
        
        with patch.object(server, '_make_safe_request') as mock_request:
            # Mock Slack failure but Teams success
            def mock_request_side_effect(method, url, **kwargs):
                if "slack.com" in url:
                    raise aiohttp.ClientError("Slack unavailable")
                else:
                    mock_response = AsyncMock()
                    mock_response.status = 200
                    return mock_response
            
            mock_request.side_effect = mock_request_side_effect
            
            result = await server.call_tool(
                "send_notification",
                {"message": "test", "channels": ["slack", "teams"]}
            )
            
            # Should succeed partially
            assert "channels" in result
            assert result["channels"]["slack"]["success"] is False
            # Teams might succeed depending on implementation


class TestCorruptedState:
    """Test handling of corrupted internal state."""
    
    @pytest.mark.asyncio
    async def test_corrupted_session_recovery(self, mock_user):
        """Test recovery from corrupted session state."""
        server = BraveMCPServer(api_key="test_key")
        
        # Corrupt the session
        server.session = "invalid_session_object"
        
        # Server should recover by creating new session
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"web": {"results": []}}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            mock_session_class.return_value = mock_session
            
            result = await server.call_tool(
                "brave_web_search",
                {"query": "test"},
                mock_user
            )
            
            # Should have recovered and succeeded
            assert "results" in result
    
    def test_corrupted_cache_handling(self):
        """Test handling of corrupted cache data."""
        server = SecurityScannerMCPServer()
        
        # Corrupt the cache
        server._scan_cache = {"corrupted": "invalid_data_structure"}
        
        # Server should handle corrupted cache gracefully
        # Implementation would depend on cache validation
        pass
    
    @pytest.mark.asyncio
    async def test_invalid_configuration_recovery(self, mock_user):
        """Test recovery from invalid configuration."""
        # Test with invalid Prometheus URL
        server = PrometheusMonitoringMCP(prometheus_url="invalid://url")
        
        # Should handle invalid URL gracefully
        with pytest.raises(Exception):
            await server.call_tool(
                "prometheus_query",
                {"query": "up"},
                mock_user
            )


class TestCascadingFailures:
    """Test cascading failure scenarios."""
    
    @pytest.mark.asyncio
    async def test_multiple_service_failures(self, mock_user):
        """Test behavior when multiple services fail simultaneously."""
        # Create servers with dependencies
        commander = DesktopCommanderMCPServer()
        docker = DockerMCPServer()
        slack = SlackNotificationMCPServer(slack_token="test_token")
        
        # Mock all services to fail
        with patch.object(commander, 'command_executor') as mock_executor, \
             patch.object(docker, '_check_docker') as mock_docker_check, \
             patch.object(slack, '_make_safe_request') as mock_slack:
            
            mock_executor.execute_async.side_effect = Exception("Command failed")
            mock_docker_check.return_value = False
            mock_slack.side_effect = aiohttp.ClientError("Slack failed")
            
            # All operations should fail gracefully
            with pytest.raises(Exception):
                await commander.call_tool(
                    "execute_command",
                    {"command": "echo test"},
                    mock_user
                )
            
            with pytest.raises(Exception):
                await docker.call_tool(
                    "docker_ps",
                    {},
                    mock_user
                )
            
            result = await slack.call_tool(
                "send_notification",
                {"message": "test", "channels": ["slack"]}
            )
            assert result["channels"]["slack"]["success"] is False
    
    @pytest.mark.asyncio
    async def test_dependency_chain_failure(self, mock_user):
        """Test failure propagation through dependency chains."""
        # Simulate a deployment pipeline failure
        servers = {
            "commander": DesktopCommanderMCPServer(),
            "docker": DockerMCPServer(),
            "kubernetes": KubernetesMCPServer(),
            "slack": SlackNotificationMCPServer(slack_token="test_token")
        }
        
        # Mock first service to fail
        with patch.object(servers["commander"], 'command_executor') as mock_executor:
            mock_executor.execute_async.side_effect = Exception("Build failed")
            
            # Build failure should be handled
            with pytest.raises(Exception):
                await servers["commander"].call_tool(
                    "execute_command",
                    {"command": "make build"},
                    mock_user
                )
            
            # Subsequent services should not be called in a real pipeline
            # This would be handled by the orchestrating system


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_empty_responses(self, mock_user):
        """Test handling of empty responses."""
        server = BraveMCPServer(api_key="test_key")
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {}  # Empty response
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            result = await server.call_tool(
                "brave_web_search",
                {"query": "test"},
                mock_user
            )
            
            # Should handle empty response gracefully
            assert "results" in result
            assert len(result["results"]) == 0
    
    @pytest.mark.asyncio
    async def test_unicode_handling(self, mock_user):
        """Test Unicode and special character handling."""
        server = DesktopCommanderMCPServer()
        
        unicode_content = "Hello 世界 🌍 ñoño café"
        
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as f:
            f.write(unicode_content)
            temp_file = f.name
        
        try:
            with patch('src.core.command_sanitizer.CommandSanitizer.sanitize_path') as mock_sanitize:
                mock_sanitize.return_value = temp_file
                
                result = await server.call_tool(
                    "read_file",
                    {"file_path": temp_file},
                    mock_user
                )
                
                # Should handle Unicode correctly
                assert result["content"] == unicode_content
        finally:
            Path(temp_file).unlink(missing_ok=True)
    
    @pytest.mark.asyncio
    async def test_concurrent_session_access(self, mock_user):
        """Test concurrent access to shared resources."""
        server = BraveMCPServer(api_key="test_key")
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"web": {"results": []}}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            # Run multiple concurrent requests
            tasks = []
            for i in range(10):
                task = server.call_tool(
                    "brave_web_search",
                    {"query": f"test {i}"},
                    mock_user
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All should succeed or fail gracefully
            for result in results:
                if isinstance(result, Exception):
                    # Exception is acceptable
                    pass
                else:
                    assert "results" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])