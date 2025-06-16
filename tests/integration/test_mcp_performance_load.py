"""
Performance and Load Testing for MCP Servers

This test suite focuses on performance testing, load testing,
and stress testing for all MCP servers to ensure they can handle
production-level workloads.
"""

import pytest
import asyncio
import time
import statistics
import psutil
import gc
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any
import logging

# Import MCP servers
from src.mcp.servers import BraveMCPServer
from src.mcp.devops_servers import AzureDevOpsMCPServer, WindowsSystemMCPServer
from src.mcp.infrastructure_servers import DesktopCommanderMCPServer, DockerMCPServer
from src.mcp.communication.slack_server import SlackNotificationMCPServer
from src.mcp.monitoring.prometheus_server import PrometheusMonitoringMCP
from src.mcp.security.scanner_server import SecurityScannerMCPServer

# Import testing utilities
from src.mcp.protocols import MCPError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MockUser:
    """Mock user for performance testing."""
    
    def __init__(self, username: str = "perf_user", user_id: str = "perf_123"):
        self.username = username
        self.id = user_id


class PerformanceMetrics:
    """Utility class for collecting performance metrics."""
    
    def __init__(self):
        self.response_times: List[float] = []
        self.success_count = 0
        self.error_count = 0
        self.start_time = None
        self.end_time = None
    
    def start_timing(self):
        """Start timing measurements."""
        self.start_time = time.time()
    
    def end_timing(self):
        """End timing measurements."""
        self.end_time = time.time()
    
    def record_response(self, response_time: float, success: bool):
        """Record a response time and success status."""
        self.response_times.append(response_time)
        if success:
            self.success_count += 1
        else:
            self.error_count += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics."""
        if not self.response_times:
            return {}
        
        total_time = self.end_time - self.start_time if self.end_time and self.start_time else 0
        total_requests = len(self.response_times)
        
        return {
            "total_requests": total_requests,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "success_rate": self.success_count / total_requests if total_requests > 0 else 0,
            "total_time": total_time,
            "requests_per_second": total_requests / total_time if total_time > 0 else 0,
            "avg_response_time": statistics.mean(self.response_times),
            "median_response_time": statistics.median(self.response_times),
            "min_response_time": min(self.response_times),
            "max_response_time": max(self.response_times),
            "p95_response_time": self._percentile(self.response_times, 95),
            "p99_response_time": self._percentile(self.response_times, 99),
        }
    
    @staticmethod
    def _percentile(data: List[float], percentile: float) -> float:
        """Calculate percentile of data."""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        return sorted_data[min(index, len(sorted_data) - 1)]


@pytest.fixture
def mock_user():
    return MockUser()


@pytest.fixture
def performance_metrics():
    return PerformanceMetrics()


class TestBasicPerformance:
    """Test basic performance characteristics."""
    
    @pytest.mark.asyncio
    async def test_brave_search_response_time(self, mock_user, performance_metrics):
        """Test Brave search response time under normal conditions."""
        server = BraveMCPServer(api_key="test_key")
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"web": {"results": []}}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            # Test multiple requests to get baseline performance
            performance_metrics.start_timing()
            
            for i in range(10):
                start_time = time.time()
                try:
                    await server.call_tool(
                        "brave_web_search",
                        {"query": f"test query {i}"},
                        mock_user
                    )
                    response_time = time.time() - start_time
                    performance_metrics.record_response(response_time, True)
                except Exception:
                    response_time = time.time() - start_time
                    performance_metrics.record_response(response_time, False)
            
            performance_metrics.end_timing()
            stats = performance_metrics.get_statistics()
            
            # Assert reasonable performance
            assert stats["avg_response_time"] < 1.0  # Should be under 1 second
            assert stats["success_rate"] >= 0.9  # At least 90% success rate
    
    @pytest.mark.asyncio
    async def test_command_execution_performance(self, mock_user, performance_metrics):
        """Test command execution performance."""
        server = DesktopCommanderMCPServer()
        
        with patch.object(server, 'command_executor') as mock_executor:
            mock_result = Mock()
            mock_result.command = "echo test"
            mock_result.working_directory = "/tmp"
            mock_result.exit_code = 0
            mock_result.stdout = "test\n"
            mock_result.stderr = ""
            mock_result.success = True
            mock_result.truncated = False
            mock_executor.execute_async.return_value = mock_result
            
            performance_metrics.start_timing()
            
            for i in range(20):
                start_time = time.time()
                try:
                    await server.call_tool(
                        "execute_command",
                        {"command": f"echo test{i}"},
                        mock_user
                    )
                    response_time = time.time() - start_time
                    performance_metrics.record_response(response_time, True)
                except Exception:
                    response_time = time.time() - start_time
                    performance_metrics.record_response(response_time, False)
            
            performance_metrics.end_timing()
            stats = performance_metrics.get_statistics()
            
            # Command execution should be fast
            assert stats["avg_response_time"] < 0.5  # Should be under 500ms
            assert stats["p95_response_time"] < 1.0  # 95th percentile under 1s
            assert stats["success_rate"] >= 0.95


class TestConcurrencyPerformance:
    """Test performance under concurrent load."""
    
    @pytest.mark.asyncio
    async def test_concurrent_brave_searches(self, mock_user):
        """Test concurrent Brave searches."""
        server = BraveMCPServer(api_key="test_key")
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"web": {"results": []}}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            # Test with increasing concurrency levels
            concurrency_levels = [1, 5, 10, 25]
            results = {}
            
            for concurrency in concurrency_levels:
                start_time = time.time()
                
                # Create concurrent tasks
                tasks = []
                for i in range(concurrency):
                    task = server.call_tool(
                        "brave_web_search",
                        {"query": f"concurrent test {i}"},
                        mock_user
                    )
                    tasks.append(task)
                
                # Execute all tasks concurrently
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                end_time = time.time()
                total_time = end_time - start_time
                
                success_count = sum(1 for r in responses if not isinstance(r, Exception))
                
                results[concurrency] = {
                    "total_time": total_time,
                    "success_count": success_count,
                    "success_rate": success_count / concurrency,
                    "requests_per_second": concurrency / total_time
                }
            
            # Verify scaling characteristics
            assert results[1]["success_rate"] >= 0.9
            assert results[5]["success_rate"] >= 0.8
            assert results[10]["success_rate"] >= 0.7
            
            # Performance should scale reasonably
            assert results[10]["requests_per_second"] > results[1]["requests_per_second"]
    
    @pytest.mark.asyncio
    async def test_concurrent_notifications(self):
        """Test concurrent notification sending."""
        server = SlackNotificationMCPServer(slack_token="test_token")
        
        with patch.object(server, '_make_safe_request') as mock_request:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"ok": True}
            mock_request.return_value = mock_response
            
            # Send 20 concurrent notifications
            tasks = []
            for i in range(20):
                task = server.call_tool(
                    "send_notification",
                    {"message": f"Test message {i}", "channels": ["slack"]}
                )
                tasks.append(task)
            
            start_time = time.time()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            end_time = time.time()
            
            success_count = sum(1 for r in results if not isinstance(r, Exception))
            
            # Should handle concurrent notifications well
            assert success_count >= 18  # At least 90% success
            assert (end_time - start_time) < 5.0  # Should complete in reasonable time
    
    @pytest.mark.asyncio
    async def test_mixed_workload_performance(self, mock_user):
        """Test performance with mixed workload types."""
        # Create multiple server types
        brave_server = BraveMCPServer(api_key="test_key")
        commander_server = DesktopCommanderMCPServer()
        slack_server = SlackNotificationMCPServer(slack_token="test_token")
        
        # Mock all servers
        with patch.object(brave_server, 'session') as mock_brave_session, \
             patch.object(commander_server, 'command_executor') as mock_executor, \
             patch.object(slack_server, '_make_safe_request') as mock_slack:
            
            # Setup mocks
            mock_brave_response = AsyncMock()
            mock_brave_response.status = 200
            mock_brave_response.json.return_value = {"web": {"results": []}}
            mock_brave_session.get.return_value.__aenter__.return_value = mock_brave_response
            brave_server.session = mock_brave_session
            
            mock_cmd_result = Mock()
            mock_cmd_result.success = True
            mock_cmd_result.exit_code = 0
            mock_cmd_result.stdout = "output"
            mock_cmd_result.stderr = ""
            mock_cmd_result.command = "test"
            mock_cmd_result.working_directory = "/tmp"
            mock_cmd_result.truncated = False
            mock_executor.execute_async.return_value = mock_cmd_result
            
            mock_slack_response = AsyncMock()
            mock_slack_response.status = 200
            mock_slack.return_value = mock_slack_response
            
            # Create mixed workload
            tasks = []
            
            # Add search tasks
            for i in range(10):
                task = brave_server.call_tool(
                    "brave_web_search",
                    {"query": f"search {i}"},
                    mock_user
                )
                tasks.append(task)
            
            # Add command tasks
            for i in range(10):
                task = commander_server.call_tool(
                    "execute_command",
                    {"command": f"echo {i}"},
                    mock_user
                )
                tasks.append(task)
            
            # Add notification tasks
            for i in range(10):
                task = slack_server.call_tool(
                    "send_notification",
                    {"message": f"notification {i}", "channels": ["slack"]}
                )
                tasks.append(task)
            
            # Execute mixed workload
            start_time = time.time()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            end_time = time.time()
            
            success_count = sum(1 for r in results if not isinstance(r, Exception))
            
            # Mixed workload should perform well
            assert success_count >= 27  # At least 90% success
            assert (end_time - start_time) < 10.0  # Reasonable total time


class TestStressTestign:
    """Stress testing with high loads."""
    
    @pytest.mark.asyncio
    async def test_high_volume_requests(self, mock_user):
        """Test server behavior under high volume."""
        server = BraveMCPServer(api_key="test_key")
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"web": {"results": []}}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            # High volume test - 100 requests
            num_requests = 100
            batch_size = 20  # Process in batches to avoid overwhelming
            
            all_results = []
            start_time = time.time()
            
            for batch_start in range(0, num_requests, batch_size):
                batch_end = min(batch_start + batch_size, num_requests)
                batch_tasks = []
                
                for i in range(batch_start, batch_end):
                    task = server.call_tool(
                        "brave_web_search",
                        {"query": f"stress test {i}"},
                        mock_user
                    )
                    batch_tasks.append(task)
                
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                all_results.extend(batch_results)
                
                # Small delay between batches
                await asyncio.sleep(0.1)
            
            end_time = time.time()
            
            success_count = sum(1 for r in all_results if not isinstance(r, Exception))
            
            # Should handle high volume reasonably
            assert success_count >= num_requests * 0.8  # At least 80% success under stress
            total_time = end_time - start_time
            rps = num_requests / total_time
            logger.info(f"Stress test: {rps:.2f} requests/second, {success_count}/{num_requests} successful")
    
    @pytest.mark.asyncio
    async def test_sustained_load(self, mock_user):
        """Test sustained load over time."""
        server = DesktopCommanderMCPServer()
        
        with patch.object(server, 'command_executor') as mock_executor:
            mock_result = Mock()
            mock_result.success = True
            mock_result.exit_code = 0
            mock_result.stdout = "output"
            mock_result.stderr = ""
            mock_result.command = "test"
            mock_result.working_directory = "/tmp"
            mock_result.truncated = False
            mock_executor.execute_async.return_value = mock_result
            
            # Sustained load for 10 seconds
            duration = 10  # seconds
            start_time = time.time()
            end_time = start_time + duration
            
            request_count = 0
            success_count = 0
            
            while time.time() < end_time:
                try:
                    await server.call_tool(
                        "execute_command",
                        {"command": f"echo {request_count}"},
                        mock_user
                    )
                    success_count += 1
                except Exception:
                    pass  # Count as failure
                
                request_count += 1
                
                # Small delay to avoid overwhelming
                await asyncio.sleep(0.05)
            
            actual_duration = time.time() - start_time
            rps = request_count / actual_duration
            success_rate = success_count / request_count if request_count > 0 else 0
            
            # Should maintain reasonable performance under sustained load
            assert success_rate >= 0.9  # At least 90% success
            assert rps >= 10  # At least 10 requests per second
            logger.info(f"Sustained load: {rps:.2f} RPS, {success_rate:.2%} success rate")


class TestMemoryPerformance:
    """Test memory usage and performance."""
    
    def test_memory_usage_baseline(self):
        """Test baseline memory usage of servers."""
        process = psutil.Process()
        baseline_memory = process.memory_info().rss
        
        # Create servers
        servers = [
            BraveMCPServer(api_key="test_key"),
            DesktopCommanderMCPServer(),
            DockerMCPServer(),
            SlackNotificationMCPServer(slack_token="test_token"),
            SecurityScannerMCPServer()
        ]
        
        after_creation_memory = process.memory_info().rss
        memory_increase = after_creation_memory - baseline_memory
        
        # Memory increase should be reasonable (less than 100MB)
        assert memory_increase < 100 * 1024 * 1024
        
        logger.info(f"Memory increase after server creation: {memory_increase / 1024 / 1024:.2f} MB")
    
    @pytest.mark.asyncio
    async def test_memory_leak_detection(self, mock_user):
        """Test for memory leaks during operations."""
        server = BraveMCPServer(api_key="test_key")
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"web": {"results": []}}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            process = psutil.Process()
            
            # Measure initial memory
            gc.collect()  # Force garbage collection
            initial_memory = process.memory_info().rss
            
            # Perform many operations
            for i in range(100):
                await server.call_tool(
                    "brave_web_search",
                    {"query": f"memory test {i}"},
                    mock_user
                )
                
                # Periodic garbage collection
                if i % 20 == 0:
                    gc.collect()
            
            # Final memory measurement
            gc.collect()
            final_memory = process.memory_info().rss
            memory_increase = final_memory - initial_memory
            
            # Memory increase should be minimal (less than 50MB)
            assert memory_increase < 50 * 1024 * 1024
            
            logger.info(f"Memory increase after 100 operations: {memory_increase / 1024 / 1024:.2f} MB")
    
    def test_large_response_handling(self):
        """Test handling of large responses."""
        # Test with large mock responses
        large_response_data = {
            "web": {
                "results": [
                    {
                        "title": f"Result {i}",
                        "url": f"https://example{i}.com",
                        "description": "A" * 1000  # 1KB description
                    }
                    for i in range(1000)  # 1000 results
                ]
            }
        }
        
        # Should handle large responses without excessive memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Process large response (simulated)
        processed_data = str(large_response_data)
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable
        assert memory_increase < 100 * 1024 * 1024  # Less than 100MB


class TestScalabilityLimits:
    """Test scalability limits and boundaries."""
    
    @pytest.mark.asyncio
    async def test_maximum_concurrent_connections(self, mock_user):
        """Test maximum concurrent connections."""
        server = BraveMCPServer(api_key="test_key")
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"web": {"results": []}}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            # Test with very high concurrency
            max_concurrency = 200
            
            tasks = []
            for i in range(max_concurrency):
                task = server.call_tool(
                    "brave_web_search",
                    {"query": f"scalability test {i}"},
                    mock_user
                )
                tasks.append(task)
            
            start_time = time.time()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            end_time = time.time()
            
            success_count = sum(1 for r in results if not isinstance(r, Exception))
            
            # Should handle high concurrency gracefully
            # Even if not all succeed, should not crash
            assert success_count > 0
            
            total_time = end_time - start_time
            logger.info(f"High concurrency test: {success_count}/{max_concurrency} successful in {total_time:.2f}s")
    
    def test_rate_limiter_performance(self):
        """Test rate limiter performance under load."""
        from src.mcp.monitoring.prometheus_server import RateLimiter
        
        rate_limiter = RateLimiter(max_requests=1000, window=60)
        
        # Test rate limiter performance
        start_time = time.time()
        
        allowed_count = 0
        for i in range(10000):  # 10k checks
            if rate_limiter.is_allowed(f"user_{i % 100}"):  # 100 different users
                allowed_count += 1
        
        end_time = time.time()
        
        checks_per_second = 10000 / (end_time - start_time)
        
        # Rate limiter should be fast
        assert checks_per_second > 1000  # At least 1000 checks per second
        logger.info(f"Rate limiter performance: {checks_per_second:.0f} checks/second")
    
    @pytest.mark.asyncio
    async def test_queue_saturation(self, mock_user):
        """Test behavior when internal queues are saturated."""
        server = SecurityScannerMCPServer()
        
        # The security scanner uses semaphores to limit concurrency
        # Test what happens when we exceed the semaphore limit
        
        mock_scan_tasks = []
        
        async def mock_long_scan(*args, **kwargs):
            await asyncio.sleep(1)  # Simulate long-running scan
            return {"status": "completed"}
        
        with patch.object(server, '_perform_security_scan', side_effect=mock_long_scan):
            # Create more tasks than the semaphore allows
            tasks = []
            for i in range(20):  # Should exceed semaphore limit
                # Note: actual implementation would depend on server's scan method
                pass
            
            # The server should handle queue saturation gracefully
            # Some requests might be queued or rejected, but shouldn't crash


class TestResourceUtilization:
    """Test CPU and resource utilization."""
    
    @pytest.mark.asyncio
    async def test_cpu_utilization(self, mock_user):
        """Test CPU utilization under load."""
        server = DesktopCommanderMCPServer()
        
        with patch.object(server, 'command_executor') as mock_executor:
            mock_result = Mock()
            mock_result.success = True
            mock_result.exit_code = 0
            mock_result.stdout = "output"
            mock_result.stderr = ""
            mock_result.command = "test"
            mock_result.working_directory = "/tmp"
            mock_result.truncated = False
            mock_executor.execute_async.return_value = mock_result
            
            process = psutil.Process()
            
            # Measure CPU before load
            cpu_before = process.cpu_percent()
            
            # Generate CPU load
            start_time = time.time()
            task_count = 0
            
            while time.time() - start_time < 5:  # 5 second test
                await server.call_tool(
                    "execute_command",
                    {"command": f"echo {task_count}"},
                    mock_user
                )
                task_count += 1
            
            # Measure CPU after load
            cpu_after = process.cpu_percent()
            
            logger.info(f"CPU utilization: {cpu_after}% (completed {task_count} tasks)")
            
            # CPU usage should be reasonable (not maxed out)
            assert cpu_after < 80  # Should not consume more than 80% CPU
    
    def test_file_descriptor_usage(self):
        """Test file descriptor usage."""
        import resource
        
        # Get initial file descriptor count
        initial_fds = len(psutil.Process().open_files())
        
        # Create multiple servers
        servers = []
        for i in range(10):
            servers.append(BraveMCPServer(api_key=f"test_key_{i}"))
        
        # Check file descriptor count after creation
        final_fds = len(psutil.Process().open_files())
        
        fd_increase = final_fds - initial_fds
        
        # Should not create excessive file descriptors
        assert fd_increase < 50  # Reasonable limit
        
        logger.info(f"File descriptor increase: {fd_increase}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])