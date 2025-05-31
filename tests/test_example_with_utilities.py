"""
Example test file demonstrating the use of test utilities.

This file shows how to use the comprehensive test utilities
for more maintainable and expressive tests.
"""

import pytest
import asyncio
from datetime import datetime, timedelta

from tests.utils import (
    MockFactory,
    TestDataGenerator,
    AssertionHelpers,
    TestHelpers,
    create_flaky_mock,
    assert_async_timeout
)


class TestExampleWithUtilities:
    """Example tests using the test utilities."""
    
    def test_mock_factory_expert_creation(self):
        """Test creating mock experts with the factory."""
        # Create a mock expert
        expert = MockFactory.create_mock_expert()
        
        # Verify the mock has expected attributes
        assert hasattr(expert, "expert_id")
        assert hasattr(expert, "query")
        assert expert.expert_id == "claude-test"
    
    async def test_mock_expert_query(self):
        """Test querying a mock expert."""
        # Create mock expert and query
        expert = MockFactory.create_mock_expert()
        query = MockFactory.create_expert_query(
            title="Test Infrastructure Query",
            content="How to optimize Kubernetes deployment?"
        )
        
        # Query the expert
        response = await expert.query(query)
        
        # Verify response
        AssertionHelpers.assert_expert_response_valid(response)
        assert response.query_id == query.id
    
    def test_test_data_generator(self):
        """Test generating realistic test data."""
        # Generate query content
        content = TestDataGenerator.generate_query_content("infrastructure")
        assert "infrastructure" in content.lower()
        
        # Generate deployment manifest
        manifest = TestDataGenerator.generate_deployment_manifest("test-app")
        AssertionHelpers.assert_json_structure(manifest, {
            "apiVersion": str,
            "kind": str,
            "metadata": dict,
            "spec": dict
        })
    
    async def test_with_helpers(self):
        """Test using various helper utilities."""
        # Test with timer
        async with TestHelpers.async_timer() as timer:
            await asyncio.sleep(0.1)
        
        AssertionHelpers.assert_in_range(timer["elapsed"], 0.09, 0.15)
        
        # Test temporary directory
        with TestHelpers.temporary_directory() as temp_dir:
            test_file = temp_dir / "test.txt"
            test_file.write_text("test content")
            assert test_file.exists()
        
        # Directory should be cleaned up
        assert not temp_dir.exists()
    
    def test_performance_data_generation(self):
        """Test generating performance data."""
        # Generate 30 minutes of performance data
        perf_data = TestDataGenerator.generate_performance_data(30)
        
        assert len(perf_data) == 30
        
        # Check data structure
        for entry in perf_data:
            AssertionHelpers.assert_json_structure(entry, {
                "timestamp": str,
                "cpu_percent": float,
                "memory_mb": int,
                "request_count": int
            })
    
    async def test_flaky_mock_behavior(self):
        """Test flaky mock that fails intermittently."""
        mock = create_flaky_mock(success_rate=0.5)
        
        successes = 0
        failures = 0
        
        for _ in range(20):
            try:
                await mock()
                successes += 1
            except:
                failures += 1
        
        # Should have both successes and failures
        assert successes > 0
        assert failures > 0
    
    def test_security_scan_results(self):
        """Test security scan result generation and validation."""
        # Generate scan results
        scan_results = TestDataGenerator.generate_security_scan_results()
        
        # Validate structure
        AssertionHelpers.assert_json_structure(scan_results, {
            "scan_id": str,
            "timestamp": str,
            "total_vulnerabilities": int,
            "vulnerabilities": list,
            "summary": dict
        })
        
        # Test security assertions
        AssertionHelpers.assert_security_scan_passed(
            scan_results,
            max_critical=5,  # Allow up to 5 critical issues for test
            max_high=10
        )
    
    async def test_mock_mcp_server(self):
        """Test creating and using a mock MCP server."""
        # Create mock server
        server = MockFactory.create_mock_mcp_server("test-docker")
        
        # Get server info
        info = await server.get_server_info()
        assert info["name"] == "test-docker"
        
        # Get tools
        tools = server.get_tools()
        assert len(tools) == 2
        
        # Call a tool
        result = await server.call_tool("test-docker_tool1", {"param": "value"})
        AssertionHelpers.assert_api_response_success(result)
    
    async def test_wait_for_condition(self):
        """Test waiting for a condition with timeout."""
        counter = {"value": 0}
        
        async def increment():
            await asyncio.sleep(0.1)
            counter["value"] += 1
        
        # Start incrementing task
        task = asyncio.create_task(increment())
        
        # Wait for condition
        await TestHelpers.wait_for_condition(
            lambda: counter["value"] > 0,
            timeout=1.0,
            message="Counter did not increment"
        )
        
        assert counter["value"] == 1
        await task
    
    def test_environment_configuration(self):
        """Test creating test configurations."""
        # Create default config
        config = TestHelpers.create_test_config()
        
        assert config["environment"] == "test"
        assert config["debug"] is True
        assert config["database"]["url"] == "sqlite:///:memory:"
        
        # Create config with overrides
        custom_config = TestHelpers.create_test_config({
            "timeout": 60,
            "api": {"base_url": "http://custom.test"}
        })
        
        assert custom_config["timeout"] == 60
        assert custom_config["api"]["base_url"] == "http://custom.test"
    
    def test_datetime_assertions(self):
        """Test datetime comparison assertions."""
        now = datetime.now()
        close_time = now + timedelta(seconds=2)
        far_time = now + timedelta(minutes=5)
        
        # Should pass - times are close
        AssertionHelpers.assert_datetime_close(now, close_time, delta=timedelta(seconds=5))
        
        # Should fail - times are too far apart
        with pytest.raises(AssertionError):
            AssertionHelpers.assert_datetime_close(now, far_time, delta=timedelta(seconds=5))
    
    async def test_async_timeout_assertion(self):
        """Test async timeout assertions."""
        async def slow_operation():
            await asyncio.sleep(2.0)
        
        # This should timeout
        await assert_async_timeout(slow_operation, timeout=0.5)
    
    def test_metric_trend_assertions(self):
        """Test asserting metric trends."""
        # Increasing trend
        increasing_metrics = [10, 12, 15, 18, 20]
        AssertionHelpers.assert_metric_trend(increasing_metrics, "increasing")
        
        # Decreasing trend
        decreasing_metrics = [20, 18, 15, 12, 10]
        AssertionHelpers.assert_metric_trend(decreasing_metrics, "decreasing")
        
        # Stable trend
        stable_metrics = [50, 52, 49, 51, 50]
        AssertionHelpers.assert_metric_trend(stable_metrics, "stable", tolerance=0.1)
    
    @pytest.mark.parametrize("expert_type,expected_prefix", [
        ("claude", "claude-test"),
        ("openai", "openai-test"),
        ("gemini", "gemini-test")
    ])
    def test_parameterized_mock_creation(self, expert_type, expected_prefix, mock_expert_manager):
        """Test parameterized mock creation with fixtures."""
        # This test uses the mock_expert_manager fixture from conftest.py
        experts = mock_expert_manager.get_available_experts()
        assert len(experts) > 0
        
        # Verify we can find experts of each type
        expert_types = [e["type"] for e in experts]
        assert any(expected_prefix in str(t) for t in expert_types)
    
    def test_error_scenario_generation(self):
        """Test generating various error scenarios."""
        errors = TestDataGenerator.create_error_scenarios()
        
        for error in errors:
            assert "type" in error
            assert "message" in error
            
            # Check specific error types
            if error["type"] == "RateLimitError":
                assert "retry_after" in error
            elif error["type"] == "ValidationError":
                assert "field" in error


class TestIntegrationWithUtilities:
    """Integration tests using utilities."""
    
    async def test_full_query_flow_with_mocks(
        self,
        mock_expert_manager,
        mock_query_handler,
        mock_response_collector,
        test_env_vars
    ):
        """Test full query flow using mock fixtures."""
        # Create test query
        query = MockFactory.create_expert_query(
            title="Integration Test Query",
            query_type="technical",
            priority="high"
        )
        
        # Process query
        await mock_query_handler.process_query(query)
        
        # Verify the flow
        mock_query_handler.process_query.assert_called_once()
        
        # Check cost estimation
        cost_estimate = mock_query_handler.estimate_cost(query)
        assert cost_estimate["estimated_cost"] > 0
    
    async def test_mcp_deployment_flow(self, mock_mcp_manager):
        """Test MCP deployment flow with utilities."""
        # Generate deployment manifest
        manifest = TestDataGenerator.generate_deployment_manifest("test-app")
        
        # Deploy using MCP
        result = await mock_mcp_manager.call_tool(
            "kubernetes.kubectl_apply",
            {"manifest": manifest}
        )
        
        # Verify deployment
        AssertionHelpers.assert_deployment_successful(result)
    
    def test_with_captured_logs(self):
        """Test with log capture utility."""
        import logging
        
        logger = logging.getLogger("test_logger")
        
        with TestHelpers.capture_logs("test_logger") as logs:
            logger.info("Test message 1")
            logger.warning("Test warning")
            logger.error("Test error")
        
        # Verify logs were captured
        assert len(logs) == 3
        assert logs[0].levelname == "INFO"
        assert logs[1].levelname == "WARNING"
        assert logs[2].levelname == "ERROR"


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v"])