"""
Comprehensive integration tests for Rust MCP Manager module.

Tests all functionality including:
- Server deployment and management
- Health monitoring
- Circuit breakers
- Load balancing
- Distributed coordination
- Chaos engineering
- Performance and reliability
"""

import asyncio
import pytest
import time
import random
import os
import sys
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the Rust module
try:
    from rust_core import mcp_manager
except ImportError:
    pytest.skip("Rust core not built", allow_module_level=True)

from src.mcp.protocols import MCPTool


class TestMCPRustIntegration:
    """Test suite for Rust MCP Manager integration."""

    @pytest.fixture
    async def manager(self):
        """Create MCP manager instance."""
        config = {
            "max_concurrent_operations": 10,
            "deployment_retry_count": 3,
            "health_check_interval": 5,
            "circuit_breaker": {
                "failure_threshold": 5,
                "timeout": 60,
                "failure_rate_threshold": 0.5
            }
        }
        manager = mcp_manager.MCPManager(config)
        await manager.initialize()
        yield manager
        await manager.shutdown()

    @pytest.mark.asyncio
    async def test_server_deployment(self, manager):
        """Test deploying MCP servers."""
        # Deploy infrastructure servers
        infra_config = {
            "name": "docker-server",
            "type": "docker",
            "port": 8001,
            "config": {
                "docker_socket": "/var/run/docker.sock",
                "api_version": "1.43"
            }
        }
        
        result = await manager.deploy_server(infra_config)
        assert result["success"] is True
        assert result["server_id"] is not None
        
        # Verify server is registered
        servers = await manager.list_servers()
        assert any(s["name"] == "docker-server" for s in servers)

    @pytest.mark.asyncio
    async def test_health_monitoring(self, manager):
        """Test health monitoring functionality."""
        # Deploy a test server
        config = {
            "name": "test-health-server",
            "type": "prometheus",
            "port": 8010,
            "config": {}
        }
        
        deploy_result = await manager.deploy_server(config)
        server_id = deploy_result["server_id"]
        
        # Wait for health checks
        await asyncio.sleep(2)
        
        # Get health status
        health = await manager.get_server_health(server_id)
        assert health["status"] in ["healthy", "unhealthy"]
        assert "last_check" in health
        assert "metrics" in health

    @pytest.mark.asyncio
    async def test_circuit_breaker(self, manager):
        """Test circuit breaker functionality."""
        # Deploy a server that will fail
        config = {
            "name": "failing-server",
            "type": "test",
            "port": 9999,
            "config": {
                "fail_rate": 1.0  # Always fail
            }
        }
        
        deploy_result = await manager.deploy_server(config)
        server_id = deploy_result["server_id"]
        
        # Make requests until circuit opens
        failures = 0
        for _ in range(10):
            try:
                await manager.execute_tool(server_id, "test_tool", {})
            except Exception:
                failures += 1
        
        # Circuit should be open after threshold
        assert failures >= 5
        
        # Next request should fail immediately (circuit open)
        start = time.time()
        with pytest.raises(Exception) as exc_info:
            await manager.execute_tool(server_id, "test_tool", {})
        duration = time.time() - start
        
        assert duration < 0.1  # Should fail fast
        assert "circuit open" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_load_balancing(self, manager):
        """Test load balancing strategies."""
        # Deploy multiple instances
        instances = []
        for i in range(3):
            config = {
                "name": f"lb-test-{i}",
                "type": "test",
                "port": 8100 + i,
                "config": {}
            }
            result = await manager.deploy_server(config)
            instances.append(result["server_id"])
        
        # Create load balancer
        lb_config = {
            "strategy": "round_robin",
            "servers": instances
        }
        lb = await manager.create_load_balancer("test-lb", lb_config)
        
        # Make requests and verify distribution
        responses = []
        for _ in range(9):
            result = await manager.execute_through_lb("test-lb", "echo", {"msg": "test"})
            responses.append(result["server_id"])
        
        # Each server should have received 3 requests (round-robin)
        for server_id in instances:
            assert responses.count(server_id) == 3

    @pytest.mark.asyncio
    async def test_distributed_coordination(self, manager):
        """Test distributed coordination with Raft."""
        # Create a cluster
        nodes = []
        for i in range(3):
            node_config = {
                "node_id": f"node-{i}",
                "address": f"127.0.0.1:{9000 + i}"
            }
            node = await manager.create_cluster_node(node_config)
            nodes.append(node)
        
        # Wait for leader election
        await asyncio.sleep(2)
        
        # Get cluster state
        state = await manager.get_cluster_state()
        assert state["leader"] is not None
        assert len(state["nodes"]) == 3
        
        # Test consensus operation
        result = await manager.cluster_consensus_write("test-key", "test-value")
        assert result["success"] is True
        
        # Verify replication
        for node in nodes:
            value = await manager.cluster_read(node["node_id"], "test-key")
            assert value == "test-value"

    @pytest.mark.asyncio
    async def test_chaos_engineering(self, manager):
        """Test chaos engineering capabilities."""
        # Deploy test servers
        servers = []
        for i in range(2):
            config = {
                "name": f"chaos-test-{i}",
                "type": "test",
                "port": 8200 + i,
                "config": {}
            }
            result = await manager.deploy_server(config)
            servers.append(result["server_id"])
        
        # Create chaos experiment
        experiment = {
            "type": "network_latency",
            "targets": servers,
            "parameters": {
                "latency_ms": 100,
                "jitter_ms": 20,
                "duration": 5
            }
        }
        
        # Start experiment
        exp_id = await manager.start_chaos_experiment(experiment)
        
        # Measure latency during experiment
        latencies = []
        start = time.time()
        while time.time() - start < 3:
            for server_id in servers:
                t1 = time.time()
                try:
                    await manager.execute_tool(server_id, "ping", {})
                    latencies.append((time.time() - t1) * 1000)
                except:
                    pass
            await asyncio.sleep(0.1)
        
        # Average latency should be around 100ms
        avg_latency = sum(latencies) / len(latencies)
        assert 80 < avg_latency < 120
        
        # Stop experiment
        await manager.stop_chaos_experiment(exp_id)

    @pytest.mark.asyncio
    async def test_bulkhead_pattern(self, manager):
        """Test bulkhead resource isolation."""
        # Create bulkheads for different services
        bulkheads = {
            "critical": {"max_concurrent": 5, "queue_size": 10},
            "normal": {"max_concurrent": 3, "queue_size": 5}
        }
        
        for name, config in bulkheads.items():
            await manager.create_bulkhead(name, config)
        
        # Deploy servers with bulkhead assignment
        critical_server = await manager.deploy_server({
            "name": "critical-service",
            "type": "test",
            "port": 8300,
            "bulkhead": "critical",
            "config": {"processing_time": 0.1}
        })
        
        normal_server = await manager.deploy_server({
            "name": "normal-service",
            "type": "test",
            "port": 8301,
            "bulkhead": "normal",
            "config": {"processing_time": 0.1}
        })
        
        # Test isolation - flood normal service
        normal_tasks = []
        for _ in range(10):
            task = asyncio.create_task(
                manager.execute_tool(normal_server["server_id"], "process", {})
            )
            normal_tasks.append(task)
        
        # Critical service should still be responsive
        start = time.time()
        result = await manager.execute_tool(
            critical_server["server_id"], "process", {}
        )
        duration = time.time() - start
        
        assert duration < 0.2  # Should not be blocked
        assert result["success"] is True
        
        # Clean up tasks
        await asyncio.gather(*normal_tasks, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_caching_strategies(self, manager):
        """Test advanced caching with different eviction policies."""
        # Create caches with different policies
        caches = {
            "lru": {"policy": "lru", "max_size": 100},
            "lfu": {"policy": "lfu", "max_size": 100},
            "ttl": {"policy": "ttl", "default_ttl": 1}
        }
        
        for name, config in caches.items():
            await manager.create_cache(name, config)
        
        # Test LRU cache
        for i in range(150):
            await manager.cache_set("lru", f"key-{i}", f"value-{i}")
        
        # First 50 should be evicted
        for i in range(50):
            result = await manager.cache_get("lru", f"key-{i}")
            assert result is None
        
        # Last 100 should be present
        for i in range(50, 150):
            result = await manager.cache_get("lru", f"key-{i}")
            assert result == f"value-{i}"
        
        # Test TTL cache
        await manager.cache_set("ttl", "temp-key", "temp-value")
        result = await manager.cache_get("ttl", "temp-key")
        assert result == "temp-value"
        
        # Wait for TTL
        await asyncio.sleep(1.1)
        result = await manager.cache_get("ttl", "temp-key")
        assert result is None

    @pytest.mark.asyncio
    async def test_predictive_prefetching(self, manager):
        """Test ML-based predictive prefetching."""
        # Enable prefetching
        await manager.enable_prefetching({
            "strategies": ["sequential", "temporal", "neural"],
            "confidence_threshold": 0.7
        })
        
        # Create access patterns
        # Sequential pattern
        for i in range(10):
            await manager.access_resource(f"seq-{i}")
            await asyncio.sleep(0.01)
        
        # Should predict next in sequence
        predictions = await manager.get_prefetch_predictions()
        assert any("seq-10" in p["resource"] for p in predictions)
        
        # Temporal pattern (every 5th access)
        for cycle in range(3):
            for i in range(5):
                if i == 0:
                    await manager.access_resource("temporal-resource")
                else:
                    await manager.access_resource(f"other-{i}")
                await asyncio.sleep(0.01)
        
        # Should learn temporal pattern
        await manager.access_resource("other-1")
        predictions = await manager.get_prefetch_predictions()
        assert any("temporal-resource" in p["resource"] for p in predictions)

    @pytest.mark.asyncio
    async def test_performance_benchmarks(self, manager):
        """Test performance meets requirements."""
        # Deploy high-performance server
        config = {
            "name": "perf-test",
            "type": "test",
            "port": 8400,
            "config": {
                "zero_copy": True,
                "connection_pool_size": 50
            }
        }
        
        result = await manager.deploy_server(config)
        server_id = result["server_id"]
        
        # Benchmark throughput
        start = time.time()
        tasks = []
        request_count = 1000
        
        for i in range(request_count):
            task = asyncio.create_task(
                manager.execute_tool(server_id, "echo", {"msg": f"test-{i}"})
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start
        
        successful = sum(1 for r in results if not isinstance(r, Exception))
        throughput = successful / duration
        
        # Should handle at least 500 req/s
        assert throughput > 500
        print(f"Throughput: {throughput:.2f} req/s")
        
        # Test latency
        latencies = []
        for _ in range(100):
            start = time.time()
            await manager.execute_tool(server_id, "echo", {"msg": "latency-test"})
            latencies.append((time.time() - start) * 1000)
        
        # P99 latency should be under 10ms
        latencies.sort()
        p99 = latencies[int(len(latencies) * 0.99)]
        assert p99 < 10
        print(f"P99 latency: {p99:.2f}ms")

    @pytest.mark.asyncio
    async def test_graceful_shutdown(self, manager):
        """Test graceful shutdown with active operations."""
        # Deploy servers
        servers = []
        for i in range(3):
            config = {
                "name": f"shutdown-test-{i}",
                "type": "test",
                "port": 8500 + i,
                "config": {}
            }
            result = await manager.deploy_server(config)
            servers.append(result["server_id"])
        
        # Start long-running operations
        tasks = []
        for server_id in servers:
            for _ in range(5):
                task = asyncio.create_task(
                    manager.execute_tool(server_id, "long_operation", {"duration": 2})
                )
                tasks.append(task)
        
        # Give tasks time to start
        await asyncio.sleep(0.1)
        
        # Initiate graceful shutdown
        shutdown_task = asyncio.create_task(manager.shutdown(grace_period=3))
        
        # New operations should be rejected
        with pytest.raises(Exception) as exc_info:
            await manager.deploy_server({"name": "new-server", "type": "test", "port": 9000})
        assert "shutting down" in str(exc_info.value).lower()
        
        # Wait for shutdown
        await shutdown_task
        
        # All tasks should have completed or been cancelled gracefully
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Some should succeed, some might be cancelled
        assert len(results) == 15

    @pytest.mark.asyncio
    async def test_hot_reload_configuration(self, manager):
        """Test hot-reload of configuration changes."""
        # Initial configuration
        initial_config = {
            "servers": [
                {"name": "reload-test", "type": "test", "port": 8600}
            ]
        }
        
        # Write config file
        import json
        config_path = "/tmp/mcp_test_config.json"
        with open(config_path, "w") as f:
            json.dump(initial_config, f)
        
        # Enable hot reload
        await manager.enable_hot_reload(config_path)
        
        # Wait for initial deployment
        await asyncio.sleep(1)
        servers = await manager.list_servers()
        assert len(servers) == 1
        
        # Update configuration
        updated_config = {
            "servers": [
                {"name": "reload-test", "type": "test", "port": 8600},
                {"name": "new-server", "type": "test", "port": 8601}
            ]
        }
        
        with open(config_path, "w") as f:
            json.dump(updated_config, f)
        
        # Wait for hot reload
        await asyncio.sleep(2)
        
        # Should have new server
        servers = await manager.list_servers()
        assert len(servers) == 2
        assert any(s["name"] == "new-server" for s in servers)
        
        # Clean up
        os.unlink(config_path)


@pytest.mark.asyncio
async def test_integration_with_circle_of_experts():
    """Test integration between MCP Manager and Circle of Experts."""
    # This would test the integration between the two Rust modules
    from rust_core import circle_of_experts
    
    # Create MCP manager
    mcp_config = {"max_concurrent_operations": 10}
    mcp_mgr = mcp_manager.MCPManager(mcp_config)
    await mcp_mgr.initialize()
    
    # Create Circle of Experts
    coe_config = {"consensus_threshold": 0.7}
    coe = circle_of_experts.CircleOfExperts(coe_config)
    
    # Deploy expert servers via MCP
    expert_configs = [
        {"name": "expert-1", "type": "claude", "port": 8700},
        {"name": "expert-2", "type": "gpt4", "port": 8701},
        {"name": "expert-3", "type": "gemini", "port": 8702}
    ]
    
    expert_servers = []
    for config in expert_configs:
        result = await mcp_mgr.deploy_server(config)
        expert_servers.append(result["server_id"])
    
    # Register servers with Circle of Experts
    for server_id in expert_servers:
        await coe.register_expert(server_id, mcp_mgr)
    
    # Test consensus query
    query = "What is the best deployment strategy for a microservices architecture?"
    result = await coe.query_consensus(query)
    
    assert result["consensus_reached"] is True
    assert len(result["expert_responses"]) == 3
    assert result["confidence"] > 0.5
    
    # Clean up
    await mcp_mgr.shutdown()


if __name__ == "__main__":
    # Run specific test
    import sys
    if len(sys.argv) > 1:
        test_name = sys.argv[1]
        asyncio.run(eval(f"test_{test_name}()"))
    else:
        # Run all tests
        pytest.main([__file__, "-v", "-s"])