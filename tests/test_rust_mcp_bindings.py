#!/usr/bin/env python3
"""
Comprehensive tests for Rust MCP Manager PyO3 bindings

Tests the Python-Rust FFI boundary for:
- Thread safety across GIL boundaries
- Async operation handling
- Error propagation
- Memory management
- Type conversions
"""

import asyncio
import concurrent.futures
import gc
import json
import pytest
import time
import threading
from typing import Dict, List, Any
from unittest.mock import Mock, patch

# Import the Rust module
try:
    from claude_optimized_deployment_rust import (
        MCPManager,
        MCPConfig,
        MCPServer,
        ServerState,
        MCPError,
        CircleOfExperts,
        Expert,
        Query,
        ConsensusLevel,
    )
except ImportError:
    pytest.skip("Rust module not built", allow_module_level=True)


class TestMCPConfig:
    """Test MCPConfig Python bindings"""
    
    def test_config_creation_default(self):
        """Test creating config with default values"""
        config = MCPConfig()
        
        assert config.max_connections_per_server == 10
        assert config.connection_timeout_ms == 5000
        assert config.enable_metrics is True
        assert config.circuit_breaker_threshold == 5
    
    def test_config_creation_custom(self):
        """Test creating config with custom values"""
        config = MCPConfig(
            max_connections_per_server=50,
            connection_timeout_ms=10000,
            enable_metrics=False,
            consensus_threshold=0.8
        )
        
        assert config.max_connections_per_server == 50
        assert config.connection_timeout_ms == 10000
        assert config.enable_metrics is False
        assert config.consensus_threshold == 0.8
    
    def test_config_validation(self):
        """Test config validation"""
        with pytest.raises(ValueError):
            MCPConfig(max_connections_per_server=0)
        
        with pytest.raises(ValueError):
            MCPConfig(connection_timeout_ms=-1)
        
        with pytest.raises(ValueError):
            MCPConfig(consensus_threshold=1.5)


class TestMCPManager:
    """Test MCPManager Python bindings"""
    
    @pytest.fixture
    def manager(self):
        """Create a test manager instance"""
        config = MCPConfig(
            max_connections_per_server=5,
            connection_timeout_ms=1000,
            health_check_interval_secs=60,
            enable_health_checks=False
        )
        return MCPManager(config)
    
    @pytest.mark.asyncio
    async def test_manager_lifecycle(self, manager):
        """Test manager start/stop lifecycle"""
        # Start manager
        await manager.start()
        assert manager.is_running()
        
        # Stop manager
        await manager.stop()
        assert not manager.is_running()
    
    @pytest.mark.asyncio
    async def test_server_registration(self, manager):
        """Test server registration and retrieval"""
        await manager.start()
        
        # Create test server
        server = MCPServer(
            id="test-python-1",
            name="Test Python Server",
            server_type="test",
            endpoint="ws://localhost:8888",
            state=ServerState.STOPPED,
            metadata={"version": "1.0", "region": "us-east"}
        )
        
        # Register server
        await manager.register_server(server)
        
        # Retrieve server
        retrieved = await manager.get_server("test-python-1")
        assert retrieved.id == server.id
        assert retrieved.name == server.name
        assert retrieved.metadata["version"] == "1.0"
        
        # List servers
        servers = await manager.list_servers()
        assert len(servers) == 1
        assert servers[0].id == "test-python-1"
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, manager):
        """Test thread safety with concurrent operations"""
        await manager.start()
        
        async def register_server(i: int):
            server = MCPServer(
                id=f"concurrent-{i}",
                name=f"Concurrent Server {i}",
                server_type="test",
                endpoint=f"ws://localhost:{9000 + i}",
                state=ServerState.STOPPED
            )
            await manager.register_server(server)
            return server.id
        
        # Register 20 servers concurrently
        tasks = [register_server(i) for i in range(20)]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 20
        assert len(set(results)) == 20  # All unique
        
        # Verify all registered
        servers = await manager.list_servers()
        assert len(servers) == 20
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_error_propagation(self, manager):
        """Test error propagation from Rust to Python"""
        await manager.start()
        
        # Test ServerNotFound error
        with pytest.raises(MCPError) as exc_info:
            await manager.get_server("non-existent")
        
        assert "ServerNotFound" in str(exc_info.value)
        
        # Test DuplicateServer error
        server = MCPServer(
            id="duplicate-test",
            name="Duplicate Test",
            server_type="test",
            endpoint="ws://localhost:7777"
        )
        
        await manager.register_server(server)
        
        with pytest.raises(MCPError) as exc_info:
            await manager.register_server(server)
        
        assert "DuplicateServer" in str(exc_info.value)
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_deployment_operations(self, manager):
        """Test deployment operations"""
        await manager.start()
        
        # Register a server
        server = MCPServer(
            id="deploy-test",
            name="Deploy Test",
            server_type="docker",
            endpoint="ws://localhost:8080"
        )
        await manager.register_server(server)
        
        # Deploy server
        result = await manager.deploy_server("deploy-test")
        assert result.success is True
        
        # Get status
        status = await manager.get_server_status("deploy-test")
        assert status.state == ServerState.RUNNING
        
        # Execute command
        cmd_result = await manager.execute_command(
            "deploy-test",
            "echo 'Hello from Python'"
        )
        assert cmd_result.success is True
        
        # Stop server
        await manager.stop_server("deploy-test")
        
        await manager.stop()


class TestThreadSafety:
    """Test thread safety across Python-Rust boundary"""
    
    @pytest.mark.asyncio
    async def test_gil_release_during_operations(self):
        """Test that GIL is properly released during Rust operations"""
        config = MCPConfig()
        manager = MCPManager(config)
        await manager.start()
        
        # Track if other threads can run
        counter = {"value": 0}
        stop_flag = threading.Event()
        
        def increment_counter():
            while not stop_flag.is_set():
                counter["value"] += 1
                time.sleep(0.001)
        
        # Start counter thread
        thread = threading.Thread(target=increment_counter)
        thread.start()
        
        # Perform long-running Rust operation
        servers = []
        for i in range(100):
            server = MCPServer(
                id=f"gil-test-{i}",
                name=f"GIL Test {i}",
                server_type="test",
                endpoint=f"ws://localhost:{10000 + i}"
            )
            servers.append(server)
        
        # Register all servers (should release GIL)
        await asyncio.gather(*[
            manager.register_server(server) for server in servers
        ])
        
        # Stop counter thread
        stop_flag.set()
        thread.join()
        
        # Counter should have incremented (GIL was released)
        assert counter["value"] > 0
        
        await manager.stop()
    
    def test_concurrent_manager_instances(self):
        """Test multiple manager instances in different threads"""
        results = {"errors": []}
        
        def run_manager(manager_id: int):
            try:
                # Create event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                async def manager_operations():
                    config = MCPConfig(
                        max_connections_per_server=10,
                        enable_health_checks=False
                    )
                    manager = MCPManager(config)
                    await manager.start()
                    
                    # Register some servers
                    for i in range(5):
                        server = MCPServer(
                            id=f"thread-{manager_id}-server-{i}",
                            name=f"Thread {manager_id} Server {i}",
                            server_type="test",
                            endpoint=f"ws://localhost:{20000 + manager_id * 10 + i}"
                        )
                        await manager.register_server(server)
                    
                    # Perform some operations
                    servers = await manager.list_servers()
                    assert len(servers) == 5
                    
                    await manager.stop()
                
                loop.run_until_complete(manager_operations())
                loop.close()
                
            except Exception as e:
                results["errors"].append(f"Manager {manager_id}: {str(e)}")
        
        # Run managers in parallel threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=run_manager, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Check no errors occurred
        assert len(results["errors"]) == 0


class TestMemoryManagement:
    """Test memory management across Python-Rust boundary"""
    
    @pytest.mark.asyncio
    async def test_memory_cleanup(self):
        """Test that memory is properly cleaned up"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Create and destroy many managers
        for i in range(10):
            config = MCPConfig()
            manager = MCPManager(config)
            await manager.start()
            
            # Register many servers
            for j in range(100):
                server = MCPServer(
                    id=f"mem-test-{i}-{j}",
                    name=f"Memory Test {i}-{j}",
                    server_type="test",
                    endpoint=f"ws://localhost:{30000 + i * 100 + j}"
                )
                await manager.register_server(server)
            
            await manager.stop()
            
            # Explicitly delete and collect
            del manager
            gc.collect()
        
        # Check memory usage
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Should not leak more than 50MB
        assert memory_increase < 50 * 1024 * 1024
    
    @pytest.mark.asyncio
    async def test_large_data_handling(self):
        """Test handling large data across FFI boundary"""
        config = MCPConfig()
        manager = MCPManager(config)
        await manager.start()
        
        # Create server with large metadata
        large_metadata = {
            f"key_{i}": "x" * 1000 for i in range(100)
        }
        
        server = MCPServer(
            id="large-data-test",
            name="Large Data Test",
            server_type="test",
            endpoint="ws://localhost:40000",
            metadata=large_metadata
        )
        
        await manager.register_server(server)
        
        # Retrieve and verify
        retrieved = await manager.get_server("large-data-test")
        assert len(retrieved.metadata) == 100
        assert all(len(v) == 1000 for v in retrieved.metadata.values())
        
        await manager.stop()


class TestCircleOfExperts:
    """Test Circle of Experts Python bindings"""
    
    @pytest.mark.asyncio
    async def test_expert_consultation(self):
        """Test expert consultation from Python"""
        # Create experts
        experts = [
            Expert("docker-expert", "docker", 0.9),
            Expert("k8s-expert", "kubernetes", 0.85),
            Expert("security-expert", "security", 0.95),
        ]
        
        circle = CircleOfExperts(experts)
        
        # Create query
        query = Query(
            id="test-query",
            content="How to deploy a secure containerized application?",
            context={"environment": "production", "scale": "large"},
            required_consensus=ConsensusLevel.STRONG
        )
        
        # Get recommendations
        result = await circle.consult(query)
        
        assert result.consensus_reached is True
        assert result.confidence > 0.7
        assert len(result.expert_opinions) == 3
        assert len(result.actions) > 0
    
    @pytest.mark.asyncio
    async def test_concurrent_consultations(self):
        """Test concurrent expert consultations"""
        experts = [
            Expert(f"expert-{i}", f"domain-{i}", 0.8 + i * 0.02)
            for i in range(5)
        ]
        
        circle = CircleOfExperts(experts)
        
        async def consult(query_id: int):
            query = Query(
                id=f"concurrent-query-{query_id}",
                content=f"Question {query_id}",
                context={"id": str(query_id)},
                required_consensus=ConsensusLevel.WEAK
            )
            return await circle.consult(query)
        
        # Run 20 consultations concurrently
        tasks = [consult(i) for i in range(20)]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 20
        assert all(r.consensus_reached for r in results)


class TestErrorScenarios:
    """Test various error scenarios"""
    
    @pytest.mark.asyncio
    async def test_panic_handling(self):
        """Test that Rust panics are converted to Python exceptions"""
        config = MCPConfig()
        manager = MCPManager(config)
        
        # This should cause a panic in Rust (hypothetical)
        with pytest.raises(Exception):
            await manager.trigger_panic_test()
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test timeout handling across FFI"""
        config = MCPConfig(
            connection_timeout_ms=100,  # Very short timeout
            request_timeout_ms=200
        )
        manager = MCPManager(config)
        await manager.start()
        
        # Register a server that will timeout
        server = MCPServer(
            id="timeout-test",
            name="Timeout Test",
            server_type="test",
            endpoint="ws://192.0.2.1:8080"  # Non-routable IP
        )
        await manager.register_server(server)
        
        # Deployment should timeout
        with pytest.raises(MCPError) as exc_info:
            await manager.deploy_server("timeout-test")
        
        assert "timeout" in str(exc_info.value).lower()
        
        await manager.stop()


class TestPerformance:
    """Performance tests for Python bindings"""
    
    @pytest.mark.asyncio
    async def test_bulk_operations_performance(self):
        """Test performance of bulk operations"""
        config = MCPConfig(enable_health_checks=False)
        manager = MCPManager(config)
        await manager.start()
        
        start_time = time.time()
        
        # Register 1000 servers
        servers = []
        for i in range(1000):
            server = MCPServer(
                id=f"perf-test-{i}",
                name=f"Performance Test {i}",
                server_type="test",
                endpoint=f"ws://localhost:{50000 + i}"
            )
            servers.append(server)
        
        # Bulk register
        await asyncio.gather(*[
            manager.register_server(server) for server in servers
        ])
        
        registration_time = time.time() - start_time
        
        # Should register 1000 servers in under 5 seconds
        assert registration_time < 5.0
        
        # Test bulk retrieval
        start_time = time.time()
        all_servers = await manager.list_servers()
        list_time = time.time() - start_time
        
        assert len(all_servers) == 1000
        assert list_time < 1.0  # Listing should be fast
        
        await manager.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])