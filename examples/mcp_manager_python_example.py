#!/usr/bin/env python3
"""
Example usage of the Rust MCP Manager from Python.

This demonstrates both synchronous and asynchronous usage patterns.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class MCPManagerWrapper:
    """Wrapper class for the Rust MCP Manager with convenience methods."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the MCP Manager wrapper."""
        try:
            from claude_optimized_deployment_rust import mcp_manager
            self.mcp_manager = mcp_manager
            self.manager = mcp_manager.PyMcpManager(config_path)
            self.started = False
            logger.info("MCP Manager initialized successfully")
        except ImportError as e:
            logger.error(f"Failed to import MCP manager: {e}")
            logger.error("Run: maturin develop --manifest-path rust_core/Cargo.toml")
            raise
    
    def start(self) -> None:
        """Start the MCP Manager."""
        if not self.started:
            self.manager.start()
            self.started = True
            logger.info("MCP Manager started")
    
    def stop(self) -> None:
        """Stop the MCP Manager."""
        if self.started:
            self.manager.stop()
            self.started = False
            logger.info("MCP Manager stopped")
    
    def deploy_server(self, server_id: str, config: Dict) -> None:
        """Deploy a new MCP server."""
        self.start()  # Ensure manager is started
        config_json = json.dumps(config)
        self.manager.deploy_server(server_id, config_json)
        logger.info(f"Deployed server: {server_id}")
    
    def undeploy_server(self, server_id: str) -> None:
        """Undeploy an MCP server."""
        self.manager.undeploy_server(server_id)
        logger.info(f"Undeployed server: {server_id}")
    
    def execute_request(self, server_id: str, request: Dict) -> Dict:
        """Execute a request on a server."""
        request_json = json.dumps(request)
        response_json = self.manager.execute(server_id, request_json)
        return json.loads(response_json)
    
    def get_health_status(self) -> Dict:
        """Get overall health status."""
        health = self.manager.get_health_status()
        return {
            'total_servers': health.total_servers,
            'healthy_servers': health.healthy_servers,
            'degraded_servers': health.degraded_servers,
            'unhealthy_servers': health.unhealthy_servers,
            'avg_response_time_ms': health.avg_response_time_ms,
        }
    
    def list_servers(self) -> List[Dict]:
        """List all deployed servers."""
        servers = self.manager.list_servers()
        return [
            {
                'id': server.id,
                'name': server.name,
                'type': server.server_type,
                'state': server.state,
                'priority': server.priority,
            }
            for server in servers
        ]
    
    def scale_server(self, server_id: str, instances: int) -> None:
        """Scale a server to the specified number of instances."""
        self.manager.scale_server(server_id, instances)
        logger.info(f"Scaled server {server_id} to {instances} instances")
    
    def get_metrics(self) -> str:
        """Get Prometheus-formatted metrics."""
        return self.manager.export_prometheus_metrics()
    
    async def start_async(self) -> None:
        """Async version of start."""
        if not self.started:
            await self.manager.start_async()
            self.started = True
            logger.info("MCP Manager started (async)")
    
    async def deploy_server_async(self, server_id: str, config: Dict) -> None:
        """Async version of deploy_server."""
        await self.start_async()  # Ensure manager is started
        config_json = json.dumps(config)
        await self.manager.deploy_server_async(server_id, config_json)
        logger.info(f"Deployed server (async): {server_id}")
    
    async def execute_request_async(self, server_id: str, request: Dict) -> Dict:
        """Async version of execute_request."""
        request_json = json.dumps(request)
        response_json = await self.manager.execute_async(server_id, request_json)
        return json.loads(response_json)


def sync_example():
    """Demonstrate synchronous usage of MCP Manager."""
    logger.info("=== Synchronous Example ===")
    
    # Create manager
    wrapper = MCPManagerWrapper()
    
    try:
        # Start the manager
        wrapper.start()
        
        # Define server configurations
        servers = [
            {
                'id': 'docker-server',
                'config': {
                    'name': 'Docker Management Server',
                    'server_type': 'infrastructure',
                    'url': 'http://localhost:8001',
                    'auth': {'type': 'api_key', 'key': 'docker-secret'},
                    'priority': 10,
                    'tags': ['docker', 'infrastructure']
                }
            },
            {
                'id': 'k8s-server',
                'config': {
                    'name': 'Kubernetes Management Server',
                    'server_type': 'infrastructure',
                    'url': 'http://localhost:8002',
                    'auth': {'type': 'bearer', 'token': 'k8s-token'},
                    'priority': 9,
                    'tags': ['kubernetes', 'infrastructure']
                }
            },
            {
                'id': 'monitoring-server',
                'config': {
                    'name': 'Prometheus Monitoring Server',
                    'server_type': 'monitoring',
                    'url': 'http://localhost:8010',
                    'auth': {'type': 'none'},
                    'priority': 8,
                    'tags': ['monitoring', 'prometheus']
                }
            }
        ]
        
        # Deploy servers
        for server in servers:
            wrapper.deploy_server(server['id'], server['config'])
        
        # List deployed servers
        deployed = wrapper.list_servers()
        logger.info(f"Deployed {len(deployed)} servers:")
        for server in deployed:
            logger.info(f"  - {server['name']} ({server['id']}): {server['state']}")
        
        # Check health status
        health = wrapper.get_health_status()
        logger.info(f"Health Status: {health['healthy_servers']}/{health['total_servers']} healthy")
        logger.info(f"Average response time: {health['avg_response_time_ms']}ms")
        
        # Execute some requests
        for server_id in ['docker-server', 'k8s-server']:
            try:
                response = wrapper.execute_request(server_id, {'method': 'ping'})
                logger.info(f"Ping response from {server_id}: {response}")
            except Exception as e:
                logger.error(f"Failed to ping {server_id}: {e}")
        
        # Scale a server
        wrapper.scale_server('docker-server', 3)
        
        # Get metrics
        metrics = wrapper.get_metrics()
        logger.info(f"Metrics sample:\n{metrics[:200]}...")
        
        # Undeploy a server
        wrapper.undeploy_server('monitoring-server')
        
    finally:
        # Always stop the manager
        wrapper.stop()


async def async_example():
    """Demonstrate asynchronous usage of MCP Manager."""
    logger.info("\n=== Asynchronous Example ===")
    
    # Create manager
    wrapper = MCPManagerWrapper()
    
    try:
        # Start the manager asynchronously
        await wrapper.start_async()
        
        # Deploy multiple servers concurrently
        deploy_tasks = [
            wrapper.deploy_server_async('async-server-1', {
                'name': 'Async Server 1',
                'server_type': 'test',
                'url': 'http://localhost:9001',
                'auth': {'type': 'none'},
                'priority': 5,
                'tags': ['async', 'test']
            }),
            wrapper.deploy_server_async('async-server-2', {
                'name': 'Async Server 2',
                'server_type': 'test',
                'url': 'http://localhost:9002',
                'auth': {'type': 'none'},
                'priority': 5,
                'tags': ['async', 'test']
            }),
        ]
        
        await asyncio.gather(*deploy_tasks)
        logger.info("Deployed async servers concurrently")
        
        # Execute concurrent requests
        request_tasks = [
            wrapper.execute_request_async('async-server-1', {'method': 'health'}),
            wrapper.execute_request_async('async-server-2', {'method': 'status'}),
        ]
        
        responses = await asyncio.gather(*request_tasks, return_exceptions=True)
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.error(f"Request {i+1} failed: {response}")
            else:
                logger.info(f"Request {i+1} response: {response}")
        
    finally:
        # Stop the manager
        wrapper.stop()


def main():
    """Run both synchronous and asynchronous examples."""
    # Run sync example
    sync_example()
    
    # Run async example
    asyncio.run(async_example())
    
    logger.info("\n✅ All examples completed successfully!")


if __name__ == "__main__":
    main()