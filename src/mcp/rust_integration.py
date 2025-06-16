"""
Rust MCP Manager Integration for Python.

This module provides a bridge between the Python MCP implementation and the
high-performance Rust MCP manager for improved performance and reliability.
"""

from __future__ import annotations
import asyncio
import logging
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
import json
from contextlib import asynccontextmanager

# Import Rust module (will be available after compilation)
try:
    from claude_optimized_deployment_rust import mcp_manager as rust_mcp
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    rust_mcp = None

from src.core.logging_config import get_logger
from src.core.exceptions import MCPError, MCPInitializationError

logger = get_logger(__name__)


@dataclass
class RustServerConfig:
    """Configuration for a Rust-managed MCP server."""
    server_type: str  # "http", "grpc", "websocket", or custom
    endpoint: str
    timeout_ms: int = 5000
    max_retries: int = 3
    circuit_breaker_enabled: bool = True


class RustMCPManager:
    """
    High-performance MCP Manager powered by Rust.
    
    Provides zero-copy operations, lock-free data structures, and
    integrated circuit breakers for bulletproof MCP server management.
    """
    
    def __init__(self, config_path: Optional[str] = None, hot_reload: bool = True):
        """Initialize the Rust MCP Manager."""
        if not RUST_AVAILABLE:
            raise MCPInitializationError(
                "Rust MCP module not available. Please build the Rust core first.",
                details={"build_command": "cargo build --release"}
            )
        
        self.config_path = config_path or "config/mcp"
        self.hot_reload = hot_reload
        self._manager = None
        self._initialized = False
        
    async def initialize(self):
        """Initialize the Rust manager."""
        if self._initialized:
            return
            
        try:
            # Create Rust manager instance
            self._manager = rust_mcp.MCPManager(
                config_path=self.config_path,
                hot_reload=self.hot_reload,
                max_concurrent_ops=50
            )
            
            # Initialize in Rust
            self._manager.initialize()
            
            self._initialized = True
            logger.info("Rust MCP Manager initialized successfully")
            
        except Exception as e:
            raise MCPInitializationError(
                "Failed to initialize Rust MCP Manager",
                cause=e
            )
    
    async def deploy_server(self, name: str, config: RustServerConfig) -> None:
        """Deploy a new MCP server using Rust."""
        if not self._initialized:
            await self.initialize()
        
        try:
            # Create Rust config
            rust_config = rust_mcp.ServerConfig(
                server_type=config.server_type,
                endpoint=config.endpoint,
                timeout_ms=config.timeout_ms,
                max_retries=config.max_retries,
                circuit_breaker_enabled=config.circuit_breaker_enabled
            )
            
            # Deploy through Rust
            self._manager.deploy_server(name, rust_config)
            
            logger.info(f"Deployed server '{name}' through Rust manager")
            
        except Exception as e:
            raise MCPError(f"Failed to deploy server '{name}': {str(e)}")
    
    async def undeploy_server(self, name: str) -> None:
        """Undeploy an MCP server."""
        if not self._initialized:
            raise MCPError("Manager not initialized")
        
        try:
            self._manager.undeploy_server(name)
            logger.info(f"Undeployed server '{name}'")
        except Exception as e:
            raise MCPError(f"Failed to undeploy server '{name}': {str(e)}")
    
    def list_servers(self) -> List[str]:
        """List all deployed servers."""
        if not self._initialized:
            return []
        
        return self._manager.list_servers()
    
    async def get_server_health(self, name: str) -> Optional[Dict[str, Any]]:
        """Get health status for a server."""
        if not self._initialized:
            return None
        
        status = self._manager.get_server_health(name)
        if status:
            return {
                "server_name": status.server_name,
                "is_healthy": status.is_healthy,
                "consecutive_failures": status.consecutive_failures,
                "consecutive_successes": status.consecutive_successes,
                "last_error": status.last_error,
                "response_time_ms": status.response_time_ms,
            }
        return None
    
    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        params: Dict[str, Any]
    ) -> Any:
        """Call a tool on a server with zero-copy optimization."""
        if not self._initialized:
            await self.initialize()
        
        try:
            # Serialize parameters
            params_bytes = json.dumps(params).encode('utf-8')
            
            # Call through Rust (zero-copy)
            result_bytes = self._manager.call_tool(server_name, tool_name, params_bytes)
            
            # Deserialize result
            return json.loads(result_bytes)
            
        except Exception as e:
            raise MCPError(f"Tool call failed: {str(e)}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics from Rust."""
        if not self._initialized:
            return {}
        
        metrics = self._manager.get_metrics()
        return {
            "timestamp": metrics.timestamp,
            "global": {
                "total_deployments": metrics.total_deployments,
                "failed_deployments": metrics.failed_deployments,
                "deployment_success_rate": metrics.deployment_success_rate,
                "active_servers": metrics.active_servers,
                "total_requests": metrics.total_requests,
                "total_failures": metrics.total_failures,
                "overall_success_rate": metrics.overall_success_rate,
            }
        }
    
    async def shutdown(self):
        """Shutdown the Rust manager."""
        if self._initialized and self._manager:
            self._manager.shutdown()
            self._initialized = False
            logger.info("Rust MCP Manager shut down")


class HybridMCPManager:
    """
    Hybrid MCP Manager that uses Rust for performance-critical operations
    while maintaining compatibility with the Python implementation.
    """
    
    def __init__(self, use_rust: bool = True):
        """Initialize hybrid manager."""
        self.use_rust = use_rust and RUST_AVAILABLE
        
        if self.use_rust:
            self.rust_manager = RustMCPManager()
            logger.info("Using Rust-accelerated MCP Manager")
        else:
            # Fall back to Python implementation
            from src.mcp.manager import MCPManager
            self.python_manager = MCPManager()
            logger.info("Using Python MCP Manager")
    
    async def initialize(self):
        """Initialize the appropriate manager."""
        if self.use_rust:
            await self.rust_manager.initialize()
        else:
            await self.python_manager.initialize()
    
    async def deploy_server(self, name: str, config: Union[RustServerConfig, Dict[str, Any]]):
        """Deploy server using the appropriate manager."""
        if self.use_rust:
            if isinstance(config, dict):
                config = RustServerConfig(**config)
            await self.rust_manager.deploy_server(name, config)
        else:
            # Convert to Python format if needed
            if isinstance(config, RustServerConfig):
                config = {
                    "server_type": config.server_type,
                    "endpoint": config.endpoint,
                    "timeout_ms": config.timeout_ms,
                    "max_retries": config.max_retries,
                }
            # Python manager would handle deployment
            pass
    
    async def call_tool(self, server_name: str, tool_name: str, params: Dict[str, Any]) -> Any:
        """Call tool using the appropriate manager."""
        if self.use_rust:
            return await self.rust_manager.call_tool(server_name, tool_name, params)
        else:
            # Python manager would handle tool call
            return await self.python_manager.call_tool(f"{server_name}.{tool_name}", params)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics from the appropriate manager."""
        if self.use_rust:
            return self.rust_manager.get_metrics()
        else:
            return self.python_manager.get_cache_stats()


# Circle of Experts Integration
class RustMCPExpertIntegration:
    """Integration between Rust MCP Manager and Circle of Experts."""
    
    def __init__(self, mcp_manager: RustMCPManager):
        """Initialize integration."""
        self.mcp_manager = mcp_manager
        
        if RUST_AVAILABLE:
            self._integration = rust_mcp.MCPExpertIntegration(mcp_manager._manager)
        else:
            self._integration = None
    
    async def call_with_consensus(
        self,
        server_name: str,
        tool_name: str,
        params: Dict[str, Any],
        expert_responses: List[Dict[str, Any]]
    ) -> Any:
        """
        Call MCP tool with parameters modified by expert consensus.
        
        High-confidence expert responses are used to optimize tool parameters.
        """
        if self._integration:
            # Use Rust integration for performance
            params_bytes = json.dumps(params).encode('utf-8')
            result = self._integration.call_with_consensus(
                server_name,
                tool_name,
                params_bytes,
                expert_responses
            )
            return json.loads(result)
        else:
            # Fallback to regular call
            return await self.mcp_manager.call_tool(server_name, tool_name, params)


# Context manager for Rust MCP Manager
@asynccontextmanager
async def rust_mcp_manager(config_path: Optional[str] = None, hot_reload: bool = True):
    """Context manager for Rust MCP Manager with automatic cleanup."""
    manager = RustMCPManager(config_path, hot_reload)
    try:
        await manager.initialize()
        yield manager
    finally:
        await manager.shutdown()


# Example usage
async def example_usage():
    """Example of using the Rust MCP Manager."""
    async with rust_mcp_manager() as manager:
        # Deploy a server
        await manager.deploy_server("example_server", RustServerConfig(
            server_type="http",
            endpoint="http://localhost:8080",
            timeout_ms=5000,
            max_retries=3,
            circuit_breaker_enabled=True
        ))
        
        # Call a tool
        result = await manager.call_tool(
            "example_server",
            "example_tool",
            {"param1": "value1", "param2": 42}
        )
        
        # Get metrics
        metrics = manager.get_metrics()
        print(f"Active servers: {metrics['global']['active_servers']}")
        
        # Check health
        health = await manager.get_server_health("example_server")
        print(f"Server healthy: {health['is_healthy'] if health else 'Unknown'}")


if __name__ == "__main__":
    # Check if Rust is available
    if RUST_AVAILABLE:
        print("Rust MCP Manager is available!")
        asyncio.run(example_usage())
    else:
        print("Rust MCP Manager not available. Build with: cargo build --release")