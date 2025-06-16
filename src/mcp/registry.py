"""
MCP Server Registry with lazy loading support.

This module provides a registry for MCP servers that avoids circular imports
by using lazy loading and dependency injection patterns.
"""

from __future__ import annotations
import logging
from typing import Dict, Any, List, Optional, Callable, Type
from importlib import import_module

from src.mcp.protocols import MCPServer, MCPTool

logger = logging.getLogger(__name__)

__all__ = ["MCPServerRegistry", "get_server_registry", "register_server_factory"]


class ServerFactory:
    """Factory for lazy server instantiation."""
    
    def __init__(self, module_path: str, class_name: str, requires_api_key: bool = False):
        self.module_path = module_path
        self.class_name = class_name
        self.requires_api_key = requires_api_key
        self._cached_class: Optional[Type[MCPServer]] = None
    
    def get_class(self) -> Type[MCPServer]:
        """Get the server class, importing it if necessary."""
        if self._cached_class is None:
            module = import_module(self.module_path)
            self._cached_class = getattr(module, self.class_name)
        return self._cached_class
    
    def create_instance(self, permission_checker: Any, **kwargs) -> MCPServer:
        """Create a server instance with the given permission checker."""
        server_class = self.get_class()
        return server_class(permission_checker=permission_checker, **kwargs)


class MCPServerRegistry:
    """Registry for managing multiple MCP servers with lazy loading."""
    
    def __init__(self, permission_checker: Any):
        """Initialize registry with required permission checker.
        
        Args:
            permission_checker: Required permission checker for authentication
            
        Raises:
            ValueError: If permission checker is not provided
        """
        if not permission_checker:
            raise ValueError(
                "Permission checker is required for MCP server registry. "
                "Cannot create registry without proper authentication system."
            )
        self.servers: Dict[str, MCPServer] = {}
        self.server_factories: Dict[str, ServerFactory] = {}
        self.permission_checker = permission_checker
        self._register_default_factories()
    
    def _register_default_factories(self):
        """Register default server factories."""
        # Core servers
        self.register_factory("brave", ServerFactory(
            "src.mcp.servers", "BraveMCPServer", requires_api_key=True
        ))
        
        # Infrastructure servers
        self.register_factory("desktop-commander", ServerFactory(
            "src.mcp.infrastructure_servers", "DesktopCommanderMCPServer"
        ))
        self.register_factory("docker", ServerFactory(
            "src.mcp.infrastructure_servers", "DockerMCPServer"
        ))
        self.register_factory("kubernetes", ServerFactory(
            "src.mcp.infrastructure_servers", "KubernetesMCPServer"
        ))
        
        # DevOps servers
        self.register_factory("azure-devops", ServerFactory(
            "src.mcp.devops_servers", "AzureDevOpsMCPServer"
        ))
        self.register_factory("windows-system", ServerFactory(
            "src.mcp.devops_servers", "WindowsSystemMCPServer"
        ))
        
        # Monitoring servers
        self.register_factory("prometheus-monitoring", ServerFactory(
            "src.mcp.monitoring.prometheus_server", "PrometheusMonitoringMCP"
        ))
        
        # Security servers
        self.register_factory("security-scanner", ServerFactory(
            "src.mcp.security.scanner_server", "SecurityScannerMCPServer"
        ))
        self.register_factory("sast-scanner", ServerFactory(
            "src.mcp.security.sast_server", "SASTMCPServer"
        ))
        self.register_factory("supply-chain-security", ServerFactory(
            "src.mcp.security.supply_chain_server", "SupplyChainSecurityMCPServer"
        ))
        
        # Communication servers
        self.register_factory("slack-notifications", ServerFactory(
            "src.mcp.communication.slack_server", "SlackNotificationMCPServer"
        ))
        
        # Storage servers
        self.register_factory("s3-storage", ServerFactory(
            "src.mcp.storage.s3_server", "S3StorageMCPServer"
        ))
        self.register_factory("cloud-storage", ServerFactory(
            "src.mcp.storage.cloud_storage_server", "CloudStorageMCP"
        ))
    
    def register_factory(self, name: str, factory: ServerFactory):
        """Register a server factory for lazy instantiation."""
        self.server_factories[name] = factory
        logger.debug(f"Registered server factory: {name}")
    
    def register(self, name: str, server: MCPServer):
        """Register an already instantiated MCP server."""
        self.servers[name] = server
        logger.info(f"Registered MCP server instance: {name}")
    
    def get(self, name: str, **kwargs) -> Optional[MCPServer]:
        """Get an MCP server by name, creating it if necessary.
        
        Args:
            name: Server name
            **kwargs: Additional arguments for server creation (e.g., api_key)
        
        Returns:
            The server instance or None if not found
        """
        # Return cached instance if available
        if name in self.servers:
            return self.servers[name]
        
        # Try to create from factory
        if name in self.server_factories:
            try:
                factory = self.server_factories[name]
                server = factory.create_instance(self.permission_checker, **kwargs)
                self.servers[name] = server
                logger.info(f"Created and cached MCP server: {name}")
                return server
            except Exception as e:
                logger.error(f"Failed to create server {name}: {e}")
                return None
        
        return None
    
    def list_servers(self) -> List[str]:
        """List all available server names (both instantiated and factories)."""
        instantiated = set(self.servers.keys())
        available = set(self.server_factories.keys())
        return sorted(list(instantiated | available))
    
    def list_instantiated_servers(self) -> List[str]:
        """List only instantiated server names."""
        return list(self.servers.keys())
    
    def get_all_tools(self) -> Dict[str, List[MCPTool]]:
        """Get all tools from all instantiated servers."""
        tools = {}
        for name, server in self.servers.items():
            # Use a dummy user for tool listing in registry context
            # Actual permission checking happens during tool execution
            try:
                class DummyUser:
                    id = "registry"
                    username = "registry"
                    roles = ["admin"]
                
                tools[name] = server.get_tools(DummyUser())
            except Exception as e:
                logger.warning(f"Failed to get tools from {name}: {e}")
                tools[name] = []
        return tools
    
    def ensure_server(self, name: str, **kwargs) -> MCPServer:
        """Ensure a server is available, creating it if necessary.
        
        Args:
            name: Server name
            **kwargs: Additional arguments for server creation
            
        Returns:
            The server instance
            
        Raises:
            ValueError: If server cannot be created
        """
        server = self.get(name, **kwargs)
        if not server:
            raise ValueError(f"Server '{name}' not found and could not be created")
        return server


# Global registry instance
_registry: Optional[MCPServerRegistry] = None


def get_server_registry(permission_checker: Any) -> MCPServerRegistry:
    """Get or create the global server registry.
    
    Args:
        permission_checker: Permission checker for authentication
        
    Returns:
        The global registry instance
    """
    global _registry
    if _registry is None:
        _registry = MCPServerRegistry(permission_checker)
    return _registry


def register_server_factory(name: str, module_path: str, class_name: str, 
                          requires_api_key: bool = False):
    """Register a server factory with the global registry.
    
    This allows external modules to register their servers without
    creating circular imports.
    
    Args:
        name: Server name
        module_path: Full module path (e.g., 'src.mcp.custom_server')
        class_name: Class name within the module
        requires_api_key: Whether the server requires an API key
    """
    if _registry is not None:
        factory = ServerFactory(module_path, class_name, requires_api_key)
        _registry.register_factory(name, factory)