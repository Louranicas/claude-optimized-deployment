"""
Circuit breaker implementations for MCP server communications.

This module provides circuit breaker protection for MCP (Model Context Protocol) servers including:
- MCP client connection protection
- Tool invocation protection
- Resource access protection
- Server health monitoring
- Automatic failover between MCP servers
- Message-level circuit breakers
"""

import asyncio
import time
import logging
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, Set
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from enum import Enum
import json
from datetime import datetime

from src.core.circuit_breaker_standard import (
    StandardizedCircuitBreaker,
    StandardCircuitBreakerConfig,
    CircuitBreakerType,
    BulkheadConfig,
    HealthCheckConfig,
    CircuitOpenError
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


class MCPServerType(Enum):
    """Types of MCP servers."""
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    DESKTOP_COMMANDER = "desktop_commander"
    PROMETHEUS = "prometheus"
    SLACK = "slack"
    S3 = "s3"
    SECURITY_SCANNER = "security_scanner"
    CUSTOM = "custom"


@dataclass
class MCPServerConfig:
    """Configuration for MCP server."""
    name: str
    server_type: MCPServerType
    transport_uri: str
    command: Optional[List[str]] = None
    environment: Optional[Dict[str, str]] = None
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    health_check_interval: float = 60.0
    tools: Optional[Set[str]] = None
    resources: Optional[Set[str]] = None
    enabled: bool = True
    priority: int = 1  # 1=high, 2=medium, 3=low


@dataclass
class MCPCircuitBreakerConfig:
    """Configuration for MCP circuit breakers."""
    connection_timeout: float = 30.0
    tool_timeout: float = 60.0
    resource_timeout: float = 45.0
    message_timeout: float = 10.0
    max_concurrent_connections: int = 5
    max_concurrent_tools: int = 20
    max_concurrent_resources: int = 10
    enable_tool_level_breakers: bool = True
    enable_resource_level_breakers: bool = True
    enable_message_level_breakers: bool = True
    enable_server_failover: bool = True
    failover_threshold: float = 0.7  # Failover when failure rate exceeds this
    health_check_tools: Optional[List[str]] = None


class MCPMessageType(Enum):
    """Types of MCP messages."""
    INITIALIZE = "initialize"
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    PROMPTS_LIST = "prompts/list"
    PROMPTS_GET = "prompts/get"
    CUSTOM = "custom"


class MCPCircuitBreaker:
    """
    Circuit breaker specifically designed for MCP server communications.
    
    Features:
    - Connection-level protection
    - Tool-level protection
    - Resource-level protection
    - Message-level protection
    - Server health monitoring
    - Automatic failover
    """
    
    def __init__(
        self,
        server_config: MCPServerConfig,
        circuit_config: Optional[MCPCircuitBreakerConfig] = None
    ):
        """Initialize MCP circuit breaker."""
        self.server_config = server_config
        self.circuit_config = circuit_config or MCPCircuitBreakerConfig()
        self.name = f"mcp_{server_config.name}"
        
        # Create circuit breakers for different operations
        self._connection_breaker = self._create_connection_breaker()
        self._tool_breakers = self._create_tool_breakers()
        self._resource_breakers = self._create_resource_breakers()
        self._message_breakers = self._create_message_breakers()
        
        # MCP-specific metrics
        self._mcp_metrics = {
            'total_connections': 0,
            'active_connections': 0,
            'connection_failures': 0,
            'tool_invocations': 0,
            'successful_tools': 0,
            'failed_tools': 0,
            'resource_accesses': 0,
            'successful_resources': 0,
            'failed_resources': 0,
            'message_count': 0,
            'message_failures': 0,
            'average_response_time': 0.0,
            'server_restarts': 0
        }
        
        # Server health and status
        self._server_status = {
            'is_connected': False,
            'last_successful_call': None,
            'consecutive_failures': 0,
            'capabilities': {},
            'supported_tools': set(),
            'supported_resources': set()
        }
        
        # Failover management
        self._failover_servers = []
        self._current_server_index = 0
        
        logger.info(f"Initialized MCP circuit breaker for server '{server_config.name}'")
    
    def _create_connection_breaker(self) -> StandardizedCircuitBreaker:
        """Create circuit breaker for MCP server connections."""
        config = StandardCircuitBreakerConfig(
            name=f"{self.name}_connection",
            circuit_type=CircuitBreakerType.COUNT_BASED,
            failure_threshold=3,
            timeout=30.0,
            failure_rate_threshold=0.4,
            minimum_calls=3,
            service_category="mcp",
            priority=self.server_config.priority,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=self.circuit_config.max_concurrent_connections,
                isolation_pool_name=f"mcp_connection_{self.server_config.name}",
                queue_timeout=self.circuit_config.connection_timeout
            ),
            health_check_config=HealthCheckConfig(
                health_check_interval=self.server_config.health_check_interval,
                health_check_timeout=10.0,
                health_check_function=self._perform_health_check
            )
        )
        
        return StandardizedCircuitBreaker(config)
    
    def _create_tool_breakers(self) -> Dict[str, StandardizedCircuitBreaker]:
        """Create circuit breakers for MCP tools."""
        tool_breakers = {}
        
        # Global tool breaker
        global_config = StandardCircuitBreakerConfig(
            name=f"{self.name}_tools_global",
            circuit_type=CircuitBreakerType.ADAPTIVE,
            failure_threshold=5,
            timeout=60.0,
            failure_rate_threshold=0.5,
            minimum_calls=5,
            service_category="mcp",
            priority=self.server_config.priority,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=self.circuit_config.max_concurrent_tools,
                isolation_pool_name=f"mcp_tools_{self.server_config.name}",
                queue_timeout=self.circuit_config.tool_timeout
            )
        )
        tool_breakers['global'] = StandardizedCircuitBreaker(global_config)
        
        # Individual tool breakers if enabled
        if self.circuit_config.enable_tool_level_breakers and self.server_config.tools:
            for tool_name in self.server_config.tools:
                tool_config = StandardCircuitBreakerConfig(
                    name=f"{self.name}_tool_{tool_name}",
                    circuit_type=CircuitBreakerType.PERCENTAGE_BASED,
                    failure_threshold=3,
                    timeout=45.0,
                    failure_rate_threshold=0.6,
                    minimum_calls=3,
                    service_category="mcp",
                    priority=self.server_config.priority
                )
                tool_breakers[tool_name] = StandardizedCircuitBreaker(tool_config)
        
        return tool_breakers
    
    def _create_resource_breakers(self) -> Dict[str, StandardizedCircuitBreaker]:
        """Create circuit breakers for MCP resources."""
        resource_breakers = {}
        
        # Global resource breaker
        global_config = StandardCircuitBreakerConfig(
            name=f"{self.name}_resources_global",
            circuit_type=CircuitBreakerType.TIME_BASED,
            failure_threshold=5,
            timeout=45.0,
            failure_rate_threshold=0.5,
            minimum_calls=3,
            service_category="mcp",
            priority=self.server_config.priority,
            bulkhead_config=BulkheadConfig(
                max_concurrent_calls=self.circuit_config.max_concurrent_resources,
                isolation_pool_name=f"mcp_resources_{self.server_config.name}",
                queue_timeout=self.circuit_config.resource_timeout
            )
        )
        resource_breakers['global'] = StandardizedCircuitBreaker(global_config)
        
        # Individual resource breakers if enabled
        if self.circuit_config.enable_resource_level_breakers and self.server_config.resources:
            for resource_name in self.server_config.resources:
                resource_config = StandardCircuitBreakerConfig(
                    name=f"{self.name}_resource_{resource_name}",
                    circuit_type=CircuitBreakerType.COUNT_BASED,
                    failure_threshold=3,
                    timeout=30.0,
                    failure_rate_threshold=0.5,
                    minimum_calls=3,
                    service_category="mcp",
                    priority=self.server_config.priority
                )
                resource_breakers[resource_name] = StandardizedCircuitBreaker(resource_config)
        
        return resource_breakers
    
    def _create_message_breakers(self) -> Dict[str, StandardizedCircuitBreaker]:
        """Create circuit breakers for MCP message types."""
        message_breakers = {}
        
        if self.circuit_config.enable_message_level_breakers:
            for message_type in MCPMessageType:
                config = StandardCircuitBreakerConfig(
                    name=f"{self.name}_message_{message_type.value}",
                    circuit_type=CircuitBreakerType.COUNT_BASED,
                    failure_threshold=5,
                    timeout=20.0,
                    failure_rate_threshold=0.6,
                    minimum_calls=3,
                    service_category="mcp",
                    priority=self.server_config.priority
                )
                message_breakers[message_type.value] = StandardizedCircuitBreaker(config)
        
        return message_breakers
    
    async def _perform_health_check(self) -> bool:
        """Perform MCP server health check."""
        try:
            # Use configured health check tools or fallback to basic ping
            if self.circuit_config.health_check_tools:
                for tool_name in self.circuit_config.health_check_tools:
                    result = await self._call_tool_internal(tool_name, {})
                    if not result.get('success', False):
                        return False
            else:
                # Basic connection check
                result = await self._send_message_internal(MCPMessageType.TOOLS_LIST, {})
                if not result.get('success', False):
                    return False
            
            self._server_status['last_successful_call'] = datetime.now()
            self._server_status['consecutive_failures'] = 0
            return True
            
        except Exception as e:
            self._server_status['consecutive_failures'] += 1
            logger.error(f"MCP health check failed for server '{self.server_config.name}': {e}")
            return False
    
    async def connect(self) -> bool:
        """
        Connect to MCP server with circuit breaker protection.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            result = await self._connection_breaker.call(self._connect_internal)
            
            if result.get('success', False):
                self._server_status['is_connected'] = True
                self._server_status['capabilities'] = result.get('capabilities', {})
                self._mcp_metrics['total_connections'] += 1
                self._mcp_metrics['active_connections'] += 1
                
                logger.info(f"Connected to MCP server '{self.server_config.name}'")
                return True
            else:
                return False
                
        except CircuitOpenError:
            logger.error(f"Connection circuit breaker is open for MCP server '{self.server_config.name}'")
            return False
        except Exception as e:
            self._mcp_metrics['connection_failures'] += 1
            logger.error(f"Failed to connect to MCP server '{self.server_config.name}': {e}")
            return False
    
    async def _connect_internal(self) -> Dict[str, Any]:
        """Internal connection logic."""
        # Placeholder for actual MCP connection logic
        await asyncio.sleep(0.1)  # Simulate connection time
        
        return {
            'success': True,
            'capabilities': {
                'tools': list(self.server_config.tools or []),
                'resources': list(self.server_config.resources or [])
            }
        }
    
    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: Optional[float] = None
    ) -> Any:
        """
        Call MCP tool with circuit breaker protection.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            timeout: Optional timeout override
        
        Returns:
            Tool result
        """
        start_time = time.time()
        
        try:
            # Use tool-specific breaker if available, otherwise global
            tool_breaker = self._tool_breakers.get(tool_name, self._tool_breakers.get('global'))
            if not tool_breaker:
                raise ValueError(f"No circuit breaker configured for tool '{tool_name}'")
            
            result = await tool_breaker.call(
                self._call_tool_internal, tool_name, arguments, timeout
            )
            
            # Record metrics
            duration = time.time() - start_time
            self._mcp_metrics['tool_invocations'] += 1
            self._mcp_metrics['successful_tools'] += 1
            self._update_average_response_time(duration)
            
            logger.debug(f"Tool '{tool_name}' executed in {duration:.3f}s")
            return result
            
        except CircuitOpenError:
            self._mcp_metrics['tool_invocations'] += 1
            self._mcp_metrics['failed_tools'] += 1
            logger.error(f"Tool circuit breaker is open for '{tool_name}' on server '{self.server_config.name}'")
            
            # Try failover if enabled
            if self.circuit_config.enable_server_failover:
                return await self._try_failover_tool_call(tool_name, arguments, timeout)
            raise
            
        except Exception as e:
            duration = time.time() - start_time
            self._mcp_metrics['tool_invocations'] += 1
            self._mcp_metrics['failed_tools'] += 1
            logger.error(
                f"Tool '{tool_name}' failed on server '{self.server_config.name}' "
                f"(duration: {duration:.3f}s): {e}"
            )
            raise
    
    async def _call_tool_internal(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: Optional[float] = None
    ) -> Any:
        """Internal tool call logic."""
        # Placeholder for actual MCP tool call
        await asyncio.sleep(0.1)  # Simulate tool execution time
        
        return {
            'success': True,
            'result': f"Tool {tool_name} executed with args: {arguments}",
            'tool_name': tool_name,
            'server': self.server_config.name
        }
    
    async def read_resource(
        self,
        resource_uri: str,
        timeout: Optional[float] = None
    ) -> Any:
        """
        Read MCP resource with circuit breaker protection.
        
        Args:
            resource_uri: URI of the resource to read
            timeout: Optional timeout override
        
        Returns:
            Resource content
        """
        start_time = time.time()
        
        try:
            # Use resource-specific breaker if available, otherwise global
            resource_name = resource_uri.split('/')[-1]  # Extract resource name
            resource_breaker = self._resource_breakers.get(
                resource_name, self._resource_breakers.get('global')
            )
            if not resource_breaker:
                raise ValueError(f"No circuit breaker configured for resource '{resource_name}'")
            
            result = await resource_breaker.call(
                self._read_resource_internal, resource_uri, timeout
            )
            
            # Record metrics
            duration = time.time() - start_time
            self._mcp_metrics['resource_accesses'] += 1
            self._mcp_metrics['successful_resources'] += 1
            self._update_average_response_time(duration)
            
            logger.debug(f"Resource '{resource_uri}' read in {duration:.3f}s")
            return result
            
        except CircuitOpenError:
            self._mcp_metrics['resource_accesses'] += 1
            self._mcp_metrics['failed_resources'] += 1
            logger.error(f"Resource circuit breaker is open for '{resource_uri}' on server '{self.server_config.name}'")
            raise
            
        except Exception as e:
            duration = time.time() - start_time
            self._mcp_metrics['resource_accesses'] += 1
            self._mcp_metrics['failed_resources'] += 1
            logger.error(
                f"Resource '{resource_uri}' failed on server '{self.server_config.name}' "
                f"(duration: {duration:.3f}s): {e}"
            )
            raise
    
    async def _read_resource_internal(
        self,
        resource_uri: str,
        timeout: Optional[float] = None
    ) -> Any:
        """Internal resource read logic."""
        # Placeholder for actual MCP resource read
        await asyncio.sleep(0.05)  # Simulate resource read time
        
        return {
            'success': True,
            'content': f"Content of resource {resource_uri}",
            'uri': resource_uri,
            'server': self.server_config.name
        }
    
    async def send_message(
        self,
        message_type: MCPMessageType,
        payload: Dict[str, Any],
        timeout: Optional[float] = None
    ) -> Any:
        """
        Send MCP message with circuit breaker protection.
        
        Args:
            message_type: Type of MCP message
            payload: Message payload
            timeout: Optional timeout override
        
        Returns:
            Message response
        """
        start_time = time.time()
        
        try:
            # Use message-type-specific breaker if available
            message_breaker = self._message_breakers.get(message_type.value)
            if message_breaker:
                result = await message_breaker.call(
                    self._send_message_internal, message_type, payload, timeout
                )
            else:
                result = await self._send_message_internal(message_type, payload, timeout)
            
            # Record metrics
            duration = time.time() - start_time
            self._mcp_metrics['message_count'] += 1
            self._update_average_response_time(duration)
            
            return result
            
        except CircuitOpenError:
            self._mcp_metrics['message_count'] += 1
            self._mcp_metrics['message_failures'] += 1
            logger.error(f"Message circuit breaker is open for '{message_type.value}' on server '{self.server_config.name}'")
            raise
            
        except Exception as e:
            duration = time.time() - start_time
            self._mcp_metrics['message_count'] += 1
            self._mcp_metrics['message_failures'] += 1
            logger.error(
                f"Message '{message_type.value}' failed on server '{self.server_config.name}' "
                f"(duration: {duration:.3f}s): {e}"
            )
            raise
    
    async def _send_message_internal(
        self,
        message_type: MCPMessageType,
        payload: Dict[str, Any],
        timeout: Optional[float] = None
    ) -> Any:
        """Internal message send logic."""
        # Placeholder for actual MCP message sending
        await asyncio.sleep(0.02)  # Simulate message processing time
        
        return {
            'success': True,
            'response': f"Response to {message_type.value}",
            'message_type': message_type.value,
            'server': self.server_config.name
        }
    
    async def _try_failover_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: Optional[float] = None
    ) -> Any:
        """Try failover tool call on alternative servers."""
        for failover_server in self._failover_servers:
            try:
                logger.info(f"Attempting failover to server '{failover_server.server_config.name}' for tool '{tool_name}'")
                result = await failover_server.call_tool(tool_name, arguments, timeout)
                logger.info(f"Failover successful for tool '{tool_name}'")
                return result
            except Exception as e:
                logger.warning(f"Failover failed on server '{failover_server.server_config.name}': {e}")
                continue
        
        raise CircuitOpenError(f"All failover attempts exhausted for tool '{tool_name}'")
    
    def _update_average_response_time(self, duration: float):
        """Update average response time metric."""
        total_operations = (
            self._mcp_metrics['tool_invocations'] +
            self._mcp_metrics['resource_accesses'] +
            self._mcp_metrics['message_count']
        )
        
        if total_operations > 0:
            current_avg = self._mcp_metrics['average_response_time']
            self._mcp_metrics['average_response_time'] = (
                (current_avg * (total_operations - 1) + duration) / total_operations
            )
    
    def add_failover_server(self, server: 'MCPCircuitBreaker'):
        """Add a failover server."""
        if server not in self._failover_servers:
            self._failover_servers.append(server)
            logger.info(f"Added failover server '{server.server_config.name}' for '{self.server_config.name}'")
    
    def remove_failover_server(self, server: 'MCPCircuitBreaker'):
        """Remove a failover server."""
        if server in self._failover_servers:
            self._failover_servers.remove(server)
            logger.info(f"Removed failover server '{server.server_config.name}' from '{self.server_config.name}'")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive MCP circuit breaker metrics."""
        circuit_metrics = {
            'connection': self._connection_breaker.get_metrics(),
            'tools': {name: breaker.get_metrics() for name, breaker in self._tool_breakers.items()},
            'resources': {name: breaker.get_metrics() for name, breaker in self._resource_breakers.items()},
            'messages': {name: breaker.get_metrics() for name, breaker in self._message_breakers.items()}
        }
        
        return {
            'server_name': self.server_config.name,
            'server_type': self.server_config.server_type.value,
            'server_status': dict(self._server_status),
            'mcp_metrics': dict(self._mcp_metrics),
            'circuit_breakers': circuit_metrics,
            'failover_servers': [s.server_config.name for s in self._failover_servers]
        }
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status summary."""
        connection_healthy = self._connection_breaker.get_state().value == "closed"
        tools_healthy = all(
            breaker.get_state().value == "closed" 
            for breaker in self._tool_breakers.values()
        )
        resources_healthy = all(
            breaker.get_state().value == "closed" 
            for breaker in self._resource_breakers.values()
        )
        
        overall_healthy = (
            connection_healthy and tools_healthy and resources_healthy and
            self._server_status['is_connected'] and
            self._server_status['consecutive_failures'] < 3
        )
        
        return {
            'overall_healthy': overall_healthy,
            'is_connected': self._server_status['is_connected'],
            'consecutive_failures': self._server_status['consecutive_failures'],
            'circuit_states': {
                'connection': self._connection_breaker.get_state().value,
                'tools_healthy': tools_healthy,
                'resources_healthy': resources_healthy
            },
            'active_connections': self._mcp_metrics['active_connections'],
            'recent_failures': {
                'tools': self._mcp_metrics['failed_tools'],
                'resources': self._mcp_metrics['failed_resources'],
                'messages': self._mcp_metrics['message_failures']
            }
        }


class MCPCircuitBreakerManager:
    """Manager for multiple MCP server circuit breakers."""
    
    def __init__(self):
        self._mcp_breakers: Dict[str, MCPCircuitBreaker] = {}
        self._server_groups: Dict[str, List[MCPCircuitBreaker]] = {}
    
    def register_mcp_server(
        self,
        server_config: MCPServerConfig,
        circuit_config: Optional[MCPCircuitBreakerConfig] = None
    ) -> MCPCircuitBreaker:
        """Register an MCP server with circuit breaker protection."""
        breaker = MCPCircuitBreaker(server_config, circuit_config)
        self._mcp_breakers[server_config.name] = breaker
        
        # Add to server group
        server_type = server_config.server_type.value
        if server_type not in self._server_groups:
            self._server_groups[server_type] = []
        self._server_groups[server_type].append(breaker)
        
        logger.info(f"Registered MCP server circuit breaker for '{server_config.name}'")
        return breaker
    
    def get_mcp_breaker(self, server_name: str) -> Optional[MCPCircuitBreaker]:
        """Get circuit breaker for an MCP server."""
        return self._mcp_breakers.get(server_name)
    
    def setup_failover_groups(self):
        """Set up failover relationships between servers of the same type."""
        for server_type, servers in self._server_groups.items():
            if len(servers) > 1:
                # Set up circular failover within the group
                for i, server in enumerate(servers):
                    for j, failover_server in enumerate(servers):
                        if i != j:
                            server.add_failover_server(failover_server)
                
                logger.info(f"Set up failover group for {len(servers)} '{server_type}' servers")
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get metrics for all MCP circuit breakers."""
        return {
            server_name: breaker.get_metrics()
            for server_name, breaker in self._mcp_breakers.items()
        }
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get health summary for all MCP servers."""
        all_healthy = True
        server_health = {}
        group_health = {}
        
        for server_name, breaker in self._mcp_breakers.items():
            health_status = breaker.get_health_status()
            server_health[server_name] = health_status
            
            if not health_status["overall_healthy"]:
                all_healthy = False
        
        # Group health by server type
        for server_type, servers in self._server_groups.items():
            healthy_servers = sum(
                1 for server in servers 
                if server.get_health_status()["overall_healthy"]
            )
            group_health[server_type] = {
                'total_servers': len(servers),
                'healthy_servers': healthy_servers,
                'group_healthy': healthy_servers > 0
            }
        
        return {
            'all_servers_healthy': all_healthy,
            'total_servers': len(self._mcp_breakers),
            'servers': server_health,
            'groups': group_health
        }


# Global MCP circuit breaker manager
_mcp_manager = MCPCircuitBreakerManager()


def get_mcp_circuit_breaker_manager() -> MCPCircuitBreakerManager:
    """Get the global MCP circuit breaker manager."""
    return _mcp_manager


def get_mcp_circuit_breaker(
    server_name: str,
    server_config: Optional[MCPServerConfig] = None,
    circuit_config: Optional[MCPCircuitBreakerConfig] = None
) -> MCPCircuitBreaker:
    """
    Get or create an MCP circuit breaker.
    
    Args:
        server_name: Name of the MCP server
        server_config: MCP server configuration (required for new servers)
        circuit_config: Circuit breaker configuration
    
    Returns:
        MCP circuit breaker instance
    """
    manager = get_mcp_circuit_breaker_manager()
    breaker = manager.get_mcp_breaker(server_name)
    
    if breaker is None:
        if server_config is None:
            raise ValueError(f"Server config required for new MCP server '{server_name}'")
        breaker = manager.register_mcp_server(server_config, circuit_config)
    
    return breaker


# Convenience decorators for MCP operations
def mcp_tool_call(server_name: str):
    """
    Decorator for MCP tool calls with circuit breaker protection.
    
    Usage:
        @mcp_tool_call("docker_server")
        async def run_container(image: str, command: str):
            # Tool call logic here
            pass
    """
    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            breaker = get_mcp_circuit_breaker(server_name)
            return await breaker._tool_breakers['global'].call(func, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    return decorator


def mcp_resource_access(server_name: str):
    """
    Decorator for MCP resource access with circuit breaker protection.
    
    Usage:
        @mcp_resource_access("s3_server")
        async def read_file(file_path: str):
            # Resource access logic here
            pass
    """
    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            breaker = get_mcp_circuit_breaker(server_name)
            return await breaker._resource_breakers['global'].call(func, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    return decorator


# Export public API
__all__ = [
    'MCPCircuitBreaker',
    'MCPServerConfig',
    'MCPCircuitBreakerConfig',
    'MCPCircuitBreakerManager',
    'MCPServerType',
    'MCPMessageType',
    'get_mcp_circuit_breaker_manager',
    'get_mcp_circuit_breaker',
    'mcp_tool_call',
    'mcp_resource_access',
]