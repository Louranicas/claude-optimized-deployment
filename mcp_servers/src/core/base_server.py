"""
MCP Server Base Class - Python Implementation

Standard base class for all Python MCP servers providing consistent
architecture patterns, error handling, logging, and health monitoring.
"""

import asyncio
import logging
import time
import traceback
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import psutil
import signal

from mcp import Tool, Resource
from mcp.server import Server
from mcp.server.stdio import stdio_server


class HealthStatus(Enum):
    """Health status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class CheckStatus(Enum):
    """Health check status enumeration"""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


@dataclass
class ServerCapabilities:
    """Server capabilities configuration"""
    tools: bool = True
    resources: bool = True
    prompts: bool = False
    roots: bool = False
    sampling: bool = False


@dataclass
class ServerMetrics:
    """Server performance metrics"""
    uptime: int = 0
    request_count: int = 0
    error_count: int = 0
    tool_calls: int = 0
    resource_access: int = 0
    last_activity: datetime = field(default_factory=datetime.now)


@dataclass
class HealthCheck:
    """Individual health check result"""
    name: str
    status: CheckStatus
    message: Optional[str] = None
    duration: Optional[float] = None


@dataclass
class HealthReport:
    """Complete health status report"""
    status: HealthStatus
    timestamp: datetime
    checks: List[HealthCheck]
    metrics: ServerMetrics


@dataclass
class MCPServerOptions:
    """MCP Server configuration options"""
    name: str
    version: str
    description: str
    config: Optional[Dict[str, Any]] = None
    capabilities: Optional[ServerCapabilities] = None


class BaseMCPServer(ABC):
    """
    Base class for all MCP servers providing standardized:
    - Error handling and logging
    - Health monitoring and metrics
    - Request/response patterns
    - Graceful shutdown
    - Event emission
    """
    
    def __init__(self, options: MCPServerOptions):
        self.options = options
        self.logger = self._setup_logging()
        self.server = Server(options.name)
        
        # Initialize state
        self.tools: Dict[str, Tool] = {}
        self.resources: Dict[str, Resource] = {}
        self.metrics = ServerMetrics()
        self.health_checks: Dict[str, Callable[[], HealthCheck]] = {}
        self.is_started = False
        self.start_time = time.time()
        
        # Event callbacks
        self.event_callbacks: Dict[str, List[Callable]] = {}
        
        # Setup standard components
        self._setup_error_handling()
        self._setup_metrics()
        self._register_standard_health_checks()
        self._setup_signal_handlers()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger(self.options.name)
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _setup_error_handling(self) -> None:
        """Setup comprehensive error handling"""
        def handle_exception(exc_type, exc_value, exc_traceback):
            if issubclass(exc_type, KeyboardInterrupt):
                return
            
            self.metrics.error_count += 1
            self.logger.error(
                "Uncaught exception",
                exc_info=(exc_type, exc_value, exc_traceback)
            )
            self.emit('error', exc_value)
    
    def _setup_metrics(self) -> None:
        """Setup metrics collection"""
        async def update_metrics():
            while self.is_started:
                self.metrics.uptime = int(time.time() - self.start_time)
                await asyncio.sleep(1)
        
        # Start metrics update task when server starts
        self._metrics_task = None
    
    def _register_standard_health_checks(self) -> None:
        """Register standard health checks"""
        
        def memory_check() -> HealthCheck:
            """Check memory usage"""
            try:
                process = psutil.Process()
                memory_info = process.memory_info()
                memory_percent = process.memory_percent()
                
                status = CheckStatus.PASS
                if memory_percent > 90:
                    status = CheckStatus.FAIL
                elif memory_percent > 75:
                    status = CheckStatus.WARN
                
                return HealthCheck(
                    name="memory",
                    status=status,
                    message=f"Memory usage: {memory_info.rss / 1024 / 1024:.1f}MB ({memory_percent:.1f}%)"
                )
            except Exception as e:
                return HealthCheck(
                    name="memory",
                    status=CheckStatus.FAIL,
                    message=f"Memory check failed: {str(e)}"
                )
        
        def server_check() -> HealthCheck:
            """Check server status"""
            return HealthCheck(
                name="server",
                status=CheckStatus.PASS if self.is_started else CheckStatus.FAIL,
                message="Server is running" if self.is_started else "Server is not started"
            )
        
        self.health_checks["memory"] = memory_check
        self.health_checks["server"] = server_check
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating graceful shutdown")
            asyncio.create_task(self.graceful_shutdown())
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
    
    def register_tool(self, tool: Tool) -> None:
        """Register a tool with the server"""
        self.tools[tool.name] = tool
        self.logger.info(f"Tool registered: {tool.name}")
        self.emit('tool_registered', tool)
    
    def register_resource(self, resource: Resource) -> None:
        """Register a resource with the server"""
        self.resources[resource.uri] = resource
        self.logger.info(f"Resource registered: {resource.uri}")
        self.emit('resource_registered', resource)
    
    def add_health_check(self, name: str, check: Callable[[], HealthCheck]) -> None:
        """Add a custom health check"""
        self.health_checks[name] = check
        self.logger.info(f"Health check registered: {name}")
    
    def on(self, event: str, callback: Callable) -> None:
        """Register event callback"""
        if event not in self.event_callbacks:
            self.event_callbacks[event] = []
        self.event_callbacks[event].append(callback)
    
    def emit(self, event: str, *args, **kwargs) -> None:
        """Emit event to registered callbacks"""
        if event in self.event_callbacks:
            for callback in self.event_callbacks[event]:
                try:
                    callback(*args, **kwargs)
                except Exception as e:
                    self.logger.error(f"Error in event callback for {event}: {str(e)}")
    
    async def start(self) -> None:
        """Start the MCP server"""
        try:
            # Setup server-specific components
            await self.setup_tools()
            await self.setup_resources()
            
            self._setup_request_handlers()
            
            # Start metrics collection
            self._metrics_task = asyncio.create_task(self._update_metrics_loop())
            
            # Start the server
            async with stdio_server() as streams:
                await self.server.run(streams[0], streams[1])
            
            self.is_started = True
            self.emit('started')
            
            self.logger.info(
                f"MCP server started: {self.options.name} v{self.options.version} "
                f"(tools: {len(self.tools)}, resources: {len(self.resources)})"
            )
        
        except Exception as error:
            self.logger.error(f"Failed to start server: {str(error)}")
            self.emit('start_failed', error)
            raise
    
    def _setup_request_handlers(self) -> None:
        """Setup standard request handlers"""
        
        @self.server.list_tools()
        async def list_tools():
            """List available tools"""
            self.metrics.request_count += 1
            self.metrics.last_activity = datetime.now()
            return list(self.tools.values())
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Optional[Dict[str, Any]] = None):
            """Execute a tool"""
            self.metrics.request_count += 1
            self.metrics.tool_calls += 1
            self.metrics.last_activity = datetime.now()
            
            if name not in self.tools:
                self.metrics.error_count += 1
                raise ValueError(f"Tool {name} not found")
            
            self.logger.info(f"Tool called: {name}")
            
            try:
                result = await self.execute_tool(name, arguments or {})
                self.emit('tool_executed', name, arguments, result)
                return [{"type": "text", "text": json.dumps(result)}]
            except Exception as error:
                self.metrics.error_count += 1
                self.logger.error(f"Tool execution failed: {name} - {str(error)}")
                self.emit('tool_failed', name, arguments, error)
                raise
        
        @self.server.list_resources()
        async def list_resources():
            """List available resources"""
            self.metrics.request_count += 1
            self.metrics.last_activity = datetime.now()
            return list(self.resources.values())
        
        @self.server.read_resource()
        async def read_resource(uri: str):
            """Read a resource"""
            self.metrics.request_count += 1
            self.metrics.resource_access += 1
            self.metrics.last_activity = datetime.now()
            
            if uri not in self.resources:
                self.metrics.error_count += 1
                raise ValueError(f"Resource {uri} not found")
            
            try:
                content = await self.read_resource_content(uri)
                self.emit('resource_read', uri, content)
                return [content]
            except Exception as error:
                self.metrics.error_count += 1
                self.logger.error(f"Resource read failed: {uri} - {str(error)}")
                self.emit('resource_failed', uri, error)
                raise
    
    async def _update_metrics_loop(self) -> None:
        """Continuous metrics update loop"""
        while self.is_started:
            self.metrics.uptime = int(time.time() - self.start_time)
            await asyncio.sleep(1)
    
    async def get_health(self) -> HealthReport:
        """Get comprehensive health status"""
        checks = []
        
        for name, check_fn in self.health_checks.items():
            try:
                start_time = time.time()
                check = check_fn()
                check.duration = time.time() - start_time
                checks.append(check)
            except Exception as e:
                checks.append(HealthCheck(
                    name=name,
                    status=CheckStatus.FAIL,
                    message=f"Health check failed: {str(e)}"
                ))
        
        # Determine overall status
        has_failures = any(check.status == CheckStatus.FAIL for check in checks)
        has_warnings = any(check.status == CheckStatus.WARN for check in checks)
        
        if has_failures:
            status = HealthStatus.UNHEALTHY
        elif has_warnings:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY
        
        return HealthReport(
            status=status,
            timestamp=datetime.now(),
            checks=checks,
            metrics=self.metrics
        )
    
    async def graceful_shutdown(self) -> None:
        """Perform graceful shutdown"""
        self.logger.info("Starting graceful shutdown")
        self.emit('shutdown_started')
        
        try:
            # Stop metrics collection
            if self._metrics_task:
                self._metrics_task.cancel()
                try:
                    await self._metrics_task
                except asyncio.CancelledError:
                    pass
            
            # Perform cleanup
            await self.cleanup()
            
            self.is_started = False
            self.emit('shutdown_complete')
            self.logger.info("Graceful shutdown completed")
        
        except Exception as error:
            self.logger.error(f"Error during graceful shutdown: {str(error)}")
            self.emit('shutdown_error', error)
    
    # Abstract methods that must be implemented by concrete servers
    @abstractmethod
    async def setup_tools(self) -> None:
        """Setup server-specific tools"""
        pass
    
    @abstractmethod
    async def setup_resources(self) -> None:
        """Setup server-specific resources"""
        pass
    
    @abstractmethod
    async def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a tool with given arguments"""
        pass
    
    @abstractmethod
    async def read_resource_content(self, uri: str) -> Dict[str, Any]:
        """Read resource content"""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Perform cleanup operations before shutdown"""
        pass