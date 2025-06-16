"""
MCP Server Startup Optimization Module
Agent 7: Advanced startup optimization for MCP servers.

This module implements intelligent startup strategies to minimize initialization time
and resource usage while ensuring optimal server availability.
"""

import asyncio
import time
import logging
from typing import Dict, Any, List, Optional, Set, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
from enum import Enum
from contextlib import asynccontextmanager

from .servers import MCPServer, MCPServerRegistry
from .protocols import MCPServerInfo, MCPCapabilities
from ..core.circuit_breaker import CircuitBreakerConfig, get_circuit_breaker_manager

logger = logging.getLogger(__name__)


class StartupStrategy(Enum):
    """Server startup strategies."""
    EAGER = "eager"          # Initialize immediately
    LAZY = "lazy"            # Initialize on first use
    PARALLEL = "parallel"    # Initialize multiple servers in parallel
    STAGED = "staged"        # Initialize in priority-based stages
    ADAPTIVE = "adaptive"    # Adapt based on usage patterns


class ServerPriority(Enum):
    """Server priority levels for staged startup."""
    CRITICAL = 1     # Must be ready immediately
    HIGH = 2         # Should be ready quickly
    MEDIUM = 3       # Can wait for on-demand initialization
    LOW = 4          # Initialize only when needed


@dataclass
class StartupConfig:
    """Configuration for server startup optimization."""
    strategy: StartupStrategy = StartupStrategy.STAGED
    parallel_limit: int = 5
    startup_timeout: float = 30.0
    health_check_timeout: float = 10.0
    retry_attempts: int = 3
    retry_delay: float = 2.0
    warmup_enabled: bool = True
    preload_tools: bool = True
    connection_prewarming: bool = True
    dependency_resolution: bool = True


@dataclass
class ServerProfile:
    """Performance profile for a server."""
    name: str
    priority: ServerPriority = ServerPriority.MEDIUM
    avg_startup_time: float = 0.0
    startup_success_rate: float = 1.0
    dependencies: List[str] = field(default_factory=list)
    resource_requirements: Dict[str, Any] = field(default_factory=dict)
    usage_frequency: float = 0.0
    last_used: Optional[datetime] = None
    initialization_count: int = 0
    failure_count: int = 0
    
    def update_startup_time(self, duration: float):
        """Update average startup time."""
        if self.avg_startup_time == 0:
            self.avg_startup_time = duration
        else:
            # Exponential moving average
            self.avg_startup_time = (
                self.avg_startup_time * 0.8 + duration * 0.2
            )
    
    def record_usage(self):
        """Record server usage."""
        self.last_used = datetime.now()
        self.usage_frequency += 1


@dataclass
class StartupMetrics:
    """Metrics for startup optimization."""
    total_servers: int = 0
    initialized_servers: int = 0
    failed_servers: int = 0
    total_startup_time: float = 0.0
    parallel_efficiency: float = 0.0
    cache_hit_rate: float = 0.0
    dependency_resolution_time: float = 0.0
    resource_usage_peak: Dict[str, float] = field(default_factory=dict)
    
    def get_success_rate(self) -> float:
        """Calculate overall startup success rate."""
        if self.total_servers == 0:
            return 0.0
        return self.initialized_servers / self.total_servers


class MCPStartupOptimizer:
    """
    Optimizes MCP server startup performance.
    
    Features:
    - Multiple startup strategies (eager, lazy, parallel, staged, adaptive)
    - Dependency resolution and ordering
    - Resource-aware initialization
    - Performance profiling and adaptation
    - Health checking and retry logic
    - Connection prewarming
    """
    
    def __init__(self, config: Optional[StartupConfig] = None):
        self.config = config or StartupConfig()
        self.metrics = StartupMetrics()
        
        # Server management
        self._server_profiles: Dict[str, ServerProfile] = {}
        self._initialized_servers: Set[str] = set()
        self._failed_servers: Set[str] = set()
        self._pending_servers: Set[str] = set()
        
        # Initialization state
        self._initialization_lock = asyncio.Lock()
        self._server_locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._initialization_tasks: Dict[str, asyncio.Task] = {}
        
        # Performance tracking
        self._startup_history: deque = deque(maxlen=100)
        self._resource_monitor_task: Optional[asyncio.Task] = None
        self._is_monitoring = False
        
        # Dependency graph
        self._dependency_graph: Dict[str, Set[str]] = defaultdict(set)
        self._reverse_dependencies: Dict[str, Set[str]] = defaultdict(set)
        
        # Adaptive learning
        self._usage_patterns: Dict[str, List[datetime]] = defaultdict(list)
        self._adaptive_priorities: Dict[str, ServerPriority] = {}
    
    async def initialize(self):
        """Initialize the startup optimizer."""
        logger.info("Initializing MCP Startup Optimizer...")
        
        # Load server profiles and configure priorities
        await self._load_server_profiles()
        
        # Build dependency graph
        await self._build_dependency_graph()
        
        # Start resource monitoring
        self._is_monitoring = True
        self._resource_monitor_task = asyncio.create_task(self._monitor_resources())
        
        logger.info("MCP Startup Optimizer initialized")
    
    async def startup_servers(
        self,
        server_names: List[str],
        registry: MCPServerRegistry
    ) -> Dict[str, bool]:
        """
        Optimize server startup based on configured strategy.
        """
        logger.info(f"Starting {len(server_names)} servers with {self.config.strategy.value} strategy")
        
        start_time = time.time()
        self.metrics.total_servers = len(server_names)
        
        # Update server profiles
        for name in server_names:
            if name not in self._server_profiles:
                self._server_profiles[name] = ServerProfile(name=name)
        
        # Choose startup strategy
        if self.config.strategy == StartupStrategy.EAGER:
            results = await self._eager_startup(server_names, registry)
        elif self.config.strategy == StartupStrategy.LAZY:
            results = await self._lazy_startup(server_names, registry)
        elif self.config.strategy == StartupStrategy.PARALLEL:
            results = await self._parallel_startup(server_names, registry)
        elif self.config.strategy == StartupStrategy.STAGED:
            results = await self._staged_startup(server_names, registry)
        elif self.config.strategy == StartupStrategy.ADAPTIVE:
            results = await self._adaptive_startup(server_names, registry)
        else:
            # Default to staged startup
            results = await self._staged_startup(server_names, registry)
        
        # Update metrics
        total_time = time.time() - start_time
        self.metrics.total_startup_time = total_time
        self.metrics.initialized_servers = sum(1 for success in results.values() if success)
        self.metrics.failed_servers = sum(1 for success in results.values() if not success)
        
        # Record startup history
        self._startup_history.append({
            "timestamp": datetime.now(),
            "strategy": self.config.strategy.value,
            "total_time": total_time,
            "success_rate": self.metrics.get_success_rate(),
            "servers": len(server_names)
        })
        
        logger.info(
            f"Startup completed in {total_time:.2f}s. "
            f"Success rate: {self.metrics.get_success_rate():.2%}"
        )
        
        return results
    
    async def _eager_startup(
        self,
        server_names: List[str],
        registry: MCPServerRegistry
    ) -> Dict[str, bool]:
        """Initialize all servers immediately in sequence."""
        results = {}
        
        for server_name in server_names:
            try:
                success = await self._initialize_server(server_name, registry)
                results[server_name] = success
            except Exception as e:
                logger.error(f"Failed to initialize {server_name}: {e}")
                results[server_name] = False
        
        return results
    
    async def _lazy_startup(
        self,
        server_names: List[str],
        registry: MCPServerRegistry
    ) -> Dict[str, bool]:
        """Mark servers for lazy initialization."""
        results = {}
        
        for server_name in server_names:
            # Mark as pending for lazy initialization
            self._pending_servers.add(server_name)
            results[server_name] = True  # "Success" for lazy strategy
        
        logger.info(f"Marked {len(server_names)} servers for lazy initialization")
        return results
    
    async def _parallel_startup(
        self,
        server_names: List[str],
        registry: MCPServerRegistry
    ) -> Dict[str, bool]:
        """Initialize servers in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(self.config.parallel_limit)
        
        async def init_with_semaphore(name: str) -> Tuple[str, bool]:
            async with semaphore:
                try:
                    success = await self._initialize_server(name, registry)
                    return name, success
                except Exception as e:
                    logger.error(f"Failed to initialize {name}: {e}")
                    return name, False
        
        # Create tasks for all servers
        tasks = [init_with_semaphore(name) for name in server_names]
        
        # Execute in parallel
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert to dictionary
        results = {}
        for result in results_list:
            if isinstance(result, Exception):
                logger.error(f"Parallel initialization error: {result}")
            else:
                name, success = result
                results[name] = success
        
        return results
    
    async def _staged_startup(
        self,
        server_names: List[str],
        registry: MCPServerRegistry
    ) -> Dict[str, bool]:
        """Initialize servers in priority-based stages."""
        results = {}
        
        # Group servers by priority
        priority_groups = defaultdict(list)
        for name in server_names:
            profile = self._server_profiles[name]
            priority_groups[profile.priority].append(name)
        
        # Initialize in priority order
        for priority in [ServerPriority.CRITICAL, ServerPriority.HIGH, 
                        ServerPriority.MEDIUM, ServerPriority.LOW]:
            if priority not in priority_groups:
                continue
            
            servers_in_stage = priority_groups[priority]
            logger.info(f"Initializing {len(servers_in_stage)} {priority.name} priority servers")
            
            # Initialize stage in parallel
            stage_results = await self._parallel_startup(servers_in_stage, registry)
            results.update(stage_results)
            
            # Wait briefly between stages for critical/high priority servers
            if priority in [ServerPriority.CRITICAL, ServerPriority.HIGH]:
                await asyncio.sleep(0.5)
        
        return results
    
    async def _adaptive_startup(
        self,
        server_names: List[str],
        registry: MCPServerRegistry
    ) -> Dict[str, bool]:
        """Adapt startup strategy based on historical performance."""
        # Analyze historical usage patterns
        await self._analyze_usage_patterns()
        
        # Adjust priorities based on usage
        await self._adjust_adaptive_priorities(server_names)
        
        # Use staged startup with adapted priorities
        return await self._staged_startup(server_names, registry)
    
    async def _initialize_server(
        self,
        server_name: str,
        registry: MCPServerRegistry
    ) -> bool:
        """Initialize a single server with optimization."""
        async with self._server_locks[server_name]:
            if server_name in self._initialized_servers:
                return True  # Already initialized
            
            if server_name in self._failed_servers:
                return False  # Previously failed
            
            profile = self._server_profiles[server_name]
            start_time = time.time()
            
            try:
                # Check dependencies first
                if self.config.dependency_resolution:
                    await self._ensure_dependencies(server_name, registry)
                
                # Get server from registry
                server = registry.get(server_name)
                if server is None:
                    logger.error(f"Server {server_name} not found in registry")
                    return False
                
                # Initialize with retry logic
                success = await self._initialize_with_retry(server, profile)
                
                if success:
                    self._initialized_servers.add(server_name)
                    self._pending_servers.discard(server_name)
                    
                    # Post-initialization optimizations
                    await self._post_initialization_tasks(server_name, server)
                    
                    # Update profile
                    duration = time.time() - start_time
                    profile.update_startup_time(duration)
                    profile.initialization_count += 1
                    
                    logger.info(f"Successfully initialized {server_name} in {duration:.2f}s")
                else:
                    self._failed_servers.add(server_name)
                    profile.failure_count += 1
                
                return success
                
            except Exception as e:
                duration = time.time() - start_time
                self._failed_servers.add(server_name)
                profile.failure_count += 1
                
                logger.error(f"Failed to initialize {server_name} after {duration:.2f}s: {e}")
                return False
    
    async def _initialize_with_retry(
        self,
        server: MCPServer,
        profile: ServerProfile
    ) -> bool:
        """Initialize server with retry logic."""
        for attempt in range(self.config.retry_attempts):
            try:
                # Initialize server
                if hasattr(server, 'initialize'):
                    await asyncio.wait_for(
                        server.initialize(),
                        timeout=self.config.startup_timeout
                    )
                
                # Health check
                if await self._health_check(server):
                    return True
                
                logger.warning(f"Health check failed for {server.name}, attempt {attempt + 1}")
                
            except asyncio.TimeoutError:
                logger.warning(f"Timeout initializing {server.name}, attempt {attempt + 1}")
            except Exception as e:
                logger.warning(f"Error initializing {server.name}, attempt {attempt + 1}: {e}")
            
            # Wait before retry
            if attempt < self.config.retry_attempts - 1:
                await asyncio.sleep(self.config.retry_delay * (attempt + 1))
        
        return False
    
    async def _health_check(self, server: MCPServer) -> bool:
        """Perform health check on initialized server."""
        try:
            # Basic health check - try to get server info
            if hasattr(server, 'get_server_info'):
                await asyncio.wait_for(
                    server.get_server_info(),
                    timeout=self.config.health_check_timeout
                )
            
            # Try to get tools list
            if hasattr(server, 'get_tools'):
                tools = server.get_tools()
                if not tools:
                    logger.warning(f"Server {server.name} has no tools available")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Health check failed for {server.name}: {e}")
            return False
    
    async def _ensure_dependencies(
        self,
        server_name: str,
        registry: MCPServerRegistry
    ) -> bool:
        """Ensure server dependencies are initialized."""
        dependencies = self._dependency_graph.get(server_name, set())
        
        for dep_name in dependencies:
            if dep_name not in self._initialized_servers:
                logger.info(f"Initializing dependency {dep_name} for {server_name}")
                success = await self._initialize_server(dep_name, registry)
                if not success:
                    logger.error(f"Failed to initialize dependency {dep_name}")
                    return False
        
        return True
    
    async def _post_initialization_tasks(
        self,
        server_name: str,
        server: MCPServer
    ):
        """Perform post-initialization optimization tasks."""
        try:
            # Preload tools metadata if enabled
            if self.config.preload_tools:
                await self._preload_tools(server)
            
            # Prewarm connections if enabled
            if self.config.connection_prewarming:
                await self._prewarm_connections(server)
            
            # Setup circuit breaker
            await self._setup_circuit_breaker(server_name)
            
        except Exception as e:
            logger.warning(f"Post-initialization tasks failed for {server_name}: {e}")
    
    async def _preload_tools(self, server: MCPServer):
        """Preload tool metadata for faster access."""
        try:
            if hasattr(server, 'get_tools'):
                tools = server.get_tools()
                logger.debug(f"Preloaded {len(tools)} tools for {server.name}")
        except Exception as e:
            logger.warning(f"Failed to preload tools for {server.name}: {e}")
    
    async def _prewarm_connections(self, server: MCPServer):
        """Prewarm server connections."""
        try:
            # Implementation would depend on server type
            # For HTTP-based servers, could make a test request
            # For database servers, could establish initial connections
            pass
        except Exception as e:
            logger.warning(f"Connection prewarming failed for {server.name}: {e}")
    
    async def _setup_circuit_breaker(self, server_name: str):
        """Setup circuit breaker for server."""
        try:
            circuit_manager = get_circuit_breaker_manager()
            config = CircuitBreakerConfig(
                failure_threshold=5,
                timeout=60,
                name=f"server_{server_name}"
            )
            await circuit_manager.get_or_create(f"server_{server_name}", config)
        except Exception as e:
            logger.warning(f"Circuit breaker setup failed for {server_name}: {e}")
    
    async def lazy_initialize_server(
        self,
        server_name: str,
        registry: MCPServerRegistry
    ) -> bool:
        """Initialize server on-demand (lazy initialization)."""
        if server_name not in self._pending_servers:
            return server_name in self._initialized_servers
        
        logger.info(f"Lazy initializing server: {server_name}")
        
        # Record usage for adaptive learning
        profile = self._server_profiles.get(server_name)
        if profile:
            profile.record_usage()
        
        # Initialize
        success = await self._initialize_server(server_name, registry)
        
        if success:
            self._pending_servers.discard(server_name)
        
        return success
    
    async def _load_server_profiles(self):
        """Load and configure server profiles."""
        # Default server priorities based on common usage patterns
        default_priorities = {
            "brave": ServerPriority.HIGH,        # Web search is commonly used
            "docker": ServerPriority.HIGH,       # Container management is common
            "kubernetes": ServerPriority.MEDIUM, # K8s management
            "desktop-commander": ServerPriority.HIGH,  # System commands
            "security-scanner": ServerPriority.LOW,    # Heavy operations
            "prometheus-monitoring": ServerPriority.MEDIUM,  # Monitoring
            "slack-notifications": ServerPriority.LOW,      # Notifications
        }
        
        for server_name, priority in default_priorities.items():
            if server_name not in self._server_profiles:
                self._server_profiles[server_name] = ServerProfile(
                    name=server_name,
                    priority=priority
                )
    
    async def _build_dependency_graph(self):
        """Build server dependency graph."""
        # Example dependencies (would be configurable)
        dependencies = {
            "security-scanner": ["docker"],  # Security scanner might need Docker
            "prometheus-monitoring": ["kubernetes"],  # Prometheus might monitor K8s
        }
        
        for server, deps in dependencies.items():
            self._dependency_graph[server].update(deps)
            for dep in deps:
                self._reverse_dependencies[dep].add(server)
    
    async def _analyze_usage_patterns(self):
        """Analyze server usage patterns for adaptive optimization."""
        current_time = datetime.now()
        
        for server_name, profile in self._server_profiles.items():
            usage_times = self._usage_patterns.get(server_name, [])
            
            # Clean old usage data (keep last 7 days)
            cutoff = current_time - timedelta(days=7)
            recent_usage = [t for t in usage_times if t > cutoff]
            self._usage_patterns[server_name] = recent_usage
            
            # Calculate usage frequency
            if recent_usage:
                profile.usage_frequency = len(recent_usage) / 7.0  # Uses per day
    
    async def _adjust_adaptive_priorities(self, server_names: List[str]):
        """Adjust server priorities based on usage patterns."""
        for server_name in server_names:
            profile = self._server_profiles.get(server_name)
            if not profile:
                continue
            
            # Adjust priority based on usage frequency
            if profile.usage_frequency > 5:  # More than 5 uses per day
                self._adaptive_priorities[server_name] = ServerPriority.HIGH
            elif profile.usage_frequency > 1:  # More than 1 use per day
                self._adaptive_priorities[server_name] = ServerPriority.MEDIUM
            else:
                self._adaptive_priorities[server_name] = ServerPriority.LOW
            
            # Update profile priority
            profile.priority = self._adaptive_priorities.get(
                server_name, profile.priority
            )
    
    async def _monitor_resources(self):
        """Monitor resource usage during startup."""
        import psutil
        
        while self._is_monitoring:
            try:
                # Memory usage
                memory = psutil.virtual_memory()
                self.metrics.resource_usage_peak["memory_mb"] = max(
                    self.metrics.resource_usage_peak.get("memory_mb", 0),
                    memory.used / 1024 / 1024
                )
                
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=0.1)
                self.metrics.resource_usage_peak["cpu_percent"] = max(
                    self.metrics.resource_usage_peak.get("cpu_percent", 0),
                    cpu_percent
                )
                
                await asyncio.sleep(1)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
    
    def get_optimization_report(self) -> Dict[str, Any]:
        """Generate startup optimization report."""
        return {
            "strategy": self.config.strategy.value,
            "metrics": {
                "total_servers": self.metrics.total_servers,
                "initialized_servers": self.metrics.initialized_servers,
                "failed_servers": self.metrics.failed_servers,
                "success_rate": self.metrics.get_success_rate(),
                "total_startup_time": self.metrics.total_startup_time,
                "resource_usage_peak": self.metrics.resource_usage_peak
            },
            "server_profiles": {
                name: {
                    "priority": profile.priority.name,
                    "avg_startup_time": profile.avg_startup_time,
                    "success_rate": (
                        (profile.initialization_count - profile.failure_count) / 
                        max(profile.initialization_count, 1)
                    ),
                    "usage_frequency": profile.usage_frequency
                }
                for name, profile in self._server_profiles.items()
            },
            "startup_history": list(self._startup_history),
            "recommendations": self._generate_startup_recommendations()
        }
    
    def _generate_startup_recommendations(self) -> List[str]:
        """Generate startup optimization recommendations."""
        recommendations = []
        
        # Strategy recommendations
        if self.metrics.get_success_rate() < 0.9:
            recommendations.append(
                "Consider using staged startup strategy to improve reliability"
            )
        
        if self.metrics.total_startup_time > 30:
            recommendations.append(
                "High startup time detected. Consider lazy initialization for non-critical servers"
            )
        
        # Server-specific recommendations
        slow_servers = [
            name for name, profile in self._server_profiles.items()
            if profile.avg_startup_time > 10
        ]
        if slow_servers:
            recommendations.append(
                f"Slow startup servers detected: {', '.join(slow_servers)}. "
                "Consider optimization or lazy loading."
            )
        
        # Resource recommendations
        if self.metrics.resource_usage_peak.get("memory_mb", 0) > 1000:
            recommendations.append(
                "High memory usage during startup. Consider staggered initialization."
            )
        
        return recommendations
    
    async def shutdown(self):
        """Shutdown startup optimizer."""
        logger.info("Shutting down MCP Startup Optimizer...")
        
        self._is_monitoring = False
        
        if self._resource_monitor_task:
            self._resource_monitor_task.cancel()
            try:
                await self._resource_monitor_task
            except asyncio.CancelledError:
                pass
        
        # Cancel any pending initialization tasks
        for task in self._initialization_tasks.values():
            task.cancel()
        
        logger.info("MCP Startup Optimizer shutdown complete")


__all__ = [
    "StartupStrategy",
    "ServerPriority",
    "StartupConfig",
    "ServerProfile",
    "StartupMetrics",
    "MCPStartupOptimizer"
]