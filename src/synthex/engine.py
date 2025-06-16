"""
SYNTHEX Engine - Python wrapper for Rust implementation
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
import uuid
from datetime import datetime, timedelta
import importlib
import sys
from enum import Enum

# TODO: Import Rust bindings when ready
# from claude_optimized_deployment_rust import synthex as rust_synthex

try:
    from ..core.logging_config import setup_logging
except ImportError:
    # Fallback to basic logging setup
    import logging as _logging
    def setup_logging(name: str):
        _logging.basicConfig(level=_logging.INFO)
from .config import SynthexConfig
from .agents import SearchAgent
from .security import sanitize_query, validate_options, SecurityError, hash_query
from .secrets import get_secret_manager

logger = logging.getLogger(__name__)


class AgentHealthStatus(Enum):
    """Health status of an agent"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    INITIALIZING = "initializing"


@dataclass
class AgentHealth:
    """Agent health information"""
    status: AgentHealthStatus
    last_check: datetime
    consecutive_failures: int = 0
    error_message: Optional[str] = None
    response_time_ms: Optional[int] = None


@dataclass
class SearchResult:
    """Search result from SYNTHEX"""
    query_id: str
    total_results: int
    execution_time_ms: int
    results: List[Dict[str, Any]]
    metadata: Dict[str, Any]


@dataclass
class QueryOptions:
    """Options for search queries"""
    max_results: int = 100
    timeout_ms: int = 5000
    enable_cache: bool = True
    sources: List[str] = field(default_factory=lambda: ["all"])
    filters: Dict[str, str] = field(default_factory=dict)


class SynthexEngine:
    """
    Main SYNTHEX search engine
    
    Provides high-speed parallel search capabilities optimized for AI agents
    """
    
    def __init__(self, config: Optional[SynthexConfig] = None):
        """
        Initialize SYNTHEX engine
        
        Args:
            config: Engine configuration
        """
        self.config = config or SynthexConfig()
        self._initialized = False
        self._agents: Dict[str, SearchAgent] = {}
        self._agent_health: Dict[str, AgentHealth] = {}
        self._rust_engine = None
        self._query_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._secret_manager = get_secret_manager()
        self._health_check_interval = 60  # seconds
        self._health_check_task: Optional[asyncio.Task] = None
        self._required_dependencies = {
            'aiohttp': False,
            'asyncpg': False,
            'cryptography': False
        }
        self._optional_dependencies = {
            'torch': False,
            'numpy': False,
            'pandas': False
        }
        
        # Setup logging with appropriate level
        setup_logging(log_level="INFO")
        
        # Check dependencies on init
        self._check_dependencies()
        
    def _check_dependencies(self) -> None:
        """Check and report on dependency availability"""
        # Check required dependencies
        for dep, _ in self._required_dependencies.items():
            try:
                importlib.import_module(dep)
                self._required_dependencies[dep] = True
            except ImportError:
                logger.warning(f"Required dependency '{dep}' not found")
        
        # Check optional dependencies
        for dep, _ in self._optional_dependencies.items():
            try:
                importlib.import_module(dep)
                self._optional_dependencies[dep] = True
            except ImportError:
                logger.debug(f"Optional dependency '{dep}' not found")
        
        # Log dependency status
        missing_required = [d for d, available in self._required_dependencies.items() if not available]
        if missing_required:
            logger.warning(f"Missing required dependencies: {', '.join(missing_required)}")
        
        available_optional = [d for d, available in self._optional_dependencies.items() if available]
        if available_optional:
            logger.info(f"Available optional dependencies: {', '.join(available_optional)}")
    
    async def initialize(self) -> None:
        """Initialize the engine and all components"""
        if self._initialized:
            return
            
        logger.info("Initializing SYNTHEX engine...")
        
        try:
            # TODO: Initialize Rust engine when bindings are ready
            # self._rust_engine = rust_synthex.SynthexEngine(self.config.to_rust_config())
            
            # Initialize default search agents with graceful degradation
            await self._initialize_default_agents()
            
            # Start health monitoring
            self._health_check_task = asyncio.create_task(self._health_monitor())
            
            self._initialized = True
            logger.info("SYNTHEX engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SYNTHEX: {e}")
            # Allow partial initialization for graceful degradation
            self._initialized = True  # Mark as initialized even if some agents failed
    
    async def _initialize_default_agents(self) -> None:
        """Initialize default search agents with graceful degradation"""
        # Import agents lazily to avoid circular imports
        agent_configs = []
        
        try:
            from .agents import (
                WebSearchAgent,
                DatabaseSearchAgent,
                ApiSearchAgent,
                FileSearchAgent,
                KnowledgeBaseAgent,
            )
            
            # Define agent configurations
            if self.config.enable_web_search and self._required_dependencies.get('aiohttp', False):
                agent_configs.append(("web", WebSearchAgent, self.config.web_search_config))
            
            if self.config.enable_database_search and self._required_dependencies.get('asyncpg', False):
                agent_configs.append(("database", DatabaseSearchAgent, self.config.database_config))
            
            if self.config.enable_api_search and self._required_dependencies.get('aiohttp', False):
                agent_configs.append(("api", ApiSearchAgent, self.config.api_config))
            
            if self.config.enable_file_search:
                agent_configs.append(("file", FileSearchAgent, self.config.file_search_config))
            
            if self.config.enable_knowledge_base:
                agent_configs.append(("knowledge_base", KnowledgeBaseAgent, self.config.knowledge_base_config))
                
        except ImportError as e:
            logger.error(f"Failed to import agent modules: {e}")
            return
        
        # Initialize each agent with error handling
        for agent_name, agent_class, agent_config in agent_configs:
            try:
                agent = agent_class(agent_config)
                await self.register_agent(agent_name, agent)
                logger.info(f"Successfully initialized {agent_name} agent")
            except Exception as e:
                logger.error(f"Failed to initialize {agent_name} agent: {e}")
                # Mark agent as failed
                self._agent_health[agent_name] = AgentHealth(
                    status=AgentHealthStatus.FAILED,
                    last_check=datetime.now(),
                    error_message=str(e)
                )
    
    async def register_agent(self, name: str, agent: SearchAgent) -> None:
        """
        Register a search agent
        
        Args:
            name: Agent name
            agent: Search agent instance
        """
        # Don't call initialize here to avoid recursion
            
        self._agents[name] = agent
        self._agent_health[name] = AgentHealth(
            status=AgentHealthStatus.INITIALIZING,
            last_check=datetime.now()
        )
        logger.info(f"Registered search agent: {name}")
        
        # TODO: Register with Rust engine
        # if self._rust_engine:
        #     await self._rust_engine.register_agent(name, agent.to_rust_agent())
    
    async def _health_monitor(self) -> None:
        """Monitor health of all registered agents"""
        while True:
            try:
                await asyncio.sleep(self._health_check_interval)
                
                for agent_name, agent in self._agents.items():
                    try:
                        start_time = datetime.now()
                        status = await agent.get_status()
                        response_time = int((datetime.now() - start_time).total_seconds() * 1000)
                        
                        # Update health status
                        if status.get("healthy", False):
                            self._agent_health[agent_name] = AgentHealth(
                                status=AgentHealthStatus.HEALTHY,
                                last_check=datetime.now(),
                                consecutive_failures=0,
                                response_time_ms=response_time
                            )
                        else:
                            current_health = self._agent_health.get(agent_name)
                            failures = current_health.consecutive_failures + 1 if current_health else 1
                            
                            self._agent_health[agent_name] = AgentHealth(
                                status=AgentHealthStatus.DEGRADED if failures < 3 else AgentHealthStatus.FAILED,
                                last_check=datetime.now(),
                                consecutive_failures=failures,
                                error_message="Agent reported unhealthy status",
                                response_time_ms=response_time
                            )
                            
                    except Exception as e:
                        logger.error(f"Health check failed for {agent_name}: {e}")
                        current_health = self._agent_health.get(agent_name)
                        failures = current_health.consecutive_failures + 1 if current_health else 1
                        
                        self._agent_health[agent_name] = AgentHealth(
                            status=AgentHealthStatus.DEGRADED if failures < 3 else AgentHealthStatus.FAILED,
                            last_check=datetime.now(),
                            consecutive_failures=failures,
                            error_message=str(e)
                        )
                
                # Log health summary
                healthy_agents = sum(1 for h in self._agent_health.values() if h.status == AgentHealthStatus.HEALTHY)
                total_agents = len(self._agent_health)
                logger.debug(f"Agent health: {healthy_agents}/{total_agents} healthy")
                
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
    
    async def _get_fallback_agent(self, preferred_agent: str) -> Optional[Tuple[str, SearchAgent]]:
        """Get a fallback agent when preferred agent is unhealthy"""
        # Define fallback order
        fallback_order = {
            "web": ["api", "knowledge_base", "file"],
            "database": ["knowledge_base", "file"],
            "api": ["web", "knowledge_base"],
            "file": ["knowledge_base", "database"],
            "knowledge_base": ["file", "database"]
        }
        
        # Try fallback agents in order
        for fallback_name in fallback_order.get(preferred_agent, []):
            if fallback_name in self._agents:
                health = self._agent_health.get(fallback_name)
                if health and health.status in [AgentHealthStatus.HEALTHY, AgentHealthStatus.DEGRADED]:
                    logger.info(f"Using fallback agent {fallback_name} instead of {preferred_agent}")
                    return fallback_name, self._agents[fallback_name]
        
        return None
    
    async def search(
        self,
        query: str,
        options: Optional[QueryOptions] = None
    ) -> SearchResult:
        """
        Execute a search query with security validation
        
        Args:
            query: Search query
            options: Query options
            
        Returns:
            SearchResult with aggregated results
            
        Raises:
            SecurityError: If query contains malicious content
        """
        if not self._initialized:
            await self.initialize()
        
        # Validate and sanitize query
        try:
            sanitized_query = sanitize_query(query)
        except SecurityError as e:
            logger.error(f"Query validation failed: {e}")
            raise
        
        options = options or QueryOptions()
        query_id = str(uuid.uuid4())
        
        logger.info(f"Executing search query: {query_id}")
        start_time = datetime.now()
        
        try:
            # TODO: Use Rust engine when available
            # if self._rust_engine:
            #     rust_result = await self._rust_engine.search(query, options.to_rust_options())
            #     return SearchResult.from_rust(rust_result)
            
            # Fallback to Python implementation with sanitized query
            results = await self._search_python(sanitized_query, options)
            
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return SearchResult(
                query_id=query_id,
                total_results=len(results),
                execution_time_ms=execution_time,
                results=results,
                metadata={
                    "sources_searched": list(self._agents.keys()),
                    "options": options.__dict__,
                    "timestamp": datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            logger.error(f"Search failed for query {query_id}: {e}")
            raise
    
    async def _search_python(
        self,
        query: str,
        options: QueryOptions
    ) -> List[Dict[str, Any]]:
        """
        Python fallback implementation of search
        
        Args:
            query: Sanitized search query
            options: Query options
            
        Returns:
            List of search results
        """
        # Generate cache key
        cache_key = hash_query(query, options.__dict__)
        
        # Check cache if enabled
        if options.enable_cache and cache_key in self._query_cache:
            logger.debug(f"Cache hit for query: {query[:50]}...")
            return self._query_cache[cache_key]
        # Determine which agents to use, filtering by health status
        available_agents = []
        for name, agent in self._agents.items():
            health = self._agent_health.get(name)
            if health and health.status in [AgentHealthStatus.HEALTHY, AgentHealthStatus.DEGRADED]:
                if "all" in options.sources or name in options.sources:
                    available_agents.append((name, agent))
            else:
                logger.debug(f"Skipping unhealthy agent: {name}")
        
        if not available_agents:
            logger.warning("No healthy agents available for search")
            return []
        
        agents_to_use = available_agents
        
        # Execute searches in parallel
        tasks = []
        for name, agent in agents_to_use:
            task = asyncio.create_task(
                self._search_with_agent(name, agent, query, options)
            )
            tasks.append(task)
        
        # Wait for all searches with timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=options.timeout_ms / 1000
            )
        except asyncio.TimeoutError:
            logger.warning(f"Search timeout after {options.timeout_ms}ms")
            results = []
        
        # Aggregate results
        all_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Agent search failed: {result}")
                continue
            if result:
                all_results.extend(result)
        
        # Sort by relevance score
        all_results.sort(key=lambda x: x.get("score", 0), reverse=True)
        
        # Limit results
        limited_results = all_results[:options.max_results]
        
        # Cache results if enabled
        if options.enable_cache:
            self._query_cache[cache_key] = limited_results
            # Implement simple LRU cache eviction
            if len(self._query_cache) > 1000:
                # Remove oldest entries
                keys_to_remove = list(self._query_cache.keys())[:100]
                for key in keys_to_remove:
                    del self._query_cache[key]
        
        return limited_results
    
    async def _search_with_agent(
        self,
        agent_name: str,
        agent: SearchAgent,
        query: str,
        options: QueryOptions
    ) -> List[Dict[str, Any]]:
        """
        Search using a specific agent
        
        Args:
            agent_name: Name of the agent
            agent: Search agent instance
            query: Search query
            options: Query options
            
        Returns:
            List of results from the agent
        """
        try:
            results = await agent.search(query, options)
            
            # Add agent name to results
            for result in results:
                result["_agent"] = agent_name
            
            return results
            
        except Exception as e:
            logger.error(f"Agent {agent_name} search failed: {e}")
            return []
    
    async def get_agent_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get status of all registered agents
        
        Returns:
            Dictionary of agent statuses
        """
        status = {}
        
        for name, agent in self._agents.items():
            health = self._agent_health.get(name)
            
            try:
                agent_status = await agent.get_status()
                status[name] = {
                    "healthy": agent_status.get("healthy", False),
                    "health_status": health.status.value if health else "unknown",
                    "consecutive_failures": health.consecutive_failures if health else 0,
                    "last_health_check": health.last_check.isoformat() if health else None,
                    "response_time_ms": health.response_time_ms if health else None,
                    "metrics": agent_status.get("metrics", {}),
                    "last_check": datetime.now().isoformat()
                }
            except Exception as e:
                status[name] = {
                    "healthy": False,
                    "health_status": health.status.value if health else "failed",
                    "consecutive_failures": health.consecutive_failures if health else 0,
                    "last_health_check": health.last_check.isoformat() if health else None,
                    "error": str(e),
                    "last_check": datetime.now().isoformat()
                }
        
        # Add dependency status
        status["_dependencies"] = {
            "required": self._required_dependencies,
            "optional": self._optional_dependencies
        }
        
        return status
    
    async def update_knowledge_graph(self, results: SearchResult) -> None:
        """
        Update the knowledge graph with search results
        
        Args:
            results: Search results to add to knowledge graph
        """
        # TODO: Implement when Rust bindings are ready
        logger.info(f"Updating knowledge graph with {results.total_results} results")
    
    async def shutdown(self) -> None:
        """Shutdown the engine and cleanup resources"""
        logger.info("Shutting down SYNTHEX engine...")
        
        # Cancel health monitoring task
        if self._health_check_task and not self._health_check_task.done():
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        # Shutdown all agents
        for name, agent in self._agents.items():
            try:
                await agent.shutdown()
            except Exception as e:
                logger.error(f"Failed to shutdown agent {name}: {e}")
        
        # Clear caches and state
        self._query_cache.clear()
        self._agents.clear()
        self._agent_health.clear()
        
        # TODO: Shutdown Rust engine
        # if self._rust_engine:
        #     await self._rust_engine.shutdown()
        
        self._initialized = False
        logger.info("SYNTHEX engine shutdown complete")