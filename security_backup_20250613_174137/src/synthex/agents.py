"""
SYNTHEX Search Agents - Python wrappers for Rust implementations
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False

from .config import (
    WebSearchConfig,
    DatabaseConfig,
    ApiConfig,
    FileSearchConfig,
    KnowledgeBaseConfig
)
from .secrets import get_secret_manager

logger = logging.getLogger(__name__)


@dataclass
class AgentStatus:
    """Status of a search agent"""
    healthy: bool
    latency_ms: int
    error_rate: float
    last_check: str
    metrics: Dict[str, Any]


class SearchAgent(ABC):
    """Base class for all search agents"""
    
    @abstractmethod
    async def search(
        self,
        query: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Execute a search
        
        Args:
            query: Search query
            options: Search options
            
        Returns:
            List of search results
        """
        pass
    
    @abstractmethod
    async def get_status(self) -> Dict[str, Any]:
        """
        Get agent status
        
        Returns:
            Agent status information
        """
        pass
    
    @abstractmethod
    async def shutdown(self) -> None:
        """Shutdown the agent and cleanup resources"""
        pass


class WebSearchAgent(SearchAgent):
    """Web search agent using Brave API and SearXNG"""
    
    def __init__(self, config: WebSearchConfig):
        self.config = config
        self.session: Optional['aiohttp.ClientSession'] = None
        self._cache: Dict[str, Any] = {}
        self._secret_manager = get_secret_manager()
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for WebSearchAgent")
        
    async def _ensure_session(self):
        """Ensure aiohttp session is created"""
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=self.config.request_timeout_ms / 1000
                ),
                headers={"User-Agent": self.config.user_agent}
            )
    
    async def search(
        self,
        query: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute web search"""
        await self._ensure_session()
        
        # Check cache
        cache_key = f"{query}:{str(options)}"
        if cache_key in self._cache:
            logger.debug(f"Cache hit for query: {query}")
            return self._cache[cache_key]
        
        results = []
        
        # Try Brave Search API
        if self.config.brave_api_key:
            try:
                brave_results = await self._search_brave(query, options)
                results.extend(brave_results)
            except Exception as e:
                logger.error(f"Brave search failed: {e}")
        
        # Try SearXNG
        if self.config.searxng_url:
            try:
                searxng_results = await self._search_searxng(query, options)
                results.extend(searxng_results)
            except Exception as e:
                logger.error(f"SearXNG search failed: {e}")
        
        # Cache results
        self._cache[cache_key] = results
        
        # Limit cache size
        if len(self._cache) > self.config.cache_size:
            # Remove oldest entries
            keys_to_remove = list(self._cache.keys())[:100]
            for key in keys_to_remove:
                del self._cache[key]
        
        return results[:options.get("max_results", 100)]
    
    async def _search_brave(
        self,
        query: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Search using Brave API"""
        url = f"https://api.search.brave.com/res/v1/web/search"
        params = {
            "q": query,
            "count": min(options.get("max_results", 20), 20)
        }
        headers = {
            "X-Subscription-Token": self.config.brave_api_key
        }
        
        async with self.session.get(url, params=params, headers=headers) as response:
            data = await response.json()
            
            results = []
            for item in data.get("web", {}).get("results", []):
                results.append({
                    "title": item.get("title", ""),
                    "snippet": item.get("description", ""),
                    "url": item.get("url", ""),
                    "score": 0.9,
                    "source": "brave"
                })
            
            return results
    
    async def _search_searxng(
        self,
        query: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Search using SearXNG"""
        url = f"{self.config.searxng_url}/search"
        params = {
            "q": query,
            "format": "json",
            "limit": options.get("max_results", 20)
        }
        
        async with self.session.get(url, params=params) as response:
            data = await response.json()
            
            results = []
            for item in data.get("results", []):
                results.append({
                    "title": item.get("title", ""),
                    "snippet": item.get("content", ""),
                    "url": item.get("url", ""),
                    "score": item.get("score", 0.8),
                    "source": "searxng",
                    "engine": item.get("engine", "")
                })
            
            return results
    
    async def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        await self._ensure_session()
        
        # Test connectivity
        try:
            async with self.session.get("https://www.google.com/robots.txt") as response:
                latency_ms = int(response.headers.get("X-Response-Time", "0"))
                healthy = response.status == 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            healthy = False
            latency_ms = 0
        
        return {
            "healthy": healthy,
            "latency_ms": latency_ms,
            "cache_size": len(self._cache),
            "config": {
                "brave_enabled": bool(self._secret_manager.get_secret('BRAVE_API_KEY')),
                "searxng_enabled": bool(self._secret_manager.get_secret('SEARXNG_URL', self.config.searxng_url))
            }
        }
    
    async def shutdown(self) -> None:
        """Shutdown the agent"""
        if self.session:
            await self.session.close()
        self._cache.clear()


class DatabaseSearchAgent(SearchAgent):
    """Database search agent using PostgreSQL full-text search"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.pool: Optional['asyncpg.Pool'] = None
        if not ASYNCPG_AVAILABLE:
            raise ImportError("asyncpg is required for DatabaseSearchAgent")
        
    async def _ensure_pool(self):
        """Ensure database connection pool is created"""
        if not self.pool:
            self.pool = await asyncpg.create_pool(
                self.config.connection_string,
                max_size=self.config.max_connections,
                command_timeout=self.config.query_timeout_ms / 1000
            )
    
    async def search(
        self,
        query: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute database search"""
        await self._ensure_pool()
        
        results = []
        
        # Search each configured table
        for table_config in self.config.search_tables:
            try:
                table_results = await self._search_table(
                    query,
                    table_config,
                    options
                )
                results.extend(table_results)
            except Exception as e:
                logger.error(f"Table search failed for {table_config['name']}: {e}")
        
        # Sort by score
        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        
        return results[:options.get("max_results", 100)]
    
    async def _search_table(
        self,
        query: str,
        table_config: Dict[str, Any],
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Search a specific table"""
        search_columns = " || ' ' || ".join(table_config["search_columns"])
        
        sql = f"""
        WITH search_query AS (
            SELECT plainto_tsquery('english', $1) AS query
        )
        SELECT 
            {table_config['id_column']} as id,
            {search_columns} as content,
            ts_rank(to_tsvector('english', {search_columns}), query) as score
        FROM {table_config['name']}, search_query
        WHERE to_tsvector('english', {search_columns}) @@ query
        ORDER BY score DESC
        LIMIT $2
        """
        
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                sql,
                query,
                options.get("max_results", 100)
            )
            
            results = []
            for row in rows:
                results.append({
                    "id": str(row["id"]),
                    "content": row["content"],
                    "score": float(row["score"]),
                    "source": "database",
                    "table": table_config["name"]
                })
            
            return results
    
    async def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        await self._ensure_pool()
        
        try:
            async with self.pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
                healthy = True
                pool_size = self.pool.get_size()
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            healthy = False
            pool_size = 0
        
        return {
            "healthy": healthy,
            "pool_size": pool_size,
            "tables_configured": len(self.config.search_tables)
        }
    
    async def shutdown(self) -> None:
        """Shutdown the agent"""
        if self.pool:
            await self.pool.close()


class ApiSearchAgent(SearchAgent):
    """API search agent for external services"""
    
    def __init__(self, config: ApiConfig):
        self.config = config
        self.session: Optional['aiohttp.ClientSession'] = None
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for ApiSearchAgent")
        
    async def _ensure_session(self):
        """Ensure aiohttp session is created"""
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    total=self.config.request_timeout_ms / 1000
                )
            )
    
    def register_endpoint(
        self,
        name: str,
        base_url: str,
        search_path: str,
        **kwargs
    ):
        """Register an API endpoint"""
        self.endpoints[name] = {
            "base_url": base_url,
            "search_path": search_path,
            **kwargs
        }
    
    async def search(
        self,
        query: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute API search"""
        await self._ensure_session()
        
        results = []
        
        # Search all registered endpoints
        for name, endpoint in self.endpoints.items():
            try:
                endpoint_results = await self._search_endpoint(
                    query,
                    endpoint,
                    options
                )
                results.extend(endpoint_results)
            except Exception as e:
                logger.error(f"API search failed for {name}: {e}")
        
        return results[:options.get("max_results", 100)]
    
    async def _search_endpoint(
        self,
        query: str,
        endpoint: Dict[str, Any],
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Search a specific API endpoint"""
        url = f"{endpoint['base_url']}{endpoint['search_path']}"
        
        # Build request
        params = {
            endpoint.get("query_param", "q"): query,
            **endpoint.get("extra_params", {})
        }
        
        headers = endpoint.get("headers", {})
        
        # Add authentication
        if "api_key" in endpoint:
            headers[endpoint.get("api_key_header", "X-API-Key")] = endpoint["api_key"]
        
        async with self.session.get(url, params=params, headers=headers) as response:
            data = await response.json()
            
            # Extract results based on endpoint configuration
            results_path = endpoint.get("results_path", "results")
            items = data
            
            for part in results_path.split("."):
                items = items.get(part, [])
            
            results = []
            for item in items:
                results.append({
                    "title": item.get(endpoint.get("title_field", "title"), ""),
                    "content": item.get(endpoint.get("content_field", "content"), ""),
                    "score": item.get(endpoint.get("score_field", "score"), 0.8),
                    "source": "api",
                    "endpoint": endpoint["base_url"]
                })
            
            return results
    
    async def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "healthy": True,
            "endpoints_registered": len(self.endpoints),
            "endpoints": list(self.endpoints.keys())
        }
    
    async def shutdown(self) -> None:
        """Shutdown the agent"""
        if self.session:
            await self.session.close()


class FileSearchAgent(SearchAgent):
    """File search agent for local file system"""
    
    def __init__(self, config: FileSearchConfig):
        self.config = config
        
    async def search(
        self,
        query: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute file search"""
        # TODO: Implement file search
        # This would call into Rust implementation
        return []
    
    async def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "healthy": True,
            "root_paths": self.config.root_paths,
            "supported_extensions": self.config.supported_extensions
        }
    
    async def shutdown(self) -> None:
        """Shutdown the agent"""
        pass


class KnowledgeBaseAgent(SearchAgent):
    """Knowledge base search agent"""
    
    def __init__(self, config: KnowledgeBaseConfig):
        self.config = config
        
    async def search(
        self,
        query: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute knowledge base search"""
        # TODO: Implement knowledge base search
        # This would call into Rust implementation
        return []
    
    async def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "healthy": True,
            "index_path": self.config.index_path,
            "fuzzy_enabled": self.config.enable_fuzzy
        }
    
    async def shutdown(self) -> None:
        """Shutdown the agent"""
        pass