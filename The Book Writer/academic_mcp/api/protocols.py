"""
Academic MCP API Specification
RESTful and GraphQL interfaces for academic search
"""

from typing import Protocol, List, Dict, Optional, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod
import asyncio


class AcademicSearchProtocol(Protocol):
    """Protocol for academic search implementations"""
    
    async def search(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Search for academic papers"""
        ...
    
    async def get_paper(self, paper_id: str) -> Optional[Dict[str, Any]]:
        """Get paper by ID"""
        ...
    
    async def get_citations(self, paper_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get citations for a paper"""
        ...


class CitationManagerProtocol(Protocol):
    """Protocol for citation management"""
    
    async def format_citation(
        self,
        paper: Dict[str, Any],
        style: str,
        locale: str = "en-US"
    ) -> str:
        """Format citation in specified style"""
        ...
    
    async def parse_reference(self, reference_text: str) -> Optional[Dict[str, Any]]:
        """Parse reference string into structured data"""
        ...
    
    async def validate_doi(self, doi: str) -> bool:
        """Validate DOI"""
        ...


@dataclass
class SearchRequest:
    """Search request model"""
    query: str
    limit: int = 10
    offset: int = 0
    filters: Optional[Dict[str, Any]] = None
    sort_by: str = "relevance"
    include_abstracts: bool = True


@dataclass
class SearchResponse:
    """Search response model"""
    results: List[Dict[str, Any]]
    total_count: int
    offset: int
    has_more: bool
    search_time_ms: float


class MCPServerAdapter(ABC):
    """Abstract adapter for MCP servers"""
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to MCP server"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection"""
        pass
    
    @abstractmethod
    async def execute_request(self, method: str, params: Dict[str, Any]) -> Any:
        """Execute request on MCP server"""
        pass


class RateLimiter:
    """Rate limiting for API calls"""
    
    def __init__(self, max_requests: int, time_window: float):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self._lock = asyncio.Lock()
    
    async def check_limit(self) -> bool:
        """Check if request is within rate limit"""
        async with self._lock:
            now = asyncio.get_event_loop().time()
            
            # Remove old requests
            self.requests = [t for t in self.requests if now - t < self.time_window]
            
            # Check limit
            if len(self.requests) >= self.max_requests:
                return False
            
            # Add current request
            self.requests.append(now)
            return True
    
    async def wait_if_needed(self) -> None:
        """Wait if rate limit exceeded"""
        while not await self.check_limit():
            await asyncio.sleep(0.1)
