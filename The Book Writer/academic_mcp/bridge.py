"""
Python-Rust FFI Bridge for Academic MCP
Provides seamless integration between Python and Rust components
"""

import asyncio
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging

# Import Rust module (will be compiled separately)
try:
    import academic_mcp_rust as rust_mcp
except ImportError:
    rust_mcp = None
    logging.warning("Rust module not found, using Python fallback")

logger = logging.getLogger(__name__)


class CitationStyle(Enum):
    """Supported citation styles"""
    APA = "apa"
    MLA = "mla"
    CHICAGO = "chicago"
    IEEE = "ieee"
    HARVARD = "harvard"
    VANCOUVER = "vancouver"


@dataclass
class Paper:
    """Academic paper representation"""
    id: str
    title: str
    authors: List[str]
    year: Optional[int]
    doi: Optional[str]
    abstract: Optional[str]
    citations: Optional[int]
    
    @classmethod
    def from_rust(cls, rust_paper: Any) -> 'Paper':
        """Convert from Rust representation"""
        return cls(
            id=rust_paper.id,
            title=rust_paper.title,
            authors=rust_paper.authors,
            year=rust_paper.year,
            doi=rust_paper.doi,
            abstract=rust_paper.abstract_text,
            citations=rust_paper.citations
        )


class AcademicMCPBridge:
    """Bridge between Python and Rust MCP implementations"""
    
    def __init__(self, cache_size: int = 1000):
        self.cache_size = cache_size
        self._rust_client = None
        self._python_fallback = PythonMCPClient()
        self._initialize_rust_client()
        
    def _initialize_rust_client(self):
        """Initialize Rust client if available"""
        if rust_mcp:
            try:
                self._rust_client = rust_mcp.PyMCPClient(self.cache_size)
                logger.info("Rust MCP client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Rust client: {e}")
                self._rust_client = None
        
    async def search(self, query: str, limit: int = 10, filters: Optional[Dict] = None) -> List[Paper]:
        """
        Search for academic papers
        
        Args:
            query: Search query string
            limit: Maximum number of results
            filters: Optional filters (year, author, etc.)
            
        Returns:
            List of Paper objects
        """
        if self._rust_client:
            try:
                # Use high-performance Rust implementation
                rust_results = await self._rust_client.search(query, limit)
                return [Paper.from_rust(r) for r in rust_results]
            except Exception as e:
                logger.warning(f"Rust search failed, falling back to Python: {e}")
        
        # Fallback to Python implementation
        return await self._python_fallback.search(query, limit, filters)
    
    async def get_paper(self, paper_id: str) -> Optional[Paper]:
        """Get paper by ID"""
        if self._rust_client:
            try:
                rust_paper = await self._rust_client.get_paper(paper_id)
                return Paper.from_rust(rust_paper) if rust_paper else None
            except Exception as e:
                logger.warning(f"Rust get_paper failed: {e}")
        
        return await self._python_fallback.get_paper(paper_id)
    
    async def format_citation(self, paper: Paper, style: CitationStyle) -> str:
        """Format paper citation in specified style"""
        if self._rust_client:
            try:
                return await self._rust_client.format_citation(
                    paper.__dict__, style.value
                )
            except Exception as e:
                logger.warning(f"Rust citation formatting failed: {e}")
        
        return await self._python_fallback.format_citation(paper, style)


class PythonMCPClient:
    """Pure Python fallback implementation"""
    
    async def search(self, query: str, limit: int, filters: Optional[Dict]) -> List[Paper]:
        """Python implementation of search"""
        # Placeholder for actual implementation
        await asyncio.sleep(0.1)  # Simulate network delay
        return []
    
    async def get_paper(self, paper_id: str) -> Optional[Paper]:
        """Python implementation of get_paper"""
        await asyncio.sleep(0.1)
        return None
    
    async def format_citation(self, paper: Paper, style: CitationStyle) -> str:
        """Python implementation of citation formatting"""
        if style == CitationStyle.APA:
            return f"{', '.join(paper.authors)} ({paper.year}). {paper.title}."
        elif style == CitationStyle.MLA:
            return f"{paper.authors[0]}. \"{paper.title}.\" {paper.year}."
        else:
            return f"{paper.title} by {', '.join(paper.authors)}"
