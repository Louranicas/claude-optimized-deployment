"""
SYNTHEX Academic Database Search Agents
Specialized agents for academic and research databases
"""

import asyncio
import json
import logging
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import quote_plus, urljoin
import hashlib
import time

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from .agents import SearchAgent
from .config import ApiConfig
from .secrets import get_secret_manager
from .security import sanitize_query

logger = logging.getLogger(__name__)


@dataclass
class Author:
    """Academic author information"""
    name: str
    affiliations: List[str] = field(default_factory=list)
    orcid: Optional[str] = None


@dataclass
class AcademicFilters:
    """Academic search filters"""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    subjects: List[str] = field(default_factory=list)
    publication_types: List[str] = field(default_factory=list)
    open_access_only: bool = False
    min_citations: Optional[int] = None


@dataclass
class AcademicResult:
    """Normalized academic search result"""
    
    # Primary identifiers
    doi: Optional[str] = None
    arxiv_id: Optional[str] = None
    pubmed_id: Optional[str] = None
    semantic_scholar_id: Optional[str] = None
    ieee_id: Optional[str] = None
    
    # Bibliographic data
    title: str = ""
    authors: List[Author] = field(default_factory=list)
    abstract: Optional[str] = None
    publication_date: Optional[datetime] = None
    venue: Optional[str] = None
    volume: Optional[str] = None
    issue: Optional[str] = None
    pages: Optional[str] = None
    
    # Citation data
    citation_count: int = 0
    reference_count: int = 0
    influential_citation_count: Optional[int] = None
    
    # Classifications
    subjects: List[str] = field(default_factory=list)
    mesh_terms: List[str] = field(default_factory=list)
    
    # Links and access
    pdf_url: Optional[str] = None
    html_url: Optional[str] = None
    open_access: bool = False
    license: Optional[str] = None
    
    # Metadata
    source: str = ""
    relevance_score: float = 0.0
    last_updated: Optional[datetime] = None
    
    def to_synthex_result(self) -> Dict[str, Any]:
        """Convert to SYNTHEX-compatible result format"""
        return {
            "title": self.title,
            "snippet": self.abstract or "",
            "url": self.html_url or self.pdf_url or "",
            "score": self.relevance_score,
            "source": f"academic_{self.source}",
            "metadata": {
                "doi": self.doi,
                "authors": [author.name for author in self.authors],
                "publication_date": self.publication_date.isoformat() if self.publication_date else None,
                "venue": self.venue,
                "citation_count": self.citation_count,
                "open_access": self.open_access,
                "subjects": self.subjects,
                "mesh_terms": self.mesh_terms,
            }
        }


class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, requests_per_second: float = 1.0):
        self.requests_per_second = requests_per_second
        self.last_request_time = 0.0
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire permission to make a request"""
        async with self.lock:
            now = time.time()
            time_since_last = now - self.last_request_time
            min_interval = 1.0 / self.requests_per_second
            
            if time_since_last < min_interval:
                await asyncio.sleep(min_interval - time_since_last)
            
            self.last_request_time = time.time()


class ExponentialBackoffLimiter:
    """Exponential backoff rate limiter"""
    
    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.failure_count = 0
        self.last_failure_time = 0.0
    
    async def on_failure(self):
        """Called when a request fails due to rate limiting"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        delay = min(self.base_delay * (2 ** self.failure_count), self.max_delay)
        logger.warning(f"Rate limited. Backing off for {delay:.2f} seconds")
        await asyncio.sleep(delay)
    
    def on_success(self):
        """Called when a request succeeds"""
        self.failure_count = 0


class AcademicSearchAgent(SearchAgent):
    """Base class for academic database search agents"""
    
    def __init__(self, config: ApiConfig):
        super().__init__()
        self.config = config
        self.session: Optional['aiohttp.ClientSession'] = None
        self._secret_manager = get_secret_manager()
        self.rate_limiter = RateLimiter(1.0)  # Default 1 RPS
        self._cache: Dict[str, List[AcademicResult]] = {}
        self._cache_ttl = timedelta(hours=1)
        self._cache_timestamps: Dict[str, datetime] = {}
        
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required for AcademicSearchAgent")
    
    async def _ensure_session(self):
        """Ensure aiohttp session is created"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(
                total=self.config.request_timeout_ms / 1000
            )
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=self._get_default_headers()
            )
    
    def _get_default_headers(self) -> Dict[str, str]:
        """Get default headers for requests"""
        return {
            "User-Agent": "SYNTHEX Academic Search/1.0 (Academic Research; Contact: research@synthex.ai)"
        }
    
    def _get_cache_key(self, query: str, filters: Optional[AcademicFilters] = None) -> str:
        """Generate cache key for query"""
        key_data = {
            "query": query,
            "filters": filters.__dict__ if filters else None
        }
        return hashlib.md5(json.dumps(key_data, sort_keys=True).encode()).hexdigest()
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached result is still valid"""
        if cache_key not in self._cache_timestamps:
            return False
        
        age = datetime.now() - self._cache_timestamps[cache_key]
        return age < self._cache_ttl
    
    async def search_academic(
        self,
        query: str,
        filters: Optional[AcademicFilters] = None,
        max_results: int = 100
    ) -> List[AcademicResult]:
        """Search academic database with specialized handling"""
        # Check cache first
        cache_key = self._get_cache_key(query, filters)
        if self._is_cache_valid(cache_key):
            logger.debug(f"Cache hit for academic query: {query[:50]}...")
            return self._cache[cache_key][:max_results]
        
        # Sanitize query
        sanitized_query = sanitize_query(query)
        
        # Execute search
        results = await self._search_implementation(sanitized_query, filters, max_results)
        
        # Cache results
        self._cache[cache_key] = results
        self._cache_timestamps[cache_key] = datetime.now()
        
        # Clean old cache entries
        self._clean_cache()
        
        return results[:max_results]
    
    def _clean_cache(self):
        """Clean expired cache entries"""
        now = datetime.now()
        expired_keys = [
            key for key, timestamp in self._cache_timestamps.items()
            if now - timestamp > self._cache_ttl
        ]
        
        for key in expired_keys:
            self._cache.pop(key, None)
            self._cache_timestamps.pop(key, None)
    
    @abstractmethod
    async def _search_implementation(
        self,
        query: str,
        filters: Optional[AcademicFilters],
        max_results: int
    ) -> List[AcademicResult]:
        """Implement specific search logic"""
        pass
    
    async def search(
        self,
        query: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Standard SYNTHEX search interface"""
        # Convert to academic format
        filters = self._convert_options_to_filters(options)
        max_results = options.get("max_results", 100)
        
        # Search
        academic_results = await self.search_academic(query, filters, max_results)
        
        # Convert to SYNTHEX format
        return [result.to_synthex_result() for result in academic_results]
    
    def _convert_options_to_filters(self, options: Dict[str, Any]) -> Optional[AcademicFilters]:
        """Convert SYNTHEX options to academic filters"""
        filters = AcademicFilters()
        
        # Extract date filters if present
        if "start_date" in options:
            filters.start_date = datetime.fromisoformat(options["start_date"])
        if "end_date" in options:
            filters.end_date = datetime.fromisoformat(options["end_date"])
        
        # Extract other filters
        filters.subjects = options.get("subjects", [])
        filters.open_access_only = options.get("open_access_only", False)
        filters.min_citations = options.get("min_citations")
        
        return filters


class ArXivAgent(AcademicSearchAgent):
    """arXiv preprint server search agent"""
    
    BASE_URL = "http://export.arxiv.org/api/query"
    
    def __init__(self, config: ApiConfig):
        super().__init__(config)
        self.rate_limiter = RateLimiter(0.5)  # Be polite to arXiv
    
    async def _search_implementation(
        self,
        query: str,
        filters: Optional[AcademicFilters],
        max_results: int
    ) -> List[AcademicResult]:
        """Search arXiv using their API"""
        await self._ensure_session()
        await self.rate_limiter.acquire()
        
        # Build query parameters
        params = {
            "search_query": self._build_arxiv_query(query, filters),
            "start": 0,
            "max_results": min(max_results, 1000),  # arXiv limit
            "sortBy": "relevance",
            "sortOrder": "descending"
        }
        
        try:
            async with self.session.get(self.BASE_URL, params=params) as response:
                if response.status != 200:
                    logger.error(f"arXiv API error: {response.status}")
                    return []
                
                xml_content = await response.text()
                return self._parse_arxiv_response(xml_content)
                
        except Exception as e:
            logger.error(f"arXiv search failed: {e}")
            return []
    
    def _build_arxiv_query(self, query: str, filters: Optional[AcademicFilters]) -> str:
        """Build arXiv-specific query string"""
        # arXiv supports field-specific searches
        arxiv_query = f"all:{query}"
        
        if filters:
            if filters.subjects:
                # Map to arXiv categories
                subject_queries = []
                for subject in filters.subjects:
                    subject_queries.append(f"cat:{subject}")
                if subject_queries:
                    arxiv_query += f" AND ({' OR '.join(subject_queries)})"
        
        return arxiv_query
    
    def _parse_arxiv_response(self, xml_content: str) -> List[AcademicResult]:
        """Parse arXiv XML response"""
        results = []
        
        try:
            root = ET.fromstring(xml_content)
            
            # Namespace mapping
            ns = {
                'atom': 'http://www.w3.org/2005/Atom',
                'arxiv': 'http://arxiv.org/schemas/atom'
            }
            
            for entry in root.findall('atom:entry', ns):
                result = AcademicResult()
                result.source = "arxiv"
                
                # Extract basic info
                title_elem = entry.find('atom:title', ns)
                if title_elem is not None:
                    result.title = title_elem.text.strip()
                
                summary_elem = entry.find('atom:summary', ns)
                if summary_elem is not None:
                    result.abstract = summary_elem.text.strip()
                
                # Extract arXiv ID
                id_elem = entry.find('atom:id', ns)
                if id_elem is not None:
                    arxiv_url = id_elem.text
                    result.arxiv_id = arxiv_url.split('/')[-1]
                    result.html_url = arxiv_url
                
                # Extract authors
                for author_elem in entry.findall('atom:author', ns):
                    name_elem = author_elem.find('atom:name', ns)
                    if name_elem is not None:
                        result.authors.append(Author(name=name_elem.text.strip()))
                
                # Extract publication date
                published_elem = entry.find('atom:published', ns)
                if published_elem is not None:
                    result.publication_date = datetime.fromisoformat(
                        published_elem.text.replace('Z', '+00:00')
                    )
                
                # Extract categories (subjects)
                for category_elem in entry.findall('arxiv:category', ns):
                    term = category_elem.get('term')
                    if term:
                        result.subjects.append(term)
                
                # Extract PDF link
                for link_elem in entry.findall('atom:link', ns):
                    if link_elem.get('type') == 'application/pdf':
                        result.pdf_url = link_elem.get('href')
                
                # arXiv is open access
                result.open_access = True
                result.relevance_score = 0.8  # Default relevance
                
                results.append(result)
                
        except ET.ParseError as e:
            logger.error(f"Failed to parse arXiv XML: {e}")
        
        return results
    
    async def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        await self._ensure_session()
        
        try:
            # Test with a simple query
            test_params = {
                "search_query": "test",
                "start": 0,
                "max_results": 1
            }
            
            async with self.session.get(self.BASE_URL, params=test_params) as response:
                healthy = response.status == 200
                latency_ms = int(response.headers.get("X-Response-Time", "0"))
        except Exception as e:
            logger.error(f"arXiv health check failed: {e}")
            healthy = False
            latency_ms = 0
        
        return {
            "healthy": healthy,
            "latency_ms": latency_ms,
            "cache_size": len(self._cache),
            "rate_limit": "0.5 RPS (polite usage)"
        }


class CrossrefAgent(AcademicSearchAgent):
    """Crossref DOI database search agent"""
    
    BASE_URL = "https://api.crossref.org/works"
    
    def __init__(self, config: ApiConfig):
        super().__init__(config)
        self.rate_limiter = None  # No explicit rate limit, but be polite
        self.contact_email = self._secret_manager.get_secret("CROSSREF_CONTACT_EMAIL")
    
    def _get_default_headers(self) -> Dict[str, str]:
        """Get default headers with contact info for polite pool"""
        headers = super()._get_default_headers()
        if self.contact_email:
            headers["User-Agent"] += f" (mailto:{self.contact_email})"
        return headers
    
    async def _search_implementation(
        self,
        query: str,
        filters: Optional[AcademicFilters],
        max_results: int
    ) -> List[AcademicResult]:
        """Search Crossref using their API"""
        await self._ensure_session()
        
        # Build query parameters
        params = {
            "query": query,
            "rows": min(max_results, 1000),  # Crossref max
            "sort": "relevance",
            "order": "desc"
        }
        
        # Add filters
        if filters:
            if filters.start_date:
                params["filter"] = f"from-pub-date:{filters.start_date.year}"
            if filters.end_date:
                existing_filter = params.get("filter", "")
                if existing_filter:
                    existing_filter += ","
                params["filter"] = existing_filter + f"until-pub-date:{filters.end_date.year}"
        
        try:
            async with self.session.get(self.BASE_URL, params=params) as response:
                if response.status != 200:
                    logger.error(f"Crossref API error: {response.status}")
                    return []
                
                data = await response.json()
                return self._parse_crossref_response(data)
                
        except Exception as e:
            logger.error(f"Crossref search failed: {e}")
            return []
    
    def _parse_crossref_response(self, data: Dict[str, Any]) -> List[AcademicResult]:
        """Parse Crossref JSON response"""
        results = []
        
        try:
            items = data.get("message", {}).get("items", [])
            
            for item in items:
                result = AcademicResult()
                result.source = "crossref"\n\n                # Extract DOI\n                result.doi = item.get("DOI")\n\n                # Extract title\n                titles = item.get("title", [])\n                if titles:\n                    result.title = titles[0]\n\n                # Extract authors\n                authors = item.get("author", [])\n                for author_data in authors:\n                    given = author_data.get("given", "")\n                    family = author_data.get("family", "")\n                    name = f"{given} {family}".strip()\n                    if name:\n                        result.authors.append(Author(name=name))\n\n                # Extract publication date\n                pub_date = item.get("published-print") or item.get("published-online")\n                if pub_date and "date-parts" in pub_date:\n                    date_parts = pub_date["date-parts"][0]\n                    if len(date_parts) >= 3:\n                        result.publication_date = datetime(\n                            date_parts[0], date_parts[1], date_parts[2]\n                        )\n                    elif len(date_parts) >= 1:\n                        result.publication_date = datetime(date_parts[0], 1, 1)\n\n                # Extract venue\n                container_title = item.get("container-title", [])\n                if container_title:\n                    result.venue = container_title[0]\n\n                # Extract citation count (if available)\n                result.citation_count = item.get("is-referenced-by-count", 0)\n\n                # Extract subjects\n                subjects = item.get("subject", [])\n                result.subjects = subjects\n\n                # Check open access\n                result.open_access = self._is_open_access(item)\n\n                # Build URL\n                if result.doi:\n                    result.html_url = f"https://doi.org/{result.doi}"\n\n                result.relevance_score = item.get("score", 0.8)\n\n                results.append(result)\n\n        except Exception as e:\n            logger.error(f"Failed to parse Crossref response: {e}")\n\n        return results\n\n    def _is_open_access(self, item: Dict[str, Any]) -> bool:\n        """Determine if article is open access"""\n        # Check license information\n        licenses = item.get("license", [])\n        if licenses:\n            return True\n\n        # Check URL for open access indicators\n        links = item.get("link", [])\n        for link in links:\n            if link.get("content-type") == "application/pdf":\n                return True\n\n        return False\n\n    async def get_status(self) -> Dict[str, Any]:\n        """Get agent status"""\n        await self._ensure_session()\n\n        try:\n            # Test with a simple query\n            test_params = {"query": "test", "rows": 1}\n\n            async with self.session.get(self.BASE_URL, params=test_params) as response:\n                healthy = response.status == 200\n                latency_ms = int(response.headers.get("X-Response-Time", "0"))\n        except Exception as e:\n            logger.error(f"Crossref health check failed: {e}")\n            healthy = False\n            latency_ms = 0\n\n        return {\n            "healthy": healthy,\n            "latency_ms": latency_ms,\n            "cache_size": len(self._cache),\n            "polite_pool": bool(self.contact_email),\n            "rate_limit": "Unlimited (polite pool)"\n        }\n\n\nclass SemanticScholarAgent(AcademicSearchAgent):\n    """Semantic Scholar search agent"""\n\n    BASE_URL = "https://api.semanticscholar.org/graph/v1"\n\n    def __init__(self, config: ApiConfig):\n        super().__init__(config)\n        self.api_key = self._secret_manager.get_secret("SEMANTIC_SCHOLAR_API_KEY")\n        self.rate_limiter = RateLimiter(1.0 if self.api_key else 0.1)  # 1 RPS with key\n        self.backoff_limiter = ExponentialBackoffLimiter()\n\n    def _get_default_headers(self) -> Dict[str, str]:\n        """Get default headers with API key if available"""\n        headers = super()._get_default_headers()\n        if self.api_key:\n            headers["x-api-key"] = self.api_key\n        return headers\n\n    async def _search_implementation(\n        self,\n        query: str,\n        filters: Optional[AcademicFilters],\n        max_results: int\n    ) -> List[AcademicResult]:\n        """Search Semantic Scholar using their API"""\n        await self._ensure_session()\n        await self.rate_limiter.acquire()\n\n        # Build search URL\n        search_url = f"{self.BASE_URL}/paper/search"\n\n        # Build query parameters\n        params = {\n            "query": query,\n            "limit": min(max_results, 100),  # S2 limit per request\n            "fields": "paperId,title,abstract,authors,year,venue,citationCount,referenceCount,influentialCitationCount,isOpenAccess,openAccessPdf,fieldsOfStudy"\n        }\n\n        # Add filters\n        if filters:\n            if filters.start_date:\n                params["year"] = f"{filters.start_date.year}-"\n            if filters.end_date:\n                year_filter = params.get("year", "")\n                params["year"] = f"{year_filter}{filters.end_date.year}"\n            if filters.open_access_only:\n                params["openAccessPdf"] = "true"\n\n        try:\n            async with self.session.get(search_url, params=params) as response:\n                if response.status == 429:  # Rate limited\n                    await self.backoff_limiter.on_failure()\n                    return []\n                elif response.status != 200:\n                    logger.error(f"Semantic Scholar API error: {response.status}")\n                    return []\n\n                self.backoff_limiter.on_success()\n                data = await response.json()\n                return self._parse_semantic_scholar_response(data)\n\n        except Exception as e:\n            logger.error(f"Semantic Scholar search failed: {e}")\n            return []\n\n    def _parse_semantic_scholar_response(self, data: Dict[str, Any]) -> List[AcademicResult]:\n        """Parse Semantic Scholar JSON response"""\n        results = []\n\n        try:\n            papers = data.get("data", [])\n\n            for paper in papers:\n                result = AcademicResult()\n                result.source = "semantic_scholar"\n\n                # Extract basic info\n                result.semantic_scholar_id = paper.get("paperId")\n                result.title = paper.get("title", "")\n                result.abstract = paper.get("abstract")\n\n                # Extract authors\n                authors = paper.get("authors", [])\n                for author_data in authors:\n                    name = author_data.get("name", "")\n                    if name:\n                        result.authors.append(Author(name=name))\n\n                # Extract publication year\n                year = paper.get("year")\n                if year:\n                    result.publication_date = datetime(year, 1, 1)\n\n                # Extract venue\n                result.venue = paper.get("venue")\n\n                # Extract citation metrics\n                result.citation_count = paper.get("citationCount", 0)\n                result.reference_count = paper.get("referenceCount", 0)\n                result.influential_citation_count = paper.get("influentialCitationCount", 0)\n\n                # Extract fields of study (subjects)\n                fields = paper.get("fieldsOfStudy", [])\n                result.subjects = fields if fields else []\n\n                # Extract open access info\n                result.open_access = paper.get("isOpenAccess", False)\n                open_access_pdf = paper.get("openAccessPdf")\n                if open_access_pdf:\n                    result.pdf_url = open_access_pdf.get("url")\n\n                # Build URL\n                if result.semantic_scholar_id:\n                    result.html_url = f"https://www.semanticscholar.org/paper/{result.semantic_scholar_id}"\n\n                # Calculate relevance score based on citations and recency\n                result.relevance_score = self._calculate_relevance_score(paper)\n\n                results.append(result)\n\n        except Exception as e:\n            logger.error(f"Failed to parse Semantic Scholar response: {e}")\n\n        return results\n\n    def _calculate_relevance_score(self, paper: Dict[str, Any]) -> float:\n        """Calculate relevance score based on citations and other factors"""\n        base_score = 0.5\n\n        # Citation boost\n        citations = paper.get("citationCount", 0)\n        if citations > 0:\n            base_score += min(0.3, citations / 1000)  # Max 0.3 boost\n\n        # Influential citation boost\n        influential = paper.get("influentialCitationCount", 0)\n        if influential > 0:\n            base_score += min(0.2, influential / 100)  # Max 0.2 boost\n\n        # Recency boost\n        year = paper.get("year")\n        if year:\n            current_year = datetime.now().year\n            years_old = current_year - year\n            if years_old < 5:\n                base_score += (5 - years_old) * 0.02  # Newer papers get slight boost\n\n        return min(1.0, base_score)\n\n    async def get_status(self) -> Dict[str, Any]:\n        """Get agent status"""\n        await self._ensure_session()\n\n        try:\n            # Test with a simple query\n            test_url = f"{self.BASE_URL}/paper/search"\n            test_params = {"query": "test", "limit": 1, "fields": "title"}\n\n            start_time = time.time()\n            async with self.session.get(test_url, params=test_params) as response:\n                latency_ms = int((time.time() - start_time) * 1000)\n                healthy = response.status == 200\n        except Exception as e:\n            logger.error(f"Semantic Scholar health check failed: {e}")\n            healthy = False\n            latency_ms = 0\n\n        return {\n            "healthy": healthy,\n            "latency_ms": latency_ms,\n            "cache_size": len(self._cache),\n            "api_key_configured": bool(self.api_key),\n            "rate_limit": "1 RPS (authenticated)" if self.api_key else "5K/5min (shared pool)"\n        }\n\n\n# Factory function for easy agent creation\ndef create_academic_agent(agent_type: str, config: ApiConfig) -> AcademicSearchAgent:\n    """Create an academic search agent of the specified type"""\n    agents = {\n        "arxiv": ArXivAgent,\n        "crossref": CrossrefAgent,\n        "semantic_scholar": SemanticScholarAgent,\n    }\n\n    if agent_type not in agents:\n        raise ValueError(f"Unknown academic agent type: {agent_type}")\n\n    return agents[agent_type](config)