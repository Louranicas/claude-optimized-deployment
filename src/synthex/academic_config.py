"""
SYNTHEX Academic Database Configuration
Extended configuration for academic search capabilities
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import os

from .config import SynthexConfig, ApiConfig


@dataclass
class AcademicApiConfig(ApiConfig):
    """Extended API configuration for academic databases"""
    
    # Academic-specific settings
    enable_citation_tracking: bool = True
    enable_cross_referencing: bool = True
    enable_metadata_enhancement: bool = True
    prefer_open_access: bool = True
    
    # Cache settings for academic content
    academic_cache_ttl_hours: int = 24
    citation_cache_ttl_hours: int = 168  # 1 week
    
    # Result quality settings
    min_relevance_score: float = 0.3
    max_results_per_database: int = 100
    enable_result_deduplication: bool = True


@dataclass
class ArXivConfig(AcademicApiConfig):
    """Configuration for arXiv preprint server"""
    base_url: str = "http://export.arxiv.org/api/query"
    request_delay_seconds: float = 1.0  # Be polite to arXiv
    max_results_per_request: int = 1000
    supported_categories: List[str] = field(default_factory=lambda: [
        "cs",  # Computer Science
        "math",  # Mathematics
        "physics",  # Physics
        "q-bio",  # Quantitative Biology
        "q-fin",  # Quantitative Finance
        "stat",  # Statistics
    ])


@dataclass
class CrossrefConfig(AcademicApiConfig):
    """Configuration for Crossref DOI database"""
    base_url: str = "https://api.crossref.org/works"
    enable_polite_pool: bool = True
    contact_email_key: str = "CROSSREF_CONTACT_EMAIL"
    max_results_per_request: int = 1000
    enable_full_text_links: bool = True
    enable_citation_data: bool = True


@dataclass
class SemanticScholarConfig(AcademicApiConfig):
    """Configuration for Semantic Scholar API"""
    base_url: str = "https://api.semanticscholar.org/graph/v1"
    api_key_name: str = "SEMANTIC_SCHOLAR_API_KEY"
    requests_per_second_authenticated: float = 1.0
    requests_per_second_unauthenticated: float = 0.1
    max_results_per_request: int = 100
    enable_exponential_backoff: bool = True
    base_backoff_delay: float = 1.0
    max_backoff_delay: float = 60.0
    
    # Semantic Scholar specific fields
    paper_fields: List[str] = field(default_factory=lambda: [
        "paperId", "title", "abstract", "authors", "year", "venue",
        "citationCount", "referenceCount", "influentialCitationCount",
        "isOpenAccess", "openAccessPdf", "fieldsOfStudy", "doi"
    ])


@dataclass
class PubMedConfig(AcademicApiConfig):
    """Configuration for PubMed/NCBI databases"""
    base_url: str = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils"
    api_key_name: str = "NCBI_API_KEY"
    requests_per_second: float = 3.0  # NCBI recommended rate
    max_results_per_request: int = 500
    enable_mesh_terms: bool = True
    enable_pmc_links: bool = True
    
    # NCBI databases to search
    databases: List[str] = field(default_factory=lambda: [
        "pubmed",  # PubMed citations
        "pmc",     # PMC full-text articles
    ])


@dataclass
class IEEEConfig(AcademicApiConfig):
    """Configuration for IEEE Xplore Digital Library"""
    base_url: str = "https://ieeexploreapi.ieee.org/api/v1/search/articles"
    api_key_name: str = "IEEE_API_KEY"
    max_results_per_request: int = 200  # IEEE limit
    max_query_words: int = 10  # IEEE limit
    
    # IEEE specific settings
    publication_types: List[str] = field(default_factory=lambda: [
        "Journals", "Conference Publications", "Standards"
    ])


@dataclass
class COREConfig(AcademicApiConfig):
    """Configuration for CORE (Open Access aggregator)"""
    base_url: str = "https://api.core.ac.uk/v3"
    api_key_name: str = "CORE_API_KEY"
    max_results_per_request: int = 100
    max_scroll_results: int = 50000  # CORE scroll limit
    
    # CORE specific settings
    enable_full_text: bool = True
    repository_filter: Optional[List[str]] = None


@dataclass
class OpenAlexConfig(AcademicApiConfig):
    """Configuration for OpenAlex scholarly database"""
    base_url: str = "https://api.openalex.org"
    contact_email_key: str = "OPENALEX_CONTACT_EMAIL"
    max_requests_per_day: int = 100000
    max_results_per_request: int = 200
    enable_polite_pool: bool = True
    
    # OpenAlex entity types to search
    entity_types: List[str] = field(default_factory=lambda: [
        "works", "authors", "venues", "institutions", "concepts"
    ])


@dataclass
class DataCiteConfig(AcademicApiConfig):
    """Configuration for DataCite metadata registry"""
    base_url: str = "https://api.datacite.org"
    max_results_per_request: int = 1000
    enable_dataset_metadata: bool = True
    
    # DataCite resource types
    resource_types: List[str] = field(default_factory=lambda: [
        "Dataset", "Software", "Text", "Collection"
    ])


@dataclass
class AcademicSearchConfig:
    """Main configuration for academic search capabilities"""
    
    # Enable/disable specific databases
    enable_arxiv: bool = True
    enable_crossref: bool = True
    enable_semantic_scholar: bool = True
    enable_pubmed: bool = True
    enable_ieee: bool = False  # Requires subscription
    enable_core: bool = True
    enable_openalex: bool = True
    enable_datacite: bool = True
    
    # Database configurations
    arxiv_config: ArXivConfig = field(default_factory=ArXivConfig)
    crossref_config: CrossrefConfig = field(default_factory=CrossrefConfig)
    semantic_scholar_config: SemanticScholarConfig = field(default_factory=SemanticScholarConfig)
    pubmed_config: PubMedConfig = field(default_factory=PubMedConfig)
    ieee_config: IEEEConfig = field(default_factory=IEEEConfig)
    core_config: COREConfig = field(default_factory=COREConfig)
    openalex_config: OpenAlexConfig = field(default_factory=OpenAlexConfig)
    datacite_config: DataCiteConfig = field(default_factory=DataCiteConfig)
    
    # Cross-database settings
    enable_result_fusion: bool = True
    fusion_weights: Dict[str, float] = field(default_factory=lambda: {
        "arxiv": 0.15,
        "crossref": 0.20,
        "semantic_scholar": 0.25,
        "pubmed": 0.20,
        "ieee": 0.10,
        "core": 0.05,
        "openalex": 0.03,
        "datacite": 0.02
    })
    
    # Deduplication settings
    deduplication_similarity_threshold: float = 0.85
    prefer_higher_citation_count: bool = True
    prefer_open_access: bool = True
    
    # Performance settings
    max_concurrent_database_queries: int = 8
    query_timeout_seconds: int = 30
    enable_progressive_results: bool = True
    
    @classmethod
    def from_env(cls) -> "AcademicSearchConfig":
        """Create configuration from environment variables"""
        config = cls()
        
        # Database enablement
        config.enable_arxiv = not os.getenv("SYNTHEX_DISABLE_ARXIV", "").lower() == "true"
        config.enable_crossref = not os.getenv("SYNTHEX_DISABLE_CROSSREF", "").lower() == "true"
        config.enable_semantic_scholar = not os.getenv("SYNTHEX_DISABLE_SEMANTIC_SCHOLAR", "").lower() == "true"
        config.enable_pubmed = not os.getenv("SYNTHEX_DISABLE_PUBMED", "").lower() == "true"
        config.enable_ieee = os.getenv("SYNTHEX_ENABLE_IEEE", "").lower() == "true"
        config.enable_core = not os.getenv("SYNTHEX_DISABLE_CORE", "").lower() == "true"
        config.enable_openalex = not os.getenv("SYNTHEX_DISABLE_OPENALEX", "").lower() == "true"
        config.enable_datacite = not os.getenv("SYNTHEX_DISABLE_DATACITE", "").lower() == "true"
        
        # Performance tuning
        if os.getenv("SYNTHEX_ACADEMIC_MAX_CONCURRENT"):
            config.max_concurrent_database_queries = int(os.getenv("SYNTHEX_ACADEMIC_MAX_CONCURRENT"))
        
        if os.getenv("SYNTHEX_ACADEMIC_TIMEOUT"):
            config.query_timeout_seconds = int(os.getenv("SYNTHEX_ACADEMIC_TIMEOUT"))
        
        # Result preferences
        if os.getenv("SYNTHEX_ACADEMIC_PREFER_OPEN_ACCESS"):
            config.prefer_open_access = os.getenv("SYNTHEX_ACADEMIC_PREFER_OPEN_ACCESS").lower() == "true"
        
        return config
    
    def get_enabled_databases(self) -> List[str]:
        """Get list of enabled database names"""
        enabled = []
        
        if self.enable_arxiv:
            enabled.append("arxiv")
        if self.enable_crossref:
            enabled.append("crossref")
        if self.enable_semantic_scholar:
            enabled.append("semantic_scholar")
        if self.enable_pubmed:
            enabled.append("pubmed")
        if self.enable_ieee:
            enabled.append("ieee")
        if self.enable_core:
            enabled.append("core")
        if self.enable_openalex:
            enabled.append("openalex")
        if self.enable_datacite:
            enabled.append("datacite")
        
        return enabled
    
    def validate(self) -> List[str]:
        """
        Validate academic search configuration
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check that at least one database is enabled
        if not any([
            self.enable_arxiv,
            self.enable_crossref, 
            self.enable_semantic_scholar,
            self.enable_pubmed,
            self.enable_ieee,
            self.enable_core,
            self.enable_openalex,
            self.enable_datacite
        ]):
            errors.append("At least one academic database must be enabled")
        
        # Validate fusion weights sum
        total_weight = sum(self.fusion_weights.values())
        if abs(total_weight - 1.0) > 0.01:
            errors.append(f"Fusion weights should sum to 1.0, got {total_weight}")
        
        # Validate performance settings
        if self.max_concurrent_database_queries < 1:
            errors.append("max_concurrent_database_queries must be at least 1")
        
        if self.query_timeout_seconds < 1:
            errors.append("query_timeout_seconds must be at least 1")
        
        if not 0.0 <= self.deduplication_similarity_threshold <= 1.0:
            errors.append("deduplication_similarity_threshold must be between 0.0 and 1.0")
        
        return errors


@dataclass
class ExtendedSynthexConfig(SynthexConfig):
    """Extended SYNTHEX configuration with academic search capabilities"""
    
    # Academic search configuration
    academic_search: AcademicSearchConfig = field(default_factory=AcademicSearchConfig)
    
    # Academic-specific performance settings
    enable_academic_search: bool = True
    academic_cache_size_mb: int = 1024  # 1GB for academic content
    academic_worker_threads: Optional[int] = None  # Auto-detect
    
    @classmethod
    def from_env(cls) -> "ExtendedSynthexConfig":
        """Create extended configuration from environment variables"""
        # Get base config
        base_config = SynthexConfig.from_env()
        
        # Create extended config
        config = cls(**base_config.__dict__)
        
        # Add academic configuration
        config.academic_search = AcademicSearchConfig.from_env()
        
        # Academic-specific environment variables
        if os.getenv("SYNTHEX_DISABLE_ACADEMIC_SEARCH"):
            config.enable_academic_search = False
        
        if os.getenv("SYNTHEX_ACADEMIC_CACHE_SIZE_MB"):
            config.academic_cache_size_mb = int(os.getenv("SYNTHEX_ACADEMIC_CACHE_SIZE_MB"))
        
        if os.getenv("SYNTHEX_ACADEMIC_WORKER_THREADS"):
            config.academic_worker_threads = int(os.getenv("SYNTHEX_ACADEMIC_WORKER_THREADS"))
        
        return config
    
    def validate(self) -> List[str]:
        """
        Validate extended configuration
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = super().validate()
        
        # Validate academic configuration
        if self.enable_academic_search:
            academic_errors = self.academic_search.validate()
            errors.extend([f"academic: {error}" for error in academic_errors])
        
        # Validate academic-specific settings
        if self.academic_cache_size_mb < 0:
            errors.append("academic_cache_size_mb cannot be negative")
        
        if self.academic_worker_threads is not None and self.academic_worker_threads < 1:
            errors.append("academic_worker_threads must be at least 1 if specified")
        
        return errors