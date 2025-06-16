"""
SYNTHEX Configuration
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import os


@dataclass
class WebSearchConfig:
    """Configuration for web search agent"""
    # API keys should be retrieved from SecretManager, not stored here
    searxng_url: Optional[str] = None  # Base URL only, no secrets
    user_agent: str = "SYNTHEX/1.0 (AI Search Engine)"
    max_concurrent_requests: int = 100
    request_timeout_ms: int = 5000
    cache_size: int = 10000
    cache_ttl_ms: int = 3600000  # 1 hour


@dataclass
class DatabaseConfig:
    """Configuration for database search agent"""
    # Connection details should be retrieved from SecretManager
    max_connections: int = 50
    query_timeout_ms: int = 10000
    enable_query_cache: bool = True
    search_tables: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ApiConfig:
    """Configuration for API search agent"""
    max_concurrent_requests: int = 50
    request_timeout_ms: int = 10000
    retry_attempts: int = 3
    retry_delay_ms: int = 1000
    rate_limit_per_second: Optional[int] = 100


@dataclass
class FileSearchConfig:
    """Configuration for file search agent"""
    root_paths: List[str] = field(default_factory=lambda: ["."])
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "node_modules", ".git", "target", "dist", "__pycache__"
    ])
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    supported_extensions: List[str] = field(default_factory=lambda: [
        "txt", "md", "py", "rs", "js", "ts", "json", "yaml", "toml"
    ])


@dataclass
class KnowledgeBaseConfig:
    """Configuration for knowledge base agent"""
    index_path: str = "./knowledge_base_index"
    max_results: int = 100
    enable_fuzzy: bool = True
    fuzzy_distance: int = 2


@dataclass
class McpV2Config:
    """Configuration for MCP v2 protocol"""
    enable_compression: bool = True
    compression_threshold: int = 1024  # 1KB
    max_message_size: int = 10 * 1024 * 1024  # 10MB
    connection_timeout_ms: int = 5000
    enable_multiplexing: bool = True
    enable_encryption: bool = False


@dataclass
class SynthexConfig:
    """Main SYNTHEX configuration"""
    # Core settings
    max_parallel_searches: int = 10000
    connection_pool_size: int = 100
    cache_size_mb: int = 4096
    query_timeout_ms: int = 5000
    enable_query_optimization: bool = True
    
    # Agent settings
    enable_web_search: bool = True
    enable_database_search: bool = True
    enable_api_search: bool = True
    enable_file_search: bool = True
    enable_knowledge_base: bool = True
    
    # Agent configurations
    web_search_config: WebSearchConfig = field(default_factory=WebSearchConfig)
    database_config: DatabaseConfig = field(default_factory=DatabaseConfig)
    api_config: ApiConfig = field(default_factory=ApiConfig)
    file_search_config: FileSearchConfig = field(default_factory=FileSearchConfig)
    knowledge_base_config: KnowledgeBaseConfig = field(default_factory=KnowledgeBaseConfig)
    
    # MCP v2 protocol
    mcp_v2_config: McpV2Config = field(default_factory=McpV2Config)
    
    # Performance settings
    enable_work_stealing: bool = True
    worker_threads: Optional[int] = None  # None = auto-detect
    enable_zero_copy: bool = True
    enable_memory_mapping: bool = True
    
    # Monitoring
    enable_metrics: bool = True
    metrics_port: int = 9090
    enable_tracing: bool = True
    tracing_endpoint: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> "SynthexConfig":
        """Create configuration from environment variables"""
        config = cls()
        
        # Override with environment variables
        if os.getenv("SYNTHEX_MAX_PARALLEL_SEARCHES"):
            config.max_parallel_searches = int(os.getenv("SYNTHEX_MAX_PARALLEL_SEARCHES"))
        
        if os.getenv("SYNTHEX_CACHE_SIZE_MB"):
            config.cache_size_mb = int(os.getenv("SYNTHEX_CACHE_SIZE_MB"))
        
        if os.getenv("SYNTHEX_QUERY_TIMEOUT_MS"):
            config.query_timeout_ms = int(os.getenv("SYNTHEX_QUERY_TIMEOUT_MS"))
        
        # Agent enablement
        if os.getenv("SYNTHEX_DISABLE_WEB_SEARCH"):
            config.enable_web_search = False
        
        if os.getenv("SYNTHEX_DISABLE_DATABASE_SEARCH"):
            config.enable_database_search = False
        
        if os.getenv("SYNTHEX_DISABLE_API_SEARCH"):
            config.enable_api_search = False
        
        if os.getenv("SYNTHEX_DISABLE_FILE_SEARCH"):
            config.enable_file_search = False
        
        if os.getenv("SYNTHEX_DISABLE_KNOWLEDGE_BASE"):
            config.enable_knowledge_base = False
        
        return config
    
    def to_rust_config(self) -> Dict[str, Any]:
        """Convert to Rust configuration format"""
        return {
            "max_parallel_searches": self.max_parallel_searches,
            "connection_pool_size": self.connection_pool_size,
            "cache_size_mb": self.cache_size_mb,
            "query_timeout_ms": self.query_timeout_ms,
            "enable_query_optimization": self.enable_query_optimization,
            "mcp_v2_config": {
                "compression": self.mcp_v2_config.enable_compression,
                "max_message_size": self.mcp_v2_config.max_message_size,
                "connection_timeout_ms": self.mcp_v2_config.connection_timeout_ms,
                "enable_multiplexing": self.mcp_v2_config.enable_multiplexing,
            }
        }
    
    def validate(self) -> List[str]:
        """
        Validate configuration
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        if self.max_parallel_searches < 1:
            errors.append("max_parallel_searches must be at least 1")
        
        if self.cache_size_mb < 0:
            errors.append("cache_size_mb cannot be negative")
        
        if self.query_timeout_ms < 100:
            errors.append("query_timeout_ms must be at least 100ms")
        
        if self.enable_database_search and not self.database_config.connection_string:
            errors.append("database_config.connection_string required when database search is enabled")
        
        return errors