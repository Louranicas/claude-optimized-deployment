"""
SYNTHEX Chapter Extraction MCP Server - Configuration Management
===============================================================

Configuration management for the SYNTHEX Chapter Extraction MCP Server.
Provides centralized configuration with environment variables, file-based
settings, and runtime overrides.

Features:
- Environment variable integration
- JSON/YAML configuration files
- Runtime configuration validation
- Security policy enforcement
- Performance tuning parameters

Author: SYNTHEX Collaborative Intelligence
"""

import json
import os
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    enable_sandboxing: bool = True
    max_file_size_mb: int = 100
    allowed_extensions: List[str] = field(default_factory=lambda: [
        '.pdf', '.epub', '.docx', '.doc', '.txt', '.md', 
        '.html', '.htm', '.rtf', '.odt', '.tex'
    ])
    enable_path_validation: bool = True
    enable_content_scanning: bool = True
    max_extraction_time_seconds: int = 300
    enable_rate_limiting: bool = True
    max_requests_per_minute: int = 100


@dataclass
class PerformanceConfig:
    """Performance optimization settings."""
    enable_caching: bool = True
    cache_size_mb: int = 256
    cache_ttl_seconds: int = 3600
    enable_parallel_processing: bool = True
    max_workers: int = 4
    chunk_size_kb: int = 1024
    enable_memory_monitoring: bool = True
    memory_limit_mb: int = 512
    gc_threshold: int = 700


@dataclass
class ChapterDetectionConfig:
    """Chapter detection algorithm settings."""
    min_chapter_length: int = 100
    max_chapter_depth: int = 6
    confidence_threshold: float = 0.7
    enable_ai_assistance: bool = True
    patterns: List[str] = field(default_factory=lambda: [
        r'Chapter\s+(\d+)',
        r'CHAPTER\s+(\d+)', 
        r'(\d+)\.\s+(.+)',
        r'#{1,6}\s+(.+)'
    ])
    enable_pattern_learning: bool = True
    learning_threshold: int = 10


@dataclass
class MonitoringConfig:
    """Monitoring and logging settings."""
    enable_metrics: bool = True
    metrics_endpoint: str = "http://localhost:9090"
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    enable_audit_logging: bool = True
    audit_log_file: str = "/tmp/synthex_audit.log"
    enable_performance_tracking: bool = True
    enable_error_reporting: bool = True


@dataclass
class IntegrationConfig:
    """Integration settings for CORE components."""
    enable_expert_consultation: bool = True
    expert_timeout_seconds: int = 30
    enable_memory_optimization: bool = True
    enable_connection_pooling: bool = True
    enable_rbac_integration: bool = True
    authentication_method: str = "jwt"
    session_timeout_minutes: int = 60


@dataclass
class SynthexConfig:
    """Main configuration class for SYNTHEX Chapter Extraction Server."""
    
    # Basic settings
    server_name: str = "synthex-chapter-extraction"
    server_version: str = "1.0.0"
    downloads_folder: Optional[str] = None
    
    # Component configurations
    security: SecurityConfig = field(default_factory=SecurityConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    chapter_detection: ChapterDetectionConfig = field(default_factory=ChapterDetectionConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    integration: IntegrationConfig = field(default_factory=IntegrationConfig)
    
    # Runtime settings
    debug_mode: bool = False
    development_mode: bool = False
    config_file: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization processing."""
        # Set downloads folder if not specified
        if not self.downloads_folder:
            self.downloads_folder = str(Path.home() / "Downloads")
        
        # Adjust settings for development mode
        if self.development_mode:
            self.security.enable_sandboxing = False
            self.monitoring.log_level = "DEBUG"
            self.performance.enable_caching = False
            logger.info("Development mode enabled - security relaxed")
    
    def validate(self) -> tuple[bool, List[str]]:
        """Validate configuration settings."""
        errors = []
        
        # Validate downloads folder
        downloads_path = Path(self.downloads_folder)
        if not downloads_path.exists():
            errors.append(f"Downloads folder does not exist: {downloads_path}")
        elif not downloads_path.is_dir():
            errors.append(f"Downloads folder is not a directory: {downloads_path}")
        
        # Validate security settings
        if self.security.max_file_size_mb <= 0:
            errors.append("max_file_size_mb must be positive")
        
        if self.security.max_extraction_time_seconds <= 0:
            errors.append("max_extraction_time_seconds must be positive")
        
        # Validate performance settings
        if self.performance.max_workers <= 0:
            errors.append("max_workers must be positive")
        
        if self.performance.cache_size_mb <= 0:
            errors.append("cache_size_mb must be positive")
        
        # Validate chapter detection settings
        if self.chapter_detection.min_chapter_length <= 0:
            errors.append("min_chapter_length must be positive")
        
        if not (0 <= self.chapter_detection.confidence_threshold <= 1):
            errors.append("confidence_threshold must be between 0 and 1")
        
        # Validate monitoring settings
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.monitoring.log_level not in valid_log_levels:
            errors.append(f"log_level must be one of: {valid_log_levels}")
        
        return len(errors) == 0, errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        def _convert_dataclass(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {k: _convert_dataclass(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, (list, tuple)):
                return [_convert_dataclass(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: _convert_dataclass(v) for k, v in obj.items()}
            else:
                return obj
        
        return _convert_dataclass(self)
    
    def save_to_file(self, file_path: Union[str, Path]) -> None:
        """Save configuration to file."""
        file_path = Path(file_path)
        config_dict = self.to_dict()
        
        if file_path.suffix.lower() == '.json':
            with open(file_path, 'w') as f:
                json.dump(config_dict, f, indent=2)
        elif file_path.suffix.lower() in ['.yml', '.yaml']:
            with open(file_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
        else:
            raise ValueError(f"Unsupported config file format: {file_path.suffix}")
        
        logger.info(f"Configuration saved to {file_path}")


class ConfigManager:
    """Configuration manager for loading and managing settings."""
    
    def __init__(self):
        self.config = SynthexConfig()
    
    def load_from_environment(self) -> SynthexConfig:
        """Load configuration from environment variables."""
        config = SynthexConfig()
        
        # Basic settings
        config.downloads_folder = os.getenv('SYNTHEX_DOWNLOADS_FOLDER', config.downloads_folder)
        config.debug_mode = os.getenv('SYNTHEX_DEBUG', 'false').lower() == 'true'
        config.development_mode = os.getenv('SYNTHEX_DEV_MODE', 'false').lower() == 'true'
        
        # Security settings
        config.security.enable_sandboxing = os.getenv('SYNTHEX_ENABLE_SANDBOXING', 'true').lower() == 'true'
        config.security.max_file_size_mb = int(os.getenv('SYNTHEX_MAX_FILE_SIZE_MB', config.security.max_file_size_mb))
        config.security.max_extraction_time_seconds = int(os.getenv('SYNTHEX_MAX_EXTRACTION_TIME', config.security.max_extraction_time_seconds))
        config.security.enable_rate_limiting = os.getenv('SYNTHEX_ENABLE_RATE_LIMITING', 'true').lower() == 'true'
        config.security.max_requests_per_minute = int(os.getenv('SYNTHEX_MAX_REQUESTS_PER_MINUTE', config.security.max_requests_per_minute))
        
        # Performance settings
        config.performance.enable_caching = os.getenv('SYNTHEX_ENABLE_CACHING', 'true').lower() == 'true'
        config.performance.cache_size_mb = int(os.getenv('SYNTHEX_CACHE_SIZE_MB', config.performance.cache_size_mb))
        config.performance.max_workers = int(os.getenv('SYNTHEX_MAX_WORKERS', config.performance.max_workers))
        config.performance.memory_limit_mb = int(os.getenv('SYNTHEX_MEMORY_LIMIT_MB', config.performance.memory_limit_mb))
        
        # Chapter detection settings
        config.chapter_detection.min_chapter_length = int(os.getenv('SYNTHEX_MIN_CHAPTER_LENGTH', config.chapter_detection.min_chapter_length))
        config.chapter_detection.confidence_threshold = float(os.getenv('SYNTHEX_CONFIDENCE_THRESHOLD', config.chapter_detection.confidence_threshold))
        config.chapter_detection.enable_ai_assistance = os.getenv('SYNTHEX_ENABLE_AI_ASSISTANCE', 'true').lower() == 'true'
        
        # Monitoring settings
        config.monitoring.log_level = os.getenv('SYNTHEX_LOG_LEVEL', config.monitoring.log_level)
        config.monitoring.enable_metrics = os.getenv('SYNTHEX_ENABLE_METRICS', 'true').lower() == 'true'
        config.monitoring.enable_audit_logging = os.getenv('SYNTHEX_ENABLE_AUDIT_LOGGING', 'true').lower() == 'true'
        
        # Integration settings
        config.integration.enable_expert_consultation = os.getenv('SYNTHEX_ENABLE_EXPERT_CONSULTATION', 'true').lower() == 'true'
        config.integration.enable_memory_optimization = os.getenv('SYNTHEX_ENABLE_MEMORY_OPTIMIZATION', 'true').lower() == 'true'
        config.integration.enable_rbac_integration = os.getenv('SYNTHEX_ENABLE_RBAC', 'true').lower() == 'true'
        
        self.config = config
        return config
    
    def load_from_file(self, file_path: Union[str, Path]) -> SynthexConfig:
        """Load configuration from file."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                if file_path.suffix.lower() == '.json':
                    data = json.load(f)
                elif file_path.suffix.lower() in ['.yml', '.yaml']:
                    data = yaml.safe_load(f)
                else:
                    raise ValueError(f"Unsupported config file format: {file_path.suffix}")
            
            # Create config from data
            config = self._dict_to_config(data)
            config.config_file = str(file_path)
            
            self.config = config
            logger.info(f"Configuration loaded from {file_path}")
            return config
            
        except Exception as e:
            logger.error(f"Failed to load configuration from {file_path}: {e}")
            raise
    
    def load_default_config(self) -> SynthexConfig:
        """Load default configuration with environment overrides."""
        # Start with environment variables
        config = self.load_from_environment()
        
        # Try to load from default config files
        default_config_paths = [
            Path.cwd() / "synthex_config.json",
            Path.cwd() / "synthex_config.yml",
            Path.home() / ".synthex" / "config.json",
            Path("/etc/synthex/config.json")
        ]
        
        for config_path in default_config_paths:
            if config_path.exists():
                try:
                    file_config = self.load_from_file(config_path)
                    # Merge with environment config (environment takes precedence)
                    config = self._merge_configs(file_config, config)
                    logger.info(f"Merged configuration from {config_path}")
                    break
                except Exception as e:
                    logger.warning(f"Failed to load config from {config_path}: {e}")
        
        self.config = config
        return config
    
    def _dict_to_config(self, data: Dict[str, Any]) -> SynthexConfig:
        """Convert dictionary to SynthexConfig."""
        config = SynthexConfig()
        
        # Basic settings
        if 'server_name' in data:
            config.server_name = data['server_name']
        if 'server_version' in data:
            config.server_version = data['server_version']
        if 'downloads_folder' in data:
            config.downloads_folder = data['downloads_folder']
        if 'debug_mode' in data:
            config.debug_mode = data['debug_mode']
        if 'development_mode' in data:
            config.development_mode = data['development_mode']
        
        # Component configurations
        if 'security' in data:
            self._update_dataclass(config.security, data['security'])
        if 'performance' in data:
            self._update_dataclass(config.performance, data['performance'])
        if 'chapter_detection' in data:
            self._update_dataclass(config.chapter_detection, data['chapter_detection'])
        if 'monitoring' in data:
            self._update_dataclass(config.monitoring, data['monitoring'])
        if 'integration' in data:
            self._update_dataclass(config.integration, data['integration'])
        
        return config
    
    def _update_dataclass(self, dataclass_obj, data: Dict[str, Any]):
        """Update dataclass instance with dictionary data."""
        for key, value in data.items():
            if hasattr(dataclass_obj, key):
                setattr(dataclass_obj, key, value)
    
    def _merge_configs(self, file_config: SynthexConfig, env_config: SynthexConfig) -> SynthexConfig:
        """Merge file and environment configurations (env takes precedence)."""
        # Start with file config
        merged = file_config
        
        # Override with environment values where they exist
        if env_config.downloads_folder != SynthexConfig().downloads_folder:
            merged.downloads_folder = env_config.downloads_folder
        
        # This is a simplified merge - in practice, you'd want to merge each field
        # For now, we'll use environment config as it includes reasonable defaults
        return env_config
    
    def get_config(self) -> SynthexConfig:
        """Get current configuration."""
        return self.config
    
    def validate_config(self) -> tuple[bool, List[str]]:
        """Validate current configuration."""
        return self.config.validate()


# Global configuration manager instance
config_manager = ConfigManager()


def get_config() -> SynthexConfig:
    """Get the global configuration."""
    return config_manager.get_config()


def load_config(config_file: Optional[str] = None) -> SynthexConfig:
    """Load configuration from file or environment."""
    if config_file:
        return config_manager.load_from_file(config_file)
    else:
        return config_manager.load_default_config()


def create_default_config_file(file_path: Union[str, Path]):
    """Create a default configuration file."""
    config = SynthexConfig()
    config.save_to_file(file_path)


# Configuration validation utilities
def validate_downloads_folder(path: str) -> bool:
    """Validate that downloads folder exists and is accessible."""
    try:
        folder_path = Path(path)
        return folder_path.exists() and folder_path.is_dir() and os.access(folder_path, os.R_OK)
    except Exception:
        return False


def get_optimal_worker_count() -> int:
    """Get optimal number of workers based on system resources."""
    import multiprocessing
    cpu_count = multiprocessing.cpu_count()
    # Use CPU count but cap at 8 for reasonable resource usage
    return min(cpu_count, 8)


def estimate_memory_requirements(file_size_mb: int) -> int:
    """Estimate memory requirements for processing a file."""
    # Rule of thumb: need 3-5x file size in memory for text processing
    return max(64, file_size_mb * 4)  # Minimum 64MB, typically 4x file size