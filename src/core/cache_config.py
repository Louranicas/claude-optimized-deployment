"""
Configuration management for all cache sizes and TTL settings.

This module provides centralized configuration for all unbounded data structure fixes.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import os
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class CacheConfiguration:
    """Central configuration for all cache sizes and TTL settings."""
    
    # Circle of Experts caches
    expert_queries_max_size: int = 1000
    expert_queries_ttl: float = 7200.0  # 2 hours
    expert_responses_max_size: int = 500
    expert_responses_ttl: float = 14400.0  # 4 hours
    response_files_max_size: int = 2000
    response_files_ttl: float = 14400.0  # 4 hours
    
    # MCP caches
    mcp_contexts_max_size: int = 200
    mcp_contexts_ttl: float = 3600.0  # 1 hour
    mcp_tool_calls_max_per_context: int = 100
    
    # Connection pool caches
    http_sessions_max_size: int = 50
    http_sessions_ttl: float = 1800.0  # 30 minutes
    http_metrics_max_size: int = 100
    http_metrics_ttl: float = 3600.0  # 1 hour
    
    # Database connection caches
    db_pool_metrics_max_size: int = 50
    db_pool_metrics_ttl: float = 3600.0  # 1 hour
    
    # Audit system caches
    audit_stats_max_size: int = 1000
    audit_stats_ttl: float = 3600.0  # 1 hour
    audit_buffer_max_size: int = 500
    audit_high_freq_buffer_max_size: int = 500
    
    # Generic LRU cache defaults
    default_lru_max_size: int = 1000
    default_ttl: float = 3600.0  # 1 hour
    default_cleanup_interval: float = 300.0  # 5 minutes
    
    # Memory limits
    memory_threshold_mb: float = 100.0
    enable_memory_monitoring: bool = True
    
    # Cleanup scheduler settings
    cleanup_check_interval: float = 10.0
    cleanup_auto_start: bool = True
    
    # Environment overrides
    enable_env_overrides: bool = True
    config_prefix: str = "CACHE_"
    
    def __post_init__(self):
        """Apply environment variable overrides if enabled."""
        if self.enable_env_overrides:
            self._apply_env_overrides()
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides to configuration."""
        for field_name in self.__dataclass_fields__:
            env_name = f"{self.config_prefix}{field_name.upper()}"
            env_value = os.getenv(env_name)
            
            if env_value is not None:
                try:
                    # Get the field type and convert accordingly
                    field_type = self.__dataclass_fields__[field_name].type
                    
                    if field_type == int:
                        setattr(self, field_name, int(env_value))
                    elif field_type == float:
                        setattr(self, field_name, float(env_value))
                    elif field_type == bool:
                        setattr(self, field_name, env_value.lower() in ('true', '1', 'yes', 'on'))
                    elif field_type == str:
                        setattr(self, field_name, env_value)
                    
                    logger.info(f"Applied environment override: {env_name}={env_value}")
                    
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid environment value for {env_name}: {env_value}, error: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            field.name: getattr(self, field.name)
            for field in self.__dataclass_fields__.values()
        }
    
    def save_to_file(self, file_path: str) -> None:
        """Save configuration to JSON file."""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)
            logger.info(f"Saved cache configuration to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration to {file_path}: {e}")
    
    @classmethod
    def load_from_file(cls, file_path: str) -> 'CacheConfiguration':
        """Load configuration from JSON file."""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Filter out unknown fields
            valid_fields = set(cls.__dataclass_fields__.keys())
            filtered_data = {k: v for k, v in data.items() if k in valid_fields}
            
            logger.info(f"Loaded cache configuration from {file_path}")
            return cls(**filtered_data)
            
        except FileNotFoundError:
            logger.info(f"Configuration file {file_path} not found, using defaults")
            return cls()
        except Exception as e:
            logger.error(f"Failed to load configuration from {file_path}: {e}")
            return cls()
    
    def get_expert_config(self) -> Dict[str, Any]:
        """Get Circle of Experts specific configuration."""
        return {
            "queries_max_size": self.expert_queries_max_size,
            "queries_ttl": self.expert_queries_ttl,
            "responses_max_size": self.expert_responses_max_size,
            "responses_ttl": self.expert_responses_ttl,
            "response_files_max_size": self.response_files_max_size,
            "response_files_ttl": self.response_files_ttl,
            "cleanup_interval": self.default_cleanup_interval
        }
    
    def get_mcp_config(self) -> Dict[str, Any]:
        """Get MCP specific configuration."""
        return {
            "contexts_max_size": self.mcp_contexts_max_size,
            "contexts_ttl": self.mcp_contexts_ttl,
            "tool_calls_max_per_context": self.mcp_tool_calls_max_per_context,
            "cleanup_interval": self.default_cleanup_interval
        }
    
    def get_connection_config(self) -> Dict[str, Any]:
        """Get connection pool specific configuration."""
        return {
            "http_sessions_max_size": self.http_sessions_max_size,
            "http_sessions_ttl": self.http_sessions_ttl,
            "http_metrics_max_size": self.http_metrics_max_size,
            "http_metrics_ttl": self.http_metrics_ttl,
            "db_metrics_max_size": self.db_pool_metrics_max_size,
            "db_metrics_ttl": self.db_pool_metrics_ttl,
            "cleanup_interval": self.default_cleanup_interval
        }
    
    def get_audit_config(self) -> Dict[str, Any]:
        """Get audit system specific configuration."""
        return {
            "stats_max_size": self.audit_stats_max_size,
            "stats_ttl": self.audit_stats_ttl,
            "buffer_max_size": self.audit_buffer_max_size,
            "high_freq_buffer_max_size": self.audit_high_freq_buffer_max_size,
            "cleanup_interval": self.default_cleanup_interval
        }
    
    def get_scheduler_config(self) -> Dict[str, Any]:
        """Get cleanup scheduler configuration."""
        return {
            "check_interval": self.cleanup_check_interval,
            "memory_threshold_mb": self.memory_threshold_mb,
            "enable_memory_monitoring": self.enable_memory_monitoring,
            "auto_start": self.cleanup_auto_start
        }
    
    def validate(self) -> bool:
        """Validate configuration values."""
        errors = []
        
        # Check positive values
        positive_fields = [
            'expert_queries_max_size', 'expert_responses_max_size', 'response_files_max_size',
            'mcp_contexts_max_size', 'mcp_tool_calls_max_per_context',
            'http_sessions_max_size', 'http_metrics_max_size',
            'audit_stats_max_size', 'audit_buffer_max_size',
            'default_lru_max_size'
        ]
        
        for field in positive_fields:
            value = getattr(self, field)
            if value <= 0:
                errors.append(f"{field} must be positive, got {value}")
        
        # Check TTL values
        ttl_fields = [
            'expert_queries_ttl', 'expert_responses_ttl', 'response_files_ttl',
            'mcp_contexts_ttl', 'http_sessions_ttl', 'http_metrics_ttl',
            'audit_stats_ttl', 'default_ttl'
        ]
        
        for field in ttl_fields:
            value = getattr(self, field)
            if value <= 0:
                errors.append(f"{field} must be positive, got {value}")
        
        # Check memory threshold
        if self.memory_threshold_mb <= 0:
            errors.append(f"memory_threshold_mb must be positive, got {self.memory_threshold_mb}")
        
        # Check cleanup interval
        if self.default_cleanup_interval <= 0:
            errors.append(f"default_cleanup_interval must be positive, got {self.default_cleanup_interval}")
        
        if errors:
            for error in errors:
                logger.error(f"Configuration validation error: {error}")
            return False
        
        return True


# Global configuration instance
_global_config: Optional[CacheConfiguration] = None


def get_cache_config() -> CacheConfiguration:
    """Get the global cache configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = CacheConfiguration()
        
        # Try to load from standard locations
        config_paths = [
            os.getenv('CACHE_CONFIG_FILE'),
            './cache_config.json',
            os.path.expanduser('~/.cache_config.json'),
            '/etc/claude-optimized-deployment/cache_config.json'
        ]
        
        for path in config_paths:
            if path and os.path.exists(path):
                _global_config = CacheConfiguration.load_from_file(path)
                break
        
        # Validate configuration
        if not _global_config.validate():
            logger.warning("Configuration validation failed, using defaults")
            _global_config = CacheConfiguration()
    
    return _global_config


def set_cache_config(config: CacheConfiguration) -> None:
    """Set the global cache configuration."""
    global _global_config
    if config.validate():
        _global_config = config
        logger.info("Updated global cache configuration")
    else:
        logger.error("Invalid configuration provided, keeping current config")


def reset_cache_config() -> None:
    """Reset to default configuration."""
    global _global_config
    _global_config = None


# Configuration presets for different environments
class ConfigPresets:
    """Predefined configuration presets for different environments."""
    
    @staticmethod
    def development() -> CacheConfiguration:
        """Development environment configuration (smaller caches, shorter TTLs)."""
        return CacheConfiguration(
            expert_queries_max_size=100,
            expert_queries_ttl=1800.0,  # 30 minutes
            expert_responses_max_size=50,
            expert_responses_ttl=3600.0,  # 1 hour
            mcp_contexts_max_size=50,
            mcp_contexts_ttl=1800.0,  # 30 minutes
            http_sessions_max_size=20,
            audit_stats_max_size=500,
            memory_threshold_mb=50.0,
            cleanup_check_interval=30.0
        )
    
    @staticmethod
    def production() -> CacheConfiguration:
        """Production environment configuration (larger caches, longer TTLs)."""
        return CacheConfiguration(
            expert_queries_max_size=2000,
            expert_queries_ttl=14400.0,  # 4 hours
            expert_responses_max_size=1000,
            expert_responses_ttl=28800.0,  # 8 hours
            mcp_contexts_max_size=500,
            mcp_contexts_ttl=7200.0,  # 2 hours
            http_sessions_max_size=100,
            audit_stats_max_size=2000,
            memory_threshold_mb=200.0,
            cleanup_check_interval=60.0
        )
    
    @staticmethod
    def testing() -> CacheConfiguration:
        """Testing environment configuration (minimal caches, very short TTLs)."""
        return CacheConfiguration(
            expert_queries_max_size=10,
            expert_queries_ttl=60.0,  # 1 minute
            expert_responses_max_size=10,
            expert_responses_ttl=60.0,  # 1 minute
            mcp_contexts_max_size=10,
            mcp_contexts_ttl=60.0,  # 1 minute
            http_sessions_max_size=5,
            audit_stats_max_size=50,
            memory_threshold_mb=25.0,
            cleanup_check_interval=5.0
        )