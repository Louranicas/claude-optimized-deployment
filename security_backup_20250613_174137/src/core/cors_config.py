"""
Secure CORS (Cross-Origin Resource Sharing) Configuration.

This module provides centralized, secure CORS configuration following OWASP guidelines.
It replaces wildcard origins with specific trusted domains and implements security best practices.
"""

import os
from typing import List, Optional
from enum import Enum

__all__ = [
    "Environment",
    "SecureCORSConfig",
    "get_cors_config",
    "reset_cors_config",
    "get_fastapi_cors_config",
    "is_origin_allowed",
    "get_cors_headers_for_origin"
]



class Environment(Enum):
    """Application environments."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class SecureCORSConfig:
    """Secure CORS configuration with environment-specific settings."""
    
    def __init__(self, environment: Optional[Environment] = None):
        """
        Initialize CORS configuration based on environment.
        
        Args:
            environment: Application environment. If None, will be detected from ENV var.
        """
        if environment is None:
            env_str = os.getenv("ENVIRONMENT", "development").lower()
            try:
                self.environment = Environment(env_str)
            except ValueError:
                self.environment = Environment.DEVELOPMENT
        else:
            self.environment = environment
        
        self._setup_cors_settings()
    
    def _setup_cors_settings(self):
        """Setup CORS settings based on environment."""
        # Base security settings
        self.allow_credentials = True
        self.allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
        self.allow_headers = [
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Authorization",
            "X-Requested-With",
            "X-API-Key",
            "X-CSRF-Token",
            "Cache-Control"
        ]
        self.expose_headers = [
            "X-Process-Time",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset"
        ]
        self.max_age = 600  # 10 minutes
        
        # Environment-specific origins
        if self.environment == Environment.PRODUCTION:
            self.allowed_origins = self._get_production_origins()
        elif self.environment == Environment.STAGING:
            self.allowed_origins = self._get_staging_origins()
        elif self.environment == Environment.TESTING:
            self.allowed_origins = self._get_testing_origins()
        else:  # Development
            self.allowed_origins = self._get_development_origins()
    
    def _get_production_origins(self) -> List[str]:
        """Get trusted origins for production environment."""
        # Production should only allow specific, verified domains
        base_origins = [
            "https://claude-optimized-deployment.com",
            "https://api.claude-optimized-deployment.com",
            "https://dashboard.claude-optimized-deployment.com",
            "https://admin.claude-optimized-deployment.com"
        ]
        
        # Allow additional origins from environment variable (comma-separated)
        additional_origins = os.getenv("CORS_ALLOWED_ORIGINS", "")
        if additional_origins:
            base_origins.extend([
                origin.strip() 
                for origin in additional_origins.split(",") 
                if origin.strip()
            ])
        
        return base_origins
    
    def _get_staging_origins(self) -> List[str]:
        """Get trusted origins for staging environment."""
        return [
            "https://staging.claude-optimized-deployment.com",
            "https://staging-api.claude-optimized-deployment.com",
            "https://staging-dashboard.claude-optimized-deployment.com",
            "https://preview.claude-optimized-deployment.com"
        ]
    
    def _get_testing_origins(self) -> List[str]:
        """Get trusted origins for testing environment."""
        return [
            "http://localhost:3000",
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8000",
            "http://testserver"
        ]
    
    def _get_development_origins(self) -> List[str]:
        """Get trusted origins for development environment."""
        # Development allows more flexibility but still avoids wildcards
        return [
            "http://localhost:3000",
            "http://localhost:3001", 
            "http://localhost:8000",
            "http://localhost:8080",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3001",
            "http://127.0.0.1:8000",
            "http://127.0.0.1:8080",
            "http://dev.claude-optimized-deployment.local",
            "https://dev.claude-optimized-deployment.local"
        ]
    
    def get_fastapi_cors_config(self) -> dict:
        """Get CORS configuration for FastAPI CORSMiddleware."""
        return {
            "allow_origins": self.allowed_origins,
            "allow_credentials": self.allow_credentials,
            "allow_methods": self.allow_methods,
            "allow_headers": self.allow_headers,
            "expose_headers": self.expose_headers,
            "max_age": self.max_age
        }
    
    def get_manual_cors_headers(self, origin: str) -> dict:
        """
        Get CORS headers for manual handling.
        
        Args:
            origin: The origin from the request
            
        Returns:
            Dictionary of CORS headers if origin is allowed, empty dict otherwise
        """
        if not self.is_origin_allowed(origin):
            return {}
        
        headers = {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": ", ".join(self.allow_methods),
            "Access-Control-Allow-Headers": ", ".join(self.allow_headers),
            "Access-Control-Max-Age": str(self.max_age)
        }
        
        if self.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        
        if self.expose_headers:
            headers["Access-Control-Expose-Headers"] = ", ".join(self.expose_headers)
        
        return headers
    
    def is_origin_allowed(self, origin: str) -> bool:
        """
        Check if an origin is allowed.
        
        Args:
            origin: The origin to check
            
        Returns:
            True if origin is allowed, False otherwise
        """
        if not origin:
            return False
        
        # Exact match
        if origin in self.allowed_origins:
            return True
        
        # For development, allow additional localhost variations
        if self.environment == Environment.DEVELOPMENT:
            if origin.startswith(("http://localhost:", "http://127.0.0.1:")):
                return True
        
        return False
    
    def validate_request_origin(self, origin: str, raise_exception: bool = True) -> bool:
        """
        Validate a request origin and optionally raise an exception.
        
        Args:
            origin: The origin to validate
            raise_exception: Whether to raise an exception if invalid
            
        Returns:
            True if valid, False otherwise
            
        Raises:
            ValueError: If origin is invalid and raise_exception is True
        """
        if self.is_origin_allowed(origin):
            return True
        
        if raise_exception:
            raise ValueError(f"Origin '{origin}' is not allowed by CORS policy")
        
        return False
    
    def add_trusted_origin(self, origin: str) -> None:
        """
        Add a trusted origin at runtime (for dynamic configuration).
        
        Args:
            origin: The origin to add
            
        Note:
            This should be used carefully and only with validated, trusted origins.
        """
        if origin and origin not in self.allowed_origins:
            # Validate origin format
            if not (origin.startswith(("http://", "https://")) or origin == "null"):
                raise ValueError(f"Invalid origin format: {origin}")
            
            self.allowed_origins.append(origin)
    
    def remove_trusted_origin(self, origin: str) -> None:
        """
        Remove a trusted origin at runtime.
        
        Args:
            origin: The origin to remove
        """
        if origin in self.allowed_origins:
            self.allowed_origins.remove(origin)
    
    def get_security_report(self) -> dict:
        """
        Get a security report of the current CORS configuration.
        
        Returns:
            Dictionary containing security analysis
        """
        report = {
            "environment": self.environment.value,
            "total_origins": len(self.allowed_origins),
            "allows_credentials": self.allow_credentials,
            "max_age_seconds": self.max_age,
            "security_analysis": {
                "uses_wildcard": "*" in self.allowed_origins,
                "allows_http_in_production": False,
                "localhost_allowed": False,
                "ip_addresses_allowed": False
            }
        }
        
        # Security analysis
        if self.environment == Environment.PRODUCTION:
            http_origins = [o for o in self.allowed_origins if o.startswith("http://")]
            report["security_analysis"]["allows_http_in_production"] = len(http_origins) > 0
        
        localhost_origins = [o for o in self.allowed_origins if "localhost" in o or "127.0.0.1" in o]
        report["security_analysis"]["localhost_allowed"] = len(localhost_origins) > 0
        
        # Check for IP addresses (basic check)
        import re
        ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        ip_origins = [o for o in self.allowed_origins if ip_pattern.search(o)]
        report["security_analysis"]["ip_addresses_allowed"] = len(ip_origins) > 0
        
        return report


# Global instance for easy access
_cors_config: Optional[SecureCORSConfig] = None


def get_cors_config(environment: Optional[Environment] = None) -> SecureCORSConfig:
    """
    Get the global CORS configuration instance.
    
    Args:
        environment: Environment to use. If None, uses existing or detects from ENV.
        
    Returns:
        SecureCORSConfig instance
    """
    global _cors_config
    
    if _cors_config is None or environment is not None:
        _cors_config = SecureCORSConfig(environment)
    
    return _cors_config


def reset_cors_config():
    """Reset the global CORS configuration (useful for testing)."""
    global _cors_config
    _cors_config = None


# Convenience functions
def get_fastapi_cors_config(environment: Optional[Environment] = None) -> dict:
    """Get FastAPI CORS configuration."""
    return get_cors_config(environment).get_fastapi_cors_config()


def is_origin_allowed(origin: str, environment: Optional[Environment] = None) -> bool:
    """Check if an origin is allowed."""
    return get_cors_config(environment).is_origin_allowed(origin)


def get_cors_headers_for_origin(origin: str, environment: Optional[Environment] = None) -> dict:
    """Get CORS headers for a specific origin."""
    return get_cors_config(environment).get_manual_cors_headers(origin)