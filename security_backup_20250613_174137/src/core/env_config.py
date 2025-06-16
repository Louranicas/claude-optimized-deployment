"""
Environment Configuration Manager
Centralizes all environment variable handling with validation
"""

import os
from typing import Optional, Dict, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class EnvironmentConfig:
    """Secure environment configuration manager"""
    
    # Required environment variables
    REQUIRED_VARS = [
        "DATABASE_URL",
        "JWT_SECRET",
        "VAULT_ADDR",
        "VAULT_TOKEN"
    ]
    
    # Optional with defaults
    OPTIONAL_VARS = {
        "LOG_LEVEL": "INFO",
        "WORKERS": "4",
        "TIMEOUT": "300",
        "REDIS_URL": "redis://localhost:6379",
        "PROMETHEUS_PORT": "9090"
    }
    
    @classmethod
    def validate_environment(cls) -> bool:
        """Validate all required environment variables are set"""
        missing = []
        
        for var in cls.REQUIRED_VARS:
            if not os.environ.get(var):
                missing.append(var)
        
        if missing:
            logger.error(f"Missing required environment variables: {missing}")
            return False
        
        return True
    
    @classmethod
    def get(cls, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get environment variable with optional default"""
        value = os.environ.get(key, cls.OPTIONAL_VARS.get(key, default))
        
        # Never log sensitive values
        if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'key', 'token']):
            logger.debug(f"Retrieved {key} from environment (value hidden)")
        else:
            logger.debug(f"Retrieved {key} = {value}")
        
        return value
    
    @classmethod
    def get_int(cls, key: str, default: int = 0) -> int:
        """Get environment variable as integer"""
        value = cls.get(key, str(default))
        try:
            return int(value)
        except ValueError:
            logger.warning(f"Invalid integer value for {key}: {value}, using default: {default}")
            return default
    
    @classmethod
    def get_bool(cls, key: str, default: bool = False) -> bool:
        """Get environment variable as boolean"""
        value = cls.get(key, str(default))
        return value.lower() in ('true', '1', 'yes', 'on')
    
    @classmethod
    def get_database_config(cls) -> Dict[str, Any]:
        """Get database configuration from environment"""
        database_url = cls.get("DATABASE_URL")
        if not database_url:
            raise ValueError("DATABASE_URL not configured")
        
        # Parse database URL securely
        from urllib.parse import urlparse
        parsed = urlparse(database_url)
        
        return {
            "host": parsed.hostname,
            "port": parsed.port or 5432,
            "database": parsed.path.lstrip('/'),
            "username": parsed.username,
            "password": parsed.password,  # Will be None if not in URL
            "ssl_mode": cls.get("DATABASE_SSL_MODE", "require")
        }
    
    @classmethod
    def load_env_file(cls, env_file: str = ".env") -> None:
        """Load environment variables from .env file"""
        env_path = Path(env_file)
        if not env_path.exists():
            logger.warning(f"Environment file {env_file} not found")
            return
        
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        # Only set if not already in environment
                        if key not in os.environ:
                            os.environ[key] = value.strip('"'')
        except Exception as e:
            logger.error(f"Error loading environment file: {e}")

# Initialize on import
if os.environ.get("LOAD_ENV_FILE", "true").lower() == "true":
    EnvironmentConfig.load_env_file()
