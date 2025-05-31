"""Tortoise ORM configuration for migrations and application setup."""

import os
from typing import Dict, Any

def get_database_url() -> str:
    """Get database URL from environment or use default."""
    url = os.getenv("DATABASE_URL", "sqlite://./code_deployment.db")
    
    # Convert SQLAlchemy format to Tortoise format
    if url.startswith("postgresql+asyncpg://"):
        return url.replace("postgresql+asyncpg://", "postgres://")
    elif url.startswith("sqlite+aiosqlite://"):
        return url.replace("sqlite+aiosqlite://", "sqlite://")
    
    return url


TORTOISE_ORM: Dict[str, Any] = {
    "connections": {
        "default": get_database_url()
    },
    "apps": {
        "models": {
            "models": [
                "src.database.models",
                "aerich.models"  # Required for migration tracking
            ],
            "default_connection": "default",
        }
    },
    "use_tz": True,
    "timezone": "UTC"
}

# Development configuration
TORTOISE_ORM_DEV: Dict[str, Any] = {
    "connections": {
        "default": "sqlite://./code_deployment_dev.db"
    },
    "apps": {
        "models": {
            "models": [
                "src.database.models",
                "aerich.models"
            ],
            "default_connection": "default",
        }
    },
    "use_tz": True,
    "timezone": "UTC"
}

# Test configuration
TORTOISE_ORM_TEST: Dict[str, Any] = {
    "connections": {
        "default": "sqlite://:memory:"
    },
    "apps": {
        "models": {
            "models": [
                "src.database.models"
            ],
            "default_connection": "default",
        }
    },
    "use_tz": True,
    "timezone": "UTC"
}