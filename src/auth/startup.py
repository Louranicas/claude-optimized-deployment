"""
Authentication Service Startup and Configuration.

Provides initialization functions for authentication services
to be used during application startup.
"""

import os
import logging
from typing import Optional, Dict, Any
from fastapi import FastAPI

from .api import (
    initialize_auth_services,
    auth_router,
    token_manager,
    rbac_manager,
    permission_checker,
    audit_logger,
    token_revocation_service,
    session_manager,
    two_factor_service
)
from .rbac import Role, Permission
from ..core.connections import ConnectionPoolConfig

logger = logging.getLogger(__name__)


async def initialize_authentication(app: FastAPI, config: Optional[Dict[str, Any]] = None):
    """
    Initialize authentication services during app startup.
    
    Args:
        app: FastAPI application instance
        config: Optional configuration dictionary
    """
    try:
        # Validate required environment variables
        if not os.getenv("JWT_SECRET_KEY"):
            raise ValueError("JWT_SECRET_KEY environment variable must be set")
        
        if not os.getenv("REDIS_URL"):
            logger.warning("REDIS_URL not set, using default localhost:6379")
        
        # Initialize authentication services
        await initialize_auth_services()
        
        # Initialize default RBAC roles if needed
        await _initialize_default_roles()
        
        # Include auth router
        app.include_router(auth_router)
        
        # Add startup event handler
        @app.on_event("startup")
        async def startup_event():
            logger.info("Authentication services started successfully")
            
            # Log configuration (without sensitive data)
            logger.info(f"Token expiration: {token_manager.access_token_expire_minutes} minutes")
            logger.info(f"Session timeout: {session_manager.session_timeout_minutes} minutes")
            logger.info(f"Max concurrent sessions: {session_manager.max_concurrent_sessions}")
            logger.info(f"2FA issuer: {two_factor_service.issuer_name}")
        
        # Add shutdown event handler
        @app.on_event("shutdown")
        async def shutdown_event():
            logger.info("Shutting down authentication services...")
            
            # Close Redis connections
            await token_revocation_service.close()
            await session_manager.close()
            await two_factor_service.close()
            
            logger.info("Authentication services shut down successfully")
        
        logger.info("Authentication initialization completed")
        
    except Exception as e:
        logger.error(f"Failed to initialize authentication: {e}")
        raise


async def _initialize_default_roles():
    """Initialize default RBAC roles and permissions."""
    # Define default permissions
    default_permissions = [
        # User permissions
        Permission(resource="profile", action="read", description="View own profile"),
        Permission(resource="profile", action="write", description="Update own profile"),
        Permission(resource="sessions", action="read", description="View own sessions"),
        Permission(resource="sessions", action="write", description="Manage own sessions"),
        
        # Admin permissions
        Permission(resource="users", action="read", description="View all users"),
        Permission(resource="users", action="write", description="Modify users"),
        Permission(resource="users", action="delete", description="Delete users"),
        Permission(resource="users", action="admin", description="Admin user operations"),
        
        # RBAC permissions
        Permission(resource="rbac", action="read", description="View roles and permissions"),
        Permission(resource="rbac", action="write", description="Modify roles and permissions"),
        
        # Audit permissions
        Permission(resource="audit", action="read", description="View audit logs"),
        Permission(resource="audit", action="write", description="Modify audit logs"),
        
        # API permissions
        Permission(resource="api", action="read", description="Read API data"),
        Permission(resource="api", action="write", description="Write API data"),
        
        # Deployment permissions
        Permission(resource="deployment", action="read", description="View deployments"),
        Permission(resource="deployment", action="execute", description="Execute deployments"),
        
        # Monitoring permissions
        Permission(resource="monitoring", action="read", description="View monitoring data"),
        Permission(resource="monitoring", action="write", description="Configure monitoring"),
        
        # MCP permissions
        Permission(resource="mcp", action="read", description="View MCP servers"),
        Permission(resource="mcp", action="execute", description="Execute MCP commands"),
        Permission(resource="mcp", action="admin", description="Admin MCP operations"),
    ]
    
    # Add permissions to RBAC manager
    for perm in default_permissions:
        rbac_manager.add_permission(perm)
    
    # Define default roles
    default_roles = [
        {
            "name": "viewer",
            "description": "Read-only access",
            "permissions": [
                Permission(resource="profile", action="read"),
                Permission(resource="sessions", action="read"),
                Permission(resource="monitoring", action="read"),
            ]
        },
        {
            "name": "user",
            "description": "Standard user access",
            "permissions": [
                Permission(resource="profile", action="read"),
                Permission(resource="profile", action="write"),
                Permission(resource="sessions", action="read"),
                Permission(resource="sessions", action="write"),
                Permission(resource="api", action="read"),
                Permission(resource="monitoring", action="read"),
            ]
        },
        {
            "name": "developer",
            "description": "Developer access",
            "permissions": [
                Permission(resource="profile", action="*"),
                Permission(resource="sessions", action="*"),
                Permission(resource="api", action="*"),
                Permission(resource="deployment", action="read"),
                Permission(resource="monitoring", action="*"),
                Permission(resource="mcp", action="read"),
                Permission(resource="mcp", action="execute"),
            ],
            "inherits": ["user"]
        },
        {
            "name": "admin",
            "description": "Administrator access",
            "permissions": [
                Permission(resource="users", action="*"),
                Permission(resource="rbac", action="*"),
                Permission(resource="audit", action="read"),
                Permission(resource="deployment", action="*"),
                Permission(resource="mcp", action="*"),
            ],
            "inherits": ["developer"]
        },
        {
            "name": "super_admin",
            "description": "Super administrator with full access",
            "permissions": [
                Permission(resource="*", action="*"),  # Full access
            ],
            "inherits": ["admin"]
        },
        {
            "name": "auditor",
            "description": "Audit and compliance access",
            "permissions": [
                Permission(resource="audit", action="*"),
                Permission(resource="users", action="read"),
                Permission(resource="rbac", action="read"),
                Permission(resource="monitoring", action="read"),
            ]
        },
        {
            "name": "api_key",
            "description": "API key access (limited)",
            "permissions": [
                Permission(resource="api", action="read"),
                Permission(resource="api", action="write"),
            ]
        }
    ]
    
    # Add roles to RBAC manager
    for role_data in default_roles:
        role = Role(
            name=role_data["name"],
            description=role_data["description"],
            permissions=set(role_data["permissions"])
        )
        
        # Set up inheritance
        if "inherits" in role_data:
            for parent_name in role_data["inherits"]:
                parent_role = rbac_manager.get_role(parent_name)
                if parent_role:
                    role.add_parent(parent_role)
        
        rbac_manager.add_role(role)
    
    logger.info(f"Initialized {len(default_permissions)} permissions and {len(default_roles)} roles")


def get_auth_config() -> Dict[str, Any]:
    """
    Get authentication configuration from environment variables.
    
    Returns:
        Dictionary with authentication configuration
    """
    return {
        # JWT Configuration
        "jwt_secret_key": os.getenv("JWT_SECRET_KEY"),
        "jwt_algorithm": os.getenv("JWT_ALGORITHM", "HS256"),
        "access_token_expire_minutes": int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")),
        "refresh_token_expire_days": int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30")),
        
        # Redis Configuration
        "redis_url": os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        
        # Session Configuration
        "max_concurrent_sessions": int(os.getenv("MAX_CONCURRENT_SESSIONS", "5")),
        "session_timeout_minutes": int(os.getenv("SESSION_TIMEOUT_MINUTES", "30")),
        "absolute_timeout_hours": int(os.getenv("ABSOLUTE_TIMEOUT_HOURS", "24")),
        "activity_timeout_minutes": int(os.getenv("ACTIVITY_TIMEOUT_MINUTES", "30")),
        
        # 2FA Configuration
        "2fa_issuer_name": os.getenv("2FA_ISSUER_NAME", "Claude Optimized Deployment"),
        "totp_window": int(os.getenv("TOTP_WINDOW", "1")),
        "challenge_timeout_minutes": int(os.getenv("CHALLENGE_TIMEOUT_MINUTES", "5")),
        "backup_codes_count": int(os.getenv("BACKUP_CODES_COUNT", "10")),
        
        # Security Configuration
        "max_failed_attempts": int(os.getenv("MAX_FAILED_ATTEMPTS", "5")),
        "lockout_duration_minutes": int(os.getenv("LOCKOUT_DURATION_MINUTES", "30")),
        "password_expiry_days": int(os.getenv("PASSWORD_EXPIRY_DAYS", "90")),
        "password_history_size": int(os.getenv("PASSWORD_HISTORY_SIZE", "5")),
        
        # API Key Configuration
        "max_api_keys_per_user": int(os.getenv("MAX_API_KEYS_PER_USER", "10")),
        "api_key_expiry_days": int(os.getenv("API_KEY_EXPIRY_DAYS", "365")),
        
        # Rate Limiting
        "rate_limit_per_minute": int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),
        "rate_limit_per_hour": int(os.getenv("RATE_LIMIT_PER_HOUR", "1000")),
        
        # Audit Configuration
        "audit_retention_days": int(os.getenv("AUDIT_RETENTION_DAYS", "90")),
        "audit_batch_size": int(os.getenv("AUDIT_BATCH_SIZE", "1000")),
    }


def validate_auth_config(config: Dict[str, Any]) -> bool:
    """
    Validate authentication configuration.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        True if configuration is valid
        
    Raises:
        ValueError: If configuration is invalid
    """
    # Check required fields
    if not config.get("jwt_secret_key"):
        raise ValueError("JWT secret key is required")
    
    # Validate JWT secret key strength
    if len(config["jwt_secret_key"]) < 32:
        raise ValueError("JWT secret key must be at least 32 characters long")
    
    # Validate numeric ranges
    if config["access_token_expire_minutes"] < 5:
        raise ValueError("Access token expiration must be at least 5 minutes")
    
    if config["max_concurrent_sessions"] < 1:
        raise ValueError("Maximum concurrent sessions must be at least 1")
    
    if config["max_failed_attempts"] < 3:
        raise ValueError("Maximum failed attempts must be at least 3")
    
    return True