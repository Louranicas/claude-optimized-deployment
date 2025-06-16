"""
Enhanced MCP Server Authentication Integration.

This module provides comprehensive authentication and authorization for all MCP servers,
addressing the security gaps identified in the audit.
"""

import asyncio
import functools
import hashlib
import hmac
import json
import logging
import secrets
import ssl
from typing import Dict, Any, Optional, List, Callable, Set
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from pathlib import Path

from ...auth.security_enhancements import (
    SecurityConfig,
    EnhancedJWTManager,
    EnhancedAPIKeyManager,
    EnhancedRBACEnforcer,
    MutualTLSAuthenticator,
    SecurityAuditLogger,
    require_mcp_authentication
)

from src.core.error_handler import (
    handle_errors,
    async_handle_errors,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    log_error
)

logger = logging.getLogger(__name__)


@dataclass
class MCPAuthContext:
    """Authentication context for MCP operations."""
    user_id: str
    session_id: str
    roles: List[str]
    permissions: Set[str]
    service_name: Optional[str] = None
    is_service_account: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def has_permission(self, resource: str, action: str) -> bool:
        """Check if context has specific permission."""
        return f"{resource}:{action}" in self.permissions or "*:*" in self.permissions


class MCPServerAuthenticator:
    """Centralized authenticator for all MCP servers."""
    
    def __init__(
        self,
        jwt_manager: EnhancedJWTManager,
        api_key_manager: EnhancedAPIKeyManager,
        rbac_enforcer: EnhancedRBACEnforcer,
        mtls_authenticator: MutualTLSAuthenticator,
        audit_logger: SecurityAuditLogger
    ):
        self.jwt_manager = jwt_manager
        self.api_key_manager = api_key_manager
        self.rbac_enforcer = rbac_enforcer
        self.mtls_authenticator = mtls_authenticator
        self.audit_logger = audit_logger
        
        # Cache for validated contexts
        self.context_cache: Dict[str, tuple[MCPAuthContext, datetime]] = {}
        self.cache_ttl = timedelta(minutes=5)
        
        # Service account registry
        self.service_accounts: Dict[str, Dict[str, Any]] = {}
        
    async def authenticate_request(
        self,
        auth_token: Optional[str] = None,
        api_key: Optional[str] = None,
        client_cert: Optional[str] = None,
        service_name: Optional[str] = None
    ) -> MCPAuthContext:
        """
        Authenticate a request using multiple authentication methods.
        
        Args:
            auth_token: JWT bearer token
            api_key: API key for service authentication
            client_cert: Client certificate for mTLS
            service_name: Name of the calling service
            
        Returns:
            Authenticated context
            
        Raises:
            AuthenticationError: If authentication fails
        """
        # Try JWT authentication first
        if auth_token:
            context = await self._authenticate_jwt(auth_token)
            if context:
                await self.audit_logger.log_authentication(
                    "jwt_auth_success",
                    context.user_id,
                    True,
                    {"service": service_name}
                )
                return context
        
        # Try API key authentication
        if api_key:
            context = await self._authenticate_api_key(api_key, service_name)
            if context:
                await self.audit_logger.log_authentication(
                    "api_key_auth_success",
                    context.user_id,
                    True,
                    {"service": service_name}
                )
                return context
        
        # Try mTLS authentication
        if client_cert and service_name:
            context = await self._authenticate_mtls(client_cert, service_name)
            if context:
                await self.audit_logger.log_authentication(
                    "mtls_auth_success",
                    context.user_id,
                    True,
                    {"service": service_name}
                )
                return context
        
        # Authentication failed
        await self.audit_logger.log_authentication(
            "auth_failed",
            None,
            False,
            {"service": service_name}
        )
        raise AuthenticationError("No valid authentication credentials provided")
    
    async def _authenticate_jwt(self, token: str) -> Optional[MCPAuthContext]:
        """Authenticate using JWT token."""
        # Check cache first
        cache_key = hashlib.sha256(token.encode()).hexdigest()
        if cache_key in self.context_cache:
            context, cached_at = self.context_cache[cache_key]
            if datetime.now(timezone.utc) - cached_at < self.cache_ttl:
                return context
        
        # Verify token
        payload = self.jwt_manager.verify_token(token)
        if not payload:
            return None
        
        # Extract user info
        user_id = payload.get("sub") or payload.get("user_id")
        if not user_id:
            return None
        
        # Get roles and permissions
        roles = payload.get("roles", [])
        permissions = set()
        for role in roles:
            role_perms = self.rbac_enforcer._calculate_permissions([role])
            permissions.update(role_perms)
        
        # Create context
        context = MCPAuthContext(
            user_id=user_id,
            session_id=payload.get("jti", ""),
            roles=roles,
            permissions=permissions,
            metadata={"token_type": "jwt"}
        )
        
        # Cache context
        self.context_cache[cache_key] = (context, datetime.now(timezone.utc))
        
        return context
    
    async def _authenticate_api_key(
        self,
        api_key: str,
        service_name: Optional[str] = None
    ) -> Optional[MCPAuthContext]:
        """Authenticate using API key."""
        # Verify API key
        key_metadata = self.api_key_manager.verify_api_key(api_key)
        if not key_metadata:
            return None
        
        # Check service name match if provided
        if service_name and key_metadata.get("service_name") != service_name:
            logger.warning(
                f"Service name mismatch: expected {key_metadata.get('service_name')}, "
                f"got {service_name}"
            )
            return None
        
        # Create context for service account
        context = MCPAuthContext(
            user_id=f"service:{key_metadata.get('service_name', 'unknown')}",
            session_id=api_key.split(".")[0],  # Use key ID as session ID
            roles=["mcp_service"],
            permissions={
                "mcp.*:*",
                "infrastructure:execute",
                "monitoring:write"
            },
            service_name=key_metadata.get("service_name"),
            is_service_account=True,
            metadata={"token_type": "api_key", "key_id": api_key.split(".")[0]}
        )
        
        return context
    
    async def _authenticate_mtls(
        self,
        client_cert: str,
        service_name: str
    ) -> Optional[MCPAuthContext]:
        """Authenticate using mutual TLS."""
        # Verify client certificate
        if not self.mtls_authenticator.verify_service_certificate(client_cert, service_name):
            return None
        
        # Get service account info
        service_info = self.service_accounts.get(service_name)
        if not service_info:
            logger.warning(f"Unknown service: {service_name}")
            return None
        
        # Create context for service
        context = MCPAuthContext(
            user_id=f"service:{service_name}",
            session_id=hashlib.sha256(client_cert.encode()).hexdigest()[:16],
            roles=service_info.get("roles", ["mcp_service"]),
            permissions=set(service_info.get("permissions", [])),
            service_name=service_name,
            is_service_account=True,
            metadata={"token_type": "mtls"}
        )
        
        return context
    
    async def authorize_tool_access(
        self,
        context: MCPAuthContext,
        server_name: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Authorize access to a specific MCP tool.
        
        Args:
            context: Authentication context
            server_name: Name of the MCP server
            tool_name: Name of the tool
            arguments: Tool arguments for context-aware authorization
            
        Returns:
            True if authorized, False otherwise
        """
        # Build resource identifier
        resource = f"mcp.{server_name.lower()}.{tool_name}"
        
        # Check permission
        allowed = self.rbac_enforcer.check_permission(
            context.user_id,
            context.roles,
            resource,
            "execute",
            {"tool_name": tool_name, "arguments": arguments}
        )
        
        # Audit authorization
        await self.audit_logger.log_authorization(
            context.user_id,
            resource,
            "execute",
            allowed,
            {"server": server_name, "tool": tool_name}
        )
        
        return allowed
    
    def register_service_account(
        self,
        service_name: str,
        roles: List[str],
        permissions: List[str]
    ):
        """Register a service account for mTLS authentication."""
        self.service_accounts[service_name] = {
            "roles": roles,
            "permissions": permissions,
            "registered_at": datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Registered service account: {service_name}")


def authenticated_mcp_server(authenticator: MCPServerAuthenticator):
    """
    Decorator to add authentication to MCP server classes.
    
    This decorator wraps the call_tool method to enforce authentication
    and authorization before tool execution.
    """
    def decorator(cls):
        # Store original call_tool method
        original_call_tool = cls.call_tool
        
        @functools.wraps(original_call_tool)
        async def authenticated_call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
            # Extract authentication credentials from context
            auth_token = getattr(self, '_auth_token', None)
            api_key = getattr(self, '_api_key', None)
            client_cert = getattr(self, '_client_cert', None)
            service_name = getattr(self, '_service_name', None)
            
            # Authenticate request
            try:
                context = await authenticator.authenticate_request(
                    auth_token=auth_token,
                    api_key=api_key,
                    client_cert=client_cert,
                    service_name=service_name
                )
            except AuthenticationError as e:
                logger.error(f"Authentication failed for {cls.__name__}: {e}")
                raise
            
            # Store context for use in tool methods
            self._auth_context = context
            
            # Authorize tool access
            server_name = cls.__name__.lower().replace('mcp', '').replace('server', '')
            authorized = await authenticator.authorize_tool_access(
                context,
                server_name,
                tool_name,
                arguments
            )
            
            if not authorized:
                raise AuthorizationError(
                    f"Access denied to tool {tool_name} in {cls.__name__}"
                )
            
            # Call original method
            try:
                result = await original_call_tool(self, tool_name, arguments)
                
                # Audit successful execution
                await authenticator.audit_logger.log_authorization(
                    context.user_id,
                    f"mcp.{server_name}.{tool_name}",
                    "executed",
                    True,
                    {"result": "success"}
                )
                
                return result
                
            except Exception as e:
                # Audit failed execution
                await authenticator.audit_logger.log_authorization(
                    context.user_id,
                    f"mcp.{server_name}.{tool_name}",
                    "executed",
                    False,
                    {"error": str(e)}
                )
                raise
        
        # Replace call_tool method
        cls.call_tool = authenticated_call_tool
        
        # Add method to set authentication credentials
        def set_auth_credentials(
            self,
            auth_token: Optional[str] = None,
            api_key: Optional[str] = None,
            client_cert: Optional[str] = None,
            service_name: Optional[str] = None
        ):
            """Set authentication credentials for the server instance."""
            self._auth_token = auth_token
            self._api_key = api_key
            self._client_cert = client_cert
            self._service_name = service_name
        
        cls.set_auth_credentials = set_auth_credentials
        
        return cls
    
    return decorator


class MCPAuthenticationMiddleware:
    """FastAPI middleware for MCP authentication."""
    
    def __init__(self, authenticator: MCPServerAuthenticator):
        self.authenticator = authenticator
    
    async def __call__(self, request, call_next):
        """Process request with authentication."""
        # Extract authentication headers
        auth_header = request.headers.get("Authorization")
        api_key_header = request.headers.get("X-API-Key")
        
        # Extract client certificate if using mTLS
        client_cert = None
        if hasattr(request, "transport"):
            ssl_object = request.transport.get_extra_info("ssl_object")
            if ssl_object:
                client_cert = ssl_object.getpeercert()
        
        # Authenticate if credentials provided
        if auth_header or api_key_header or client_cert:
            try:
                # Extract bearer token
                auth_token = None
                if auth_header and auth_header.startswith("Bearer "):
                    auth_token = auth_header.split(" ", 1)[1]
                
                # Authenticate
                context = await self.authenticator.authenticate_request(
                    auth_token=auth_token,
                    api_key=api_key_header,
                    client_cert=client_cert
                )
                
                # Add context to request state
                request.state.auth_context = context
                
            except AuthenticationError as e:
                logger.warning(f"Authentication failed: {e}")
                # Continue without authentication context
        
        # Process request
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        return response


# Tool-specific authorization helpers
def require_tool_permission(resource: str, action: str = "execute"):
    """
    Decorator for MCP tool methods requiring specific permissions.
    
    Usage:
        @require_tool_permission("mcp.docker.build")
        async def docker_build(self, ...):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(self, *args, **kwargs):
            # Check for auth context
            if not hasattr(self, '_auth_context') or not self._auth_context:
                raise AuthenticationError("No authentication context")
            
            context: MCPAuthContext = self._auth_context
            
            # Check permission
            if not context.has_permission(resource, action):
                raise AuthorizationError(
                    f"Permission denied: {resource}:{action}"
                )
            
            # Execute tool
            return await func(self, *args, **kwargs)
        
        return wrapper
    
    return decorator


# Service registry for inter-service authentication
class ServiceRegistry:
    """Registry for MCP services and their credentials."""
    
    def __init__(self):
        self.services: Dict[str, Dict[str, Any]] = {}
        self.service_keys: Dict[str, str] = {}
    
    def register_service(
        self,
        service_name: str,
        api_key: str,
        cert_path: Optional[str] = None,
        permissions: Optional[List[str]] = None
    ):
        """Register a service with its credentials."""
        self.services[service_name] = {
            "api_key": api_key,
            "cert_path": cert_path,
            "permissions": permissions or [],
            "registered_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Store API key separately for quick lookup
        key_id = api_key.split(".")[0]
        self.service_keys[key_id] = service_name
        
        logger.info(f"Registered service: {service_name}")
    
    def get_service_credentials(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get credentials for a service."""
        return self.services.get(service_name)
    
    def get_service_by_key_id(self, key_id: str) -> Optional[str]:
        """Get service name by API key ID."""
        return self.service_keys.get(key_id)


# Global authenticator instance
_mcp_authenticator: Optional[MCPServerAuthenticator] = None
_service_registry: Optional[ServiceRegistry] = None


async def initialize_mcp_authentication(
    jwt_manager: EnhancedJWTManager,
    api_key_manager: EnhancedAPIKeyManager,
    rbac_enforcer: EnhancedRBACEnforcer,
    mtls_authenticator: MutualTLSAuthenticator,
    audit_logger: SecurityAuditLogger
):
    """Initialize MCP authentication system."""
    global _mcp_authenticator, _service_registry
    
    _mcp_authenticator = MCPServerAuthenticator(
        jwt_manager,
        api_key_manager,
        rbac_enforcer,
        mtls_authenticator,
        audit_logger
    )
    
    _service_registry = ServiceRegistry()
    
    # Register default service accounts
    _mcp_authenticator.register_service_account(
        "docker-server",
        ["mcp_service"],
        ["mcp.docker:*", "infrastructure:execute"]
    )
    
    _mcp_authenticator.register_service_account(
        "kubernetes-server",
        ["mcp_service"],
        ["mcp.kubernetes:*", "infrastructure:execute"]
    )
    
    _mcp_authenticator.register_service_account(
        "prometheus-server",
        ["monitoring_service"],
        ["mcp.prometheus:*", "monitoring:*"]
    )
    
    logger.info("MCP authentication system initialized")


def get_mcp_authenticator() -> MCPServerAuthenticator:
    """Get the global MCP authenticator instance."""
    if not _mcp_authenticator:
        raise RuntimeError("MCP authenticator not initialized")
    return _mcp_authenticator


def get_service_registry() -> ServiceRegistry:
    """Get the global service registry."""
    if not _service_registry:
        raise RuntimeError("Service registry not initialized")
    return _service_registry