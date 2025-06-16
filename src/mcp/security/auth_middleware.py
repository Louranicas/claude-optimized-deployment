"""
MCP Authentication Middleware for secure tool access control.

Implements JWT-based authentication, role-based access control (RBAC),
and per-tool authorization with comprehensive audit logging.
"""

from __future__ import annotations
import os
import time
import hashlib
import hmac
import jwt
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
from functools import wraps
import asyncio
from collections import defaultdict

from src.core.error_handler import (
    handle_errors,
    async_handle_errors,
    log_error,
    ValidationError,
    ConfigurationError,
    CircuitBreakerError,
    RateLimitError
)

__all__ = [
    "UserRole",
    "Permission",
    "AuthContext",
    "RateLimitInfo",
    "MCPAuthMiddleware",
    "require_auth",
    "get_auth_middleware",
    "initialize_auth_middleware"
]


logger = logging.getLogger(__name__)


class UserRole(Enum):
    """User roles with hierarchical permissions."""
    ADMIN = "admin"
    OPERATOR = "operator" 
    READONLY = "readonly"
    GUEST = "guest"


class Permission(Enum):
    """Tool permissions."""
    EXECUTE = "execute"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


@dataclass
class AuthContext:
    """Authentication context for requests."""
    user_id: str
    role: UserRole
    permissions: Set[Permission]
    session_id: str
    issued_at: datetime
    expires_at: datetime
    tool_whitelist: Optional[Set[str]] = None
    metadata: Dict[str, Any] = None


@dataclass 
class RateLimitInfo:
    """Rate limiting information per user/tool combination."""
    requests_count: int = 0
    window_start: float = 0.0
    burst_count: int = 0
    last_request: float = 0.0


class MCPAuthMiddleware:
    """
    MCP Authentication Middleware with JWT tokens and RBAC.
    
    Features:
    - JWT token validation with role-based permissions
    - Per-tool authorization checks
    - Rate limiting per user and tool
    - Session management with proper invalidation
    - Comprehensive audit logging
    - Circuit breaker for failed authentication attempts
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        """Initialize authentication middleware."""
        self.secret_key = secret_key or os.getenv("MCP_AUTH_SECRET") or self._generate_secret()
        self.algorithm = "HS256"
        self.token_expiry = timedelta(hours=1)
        
        # Active sessions tracking
        self.active_sessions: Dict[str, AuthContext] = {}
        
        # Rate limiting per user/tool combination
        self.rate_limits: Dict[str, RateLimitInfo] = defaultdict(RateLimitInfo)
        self.rate_limit_config = {
            "requests_per_minute": 60,
            "burst_size": 10,
            "window_seconds": 60
        }
        
        # Tool permissions matrix
        self.tool_permissions = self._initialize_tool_permissions()
        
        # Audit log
        self.audit_log: List[Dict[str, Any]] = []
        
        # Failed authentication tracking (circuit breaker)
        self.failed_attempts: Dict[str, List[float]] = defaultdict(list)
        self.lockout_threshold = 5
        self.lockout_duration = 300  # 5 minutes
    
    def _generate_secret(self) -> str:
        """Generate a secure secret key."""
        return hashlib.sha256(os.urandom(32)).hexdigest()
    
    def _initialize_tool_permissions(self) -> Dict[str, Dict[UserRole, Set[Permission]]]:
        """Initialize tool permissions matrix."""
        return {
            # Infrastructure tools - high privilege required
            "execute_command": {
                UserRole.ADMIN: {Permission.EXECUTE, Permission.READ},
                UserRole.OPERATOR: {Permission.EXECUTE, Permission.READ}
            },
            "make_command": {
                UserRole.ADMIN: {Permission.EXECUTE, Permission.READ},
                UserRole.OPERATOR: {Permission.EXECUTE, Permission.READ}
            },
            "write_file": {
                UserRole.ADMIN: {Permission.WRITE, Permission.READ},
                UserRole.OPERATOR: {Permission.WRITE, Permission.READ}
            },
            
            # Docker tools
            "docker_build": {
                UserRole.ADMIN: {Permission.EXECUTE, Permission.READ},
                UserRole.OPERATOR: {Permission.EXECUTE, Permission.READ}
            },
            "docker_run": {
                UserRole.ADMIN: {Permission.EXECUTE, Permission.READ},
                UserRole.OPERATOR: {Permission.EXECUTE, Permission.READ}
            },
            "docker_ps": {
                UserRole.ADMIN: {Permission.READ},
                UserRole.OPERATOR: {Permission.READ},
                UserRole.READONLY: {Permission.READ}
            },
            
            # Kubernetes tools
            "kubectl_apply": {
                UserRole.ADMIN: {Permission.EXECUTE, Permission.READ},
                UserRole.OPERATOR: {Permission.EXECUTE, Permission.READ}
            },
            "kubectl_get": {
                UserRole.ADMIN: {Permission.READ},
                UserRole.OPERATOR: {Permission.READ}, 
                UserRole.READONLY: {Permission.READ}
            },
            "kubectl_delete": {
                UserRole.ADMIN: {Permission.DELETE, Permission.READ}
            },
            
            # Security tools
            "npm_audit": {
                UserRole.ADMIN: {Permission.READ},
                UserRole.OPERATOR: {Permission.READ},
                UserRole.READONLY: {Permission.READ}
            },
            "python_safety_check": {
                UserRole.ADMIN: {Permission.READ},
                UserRole.OPERATOR: {Permission.READ},
                UserRole.READONLY: {Permission.READ}
            },
            
            # Communication tools
            "send_notification": {
                UserRole.ADMIN: {Permission.EXECUTE},
                UserRole.OPERATOR: {Permission.EXECUTE}
            },
            "post_message": {
                UserRole.ADMIN: {Permission.EXECUTE},
                UserRole.OPERATOR: {Permission.EXECUTE}
            },
            
            # Monitoring tools - read access for most roles
            "prometheus_query": {
                UserRole.ADMIN: {Permission.READ},
                UserRole.OPERATOR: {Permission.READ},
                UserRole.READONLY: {Permission.READ}
            },
            
            # Storage tools
            "s3_upload_file": {
                UserRole.ADMIN: {Permission.WRITE, Permission.READ},
                UserRole.OPERATOR: {Permission.WRITE, Permission.READ}
            },
            "s3_list_buckets": {
                UserRole.ADMIN: {Permission.READ},
                UserRole.OPERATOR: {Permission.READ},
                UserRole.READONLY: {Permission.READ}
            }
        }
    
    def generate_token(
        self,
        user_id: str,
        role: UserRole,
        tool_whitelist: Optional[List[str]] = None,
        custom_expiry: Optional[timedelta] = None
    ) -> str:
        """
        Generate JWT token for user authentication.
        
        Args:
            user_id: Unique user identifier (REQUIRED)
            role: User role (REQUIRED)
            tool_whitelist: Optional list of tools user can access
            custom_expiry: Custom token expiration time
            
        Returns:
            JWT token string
            
        Raises:
            ValueError: If required parameters are missing or invalid
        """
        # SECURITY FIX: Strict input validation
        if not user_id or not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("User ID is required and cannot be empty")
        if not role or not isinstance(role, UserRole):
            raise ValueError("Valid UserRole is required")
        if tool_whitelist is not None and not isinstance(tool_whitelist, list):
            raise ValueError("Tool whitelist must be a list if provided")
        if custom_expiry is not None and not isinstance(custom_expiry, timedelta):
            raise ValueError("Custom expiry must be a timedelta if provided")
        now = datetime.utcnow()
        expiry = now + (custom_expiry or self.token_expiry)
        session_id = hashlib.sha256(f"{user_id}:{now.isoformat()}:{os.urandom(16).hex()}".encode()).hexdigest()
        
        payload = {
            "user_id": user_id,
            "role": role.value,
            "session_id": session_id,
            "iat": now.timestamp(),
            "exp": expiry.timestamp(),
            "tool_whitelist": tool_whitelist
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        # Store session
        auth_context = AuthContext(
            user_id=user_id,
            role=role,
            permissions=self._get_user_permissions(role),
            session_id=session_id,
            issued_at=now,
            expires_at=expiry,
            tool_whitelist=set(tool_whitelist) if tool_whitelist else None
        )
        self.active_sessions[session_id] = auth_context
        
        self._audit_log("token_generated", user_id, {"role": role.value, "session_id": session_id})
        
        return token
    
    def _get_user_permissions(self, role: UserRole) -> Set[Permission]:
        """Get all permissions for a user role."""
        permissions = set()
        for tool_perms in self.tool_permissions.values():
            if role in tool_perms:
                permissions.update(tool_perms[role])
        return permissions
    
    async def validate_token(self, token: str) -> Optional[AuthContext]:
        """
        Validate JWT token and return authentication context.
        
        Args:
            token: JWT token to validate
            
        Returns:
            AuthContext if valid, None if invalid
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            session_id = payload.get("session_id")
            if not session_id:
                self._audit_log("token_validation_failed", "unknown", {"reason": "missing_session_id"})
                return None
            
            # Check if session is still active
            auth_context = self.active_sessions.get(session_id)
            if not auth_context:
                self._audit_log("token_validation_failed", payload.get("user_id"), {"reason": "session_not_found"})
                return None
            
            # Check expiration
            if datetime.utcnow() > auth_context.expires_at:
                await self.invalidate_session(session_id)
                self._audit_log("token_validation_failed", auth_context.user_id, {"reason": "token_expired"})
                return None
            
            return auth_context
            
        except jwt.ExpiredSignatureError:
            self._audit_log("token_validation_failed", "unknown", {"reason": "expired_signature"})
            return None
        except jwt.InvalidTokenError as e:
            self._audit_log("token_validation_failed", "unknown", {"reason": f"invalid_token: {str(e)}"})
            return None
    
    async def validate_request(self, token: str, tool_name: str, context_id: str) -> bool:
        """
        Validate request with comprehensive security checks.
        
        Args:
            token: JWT authentication token (REQUIRED)
            tool_name: Name of the tool being accessed (REQUIRED)
            context_id: Request context identifier (REQUIRED)
            
        Returns:
            True if request is authorized, False otherwise
            
        Raises:
            ValueError: If any required parameter is missing or empty
        """
        # SECURITY FIX: Strict parameter validation
        if not token or not isinstance(token, str) or not token.strip():
            raise ValueError("Authentication token is required and cannot be empty")
        if not tool_name or not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("Tool name is required and cannot be empty")
        if not context_id or not isinstance(context_id, str) or not context_id.strip():
            raise ValueError("Context ID is required and cannot be empty")
        # 1. Validate authentication token
        auth_context = await self.validate_token(token)
        if not auth_context:
            return False
        
        # 2. Check if user is locked out due to failed attempts
        if await self._is_user_locked_out(auth_context.user_id):
            self._audit_log("request_blocked", auth_context.user_id, {"reason": "user_locked_out"})
            return False
        
        # 3. Check tool authorization
        if not await self.check_tool_authorization(auth_context, tool_name):
            self._audit_log("authorization_failed", auth_context.user_id, {"tool": tool_name, "reason": "insufficient_permissions"})
            return False
        
        # 4. Check rate limiting
        if not await self._check_rate_limit(auth_context.user_id, tool_name):
            self._audit_log("rate_limit_exceeded", auth_context.user_id, {"tool": tool_name})
            return False
        
        # 5. Log successful authorization
        self._audit_log("request_authorized", auth_context.user_id, {"tool": tool_name, "context_id": context_id})
        
        return True
    
    async def check_tool_authorization(self, auth_context: AuthContext, tool_name: str) -> bool:
        """
        Check if user is authorized to access specific tool.
        
        Args:
            auth_context: User authentication context
            tool_name: Name of the tool to check
            
        Returns:
            True if authorized, False otherwise
        """
        # Check tool whitelist if specified
        if auth_context.tool_whitelist and tool_name not in auth_context.tool_whitelist:
            return False
        
        # Check tool permissions matrix
        tool_perms = self.tool_permissions.get(tool_name, {})
        user_perms = tool_perms.get(auth_context.role, set())
        
        # For now, require at least READ permission for any tool access
        return Permission.READ in user_perms or Permission.EXECUTE in user_perms
    
    async def _check_rate_limit(self, user_id: str, tool_name: str) -> bool:
        """Check rate limiting for user/tool combination."""
        key = f"{user_id}:{tool_name}"
        limit_info = self.rate_limits[key]
        now = time.time()
        
        # Reset window if needed
        if now - limit_info.window_start > self.rate_limit_config["window_seconds"]:
            limit_info.requests_count = 0
            limit_info.burst_count = 0
            limit_info.window_start = now
        
        # Check burst limit (short-term)
        if now - limit_info.last_request < 1.0:  # Less than 1 second
            limit_info.burst_count += 1
            if limit_info.burst_count > self.rate_limit_config["burst_size"]:
                return False
        else:
            limit_info.burst_count = 0
        
        # Check requests per minute limit
        if limit_info.requests_count >= self.rate_limit_config["requests_per_minute"]:
            return False
        
        # Update counters
        limit_info.requests_count += 1
        limit_info.last_request = now
        
        return True
    
    async def _is_user_locked_out(self, user_id: str) -> bool:
        """Check if user is locked out due to failed authentication attempts."""
        now = time.time()
        attempts = self.failed_attempts[user_id]
        
        # Remove old attempts outside lockout window
        self.failed_attempts[user_id] = [
            attempt for attempt in attempts
            if now - attempt < self.lockout_duration
        ]
        
        # Check if user is locked out
        return len(self.failed_attempts[user_id]) >= self.lockout_threshold
    
    async def record_failed_attempt(self, user_id: str):
        """Record failed authentication attempt."""
        self.failed_attempts[user_id].append(time.time())
        self._audit_log("authentication_failed", user_id, {"attempts": len(self.failed_attempts[user_id])})
    
    async def invalidate_session(self, session_id: str):
        """Invalidate user session."""
        if session_id in self.active_sessions:
            auth_context = self.active_sessions[session_id]
            del self.active_sessions[session_id]
            self._audit_log("session_invalidated", auth_context.user_id, {"session_id": session_id})
    
    async def invalidate_user_sessions(self, user_id: str):
        """Invalidate all sessions for a user."""
        sessions_to_remove = [
            session_id for session_id, context in self.active_sessions.items()
            if context.user_id == user_id
        ]
        
        for session_id in sessions_to_remove:
            await self.invalidate_session(session_id)
    
    def _audit_log(self, action: str, user_id: str, details: Dict[str, Any] = None):
        """Add entry to audit log."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "user_id": user_id,
            "details": details or {}
        }
        self.audit_log.append(entry)
        
        # Log to system logger as well
        logger.info(f"MCP Auth: {action}", extra={
            "user_id": user_id,
            "action": action,
            **entry["details"]
        })
        
        # Keep only last 10000 audit entries in memory
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]
    
    def get_audit_log(self, user_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log entries."""
        entries = self.audit_log
        
        if user_id:
            entries = [entry for entry in entries if entry["user_id"] == user_id]
        
        return entries[-limit:]
    
    def get_active_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Get information about active sessions."""
        return {
            session_id: {
                "user_id": context.user_id,
                "role": context.role.value,
                "issued_at": context.issued_at.isoformat(),
                "expires_at": context.expires_at.isoformat(),
                "tool_whitelist": list(context.tool_whitelist) if context.tool_whitelist else None
            }
            for session_id, context in self.active_sessions.items()
        }
    
    async def cleanup_expired_sessions(self):
        """Remove expired sessions (background task)."""
        now = datetime.utcnow()
        expired_sessions = [
            session_id for session_id, context in self.active_sessions.items()
            if now > context.expires_at
        ]
        
        for session_id in expired_sessions:
            await self.invalidate_session(session_id)
        
        return len(expired_sessions)


# Decorator for protecting MCP tool functions
def require_auth(auth_middleware: Optional[MCPAuthMiddleware] = None, required_permission: Permission = Permission.READ):
    """
    Decorator to protect MCP tool functions with authentication.
    
    Args:
        auth_middleware: Authentication middleware instance (can be None for global instance)
        required_permission: Minimum permission required
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            # Get auth middleware (global or provided)
            middleware = auth_middleware or get_auth_middleware()
            if not middleware:
                raise Exception("Authentication middleware not configured")
                
            # Extract token from kwargs or context
            token = kwargs.get("auth_token") or getattr(self, "_current_auth_token", None)
            tool_name = func.__name__
            
            # SECURITY FIX: Strict token validation
            if not token or not isinstance(token, str) or not token.strip():
                raise Exception("Valid authentication token required")
            
            # Generate unique context ID for this request
            context_id = f"{id(self)}_{func.__name__}_{hash(str(args) + str(kwargs))}"
            
            # Validate request with comprehensive checks
            try:
                if not await middleware.validate_request(token, tool_name, context_id):
                    raise Exception("Unauthorized access to tool")
            except ValueError as e:
                raise Exception(f"Authentication validation failed: {str(e)}")
            
            # Proceed with tool execution
            return await func(self, *args, **kwargs)
        
        return wrapper
    return decorator


# Singleton instance for global use
_global_auth_middleware: Optional[MCPAuthMiddleware] = None


def get_auth_middleware() -> Optional[MCPAuthMiddleware]:
    """Get global authentication middleware instance.
    
    Returns:
        MCPAuthMiddleware instance or None if not initialized
        
    Note:
        Returns None instead of auto-creating to prevent security bypasses.
        Authentication middleware must be explicitly initialized.
    """
    global _global_auth_middleware
    return _global_auth_middleware


def initialize_auth_middleware(secret_key: Optional[str] = None) -> MCPAuthMiddleware:
    """Initialize global authentication middleware.
    
    Args:
        secret_key: Optional secret key for JWT signing
        
    Returns:
        Initialized MCPAuthMiddleware instance
        
    Raises:
        RuntimeError: If middleware is already initialized
    """
    global _global_auth_middleware
    if _global_auth_middleware is not None:
        raise RuntimeError("Authentication middleware is already initialized")
    
    _global_auth_middleware = MCPAuthMiddleware(secret_key)
    return _global_auth_middleware


# Background task for session cleanup
async def session_cleanup_task(auth_middleware: MCPAuthMiddleware, interval: int = 300):
    """Background task to clean up expired sessions."""
    while True:
        try:
            cleaned = await auth_middleware.cleanup_expired_sessions()
            if cleaned > 0:
                logger.info(f"Cleaned up {cleaned} expired sessions")
        except Exception as e:
            logger.error(f"Error during session cleanup: {e}")
        
        await asyncio.sleep(interval)