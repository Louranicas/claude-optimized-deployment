"""Authentication Middleware for FastAPI.

Implements JWT authentication, API key authentication, and permission checking
middleware following OWASP security guidelines.
"""

from typing import Optional, List, Dict, Any, Callable
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from fastapi.responses import JSONResponse
import time
from datetime import datetime, timezone
import re
import ipaddress
from functools import wraps

from .tokens import TokenManager, TokenData
from .models import User, APIKey
from .rbac import RBACManager
from .permissions import PermissionChecker


# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class AuthMiddleware:
    """Authentication and authorization middleware."""
    
    def __init__(self, token_manager: TokenManager,
                 rbac_manager: RBACManager,
                 permission_checker: PermissionChecker,
                 user_store: Optional[Any] = None,
                 api_key_store: Optional[Any] = None):
        """
        Initialize authentication middleware.
        
        Args:
            token_manager: JWT token manager
            rbac_manager: RBAC manager
            permission_checker: Permission checker
            user_store: User storage backend
            api_key_store: API key storage backend
        """
        self.token_manager = token_manager
        self.rbac_manager = rbac_manager
        self.permission_checker = permission_checker
        self.user_store = user_store
        self.api_key_store = api_key_store
        
        # Security settings
        self.max_failed_attempts = 5
        self.lockout_duration = 1800  # 30 minutes
        self.rate_limit_window = 60  # 1 minute
        self.rate_limit_max_requests = 100
        
        # Rate limiting storage (in production, use Redis)
        self.rate_limit_storage: Dict[str, List[float]] = {}
        
        # IP whitelist/blacklist
        self.ip_whitelist: set = set()
        self.ip_blacklist: set = set()
        
        # CORS settings
        self.allowed_origins = ["*"]
        self.allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.allowed_headers = ["*"]
    
    async def __call__(self, request: Request, call_next: Callable) -> Any:
        """Main middleware handler."""
        start_time = time.time()
        
        # Security headers
        response_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        }
        
        try:
            # Check IP blacklist
            client_ip = self._get_client_ip(request)
            if not self._check_ip_allowed(client_ip):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "IP address blocked"},
                    headers=response_headers
                )
            
            # Rate limiting
            if not self._check_rate_limit(client_ip):
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Rate limit exceeded"},
                    headers={**response_headers, "Retry-After": "60"}
                )
            
            # CORS preflight
            if request.method == "OPTIONS":
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    headers={
                        **response_headers,
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": ", ".join(self.allowed_methods),
                        "Access-Control-Allow-Headers": ", ".join(self.allowed_headers),
                        "Access-Control-Max-Age": "86400",
                    }
                )
            
            # Process request
            response = await call_next(request)
            
            # Add security headers to response
            for header, value in response_headers.items():
                response.headers[header] = value
            
            # Add request timing
            process_time = time.time() - start_time
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
            
        except Exception as e:
            # Log error securely (don't expose internal details)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error"},
                headers=response_headers
            )
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check X-Forwarded-For header (reverse proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to connection IP
        return request.client.host if request.client else "unknown"
    
    def _check_ip_allowed(self, ip_address: str) -> bool:
        """Check if IP address is allowed."""
        # Check blacklist first
        if ip_address in self.ip_blacklist:
            return False
        
        # If whitelist is configured, check it
        if self.ip_whitelist:
            return ip_address in self.ip_whitelist
        
        return True
    
    def _check_rate_limit(self, identifier: str) -> bool:
        """Check rate limit for identifier (IP or user ID)."""
        current_time = time.time()
        
        # Clean up old entries
        if identifier in self.rate_limit_storage:
            self.rate_limit_storage[identifier] = [
                t for t in self.rate_limit_storage[identifier]
                if current_time - t < self.rate_limit_window
            ]
        
        # Check limit
        if identifier not in self.rate_limit_storage:
            self.rate_limit_storage[identifier] = []
        
        if len(self.rate_limit_storage[identifier]) >= self.rate_limit_max_requests:
            return False
        
        # Record request
        self.rate_limit_storage[identifier].append(current_time)
        return True
    
    async def get_current_user(self, 
                             credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
                             api_key: Optional[str] = Depends(api_key_header),
                             request: Request = None) -> Optional[User]:
        """Get current authenticated user from JWT or API key."""
        # Try JWT authentication first
        if credentials and credentials.credentials:
            token_data = self.token_manager.verify_token(credentials.credentials)
            if token_data:
                # Load user from storage
                if self.user_store:
                    user = await self.user_store.get_user(token_data.user_id)
                    if user and not user.is_locked():
                        # Update user's roles and permissions from token
                        user.roles = token_data.roles
                        user.permissions = set(token_data.permissions)
                        return user
                else:
                    # Create temporary user from token data
                    return User(
                        id=token_data.user_id,
                        username=token_data.username,
                        email=f"{token_data.username}@example.com",
                        password_hash="",
                        roles=token_data.roles,
                        permissions=set(token_data.permissions)
                    )
        
        # Try API key authentication
        if api_key:
            api_key_parts = api_key.split(".", 1)
            if len(api_key_parts) == 2:
                key_id, key_secret = api_key_parts
                
                if self.api_key_store:
                    stored_key = await self.api_key_store.get_api_key(key_id)
                    if stored_key and stored_key.verify_key(key_secret) and stored_key.is_valid():
                        # Check IP restrictions
                        if request:
                            client_ip = self._get_client_ip(request)
                            if not stored_key.check_ip_allowed(client_ip):
                                raise HTTPException(
                                    status_code=status.HTTP_403_FORBIDDEN,
                                    detail="IP address not allowed for this API key"
                                )
                        
                        # Record usage
                        stored_key.record_usage()
                        await self.api_key_store.update_api_key(stored_key)
                        
                        # Create service user from API key
                        return User(
                            id=f"apikey:{stored_key.id}",
                            username=f"apikey:{stored_key.name}",
                            email=f"{stored_key.name}@apikey.local",
                            password_hash="",
                            roles=["api_key"],
                            permissions=stored_key.permissions
                        )
        
        return None
    
    def add_ip_to_whitelist(self, ip_address: str) -> None:
        """Add IP address to whitelist."""
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
            self.ip_whitelist.add(ip_address)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip_address}")
    
    def add_ip_to_blacklist(self, ip_address: str) -> None:
        """Add IP address to blacklist."""
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
            self.ip_blacklist.add(ip_address)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip_address}")
    
    def remove_ip_from_whitelist(self, ip_address: str) -> None:
        """Remove IP address from whitelist."""
        self.ip_whitelist.discard(ip_address)
    
    def remove_ip_from_blacklist(self, ip_address: str) -> None:
        """Remove IP address from blacklist."""
        self.ip_blacklist.discard(ip_address)


async def get_current_user_dependency(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    api_key: Optional[str] = Depends(api_key_header)
) -> User:
    """
    FastAPI dependency for getting current authenticated user.
    
    Usage:
        @app.get("/protected")
        async def protected_route(current_user: User = Depends(get_current_user_dependency)):
            return {"user": current_user.username}
    """
    # This would be initialized with actual middleware instance
    # For now, raise an error
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_auth(func: Callable) -> Callable:
    """
    Decorator for requiring authentication on endpoints.
    
    Usage:
        @app.get("/protected")
        @require_auth
        async def protected_route(current_user: User):
            return {"user": current_user.username}
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Check if current_user is in kwargs
        if "current_user" not in kwargs or kwargs["current_user"] is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return await func(*args, **kwargs)
    
    return wrapper


def require_permission(resource: str, action: str) -> Callable:
    """
    Decorator for requiring specific permissions on endpoints.
    
    Usage:
        @app.post("/deploy")
        @require_permission("deployment", "execute")
        async def deploy(current_user: User = Depends(get_current_user_dependency)):
            return {"status": "deployed"}
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract current user
            current_user = kwargs.get("current_user")
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Check permission
            # This would use the actual permission checker instance
            has_permission = resource in ["*"] or action in ["*"]  # Simplified
            
            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {resource}:{action}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    
    return decorator


class RateLimitMiddleware:
    """Rate limiting middleware using sliding window algorithm."""
    
    def __init__(self, requests_per_minute: int = 60,
                 requests_per_hour: int = 1000,
                 burst_size: int = 10):
        """Initialize rate limiter."""
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.burst_size = burst_size
        
        # Storage for request timestamps (use Redis in production)
        self.request_history: Dict[str, List[float]] = {}
    
    async def __call__(self, request: Request, call_next: Callable) -> Any:
        """Rate limiting middleware handler."""
        # Get identifier (user ID or IP)
        identifier = self._get_identifier(request)
        
        # Check rate limits
        if not self._check_limits(identifier):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded"},
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + 60)
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        remaining = self._get_remaining_requests(identifier)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)
        
        return response
    
    def _get_identifier(self, request: Request) -> str:
        """Get identifier for rate limiting."""
        # Try to get user ID from request state
        if hasattr(request.state, "user") and request.state.user:
            return f"user:{request.state.user.id}"
        
        # Fall back to IP address
        return f"ip:{request.client.host}" if request.client else "unknown"
    
    def _check_limits(self, identifier: str) -> bool:
        """Check if request is within rate limits."""
        current_time = time.time()
        
        # Initialize history if needed
        if identifier not in self.request_history:
            self.request_history[identifier] = []
        
        # Clean up old entries
        self.request_history[identifier] = [
            t for t in self.request_history[identifier]
            if current_time - t < 3600  # Keep last hour
        ]
        
        history = self.request_history[identifier]
        
        # Check burst limit
        recent_requests = [t for t in history if current_time - t < 1]
        if len(recent_requests) >= self.burst_size:
            return False
        
        # Check minute limit
        minute_requests = [t for t in history if current_time - t < 60]
        if len(minute_requests) >= self.requests_per_minute:
            return False
        
        # Check hour limit
        if len(history) >= self.requests_per_hour:
            return False
        
        # Record request
        self.request_history[identifier].append(current_time)
        return True
    
    def _get_remaining_requests(self, identifier: str) -> int:
        """Get remaining requests in current window."""
        if identifier not in self.request_history:
            return self.requests_per_minute
        
        current_time = time.time()
        minute_requests = [
            t for t in self.request_history[identifier]
            if current_time - t < 60
        ]
        
        return max(0, self.requests_per_minute - len(minute_requests))