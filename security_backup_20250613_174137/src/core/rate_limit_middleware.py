"""
FastAPI Rate Limiting Middleware

This module provides middleware for integrating the distributed rate limiter
with FastAPI applications.
"""

import logging
import time
from typing import Callable, Optional

from fastapi import HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from .rate_limiter import (
    DistributedRateLimiter,
    RateLimitExceeded,
    get_rate_limiter
)

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for distributed rate limiting."""
    
    def __init__(
        self,
        app,
        rate_limiter: Optional[DistributedRateLimiter] = None,
        skip_paths: Optional[list] = None,
        get_user_id: Optional[Callable[[Request], str]] = None,
        get_ip_address: Optional[Callable[[Request], str]] = None,
        enable_headers: bool = True
    ):
        """
        Initialize rate limiting middleware.
        
        Args:
            app: FastAPI application
            rate_limiter: Rate limiter instance (uses global if None)
            skip_paths: List of paths to skip rate limiting
            get_user_id: Function to extract user ID from request
            get_ip_address: Function to extract IP address from request
            enable_headers: Whether to add rate limit headers to responses
        """
        super().__init__(app)
        self.rate_limiter = rate_limiter or get_rate_limiter()
        self.skip_paths = skip_paths or ["/health", "/metrics", "/docs", "/openapi.json"]
        self.get_user_id = get_user_id or self._default_get_user_id
        self.get_ip_address = get_ip_address or self._default_get_ip_address
        self.enable_headers = enable_headers
    
    def _default_get_user_id(self, request: Request) -> Optional[str]:
        """Default user ID extraction from request."""
        # Try to get user ID from various sources
        user = getattr(request.state, 'user', None)
        if user:
            return str(getattr(user, 'id', None) or getattr(user, 'user_id', None))
        
        # Try from JWT claims
        if hasattr(request.state, 'jwt_claims'):
            claims = request.state.jwt_claims
            return claims.get('sub') or claims.get('user_id')
        
        # Try from headers
        return request.headers.get('X-User-ID')
    
    def _default_get_ip_address(self, request: Request) -> str:
        """Default IP address extraction from request."""
        # Handle proxy headers
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Get the first IP in the chain
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        # Fallback to client IP
        client = getattr(request, 'client', None)
        if client:
            return client.host
        
        return '127.0.0.1'
    
    def _should_skip_path(self, path: str) -> bool:
        """Check if path should be skipped for rate limiting."""
        return any(skip_path in path for skip_path in self.skip_paths)
    
    def _extract_endpoint(self, request: Request) -> str:
        """Extract endpoint identifier from request."""
        # Use route pattern if available
        if hasattr(request, 'url') and hasattr(request.url, 'path'):
            path = request.url.path
            method = request.method.upper()
            
            # Try to get route pattern from FastAPI
            if hasattr(request.scope, 'route'):
                route = request.scope.get('route')
                if route and hasattr(route, 'path'):
                    return f"{method}:{route.path}"
            
            # Fallback to actual path
            return f"{method}:{path}"
        
        return "unknown"
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with rate limiting."""
        start_time = time.time()
        
        # Check if we should skip this path
        path = request.url.path
        if self._should_skip_path(path):
            response = await call_next(request)
            return response
        
        # Extract request information
        endpoint = self._extract_endpoint(request)
        ip_address = self.get_ip_address(request)
        user_id = self.get_user_id(request)
        
        try:
            # Check rate limits
            results = await self.rate_limiter.check_rate_limit(
                endpoint=endpoint,
                ip_address=ip_address,
                user_id=user_id,
                raise_on_limit=False
            )
            
            # Check if any rate limit is exceeded
            exceeded_result = None
            for result in results:
                if not result.allowed:
                    exceeded_result = result
                    break
            
            if exceeded_result:
                # Rate limit exceeded
                logger.warning(
                    f"Rate limit exceeded for {endpoint} "
                    f"(IP: {ip_address}, User: {user_id}): "
                    f"{exceeded_result.scope} limit of {exceeded_result.limit} requests"
                )
                
                # Create rate limit headers
                headers = {}
                if self.enable_headers:
                    headers = await self.rate_limiter.get_rate_limit_headers(
                        endpoint, ip_address, user_id
                    )
                
                # Return 429 Too Many Requests
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Rate limit exceeded",
                        "limit": exceeded_result.limit,
                        "remaining": exceeded_result.remaining,
                        "reset_time": exceeded_result.reset_time,
                        "retry_after": exceeded_result.retry_after,
                        "scope": exceeded_result.scope,
                        "algorithm": exceeded_result.algorithm
                    },
                    headers=headers
                )
            
            # Process request
            response = await call_next(request)
            
            # Add rate limit headers to successful responses
            if self.enable_headers:
                headers = await self.rate_limiter.get_rate_limit_headers(
                    endpoint, ip_address, user_id
                )
                for key, value in headers.items():
                    response.headers[key] = value
            
            # Log request metrics
            process_time = time.time() - start_time
            logger.debug(
                f"Request processed: {endpoint} "
                f"(IP: {ip_address}, User: {user_id}) "
                f"in {process_time:.3f}s"
            )
            
            return response
            
        except HTTPException:
            # Re-raise HTTP exceptions (including our rate limit exception)
            raise
        except Exception as e:
            # Log unexpected errors but don't block requests
            logger.error(f"Rate limiting error for {endpoint}: {e}")
            
            # Continue with request processing on rate limiter errors
            response = await call_next(request)
            return response


class RateLimitDependency:
    """FastAPI dependency for rate limiting specific endpoints."""
    
    def __init__(
        self,
        rate_limiter: Optional[DistributedRateLimiter] = None,
        get_user_id: Optional[Callable[[Request], str]] = None,
        get_ip_address: Optional[Callable[[Request], str]] = None
    ):
        self.rate_limiter = rate_limiter or get_rate_limiter()
        self.get_user_id = get_user_id or self._default_get_user_id
        self.get_ip_address = get_ip_address or self._default_get_ip_address
    
    def _default_get_user_id(self, request: Request) -> Optional[str]:
        """Default user ID extraction from request."""
        user = getattr(request.state, 'user', None)
        if user:
            return str(getattr(user, 'id', None) or getattr(user, 'user_id', None))
        return request.headers.get('X-User-ID')
    
    def _default_get_ip_address(self, request: Request) -> str:
        """Default IP address extraction from request."""
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        client = getattr(request, 'client', None)
        if client:
            return client.host
        
        return '127.0.0.1'
    
    async def __call__(self, request: Request) -> None:
        """Check rate limit for the current request."""
        # Extract endpoint from route
        endpoint = "unknown"
        if hasattr(request.scope, 'route'):
            route = request.scope.get('route')
            if route and hasattr(route, 'path'):
                method = request.method.upper()
                endpoint = f"{method}:{route.path}"
        
        # Extract request information
        ip_address = self.get_ip_address(request)
        user_id = self.get_user_id(request)
        
        try:
            # Check rate limits
            await self.rate_limiter.check_rate_limit(
                endpoint=endpoint,
                ip_address=ip_address,
                user_id=user_id,
                raise_on_limit=True
            )
        except RateLimitExceeded as e:
            # Convert to HTTP exception
            headers = await self.rate_limiter.get_rate_limit_headers(
                endpoint, ip_address, user_id
            )
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Rate limit exceeded",
                    "limit": e.result.limit,
                    "remaining": e.result.remaining,
                    "reset_time": e.result.reset_time,
                    "retry_after": e.result.retry_after,
                    "scope": e.result.scope,
                    "algorithm": e.result.algorithm
                },
                headers=headers
            )


# Helper functions for creating rate limit dependencies
def rate_limit_dependency(
    rate_limiter: Optional[DistributedRateLimiter] = None
) -> RateLimitDependency:
    """Create a rate limit dependency for FastAPI endpoints."""
    return RateLimitDependency(rate_limiter=rate_limiter)