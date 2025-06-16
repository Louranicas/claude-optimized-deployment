"""
Rate Limiting API Endpoints

FastAPI endpoints for managing and monitoring rate limiting.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from fastapi import APIRouter, HTTPException, Depends, Request, status
from pydantic import BaseModel, Field

from ..auth.api import get_current_user, require_permission
from ..auth.models import User
from ..core.rate_limiter import (
    DistributedRateLimiter,
    RateLimitAlgorithm,
    RateLimitConfig,
    RateLimitScope,
    get_rate_limiter
)
from ..core.rate_limit_config import (
    get_rate_limiting_config,
    UserTierConfig,
    EndpointRateLimitConfig
)
from ..core.rate_limit_monitoring import RateLimitMonitor

logger = logging.getLogger(__name__)

# Request/Response models
class RateLimitConfigRequest(BaseModel):
    """Request model for rate limit configuration."""
    requests: int = Field(..., ge=1, le=100000)
    window: int = Field(..., ge=1, le=86400)  # Max 24 hours
    algorithm: RateLimitAlgorithm
    scope: RateLimitScope
    burst: Optional[int] = Field(None, ge=1, le=100000)


class EndpointConfigRequest(BaseModel):
    """Request model for endpoint rate limit configuration."""
    endpoint_pattern: str = Field(..., min_length=1)
    description: str = ""
    configs: List[RateLimitConfigRequest]


class RateLimitStatusResponse(BaseModel):
    """Response model for rate limit status."""
    allowed: bool
    remaining: int
    reset_time: float
    limit: int
    scope: str
    algorithm: str
    retry_after: Optional[int] = None


class RateLimitMetricsResponse(BaseModel):
    """Response model for rate limiting metrics."""
    total_requests: int
    allowed_requests: int
    denied_requests: int
    denial_rate: float
    top_denied_endpoints: List[Dict[str, Any]]
    top_denied_ips: List[Dict[str, Any]]
    algorithm_usage: Dict[str, int]
    scope_usage: Dict[str, int]


class ResetRateLimitRequest(BaseModel):
    """Request model for rate limit reset."""
    endpoint: str
    ip_address: Optional[str] = None
    user_id: Optional[str] = None
    scope: Optional[RateLimitScope] = None


# Router
rate_limit_router = APIRouter(prefix="/rate-limits", tags=["Rate Limiting"])


@rate_limit_router.get("/status")
async def check_rate_limit_status(
    endpoint: str,
    request: Request,
    current_user: User = Depends(get_current_user)
) -> List[RateLimitStatusResponse]:
    """Check rate limit status for an endpoint."""
    rate_limiter = get_rate_limiter()
    
    # Extract IP address
    ip_address = request.client.host if request.client else None
    
    try:
        results = await rate_limiter.check_rate_limit(
            endpoint=endpoint,
            ip_address=ip_address,
            user_id=current_user.id
        )
        
        return [
            RateLimitStatusResponse(
                allowed=result.allowed,
                remaining=result.remaining,
                reset_time=result.reset_time,
                limit=result.limit,
                scope=result.scope,
                algorithm=result.algorithm,
                retry_after=result.retry_after
            )
            for result in results
        ]
        
    except Exception as e:
        logger.error(f"Failed to check rate limit status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check rate limit status"
        )


@rate_limit_router.get("/metrics")
async def get_rate_limit_metrics(
    hours: int = 1,
    current_user: User = Depends(require_permission("monitoring", "read"))
) -> RateLimitMetricsResponse:
    """Get rate limiting metrics for the specified time period."""
    rate_limiter = get_rate_limiter()
    
    try:
        # Get monitor instance (this would be initialized elsewhere in production)
        monitor = RateLimitMonitor(rate_limiter.redis)
        
        end_time = datetime.utcnow().timestamp()
        start_time = end_time - (hours * 3600)
        
        summary = await monitor.get_metrics_summary(start_time, end_time)
        
        return RateLimitMetricsResponse(
            total_requests=summary.total_requests,
            allowed_requests=summary.allowed_requests,
            denied_requests=summary.denied_requests,
            denial_rate=summary.denial_rate,
            top_denied_endpoints=[
                {"endpoint": endpoint, "count": count}
                for endpoint, count in summary.top_denied_endpoints
            ],
            top_denied_ips=[
                {"ip": ip, "count": count}
                for ip, count in summary.top_denied_ips
            ],
            algorithm_usage=summary.algorithm_usage,
            scope_usage=summary.scope_usage
        )
        
    except Exception as e:
        logger.error(f"Failed to get rate limit metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get rate limit metrics"
        )


@rate_limit_router.get("/metrics/endpoint/{endpoint:path}")
async def get_endpoint_metrics(
    endpoint: str,
    hours: int = 24,
    current_user: User = Depends(require_permission("monitoring", "read"))
) -> Dict[str, Any]:
    """Get detailed metrics for a specific endpoint."""
    rate_limiter = get_rate_limiter()
    
    try:
        monitor = RateLimitMonitor(rate_limiter.redis)
        metrics = await monitor.get_endpoint_metrics(endpoint, hours)
        return metrics
        
    except Exception as e:
        logger.error(f"Failed to get endpoint metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get endpoint metrics"
        )


@rate_limit_router.get("/metrics/real-time")
async def get_real_time_metrics(
    current_user: User = Depends(require_permission("monitoring", "read"))
) -> Dict[str, Any]:
    """Get real-time rate limiting statistics."""
    rate_limiter = get_rate_limiter()
    
    try:
        monitor = RateLimitMonitor(rate_limiter.redis)
        stats = await monitor.get_real_time_stats()
        return stats
        
    except Exception as e:
        logger.error(f"Failed to get real-time metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get real-time metrics"
        )


@rate_limit_router.get("/config")
async def get_rate_limit_config(
    current_user: User = Depends(require_permission("rate_limits", "read"))
) -> Dict[str, Any]:
    """Get current rate limiting configuration."""
    try:
        config = get_rate_limiting_config()
        rate_limiter = get_rate_limiter()
        
        metrics = await rate_limiter.get_metrics()
        
        return {
            "endpoint_configs": config.get_endpoint_configs(),
            "redis_url": config.redis_url,
            "redis_pool_size": config.redis_pool_size,
            "default_enabled": config.default_enabled,
            "metrics": metrics
        }
        
    except Exception as e:
        logger.error(f"Failed to get rate limit config: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get rate limit configuration"
        )


@rate_limit_router.post("/config/endpoint")
async def configure_endpoint_rate_limit(
    config_request: EndpointConfigRequest,
    current_user: User = Depends(require_permission("rate_limits", "write"))
) -> Dict[str, str]:
    """Configure rate limiting for a specific endpoint."""
    try:
        rate_limiter = get_rate_limiter()
        
        # Convert request to rate limit configs
        configs = []
        for req_config in config_request.configs:
            config = RateLimitConfig(
                requests=req_config.requests,
                window=req_config.window,
                algorithm=req_config.algorithm,
                scope=req_config.scope,
                burst=req_config.burst
            )
            configs.append(config)
        
        # Apply configuration
        rate_limiter.configure_endpoint(config_request.endpoint_pattern, configs)
        
        logger.info(
            f"User {current_user.id} configured rate limiting for endpoint "
            f"{config_request.endpoint_pattern} with {len(configs)} rules"
        )
        
        return {
            "message": f"Rate limiting configured for endpoint {config_request.endpoint_pattern}",
            "endpoint": config_request.endpoint_pattern,
            "rules_count": len(configs)
        }
        
    except Exception as e:
        logger.error(f"Failed to configure endpoint rate limit: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to configure endpoint rate limit"
        )


@rate_limit_router.post("/reset")
async def reset_rate_limit(
    reset_request: ResetRateLimitRequest,
    current_user: User = Depends(require_permission("rate_limits", "admin"))
) -> Dict[str, str]:
    """Reset rate limits for specific endpoint/user/IP."""
    try:
        rate_limiter = get_rate_limiter()
        
        await rate_limiter.reset_rate_limit(
            endpoint=reset_request.endpoint,
            ip_address=reset_request.ip_address,
            user_id=reset_request.user_id,
            scope=reset_request.scope
        )
        
        logger.info(
            f"User {current_user.id} reset rate limits for endpoint "
            f"{reset_request.endpoint} (IP: {reset_request.ip_address}, "
            f"User: {reset_request.user_id}, Scope: {reset_request.scope})"
        )
        
        return {
            "message": "Rate limits reset successfully",
            "endpoint": reset_request.endpoint
        }
        
    except Exception as e:
        logger.error(f"Failed to reset rate limit: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset rate limit"
        )


@rate_limit_router.get("/presets")
async def get_rate_limit_presets(
    current_user: User = Depends(require_permission("rate_limits", "read"))
) -> Dict[str, Any]:
    """Get predefined rate limiting presets for different user tiers."""
    try:
        return {
            "user_tiers": {
                "free": [
                    {
                        "requests": config.requests,
                        "window": config.window,
                        "algorithm": config.algorithm.value,
                        "scope": config.scope.value,
                        "burst": config.burst
                    }
                    for config in UserTierConfig.free_tier()
                ],
                "premium": [
                    {
                        "requests": config.requests,
                        "window": config.window,
                        "algorithm": config.algorithm.value,
                        "scope": config.scope.value,
                        "burst": config.burst
                    }
                    for config in UserTierConfig.premium_tier()
                ],
                "enterprise": [
                    {
                        "requests": config.requests,
                        "window": config.window,
                        "algorithm": config.algorithm.value,
                        "scope": config.scope.value,
                        "burst": config.burst
                    }
                    for config in UserTierConfig.enterprise_tier()
                ]
            },
            "algorithms": [alg.value for alg in RateLimitAlgorithm],
            "scopes": [scope.value for scope in RateLimitScope]
        }
        
    except Exception as e:
        logger.error(f"Failed to get rate limit presets: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get rate limit presets"
        )


@rate_limit_router.post("/test")
async def test_rate_limit(
    endpoint: str,
    request: Request,
    requests_count: int = Field(10, ge=1, le=100),
    current_user: User = Depends(require_permission("rate_limits", "admin"))
) -> Dict[str, Any]:
    """Test rate limiting by making multiple requests."""
    rate_limiter = get_rate_limiter()
    ip_address = request.client.host if request.client else None
    
    try:
        results = []
        for i in range(requests_count):
            result = await rate_limiter.check_rate_limit(
                endpoint=f"TEST:{endpoint}",
                ip_address=ip_address,
                user_id=current_user.id
            )
            
            results.append({
                "request_number": i + 1,
                "allowed": all(r.allowed for r in result),
                "results": [
                    {
                        "scope": r.scope,
                        "algorithm": r.algorithm,
                        "allowed": r.allowed,
                        "remaining": r.remaining,
                        "retry_after": r.retry_after
                    }
                    for r in result
                ]
            })
            
            # Stop if rate limited
            if not all(r.allowed for r in result):
                break
        
        return {
            "endpoint": endpoint,
            "total_requests": len(results),
            "successful_requests": sum(1 for r in results if r["allowed"]),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Failed to test rate limit: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to test rate limit"
        )


@rate_limit_router.get("/health")
async def rate_limit_health_check() -> Dict[str, Any]:
    """Health check for rate limiting system."""
    try:
        rate_limiter = get_rate_limiter()
        
        # Test Redis connection
        if rate_limiter.redis:
            await rate_limiter.redis.ping()
            redis_status = "healthy"
        else:
            redis_status = "not_initialized"
        
        # Get basic metrics
        metrics = await rate_limiter.get_metrics()
        
        return {
            "status": "healthy" if redis_status == "healthy" else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "redis_status": redis_status,
            "configured_endpoints": len(rate_limiter.endpoint_configs),
            "global_metrics": metrics.get("global_metrics", {}),
            "redis_info": metrics.get("redis_info", {})
        }
        
    except Exception as e:
        logger.error(f"Rate limit health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }