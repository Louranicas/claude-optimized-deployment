"""
Rate Limiting Configuration

Configures and activates rate limiting for MCP authentication.
"""

from typing import Dict, Any
import time

class RateLimitConfig:
    """Rate limiting configuration."""
    
    # Global rate limits
    GLOBAL_LIMITS = {
        "requests_per_minute": 100,
        "requests_per_hour": 1000,
        "burst_size": 20
    }
    
    # Per-tool rate limits
    TOOL_LIMITS = {
        "execute_command": {"per_minute": 10, "burst": 3},
        "kubectl_apply": {"per_minute": 5, "burst": 1}, 
        "terraform_plan": {"per_minute": 3, "burst": 1},
        "docker_build": {"per_minute": 5, "burst": 2},
        "run_security_scan": {"per_minute": 2, "burst": 1}
    }
    
    # IP-based rate limits
    IP_LIMITS = {
        "requests_per_minute": 60,
        "burst_size": 10
    }
    
    @classmethod
    def get_limit_for_tool(cls, tool_name: str) -> Dict[str, int]:
        """Get rate limit configuration for tool."""
        return cls.TOOL_LIMITS.get(tool_name, {
            "per_minute": 30,
            "burst": 5
        })
    
    @classmethod
    def is_rate_limited(cls, identifier: str, tool_name: str, 
                       request_history: Dict[str, list]) -> bool:
        """Check if request should be rate limited."""
        current_time = time.time()
        key = f"{identifier}:{tool_name}"
        
        # Initialize history
        if key not in request_history:
            request_history[key] = []
        
        # Clean old entries
        request_history[key] = [
            t for t in request_history[key]
            if current_time - t < 60
        ]
        
        # Get limits
        limits = cls.get_limit_for_tool(tool_name)
        per_minute = limits.get("per_minute", 30)
        burst = limits.get("burst", 5)
        
        # Check burst limit
        recent_requests = [
            t for t in request_history[key]
            if current_time - t < 1
        ]
        if len(recent_requests) >= burst:
            return True
        
        # Check per-minute limit
        if len(request_history[key]) >= per_minute:
            return True
        
        # Record request
        request_history[key].append(current_time)
        return False
