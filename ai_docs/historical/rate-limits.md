# Rate Limiting Documentation

The Claude-Optimized Deployment Engine implements comprehensive rate limiting to ensure fair usage, maintain system stability, and protect against abuse. This document explains rate limiting policies, headers, and best practices for handling limits.

## Table of Contents

1. [Overview](#overview)
2. [Rate Limit Policies](#rate-limit-policies)
3. [Rate Limit Headers](#rate-limit-headers)
4. [HTTP Status Codes](#http-status-codes)
5. [Handling Rate Limits](#handling-rate-limits)
6. [Best Practices](#best-practices)
7. [Monitoring Usage](#monitoring-usage)
8. [Enterprise Options](#enterprise-options)

## Overview

Rate limiting helps maintain API performance and availability by controlling the number of requests clients can make within specific time windows. CODE uses multiple rate limiting strategies:

- **Request-based limiting**: Maximum requests per time period
- **Resource-based limiting**: Limits based on computational cost
- **Concurrent connection limiting**: Maximum simultaneous connections
- **Burst allowances**: Temporary allowances for traffic spikes

### Key Features

- **Sliding window algorithm**: Smooth rate limiting without sharp cutoffs
- **Per-endpoint granularity**: Different limits for different operations
- **User and API key based**: Separate limits per authentication method
- **Intelligent backoff**: Automatic retry-after suggestions
- **Grace periods**: Temporary allowances for legitimate traffic spikes

## Rate Limit Policies

### Default Limits

| Category | Endpoint Pattern | Requests per Minute | Burst Allowance | Notes |
|----------|------------------|-------------------|-----------------|-------|
| **Authentication** | `/auth/*` | 10 | 20 | Login, token refresh |
| **Health Checks** | `/health`, `/api/*/health` | 60 | 120 | System status |
| **Circuit Breakers** | `/api/circuit-breakers/*` | 100 | 200 | Monitoring endpoints |
| **MCP Tools (Read)** | `GET /api/mcp/*` | 100 | 200 | Server and tool listing |
| **MCP Tools (Execute)** | `POST /api/mcp/execute` | 30 | 60 | Tool execution |
| **Expert Consultation** | `/api/experts/consult` | 10 | 20 | AI expert queries |
| **Deployments (Read)** | `GET /api/deployments/*` | 200 | 400 | Status and logs |
| **Deployments (Write)** | `POST /api/deployments` | 20 | 40 | Create deployments |
| **Security Scans** | `/api/security/scan` | 15 | 30 | Security scanning |
| **Monitoring** | `/api/monitoring/*` | 150 | 300 | Metrics and alerts |
| **Webhooks** | `/api/webhooks*` | 50 | 100 | Webhook management |

### Resource-Intensive Operations

Some operations have additional constraints based on computational cost:

| Operation | Additional Limits | Reason |
|-----------|------------------|--------|
| **Docker Builds** | 5 concurrent, 10/hour | CPU and I/O intensive |
| **Kubernetes Deployments** | 3 concurrent, 20/hour | Network and cluster impact |
| **Security Scans** | 2 concurrent, 15/hour | Scan engine limitations |
| **Expert Consultations** | 1 concurrent, 10/hour | AI model costs |
| **Large File Operations** | 1 concurrent, 5/hour | Storage and bandwidth |

### Authentication-Based Limits

Different authentication methods have different limits:

#### API Key Authentication

```
Standard Plan:
- 1,000 requests/hour
- 50 concurrent operations
- 5 MCP tool executions/minute

Professional Plan:
- 5,000 requests/hour  
- 100 concurrent operations
- 20 MCP tool executions/minute

Enterprise Plan:
- 20,000 requests/hour
- 500 concurrent operations  
- 100 MCP tool executions/minute
```

#### JWT Token Authentication

```
User Tokens:
- 500 requests/hour
- 20 concurrent operations
- 10 MCP tool executions/minute

Service Tokens:
- 2,000 requests/hour
- 100 concurrent operations
- 30 MCP tool executions/minute
```

## Rate Limit Headers

CODE includes rate limiting information in response headers to help clients understand their usage and limits.

### Standard Headers

Every API response includes these headers:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 85
X-RateLimit-Reset: 1672531200
X-RateLimit-Window: 60
X-RateLimit-Policy: sliding
```

### Header Descriptions

| Header | Description | Example |
|--------|-------------|---------|
| `X-RateLimit-Limit` | Maximum requests in current window | `100` |
| `X-RateLimit-Remaining` | Requests remaining in current window | `85` |
| `X-RateLimit-Reset` | Unix timestamp when window resets | `1672531200` |
| `X-RateLimit-Window` | Window duration in seconds | `60` |
| `X-RateLimit-Policy` | Rate limiting algorithm used | `sliding` |

### Additional Headers

For specific operations, additional headers may be included:

```http
X-RateLimit-Resource: mcp-execution
X-RateLimit-Resource-Limit: 30
X-RateLimit-Resource-Remaining: 12
X-RateLimit-Burst-Limit: 60
X-RateLimit-Burst-Remaining: 45
```

| Header | Description |
|--------|-------------|
| `X-RateLimit-Resource` | Specific resource being limited |
| `X-RateLimit-Resource-Limit` | Resource-specific limit |
| `X-RateLimit-Resource-Remaining` | Resource-specific remaining |
| `X-RateLimit-Burst-Limit` | Maximum burst allowance |
| `X-RateLimit-Burst-Remaining` | Burst allowance remaining |

## HTTP Status Codes

### 429 Too Many Requests

When rate limits are exceeded, the API returns HTTP 429:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1672531200
Retry-After: 30

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded for MCP tool execution",
    "details": {
      "limit": 30,
      "window": "1 minute",
      "retry_after": 30,
      "reset_time": "2025-05-31T10:20:00.000Z"
    },
    "timestamp": "2025-05-31T10:19:30.000Z",
    "request_id": "req-123456789"
  }
}
```

### 503 Service Unavailable

When system-wide limits are reached:

```http
HTTP/1.1 503 Service Unavailable
Content-Type: application/json
Retry-After: 120

{
  "error": {
    "code": "SERVICE_OVERLOADED",
    "message": "System is temporarily overloaded",
    "details": {
      "reason": "High concurrent MCP operations",
      "retry_after": 120,
      "status_url": "/api/system/status"
    },
    "timestamp": "2025-05-31T10:19:30.000Z",
    "request_id": "req-123456789"
  }
}
```

## Handling Rate Limits

### Exponential Backoff

Implement exponential backoff for robust rate limit handling:

#### Python Example

```python
import asyncio
import aiohttp
import time
from typing import Optional

class RateLimitHandler:
    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.current_delay = base_delay
    
    async def make_request_with_retry(
        self, 
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        max_retries: int = 3,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """Make HTTP request with automatic rate limit handling."""
        
        for attempt in range(max_retries + 1):
            try:
                async with session.request(method, url, **kwargs) as response:
                    # Check rate limit headers
                    remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    
                    if response.status == 200:
                        # Success - reset backoff
                        self.current_delay = self.base_delay
                        return response
                    
                    elif response.status == 429:
                        # Rate limit exceeded
                        retry_after = int(response.headers.get('Retry-After', self.current_delay))
                        
                        if attempt < max_retries:
                            print(f"Rate limited. Waiting {retry_after} seconds...")
                            await asyncio.sleep(retry_after)
                            self.current_delay = min(self.current_delay * 2, self.max_delay)
                            continue
                        else:
                            raise aiohttp.ClientResponseError(
                                request_info=response.request_info,
                                history=response.history,
                                status=response.status,
                                message="Rate limit exceeded after max retries"
                            )
                    
                    elif response.status == 503:
                        # Service overloaded
                        retry_after = int(response.headers.get('Retry-After', 60))
                        
                        if attempt < max_retries:
                            print(f"Service overloaded. Waiting {retry_after} seconds...")
                            await asyncio.sleep(retry_after)
                            continue
                        else:
                            raise aiohttp.ClientResponseError(
                                request_info=response.request_info,
                                history=response.history,
                                status=response.status,
                                message="Service overloaded after max retries"
                            )
                    
                    else:
                        # Other error
                        response.raise_for_status()
            
            except aiohttp.ClientError as e:
                if attempt < max_retries:
                    await asyncio.sleep(self.current_delay)
                    self.current_delay = min(self.current_delay * 2, self.max_delay)
                    continue
                else:
                    raise

# Usage example
async def main():
    handler = RateLimitHandler()
    
    async with aiohttp.ClientSession() as session:
        response = await handler.make_request_with_retry(
            session, 
            'POST', 
            'http://localhost:8000/api/mcp/execute',
            headers={'X-API-Key': 'your-api-key'},
            json={
                'server': 'docker',
                'tool': 'docker_ps',
                'arguments': {}
            }
        )
        result = await response.json()
        print(result)
```

#### JavaScript Example

```javascript
class RateLimitHandler {
    constructor(baseDelay = 1000, maxDelay = 60000) {
        this.baseDelay = baseDelay;
        this.maxDelay = maxDelay;
        this.currentDelay = baseDelay;
    }

    async makeRequestWithRetry(url, options = {}, maxRetries = 3) {
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                const response = await fetch(url, options);
                
                // Check rate limit headers
                const remaining = parseInt(response.headers.get('X-RateLimit-Remaining') || '0');
                const resetTime = parseInt(response.headers.get('X-RateLimit-Reset') || '0');
                
                if (response.ok) {
                    // Success - reset backoff
                    this.currentDelay = this.baseDelay;
                    return response;
                }
                
                if (response.status === 429) {
                    // Rate limit exceeded
                    const retryAfter = parseInt(response.headers.get('Retry-After') || this.currentDelay / 1000);
                    
                    if (attempt < maxRetries) {
                        console.log(`Rate limited. Waiting ${retryAfter} seconds...`);
                        await this.sleep(retryAfter * 1000);
                        this.currentDelay = Math.min(this.currentDelay * 2, this.maxDelay);
                        continue;
                    } else {
                        throw new Error('Rate limit exceeded after max retries');
                    }
                }
                
                if (response.status === 503) {
                    // Service overloaded
                    const retryAfter = parseInt(response.headers.get('Retry-After') || '60');
                    
                    if (attempt < maxRetries) {
                        console.log(`Service overloaded. Waiting ${retryAfter} seconds...`);
                        await this.sleep(retryAfter * 1000);
                        continue;
                    } else {
                        throw new Error('Service overloaded after max retries');
                    }
                }
                
                // Other error
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                
            } catch (error) {
                if (attempt < maxRetries && error.name !== 'TypeError') {
                    await this.sleep(this.currentDelay);
                    this.currentDelay = Math.min(this.currentDelay * 2, this.maxDelay);
                    continue;
                } else {
                    throw error;
                }
            }
        }
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Usage example
async function executeMCPTool() {
    const handler = new RateLimitHandler();
    
    try {
        const response = await handler.makeRequestWithRetry(
            'http://localhost:8000/api/mcp/execute',
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': 'your-api-key'
                },
                body: JSON.stringify({
                    server: 'docker',
                    tool: 'docker_ps',
                    arguments: {}
                })
            }
        );
        
        const result = await response.json();
        console.log(result);
    } catch (error) {
        console.error('Request failed:', error);
    }
}
```

### Request Queuing

For high-volume applications, implement request queuing:

```python
import asyncio
from asyncio import Queue, Semaphore
from typing import Callable, Any

class RequestQueue:
    def __init__(self, max_concurrent: int = 10, requests_per_minute: int = 100):
        self.max_concurrent = max_concurrent
        self.requests_per_minute = requests_per_minute
        self.semaphore = Semaphore(max_concurrent)
        self.queue = Queue()
        self.request_times = []
        
    async def add_request(self, func: Callable, *args, **kwargs) -> Any:
        """Add request to queue and execute when rate limits allow."""
        await self.queue.put((func, args, kwargs))
        return await self._process_queue()
    
    async def _process_queue(self):
        """Process queued requests respecting rate limits."""
        async with self.semaphore:
            # Check rate limit
            now = time.time()
            self.request_times = [t for t in self.request_times if now - t < 60]
            
            if len(self.request_times) >= self.requests_per_minute:
                # Wait until we can make another request
                wait_time = 60 - (now - self.request_times[0])
                await asyncio.sleep(wait_time)
            
            # Execute request
            func, args, kwargs = await self.queue.get()
            self.request_times.append(now)
            
            try:
                return await func(*args, **kwargs)
            finally:
                self.queue.task_done()

# Usage
queue = RequestQueue(max_concurrent=5, requests_per_minute=50)

async def make_api_call(endpoint, data):
    # Your API call logic here
    pass

# Add requests to queue
result = await queue.add_request(make_api_call, '/api/mcp/execute', {'server': 'docker'})
```

## Best Practices

### 1. Monitor Rate Limit Headers

Always check rate limit headers to avoid hitting limits:

```python
def check_rate_limits(response):
    """Check rate limit headers and warn if approaching limits."""
    remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
    limit = int(response.headers.get('X-RateLimit-Limit', 0))
    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
    
    if limit > 0:
        usage_percentage = ((limit - remaining) / limit) * 100
        
        if usage_percentage > 80:
            reset_in = reset_time - time.time()
            print(f"Warning: {usage_percentage:.1f}% of rate limit used. "
                  f"Resets in {reset_in:.0f} seconds.")
```

### 2. Implement Graceful Degradation

Handle rate limits gracefully without failing operations:

```python
async def robust_mcp_execution(server, tool, arguments, fallback=None):
    """Execute MCP tool with fallback for rate limiting."""
    try:
        return await execute_mcp_tool(server, tool, arguments)
    except RateLimitError:
        if fallback:
            print(f"Rate limited, using fallback for {tool}")
            return await fallback(arguments)
        else:
            print(f"Rate limited, queuing {tool} for later")
            await queue_for_later(server, tool, arguments)
            return {"status": "queued", "message": "Rate limited, will retry later"}
```

### 3. Cache Responses

Reduce API calls by caching responses:

```python
from functools import lru_cache
import time

class CachedAPIClient:
    def __init__(self):
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    async def get_with_cache(self, endpoint, params=None):
        """Get data with caching to reduce API calls."""
        cache_key = f"{endpoint}:{hash(str(params))}"
        
        if cache_key in self.cache:
            data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return data
        
        # Cache miss or expired
        data = await self.api_call(endpoint, params)
        self.cache[cache_key] = (data, time.time())
        return data
```

### 4. Batch Operations

Combine multiple operations into single requests when possible:

```python
async def batch_mcp_operations(operations):
    """Batch multiple MCP operations to reduce API calls."""
    batch_request = {
        "operations": operations,
        "execution_mode": "parallel"
    }
    
    return await execute_mcp_batch(batch_request)

# Instead of multiple calls:
# result1 = await execute_mcp_tool("docker", "docker_ps", {})
# result2 = await execute_mcp_tool("kubernetes", "kubectl_get", {"resource": "pods"})

# Use batching:
results = await batch_mcp_operations([
    {"server": "docker", "tool": "docker_ps", "arguments": {}},
    {"server": "kubernetes", "tool": "kubectl_get", "arguments": {"resource": "pods"}}
])
```

### 5. Use Webhooks Instead of Polling

Replace frequent polling with webhook notifications:

```python
# Instead of polling deployment status:
# while True:
#     status = await get_deployment_status(deployment_id)
#     if status in ['completed', 'failed']:
#         break
#     await asyncio.sleep(10)

# Register webhook for deployment events:
await register_webhook({
    "url": "https://your-app.com/webhooks/deployments",
    "events": ["deployment.completed", "deployment.failed"]
})
```

## Monitoring Usage

### API Usage Dashboard

Monitor your API usage to optimize requests:

```python
class UsageMonitor:
    def __init__(self):
        self.request_counts = {}
        self.rate_limit_hits = 0
        self.average_response_time = 0
    
    def record_request(self, endpoint, response_time, rate_limited=False):
        """Record API request metrics."""
        if endpoint not in self.request_counts:
            self.request_counts[endpoint] = 0
        
        self.request_counts[endpoint] += 1
        
        if rate_limited:
            self.rate_limit_hits += 1
        
        # Update average response time
        self.average_response_time = (
            (self.average_response_time * (sum(self.request_counts.values()) - 1) + response_time) /
            sum(self.request_counts.values())
        )
    
    def get_usage_report(self):
        """Generate usage report."""
        total_requests = sum(self.request_counts.values())
        rate_limit_percentage = (self.rate_limit_hits / total_requests) * 100 if total_requests > 0 else 0
        
        return {
            "total_requests": total_requests,
            "requests_by_endpoint": self.request_counts,
            "rate_limit_hits": self.rate_limit_hits,
            "rate_limit_percentage": rate_limit_percentage,
            "average_response_time": self.average_response_time
        }
```

### Health Checks

Implement health checks that monitor rate limit status:

```python
async def check_api_health():
    """Check API health including rate limit status."""
    try:
        response = await make_api_request('/api/circuit-breakers/health')
        
        remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
        limit = int(response.headers.get('X-RateLimit-Limit', 0))
        
        health_status = "healthy"
        if limit > 0:
            usage_percentage = ((limit - remaining) / limit) * 100
            if usage_percentage > 90:
                health_status = "rate_limit_warning"
            elif usage_percentage > 95:
                health_status = "rate_limit_critical"
        
        return {
            "status": health_status,
            "rate_limit_usage": f"{usage_percentage:.1f}%",
            "requests_remaining": remaining
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
```

## Enterprise Options

### Custom Rate Limits

Enterprise customers can request custom rate limits:

```json
{
  "account_id": "enterprise-123",
  "custom_limits": {
    "api_requests_per_hour": 50000,
    "mcp_executions_per_minute": 200,
    "concurrent_operations": 1000,
    "expert_consultations_per_hour": 100
  },
  "burst_allowances": {
    "emergency_mode": true,
    "burst_multiplier": 2.0,
    "burst_duration": 300
  }
}
```

### Dedicated Resources

Enterprise plans include:

- **Dedicated API endpoints**: Isolated infrastructure
- **Priority processing**: Faster response times
- **Custom timeouts**: Extended limits for long-running operations
- **White-label options**: Custom branding and domains

### SLA Guarantees

Enterprise SLA includes:

- **99.9% uptime**: Guaranteed availability
- **<100ms response time**: For standard operations
- **24/7 support**: Direct access to engineering team
- **Custom monitoring**: Dedicated dashboards and alerts

To request enterprise features, contact sales@code-engine.io.

This comprehensive rate limiting documentation ensures efficient and respectful API usage while providing the tools needed to build robust, production-ready integrations with the CODE platform.