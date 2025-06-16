#!/usr/bin/env python3
"""
MCP Server with API Integration Stability and Fallback Mechanisms
Implements Tavily, Brave, and Smithery API integrations with robust fallback patterns
"""

import asyncio
import json
import logging
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
import statistics
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# API Configuration with credentials and endpoints
API_CONFIG = {
    "tavily": {
        "api_key": "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",
        "base_url": "https://api.tavily.com/search",
        "timeout": 30,
        "priority": 1,
        "enabled": True
    },
    "brave": {
        "api_key": "BSAigVAUU4-V72PjB48t8_CqN00Hh5z",
        "base_url": "https://api.search.brave.com/res/v1/web/search",
        "timeout": 25,
        "priority": 2,
        "enabled": True
    },
    "smithery": {
        "api_key": "85861ba2-5eba-4599-b38d-61f4b3df44a7",
        "base_url": "https://api.smithery.ai/v1",
        "timeout": 45,
        "priority": 3,
        "enabled": False  # Disabled due to connectivity issues
    }
}

class APIHealthStatus(Enum):
    """API health status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    RECOVERING = "recovering"
    DISABLED = "disabled"

@dataclass
class APIMetrics:
    """Comprehensive API metrics tracking"""
    api_name: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    response_times: List[float] = None
    errors: List[str] = None
    status: APIHealthStatus = APIHealthStatus.HEALTHY
    last_success: Optional[float] = None
    last_failure: Optional[float] = None
    
    def __post_init__(self):
        if self.response_times is None:
            self.response_times = []
        if self.errors is None:
            self.errors = []
    
    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100
    
    @property
    def avg_response_time(self) -> float:
        if not self.response_times:
            return 0.0
        return statistics.mean(self.response_times)
    
    @property
    def p95_response_time(self) -> float:
        if not self.response_times:
            return 0.0
        sorted_times = sorted(self.response_times)
        index = int(len(sorted_times) * 0.95)
        return sorted_times[min(index, len(sorted_times) - 1)]

class CircuitBreaker:
    """Circuit breaker implementation for API resilience"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60, 
                 half_open_max_calls: int = 3):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half-open
        self.half_open_calls = 0
        self._lock = threading.Lock()
    
    def call_allowed(self) -> bool:
        """Check if API call is allowed based on circuit breaker state"""
        with self._lock:
            if self.state == "closed":
                return True
            elif self.state == "open":
                if self.last_failure_time and \
                   (time.time() - self.last_failure_time) > self.recovery_timeout:
                    self.state = "half-open"
                    self.half_open_calls = 0
                    logger.info("Circuit breaker moved to half-open state")
                    return True
                return False
            elif self.state == "half-open":
                return self.half_open_calls < self.half_open_max_calls
            return False
    
    def record_success(self):
        """Record successful API call"""
        with self._lock:
            if self.state == "half-open":
                self.half_open_calls += 1
                if self.half_open_calls >= self.half_open_max_calls:
                    self.state = "closed"
                    self.failure_count = 0
                    logger.info("Circuit breaker closed after successful recovery")
            elif self.state == "closed":
                self.failure_count = 0
    
    def record_failure(self):
        """Record failed API call"""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.state == "half-open":
                self.state = "open"
                logger.warning("Circuit breaker opened during half-open state")
            elif self.state == "closed" and self.failure_count >= self.failure_threshold:
                self.state = "open"
                logger.warning(f"Circuit breaker opened after {self.failure_count} failures")

class APIIntegrationManager:
    """Manages API integrations with fallback and circuit breaker patterns"""
    
    def __init__(self):
        self.metrics: Dict[str, APIMetrics] = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._initialize_apis()
    
    def _initialize_apis(self):
        """Initialize API metrics and circuit breakers"""
        for api_name, config in API_CONFIG.items():
            if config["enabled"]:
                self.metrics[api_name] = APIMetrics(api_name=api_name)
                self.circuit_breakers[api_name] = CircuitBreaker()
                logger.info(f"Initialized {api_name} API with priority {config['priority']}")
            else:
                logger.info(f"Skipped {api_name} API (disabled)")
    
    def _make_http_request(self, url: str, headers: Dict[str, str], 
                          data: Optional[str] = None, timeout: int = 30) -> Dict[str, Any]:
        """Make HTTP request with comprehensive error handling"""
        start_time = time.time()
        
        try:
            request = urllib.request.Request(url, headers=headers)
            if data:
                request.data = data.encode('utf-8')
            
            with urllib.request.urlopen(request, timeout=timeout) as response:
                response_time = time.time() - start_time
                response_data = response.read().decode('utf-8')
                
                return {
                    "success": True,
                    "status_code": response.getcode(),
                    "data": json.loads(response_data) if response_data else {},
                    "response_time": response_time,
                    "error": None
                }
                
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "status_code": None,
                "data": {},
                "response_time": time.time() - start_time,
                "error": f"JSON decode error: {str(e)}"
            }
        except urllib.error.HTTPError as e:
            return {
                "success": False,
                "status_code": e.code,
                "data": {},
                "response_time": time.time() - start_time,
                "error": f"HTTP {e.code}: {str(e)}"
            }
        except urllib.error.URLError as e:
            return {
                "success": False,
                "status_code": None,
                "data": {},
                "response_time": time.time() - start_time,
                "error": f"URL Error: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "status_code": None,
                "data": {},
                "response_time": time.time() - start_time,
                "error": f"Unexpected error: {str(e)}"
            }
    
    def _call_tavily_api(self, query: str, **kwargs) -> Dict[str, Any]:
        """Call Tavily Search API"""
        api_name = "tavily"
        config = API_CONFIG[api_name]
        
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "api_key": config["api_key"],
            "query": query,
            "search_depth": kwargs.get("search_depth", "basic"),
            "include_answer": kwargs.get("include_answer", True),
            "include_images": kwargs.get("include_images", False),
            "include_raw_content": kwargs.get("include_raw_content", False),
            "max_results": kwargs.get("max_results", 10)
        }
        
        result = self._make_http_request(
            config["base_url"],
            headers,
            json.dumps(payload),
            config["timeout"]
        )
        
        if result["success"]:
            # Process Tavily response
            data = result["data"]
            return {
                "api": api_name,
                "success": True,
                "results": data.get("results", []),
                "answer": data.get("answer", ""),
                "query": data.get("query", query),
                "response_time": result["response_time"],
                "total_results": len(data.get("results", []))
            }
        else:
            return {
                "api": api_name,
                "success": False,
                "error": result["error"],
                "response_time": result["response_time"]
            }
    
    def _call_brave_api(self, query: str, **kwargs) -> Dict[str, Any]:
        """Call Brave Search API"""
        api_name = "brave"
        config = API_CONFIG[api_name]
        
        params = urllib.parse.urlencode({
            "q": query,
            "count": kwargs.get("count", 10),
            "offset": kwargs.get("offset", 0),
            "safesearch": kwargs.get("safesearch", "moderate"),
            "country": kwargs.get("country", "us")
        })
        
        url = f"{config['base_url']}?{params}"
        headers = {
            "Accept": "application/json",
            "X-Subscription-Token": config["api_key"]
        }
        
        result = self._make_http_request(url, headers, None, config["timeout"])
        
        if result["success"]:
            # Process Brave response
            data = result["data"]
            web_results = data.get("web", {}).get("results", [])
            
            return {
                "api": api_name,
                "success": True,
                "results": web_results,
                "query": data.get("query", {}).get("original", query),
                "response_time": result["response_time"],
                "total_results": len(web_results),
                "has_discussions": "discussions" in data,
                "has_news": "news" in data
            }
        else:
            return {
                "api": api_name,
                "success": False,
                "error": result["error"],
                "response_time": result["response_time"]
            }
    
    def _call_smithery_api(self, endpoint: str = "models", **kwargs) -> Dict[str, Any]:
        """Call Smithery API"""
        api_name = "smithery"
        config = API_CONFIG[api_name]
        
        url = f"{config['base_url']}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {config['api_key']}",
            "Content-Type": "application/json"
        }
        
        result = self._make_http_request(url, headers, None, config["timeout"])
        
        if result["success"]:
            return {
                "api": api_name,
                "success": True,
                "data": result["data"],
                "response_time": result["response_time"]
            }
        else:
            return {
                "api": api_name,
                "success": False,
                "error": result["error"],
                "response_time": result["response_time"]
            }
    
    def search_with_fallback(self, query: str, **kwargs) -> Dict[str, Any]:
        """Search with automatic fallback between APIs"""
        # Get APIs sorted by priority
        available_apis = sorted(
            [(name, config) for name, config in API_CONFIG.items() if config["enabled"]],
            key=lambda x: x[1]["priority"]
        )
        
        attempts = []
        
        for api_name, config in available_apis:
            # Check circuit breaker
            if api_name in self.circuit_breakers:
                if not self.circuit_breakers[api_name].call_allowed():
                    logger.warning(f"Circuit breaker open for {api_name}, skipping")
                    attempts.append({
                        "api": api_name,
                        "success": False,
                        "error": "Circuit breaker open",
                        "skipped": True
                    })
                    continue
            
            logger.info(f"Attempting search with {api_name} API...")
            
            # Record request
            if api_name in self.metrics:
                self.metrics[api_name].total_requests += 1
            
            try:
                # Call appropriate API
                if api_name == "tavily":
                    result = self._call_tavily_api(query, **kwargs)
                elif api_name == "brave":
                    result = self._call_brave_api(query, **kwargs)
                elif api_name == "smithery":
                    result = self._call_smithery_api(**kwargs)
                else:
                    result = {"api": api_name, "success": False, "error": "Unknown API"}
                
                attempts.append(result)
                
                # Update metrics and circuit breaker
                if api_name in self.metrics and api_name in self.circuit_breakers:
                    if result["success"]:
                        self.metrics[api_name].successful_requests += 1
                        self.metrics[api_name].response_times.append(result.get("response_time", 0))
                        self.metrics[api_name].last_success = time.time()
                        self.circuit_breakers[api_name].record_success()
                        
                        logger.info(f"Search successful with {api_name} API")
                        return {
                            "primary_api": api_name,
                            "success": True,
                            "fallback_used": api_name != available_apis[0][0],
                            "result": result,
                            "attempts": attempts
                        }
                    else:
                        self.metrics[api_name].failed_requests += 1
                        self.metrics[api_name].errors.append(result.get("error", "Unknown error"))
                        self.metrics[api_name].last_failure = time.time()
                        self.circuit_breakers[api_name].record_failure()
                        
                        logger.warning(f"Search failed with {api_name} API: {result.get('error')}")
                
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Exception calling {api_name} API: {error_msg}")
                
                attempts.append({
                    "api": api_name,
                    "success": False,
                    "error": error_msg
                })
                
                if api_name in self.metrics and api_name in self.circuit_breakers:
                    self.metrics[api_name].failed_requests += 1
                    self.metrics[api_name].errors.append(error_msg)
                    self.circuit_breakers[api_name].record_failure()
        
        logger.error("All APIs failed or unavailable")
        return {
            "primary_api": None,
            "success": False,
            "fallback_used": True,
            "result": None,
            "attempts": attempts,
            "error": "All APIs failed or unavailable"
        }
    
    def get_api_health_status(self) -> Dict[str, Any]:
        """Get comprehensive API health status"""
        health_report = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "healthy",
            "apis": {}
        }
        
        failed_count = 0
        degraded_count = 0
        
        for api_name, metrics in self.metrics.items():
            # Determine API status
            if metrics.success_rate >= 95:
                status = APIHealthStatus.HEALTHY
            elif metrics.success_rate >= 75:
                status = APIHealthStatus.DEGRADED
                degraded_count += 1
            elif metrics.success_rate >= 50:
                status = APIHealthStatus.RECOVERING
            else:
                status = APIHealthStatus.FAILED
                failed_count += 1
            
            circuit_breaker = self.circuit_breakers.get(api_name)
            
            health_report["apis"][api_name] = {
                "status": status.value,
                "total_requests": metrics.total_requests,
                "successful_requests": metrics.successful_requests,
                "failed_requests": metrics.failed_requests,
                "success_rate": f"{metrics.success_rate:.2f}%",
                "avg_response_time": f"{metrics.avg_response_time:.3f}s",
                "p95_response_time": f"{metrics.p95_response_time:.3f}s",
                "circuit_breaker_state": circuit_breaker.state if circuit_breaker else "unknown",
                "last_success": metrics.last_success,
                "last_failure": metrics.last_failure,
                "recent_errors": metrics.errors[-3:] if metrics.errors else []
            }
        
        # Determine overall status
        if failed_count > 1:
            health_report["overall_status"] = "critical"
        elif failed_count == 1 or degraded_count > 0:
            health_report["overall_status"] = "degraded"
        else:
            health_report["overall_status"] = "healthy"
        
        return health_report
    
    def reset_circuit_breakers(self):
        """Reset all circuit breakers (for testing/recovery)"""
        for api_name, breaker in self.circuit_breakers.items():
            breaker.state = "closed"
            breaker.failure_count = 0
            breaker.half_open_calls = 0
            logger.info(f"Reset circuit breaker for {api_name}")

class MCPAPIIntegrationServer:
    """MCP Server with integrated API management"""
    
    def __init__(self):
        self.api_manager = APIIntegrationManager()
        self.server_stats = {
            "start_time": time.time(),
            "total_searches": 0,
            "successful_searches": 0,
            "failed_searches": 0
        }
    
    def handle_search_request(self, query: str, **kwargs) -> Dict[str, Any]:
        """Handle search request with fallback mechanisms"""
        self.server_stats["total_searches"] += 1
        
        start_time = time.time()
        result = self.api_manager.search_with_fallback(query, **kwargs)
        end_time = time.time()
        
        if result["success"]:
            self.server_stats["successful_searches"] += 1
        else:
            self.server_stats["failed_searches"] += 1
        
        # Add server metadata
        result["server_response_time"] = end_time - start_time
        result["server_stats"] = self.server_stats.copy()
        
        return result
    
    def handle_health_check(self) -> Dict[str, Any]:
        """Handle health check request"""
        health_status = self.api_manager.get_api_health_status()
        
        health_status["server_stats"] = {
            **self.server_stats,
            "uptime_seconds": time.time() - self.server_stats["start_time"],
            "search_success_rate": (
                self.server_stats["successful_searches"] / 
                max(self.server_stats["total_searches"], 1)
            ) * 100
        }
        
        return health_status
    
    def handle_reset_request(self) -> Dict[str, Any]:
        """Handle circuit breaker reset request"""
        self.api_manager.reset_circuit_breakers()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "action": "circuit_breakers_reset",
            "success": True,
            "message": "All circuit breakers have been reset"
        }

def main():
    """Demonstration of MCP API Integration Server"""
    logger.info("Starting MCP API Integration Server")
    
    server = MCPAPIIntegrationServer()
    
    # Demonstration scenarios
    test_scenarios = [
        {
            "name": "Basic Search Test",
            "query": "artificial intelligence trends 2024",
            "description": "Test basic search functionality"
        },
        {
            "name": "Machine Learning Search",
            "query": "machine learning algorithms",
            "description": "Test ML-related search"
        },
        {
            "name": "Technology Search",
            "query": "quantum computing applications",
            "description": "Test technology search"
        }
    ]
    
    print("\n" + "="*60)
    print("MCP API INTEGRATION SERVER DEMONSTRATION")
    print("="*60)
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\nScenario {i}: {scenario['name']}")
        print(f"Query: '{scenario['query']}'")
        print(f"Description: {scenario['description']}")
        print("-" * 40)
        
        # Execute search
        result = server.handle_search_request(scenario["query"])
        
        if result["success"]:
            print(f"✓ Search successful using {result['primary_api']} API")
            print(f"  Response time: {result['server_response_time']:.3f}s")
            print(f"  Fallback used: {result['fallback_used']}")
            if "result" in result and result["result"]:
                api_result = result["result"]
                if "total_results" in api_result:
                    print(f"  Results found: {api_result['total_results']}")
        else:
            print(f"✗ Search failed: {result.get('error', 'Unknown error')}")
            print(f"  Attempts made: {len(result.get('attempts', []))}")
        
        time.sleep(1)  # Small delay between tests
    
    # Health check
    print(f"\n" + "-" * 40)
    print("HEALTH CHECK RESULTS")
    print("-" * 40)
    
    health = server.handle_health_check()
    print(f"Overall Status: {health['overall_status'].upper()}")
    print(f"Server Uptime: {health['server_stats']['uptime_seconds']:.1f}s")
    print(f"Total Searches: {health['server_stats']['total_searches']}")
    print(f"Success Rate: {health['server_stats']['search_success_rate']:.1f}%")
    
    print(f"\nAPI Status Summary:")
    for api_name, api_status in health["apis"].items():
        status_icon = "✓" if api_status["status"] == "healthy" else "✗"
        print(f"  {status_icon} {api_name.upper()}: {api_status['status']} "
              f"({api_status['success_rate']} success rate)")
    
    print("="*60)
    
    # Save detailed report
    report = {
        "test_timestamp": datetime.now().isoformat(),
        "server_stats": server.server_stats,
        "health_status": health,
        "test_scenarios": test_scenarios
    }
    
    with open("mcp_api_integration_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    logger.info("Detailed report saved to mcp_api_integration_report.json")

if __name__ == "__main__":
    main()