#!/usr/bin/env python3
"""
Agent 8 - API Integration Stability Testing
Validates Tavily, Smithery, Brave API integrations with fallback mechanisms
"""

import asyncio
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
from aiohttp import ClientTimeout, ClientError
import backoff
from collections import defaultdict
import statistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# API Credentials
API_CREDENTIALS = {
    "tavily": {
        "api_key": "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",
        "base_url": "https://api.tavily.com/search",
        "timeout": 30
    },
    "smithery": {
        "api_key": "85861ba2-5eba-4599-b38d-61f4b3df44a7",
        "base_url": "https://api.smithery.ai/v1",
        "timeout": 45
    },
    "brave": {
        "api_key": "BSAigVAUU4-V72PjB48t8_CqN00Hh5z",
        "base_url": "https://api.search.brave.com/res/v1/web/search",
        "timeout": 25
    }
}

class APIStatus(Enum):
    """API health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    RECOVERING = "recovering"

@dataclass
class APIMetrics:
    """Metrics for API performance"""
    api_name: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    response_times: List[float] = None
    errors: List[str] = None
    status: APIStatus = APIStatus.HEALTHY
    last_failure: Optional[float] = None
    circuit_breaker_open: bool = False
    
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
    """Circuit breaker pattern implementation"""
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.is_open = False
    
    def record_success(self):
        """Record successful request"""
        self.failure_count = 0
        self.is_open = False
    
    def record_failure(self):
        """Record failed request"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.is_open = True
            logger.warning(f"Circuit breaker opened after {self.failure_count} failures")
    
    def can_attempt(self) -> bool:
        """Check if request can be attempted"""
        if not self.is_open:
            return True
        
        # Check if recovery timeout has passed
        if self.last_failure_time and \
           (time.time() - self.last_failure_time) > self.recovery_timeout:
            self.is_open = False
            self.failure_count = 0
            logger.info("Circuit breaker closed after recovery timeout")
            return True
        
        return False

class APIIntegrationTester:
    """Main API integration testing class"""
    
    def __init__(self):
        self.metrics: Dict[str, APIMetrics] = {
            api: APIMetrics(api_name=api) for api in API_CREDENTIALS
        }
        self.circuit_breakers: Dict[str, CircuitBreaker] = {
            api: CircuitBreaker() for api in API_CREDENTIALS
        }
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    @backoff.on_exception(
        backoff.expo,
        (ClientError, asyncio.TimeoutError),
        max_tries=3,
        max_time=30
    )
    async def _make_api_request(self, api_name: str, endpoint: str, 
                               params: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], float]:
        """Make API request with retry logic"""
        config = API_CREDENTIALS[api_name]
        start_time = time.time()
        
        try:
            timeout = ClientTimeout(total=config["timeout"])
            headers = self._get_headers(api_name)
            
            async with self.session.get(
                endpoint,
                params=params,
                headers=headers,
                timeout=timeout
            ) as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    data = await response.json()
                    return True, data, response_time
                else:
                    error_text = await response.text()
                    return False, {
                        "status": response.status,
                        "error": error_text
                    }, response_time
                    
        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            return False, {"error": "Request timeout"}, response_time
        except Exception as e:
            response_time = time.time() - start_time
            return False, {"error": str(e)}, response_time
    
    def _get_headers(self, api_name: str) -> Dict[str, str]:
        """Get API-specific headers"""
        if api_name == "tavily":
            return {
                "Content-Type": "application/json",
                "X-API-Key": API_CREDENTIALS[api_name]["api_key"]
            }
        elif api_name == "brave":
            return {
                "Accept": "application/json",
                "X-Subscription-Token": API_CREDENTIALS[api_name]["api_key"]
            }
        elif api_name == "smithery":
            return {
                "Authorization": f"Bearer {API_CREDENTIALS[api_name]['api_key']}",
                "Content-Type": "application/json"
            }
        return {}
    
    async def test_tavily_api(self, query: str = "AI technology trends 2024") -> Dict[str, Any]:
        """Test Tavily Search API"""
        api_name = "tavily"
        metrics = self.metrics[api_name]
        circuit_breaker = self.circuit_breakers[api_name]
        
        if not circuit_breaker.can_attempt():
            return {
                "api": api_name,
                "status": "circuit_breaker_open",
                "success": False
            }
        
        metrics.total_requests += 1
        
        try:
            # Tavily uses POST request
            url = API_CREDENTIALS[api_name]["base_url"]
            
            async with self.session.post(
                url,
                json={
                    "api_key": API_CREDENTIALS[api_name]["api_key"],
                    "query": query,
                    "search_depth": "basic",
                    "include_answer": True,
                    "include_images": False,
                    "include_raw_content": False,
                    "max_results": 5
                },
                timeout=ClientTimeout(total=API_CREDENTIALS[api_name]["timeout"])
            ) as response:
                response_time = time.time()
                
                if response.status == 200:
                    data = await response.json()
                    metrics.successful_requests += 1
                    metrics.response_times.append(response_time)
                    circuit_breaker.record_success()
                    
                    return {
                        "api": api_name,
                        "status": "success",
                        "success": True,
                        "response_time": response_time,
                        "results_count": len(data.get("results", [])),
                        "has_answer": "answer" in data
                    }
                else:
                    error_text = await response.text()
                    metrics.failed_requests += 1
                    metrics.errors.append(f"HTTP {response.status}: {error_text[:100]}")
                    circuit_breaker.record_failure()
                    
                    return {
                        "api": api_name,
                        "status": "http_error",
                        "success": False,
                        "error": f"HTTP {response.status}",
                        "details": error_text[:200]
                    }
                    
        except Exception as e:
            metrics.failed_requests += 1
            metrics.errors.append(str(e)[:100])
            circuit_breaker.record_failure()
            
            return {
                "api": api_name,
                "status": "exception",
                "success": False,
                "error": str(e)
            }
    
    async def test_brave_api(self, query: str = "machine learning applications") -> Dict[str, Any]:
        """Test Brave Search API"""
        api_name = "brave"
        metrics = self.metrics[api_name]
        circuit_breaker = self.circuit_breakers[api_name]
        
        if not circuit_breaker.can_attempt():
            return {
                "api": api_name,
                "status": "circuit_breaker_open",
                "success": False
            }
        
        metrics.total_requests += 1
        
        params = {
            "q": query,
            "count": 10
        }
        
        success, data, response_time = await self._make_api_request(
            api_name,
            API_CREDENTIALS[api_name]["base_url"],
            params
        )
        
        if success:
            metrics.successful_requests += 1
            metrics.response_times.append(response_time)
            circuit_breaker.record_success()
            
            return {
                "api": api_name,
                "status": "success",
                "success": True,
                "response_time": response_time,
                "results_count": len(data.get("web", {}).get("results", [])),
                "has_discussions": "discussions" in data
            }
        else:
            metrics.failed_requests += 1
            metrics.errors.append(str(data.get("error", "Unknown error"))[:100])
            circuit_breaker.record_failure()
            
            return {
                "api": api_name,
                "status": "failed",
                "success": False,
                "error": data.get("error", "Unknown error"),
                "response_time": response_time
            }
    
    async def test_smithery_api(self) -> Dict[str, Any]:
        """Test Smithery API"""
        api_name = "smithery"
        metrics = self.metrics[api_name]
        circuit_breaker = self.circuit_breakers[api_name]
        
        if not circuit_breaker.can_attempt():
            return {
                "api": api_name,
                "status": "circuit_breaker_open",
                "success": False
            }
        
        metrics.total_requests += 1
        
        # Test endpoint - adjust based on actual Smithery API
        endpoint = f"{API_CREDENTIALS[api_name]['base_url']}/models"
        
        success, data, response_time = await self._make_api_request(
            api_name,
            endpoint,
            {}
        )
        
        if success:
            metrics.successful_requests += 1
            metrics.response_times.append(response_time)
            circuit_breaker.record_success()
            
            return {
                "api": api_name,
                "status": "success",
                "success": True,
                "response_time": response_time,
                "data": data
            }
        else:
            metrics.failed_requests += 1
            metrics.errors.append(str(data.get("error", "Unknown error"))[:100])
            circuit_breaker.record_failure()
            
            return {
                "api": api_name,
                "status": "failed",
                "success": False,
                "error": data.get("error", "Unknown error"),
                "response_time": response_time
            }
    
    async def test_api_with_fallback(self, query: str = "quantum computing") -> Dict[str, Any]:
        """Test API with fallback mechanism"""
        api_priority = ["tavily", "brave", "smithery"]
        results = []
        
        for api in api_priority:
            logger.info(f"Attempting {api} API...")
            
            if api == "tavily":
                result = await self.test_tavily_api(query)
            elif api == "brave":
                result = await self.test_brave_api(query)
            else:
                result = await self.test_smithery_api()
            
            results.append(result)
            
            if result["success"]:
                logger.info(f"Successfully used {api} API")
                return {
                    "primary_api": api,
                    "success": True,
                    "fallback_used": api != api_priority[0],
                    "attempts": results
                }
        
        logger.error("All APIs failed")
        return {
            "primary_api": None,
            "success": False,
            "fallback_used": True,
            "attempts": results
        }
    
    async def stress_test_apis(self, num_requests: int = 50, concurrent: int = 10):
        """Stress test APIs with concurrent requests"""
        logger.info(f"Starting stress test: {num_requests} requests, {concurrent} concurrent")
        
        tasks = []
        for i in range(num_requests):
            # Rotate through different queries
            queries = [
                "artificial intelligence",
                "machine learning",
                "data science",
                "cloud computing",
                "cybersecurity"
            ]
            query = queries[i % len(queries)]
            
            task = self.test_api_with_fallback(query)
            tasks.append(task)
            
            # Control concurrency
            if len(tasks) >= concurrent:
                results = await asyncio.gather(*tasks)
                tasks = []
                await asyncio.sleep(0.1)  # Small delay between batches
        
        # Process remaining tasks
        if tasks:
            await asyncio.gather(*tasks)
        
        return self.generate_stress_test_report()
    
    def update_api_status(self):
        """Update API status based on metrics"""
        for api_name, metrics in self.metrics.items():
            if metrics.success_rate >= 95:
                metrics.status = APIStatus.HEALTHY
            elif metrics.success_rate >= 75:
                metrics.status = APIStatus.DEGRADED
            elif metrics.success_rate >= 50:
                metrics.status = APIStatus.RECOVERING
            else:
                metrics.status = APIStatus.FAILED
    
    def generate_stress_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive stress test report"""
        self.update_api_status()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "api_metrics": {},
            "overall_health": "healthy",
            "recommendations": []
        }
        
        failed_apis = 0
        
        for api_name, metrics in self.metrics.items():
            api_report = {
                "status": metrics.status.value,
                "total_requests": metrics.total_requests,
                "successful_requests": metrics.successful_requests,
                "failed_requests": metrics.failed_requests,
                "success_rate": f"{metrics.success_rate:.2f}%",
                "avg_response_time": f"{metrics.avg_response_time:.3f}s",
                "p95_response_time": f"{metrics.p95_response_time:.3f}s",
                "circuit_breaker_open": self.circuit_breakers[api_name].is_open,
                "recent_errors": metrics.errors[-5:] if metrics.errors else []
            }
            
            report["api_metrics"][api_name] = api_report
            
            if metrics.status == APIStatus.FAILED:
                failed_apis += 1
        
        # Determine overall health
        if failed_apis == 0:
            report["overall_health"] = "healthy"
        elif failed_apis == 1:
            report["overall_health"] = "degraded"
        else:
            report["overall_health"] = "critical"
        
        # Generate recommendations
        for api_name, metrics in self.metrics.items():
            if metrics.status == APIStatus.FAILED:
                report["recommendations"].append(
                    f"Investigate {api_name} API failures - success rate: {metrics.success_rate:.2f}%"
                )
            elif metrics.status == APIStatus.DEGRADED:
                report["recommendations"].append(
                    f"Monitor {api_name} API performance - showing degradation"
                )
            
            if metrics.avg_response_time > 5.0:
                report["recommendations"].append(
                    f"Optimize {api_name} API requests - high average response time"
                )
        
        return report
    
    async def test_network_failure_recovery(self):
        """Test API recovery from network failures"""
        logger.info("Testing network failure recovery...")
        
        results = {
            "test_name": "network_failure_recovery",
            "timestamp": datetime.now().isoformat(),
            "phases": []
        }
        
        # Phase 1: Normal operation
        phase1_results = []
        for _ in range(5):
            result = await self.test_api_with_fallback()
            phase1_results.append(result)
            await asyncio.sleep(1)
        
        results["phases"].append({
            "phase": "normal_operation",
            "success_rate": sum(1 for r in phase1_results if r["success"]) / len(phase1_results) * 100
        })
        
        # Phase 2: Simulate failures (circuit breakers will open)
        for api in self.circuit_breakers:
            for _ in range(6):  # Exceed failure threshold
                self.circuit_breakers[api].record_failure()
        
        phase2_results = []
        for _ in range(5):
            result = await self.test_api_with_fallback()
            phase2_results.append(result)
        
        results["phases"].append({
            "phase": "during_failure",
            "success_rate": sum(1 for r in phase2_results if r["success"]) / len(phase2_results) * 100,
            "circuit_breakers_open": sum(1 for cb in self.circuit_breakers.values() if cb.is_open)
        })
        
        # Phase 3: Wait for recovery
        logger.info("Waiting for circuit breaker recovery...")
        await asyncio.sleep(65)  # Wait for recovery timeout
        
        phase3_results = []
        for _ in range(5):
            result = await self.test_api_with_fallback()
            phase3_results.append(result)
            await asyncio.sleep(1)
        
        results["phases"].append({
            "phase": "after_recovery",
            "success_rate": sum(1 for r in phase3_results if r["success"]) / len(phase3_results) * 100,
            "circuit_breakers_open": sum(1 for cb in self.circuit_breakers.values() if cb.is_open)
        })
        
        return results

async def main():
    """Main test execution"""
    logger.info("Starting API Integration Stability Testing")
    
    test_results = {
        "test_suite": "API Integration Stability",
        "timestamp": datetime.now().isoformat(),
        "tests": {}
    }
    
    async with APIIntegrationTester() as tester:
        # Test 1: Individual API connectivity
        logger.info("Test 1: Individual API Connectivity")
        test_results["tests"]["individual_connectivity"] = {
            "tavily": await tester.test_tavily_api(),
            "brave": await tester.test_brave_api(),
            "smithery": await tester.test_smithery_api()
        }
        
        # Test 2: Fallback mechanism
        logger.info("Test 2: API Fallback Mechanism")
        test_results["tests"]["fallback_mechanism"] = await tester.test_api_with_fallback()
        
        # Test 3: Stress testing
        logger.info("Test 3: API Stress Testing")
        stress_report = await tester.stress_test_apis(num_requests=30, concurrent=5)
        test_results["tests"]["stress_test"] = stress_report
        
        # Test 4: Network failure recovery
        logger.info("Test 4: Network Failure Recovery")
        test_results["tests"]["network_recovery"] = await tester.test_network_failure_recovery()
        
        # Generate final report
        test_results["summary"] = {
            "total_apis_tested": len(API_CREDENTIALS),
            "apis_healthy": sum(1 for m in tester.metrics.values() if m.status == APIStatus.HEALTHY),
            "apis_degraded": sum(1 for m in tester.metrics.values() if m.status == APIStatus.DEGRADED),
            "apis_failed": sum(1 for m in tester.metrics.values() if m.status == APIStatus.FAILED),
            "overall_stability": stress_report["overall_health"],
            "recommendations": stress_report["recommendations"]
        }
    
    # Save results
    with open("api_integration_stability_report.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    logger.info(f"Test completed. Results saved to api_integration_stability_report.json")
    
    # Print summary
    print("\n" + "="*60)
    print("API INTEGRATION STABILITY TEST SUMMARY")
    print("="*60)
    print(f"Timestamp: {test_results['timestamp']}")
    print(f"\nAPIs Tested: {test_results['summary']['total_apis_tested']}")
    print(f"Healthy APIs: {test_results['summary']['apis_healthy']}")
    print(f"Degraded APIs: {test_results['summary']['apis_degraded']}")
    print(f"Failed APIs: {test_results['summary']['apis_failed']}")
    print(f"\nOverall Stability: {test_results['summary']['overall_stability'].upper()}")
    
    if test_results['summary']['recommendations']:
        print("\nRecommendations:")
        for rec in test_results['summary']['recommendations']:
            print(f"  - {rec}")
    
    print("="*60)
    
    return test_results

if __name__ == "__main__":
    asyncio.run(main())