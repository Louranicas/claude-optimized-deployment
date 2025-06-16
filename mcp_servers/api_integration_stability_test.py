#!/usr/bin/env python3
"""
Agent 8 - API Integration Stability Testing (Standard Library Version)
Validates Tavily, Smithery, Brave API integrations with fallback mechanisms
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
import concurrent.futures
import socket

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
        self._lock = threading.Lock()
    
    def record_success(self):
        """Record successful request"""
        with self._lock:
            self.failure_count = 0
            self.is_open = False
    
    def record_failure(self):
        """Record failed request"""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.is_open = True
                logger.warning(f"Circuit breaker opened after {self.failure_count} failures")
    
    def can_attempt(self) -> bool:
        """Check if request can be attempted"""
        with self._lock:
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
    
    def _make_http_request(self, url: str, headers: Dict[str, str], 
                          data: Optional[str] = None, timeout: int = 30) -> Tuple[bool, Dict[str, Any], float]:
        """Make HTTP request with timeout and error handling"""
        start_time = time.time()
        
        try:
            request = urllib.request.Request(url, headers=headers)
            if data:
                request.data = data.encode('utf-8')
            
            # Set timeout
            socket.setdefaulttimeout(timeout)
            
            with urllib.request.urlopen(request) as response:
                response_time = time.time() - start_time
                response_data = response.read().decode('utf-8')
                
                if response.getcode() == 200:
                    try:
                        json_data = json.loads(response_data)
                        return True, json_data, response_time
                    except json.JSONDecodeError:
                        return True, {"raw_response": response_data}, response_time
                else:
                    return False, {
                        "status": response.getcode(),
                        "error": response_data
                    }, response_time
                    
        except urllib.error.HTTPError as e:
            response_time = time.time() - start_time
            return False, {
                "status": e.code,
                "error": str(e)
            }, response_time
        except urllib.error.URLError as e:
            response_time = time.time() - start_time
            return False, {"error": f"URL Error: {str(e)}"}, response_time
        except socket.timeout:
            response_time = time.time() - start_time
            return False, {"error": "Request timeout"}, response_time
        except Exception as e:
            response_time = time.time() - start_time
            return False, {"error": str(e)}, response_time
    
    def test_tavily_api(self, query: str = "AI technology trends 2024") -> Dict[str, Any]:
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
            url = API_CREDENTIALS[api_name]["base_url"]
            headers = {
                "Content-Type": "application/json"
            }
            
            payload = {
                "api_key": API_CREDENTIALS[api_name]["api_key"],
                "query": query,
                "search_depth": "basic",
                "include_answer": True,
                "include_images": False,
                "include_raw_content": False,
                "max_results": 5
            }
            
            success, data, response_time = self._make_http_request(
                url, headers, json.dumps(payload), API_CREDENTIALS[api_name]["timeout"]
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
                    "results_count": len(data.get("results", [])) if isinstance(data, dict) else 0,
                    "has_answer": "answer" in data if isinstance(data, dict) else False
                }
            else:
                metrics.failed_requests += 1
                error_msg = str(data.get("error", "Unknown error"))[:100]
                metrics.errors.append(error_msg)
                circuit_breaker.record_failure()
                
                return {
                    "api": api_name,
                    "status": "failed",
                    "success": False,
                    "error": error_msg,
                    "response_time": response_time
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
    
    def test_brave_api(self, query: str = "machine learning applications") -> Dict[str, Any]:
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
        
        try:
            params = urllib.parse.urlencode({
                "q": query,
                "count": 10
            })
            
            url = f"{API_CREDENTIALS[api_name]['base_url']}?{params}"
            headers = {
                "Accept": "application/json",
                "X-Subscription-Token": API_CREDENTIALS[api_name]["api_key"]
            }
            
            success, data, response_time = self._make_http_request(
                url, headers, None, API_CREDENTIALS[api_name]["timeout"]
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
                    "results_count": len(data.get("web", {}).get("results", [])) if isinstance(data, dict) else 0,
                    "has_discussions": "discussions" in data if isinstance(data, dict) else False
                }
            else:
                metrics.failed_requests += 1
                error_msg = str(data.get("error", "Unknown error"))[:100]
                metrics.errors.append(error_msg)
                circuit_breaker.record_failure()
                
                return {
                    "api": api_name,
                    "status": "failed",
                    "success": False,
                    "error": error_msg,
                    "response_time": response_time
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
    
    def test_smithery_api(self) -> Dict[str, Any]:
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
        
        try:
            url = f"{API_CREDENTIALS[api_name]['base_url']}/models"
            headers = {
                "Authorization": f"Bearer {API_CREDENTIALS[api_name]['api_key']}",
                "Content-Type": "application/json"
            }
            
            success, data, response_time = self._make_http_request(
                url, headers, None, API_CREDENTIALS[api_name]["timeout"]
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
                    "data_size": len(str(data)) if data else 0
                }
            else:
                metrics.failed_requests += 1
                error_msg = str(data.get("error", "Unknown error"))[:100]
                metrics.errors.append(error_msg)
                circuit_breaker.record_failure()
                
                return {
                    "api": api_name,
                    "status": "failed",
                    "success": False,
                    "error": error_msg,
                    "response_time": response_time
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
    
    def test_api_with_fallback(self, query: str = "quantum computing") -> Dict[str, Any]:
        """Test API with fallback mechanism"""
        api_priority = ["tavily", "brave", "smithery"]
        results = []
        
        for api in api_priority:
            logger.info(f"Attempting {api} API...")
            
            if api == "tavily":
                result = self.test_tavily_api(query)
            elif api == "brave":
                result = self.test_brave_api(query)
            else:
                result = self.test_smithery_api()
            
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
    
    def stress_test_apis(self, num_requests: int = 20, max_workers: int = 5):
        """Stress test APIs with concurrent requests"""
        logger.info(f"Starting stress test: {num_requests} requests, {max_workers} concurrent")
        
        queries = [
            "artificial intelligence",
            "machine learning",
            "data science",
            "cloud computing",
            "cybersecurity"
        ]
        
        def make_request(i):
            query = queries[i % len(queries)]
            return self.test_api_with_fallback(query)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
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
    
    def test_network_failure_recovery(self):
        """Test API recovery from network failures"""
        logger.info("Testing network failure recovery...")
        
        results = {
            "test_name": "network_failure_recovery",
            "timestamp": datetime.now().isoformat(),
            "phases": []
        }
        
        # Phase 1: Normal operation
        phase1_results = []
        for _ in range(3):
            result = self.test_api_with_fallback()
            phase1_results.append(result)
            time.sleep(1)
        
        results["phases"].append({
            "phase": "normal_operation",
            "success_rate": sum(1 for r in phase1_results if r["success"]) / len(phase1_results) * 100
        })
        
        # Phase 2: Simulate failures (circuit breakers will open)
        for api in self.circuit_breakers:
            for _ in range(6):  # Exceed failure threshold
                self.circuit_breakers[api].record_failure()
        
        phase2_results = []
        for _ in range(3):
            result = self.test_api_with_fallback()
            phase2_results.append(result)
        
        results["phases"].append({
            "phase": "during_failure",
            "success_rate": sum(1 for r in phase2_results if r["success"]) / len(phase2_results) * 100,
            "circuit_breakers_open": sum(1 for cb in self.circuit_breakers.values() if cb.is_open)
        })
        
        # Phase 3: Simulate recovery
        logger.info("Simulating circuit breaker recovery...")
        for api in self.circuit_breakers:
            self.circuit_breakers[api].is_open = False
            self.circuit_breakers[api].failure_count = 0
        
        phase3_results = []
        for _ in range(3):
            result = self.test_api_with_fallback()
            phase3_results.append(result)
            time.sleep(1)
        
        results["phases"].append({
            "phase": "after_recovery",
            "success_rate": sum(1 for r in phase3_results if r["success"]) / len(phase3_results) * 100,
            "circuit_breakers_open": sum(1 for cb in self.circuit_breakers.values() if cb.is_open)
        })
        
        return results

def main():
    """Main test execution"""
    logger.info("Starting API Integration Stability Testing")
    
    test_results = {
        "test_suite": "API Integration Stability",
        "timestamp": datetime.now().isoformat(),
        "tests": {}
    }
    
    tester = APIIntegrationTester()
    
    # Test 1: Individual API connectivity
    logger.info("Test 1: Individual API Connectivity")
    test_results["tests"]["individual_connectivity"] = {
        "tavily": tester.test_tavily_api(),
        "brave": tester.test_brave_api(),
        "smithery": tester.test_smithery_api()
    }
    
    # Test 2: Fallback mechanism
    logger.info("Test 2: API Fallback Mechanism")
    test_results["tests"]["fallback_mechanism"] = tester.test_api_with_fallback()
    
    # Test 3: Stress testing
    logger.info("Test 3: API Stress Testing")
    stress_report = tester.stress_test_apis(num_requests=15, max_workers=3)
    test_results["tests"]["stress_test"] = stress_report
    
    # Test 4: Network failure recovery
    logger.info("Test 4: Network Failure Recovery")
    test_results["tests"]["network_recovery"] = tester.test_network_failure_recovery()
    
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
    
    # Display individual API results
    print(f"\nIndividual API Test Results:")
    for api_name, result in test_results["tests"]["individual_connectivity"].items():
        status = "✓" if result["success"] else "✗"
        print(f"  {status} {api_name.upper()}: {result['status']}")
        if not result["success"] and "error" in result:
            print(f"    Error: {result['error']}")
    
    print("="*60)
    
    return test_results

if __name__ == "__main__":
    main()