"""
MCP Server Reliability Validation
Agent 8 - ULTRATHINK Mission: Real-world MCP Server Testing

This script performs actual reliability testing of the MCP servers with real
failure scenarios and validates error handling, recovery, and resilience patterns.
"""

import asyncio
import pytest
import logging
import time
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import aiohttp
from unittest.mock import patch, AsyncMock

# Import MCP components
from src.mcp.manager import get_mcp_manager, MCPManager
from src.mcp.protocols import MCPError
from src.mcp.servers import MCPServerRegistry

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class MCPReliabilityTestResult:
    """Track MCP-specific reliability test results."""
    server_name: str
    tool_name: str
    test_type: str
    success: bool
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    response_time: Optional[float] = None
    recovery_successful: bool = False
    error_handling_quality: str = "unknown"  # excellent, good, acceptable, poor
    details: Dict[str, Any] = field(default_factory=dict)


class MCPReliabilityValidator:
    """Validate MCP server reliability and error handling."""
    
    def __init__(self):
        self.manager: Optional[MCPManager] = None
        self.registry: Optional[MCPServerRegistry] = None
        self.test_results: List[MCPReliabilityTestResult] = []
    
    async def setup(self):
        """Setup MCP manager and registry."""
        try:
            self.manager = get_mcp_manager()
            await self.manager.initialize()
            self.registry = self.manager.registry
            logger.info(f"Initialized MCP manager with {len(self.registry.servers)} servers")
        except Exception as e:
            logger.error(f"Failed to setup MCP manager: {e}")
            raise
    
    async def teardown(self):
        """Cleanup resources."""
        if self.manager:
            for server in self.registry.servers.values():
                if hasattr(server, 'close'):
                    try:
                        await server.close()
                    except Exception as e:
                        logger.warning(f"Error closing server: {e}")
    
    async def test_server_availability(self) -> List[MCPReliabilityTestResult]:
        """Test basic server availability and health."""
        results = []
        
        for server_name, server in self.registry.servers.items():
            start_time = time.time()
            
            try:
                # Test server info retrieval
                server_info = server.get_server_info()
                tools = server.get_tools()
                
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name="server_health",
                    test_type="availability",
                    success=True,
                    response_time=time.time() - start_time,
                    error_handling_quality="excellent",
                    details={
                        "server_version": server_info.version,
                        "tool_count": len(tools),
                        "capabilities": server_info.capabilities.dict() if hasattr(server_info.capabilities, 'dict') else str(server_info.capabilities)
                    }
                )
                
            except Exception as e:
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name="server_health",
                    test_type="availability",
                    success=False,
                    error_message=str(e),
                    response_time=time.time() - start_time,
                    error_handling_quality="poor"
                )
            
            results.append(result)
            self.test_results.append(result)
        
        return results
    
    async def test_invalid_tool_calls(self) -> List[MCPReliabilityTestResult]:
        """Test error handling for invalid tool calls."""
        results = []
        
        for server_name, server in self.registry.servers.items():
            # Test unknown tool
            start_time = time.time()
            
            try:
                await server.call_tool("nonexistent_tool", {})
                # Should not reach here
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name="nonexistent_tool",
                    test_type="invalid_tool",
                    success=False,
                    error_handling_quality="poor",
                    details={"unexpected_success": True}
                )
            except MCPError as e:
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name="nonexistent_tool",
                    test_type="invalid_tool",
                    success=True,  # Proper error handling is success
                    error_code=e.code,
                    error_message=str(e),
                    response_time=time.time() - start_time,
                    error_handling_quality="excellent" if e.code == -32601 else "good"
                )
            except Exception as e:
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name="nonexistent_tool",
                    test_type="invalid_tool",
                    success=False,
                    error_message=str(e),
                    response_time=time.time() - start_time,
                    error_handling_quality="poor",
                    details={"unexpected_error_type": type(e).__name__}
                )
            
            results.append(result)
            self.test_results.append(result)
        
        return results
    
    async def test_invalid_parameters(self) -> List[MCPReliabilityTestResult]:
        """Test error handling for invalid parameters."""
        results = []
        
        # Test cases for different parameter validation scenarios
        test_cases = [
            {"description": "missing_required_param", "args": {}},
            {"description": "invalid_type", "args": {"query": 123}},  # String expected
            {"description": "invalid_enum", "args": {"state": "invalid_state"}},
            {"description": "too_long_string", "args": {"query": "x" * 2000}},
            {"description": "negative_number", "args": {"count": -1}},
        ]
        
        # Test with a few representative tools from each server
        test_tools = [
            ("brave", "brave_web_search"),
            ("prometheus-monitoring", "prometheus_query"),
            ("docker", "docker_run"),
            ("kubernetes", "kubectl_get"),
            ("security-scanner", "npm_audit")
        ]
        
        for server_name, tool_name in test_tools:
            if server_name not in self.registry.servers:
                continue
            
            server = self.registry.servers[server_name]
            
            for test_case in test_cases:
                start_time = time.time()
                
                try:
                    await server.call_tool(tool_name, test_case["args"])
                    # Should not reach here for invalid params
                    result = MCPReliabilityTestResult(
                        server_name=server_name,
                        tool_name=tool_name,
                        test_type=f"invalid_params_{test_case['description']}",
                        success=False,
                        error_handling_quality="poor",
                        details={"unexpected_success": True, "test_args": test_case["args"]}
                    )
                except MCPError as e:
                    quality = "excellent" if e.code == -32602 else "good"
                    result = MCPReliabilityTestResult(
                        server_name=server_name,
                        tool_name=tool_name,
                        test_type=f"invalid_params_{test_case['description']}",
                        success=True,
                        error_code=e.code,
                        error_message=str(e),
                        response_time=time.time() - start_time,
                        error_handling_quality=quality
                    )
                except Exception as e:
                    result = MCPReliabilityTestResult(
                        server_name=server_name,
                        tool_name=tool_name,
                        test_type=f"invalid_params_{test_case['description']}",
                        success=False,
                        error_message=str(e),
                        response_time=time.time() - start_time,
                        error_handling_quality="poor",
                        details={"unexpected_error_type": type(e).__name__}
                    )
                
                results.append(result)
                self.test_results.append(result)
        
        return results
    
    async def test_network_failure_resilience(self) -> List[MCPReliabilityTestResult]:
        """Test resilience to network failures."""
        results = []
        
        # Test network-dependent servers
        network_dependent_tools = [
            ("brave", "brave_web_search", {"query": "test"}),
            ("prometheus-monitoring", "prometheus_query", {"query": "up"}),
            ("slack-notifications", "send_notification", {"channel": "test", "message": "test"}),
            ("s3-storage", "s3_list_buckets", {}),
        ]
        
        for server_name, tool_name, args in network_dependent_tools:
            if server_name not in self.registry.servers:
                continue
            
            server = self.registry.servers[server_name]
            
            # Test with connection error
            start_time = time.time()
            
            async def connection_error(*args, **kwargs):
                raise aiohttp.ClientConnectionError("Simulated connection failure")
            
            try:
                with patch('aiohttp.ClientSession.request', side_effect=connection_error):
                    await server.call_tool(tool_name, args)
                
                # Should not reach here
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name=tool_name,
                    test_type="network_failure",
                    success=False,
                    error_handling_quality="poor",
                    details={"unexpected_success": True}
                )
            except MCPError as e:
                quality = "excellent" if "connection" in str(e).lower() else "good"
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name=tool_name,
                    test_type="network_failure",
                    success=True,
                    error_code=e.code,
                    error_message=str(e),
                    response_time=time.time() - start_time,
                    error_handling_quality=quality
                )
            except Exception as e:
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name=tool_name,
                    test_type="network_failure",
                    success=False,
                    error_message=str(e),
                    response_time=time.time() - start_time,
                    error_handling_quality="acceptable",  # Some network errors are acceptable
                    details={"error_type": type(e).__name__}
                )
            
            results.append(result)
            self.test_results.append(result)
        
        return results
    
    async def test_timeout_handling(self) -> List[MCPReliabilityTestResult]:
        """Test timeout handling across servers."""
        results = []
        
        # Test with simulated timeouts
        timeout_tools = [
            ("prometheus-monitoring", "prometheus_query", {"query": "up"}),
            ("brave", "brave_web_search", {"query": "test"}),
        ]
        
        for server_name, tool_name, args in timeout_tools:
            if server_name not in self.registry.servers:
                continue
            
            server = self.registry.servers[server_name]
            start_time = time.time()
            
            async def timeout_error(*args, **kwargs):
                await asyncio.sleep(0.1)  # Small delay
                raise asyncio.TimeoutError("Simulated timeout")
            
            try:
                with patch('aiohttp.ClientSession.request', side_effect=timeout_error):
                    await server.call_tool(tool_name, args)
                
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name=tool_name,
                    test_type="timeout",
                    success=False,
                    error_handling_quality="poor",
                    details={"unexpected_success": True}
                )
            except MCPError as e:
                quality = "excellent" if "timeout" in str(e).lower() else "good"
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name=tool_name,
                    test_type="timeout",
                    success=True,
                    error_code=e.code,
                    error_message=str(e),
                    response_time=time.time() - start_time,
                    error_handling_quality=quality
                )
            except Exception as e:
                result = MCPReliabilityTestResult(
                    server_name=server_name,
                    tool_name=tool_name,
                    test_type="timeout",
                    success=False,
                    error_message=str(e),
                    response_time=time.time() - start_time,
                    error_handling_quality="acceptable",
                    details={"error_type": type(e).__name__}
                )
            
            results.append(result)
            self.test_results.append(result)
        
        return results
    
    async def test_service_dependency_failures(self) -> List[MCPReliabilityTestResult]:
        """Test handling of service dependency failures."""
        results = []
        
        # Test tools that depend on external services
        dependency_tests = [
            {
                "server_name": "docker",
                "tool_name": "docker_ps",
                "args": {"all": False},
                "dependency": "Docker daemon",
                "mock_failure": lambda: patch('asyncio.create_subprocess_shell', side_effect=FileNotFoundError("Docker not found"))
            },
            {
                "server_name": "kubernetes",
                "tool_name": "kubectl_get",
                "args": {"resource_type": "pods"},
                "dependency": "kubectl",
                "mock_failure": lambda: patch('asyncio.create_subprocess_shell', side_effect=FileNotFoundError("kubectl not found"))
            }
        ]
        
        for test in dependency_tests:
            if test["server_name"] not in self.registry.servers:
                continue
            
            server = self.registry.servers[test["server_name"]]
            start_time = time.time()
            
            try:
                with test["mock_failure"]():
                    await server.call_tool(test["tool_name"], test["args"])
                
                result = MCPReliabilityTestResult(
                    server_name=test["server_name"],
                    tool_name=test["tool_name"],
                    test_type="dependency_failure",
                    success=False,
                    error_handling_quality="poor",
                    details={"dependency": test["dependency"], "unexpected_success": True}
                )
            except MCPError as e:
                quality = "excellent" if test["dependency"].lower() in str(e).lower() else "good"
                result = MCPReliabilityTestResult(
                    server_name=test["server_name"],
                    tool_name=test["tool_name"],
                    test_type="dependency_failure",
                    success=True,
                    error_code=e.code,
                    error_message=str(e),
                    response_time=time.time() - start_time,
                    error_handling_quality=quality,
                    details={"dependency": test["dependency"]}
                )
            except Exception as e:
                result = MCPReliabilityTestResult(
                    server_name=test["server_name"],
                    tool_name=test["tool_name"],
                    test_type="dependency_failure",
                    success=False,
                    error_message=str(e),
                    response_time=time.time() - start_time,
                    error_handling_quality="acceptable",
                    details={"dependency": test["dependency"], "error_type": type(e).__name__}
                )
            
            results.append(result)
            self.test_results.append(result)
        
        return results
    
    async def test_circuit_breaker_functionality(self) -> List[MCPReliabilityTestResult]:
        """Test circuit breaker implementation."""
        results = []
        
        # Test Prometheus server circuit breaker specifically
        if "prometheus-monitoring" in self.registry.servers:
            server = self.registry.servers["prometheus-monitoring"]
            
            # Simulate multiple failures to trigger circuit breaker
            failure_count = 0
            circuit_opened = False
            
            async def simulate_failure(*args, **kwargs):
                nonlocal failure_count
                failure_count += 1
                raise aiohttp.ClientError("Simulated service failure")
            
            with patch('aiohttp.ClientSession.request', side_effect=simulate_failure):
                # Make multiple requests to trigger circuit breaker
                for i in range(10):
                    start_time = time.time()
                    
                    try:
                        await server.call_tool("prometheus_query", {"query": "up"})
                    except MCPError as e:
                        if "circuit" in str(e).lower():
                            circuit_opened = True
                            result = MCPReliabilityTestResult(
                                server_name="prometheus-monitoring",
                                tool_name="prometheus_query",
                                test_type="circuit_breaker",
                                success=True,
                                error_code=e.code,
                                error_message=str(e),
                                response_time=time.time() - start_time,
                                error_handling_quality="excellent",
                                details={"circuit_opened_after": i + 1, "failure_count": failure_count}
                            )
                            results.append(result)
                            self.test_results.append(result)
                            break
                    except Exception as e:
                        # Regular failure, continue
                        pass
            
            if not circuit_opened:
                result = MCPReliabilityTestResult(
                    server_name="prometheus-monitoring",
                    tool_name="prometheus_query",
                    test_type="circuit_breaker",
                    success=False,
                    error_handling_quality="poor",
                    details={"circuit_never_opened": True, "failure_count": failure_count}
                )
                results.append(result)
                self.test_results.append(result)
        
        return results
    
    async def test_rate_limiting(self) -> List[MCPReliabilityTestResult]:
        """Test rate limiting implementation."""
        results = []
        
        # Test rate limiting on Prometheus server
        if "prometheus-monitoring" in self.registry.servers:
            server = self.registry.servers["prometheus-monitoring"]
            
            rate_limited = False
            requests_made = 0
            
            # Make rapid requests to trigger rate limiting
            for i in range(150):  # Exceed rate limit
                start_time = time.time()
                
                try:
                    await server.call_tool("prometheus_query", {"query": "up"})
                    requests_made += 1
                except MCPError as e:
                    if "rate limit" in str(e).lower():
                        rate_limited = True
                        result = MCPReliabilityTestResult(
                            server_name="prometheus-monitoring",
                            tool_name="prometheus_query",
                            test_type="rate_limiting",
                            success=True,
                            error_code=e.code,
                            error_message=str(e),
                            response_time=time.time() - start_time,
                            error_handling_quality="excellent",
                            details={"rate_limited_after": requests_made, "request_number": i + 1}
                        )
                        results.append(result)
                        self.test_results.append(result)
                        break
                except Exception as e:
                    # Other error, continue
                    pass
            
            if not rate_limited:
                result = MCPReliabilityTestResult(
                    server_name="prometheus-monitoring",
                    tool_name="prometheus_query",
                    test_type="rate_limiting",
                    success=False,
                    error_handling_quality="poor",
                    details={"rate_limiting_not_triggered": True, "requests_made": requests_made}
                )
                results.append(result)
                self.test_results.append(result)
        
        return results
    
    async def run_comprehensive_reliability_tests(self) -> Dict[str, Any]:
        """Run all reliability tests."""
        logger.info("Starting comprehensive MCP reliability testing...")
        
        test_suites = [
            ("Server Availability", self.test_server_availability),
            ("Invalid Tool Calls", self.test_invalid_tool_calls),
            ("Invalid Parameters", self.test_invalid_parameters),
            ("Network Failures", self.test_network_failure_resilience),
            ("Timeout Handling", self.test_timeout_handling),
            ("Service Dependencies", self.test_service_dependency_failures),
            ("Circuit Breaker", self.test_circuit_breaker_functionality),
            ("Rate Limiting", self.test_rate_limiting),
        ]
        
        test_results = {}
        
        for suite_name, test_func in test_suites:
            logger.info(f"Running {suite_name} tests...")
            
            try:
                suite_results = await test_func()
                test_results[suite_name] = {
                    "results": suite_results,
                    "passed": sum(1 for r in suite_results if r.success),
                    "failed": sum(1 for r in suite_results if not r.success),
                    "total": len(suite_results)
                }
                logger.info(f"{suite_name}: {test_results[suite_name]['passed']}/{test_results[suite_name]['total']} passed")
                
            except Exception as e:
                logger.error(f"Test suite {suite_name} failed: {e}")
                test_results[suite_name] = {
                    "error": str(e),
                    "passed": 0,
                    "failed": 1,
                    "total": 1
                }
        
        # Generate summary
        total_tests = sum(suite["total"] for suite in test_results.values())
        total_passed = sum(suite["passed"] for suite in test_results.values())
        total_failed = sum(suite["failed"] for suite in test_results.values())
        
        summary = {
            "test_timestamp": datetime.utcnow().isoformat(),
            "total_tests": total_tests,
            "passed": total_passed,
            "failed": total_failed,
            "pass_rate": total_passed / total_tests if total_tests > 0 else 0,
            "test_suites": test_results,
            "error_handling_quality": self._analyze_error_handling_quality(),
            "recommendations": self._generate_reliability_recommendations()
        }
        
        # Save results
        with open("mcp_reliability_test_results.json", "w") as f:
            json.dump(summary, f, indent=2, default=str)
        
        return summary
    
    def _analyze_error_handling_quality(self) -> Dict[str, Any]:
        """Analyze overall error handling quality."""
        quality_counts = {"excellent": 0, "good": 0, "acceptable": 0, "poor": 0, "unknown": 0}
        
        for result in self.test_results:
            quality_counts[result.error_handling_quality] += 1
        
        total = len(self.test_results)
        quality_percentages = {k: (v / total * 100) if total > 0 else 0 for k, v in quality_counts.items()}
        
        # Calculate overall grade
        score = (
            quality_counts["excellent"] * 5 +
            quality_counts["good"] * 4 +
            quality_counts["acceptable"] * 3 +
            quality_counts["poor"] * 1 +
            quality_counts["unknown"] * 0
        ) / (total * 5) if total > 0 else 0
        
        if score >= 0.9:
            grade = "A"
        elif score >= 0.8:
            grade = "B"
        elif score >= 0.7:
            grade = "C"
        elif score >= 0.6:
            grade = "D"
        else:
            grade = "F"
        
        return {
            "overall_grade": grade,
            "score": score,
            "quality_distribution": quality_counts,
            "quality_percentages": quality_percentages
        }
    
    def _generate_reliability_recommendations(self) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        # Analyze failure patterns
        failure_types = {}
        for result in self.test_results:
            if not result.success:
                failure_types[result.test_type] = failure_types.get(result.test_type, 0) + 1
        
        # Server-specific issues
        server_issues = {}
        for result in self.test_results:
            if result.error_handling_quality in ["poor", "unknown"]:
                server_issues[result.server_name] = server_issues.get(result.server_name, 0) + 1
        
        # Generate recommendations
        if failure_types.get("invalid_tool", 0) > 0:
            recommendations.append("IMPROVE: Standardize error codes for invalid tool calls across all servers")
        
        if failure_types.get("invalid_params", 0) > 2:
            recommendations.append("CRITICAL: Implement comprehensive parameter validation before tool execution")
        
        if failure_types.get("network_failure", 0) > 1:
            recommendations.append("ENHANCE: Add retry logic and better network error handling")
        
        if failure_types.get("timeout", 0) > 0:
            recommendations.append("IMPROVE: Implement consistent timeout handling across all network operations")
        
        if not any("circuit_breaker" in r.test_type for r in self.test_results if r.success):
            recommendations.append("IMPLEMENT: Add circuit breaker patterns to all network-dependent servers")
        
        if not any("rate_limiting" in r.test_type for r in self.test_results if r.success):
            recommendations.append("IMPLEMENT: Add rate limiting to prevent abuse and resource exhaustion")
        
        for server, issue_count in server_issues.items():
            if issue_count > 2:
                recommendations.append(f"URGENT: Review error handling in {server} server - {issue_count} issues found")
        
        return recommendations
    
    def print_test_summary(self, summary: Dict[str, Any]):
        """Print formatted test summary."""
        print("\n" + "="*80)
        print("MCP RELIABILITY TEST RESULTS")
        print("="*80)
        
        print(f"\nOVERALL RESULTS:")
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Passed: {summary['passed']} ({summary['pass_rate']:.1%})")
        print(f"Failed: {summary['failed']}")
        
        # Error handling quality
        quality = summary["error_handling_quality"]
        print(f"\nERROR HANDLING QUALITY: {quality['overall_grade']} ({quality['score']:.2f}/1.0)")
        print(f"Excellent: {quality['quality_distribution']['excellent']}")
        print(f"Good: {quality['quality_distribution']['good']}")
        print(f"Acceptable: {quality['quality_distribution']['acceptable']}")
        print(f"Poor: {quality['quality_distribution']['poor']}")
        
        # Test suite breakdown
        print(f"\nTEST SUITE BREAKDOWN:")
        for suite_name, suite_results in summary["test_suites"].items():
            if "error" in suite_results:
                print(f"{suite_name}: ERROR - {suite_results['error']}")
            else:
                pass_rate = suite_results["passed"] / suite_results["total"] if suite_results["total"] > 0 else 0
                print(f"{suite_name}: {suite_results['passed']}/{suite_results['total']} ({pass_rate:.1%})")
        
        # Recommendations
        print(f"\nRECOMMENDATIONS:")
        for i, rec in enumerate(summary["recommendations"][:8], 1):  # Top 8
            print(f"{i}. {rec}")
        
        print("\n" + "="*80)
        print(f"Full results saved to: mcp_reliability_test_results.json")
        print("="*80)


async def main():
    """Run MCP reliability validation tests."""
    validator = MCPReliabilityValidator()
    
    try:
        await validator.setup()
        summary = await validator.run_comprehensive_reliability_tests()
        validator.print_test_summary(summary)
        
        print(f"\nMCP reliability testing completed!")
        print(f"Overall reliability grade: {summary['error_handling_quality']['overall_grade']}")
        
        return summary
        
    except Exception as e:
        logger.error(f"Reliability testing failed: {e}")
        raise
    finally:
        await validator.teardown()


if __name__ == "__main__":
    # Run the reliability tests
    asyncio.run(main())