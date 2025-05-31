"""
Custom assertions for more expressive tests.

This module provides custom assertion functions that make tests
more readable and provide better error messages.
"""

from typing import Dict, Any, List, Optional, Union, Callable
from datetime import datetime, timedelta
import json
import re


class AssertionHelpers:
    """Custom assertion helpers for testing."""
    
    @staticmethod
    def assert_valid_uuid(value: str, message: str = None) -> None:
        """Assert that a string is a valid UUID."""
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        assert uuid_pattern.match(value), message or f"Invalid UUID format: {value}"
    
    @staticmethod
    def assert_datetime_close(
        actual: Union[datetime, str],
        expected: Union[datetime, str],
        delta: timedelta = timedelta(seconds=5),
        message: str = None
    ) -> None:
        """Assert that two datetimes are close to each other."""
        if isinstance(actual, str):
            actual = datetime.fromisoformat(actual.replace('Z', '+00:00'))
        if isinstance(expected, str):
            expected = datetime.fromisoformat(expected.replace('Z', '+00:00'))
        
        diff = abs(actual - expected)
        assert diff <= delta, (
            message or f"Datetime difference {diff} exceeds allowed delta {delta}. "
            f"Actual: {actual}, Expected: {expected}"
        )
    
    @staticmethod
    def assert_json_structure(
        actual: Dict[str, Any],
        expected_structure: Dict[str, type],
        message: str = None
    ) -> None:
        """Assert that a JSON object has the expected structure."""
        for key, expected_type in expected_structure.items():
            assert key in actual, message or f"Missing required key: {key}"
            assert isinstance(actual[key], expected_type), (
                message or f"Wrong type for key '{key}': expected {expected_type.__name__}, "
                f"got {type(actual[key]).__name__}"
            )
    
    @staticmethod
    def assert_api_response_success(
        response: Dict[str, Any],
        expected_status: str = "success",
        message: str = None
    ) -> None:
        """Assert that an API response indicates success."""
        assert "status" in response, message or "Response missing 'status' field"
        assert response["status"] == expected_status, (
            message or f"Expected status '{expected_status}', got '{response['status']}'"
        )
        
        if "error" in response:
            assert response["error"] is None, (
                message or f"Response contains error: {response['error']}"
            )
    
    @staticmethod
    def assert_in_range(
        value: Union[int, float],
        min_value: Union[int, float],
        max_value: Union[int, float],
        message: str = None
    ) -> None:
        """Assert that a value is within a specified range."""
        assert min_value <= value <= max_value, (
            message or f"Value {value} not in range [{min_value}, {max_value}]"
        )
    
    @staticmethod
    def assert_performance_metrics(
        metrics: Dict[str, Any],
        max_response_time: float = None,
        min_throughput: float = None,
        max_error_rate: float = None,
        message: str = None
    ) -> None:
        """Assert that performance metrics meet requirements."""
        if max_response_time is not None and "response_time" in metrics:
            assert metrics["response_time"] <= max_response_time, (
                message or f"Response time {metrics['response_time']}s exceeds max {max_response_time}s"
            )
        
        if min_throughput is not None and "throughput" in metrics:
            assert metrics["throughput"] >= min_throughput, (
                message or f"Throughput {metrics['throughput']} below min {min_throughput}"
            )
        
        if max_error_rate is not None and "error_rate" in metrics:
            assert metrics["error_rate"] <= max_error_rate, (
                message or f"Error rate {metrics['error_rate']} exceeds max {max_error_rate}"
            )
    
    @staticmethod
    def assert_expert_response_valid(response: Dict[str, Any], message: str = None) -> None:
        """Assert that an expert response has all required fields and valid values."""
        required_fields = ["content", "confidence", "reasoning", "recommendations"]
        
        for field in required_fields:
            assert field in response, message or f"Expert response missing required field: {field}"
        
        assert 0 <= response["confidence"] <= 1, (
            message or f"Confidence {response['confidence']} not in valid range [0, 1]"
        )
        
        assert isinstance(response["recommendations"], list), (
            message or "Recommendations must be a list"
        )
        
        assert len(response["recommendations"]) > 0, (
            message or "Expert response must include at least one recommendation"
        )
    
    @staticmethod
    def assert_mcp_tool_valid(tool: Dict[str, Any], message: str = None) -> None:
        """Assert that an MCP tool definition is valid."""
        required_fields = ["name", "description", "parameters"]
        
        for field in required_fields:
            assert field in tool, message or f"MCP tool missing required field: {field}"
        
        assert isinstance(tool["parameters"], list), (
            message or "Tool parameters must be a list"
        )
        
        for param in tool["parameters"]:
            assert "name" in param and "type" in param, (
                message or f"Tool parameter missing required fields: {param}"
            )
    
    @staticmethod
    def assert_deployment_successful(
        deployment_result: Dict[str, Any],
        expected_resources: List[str] = None,
        message: str = None
    ) -> None:
        """Assert that a deployment was successful."""
        assert deployment_result.get("status") == "success", (
            message or f"Deployment failed with status: {deployment_result.get('status')}"
        )
        
        if expected_resources:
            deployed = deployment_result.get("resources_created", [])
            for resource in expected_resources:
                assert resource in deployed, (
                    message or f"Expected resource '{resource}' not found in deployment"
                )
    
    @staticmethod
    def assert_security_scan_passed(
        scan_result: Dict[str, Any],
        max_critical: int = 0,
        max_high: int = 0,
        message: str = None
    ) -> None:
        """Assert that security scan results are within acceptable limits."""
        summary = scan_result.get("summary", {})
        
        critical_count = summary.get("critical", 0)
        high_count = summary.get("high", 0)
        
        assert critical_count <= max_critical, (
            message or f"Found {critical_count} critical vulnerabilities, max allowed: {max_critical}"
        )
        
        assert high_count <= max_high, (
            message or f"Found {high_count} high severity vulnerabilities, max allowed: {max_high}"
        )
    
    @staticmethod
    def assert_contains_all(
        container: Union[list, dict, str],
        items: List[Any],
        message: str = None
    ) -> None:
        """Assert that a container contains all specified items."""
        for item in items:
            assert item in container, (
                message or f"Container does not contain required item: {item}"
            )
    
    @staticmethod
    def assert_contains_any(
        container: Union[list, dict, str],
        items: List[Any],
        message: str = None
    ) -> None:
        """Assert that a container contains at least one of the specified items."""
        found = any(item in container for item in items)
        assert found, (
            message or f"Container does not contain any of the required items: {items}"
        )
    
    @staticmethod
    def assert_async_completed_within(
        duration: float,
        expected_max: float,
        message: str = None
    ) -> None:
        """Assert that an async operation completed within expected time."""
        assert duration <= expected_max, (
            message or f"Operation took {duration}s, expected max {expected_max}s"
        )
    
    @staticmethod
    def assert_retry_behavior(
        attempts: int,
        min_attempts: int = 1,
        max_attempts: int = None,
        message: str = None
    ) -> None:
        """Assert that retry behavior is within expected bounds."""
        assert attempts >= min_attempts, (
            message or f"Expected at least {min_attempts} attempts, got {attempts}"
        )
        
        if max_attempts is not None:
            assert attempts <= max_attempts, (
                message or f"Expected at most {max_attempts} attempts, got {attempts}"
            )
    
    @staticmethod
    def assert_log_contains(
        logs: Union[str, List[str]],
        expected_patterns: List[str],
        message: str = None
    ) -> None:
        """Assert that logs contain expected patterns."""
        if isinstance(logs, list):
            logs = '\n'.join(logs)
        
        for pattern in expected_patterns:
            assert re.search(pattern, logs), (
                message or f"Log does not contain expected pattern: {pattern}"
            )
    
    @staticmethod
    def assert_metric_trend(
        metrics: List[float],
        trend: str = "increasing",
        tolerance: float = 0.1,
        message: str = None
    ) -> None:
        """Assert that metrics follow an expected trend."""
        if len(metrics) < 2:
            return
        
        if trend == "increasing":
            for i in range(1, len(metrics)):
                assert metrics[i] >= metrics[i-1] * (1 - tolerance), (
                    message or f"Metric at index {i} ({metrics[i]}) is not increasing from {metrics[i-1]}"
                )
        elif trend == "decreasing":
            for i in range(1, len(metrics)):
                assert metrics[i] <= metrics[i-1] * (1 + tolerance), (
                    message or f"Metric at index {i} ({metrics[i]}) is not decreasing from {metrics[i-1]}"
                )
        elif trend == "stable":
            avg = sum(metrics) / len(metrics)
            for i, value in enumerate(metrics):
                assert abs(value - avg) <= avg * tolerance, (
                    message or f"Metric at index {i} ({value}) deviates too much from average ({avg})"
                )


# Async assertion helpers

async def assert_async_raises(
    exception_type: type,
    async_callable: Callable,
    *args,
    message: str = None,
    **kwargs
) -> None:
    """Assert that an async function raises the expected exception."""
    try:
        await async_callable(*args, **kwargs)
        assert False, message or f"Expected {exception_type.__name__} to be raised"
    except exception_type:
        pass  # Expected
    except Exception as e:
        assert False, (
            message or f"Expected {exception_type.__name__}, got {type(e).__name__}: {e}"
        )


async def assert_async_timeout(
    async_callable: Callable,
    timeout: float,
    *args,
    message: str = None,
    **kwargs
) -> None:
    """Assert that an async function times out."""
    import asyncio
    
    try:
        await asyncio.wait_for(
            async_callable(*args, **kwargs),
            timeout=timeout
        )
        assert False, message or f"Expected timeout after {timeout}s"
    except asyncio.TimeoutError:
        pass  # Expected


# Comparison helpers

def assert_dict_subset(
    subset: Dict[str, Any],
    superset: Dict[str, Any],
    message: str = None
) -> None:
    """Assert that all items in subset exist in superset with same values."""
    for key, value in subset.items():
        assert key in superset, (
            message or f"Key '{key}' not found in superset"
        )
        assert superset[key] == value, (
            message or f"Value mismatch for key '{key}': {superset[key]} != {value}"
        )


def assert_lists_equal_unordered(
    list1: List[Any],
    list2: List[Any],
    message: str = None
) -> None:
    """Assert that two lists contain the same elements regardless of order."""
    assert len(list1) == len(list2), (
        message or f"Lists have different lengths: {len(list1)} != {len(list2)}"
    )
    
    for item in list1:
        assert item in list2, (
            message or f"Item {item} from first list not found in second list"
        )
    
    for item in list2:
        assert item in list1, (
            message or f"Item {item} from second list not found in first list"
        )


def assert_close(
    actual: float,
    expected: float,
    rel_tol: float = 1e-9,
    abs_tol: float = 0.0,
    message: str = None
) -> None:
    """Assert that two float values are close to each other."""
    import math
    assert math.isclose(actual, expected, rel_tol=rel_tol, abs_tol=abs_tol), (
        message or f"Values not close: {actual} != {expected} "
        f"(rel_tol={rel_tol}, abs_tol={abs_tol})"
    )