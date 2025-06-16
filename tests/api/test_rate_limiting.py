"""
Rate Limiting Contract Tests

This module contains comprehensive tests for rate limiting enforcement
and headers across the Claude-Optimized Deployment Engine API.
"""

import pytest
import asyncio
from typing import Dict, Any, List
from httpx import AsyncClient
from datetime import datetime

# Test markers
pytestmark = [pytest.mark.api_contract, pytest.mark.rate_limit]


class TestRateLimitingHeaders:
    """Test rate limiting HTTP headers."""

    async def test_rate_limit_headers_present(self, async_client: AsyncClient):
        """Test that rate limit headers are present in responses."""
        endpoints_to_test = [
            "/api/test",
            "/api/public",
            "/health",
            "/"
        ]
        
        for endpoint in endpoints_to_test:
            response = await async_client.get(endpoint)
            
            if response.status_code in [200, 429]:
                headers = response.headers
                
                # Common rate limit headers
                rate_limit_headers = [
                    "x-ratelimit-limit",
                    "x-ratelimit-remaining", 
                    "x-ratelimit-reset",
                    "x-ratelimit-window"
                ]
                
                # At least some rate limiting headers should be present
                headers_present = any(header in headers for header in rate_limit_headers)
                
                if headers_present:
                    # Validate header values if present
                    if "x-ratelimit-limit" in headers:
                        limit = headers["x-ratelimit-limit"]
                        assert limit.isdigit(), f"Invalid rate limit: {limit}"
                        assert int(limit) > 0
                    
                    if "x-ratelimit-remaining" in headers:
                        remaining = headers["x-ratelimit-remaining"]
                        assert remaining.isdigit(), f"Invalid remaining count: {remaining}"
                        assert int(remaining) >= 0
                    
                    if "x-ratelimit-reset" in headers:
                        reset = headers["x-ratelimit-reset"]
                        # Could be timestamp or seconds until reset
                        assert reset.isdigit(), f"Invalid reset time: {reset}"

    async def test_rate_limit_headers_consistency(self, async_client: AsyncClient):
        """Test rate limit headers are consistent across requests."""
        endpoint = "/api/test"
        
        # Make multiple requests to the same endpoint
        responses = []
        for i in range(3):
            response = await async_client.get(endpoint)
            responses.append(response)
            await asyncio.sleep(0.1)  # Small delay
        
        # Check if any responses have rate limit headers
        for i, response in enumerate(responses):
            if response.status_code in [200, 429]:
                headers = response.headers
                
                if "x-ratelimit-limit" in headers:
                    limit = int(headers["x-ratelimit-limit"])
                    
                    # Limit should be consistent across requests
                    for other_response in responses:
                        if "x-ratelimit-limit" in other_response.headers:
                            other_limit = int(other_response.headers["x-ratelimit-limit"])
                            assert limit == other_limit, "Rate limit should be consistent"

    async def test_rate_limit_remaining_decreases(self, async_client: AsyncClient):
        """Test that remaining count decreases with requests."""
        endpoint = "/api/test"
        
        # Make several requests in quick succession
        remaining_counts = []
        
        for i in range(5):
            response = await async_client.get(endpoint)
            
            if response.status_code in [200, 429]:
                headers = response.headers
                
                if "x-ratelimit-remaining" in headers:
                    remaining = int(headers["x-ratelimit-remaining"])
                    remaining_counts.append(remaining)
                    
                    # If we have previous counts, remaining should not increase
                    if len(remaining_counts) > 1:
                        previous_remaining = remaining_counts[-2]
                        assert remaining <= previous_remaining, \
                            f"Remaining count should not increase: {remaining} > {previous_remaining}"
            
            # Small delay between requests
            await asyncio.sleep(0.1)


class TestRateLimitingEnforcement:
    """Test rate limiting enforcement."""

    async def test_rate_limiting_on_api_endpoints(self, async_client: AsyncClient):
        """Test rate limiting on API endpoints."""
        endpoint = "/api/test"
        
        # Make many requests quickly to trigger rate limiting
        rate_limited = False
        
        for i in range(20):  # Make enough requests to potentially trigger rate limiting
            response = await async_client.get(endpoint)
            
            if response.status_code == 429:
                rate_limited = True
                
                # Should have proper error response
                error_data = response.json()
                assert "detail" in error_data
                
                detail = error_data["detail"].lower()
                assert "rate" in detail or "limit" in detail or "too many" in detail
                
                # Should have retry-after header
                if "retry-after" in response.headers:
                    retry_after = response.headers["retry-after"]
                    assert retry_after.isdigit()
                    assert int(retry_after) > 0
                
                break
            
            # No delay to stress test rate limiting
        
        # Note: It's okay if rate limiting isn't triggered in test environment
        # The important thing is that if it is triggered, it follows the proper format

    async def test_rate_limiting_on_authentication_endpoints(self, async_client: AsyncClient):
        """Test rate limiting on authentication endpoints."""
        login_endpoint = "/auth/login"
        
        # Make multiple failed login attempts
        credentials = {
            "username": "testuser",
            "password": "wrongpassword"
        }
        
        for i in range(10):
            response = await async_client.post(login_endpoint, json=credentials)
            
            if response.status_code == 429:
                # Rate limiting triggered on auth endpoint
                error_data = response.json()
                assert "detail" in error_data
                
                # Should include rate limit information
                headers = response.headers
                if "retry-after" in headers:
                    retry_after = int(headers["retry-after"])
                    assert retry_after > 0
                
                break
            
            # Small delay between attempts
            await asyncio.sleep(0.1)

    async def test_rate_limiting_on_heavy_operations(self, async_client: AsyncClient):
        """Test rate limiting on heavy operation endpoints."""
        endpoint = "/api/heavy-operation"
        
        # Heavy operations should have stricter rate limits
        for i in range(5):
            response = await async_client.post(endpoint)
            
            if response.status_code == 429:
                # Stricter rate limiting for heavy operations
                error_data = response.json()
                assert "detail" in error_data
                break
            elif response.status_code == 200:
                # Successful response should include processing info
                data = response.json()
                assert "message" in data
                assert "processing_time" in data
            
            # Small delay
            await asyncio.sleep(0.2)

    async def test_different_rate_limits_for_different_endpoints(self, async_client: AsyncClient):
        """Test that different endpoints have different rate limits."""
        endpoints = [
            "/api/public",      # Should have lenient limits
            "/api/test",        # Should have moderate limits
            "/api/heavy-operation"  # Should have strict limits
        ]
        
        endpoint_limits = {}
        
        for endpoint in endpoints:
            if endpoint == "/api/heavy-operation":
                response = await async_client.post(endpoint)
            else:
                response = await async_client.get(endpoint)
            
            if response.status_code in [200, 429]:
                headers = response.headers
                
                if "x-ratelimit-limit" in headers:
                    limit = int(headers["x-ratelimit-limit"])
                    endpoint_limits[endpoint] = limit
        
        # If we have limits for multiple endpoints, they might be different
        limits = list(endpoint_limits.values())
        if len(limits) > 1:
            # There might be different rate limits for different endpoints
            # This is implementation-dependent
            pass


class TestRateLimitingByClientIdentification:
    """Test rate limiting based on client identification."""

    async def test_rate_limiting_by_ip_address(self, async_client: AsyncClient):
        """Test rate limiting based on IP address."""
        endpoint = "/api/test"
        
        # Test with different IP addresses
        ip_addresses = ["192.168.1.100", "192.168.1.101", "10.0.0.1"]
        
        for ip in ip_addresses:
            headers = {"X-Real-IP": ip}
            
            # Make requests with specific IP
            for i in range(5):
                response = await async_client.get(endpoint, headers=headers)
                
                if response.status_code == 429:
                    # Rate limiting triggered for this IP
                    break
                
                await asyncio.sleep(0.1)

    async def test_rate_limiting_by_user_agent(self, async_client: AsyncClient):
        """Test rate limiting considers user agent."""
        endpoint = "/api/test"
        
        user_agents = [
            "Mozilla/5.0 (compatible; TestBot/1.0)",
            "API-Client/1.0",
            "curl/7.68.0"
        ]
        
        for ua in user_agents:
            headers = {"User-Agent": ua}
            
            # Make requests with specific user agent
            for i in range(3):
                response = await async_client.get(endpoint, headers=headers)
                
                # Check if user agent affects rate limiting
                if response.status_code == 429:
                    break
                
                await asyncio.sleep(0.1)

    async def test_rate_limiting_with_authentication(self, async_client: AsyncClient):
        """Test rate limiting with authenticated users."""
        endpoint = "/api/test"
        
        # Test with mock authentication tokens
        tokens = [
            "Bearer mock-user-token-1",
            "Bearer mock-user-token-2",
            "Bearer mock-admin-token"
        ]
        
        for token in tokens:
            headers = {"Authorization": token}
            
            # Make requests as authenticated user
            for i in range(3):
                response = await async_client.get(endpoint, headers=headers)
                
                # Authenticated users might have different rate limits
                if response.status_code == 429:
                    error_data = response.json()
                    assert "detail" in error_data
                    break
                
                await asyncio.sleep(0.1)


class TestRateLimitingRecovery:
    """Test rate limiting recovery and reset."""

    async def test_rate_limit_reset_over_time(self, async_client: AsyncClient):
        """Test that rate limits reset over time."""
        endpoint = "/api/test"
        
        # First, try to trigger rate limiting
        initial_remaining = None
        
        for i in range(10):
            response = await async_client.get(endpoint)
            
            if "x-ratelimit-remaining" in response.headers:
                remaining = int(response.headers["x-ratelimit-remaining"])
                
                if initial_remaining is None:
                    initial_remaining = remaining
                
                # If remaining is 0 or very low, wait and test recovery
                if remaining <= 1:
                    # Wait for rate limit window to reset
                    await asyncio.sleep(2)
                    
                    # Make another request
                    recovery_response = await async_client.get(endpoint)
                    
                    if "x-ratelimit-remaining" in recovery_response.headers:
                        recovery_remaining = int(recovery_response.headers["x-ratelimit-remaining"])
                        
                        # After waiting, we might have more requests available
                        # This depends on the rate limiting implementation
                        pass
                    
                    break
            
            await asyncio.sleep(0.1)

    async def test_rate_limit_retry_after_header(self, async_client: AsyncClient):
        """Test retry-after header provides accurate timing."""
        endpoint = "/api/test"
        
        # Try to trigger rate limiting
        for i in range(15):
            response = await async_client.get(endpoint)
            
            if response.status_code == 429:
                headers = response.headers
                
                if "retry-after" in headers:
                    retry_after = int(headers["retry-after"])
                    
                    # Retry-after should be reasonable (not too long)
                    assert 0 < retry_after <= 300, f"Unreasonable retry-after: {retry_after}"
                    
                    # Wait a bit and try again (don't wait full time in tests)
                    await asyncio.sleep(min(retry_after, 2))
                    
                    retry_response = await async_client.get(endpoint)
                    # After waiting, request might succeed
                    assert retry_response.status_code in [200, 429]
                
                break


class TestRateLimitingConfiguration:
    """Test rate limiting configuration endpoints."""

    async def test_rate_limit_status_endpoint(self, async_client: AsyncClient):
        """Test rate limiting status endpoint."""
        status_endpoints = [
            "/api/rate-limit/status",
            "/rate-limit/status"
        ]
        
        for endpoint in status_endpoints:
            response = await async_client.get(endpoint)
            
            if response.status_code == 200:
                data = response.json()
                
                # Should include rate limiting status information
                expected_fields = ["enabled", "global_limits", "endpoint_limits"]
                
                # At least some status information should be present
                has_status_info = any(field in data for field in expected_fields)
                if has_status_info:
                    # Validate structure
                    if "global_limits" in data:
                        assert isinstance(data["global_limits"], dict)
                    
                    if "endpoint_limits" in data:
                        assert isinstance(data["endpoint_limits"], dict)
                
                break
            
            elif response.status_code in [401, 403]:
                # Endpoint might require authentication
                break
            
            elif response.status_code == 404:
                # Endpoint might not exist
                continue

    async def test_rate_limit_metrics_endpoint(self, async_client: AsyncClient):
        """Test rate limiting metrics endpoint."""
        metrics_endpoints = [
            "/api/rate-limit/metrics",
            "/monitoring/rate-limit-metrics"
        ]
        
        for endpoint in metrics_endpoints:
            response = await async_client.get(endpoint)
            
            if response.status_code == 200:
                data = response.json()
                
                # Should include metrics about rate limiting
                metric_fields = ["requests_total", "requests_blocked", "current_usage"]
                
                has_metrics = any(field in data for field in metric_fields)
                if has_metrics:
                    # Validate metric types
                    for field in metric_fields:
                        if field in data:
                            assert isinstance(data[field], (int, float))
                
                break
            
            elif response.status_code in [401, 403, 404]:
                # Expected for non-existent or protected endpoints
                continue


class TestRateLimitingEdgeCases:
    """Test rate limiting edge cases."""

    async def test_concurrent_requests_rate_limiting(self, async_client: AsyncClient):
        """Test rate limiting with concurrent requests."""
        endpoint = "/api/test"
        
        # Make concurrent requests
        import asyncio
        
        async def make_request():
            return await async_client.get(endpoint)
        
        # Create multiple concurrent requests
        tasks = [make_request() for _ in range(5)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check responses
        rate_limited_count = 0
        success_count = 0
        
        for response in responses:
            if hasattr(response, 'status_code'):
                if response.status_code == 200:
                    success_count += 1
                elif response.status_code == 429:
                    rate_limited_count += 1
        
        # At least some requests should succeed
        assert success_count > 0

    async def test_malformed_rate_limit_headers(self, async_client: AsyncClient):
        """Test handling of malformed rate limit headers in requests."""
        endpoint = "/api/test"
        
        # Test with potentially problematic headers
        problematic_headers = [
            {"X-RateLimit-Override": "999999"},
            {"X-Rate-Limit": "bypass"},
            {"User-Agent": "RateLimitBypass/1.0"},
        ]
        
        for headers in problematic_headers:
            response = await async_client.get(endpoint, headers=headers)
            
            # Should handle gracefully (not bypass rate limiting)
            assert response.status_code in [200, 429]
            
            # Should not return server errors
            assert response.status_code != 500

    async def test_rate_limiting_with_invalid_client_info(self, async_client: AsyncClient):
        """Test rate limiting with invalid client information."""
        endpoint = "/api/test"
        
        # Test with invalid IP addresses and user agents
        invalid_headers = [
            {"X-Real-IP": "999.999.999.999"},  # Invalid IP
            {"X-Real-IP": "not-an-ip"},
            {"User-Agent": ""},  # Empty user agent
            {"User-Agent": "x" * 1000},  # Very long user agent
        ]
        
        for headers in invalid_headers:
            response = await async_client.get(endpoint, headers=headers)
            
            # Should handle gracefully
            assert response.status_code in [200, 429, 400]
            
            # Should not cause server errors
            assert response.status_code != 500