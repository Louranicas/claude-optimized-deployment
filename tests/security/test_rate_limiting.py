"""
Rate Limiting Security Tests

Tests for rate limiting and DDoS protection following OWASP guidelines.
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from collections import defaultdict
import redis
from fastapi import HTTPException, Request

from src.auth.middleware import RateLimitMiddleware
from src.core.exceptions import RateLimitExceeded


class TestRateLimiting:
    """Test suite for rate limiting mechanisms."""
    
    @pytest.fixture
    def rate_limiter(self):
        """Create RateLimiter instance for testing."""
        return RateLimitMiddleware(
            Mock(),
            requests_per_minute=60,
            requests_per_hour=1000,
            burst_size=10
        )
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request object."""
        request = Mock(spec=Request)
        request.client = Mock()
        request.client.host = "192.168.1.100"
        request.headers = {"User-Agent": "TestClient/1.0"}
        request.url = Mock()
        request.url.path = "/api/test"
        request.method = "GET"
        return request
    
    @pytest.mark.asyncio
    async def test_basic_rate_limiting(self, rate_limiter, mock_request):
        """Test basic rate limiting functionality."""
        async def call_next(request):
            return Mock(status_code=200)
        
        # Make requests up to the limit
        for i in range(60):
            response = await rate_limiter(mock_request, call_next)
            assert response.status_code == 200
        
        # Next request should be rate limited
        with pytest.raises(HTTPException) as exc_info:
            await rate_limiter(mock_request, call_next)
        
        assert exc_info.value.status_code == 429
        assert "Rate limit exceeded" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_burst_protection(self, rate_limiter, mock_request):
        """Test burst request protection."""
        async def call_next(request):
            return Mock(status_code=200)
        
        # Make burst requests
        start_time = time.time()
        burst_count = 0
        
        while time.time() - start_time < 1.0:  # Within 1 second
            try:
                await rate_limiter(mock_request, call_next)
                burst_count += 1
            except HTTPException:
                break
        
        # Should allow burst_size requests
        assert burst_count == rate_limiter.burst_size
    
    @pytest.mark.asyncio
    async def test_per_ip_rate_limiting(self, rate_limiter):
        """Test that rate limiting is applied per IP address."""
        async def call_next(request):
            return Mock(status_code=200)
        
        # Create requests from different IPs
        ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
        
        for ip in ips:
            request = Mock()
            request.client = Mock()
            request.client.host = ip
            request.url = Mock(path="/api/test")
            request.method = "GET"
            
            # Each IP should have its own limit
            for _ in range(rate_limiter.burst_size):
                response = await rate_limiter(request, call_next)
                assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_endpoint_specific_limits(self, rate_limiter):
        """Test different rate limits for different endpoints."""
        rate_limiter.endpoint_limits = {
            "/api/auth/login": {"requests_per_minute": 5},
            "/api/expensive": {"requests_per_minute": 10},
            "/api/public": {"requests_per_minute": 100}
        }
        
        async def call_next(request):
            return Mock(status_code=200)
        
        # Test login endpoint (strict limit)
        login_request = Mock()
        login_request.client = Mock(host="192.168.1.100")
        login_request.url = Mock(path="/api/auth/login")
        login_request.method = "POST"
        
        for i in range(5):
            await rate_limiter(login_request, call_next)
        
        with pytest.raises(HTTPException):
            await rate_limiter(login_request, call_next)
    
    @pytest.mark.asyncio
    async def test_authenticated_user_limits(self, rate_limiter, mock_request):
        """Test different limits for authenticated users."""
        async def call_next(request):
            return Mock(status_code=200)
        
        # Unauthenticated request
        for _ in range(rate_limiter.burst_size):
            await rate_limiter(mock_request, call_next)
        
        with pytest.raises(HTTPException):
            await rate_limiter(mock_request, call_next)
        
        # Authenticated request (higher limit)
        auth_request = Mock()
        auth_request.client = Mock(host="192.168.1.101")
        auth_request.url = Mock(path="/api/test")
        auth_request.method = "GET"
        auth_request.user = Mock(id="user123", role="authenticated")
        
        # Should have higher limit
        for _ in range(rate_limiter.burst_size * 2):
            await rate_limiter(auth_request, call_next)
    
    @pytest.mark.asyncio
    async def test_distributed_rate_limiting(self, rate_limiter):
        """Test distributed rate limiting across multiple instances."""
        # Mock Redis for distributed rate limiting
        with patch('redis.Redis') as mock_redis:
            redis_instance = Mock()
            mock_redis.return_value = redis_instance
            
            # Simulate distributed counter
            redis_instance.incr = Mock(side_effect=range(1, 100))
            redis_instance.expire = Mock()
            
            rate_limiter.use_redis = True
            rate_limiter.redis_client = redis_instance
            
            async def call_next(request):
                return Mock(status_code=200)
            
            # Make requests
            for i in range(60):
                response = await rate_limiter(mock_request, call_next)
                assert response.status_code == 200
            
            # Verify Redis was used
            assert redis_instance.incr.call_count == 60
    
    @pytest.mark.asyncio
    async def test_sliding_window_algorithm(self, rate_limiter, mock_request):
        """Test sliding window rate limiting algorithm."""
        rate_limiter.algorithm = "sliding_window"
        rate_limiter.window_size = 60  # 60 seconds
        rate_limiter.max_requests = 60
        
        async def call_next(request):
            return Mock(status_code=200)
        
        # Make 60 requests over 30 seconds
        for i in range(60):
            await rate_limiter(mock_request, call_next)
            if i % 2 == 0:
                await asyncio.sleep(0.5)
        
        # Wait 30 seconds (half window)
        await asyncio.sleep(30)
        
        # Should be able to make ~30 more requests
        successful_requests = 0
        for _ in range(40):
            try:
                await rate_limiter(mock_request, call_next)
                successful_requests += 1
            except HTTPException:
                break
        
        assert 25 <= successful_requests <= 35
    
    @pytest.mark.asyncio
    async def test_token_bucket_algorithm(self, rate_limiter, mock_request):
        """Test token bucket rate limiting algorithm."""
        rate_limiter.algorithm = "token_bucket"
        rate_limiter.bucket_size = 10
        rate_limiter.refill_rate = 1  # 1 token per second
        
        async def call_next(request):
            return Mock(status_code=200)
        
        # Consume all tokens
        for _ in range(10):
            await rate_limiter(mock_request, call_next)
        
        # Should be rate limited
        with pytest.raises(HTTPException):
            await rate_limiter(mock_request, call_next)
        
        # Wait for refill
        await asyncio.sleep(2)
        
        # Should have 2 tokens now
        await rate_limiter(mock_request, call_next)
        await rate_limiter(mock_request, call_next)
        
        with pytest.raises(HTTPException):
            await rate_limiter(mock_request, call_next)
    
    @pytest.mark.asyncio
    async def test_retry_after_header(self, rate_limiter, mock_request):
        """Test Retry-After header in rate limit responses."""
        async def call_next(request):
            return Mock(status_code=200)
        
        # Exceed rate limit
        for _ in range(rate_limiter.burst_size + 1):
            try:
                await rate_limiter(mock_request, call_next)
            except HTTPException as e:
                assert "Retry-After" in e.headers
                retry_after = int(e.headers["Retry-After"])
                assert 0 < retry_after <= 60
    
    @pytest.mark.asyncio
    async def test_rate_limit_headers(self, rate_limiter, mock_request):
        """Test rate limit information headers."""
        async def call_next(request):
            response = Mock(status_code=200)
            response.headers = {}
            return response
        
        response = await rate_limiter(mock_request, call_next)
        
        # Should include rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers
    
    @pytest.mark.asyncio
    async def test_bypass_for_whitelisted_ips(self, rate_limiter):
        """Test rate limit bypass for whitelisted IPs."""
        rate_limiter.whitelist_ips = ["10.0.0.1", "10.0.0.2"]
        
        async def call_next(request):
            return Mock(status_code=200)
        
        # Whitelisted IP
        whitelist_request = Mock()
        whitelist_request.client = Mock(host="10.0.0.1")
        whitelist_request.url = Mock(path="/api/test")
        whitelist_request.method = "GET"
        
        # Should not be rate limited
        for _ in range(100):
            response = await rate_limiter(whitelist_request, call_next)
            assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_ddos_protection(self, rate_limiter, mock_request):
        """Test DDoS protection mechanisms."""
        # Enable aggressive DDoS protection
        rate_limiter.ddos_protection = True
        rate_limiter.ddos_threshold = 100  # requests per second
        
        async def call_next(request):
            return Mock(status_code=200)
        
        # Simulate DDoS attack
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < 1.0:
            try:
                await rate_limiter(mock_request, call_next)
                request_count += 1
            except HTTPException as e:
                # Should get blocked quickly
                assert e.status_code == 429
                break
        
        assert request_count < rate_limiter.ddos_threshold
    
    @pytest.mark.asyncio
    async def test_gradual_backoff(self, rate_limiter, mock_request):
        """Test gradual backoff for repeated violations."""
        async def call_next(request):
            return Mock(status_code=200)
        
        backoff_times = []
        
        for violation in range(3):
            # Exceed rate limit
            for _ in range(rate_limiter.burst_size + 1):
                try:
                    await rate_limiter(mock_request, call_next)
                except HTTPException as e:
                    if "Retry-After" in e.headers:
                        backoff_times.append(int(e.headers["Retry-After"]))
            
            # Wait before next violation
            await asyncio.sleep(1)
        
        # Backoff times should increase
        assert backoff_times[1] > backoff_times[0]
        assert backoff_times[2] > backoff_times[1]
    
    @pytest.mark.asyncio
    async def test_rate_limit_by_api_key(self, rate_limiter):
        """Test rate limiting by API key."""
        api_key_limits = {
            "basic_key": 100,
            "premium_key": 1000,
            "enterprise_key": 10000
        }
        
        async def call_next(request):
            return Mock(status_code=200)
        
        for api_key, limit in api_key_limits.items():
            request = Mock()
            request.headers = {"X-API-Key": api_key}
            request.client = Mock(host=f"192.168.1.{api_key}")
            request.url = Mock(path="/api/test")
            request.method = "GET"
            
            rate_limiter.api_key_limits = api_key_limits
            
            # Should respect API key specific limit
            # Test a portion of the limit
            test_count = min(limit // 10, 50)
            for _ in range(test_count):
                response = await rate_limiter(request, call_next)
                assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_cost_based_rate_limiting(self, rate_limiter):
        """Test cost-based rate limiting for expensive operations."""
        rate_limiter.enable_cost_based = True
        rate_limiter.cost_limit = 100
        
        endpoint_costs = {
            "/api/cheap": 1,
            "/api/moderate": 10,
            "/api/expensive": 50
        }
        
        async def call_next(request):
            return Mock(status_code=200)
        
        total_cost = 0
        requests_made = 0
        
        while total_cost < rate_limiter.cost_limit:
            endpoint = list(endpoint_costs.keys())[requests_made % 3]
            cost = endpoint_costs[endpoint]
            
            request = Mock()
            request.client = Mock(host="192.168.1.100")
            request.url = Mock(path=endpoint)
            request.method = "GET"
            
            try:
                await rate_limiter(request, call_next)
                total_cost += cost
                requests_made += 1
            except HTTPException:
                break
        
        assert total_cost <= rate_limiter.cost_limit
    
    @pytest.mark.asyncio
    async def test_geographic_rate_limiting(self, rate_limiter):
        """Test geographic-based rate limiting."""
        rate_limiter.geo_limits = {
            "high_risk_countries": 10,
            "medium_risk_countries": 50,
            "low_risk_countries": 100
        }
        
        async def call_next(request):
            return Mock(status_code=200)
        
        # Mock GeoIP lookup
        with patch.object(rate_limiter, 'get_country_from_ip') as mock_geo:
            mock_geo.return_value = "high_risk_countries"
            
            # Should have strict limit
            for i in range(10):
                await rate_limiter(mock_request, call_next)
            
            with pytest.raises(HTTPException):
                await rate_limiter(mock_request, call_next)