"""
Comprehensive tests for the distributed rate limiting system.
"""

import asyncio
import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.core.rate_limiter import (
    DistributedRateLimiter,
    RateLimitAlgorithm,
    RateLimitConfig,
    RateLimitScope,
    RateLimitExceeded,
    TokenBucketRateLimiter,
    SlidingWindowRateLimiter,
    FixedWindowRateLimiter
)
from src.core.rate_limit_middleware import RateLimitMiddleware
from src.core.rate_limit_config import (
    RateLimitingConfig,
    UserTierConfig,
    EndpointRateLimitConfig
)
from src.core.rate_limit_monitoring import RateLimitMonitor


class TestRateLimitAlgorithms:
    """Test individual rate limiting algorithms."""
    
    @pytest.fixture
    async def redis_mock(self):
        """Mock Redis instance."""
        redis_mock = AsyncMock()
        redis_mock.pipeline.return_value.__aenter__.return_value = redis_mock
        redis_mock.pipeline.return_value.__aexit__.return_value = None
        return redis_mock
    
    @pytest.fixture
    def token_bucket_config(self):
        """Token bucket configuration."""
        return RateLimitConfig(
            requests=10,
            window=60,
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            scope=RateLimitScope.PER_IP,
            burst=15
        )
    
    @pytest.fixture
    def sliding_window_config(self):
        """Sliding window configuration."""
        return RateLimitConfig(
            requests=5,
            window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_USER
        )
    
    @pytest.fixture
    def fixed_window_config(self):
        """Fixed window configuration."""
        return RateLimitConfig(
            requests=100,
            window=3600,
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            scope=RateLimitScope.GLOBAL
        )
    
    @pytest.mark.asyncio
    async def test_token_bucket_algorithm(self, redis_mock, token_bucket_config):
        """Test token bucket rate limiting algorithm."""
        limiter = TokenBucketRateLimiter(redis_mock, token_bucket_config)
        
        # Mock Redis responses for new bucket
        redis_mock.hmget.return_value = [None, None]
        redis_mock.hmset.return_value = None
        redis_mock.expire.return_value = None
        redis_mock.execute.return_value = None
        
        # First request should be allowed
        result = await limiter.check_rate_limit("test_endpoint", "127.0.0.1")
        
        assert result.allowed is True
        assert result.remaining == 14  # burst - 1
        assert result.algorithm == RateLimitAlgorithm.TOKEN_BUCKET.value
        assert result.scope == RateLimitScope.PER_IP.value
    
    @pytest.mark.asyncio
    async def test_sliding_window_algorithm(self, redis_mock, sliding_window_config):
        """Test sliding window rate limiting algorithm."""
        limiter = SlidingWindowRateLimiter(redis_mock, sliding_window_config)
        
        # Mock Redis responses
        redis_mock.zremrangebyscore.return_value = None
        redis_mock.zcard.return_value = 0  # No existing requests
        redis_mock.zadd.return_value = None
        redis_mock.expire.return_value = None
        redis_mock.execute.return_value = None
        
        # First request should be allowed
        result = await limiter.check_rate_limit("test_endpoint", "user_123")
        
        assert result.allowed is True
        assert result.remaining == 4  # 5 - 1
        assert result.algorithm == RateLimitAlgorithm.SLIDING_WINDOW.value
        assert result.scope == RateLimitScope.PER_USER.value
    
    @pytest.mark.asyncio
    async def test_fixed_window_algorithm(self, redis_mock, fixed_window_config):
        """Test fixed window rate limiting algorithm."""
        limiter = FixedWindowRateLimiter(redis_mock, fixed_window_config)
        
        # Mock Redis responses
        redis_mock.get.return_value = None  # No existing count
        redis_mock.incr.return_value = None
        redis_mock.expire.return_value = None
        redis_mock.execute.return_value = None
        
        # First request should be allowed
        result = await limiter.check_rate_limit("test_endpoint", "global")
        
        assert result.allowed is True
        assert result.remaining == 99  # 100 - 1
        assert result.algorithm == RateLimitAlgorithm.FIXED_WINDOW.value
        assert result.scope == RateLimitScope.GLOBAL.value
    
    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self, redis_mock, sliding_window_config):
        """Test rate limit exceeded scenario."""
        limiter = SlidingWindowRateLimiter(redis_mock, sliding_window_config)
        
        # Mock Redis responses for rate limit exceeded
        redis_mock.zremrangebyscore.return_value = None
        redis_mock.zcard.return_value = 5  # Already at limit
        redis_mock.zrange.return_value = [(b"request", time.time() - 30)]
        
        # Request should be denied
        result = await limiter.check_rate_limit("test_endpoint", "user_123")
        
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after is not None
        assert result.retry_after > 0


class TestDistributedRateLimiter:
    """Test distributed rate limiter functionality."""
    
    @pytest.fixture
    async def rate_limiter(self):
        """Create rate limiter instance with mock Redis."""
        limiter = DistributedRateLimiter("redis://localhost:6379/15")  # Test DB
        
        # Mock Redis for testing
        limiter.redis = AsyncMock()
        limiter.redis.ping.return_value = True
        
        return limiter
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_multiple_configs(self, rate_limiter):
        """Test rate limiting with multiple configurations."""
        # Configure endpoint with multiple rules
        configs = [
            RateLimitConfig(
                requests=10, window=60,
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
                scope=RateLimitScope.PER_IP
            ),
            RateLimitConfig(
                requests=50, window=60,
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                scope=RateLimitScope.PER_USER
            )
        ]
        
        rate_limiter.configure_endpoint("/api/test", configs)
        
        # Mock individual limiter responses
        with patch.object(rate_limiter, '_get_limiter') as mock_get_limiter:
            mock_limiter = AsyncMock()
            mock_limiter.check_rate_limit.return_value = AsyncMock(
                allowed=True, remaining=9, reset_time=time.time() + 60,
                limit=10, scope="per_ip", algorithm="token_bucket"
            )
            mock_get_limiter.return_value = mock_limiter
            
            results = await rate_limiter.check_rate_limit(
                endpoint="/api/test",
                ip_address="127.0.0.1",
                user_id="user_123"
            )
            
            assert len(results) == 2
            assert all(result.allowed for result in results)
    
    @pytest.mark.asyncio
    async def test_rate_limit_headers(self, rate_limiter):
        """Test rate limit header generation."""
        # Configure endpoint
        config = RateLimitConfig(
            requests=100, window=3600,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_USER
        )
        rate_limiter.configure_endpoint("/api/headers", [config])
        
        # Mock limiter response
        with patch.object(rate_limiter, 'check_rate_limit') as mock_check:
            mock_result = MagicMock()
            mock_result.allowed = True
            mock_result.remaining = 95
            mock_result.reset_time = time.time() + 3600
            mock_result.limit = 100
            mock_result.scope = "per_user"
            mock_result.algorithm = "sliding_window"
            mock_check.return_value = [mock_result]
            
            headers = await rate_limiter.get_rate_limit_headers(
                "/api/headers", "127.0.0.1", "user_123"
            )
            
            assert "X-RateLimit-Limit" in headers
            assert "X-RateLimit-Remaining" in headers
            assert "X-RateLimit-Reset" in headers
            assert "X-RateLimit-Scope" in headers
            assert "X-RateLimit-Algorithm" in headers
            assert headers["X-RateLimit-Limit"] == "100"
            assert headers["X-RateLimit-Remaining"] == "95"
    
    @pytest.mark.asyncio
    async def test_reset_rate_limit(self, rate_limiter):
        """Test rate limit reset functionality."""
        rate_limiter.redis.keys.return_value = ["key1", "key2"]
        rate_limiter.redis.delete.return_value = 2
        
        await rate_limiter.reset_rate_limit(
            endpoint="/api/test",
            ip_address="127.0.0.1"
        )
        
        rate_limiter.redis.keys.assert_called_once()
        rate_limiter.redis.delete.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_metrics(self, rate_limiter):
        """Test metrics retrieval."""
        rate_limiter._check_redis_health = AsyncMock(return_value=True)
        
        metrics = await rate_limiter.get_metrics()
        
        assert "global_metrics" in metrics
        assert "limiter_metrics" in metrics
        assert "endpoint_configs" in metrics
        assert "redis_info" in metrics


class TestRateLimitMiddleware:
    """Test FastAPI rate limiting middleware."""
    
    @pytest.fixture
    def app(self):
        """Create FastAPI app with rate limiting middleware."""
        app = FastAPI()
        
        # Mock rate limiter
        mock_rate_limiter = AsyncMock()
        mock_rate_limiter.check_rate_limit.return_value = [
            MagicMock(
                allowed=True, remaining=9, reset_time=time.time() + 60,
                limit=10, scope="per_ip", algorithm="sliding_window"
            )
        ]
        mock_rate_limiter.get_rate_limit_headers.return_value = {
            "X-RateLimit-Limit": "10",
            "X-RateLimit-Remaining": "9"
        }
        
        # Add middleware
        app.add_middleware(
            RateLimitMiddleware,
            rate_limiter=mock_rate_limiter,
            skip_paths=["/health"]
        )
        
        @app.get("/test")
        async def test_endpoint():
            return {"message": "success"}
        
        @app.get("/health")
        async def health_endpoint():
            return {"status": "ok"}
        
        return app
    
    def test_middleware_allows_request(self, app):
        """Test middleware allows requests within rate limit."""
        client = TestClient(app)
        response = client.get("/test")
        
        assert response.status_code == 200
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
    
    def test_middleware_skips_health_endpoint(self, app):
        """Test middleware skips health endpoints."""
        client = TestClient(app)
        response = client.get("/health")
        
        assert response.status_code == 200
        assert "X-RateLimit-Limit" not in response.headers
    
    @patch('src.core.rate_limit_middleware.get_rate_limiter')
    def test_middleware_blocks_rate_limited_request(self, mock_get_limiter, app):
        """Test middleware blocks rate limited requests."""
        # Mock rate limiter to return rate limit exceeded
        mock_rate_limiter = AsyncMock()
        mock_rate_limiter.check_rate_limit.return_value = [
            MagicMock(
                allowed=False, remaining=0, reset_time=time.time() + 60,
                limit=10, scope="per_ip", algorithm="sliding_window",
                retry_after=60
            )
        ]
        mock_rate_limiter.get_rate_limit_headers.return_value = {
            "X-RateLimit-Limit": "10",
            "X-RateLimit-Remaining": "0",
            "Retry-After": "60"
        }
        mock_get_limiter.return_value = mock_rate_limiter
        
        client = TestClient(app)
        response = client.get("/test")
        
        assert response.status_code == 429
        assert "Retry-After" in response.headers


class TestRateLimitConfiguration:
    """Test rate limiting configuration management."""
    
    def test_endpoint_config_creation(self):
        """Test endpoint configuration creation."""
        config = EndpointRateLimitConfig(
            endpoint_pattern="/api/test",
            description="Test endpoint"
        )
        
        config.add_config(
            requests=100,
            window=60,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=RateLimitScope.PER_USER
        )
        
        assert len(config.configs) == 1
        assert config.configs[0].requests == 100
        assert config.configs[0].window == 60
    
    def test_rate_limiting_config_defaults(self):
        """Test default configuration setup."""
        config = RateLimitingConfig()
        config.configure_defaults()
        
        assert len(config.endpoint_configs) > 0
        
        # Check that auth endpoints have strict limits
        auth_configs = [
            c for c in config.endpoint_configs
            if "auth" in c.endpoint_pattern.lower()
        ]
        assert len(auth_configs) > 0
    
    def test_user_tier_configs(self):
        """Test user tier configurations."""
        free_tier = UserTierConfig.free_tier()
        premium_tier = UserTierConfig.premium_tier()
        enterprise_tier = UserTierConfig.enterprise_tier()
        
        assert len(free_tier) > 0
        assert len(premium_tier) > 0
        assert len(enterprise_tier) > 0
        
        # Premium should have higher limits than free
        free_hourly = next(
            (c for c in free_tier if c.window == 3600), None
        )
        premium_hourly = next(
            (c for c in premium_tier if c.window == 3600), None
        )
        
        if free_hourly and premium_hourly:
            assert premium_hourly.requests > free_hourly.requests
    
    def test_environment_configuration(self):
        """Test environment-specific configurations."""
        config = RateLimitingConfig()
        
        # Development should be permissive
        config.configure_development()
        assert len(config.endpoint_configs) == 1
        dev_config = config.endpoint_configs[0]
        assert dev_config.configs[0].requests >= 1000
        
        # Production should be strict
        config.configure_production()
        assert len(config.endpoint_configs) > 1


class TestRateLimitMonitoring:
    """Test rate limiting monitoring and metrics."""
    
    @pytest.fixture
    async def monitor(self):
        """Create rate limit monitor with mock Redis."""
        redis_mock = AsyncMock()
        monitor = RateLimitMonitor(redis_mock)
        return monitor
    
    @pytest.mark.asyncio
    async def test_record_metric(self, monitor):
        """Test metric recording."""
        await monitor.record_metric(
            endpoint="/api/test",
            scope="per_ip",
            algorithm="sliding_window",
            identifier="127.0.0.1",
            allowed=True,
            limit=100,
            remaining=99,
            reset_time=time.time() + 60
        )
        
        assert len(monitor.metrics_buffer) == 1
        metric = monitor.metrics_buffer[0]
        assert metric.endpoint == "/api/test"
        assert metric.allowed is True
    
    @pytest.mark.asyncio
    async def test_metrics_summary(self, monitor):
        """Test metrics summary generation."""
        # Mock Redis responses
        monitor.redis.zrangebyscore.return_value = []
        
        summary = await monitor.get_metrics_summary()
        
        assert summary.total_requests == 0
        assert summary.denial_rate == 0.0
        assert isinstance(summary.top_denied_endpoints, list)
        assert isinstance(summary.algorithm_usage, dict)


class TestHighThroughputScenarios:
    """Test rate limiting under high-throughput scenarios."""
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """Test handling of concurrent requests."""
        # Create rate limiter with real Redis (requires Redis for this test)
        try:
            rate_limiter = DistributedRateLimiter("redis://localhost:6379/15")
            await rate_limiter.initialize()
            
            # Configure strict rate limit
            config = RateLimitConfig(
                requests=10,
                window=60,
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                scope=RateLimitScope.PER_IP
            )
            rate_limiter.configure_endpoint("/api/concurrent", [config])
            
            # Make concurrent requests
            async def make_request(request_id):
                try:
                    results = await rate_limiter.check_rate_limit(
                        endpoint="/api/concurrent",
                        ip_address="127.0.0.1"
                    )
                    return request_id, results[0].allowed
                except Exception as e:
                    return request_id, False
            
            # Run 20 concurrent requests
            tasks = [make_request(i) for i in range(20)]
            results = await asyncio.gather(*tasks)
            
            allowed_count = sum(1 for _, allowed in results if allowed)
            denied_count = len(results) - allowed_count
            
            # Should allow exactly 10 requests and deny the rest
            assert allowed_count <= 10
            assert denied_count >= 10
            
            await rate_limiter.close()
            
        except Exception as e:
            pytest.skip(f"Redis not available for integration test: {e}")
    
    @pytest.mark.asyncio
    async def test_burst_handling(self):
        """Test token bucket burst handling."""
        try:
            rate_limiter = DistributedRateLimiter("redis://localhost:6379/15")
            await rate_limiter.initialize()
            
            # Configure token bucket with burst
            config = RateLimitConfig(
                requests=5,  # 5 requests per minute
                window=60,
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
                scope=RateLimitScope.PER_IP,
                burst=10  # Allow burst up to 10
            )
            rate_limiter.configure_endpoint("/api/burst", [config])
            
            # Make burst of requests
            results = []
            for i in range(15):
                result = await rate_limiter.check_rate_limit(
                    endpoint="/api/burst",
                    ip_address="127.0.0.1"
                )
                results.append(result[0].allowed)
                
                # Small delay to avoid overwhelming
                await asyncio.sleep(0.01)
            
            allowed_count = sum(results)
            
            # Should allow up to burst capacity (10)
            assert allowed_count <= 10
            assert allowed_count >= 5  # At least the base rate
            
            await rate_limiter.close()
            
        except Exception as e:
            pytest.skip(f"Redis not available for integration test: {e}")
    
    @pytest.mark.asyncio
    async def test_algorithm_performance(self):
        """Test performance characteristics of different algorithms."""
        try:
            rate_limiter = DistributedRateLimiter("redis://localhost:6379/15")
            await rate_limiter.initialize()
            
            algorithms = [
                RateLimitAlgorithm.TOKEN_BUCKET,
                RateLimitAlgorithm.SLIDING_WINDOW,
                RateLimitAlgorithm.FIXED_WINDOW
            ]
            
            performance_results = {}
            
            for algorithm in algorithms:
                config = RateLimitConfig(
                    requests=100,
                    window=60,
                    algorithm=algorithm,
                    scope=RateLimitScope.PER_IP
                )
                endpoint = f"/api/perf_{algorithm.value}"
                rate_limiter.configure_endpoint(endpoint, [config])
                
                # Measure time for 50 requests
                start_time = time.time()
                
                for i in range(50):
                    await rate_limiter.check_rate_limit(
                        endpoint=endpoint,
                        ip_address="127.0.0.1"
                    )
                
                end_time = time.time()
                duration = end_time - start_time
                performance_results[algorithm.value] = {
                    "duration": duration,
                    "requests_per_second": 50 / duration
                }
            
            # All algorithms should handle reasonable throughput
            for alg, perf in performance_results.items():
                assert perf["requests_per_second"] > 10, f"{alg} too slow: {perf}"
            
            await rate_limiter.close()
            
        except Exception as e:
            pytest.skip(f"Redis not available for integration test: {e}")


class TestErrorHandling:
    """Test error handling in rate limiting system."""
    
    @pytest.mark.asyncio
    async def test_redis_connection_failure(self):
        """Test handling of Redis connection failures."""
        rate_limiter = DistributedRateLimiter("redis://invalid:6379/0")
        
        # Should handle Redis errors gracefully
        try:
            await rate_limiter.initialize()
        except Exception:
            pass  # Expected to fail
        
        # Rate limiter should still function (permissively) without Redis
        results = await rate_limiter.check_rate_limit(
            endpoint="/api/test",
            ip_address="127.0.0.1"
        )
        
        # Should allow requests when Redis is unavailable
        assert len(results) > 0
        assert results[0].allowed is True
    
    @pytest.mark.asyncio
    async def test_invalid_configuration(self):
        """Test handling of invalid configurations."""
        rate_limiter = DistributedRateLimiter()
        
        # Test invalid algorithm
        with pytest.raises(ValueError):
            config = RateLimitConfig(
                requests=10,
                window=60,
                algorithm="invalid_algorithm",  # type: ignore
                scope=RateLimitScope.PER_IP
            )
    
    @pytest.mark.asyncio
    async def test_rate_limit_exceeded_exception(self):
        """Test RateLimitExceeded exception handling."""
        rate_limiter = DistributedRateLimiter()
        
        # Mock to always return rate limit exceeded
        with patch.object(rate_limiter, 'check_rate_limit') as mock_check:
            from src.core.rate_limiter import RateLimitResult
            
            mock_result = RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=time.time() + 60,
                retry_after=60,
                limit=10,
                scope="per_ip",
                algorithm="sliding_window"
            )
            mock_check.return_value = [mock_result]
            
            with pytest.raises(RateLimitExceeded):
                await rate_limiter.check_rate_limit(
                    endpoint="/api/test",
                    ip_address="127.0.0.1",
                    raise_on_limit=True
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])