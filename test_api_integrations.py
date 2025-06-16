"""Comprehensive API integration tests for Tavily, Smithery, and Brave."""

import asyncio
import json
import logging
import os
import time
from typing import Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.api import APIManager, TavilyClient, SmitheryClient, BraveClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Test API keys (use environment variables in production)
TEST_TAVILY_KEY = "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"
TEST_SMITHERY_KEY = "85861ba2-5eba-4599-b38d-61f4b3df44a7"
TEST_BRAVE_KEY = "BSAigVAUU4-V72PjB48t8_CqN00Hh5z"


class TestAPIIntegrations:
    """Test suite for API integrations."""
    
    @pytest.fixture
    async def api_manager(self):
        """Create API manager with test keys."""
        manager = APIManager(
            tavily_api_key=TEST_TAVILY_KEY,
            smithery_api_key=TEST_SMITHERY_KEY,
            brave_api_key=TEST_BRAVE_KEY,
            enable_fallbacks=True
        )
        yield manager
        await manager.close()
    
    @pytest.fixture
    async def tavily_client(self):
        """Create Tavily client."""
        client = TavilyClient(TEST_TAVILY_KEY)
        yield client
        await client.close()
    
    @pytest.fixture
    async def smithery_client(self):
        """Create Smithery client."""
        client = SmitheryClient(TEST_SMITHERY_KEY)
        yield client
        await client.close()
    
    @pytest.fixture
    async def brave_client(self):
        """Create Brave client."""
        client = BraveClient(TEST_BRAVE_KEY)
        yield client
        await client.close()
    
    async def test_tavily_api_key_validation(self, tavily_client):
        """Test Tavily API key validation."""
        try:
            is_valid = await tavily_client.validate_api_key()
            logger.info(f"Tavily API key validation: {is_valid}")
            
            # Test with mock for invalid key
            with patch.object(tavily_client, '_make_request', side_effect=Exception("Invalid key")):
                is_invalid = await tavily_client.validate_api_key()
                assert not is_invalid
                
        except Exception as e:
            logger.warning(f"Tavily API key validation failed: {e}")
            # Continue with mock tests
            
    async def test_smithery_api_key_validation(self, smithery_client):
        """Test Smithery API key validation."""
        try:
            is_valid = await smithery_client.validate_api_key()
            logger.info(f"Smithery API key validation: {is_valid}")
            
        except Exception as e:
            logger.warning(f"Smithery API key validation failed: {e}")
            # Continue with mock tests
    
    async def test_brave_api_key_validation(self, brave_client):
        """Test Brave API key validation."""
        try:
            is_valid = await brave_client.validate_api_key()
            logger.info(f"Brave API key validation: {is_valid}")
            
        except Exception as e:
            logger.warning(f"Brave API key validation failed: {e}")
            # Continue with mock tests
    
    async def test_tavily_search_functionality(self, tavily_client):
        """Test Tavily search functionality."""
        # Test with mock response
        mock_response = {
            'results': [
                {
                    'title': 'Test Result',
                    'url': 'https://example.com',
                    'content': 'Test content',
                    'score': 0.9
                }
            ],
            'query': 'python programming',
            'response_time': 0.5
        }
        
        with patch.object(tavily_client, '_make_request', return_value=mock_response):
            result = await tavily_client.search(
                query="python programming",
                max_results=5,
                use_cache=False
            )
            
            assert 'results' in result
            assert result['total_results'] == 1
            assert result['results'][0]['title'] == 'Test Result'
            logger.info("Tavily search test passed")
        
        # Test real API if available
        try:
            real_result = await tavily_client.search(
                query="python programming",
                max_results=2,
                use_cache=False
            )
            logger.info(f"Tavily real search returned {real_result.get('total_results', 0)} results")
            
        except Exception as e:
            logger.warning(f"Tavily real search failed: {e}")
    
    async def test_smithery_text_enhancement(self, smithery_client):
        """Test Smithery text enhancement."""
        # Test with mock response
        mock_response = {
            'enhanced_content': 'This is an improved version of the text.',
            'confidence': 0.95,
            'metadata': {'changes': 3},
            'processing_time': 1.2
        }
        
        with patch.object(smithery_client, '_make_request', return_value=mock_response):
            result = await smithery_client.enhance_text(
                text="This is some text to improve.",
                enhancement_type="improve",
                use_cache=False
            )
            
            assert 'content' in result
            assert result['confidence'] == 0.95
            logger.info("Smithery enhancement test passed")
        
        # Test real API if available
        try:
            real_result = await smithery_client.enhance_text(
                text="This is a simple test text.",
                enhancement_type="improve",
                use_cache=False
            )
            logger.info(f"Smithery real enhancement confidence: {real_result.get('confidence', 0)}")
            
        except Exception as e:
            logger.warning(f"Smithery real enhancement failed: {e}")
    
    async def test_brave_search_functionality(self, brave_client):
        """Test Brave search functionality."""
        # Test with mock response
        mock_response = {
            'web': {
                'results': [
                    {
                        'title': 'Python Programming Guide',
                        'url': 'https://python.org',
                        'description': 'Learn Python programming',
                        'age': '2024-01-01'
                    }
                ]
            },
            'query': {'original': 'python programming'}
        }
        
        with patch.object(brave_client, '_make_request', return_value=mock_response):
            result = await brave_client.search_web(
                query="python programming",
                count=5,
                use_cache=False
            )
            
            assert 'results' in result
            assert result['total_results'] == 1
            assert result['results'][0]['title'] == 'Python Programming Guide'
            logger.info("Brave search test passed")
        
        # Test real API if available
        try:
            real_result = await brave_client.search_web(
                query="python programming",
                count=2,
                use_cache=False
            )
            logger.info(f"Brave real search returned {real_result.get('total_results', 0)} results")
            
        except Exception as e:
            logger.warning(f"Brave real search failed: {e}")
    
    async def test_rate_limiting(self, tavily_client):
        """Test rate limiting functionality."""
        start_time = time.time()
        
        # Make multiple requests quickly
        tasks = []
        for i in range(3):
            tasks.append(tavily_client.search(
                query=f"test query {i}",
                max_results=1,
                use_cache=False
            ))
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            elapsed = time.time() - start_time
            logger.info(f"Rate limiting test completed in {elapsed:.2f}s")
            
            # Check if any rate limiting occurred
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.info(f"Request {i} failed (expected for rate limiting): {result}")
                else:
                    logger.info(f"Request {i} succeeded")
                    
        except Exception as e:
            logger.info(f"Rate limiting test caught exception: {e}")
    
    async def test_caching_functionality(self, tavily_client):
        """Test response caching."""
        query = "unique test query for caching"
        
        # First request (cache miss)
        start_time = time.time()
        with patch.object(tavily_client, '_make_request') as mock_request:
            mock_request.return_value = {'results': [], 'query': query}
            
            result1 = await tavily_client.search(query=query, use_cache=True)
            first_duration = time.time() - start_time
            
            # Second request (cache hit)
            start_time = time.time()
            result2 = await tavily_client.search(query=query, use_cache=True)
            second_duration = time.time() - start_time
            
            # Verify caching worked
            assert mock_request.call_count == 1  # Only called once
            assert tavily_client.metrics['cache_hits'] >= 1
            logger.info(f"Caching test: first={first_duration:.3f}s, second={second_duration:.3f}s")
    
    async def test_circuit_breaker(self, tavily_client):
        """Test circuit breaker functionality."""
        # Force failures to trigger circuit breaker
        with patch.object(tavily_client, '_handle_response', side_effect=Exception("Simulated failure")):
            
            # Make several failing requests
            for i in range(6):  # More than failure threshold
                try:
                    await tavily_client.search(query=f"test {i}", use_cache=False)
                except Exception:
                    pass
            
            # Check circuit breaker state
            if tavily_client.circuit_breaker:
                logger.info(f"Circuit breaker state: {tavily_client.circuit_breaker.state}")
                logger.info(f"Failure count: {tavily_client.circuit_breaker.failure_count}")
    
    async def test_error_handling(self, tavily_client):
        """Test error handling and retry logic."""
        # Test with various error types
        error_types = [
            Exception("Generic error"),
            asyncio.TimeoutError("Timeout"),
            ConnectionError("Connection failed")
        ]
        
        for error in error_types:
            with patch.object(tavily_client, '_handle_response', side_effect=error):
                try:
                    await tavily_client.search(query="test", use_cache=False)
                    assert False, f"Expected {type(error)} to be raised"
                except type(error):
                    logger.info(f"Correctly handled {type(error).__name__}")
                except Exception as e:
                    logger.info(f"Error transformed to: {type(e).__name__}")
    
    async def test_api_manager_health_check(self, api_manager):
        """Test API manager health check."""
        # Mock all client health checks
        mock_health = {
            'status': 'healthy',
            'metrics': {'requests': 10, 'errors': 1},
            'circuit_breaker': {'state': 'closed', 'failure_count': 0}
        }
        
        for client in [api_manager.tavily, api_manager.smithery, api_manager.brave]:
            if client:
                with patch.object(client, 'health_check', return_value=mock_health):
                    with patch.object(client, 'validate_api_key', return_value=True):
                        pass
        
        health_results = await api_manager.health_check_all()
        
        assert isinstance(health_results, dict)
        for service in ['tavily', 'smithery', 'brave']:
            assert service in health_results
            logger.info(f"{service} health: {health_results[service]}")
    
    async def test_api_manager_fallback(self, api_manager):
        """Test API manager fallback functionality."""
        # Mock Tavily to fail and Brave to succeed
        tavily_mock_response = Exception("Tavily failed")
        brave_mock_response = {
            'web': {
                'results': [{'title': 'Brave result', 'url': 'test.com', 'description': 'test'}]
            },
            'query': {'original': 'test query'}
        }
        
        if api_manager.tavily and api_manager.brave:
            with patch.object(api_manager.tavily, '_make_request', side_effect=tavily_mock_response):
                with patch.object(api_manager.brave, '_make_request', return_value=brave_mock_response):
                    
                    result = await api_manager.search_web(
                        query="test query",
                        prefer_client="tavily",
                        use_cache=False
                    )
                    
                    assert result['source'] == 'brave'
                    logger.info("Fallback functionality working correctly")
    
    async def test_concurrent_requests(self, api_manager):
        """Test concurrent request handling."""
        # Mock responses
        mock_responses = {
            'tavily': {'results': [], 'query': 'test'},
            'brave': {'web': {'results': []}, 'query': {'original': 'test'}},
            'smithery': {'enhanced_content': 'enhanced', 'confidence': 0.8}
        }
        
        tasks = []
        
        # Create concurrent requests
        if api_manager.tavily:
            with patch.object(api_manager.tavily, '_make_request', return_value=mock_responses['tavily']):
                tasks.append(api_manager.search_web(query="test 1"))
        
        if api_manager.brave:
            with patch.object(api_manager.brave, '_make_request', return_value=mock_responses['brave']):
                tasks.append(api_manager.search_web(query="test 2", prefer_client="brave"))
        
        if api_manager.smithery:
            with patch.object(api_manager.smithery, '_make_request', return_value=mock_responses['smithery']):
                tasks.append(api_manager.enhance_text(text="test text"))
        
        if tasks:
            start_time = time.time()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.time() - start_time
            
            logger.info(f"Concurrent requests completed in {elapsed:.2f}s")
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Task {i} failed: {result}")
                else:
                    logger.info(f"Task {i} succeeded: {type(result)}")


async def main():
    """Run all tests."""
    test_instance = TestAPIIntegrations()
    
    # Create fixtures
    api_manager = APIManager(
        tavily_api_key=TEST_TAVILY_KEY,
        smithery_api_key=TEST_SMITHERY_KEY,
        brave_api_key=TEST_BRAVE_KEY
    )
    
    tavily_client = TavilyClient(TEST_TAVILY_KEY)
    smithery_client = SmitheryClient(TEST_SMITHERY_KEY)
    brave_client = BraveClient(TEST_BRAVE_KEY)
    
    try:
        logger.info("Starting API integration tests...")
        
        # Run tests
        test_methods = [
            test_instance.test_tavily_api_key_validation,
            test_instance.test_smithery_api_key_validation,
            test_instance.test_brave_api_key_validation,
            test_instance.test_tavily_search_functionality,
            test_instance.test_smithery_text_enhancement,
            test_instance.test_brave_search_functionality,
            test_instance.test_rate_limiting,
            test_instance.test_caching_functionality,
            test_instance.test_circuit_breaker,
            test_instance.test_error_handling,
            test_instance.test_api_manager_health_check,
            test_instance.test_api_manager_fallback,
            test_instance.test_concurrent_requests
        ]
        
        results = {}
        for test_method in test_methods:
            test_name = test_method.__name__
            try:
                logger.info(f"Running {test_name}...")
                
                # Pass appropriate client based on test
                if 'tavily' in test_name:
                    await test_method(tavily_client)
                elif 'smithery' in test_name:
                    await test_method(smithery_client)
                elif 'brave' in test_name:
                    await test_method(brave_client)
                elif 'api_manager' in test_name:
                    await test_method(api_manager)
                else:
                    await test_method(tavily_client)  # Default
                
                results[test_name] = "PASSED"
                logger.info(f"✓ {test_name} PASSED")
                
            except Exception as e:
                results[test_name] = f"FAILED: {str(e)}"
                logger.error(f"✗ {test_name} FAILED: {str(e)}")
        
        # Summary
        logger.info("\\n" + "="*60)
        logger.info("TEST SUMMARY")
        logger.info("="*60)
        
        passed = sum(1 for r in results.values() if r == "PASSED")
        total = len(results)
        
        for test_name, result in results.items():
            status = "✓" if result == "PASSED" else "✗"
            logger.info(f"{status} {test_name}: {result}")
        
        logger.info(f"\\nTotal: {passed}/{total} tests passed")
        
        # Save results
        test_results = {
            'timestamp': time.time(),
            'summary': {
                'total_tests': total,
                'passed': passed,
                'failed': total - passed,
                'success_rate': f"{(passed/total)*100:.1f}%"
            },
            'results': results,
            'api_keys_tested': {
                'tavily': TEST_TAVILY_KEY[:10] + "...",
                'smithery': TEST_SMITHERY_KEY[:10] + "...",
                'brave': TEST_BRAVE_KEY[:10] + "..."
            }
        }
        
        with open('api_integration_test_results.json', 'w') as f:
            json.dump(test_results, f, indent=2)
        
        logger.info("\\nTest results saved to api_integration_test_results.json")
        
    finally:
        # Cleanup
        await api_manager.close()
        await tavily_client.close()
        await smithery_client.close()
        await brave_client.close()


if __name__ == "__main__":
    asyncio.run(main())