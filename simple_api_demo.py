#!/usr/bin/env python3
"""
Simplified API integration demo that works standalone.
Demonstrates Tavily, Smithery, and Brave API integrations.
"""

import asyncio
import aiohttp
import json
import logging
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Test API keys
TAVILY_KEY = "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"
SMITHERY_KEY = "85861ba2-5eba-4599-b38d-61f4b3df44a7"
BRAVE_KEY = "BSAigVAUU4-V72PjB48t8_CqN00Hh5z"


@dataclass
class APIResponse:
    """Standard API response structure."""
    success: bool
    data: Any
    error: Optional[str] = None
    source: Optional[str] = None
    response_time: Optional[float] = None


class SimpleAPIClient:
    """Simplified API client base class."""
    
    def __init__(self, name: str, base_url: str, headers: Dict[str, str]):
        self.name = name
        self.base_url = base_url.rstrip('/')
        self.headers = headers
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers=self.headers
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def request(self, method: str, endpoint: str, **kwargs) -> APIResponse:
        """Make HTTP request and return standardized response."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        start_time = time.time()
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                response_time = time.time() - start_time
                
                try:
                    data = await response.json()
                except:
                    data = {"text": await response.text()}
                
                if response.status >= 400:
                    error_msg = data.get('error', data.get('message', f"HTTP {response.status}"))
                    return APIResponse(
                        success=False,
                        data=None,
                        error=error_msg,
                        source=self.name,
                        response_time=response_time
                    )
                
                return APIResponse(
                    success=True,
                    data=data,
                    error=None,
                    source=self.name,
                    response_time=response_time
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return APIResponse(
                success=False,
                data=None,
                error=str(e),
                source=self.name,
                response_time=response_time
            )


class TavilyAPI:
    """Simplified Tavily API client."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = SimpleAPIClient(
            name="Tavily",
            base_url="https://api.tavily.com",
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'Claude-API-Demo/1.0'
            }
        )
    
    async def __aenter__(self):
        await self.client.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.__aexit__(exc_type, exc_val, exc_tb)
    
    async def search(self, query: str, max_results: int = 5) -> APIResponse:
        """Search the web using Tavily."""
        payload = {
            "api_key": self.api_key,
            "query": query,
            "search_depth": "basic",
            "max_results": max_results,
            "include_answer": True
        }
        
        response = await self.client.request('POST', '/search', json=payload)
        
        if response.success and response.data:
            # Process Tavily response
            results = response.data.get('results', [])
            processed_data = {
                'query': query,
                'total_results': len(results),
                'results': results[:max_results],
                'answer': response.data.get('answer', '')
            }
            response.data = processed_data
        
        return response


class SmitheryAPI:
    """Simplified Smithery API client."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = SimpleAPIClient(
            name="Smithery",
            base_url="https://api.smithery.ai",
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json',
                'User-Agent': 'Claude-API-Demo/1.0'
            }
        )
    
    async def __aenter__(self):
        await self.client.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.__aexit__(exc_type, exc_val, exc_tb)
    
    async def enhance_text(self, text: str, enhancement_type: str = "improve") -> APIResponse:
        """Enhance text using Smithery AI."""
        payload = {
            "text": text,
            "enhancement_type": enhancement_type
        }
        
        response = await self.client.request('POST', '/enhance/text', json=payload)
        
        if response.success and response.data:
            # Process Smithery response
            processed_data = {
                'original': text,
                'enhanced': response.data.get('enhanced_content', text),
                'confidence': response.data.get('confidence', 0.0),
                'enhancement_type': enhancement_type
            }
            response.data = processed_data
        
        return response


class BraveAPI:
    """Simplified Brave Search API client."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = SimpleAPIClient(
            name="Brave",
            base_url="https://api.search.brave.com",
            headers={
                'X-Subscription-Token': api_key,
                'Accept': 'application/json',
                'User-Agent': 'Claude-API-Demo/1.0'
            }
        )
    
    async def __aenter__(self):
        await self.client.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.__aexit__(exc_type, exc_val, exc_tb)
    
    async def search_web(self, query: str, count: int = 5) -> APIResponse:
        """Search the web using Brave."""
        params = {
            'q': query,
            'count': min(count, 20),  # API limit
            'safesearch': 'moderate'
        }
        
        response = await self.client.request('GET', '/res/v1/web/search', params=params)
        
        if response.success and response.data:
            # Process Brave response
            web_results = response.data.get('web', {}).get('results', [])
            processed_data = {
                'query': query,
                'total_results': len(web_results),
                'results': [
                    {
                        'title': result.get('title', ''),
                        'url': result.get('url', ''),
                        'description': result.get('description', '')
                    }
                    for result in web_results[:count]
                ]
            }
            response.data = processed_data
        
        return response


class APIIntegrationDemo:
    """Main demo class showcasing all API integrations."""
    
    def __init__(self):
        self.results = {}
    
    async def test_api_keys(self):
        """Test API key validity by making simple requests."""
        logger.info("="*60)
        logger.info("API KEY VALIDATION")
        logger.info("="*60)
        
        # Test Tavily
        try:
            async with TavilyAPI(TAVILY_KEY) as tavily:
                result = await tavily.search("test", max_results=1)
                tavily_status = "✓ VALID" if result.success else f"✗ INVALID: {result.error}"
                logger.info(f"Tavily API Key: {tavily_status}")
                self.results['tavily_key_valid'] = result.success
        except Exception as e:
            logger.info(f"Tavily API Key: ✗ ERROR: {e}")
            self.results['tavily_key_valid'] = False
        
        # Test Smithery
        try:
            async with SmitheryAPI(SMITHERY_KEY) as smithery:
                result = await smithery.enhance_text("test text")
                smithery_status = "✓ VALID" if result.success else f"✗ INVALID: {result.error}"
                logger.info(f"Smithery API Key: {smithery_status}")
                self.results['smithery_key_valid'] = result.success
        except Exception as e:
            logger.info(f"Smithery API Key: ✗ ERROR: {e}")
            self.results['smithery_key_valid'] = False
        
        # Test Brave
        try:
            async with BraveAPI(BRAVE_KEY) as brave:
                result = await brave.search_web("test", count=1)
                brave_status = "✓ VALID" if result.success else f"✗ INVALID: {result.error}"
                logger.info(f"Brave API Key: {brave_status}")
                self.results['brave_key_valid'] = result.success
        except Exception as e:
            logger.info(f"Brave API Key: ✗ ERROR: {e}")
            self.results['brave_key_valid'] = False
    
    async def demo_web_search(self):
        """Demonstrate web search capabilities."""
        logger.info("\\n" + "="*60)
        logger.info("WEB SEARCH DEMONSTRATION")
        logger.info("="*60)
        
        query = "Python async programming best practices"
        logger.info(f"Search Query: '{query}'")
        
        # Try Tavily first
        try:
            async with TavilyAPI(TAVILY_KEY) as tavily:
                result = await tavily.search(query, max_results=3)
                if result.success:
                    data = result.data
                    logger.info(f"\\n✓ Tavily Results ({result.response_time:.2f}s):")
                    logger.info(f"  Total Results: {data['total_results']}")
                    for i, r in enumerate(data['results'][:2], 1):
                        logger.info(f"  {i}. {r.get('title', 'No title')}")
                        logger.info(f"     {r.get('url', 'No URL')}")
                    if data.get('answer'):
                        logger.info(f"  AI Answer: {data['answer'][:100]}...")
                    self.results['tavily_search'] = {'success': True, 'time': result.response_time}
                else:
                    logger.info(f"✗ Tavily Failed: {result.error}")
                    self.results['tavily_search'] = {'success': False, 'error': result.error}
        except Exception as e:
            logger.info(f"✗ Tavily Error: {e}")
            self.results['tavily_search'] = {'success': False, 'error': str(e)}
        
        # Try Brave as fallback
        try:
            async with BraveAPI(BRAVE_KEY) as brave:
                result = await brave.search_web(query, count=3)
                if result.success:
                    data = result.data
                    logger.info(f"\\n✓ Brave Results ({result.response_time:.2f}s):")
                    logger.info(f"  Total Results: {data['total_results']}")
                    for i, r in enumerate(data['results'][:2], 1):
                        logger.info(f"  {i}. {r.get('title', 'No title')}")
                        logger.info(f"     {r.get('url', 'No URL')}")
                    self.results['brave_search'] = {'success': True, 'time': result.response_time}
                else:
                    logger.info(f"✗ Brave Failed: {result.error}")
                    self.results['brave_search'] = {'success': False, 'error': result.error}
        except Exception as e:
            logger.info(f"✗ Brave Error: {e}")
            self.results['brave_search'] = {'success': False, 'error': str(e)}
    
    async def demo_text_enhancement(self):
        """Demonstrate text enhancement capabilities."""
        logger.info("\\n" + "="*60)
        logger.info("TEXT ENHANCEMENT DEMONSTRATION")
        logger.info("="*60)
        
        test_texts = [
            {"text": "This API is good.", "type": "improve"},
            {"text": "Python is a programming language used for web development, data science, machine learning, and automation. It has simple syntax and extensive libraries.", "type": "summarize"}
        ]
        
        try:
            async with SmitheryAPI(SMITHERY_KEY) as smithery:
                for i, test in enumerate(test_texts, 1):
                    logger.info(f"\\nTest {i} - {test['type'].title()}:")
                    logger.info(f"  Original: {test['text']}")
                    
                    result = await smithery.enhance_text(test['text'], test['type'])
                    
                    if result.success:
                        data = result.data
                        logger.info(f"  Enhanced: {data['enhanced']}")
                        logger.info(f"  Confidence: {data['confidence']:.2f}")
                        logger.info(f"  Time: {result.response_time:.2f}s")
                        
                        self.results[f'smithery_enhance_{i}'] = {
                            'success': True,
                            'confidence': data['confidence'],
                            'time': result.response_time
                        }
                    else:
                        logger.info(f"  ✗ Failed: {result.error}")
                        self.results[f'smithery_enhance_{i}'] = {'success': False, 'error': result.error}
        except Exception as e:
            logger.info(f"✗ Smithery Error: {e}")
            self.results['smithery_enhance'] = {'success': False, 'error': str(e)}
    
    async def demo_concurrent_requests(self):
        """Demonstrate concurrent API requests."""
        logger.info("\\n" + "="*60)
        logger.info("CONCURRENT REQUESTS DEMONSTRATION")
        logger.info("="*60)
        
        start_time = time.time()
        
        # Create concurrent tasks
        tasks = []
        
        # Tavily search
        async def tavily_task():
            async with TavilyAPI(TAVILY_KEY) as tavily:
                return await tavily.search("concurrent API test", max_results=2)
        
        # Smithery enhancement
        async def smithery_task():
            async with SmitheryAPI(SMITHERY_KEY) as smithery:
                return await smithery.enhance_text("This is a concurrent test.", "improve")
        
        # Brave search
        async def brave_task():
            async with BraveAPI(BRAVE_KEY) as brave:
                return await brave.search_web("concurrent processing", count=2)
        
        tasks = [tavily_task(), smithery_task(), brave_task()]
        
        try:
            logger.info("Starting 3 concurrent API requests...")
            results = await asyncio.gather(*tasks, return_exceptions=True)
            total_time = time.time() - start_time
            
            logger.info(f"All requests completed in {total_time:.2f} seconds")
            
            # Process results
            api_names = ["Tavily", "Smithery", "Brave"]
            concurrent_results = {}
            
            for i, (name, result) in enumerate(zip(api_names, results)):
                if isinstance(result, Exception):
                    logger.info(f"  {name}: ✗ Failed - {result}")
                    concurrent_results[name.lower()] = {'success': False, 'error': str(result)}
                elif result.success:
                    logger.info(f"  {name}: ✓ Success ({result.response_time:.2f}s)")
                    concurrent_results[name.lower()] = {'success': True, 'time': result.response_time}
                else:
                    logger.info(f"  {name}: ✗ Failed - {result.error}")
                    concurrent_results[name.lower()] = {'success': False, 'error': result.error}
            
            self.results['concurrent_requests'] = {
                'total_time': total_time,
                'results': concurrent_results
            }
            
        except Exception as e:
            logger.info(f"✗ Concurrent requests failed: {e}")
            self.results['concurrent_requests'] = {'success': False, 'error': str(e)}
    
    async def demo_error_handling(self):
        """Demonstrate error handling and fallback mechanisms."""
        logger.info("\\n" + "="*60)
        logger.info("ERROR HANDLING DEMONSTRATION")
        logger.info("="*60)
        
        # Test with invalid API key
        logger.info("Testing with invalid API key...")
        try:
            async with TavilyAPI("invalid-key") as tavily:
                result = await tavily.search("test query")
                if not result.success:
                    logger.info(f"✓ Correctly handled invalid key: {result.error}")
                    self.results['error_handling'] = {'success': True, 'handled_invalid_key': True}
                else:
                    logger.info("✗ Invalid key should have failed")
                    self.results['error_handling'] = {'success': False, 'handled_invalid_key': False}
        except Exception as e:
            logger.info(f"✓ Exception correctly caught: {e}")
            self.results['error_handling'] = {'success': True, 'handled_exception': True}
        
        # Test fallback mechanism (simulate primary service failure)
        logger.info("\\nTesting fallback mechanism...")
        primary_failed = False
        fallback_success = False
        
        # Simulate primary service failure, try fallback
        try:
            # First try with potentially failing service
            async with TavilyAPI("potentially-failing-key") as tavily:
                result = await tavily.search("fallback test")
                if not result.success:
                    primary_failed = True
                    logger.info("Primary service failed, trying fallback...")
                    
                    # Try fallback service
                    async with BraveAPI(BRAVE_KEY) as brave:
                        fallback_result = await brave.search_web("fallback test")
                        if fallback_result.success:
                            fallback_success = True
                            logger.info("✓ Fallback service succeeded")
                        else:
                            logger.info(f"✗ Fallback service also failed: {fallback_result.error}")
                else:
                    logger.info("Primary service unexpectedly succeeded")
        except Exception as e:
            logger.info(f"Exception during fallback test: {e}")
        
        self.results['fallback_mechanism'] = {
            'primary_failed': primary_failed,
            'fallback_success': fallback_success
        }
    
    async def run_all_demos(self):
        """Run all demonstration scenarios."""
        logger.info("🚀 Starting Comprehensive API Integration Demonstration")
        logger.info("Testing Tavily, Smithery, and Brave APIs")
        
        start_time = time.time()
        
        # Run all demos
        demo_functions = [
            self.test_api_keys,
            self.demo_web_search,
            self.demo_text_enhancement,
            self.demo_concurrent_requests,
            self.demo_error_handling
        ]
        
        for demo_func in demo_functions:
            try:
                await demo_func()
            except Exception as e:
                logger.error(f"Demo {demo_func.__name__} failed: {e}")
                self.results[demo_func.__name__] = {'success': False, 'error': str(e)}
        
        total_time = time.time() - start_time
        
        # Summary
        logger.info("\\n" + "="*60)
        logger.info("DEMONSTRATION SUMMARY")
        logger.info("="*60)
        logger.info(f"Total demonstration time: {total_time:.2f} seconds")
        
        # Count successes
        successful_tests = 0
        total_tests = 0
        
        for key, result in self.results.items():
            if isinstance(result, dict):
                total_tests += 1
                if result.get('success', False):
                    successful_tests += 1
                    logger.info(f"✓ {key}: SUCCESS")
                else:
                    logger.info(f"✗ {key}: FAILED - {result.get('error', 'Unknown error')}")
        
        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
        logger.info(f"\\nOverall Success Rate: {successful_tests}/{total_tests} ({success_rate:.1f}%)")
        
        # Save results
        self.results['summary'] = {
            'total_time': total_time,
            'successful_tests': successful_tests,
            'total_tests': total_tests,
            'success_rate': f"{success_rate:.1f}%",
            'timestamp': time.time()
        }
        
        with open('simple_api_demo_results.json', 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info("\\n📊 Results saved to: simple_api_demo_results.json")
        logger.info("🎉 Demonstration completed!")


async def main():
    """Main function to run the demonstration."""
    demo = APIIntegrationDemo()
    await demo.run_all_demos()


if __name__ == "__main__":
    print("🔧 Claude API Integration Demonstration")
    print("This demo validates Tavily, Smithery, and Brave API integrations")
    print("-" * 60)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()