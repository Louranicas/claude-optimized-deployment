"""Demonstration of API integrations with Tavily, Smithery, and Brave."""

import asyncio
import json
import logging
import time
from typing import Dict, Any

from src.api import APIManager
from src.api.config import get_api_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class APIIntegrationDemo:
    """Demonstration of API integration capabilities."""
    
    def __init__(self):
        self.api_manager = None
        self.demo_results = {}
    
    async def setup(self):
        """Initialize API manager with configuration."""
        try:
            config = get_api_config()
            
            self.api_manager = APIManager(
                tavily_api_key=config.tavily.api_key if config.tavily else None,
                smithery_api_key=config.smithery.api_key if config.smithery else None,
                brave_api_key=config.brave.api_key if config.brave else None,
                enable_fallbacks=config.enable_fallbacks,
                max_concurrent_requests=config.max_concurrent_requests
            )
            
            logger.info("API Manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize API Manager: {e}")
            raise
    
    async def demo_health_checks(self):
        """Demonstrate health checking of all APIs."""
        logger.info("\\n" + "="*60)
        logger.info("HEALTH CHECK DEMONSTRATION")
        logger.info("="*60)
        
        try:
            health_results = await self.api_manager.health_check_all()
            
            for service, health in health_results.items():
                status = "✓ HEALTHY" if health.get('healthy', False) else "✗ UNHEALTHY"
                api_key_status = "✓ VALID" if health.get('api_key_valid', False) else "✗ INVALID"
                
                logger.info(f"{service.upper():>10}: {status} | API Key: {api_key_status}")
                
                if health.get('metrics'):
                    metrics = health['metrics']
                    logger.info(f"           Requests: {metrics.get('requests', 0)}, "
                              f"Errors: {metrics.get('errors', 0)}, "
                              f"Cache Hits: {metrics.get('cache_hits', 0)}")
            
            self.demo_results['health_check'] = health_results
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            self.demo_results['health_check'] = {'error': str(e)}
    
    async def demo_web_search(self):
        """Demonstrate web search capabilities."""
        logger.info("\\n" + "="*60)
        logger.info("WEB SEARCH DEMONSTRATION")
        logger.info("="*60)
        
        search_queries = [
            "Python async programming best practices",
            "API rate limiting strategies 2024",
            "Claude AI capabilities"
        ]
        
        search_results = {}
        
        for query in search_queries:
            logger.info(f"\\nSearching for: '{query}'")
            
            try:
                # Try with Tavily first
                result = await self.api_manager.search_web(
                    query=query,
                    max_results=3,
                    prefer_client="tavily"
                )
                
                logger.info(f"  Found {result.get('total_results', 0)} results using {result.get('source', 'unknown')}")
                
                # Display first result
                if result.get('results'):
                    first_result = result['results'][0]
                    logger.info(f"  Top result: {first_result.get('title', 'No title')}")
                    logger.info(f"  URL: {first_result.get('url', 'No URL')}")
                
                search_results[query] = {
                    'source': result.get('source'),
                    'total_results': result.get('total_results', 0),
                    'success': True
                }
                
            except Exception as e:
                logger.error(f"  Search failed: {e}")
                search_results[query] = {'error': str(e), 'success': False}
        
        self.demo_results['web_search'] = search_results
    
    async def demo_news_search(self):
        """Demonstrate news search capabilities."""
        logger.info("\\n" + "="*60)
        logger.info("NEWS SEARCH DEMONSTRATION")
        logger.info("="*60)
        
        news_queries = [
            "artificial intelligence developments",
            "Python programming updates",
            "API security trends"
        ]
        
        news_results = {}
        
        for query in news_queries:
            logger.info(f"\\nSearching news for: '{query}'")
            
            try:
                result = await self.api_manager.search_news(
                    query=query,
                    max_results=3,
                    days=7
                )
                
                logger.info(f"  Found {result.get('total_results', 0)} news articles using {result.get('source', 'unknown')}")
                
                # Display first news article
                if result.get('results'):
                    first_article = result['results'][0]
                    logger.info(f"  Latest: {first_article.get('title', 'No title')}")
                    logger.info(f"  URL: {first_article.get('url', 'No URL')}")
                
                news_results[query] = {
                    'source': result.get('source'),
                    'total_results': result.get('total_results', 0),
                    'success': True
                }
                
            except Exception as e:
                logger.error(f"  News search failed: {e}")
                news_results[query] = {'error': str(e), 'success': False}
        
        self.demo_results['news_search'] = news_results
    
    async def demo_text_enhancement(self):
        """Demonstrate text enhancement capabilities."""
        logger.info("\\n" + "="*60)
        logger.info("TEXT ENHANCEMENT DEMONSTRATION")
        logger.info("="*60)
        
        sample_texts = [
            {
                'text': "This is a basic text that needs improvement.",
                'enhancement_type': 'improve'
            },
            {
                'text': "Python is a programming language. It's easy to learn. Many developers use it for web development, data science, and automation.",
                'enhancement_type': 'summarize'
            },
            {
                'text': "AI good.",
                'enhancement_type': 'expand'
            }
        ]
        
        enhancement_results = {}
        
        for i, sample in enumerate(sample_texts):
            logger.info(f"\\nEnhancing text {i+1} ({sample['enhancement_type']}):")
            logger.info(f"  Original: {sample['text']}")
            
            try:
                result = await self.api_manager.enhance_text(
                    text=sample['text'],
                    enhancement_type=sample['enhancement_type']
                )
                
                enhanced_text = result.get('content', 'No enhanced content')
                confidence = result.get('confidence', 0)
                
                logger.info(f"  Enhanced: {enhanced_text}")
                logger.info(f"  Confidence: {confidence:.2f}")
                
                enhancement_results[f"sample_{i+1}"] = {
                    'original': sample['text'],
                    'enhanced': enhanced_text,
                    'confidence': confidence,
                    'enhancement_type': sample['enhancement_type'],
                    'success': True
                }
                
            except Exception as e:
                logger.error(f"  Enhancement failed: {e}")
                enhancement_results[f"sample_{i+1}"] = {
                    'original': sample['text'],
                    'error': str(e),
                    'success': False
                }
        
        self.demo_results['text_enhancement'] = enhancement_results
    
    async def demo_sentiment_analysis(self):
        """Demonstrate sentiment analysis capabilities."""
        logger.info("\\n" + "="*60)
        logger.info("SENTIMENT ANALYSIS DEMONSTRATION")
        logger.info("="*60)
        
        sample_texts = [
            "I love this new API integration! It works perfectly.",
            "This is terrible. Nothing works as expected.",
            "The API is okay, but could be better documented.",
            "Neutral statement about programming languages."
        ]
        
        sentiment_results = {}
        
        for i, text in enumerate(sample_texts):
            logger.info(f"\\nAnalyzing sentiment for text {i+1}:")
            logger.info(f"  Text: {text}")
            
            try:
                result = await self.api_manager.analyze_sentiment(text=text)
                
                sentiment = result.get('sentiment', 'unknown')
                score = result.get('score', 0)
                
                logger.info(f"  Sentiment: {sentiment}")
                logger.info(f"  Score: {score:.2f}")
                
                sentiment_results[f"text_{i+1}"] = {
                    'text': text,
                    'sentiment': sentiment,
                    'score': score,
                    'success': True
                }
                
            except Exception as e:
                logger.error(f"  Sentiment analysis failed: {e}")
                sentiment_results[f"text_{i+1}"] = {
                    'text': text,
                    'error': str(e),
                    'success': False
                }
        
        self.demo_results['sentiment_analysis'] = sentiment_results
    
    async def demo_image_search(self):
        """Demonstrate image search capabilities."""
        logger.info("\\n" + "="*60)
        logger.info("IMAGE SEARCH DEMONSTRATION")
        logger.info("="*60)
        
        image_queries = [
            "Python programming",
            "API architecture diagram",
            "Cloud computing"
        ]
        
        image_results = {}
        
        for query in image_queries:
            logger.info(f"\\nSearching images for: '{query}'")
            
            try:
                result = await self.api_manager.search_images(
                    query=query,
                    max_results=3
                )
                
                logger.info(f"  Found {result.get('total_results', 0)} images using {result.get('source', 'unknown')}")
                
                # Display first image result
                if result.get('results'):
                    first_image = result['results'][0]
                    logger.info(f"  Top image: {first_image.get('title', 'No title')}")
                    logger.info(f"  URL: {first_image.get('url', 'No URL')}")
                
                image_results[query] = {
                    'source': result.get('source'),
                    'total_results': result.get('total_results', 0),
                    'success': True
                }
                
            except Exception as e:
                logger.error(f"  Image search failed: {e}")
                image_results[query] = {'error': str(e), 'success': False}
        
        self.demo_results['image_search'] = image_results
    
    async def demo_concurrent_operations(self):
        """Demonstrate concurrent API operations."""
        logger.info("\\n" + "="*60)
        logger.info("CONCURRENT OPERATIONS DEMONSTRATION")
        logger.info("="*60)
        
        start_time = time.time()
        
        # Create concurrent tasks
        tasks = []
        
        # Web search task
        tasks.append(self.api_manager.search_web(
            query="concurrent API calls",
            max_results=2
        ))
        
        # Text enhancement task
        tasks.append(self.api_manager.enhance_text(
            text="Concurrent processing improves performance.",
            enhancement_type="expand"
        ))
        
        # News search task
        tasks.append(self.api_manager.search_news(
            query="API performance",
            max_results=2
        ))
        
        try:
            logger.info(f"Starting {len(tasks)} concurrent operations...")
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            elapsed = time.time() - start_time
            logger.info(f"All operations completed in {elapsed:.2f} seconds")
            
            # Process results
            operation_types = ['web_search', 'text_enhancement', 'news_search']
            concurrent_results = {}
            
            for i, (op_type, result) in enumerate(zip(operation_types, results)):
                if isinstance(result, Exception):
                    logger.error(f"  {op_type} failed: {result}")
                    concurrent_results[op_type] = {'error': str(result), 'success': False}
                else:
                    logger.info(f"  {op_type} succeeded")
                    concurrent_results[op_type] = {
                        'source': result.get('source', 'unknown'),
                        'success': True
                    }
            
            self.demo_results['concurrent_operations'] = {
                'elapsed_time': elapsed,
                'results': concurrent_results
            }
            
        except Exception as e:
            logger.error(f"Concurrent operations failed: {e}")
            self.demo_results['concurrent_operations'] = {'error': str(e)}
    
    async def demo_caching_performance(self):
        """Demonstrate caching performance benefits."""
        logger.info("\\n" + "="*60)
        logger.info("CACHING PERFORMANCE DEMONSTRATION")
        logger.info("="*60)
        
        query = "Python API caching performance test"
        
        # First request (cache miss)
        logger.info("Making first request (cache miss)...")
        start_time = time.time()
        try:
            result1 = await self.api_manager.search_web(query=query, max_results=2)
            first_duration = time.time() - start_time
            logger.info(f"  First request took {first_duration:.3f} seconds")
        except Exception as e:
            logger.error(f"  First request failed: {e}")
            return
        
        # Second request (cache hit)
        logger.info("Making second request (cache hit)...")
        start_time = time.time()
        try:
            result2 = await self.api_manager.search_web(query=query, max_results=2)
            second_duration = time.time() - start_time
            logger.info(f"  Second request took {second_duration:.3f} seconds")
            
            speed_improvement = (first_duration - second_duration) / first_duration * 100
            logger.info(f"  Caching provided {speed_improvement:.1f}% speed improvement")
            
            self.demo_results['caching_performance'] = {
                'first_request_time': first_duration,
                'second_request_time': second_duration,
                'speed_improvement_percent': speed_improvement,
                'success': True
            }
            
        except Exception as e:
            logger.error(f"  Second request failed: {e}")
            self.demo_results['caching_performance'] = {'error': str(e), 'success': False}
    
    async def run_all_demos(self):
        """Run all demonstration scenarios."""
        logger.info("Starting comprehensive API integration demonstration...")
        
        demo_functions = [
            self.demo_health_checks,
            self.demo_web_search,
            self.demo_news_search,
            self.demo_text_enhancement,
            self.demo_sentiment_analysis,
            self.demo_image_search,
            self.demo_concurrent_operations,
            self.demo_caching_performance
        ]
        
        start_time = time.time()
        
        for demo_func in demo_functions:
            try:
                await demo_func()
            except Exception as e:
                logger.error(f"Demo {demo_func.__name__} failed: {e}")
                self.demo_results[demo_func.__name__] = {'error': str(e)}
        
        total_time = time.time() - start_time
        
        logger.info("\\n" + "="*60)
        logger.info("DEMONSTRATION COMPLETE")
        logger.info("="*60)
        logger.info(f"Total demonstration time: {total_time:.2f} seconds")
        
        # Summary
        successful_demos = sum(1 for result in self.demo_results.values() 
                              if isinstance(result, dict) and result.get('success', True))
        total_demos = len(self.demo_results)
        
        logger.info(f"Successful demonstrations: {successful_demos}/{total_demos}")
        
        # Save results
        self.demo_results['summary'] = {
            'total_time': total_time,
            'successful_demos': successful_demos,
            'total_demos': total_demos,
            'success_rate': f"{(successful_demos/total_demos)*100:.1f}%"
        }
        
        with open('api_integration_demo_results.json', 'w') as f:
            json.dump(self.demo_results, f, indent=2, default=str)
        
        logger.info("\\nDemo results saved to api_integration_demo_results.json")
    
    async def cleanup(self):
        """Clean up resources."""
        if self.api_manager:
            await self.api_manager.close()


async def main():
    """Main demonstration function."""
    demo = APIIntegrationDemo()
    
    try:
        await demo.setup()
        await demo.run_all_demos()
    except Exception as e:
        logger.error(f"Demonstration failed: {e}")
    finally:
        await demo.cleanup()


if __name__ == "__main__":
    asyncio.run(main())