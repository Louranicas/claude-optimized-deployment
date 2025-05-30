#!/usr/bin/env python3
"""
Example: Using Circle of Experts with Rust Acceleration

This example demonstrates:
1. Automatic Rust acceleration
2. Performance monitoring
3. Batch processing
4. Fallback handling
"""

import asyncio
import logging
import os
from typing import List, Dict, Any

# Add parent directory to path for imports
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.circle_of_experts.core import EnhancedExpertManager
from src.circle_of_experts.models.query import QueryType, QueryPriority
from src.circle_of_experts.utils import get_rust_integration

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def example_single_query():
    """Example: Single query with Rust acceleration."""
    logger.info("=== Single Query Example ===")
    
    # Initialize manager - Rust acceleration is automatic
    manager = EnhancedExpertManager(
        credentials_path=os.getenv("GOOGLE_CREDENTIALS_PATH"),
        enable_performance_monitoring=True
    )
    
    # Check Rust availability
    rust_stats = manager._rust_integration.get_performance_stats()
    logger.info(f"Rust modules available: {rust_stats['rust_available']}")
    
    # Submit a query
    try:
        result = await manager.consult_experts_enhanced(
            title="Rust Performance Optimization",
            content="""
            I'm building a high-performance data processing system in Python.
            What are the best practices for integrating Rust modules to optimize
            performance-critical sections? Please provide specific examples and
            benchmarking strategies.
            """,
            requester="developer",
            query_type=QueryType.TECHNICAL,
            priority=QueryPriority.HIGH,
            tags=["rust", "performance", "optimization"],
            wait_for_responses=True,
            response_timeout=60.0,
            min_responses=2
        )
        
        # Display results
        logger.info(f"Query ID: {result['query_id']}")
        logger.info(f"Status: {result['status']}")
        
        # Performance information
        perf = result.get('performance', {})
        logger.info(f"Total time: {perf.get('total_time', 'N/A')}s")
        logger.info(f"Rust accelerated: {perf.get('rust_accelerated', False)}")
        
        # Consensus analysis
        if 'aggregation' in result:
            agg = result['aggregation']
            logger.info(f"Responses: {agg.get('response_count', 0)}")
            logger.info(f"Consensus level: {agg.get('consensus_level', 'N/A')}")
            logger.info(f"Average confidence: {agg.get('average_confidence', 0)}")
            
            # Show if Rust was used for aggregation
            if agg.get('accelerated'):
                logger.info("✓ Response aggregation was Rust-accelerated!")
            
            # Advanced consensus if available
            if 'advanced_consensus' in agg:
                consensus = agg['advanced_consensus']
                logger.info(f"Consensus score: {consensus.get('consensus_score', 0)}")
                logger.info(f"Agreement level: {consensus.get('agreement_level', 'N/A')}")
                if consensus.get('key_points'):
                    logger.info("Key points identified:")
                    for point in consensus['key_points'][:3]:
                        logger.info(f"  - {point}")
        
    except Exception as e:
        logger.error(f"Query failed: {e}")
        logger.info("This is normal if Google Drive credentials are not configured")


async def example_batch_processing():
    """Example: Batch processing with Rust acceleration."""
    logger.info("\n=== Batch Processing Example ===")
    
    manager = EnhancedExpertManager(
        credentials_path=os.getenv("GOOGLE_CREDENTIALS_PATH"),
        enable_performance_monitoring=True
    )
    
    # Optimize for performance
    await manager.optimize_for_performance()
    
    # Batch consultation
    try:
        async with manager.batch_consultation("batch_user") as batch:
            # Add multiple queries
            queries = [
                ("Python vs Rust Performance", "When should I use Rust instead of Python?"),
                ("Memory Management", "How does Rust's ownership system work?"),
                ("Async Programming", "Best practices for async Rust?"),
                ("Error Handling", "Rust error handling patterns?"),
                ("Interop with Python", "How to create Python bindings for Rust?")
            ]
            
            for title, content in queries:
                await batch.add_query(title, content, QueryType.TECHNICAL)
            
            logger.info(f"Prepared batch with {len(batch.queries)} queries")
            
            # Execute batch - Rust acceleration applied automatically
            results = await batch.execute(wait_for_responses=False)
            
            logger.info(f"Batch submitted: {len(results)} queries")
            
            # Check how many used Rust
            rust_count = sum(
                1 for r in results 
                if r.get('performance', {}).get('rust_accelerated', False)
            )
            logger.info(f"Rust acceleration used for: {rust_count}/{len(results)} queries")
            
    except Exception as e:
        logger.error(f"Batch processing failed: {e}")
        logger.info("This is normal if Google Drive credentials are not configured")
    
    # Show performance report
    report = manager.get_performance_report()
    logger.info("\n--- Performance Report ---")
    logger.info(f"Total queries: {report['query_metrics']['total_queries']}")
    logger.info(f"Rust accelerated: {report['query_metrics']['rust_accelerated_queries']}")
    logger.info(f"Rust usage: {report['query_metrics']['rust_acceleration_rate']}%")
    logger.info(f"Average response time: {report['query_metrics']['average_response_time']}s")
    logger.info(f"Estimated speedup: {report['estimated_speedup']['speedup_factor']}")


async def example_streaming_responses():
    """Example: Streaming responses with Rust processing."""
    logger.info("\n=== Streaming Responses Example ===")
    
    manager = EnhancedExpertManager(
        credentials_path=os.getenv("GOOGLE_CREDENTIALS_PATH"),
        enable_performance_monitoring=True
    )
    
    try:
        # Submit a query without waiting
        result = await manager.consult_experts_enhanced(
            title="Streaming Test Query",
            content="This is a test query for streaming responses.",
            requester="stream_user",
            wait_for_responses=False
        )
        
        query_id = result['query_id']
        logger.info(f"Query submitted: {query_id}")
        
        # Stream responses as they arrive
        logger.info("Streaming responses (will timeout after 30s)...")
        response_count = 0
        
        async for response in manager.stream_expert_responses(
            query_id, 
            poll_interval=2.0, 
            timeout=30.0
        ):
            response_count += 1
            logger.info(f"Received response {response_count} from {response.expert_type.value}")
            logger.info(f"  Confidence: {response.confidence}")
            logger.info(f"  Processing time: {response.processing_time}s")
            
            # Each response is processed with Rust if available
            if manager._rust_integration.rust_available:
                logger.info("  ✓ Response processed with Rust acceleration")
        
        if response_count == 0:
            logger.info("No responses received (this is normal in test mode)")
            
    except Exception as e:
        logger.error(f"Streaming failed: {e}")
        logger.info("This is normal if Google Drive credentials are not configured")


async def example_performance_comparison():
    """Example: Compare performance with and without Rust."""
    logger.info("\n=== Performance Comparison Example ===")
    
    rust_integration = get_rust_integration()
    
    # Create test data
    test_responses = []
    for i in range(100):
        test_responses.append({
            "expert_type": f"expert_{i}",
            "confidence": 0.5 + (i % 5) * 0.1,
            "content": f"Response {i} with analysis",
            "recommendations": [f"Recommendation {i}.{j}" for j in range(3)]
        })
    
    # Test with Rust (if available)
    if rust_integration.rust_available:
        import time
        
        # Rust version
        start = time.time()
        rust_result, used_rust = rust_integration.aggregate_responses(test_responses)
        rust_time = time.time() - start
        
        # Force Python version
        rust_integration.rust_available = False
        start = time.time()
        python_result, _ = rust_integration.aggregate_responses(test_responses)
        python_time = time.time() - start
        
        # Restore Rust
        rust_integration._detect_and_load_rust_modules()
        
        # Compare
        logger.info("Performance Comparison (100 responses):")
        logger.info(f"  Python time: {python_time:.4f}s")
        logger.info(f"  Rust time: {rust_time:.4f}s")
        logger.info(f"  Speedup: {python_time/rust_time:.2f}x")
        logger.info(f"  Time saved: {python_time - rust_time:.4f}s")
        
    else:
        logger.info("Rust modules not available for comparison")
        logger.info("To enable Rust acceleration:")
        logger.info("  1. cd rust_core")
        logger.info("  2. maturin develop --release")


async def main():
    """Run all examples."""
    logger.info("Circle of Experts - Rust Acceleration Examples\n")
    
    # Check Rust availability globally
    rust_integration = get_rust_integration()
    if rust_integration.rust_available:
        logger.info("✓ Rust acceleration is ENABLED")
    else:
        logger.info("✗ Rust acceleration is DISABLED (using Python fallback)")
        logger.info("  To enable: cd rust_core && maturin develop --release\n")
    
    # Run examples
    await example_single_query()
    await example_batch_processing()
    await example_streaming_responses()
    await example_performance_comparison()
    
    # Final stats
    if rust_integration.rust_available:
        final_stats = rust_integration.get_performance_stats()
        logger.info(f"\n=== Final Rust Integration Stats ===")
        logger.info(f"Rust calls: {final_stats['rust_calls']}")
        logger.info(f"Fallback calls: {final_stats['fallback_calls']}")
        logger.info(f"Rust usage: {final_stats['rust_usage_percent']}%")
        logger.info(f"Total time saved: {final_stats['estimated_time_saved_seconds']}s")


if __name__ == "__main__":
    asyncio.run(main())