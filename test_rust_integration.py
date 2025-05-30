#!/usr/bin/env python3
"""
Test script for Rust integration with Circle of Experts.

This script demonstrates:
1. Automatic Rust detection and fallback
2. Performance comparison between Rust and Python
3. Enhanced expert manager features
"""

import asyncio
import logging
import time
from typing import List, Dict, Any

from src.circle_of_experts.core import EnhancedExpertManager
from src.circle_of_experts.models.query import QueryType, QueryPriority
from src.circle_of_experts.models.response import ExpertResponse, ExpertType, ResponseStatus
from src.circle_of_experts.utils import get_rust_integration

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def create_mock_responses(count: int = 5) -> List[ExpertResponse]:
    """Create mock expert responses for testing."""
    responses = []
    for i in range(count):
        response = ExpertResponse(
            query_id="test-query-123",
            expert_type=ExpertType.CLAUDE if i % 2 == 0 else ExpertType.GPT4,
            content=f"This is test response {i+1} with detailed analysis and recommendations.",
            confidence=0.7 + (i * 0.05),
            status=ResponseStatus.COMPLETED,
            recommendations=[
                f"Recommendation {i+1}.1: Implement feature X",
                f"Recommendation {i+1}.2: Optimize algorithm Y",
                f"Recommendation {i+1}.3: Consider approach Z"
            ],
            code_snippets=[
                f"# Example code {i+1}\ndef solution_{i+1}():\n    return 'optimized'"
            ],
            limitations=[
                f"Limitation {i+1}: Requires additional testing",
                "General limitation: Performance needs monitoring"
            ],
            processing_time=1.5 + (i * 0.2)
        )
        responses.append(response)
    return responses


async def test_rust_integration():
    """Test Rust integration functionality."""
    logger.info("=== Testing Rust Integration ===")
    
    # Check Rust availability
    rust_integration = get_rust_integration()
    stats = rust_integration.get_performance_stats()
    
    logger.info(f"Rust Available: {stats['rust_available']}")
    logger.info(f"Initial Stats: {stats}")
    
    # Test consensus analysis
    logger.info("\n--- Testing Consensus Analysis ---")
    
    # Create test data
    test_responses = [
        {"expert_type": "claude", "confidence": 0.8, "content": "Test 1", "recommendations": ["A", "B"]},
        {"expert_type": "gpt4", "confidence": 0.9, "content": "Test 2", "recommendations": ["B", "C"]},
        {"expert_type": "gemini", "confidence": 0.7, "content": "Test 3", "recommendations": ["A", "C"]},
    ]
    
    # Test consensus analysis
    start_time = time.time()
    consensus_result, used_rust = rust_integration.analyze_consensus(test_responses)
    elapsed = time.time() - start_time
    
    logger.info(f"Consensus Result: {consensus_result}")
    logger.info(f"Used Rust: {used_rust}")
    logger.info(f"Time taken: {elapsed:.4f}s")
    
    # Test response aggregation
    logger.info("\n--- Testing Response Aggregation ---")
    
    start_time = time.time()
    aggregation_result, used_rust = rust_integration.aggregate_responses(test_responses)
    elapsed = time.time() - start_time
    
    logger.info(f"Aggregation Result: {aggregation_result}")
    logger.info(f"Used Rust: {used_rust}")
    logger.info(f"Time taken: {elapsed:.4f}s")
    
    # Show performance stats
    final_stats = rust_integration.get_performance_stats()
    logger.info(f"\nFinal Performance Stats: {final_stats}")


async def test_enhanced_expert_manager():
    """Test Enhanced Expert Manager with Rust integration."""
    logger.info("\n=== Testing Enhanced Expert Manager ===")
    
    # Initialize manager (will use mock Drive for testing)
    manager = EnhancedExpertManager(
        credentials_path=None,  # Will use mock
        enable_performance_monitoring=True
    )
    
    # Optimize for performance
    await manager.optimize_for_performance()
    
    # Test single query (mock mode)
    logger.info("\n--- Testing Single Query ---")
    
    try:
        result = await manager.consult_experts_enhanced(
            title="Test Rust Integration",
            content="How can we optimize Python code with Rust?",
            requester="test_user",
            query_type=QueryType.TECHNICAL,
            priority=QueryPriority.HIGH,
            wait_for_responses=False  # Don't wait in test mode
        )
        
        logger.info(f"Query submitted: {result['query_id']}")
        logger.info(f"Performance: {result.get('performance', {})}")
        logger.info(f"Rust stats: {result.get('rust_stats', {})}")
        
    except Exception as e:
        logger.warning(f"Query submission failed (expected in test mode): {e}")
    
    # Test batch consultation
    logger.info("\n--- Testing Batch Consultation ---")
    
    async with manager.batch_consultation("test_user") as batch:
        await batch.add_query("Query 1", "Content 1", QueryType.GENERAL)
        await batch.add_query("Query 2", "Content 2", QueryType.CODE_REVIEW)
        await batch.add_query("Query 3", "Content 3", QueryType.ANALYSIS)
        
        logger.info(f"Batch prepared with {len(batch.queries)} queries")
        
        # Note: In test mode, this might fail due to Drive unavailability
        try:
            results = await batch.execute(wait_for_responses=False)
            logger.info(f"Batch execution completed: {len(results)} results")
        except Exception as e:
            logger.warning(f"Batch execution failed (expected in test mode): {e}")
    
    # Get performance report
    performance_report = manager.get_performance_report()
    logger.info(f"\nPerformance Report: {performance_report}")


async def benchmark_rust_vs_python():
    """Benchmark Rust vs Python implementations."""
    logger.info("\n=== Benchmarking Rust vs Python ===")
    
    rust_integration = get_rust_integration()
    
    # Create varying sizes of test data
    test_sizes = [10, 50, 100, 500]
    
    for size in test_sizes:
        logger.info(f"\n--- Testing with {size} responses ---")
        
        # Create test data
        test_responses = []
        for i in range(size):
            test_responses.append({
                "expert_type": f"expert_{i}",
                "confidence": 0.5 + (i % 5) * 0.1,
                "content": f"Response {i} with detailed content",
                "recommendations": [f"Rec {i}.{j}" for j in range(3)],
                "code_snippets": [f"code_{i}"],
                "limitations": [f"limit_{i}"]
            })
        
        # Force Python implementation
        rust_integration.rust_available = False
        start_time = time.time()
        python_result, _ = rust_integration.aggregate_responses(test_responses)
        python_time = time.time() - start_time
        
        # Reset to use Rust if available
        rust_integration._detect_and_load_rust_modules()
        start_time = time.time()
        rust_result, used_rust = rust_integration.aggregate_responses(test_responses)
        rust_time = time.time() - start_time
        
        if used_rust:
            speedup = python_time / rust_time
            logger.info(f"Python time: {python_time:.4f}s")
            logger.info(f"Rust time: {rust_time:.4f}s")
            logger.info(f"Speedup: {speedup:.2f}x")
        else:
            logger.info(f"Rust not available, Python time: {python_time:.4f}s")


async def main():
    """Run all tests."""
    logger.info("Starting Rust Integration Tests\n")
    
    # Test basic Rust integration
    await test_rust_integration()
    
    # Test Enhanced Expert Manager
    await test_enhanced_expert_manager()
    
    # Benchmark if Rust is available
    rust_integration = get_rust_integration()
    if rust_integration.rust_available:
        await benchmark_rust_vs_python()
    else:
        logger.info("\nSkipping benchmarks - Rust modules not available")
        logger.info("To enable Rust acceleration:")
        logger.info("1. cd rust_core")
        logger.info("2. maturin develop")
        logger.info("3. Run this test again")
    
    logger.info("\n=== All Tests Completed ===")


if __name__ == "__main__":
    asyncio.run(main())