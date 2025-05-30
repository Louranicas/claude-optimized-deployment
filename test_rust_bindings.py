#!/usr/bin/env python3
"""
Test script for Rust-accelerated Circle of Experts bindings.

This script verifies that the Rust extensions are properly integrated
and provides performance comparisons.
"""

import time
from typing import List, Dict, Any
import random
import string

# Try to import the Rust-accelerated module
try:
    from src.circle_of_experts.core.rust_accelerated import (
        ConsensusAnalyzer,
        ResponseAggregator,
        PatternMatcher,
        get_performance_metrics,
        RUST_AVAILABLE
    )
    print(f"✓ Rust-accelerated module imported successfully")
    print(f"✓ Rust extensions available: {RUST_AVAILABLE}")
except ImportError as e:
    print(f"✗ Failed to import rust_accelerated module: {e}")
    exit(1)

def generate_mock_responses(count: int) -> List[Dict[str, Any]]:
    """Generate mock expert responses for testing."""
    responses = []
    
    recommendations_pool = [
        "Implement caching strategy",
        "Optimize database queries",
        "Use connection pooling",
        "Add monitoring metrics",
        "Implement rate limiting",
        "Use async processing",
        "Add error handling",
        "Improve logging",
        "Add unit tests",
        "Refactor code structure"
    ]
    
    for i in range(count):
        content = f"Expert analysis {i}: " + " ".join(
            random.choice(string.ascii_lowercase) for _ in range(100)
        )
        
        recommendations = random.sample(
            recommendations_pool, 
            k=random.randint(2, 5)
        )
        
        responses.append({
            "expert_name": f"Expert_{i}",
            "content": content,
            "confidence": random.uniform(0.5, 1.0),
            "recommendations": recommendations,
            "limitations": [f"Limitation {j}" for j in range(random.randint(1, 3))]
        })
    
    return responses

def test_consensus_analyzer():
    """Test the ConsensusAnalyzer functionality."""
    print("\n=== Testing ConsensusAnalyzer ===")
    
    analyzer = ConsensusAnalyzer(confidence_threshold=0.7, consensus_threshold=0.6)
    responses = generate_mock_responses(10)
    
    # Test consensus analysis
    start_time = time.time()
    consensus_result = analyzer.analyze_consensus(responses)
    elapsed_time = time.time() - start_time
    
    print(f"✓ Consensus analysis completed in {elapsed_time:.4f}s")
    print(f"  - Consensus score: {consensus_result.get('consensus_score', 0):.2f}")
    print(f"  - Agreement level: {consensus_result.get('agreement_level', 'none')}")
    print(f"  - High confidence experts: {len(consensus_result.get('high_confidence_experts', []))}")
    
    # Test finding agreements
    start_time = time.time()
    agreements = analyzer.find_agreements(responses)
    elapsed_time = time.time() - start_time
    
    print(f"✓ Found {len(agreements)} agreements in {elapsed_time:.4f}s")
    if agreements:
        print(f"  - Sample agreements: {agreements[:3]}")
    
    # Test confidence statistics
    start_time = time.time()
    stats = analyzer.calculate_confidence_stats(responses)
    elapsed_time = time.time() - start_time
    
    print(f"✓ Calculated statistics in {elapsed_time:.4f}s")
    print(f"  - Mean confidence: {stats.get('mean', 0):.2f}")
    print(f"  - Std deviation: {stats.get('std_dev', 0):.2f}")

def test_response_aggregator():
    """Test the ResponseAggregator functionality."""
    print("\n=== Testing ResponseAggregator ===")
    
    aggregator = ResponseAggregator(weight_by_confidence=True, deduplication_threshold=0.8)
    responses = generate_mock_responses(8)
    
    # Test response aggregation
    start_time = time.time()
    aggregated = aggregator.aggregate_responses(responses)
    elapsed_time = time.time() - start_time
    
    print(f"✓ Response aggregation completed in {elapsed_time:.4f}s")
    print(f"  - Expert count: {aggregated.get('expert_count', 0)}")
    print(f"  - Overall confidence: {aggregated.get('overall_confidence', 0):.2f}")
    print(f"  - Aggregation method: {aggregated.get('aggregation_method', 'unknown')}")
    print(f"  - Recommendations: {len(aggregated.get('recommendations', []))}")
    
    # Test recommendation merging
    start_time = time.time()
    merged_recs = aggregator.merge_recommendations(responses)
    elapsed_time = time.time() - start_time
    
    print(f"✓ Merged recommendations in {elapsed_time:.4f}s")
    print(f"  - Unique recommendations: {len(merged_recs)}")

def test_pattern_matcher():
    """Test the PatternMatcher functionality."""
    print("\n=== Testing PatternMatcher ===")
    
    patterns = ["optimize", "implement", "database", "async", "error"]
    matcher = PatternMatcher(patterns=patterns, case_sensitive=False)
    responses = generate_mock_responses(15)
    
    # Test pattern finding
    start_time = time.time()
    pattern_results = matcher.find_patterns(responses)
    elapsed_time = time.time() - start_time
    
    print(f"✓ Pattern matching completed in {elapsed_time:.4f}s")
    for pattern, results in pattern_results.items():
        count = results.get('count', 0)
        if count > 0:
            print(f"  - Pattern '{pattern}': {count} occurrences")
    
    # Test key phrase extraction
    start_time = time.time()
    key_phrases = matcher.extract_key_phrases(responses)
    elapsed_time = time.time() - start_time
    
    print(f"✓ Extracted {len(key_phrases)} key phrases in {elapsed_time:.4f}s")
    if key_phrases:
        print(f"  - Sample phrases: {key_phrases[:3]}")

def test_performance_comparison():
    """Test performance with different response counts."""
    print("\n=== Performance Comparison ===")
    
    response_counts = [10, 50, 100, 500]
    
    for count in response_counts:
        responses = generate_mock_responses(count)
        analyzer = ConsensusAnalyzer()
        
        start_time = time.time()
        analyzer.analyze_consensus(responses)
        elapsed_time = time.time() - start_time
        
        print(f"✓ Processed {count} responses in {elapsed_time:.4f}s "
              f"({count/elapsed_time:.0f} responses/second)")

def main():
    """Run all tests."""
    print("=" * 60)
    print("Rust-Accelerated Circle of Experts Test Suite")
    print("=" * 60)
    
    # Show performance metrics
    metrics = get_performance_metrics()
    print(f"\n✓ Rust available: {metrics['rust_available']}")
    
    if metrics['rust_available']:
        print("\nExpected performance improvements:")
        for operation, speedup in metrics['expected_speedup'].items():
            print(f"  - {operation}: {speedup}")
    
    # Run tests
    test_consensus_analyzer()
    test_response_aggregator()
    test_pattern_matcher()
    test_performance_comparison()
    
    print("\n" + "=" * 60)
    print("✓ All tests completed successfully!")
    print("=" * 60)

if __name__ == "__main__":
    main()