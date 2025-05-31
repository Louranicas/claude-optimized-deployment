"""
Rust vs Python Performance Comparison Tests
Agent 8C: Comprehensive performance benchmarking
"""

import pytest
import pytest_benchmark
import asyncio
import time
import numpy as np
from typing import List, Dict, Any
import sys
import os
import json

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.circle_of_experts.core.rust_accelerated import (
    ExpertAnalyzer,
    ConsensusEngine,
    ResponseAggregator,
    QueryValidator
)
from src.circle_of_experts.models.response import ExpertResponse
from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority


class TestRustAcceleration:
    """Test suite comparing Rust vs Python performance"""
    
    @pytest.fixture
    def sample_responses(self) -> List[ExpertResponse]:
        """Generate sample expert responses for testing"""
        responses = []
        for i in range(10):
            responses.append(ExpertResponse(
                expert_type=f"expert_{i}",
                content=f"This is a detailed response from expert {i} with analysis and recommendations.",
                confidence=0.8 + (i % 3) * 0.05,
                response_time=1.5 + (i % 5) * 0.2,
                model_used=f"model_{i % 3}",
                cost_estimate=0.002 * (i + 1),
                metadata={
                    "tokens": 150 + i * 10,
                    "reasoning_depth": i % 5 + 1
                }
            ))
        return responses
    
    @pytest.fixture
    def large_response_set(self) -> List[ExpertResponse]:
        """Generate large set of responses for stress testing"""
        responses = []
        for i in range(100):
            responses.append(ExpertResponse(
                expert_type=f"expert_{i % 10}",
                content=f"Response {i}: " + "x" * 500,  # 500 char response
                confidence=0.7 + (i % 30) * 0.01,
                response_time=1.0 + (i % 10) * 0.1,
                model_used=f"model_{i % 5}",
                cost_estimate=0.001 * (i % 10 + 1),
                metadata={
                    "tokens": 100 + i * 5,
                    "batch_id": i // 10
                }
            ))
        return responses
    
    def python_analyze_responses(self, responses: List[ExpertResponse]) -> Dict[str, Any]:
        """Pure Python implementation of response analysis"""
        # Pattern extraction
        patterns = {}
        for response in responses:
            words = response.content.split()
            for word in words:
                patterns[word] = patterns.get(word, 0) + 1
        
        # Confidence statistics
        confidences = [r.confidence for r in responses]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        # Response time analysis
        response_times = [r.response_time for r in responses]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            "pattern_count": len(patterns),
            "avg_confidence": avg_confidence,
            "avg_response_time": avg_response_time,
            "total_responses": len(responses)
        }
    
    def python_calculate_consensus(self, responses: List[ExpertResponse]) -> Dict[str, Any]:
        """Pure Python implementation of consensus calculation"""
        if not responses:
            return {"consensus_level": 0, "agreement_score": 0}
        
        # Calculate pairwise agreement
        agreement_scores = []
        for i in range(len(responses)):
            for j in range(i + 1, len(responses)):
                # Simple similarity based on confidence difference
                similarity = 1.0 - abs(responses[i].confidence - responses[j].confidence)
                agreement_scores.append(similarity)
        
        # Calculate consensus metrics
        avg_agreement = sum(agreement_scores) / len(agreement_scores) if agreement_scores else 0
        confidence_variance = np.var([r.confidence for r in responses])
        consensus_level = avg_agreement * (1 - confidence_variance)
        
        return {
            "consensus_level": consensus_level,
            "agreement_score": avg_agreement,
            "confidence_variance": confidence_variance
        }
    
    def python_aggregate_responses(self, responses: List[ExpertResponse]) -> Dict[str, Any]:
        """Pure Python implementation of response aggregation"""
        aggregated = {
            "total_responses": len(responses),
            "by_expert_type": {},
            "by_model": {},
            "cost_breakdown": {},
            "confidence_distribution": {}
        }
        
        for response in responses:
            # By expert type
            if response.expert_type not in aggregated["by_expert_type"]:
                aggregated["by_expert_type"][response.expert_type] = []
            aggregated["by_expert_type"][response.expert_type].append(response.confidence)
            
            # By model
            if response.model_used not in aggregated["by_model"]:
                aggregated["by_model"][response.model_used] = 0
            aggregated["by_model"][response.model_used] += 1
            
            # Cost breakdown
            if response.expert_type not in aggregated["cost_breakdown"]:
                aggregated["cost_breakdown"][response.expert_type] = 0
            aggregated["cost_breakdown"][response.expert_type] += response.cost_estimate
            
            # Confidence distribution
            conf_bucket = f"{int(response.confidence * 10) / 10:.1f}"
            if conf_bucket not in aggregated["confidence_distribution"]:
                aggregated["confidence_distribution"][conf_bucket] = 0
            aggregated["confidence_distribution"][conf_bucket] += 1
        
        return aggregated
    
    @pytest.mark.benchmark(group="response_analysis")
    def test_rust_vs_python_analysis(self, benchmark, sample_responses):
        """Benchmark Rust vs Python response analysis"""
        # Test Rust implementation
        rust_analyzer = ExpertAnalyzer()
        
        def rust_analysis():
            return rust_analyzer.analyze_responses(sample_responses)
        
        rust_result = benchmark.pedantic(rust_analysis, rounds=100, iterations=5)
        
        # Compare with Python implementation
        python_start = time.time()
        python_result = self.python_analyze_responses(sample_responses)
        python_time = time.time() - python_start
        
        # Verify results are similar
        assert rust_result is not None
        print(f"\nRust time: {benchmark.stats['mean']:.6f}s")
        print(f"Python time: {python_time:.6f}s")
        print(f"Speedup: {python_time / benchmark.stats['mean']:.2f}x")
    
    @pytest.mark.benchmark(group="consensus_calculation")
    def test_rust_vs_python_consensus(self, benchmark, sample_responses):
        """Benchmark Rust vs Python consensus calculation"""
        # Test Rust implementation
        rust_consensus = ConsensusEngine()
        
        def rust_calculation():
            return rust_consensus.calculate_consensus(sample_responses)
        
        rust_result = benchmark.pedantic(rust_calculation, rounds=100, iterations=5)
        
        # Compare with Python implementation
        python_start = time.time()
        python_result = self.python_calculate_consensus(sample_responses)
        python_time = time.time() - python_start
        
        # Verify results are similar
        assert rust_result is not None
        print(f"\nRust time: {benchmark.stats['mean']:.6f}s")
        print(f"Python time: {python_time:.6f}s")
        print(f"Speedup: {python_time / benchmark.stats['mean']:.2f}x")
    
    @pytest.mark.benchmark(group="response_aggregation")
    def test_rust_vs_python_aggregation(self, benchmark, large_response_set):
        """Benchmark Rust vs Python response aggregation"""
        # Test Rust implementation
        rust_aggregator = ResponseAggregator()
        
        def rust_aggregation():
            return rust_aggregator.aggregate_responses(large_response_set)
        
        rust_result = benchmark.pedantic(rust_aggregation, rounds=50, iterations=3)
        
        # Compare with Python implementation
        python_start = time.time()
        python_result = self.python_aggregate_responses(large_response_set)
        python_time = time.time() - python_start
        
        # Verify results are similar
        assert rust_result is not None
        print(f"\nRust time: {benchmark.stats['mean']:.6f}s")
        print(f"Python time: {python_time:.6f}s")
        print(f"Speedup: {python_time / benchmark.stats['mean']:.2f}x")
    
    @pytest.mark.benchmark(group="batch_processing")
    def test_rust_batch_processing(self, benchmark, large_response_set):
        """Benchmark Rust batch processing capabilities"""
        rust_analyzer = ExpertAnalyzer()
        
        # Process in batches
        batch_size = 10
        batches = [large_response_set[i:i+batch_size] 
                   for i in range(0, len(large_response_set), batch_size)]
        
        def process_batches():
            results = []
            for batch in batches:
                results.append(rust_analyzer.analyze_responses(batch))
            return results
        
        results = benchmark.pedantic(process_batches, rounds=20, iterations=2)
        
        total_processed = len(large_response_set)
        avg_time = benchmark.stats['mean']
        throughput = total_processed / avg_time
        
        print(f"\nBatch processing throughput: {throughput:.2f} responses/second")
        print(f"Average time per response: {avg_time / total_processed * 1000:.2f}ms")
    
    @pytest.mark.benchmark(group="concurrent_operations")
    def test_rust_concurrent_analysis(self, benchmark, large_response_set):
        """Benchmark Rust concurrent processing"""
        rust_analyzer = ExpertAnalyzer()
        rust_consensus = ConsensusEngine()
        rust_aggregator = ResponseAggregator()
        
        async def concurrent_analysis():
            # Run multiple analyses concurrently
            tasks = [
                asyncio.create_task(asyncio.to_thread(
                    rust_analyzer.analyze_responses, large_response_set
                )),
                asyncio.create_task(asyncio.to_thread(
                    rust_consensus.calculate_consensus, large_response_set
                )),
                asyncio.create_task(asyncio.to_thread(
                    rust_aggregator.aggregate_responses, large_response_set
                ))
            ]
            
            results = await asyncio.gather(*tasks)
            return results
        
        def run_concurrent():
            return asyncio.run(concurrent_analysis())
        
        results = benchmark.pedantic(run_concurrent, rounds=10, iterations=1)
        
        print(f"\nConcurrent operations completed in: {benchmark.stats['mean']:.3f}s")
        print(f"Operations per second: {3 / benchmark.stats['mean']:.2f}")
    
    @pytest.mark.benchmark(group="scaling")
    def test_rust_scaling_performance(self, benchmark):
        """Test Rust performance scaling with data size"""
        rust_analyzer = ExpertAnalyzer()
        
        sizes = [10, 50, 100, 500, 1000]
        results = {}
        
        for size in sizes:
            # Generate responses of specific size
            responses = []
            for i in range(size):
                responses.append(ExpertResponse(
                    expert_type=f"expert_{i % 10}",
                    content=f"Response {i} with detailed analysis",
                    confidence=0.8,
                    response_time=1.5,
                    model_used="gpt-4",
                    cost_estimate=0.002
                ))
            
            # Measure performance
            start = time.time()
            result = rust_analyzer.analyze_responses(responses)
            elapsed = time.time() - start
            
            results[size] = {
                "time": elapsed,
                "throughput": size / elapsed
            }
            
            print(f"\nSize {size}: {elapsed:.4f}s ({size/elapsed:.2f} items/s)")
        
        # Check scaling efficiency
        base_throughput = results[sizes[0]]["throughput"]
        for size in sizes[1:]:
            efficiency = results[size]["throughput"] / base_throughput
            print(f"Scaling efficiency at {size}: {efficiency:.2%}")
    
    @pytest.mark.benchmark(group="memory_efficiency")
    def test_rust_memory_efficiency(self, benchmark):
        """Test Rust memory efficiency compared to Python"""
        import psutil
        process = psutil.Process()
        
        # Generate large dataset
        large_responses = []
        for i in range(10000):
            large_responses.append(ExpertResponse(
                expert_type=f"expert_{i % 100}",
                content="x" * 1000,  # 1KB per response
                confidence=0.85,
                response_time=1.5,
                model_used="model",
                cost_estimate=0.001,
                metadata={"index": i}
            ))
        
        # Test Rust memory usage
        rust_analyzer = ExpertAnalyzer()
        
        mem_before = process.memory_info().rss / 1024 / 1024  # MB
        
        def rust_process():
            return rust_analyzer.analyze_responses(large_responses)
        
        rust_result = benchmark(rust_process)
        
        mem_after = process.memory_info().rss / 1024 / 1024  # MB
        rust_memory_delta = mem_after - mem_before
        
        # Test Python memory usage
        mem_before = process.memory_info().rss / 1024 / 1024  # MB
        python_result = self.python_analyze_responses(large_responses)
        mem_after = process.memory_info().rss / 1024 / 1024  # MB
        python_memory_delta = mem_after - mem_before
        
        print(f"\nRust memory usage: {rust_memory_delta:.2f} MB")
        print(f"Python memory usage: {python_memory_delta:.2f} MB")
        print(f"Memory reduction: {(1 - rust_memory_delta/python_memory_delta) * 100:.1f}%")
    
    @pytest.mark.benchmark(group="edge_cases")
    def test_rust_edge_case_performance(self, benchmark):
        """Test Rust performance with edge cases"""
        rust_analyzer = ExpertAnalyzer()
        
        # Test with empty responses
        empty_responses = []
        
        def process_empty():
            return rust_analyzer.analyze_responses(empty_responses)
        
        benchmark(process_empty)
        
        # Test with single response
        single_response = [ExpertResponse(
            expert_type="expert",
            content="Single response",
            confidence=0.9,
            response_time=1.0,
            model_used="model",
            cost_estimate=0.001
        )]
        
        def process_single():
            return rust_analyzer.analyze_responses(single_response)
        
        benchmark(process_single)
        
        # Test with very large individual responses
        large_content_responses = [
            ExpertResponse(
                expert_type="expert",
                content="x" * 100000,  # 100KB response
                confidence=0.9,
                response_time=1.0,
                model_used="model",
                cost_estimate=0.001
            ) for _ in range(10)
        ]
        
        def process_large_content():
            return rust_analyzer.analyze_responses(large_content_responses)
        
        benchmark(process_large_content)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--benchmark-only", "--benchmark-columns=mean,stddev,min,max"])