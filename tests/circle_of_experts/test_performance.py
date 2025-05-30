"""
Performance benchmarking tests for Circle of Experts.

Compares performance between pure Python and Rust-accelerated implementations.
"""

import pytest
import asyncio
import time
import statistics
import json
import psutil
import os
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
# import matplotlib.pyplot as plt  # Optional, only needed for plot generation
# import numpy as np  # Optional, only needed for plot generation

from src.circle_of_experts import (
    ExpertQuery,
    ExpertResponse,
    ExpertType,
    QueryType
)

# Try to import Rust modules
try:
    from claude_optimized_deployment_rust.circle_of_experts import (
        ExpertAnalyzer,
        QueryValidator
    )
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    ExpertAnalyzer = None
    QueryValidator = None


@dataclass
class BenchmarkResult:
    """Container for benchmark results."""
    operation: str
    implementation: str
    input_size: int
    duration: float
    memory_used: float
    throughput: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "implementation": self.implementation,
            "input_size": self.input_size,
            "duration_ms": self.duration * 1000,
            "memory_mb": self.memory_used / (1024 * 1024),
            "throughput_ops_per_sec": self.throughput
        }


class PerformanceBenchmark:
    """Base class for performance benchmarks."""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.process = psutil.Process()
    
    def measure_memory(self) -> float:
        """Measure current memory usage."""
        return self.process.memory_info().rss
    
    def benchmark_operation(
        self,
        operation_name: str,
        implementation: str,
        operation_func,
        input_data: Any,
        iterations: int = 5
    ) -> BenchmarkResult:
        """Benchmark a single operation."""
        # Warm-up
        operation_func(input_data)
        
        # Measure
        durations = []
        memory_before = self.measure_memory()
        
        for _ in range(iterations):
            start_time = time.perf_counter()
            operation_func(input_data)
            end_time = time.perf_counter()
            durations.append(end_time - start_time)
        
        memory_after = self.measure_memory()
        
        # Calculate metrics
        avg_duration = statistics.mean(durations)
        memory_used = memory_after - memory_before
        input_size = self._get_input_size(input_data)
        throughput = input_size / avg_duration if avg_duration > 0 else 0
        
        result = BenchmarkResult(
            operation=operation_name,
            implementation=implementation,
            input_size=input_size,
            duration=avg_duration,
            memory_used=memory_used,
            throughput=throughput
        )
        
        self.results.append(result)
        return result
    
    def _get_input_size(self, input_data: Any) -> int:
        """Get the size of input data."""
        if isinstance(input_data, list):
            return len(input_data)
        elif isinstance(input_data, str):
            return len(input_data)
        else:
            return 1
    
    def save_results(self, filename: str):
        """Save benchmark results to JSON."""
        results_dict = {
            "timestamp": datetime.now().isoformat(),
            "rust_available": RUST_AVAILABLE,
            "results": [r.to_dict() for r in self.results]
        }
        
        with open(filename, 'w') as f:
            json.dump(results_dict, f, indent=2)
    
    def plot_results(self, output_dir: str = "benchmark_plots"):
        """Generate performance comparison plots."""
        # Plotting disabled - requires matplotlib
        pass
        # os.makedirs(output_dir, exist_ok=True)
        # 
        # # Group results by operation
        # operations = {}
        # for result in self.results:
        #     if result.operation not in operations:
        #         operations[result.operation] = []
        #     operations[result.operation].append(result)
        # 
        # # Create plots for each operation
        # for op_name, op_results in operations.items():
        #     self._plot_operation_comparison(op_name, op_results, output_dir)
    
    def _plot_operation_comparison(self, operation: str, results: List[BenchmarkResult], output_dir: str):
        """Plot comparison for a single operation."""
        # Plotting disabled - requires matplotlib
        pass


@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust modules not available")
class TestResponseAnalysisPerformance(PerformanceBenchmark):
    """Benchmark response analysis performance."""
    
    def create_test_responses(self, count: int) -> List[Dict[str, Any]]:
        """Create test expert responses."""
        responses = []
        for i in range(count):
            responses.append({
                "confidence": 0.7 + (i % 3) * 0.1,
                "expert_type": f"expert_{i % 5}",
                "recommendations": [f"Recommendation {j} for expert {i}" for j in range(10)],
                "limitations": [f"Limitation {j} for expert {i}" for j in range(5)]
            })
        return responses
    
    def python_analyze_responses(self, responses: List[Dict]) -> Dict:
        """Pure Python implementation of response analysis."""
        if not responses:
            return {
                "total_responses": 0,
                "average_confidence": 0.0,
                "consensus_score": 0.0,
                "high_confidence_count": 0,
                "common_recommendations": [],
                "unique_limitations": []
            }
        
        # Calculate metrics
        total_confidence = sum(r.get('confidence', 0) for r in responses)
        average_confidence = total_confidence / len(responses)
        
        high_confidence_count = sum(1 for r in responses if r.get('confidence', 0) >= 0.7)
        
        # Find common recommendations
        recommendation_counts = {}
        for response in responses:
            for rec in response.get('recommendations', []):
                rec_lower = rec.lower()
                recommendation_counts[rec_lower] = recommendation_counts.get(rec_lower, 0) + 1
        
        threshold = len(responses) // 2
        common_recommendations = [rec for rec, count in recommendation_counts.items() if count > threshold]
        
        # Collect unique limitations
        unique_limitations = set()
        for response in responses:
            for limitation in response.get('limitations', []):
                unique_limitations.add(limitation.lower())
        
        # Simple consensus score
        consensus_score = average_confidence * 0.8 + (high_confidence_count / len(responses)) * 0.2
        
        return {
            "total_responses": len(responses),
            "average_confidence": average_confidence,
            "consensus_score": consensus_score,
            "high_confidence_count": high_confidence_count,
            "common_recommendations": common_recommendations,
            "unique_limitations": list(unique_limitations)
        }
    
    def test_response_analysis_scaling(self):
        """Test how response analysis scales with input size."""
        analyzer = ExpertAnalyzer()
        
        input_sizes = [10, 50, 100, 500, 1000, 5000]
        
        for size in input_sizes:
            responses = self.create_test_responses(size)
            
            # Benchmark Python
            self.benchmark_operation(
                "Response Analysis",
                "Python",
                self.python_analyze_responses,
                responses
            )
            
            # Benchmark Rust
            self.benchmark_operation(
                "Response Analysis",
                "Rust",
                analyzer.analyze_responses,
                responses
            )
        
        # Save results
        self.save_results("response_analysis_benchmark.json")
        
        # Verify Rust is faster for larger inputs
        for size in input_sizes[2:]:  # Start from 100
            python_result = next(r for r in self.results if r.implementation == "Python" and r.input_size == size)
            rust_result = next(r for r in self.results if r.implementation == "Rust" and r.input_size == size)
            assert rust_result.duration < python_result.duration
    
    def test_memory_efficiency(self):
        """Test memory usage comparison."""
        analyzer = ExpertAnalyzer()
        
        # Large dataset
        large_responses = self.create_test_responses(10000)
        
        # Measure Python memory
        import gc
        gc.collect()
        mem_before = self.measure_memory()
        python_result = self.python_analyze_responses(large_responses)
        mem_after_python = self.measure_memory()
        python_memory = mem_after_python - mem_before
        
        # Measure Rust memory
        gc.collect()
        mem_before = self.measure_memory()
        rust_result = analyzer.analyze_responses(large_responses)
        mem_after_rust = self.measure_memory()
        rust_memory = mem_after_rust - mem_before
        
        # Rust should use less memory
        assert rust_memory < python_memory * 1.5  # Allow some overhead
        
        # Results should be similar
        assert rust_result['total_responses'] == python_result['total_responses']
        assert abs(rust_result['average_confidence'] - python_result['average_confidence']) < 0.01


@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust modules not available")
class TestQueryValidationPerformance(PerformanceBenchmark):
    """Benchmark query validation performance."""
    
    def create_test_queries(self, count: int) -> List[str]:
        """Create test queries."""
        queries = []
        for i in range(count):
            length = 50 + (i % 100)
            queries.append(f"Test query {i}: " + "x" * length)
        return queries
    
    def python_validate_queries(self, queries: List[str]) -> List[bool]:
        """Pure Python query validation."""
        min_length = 10
        max_length = 10000
        forbidden_patterns = ["spam", "malicious", "hack"]
        
        results = []
        for query in queries:
            # Length check
            if len(query) < min_length or len(query) > max_length:
                results.append(False)
                continue
            
            # Forbidden pattern check
            valid = True
            for pattern in forbidden_patterns:
                if pattern in query.lower():
                    valid = False
                    break
            
            results.append(valid)
        
        return results
    
    def test_batch_validation_scaling(self):
        """Test how batch validation scales."""
        validator = QueryValidator()
        
        input_sizes = [100, 500, 1000, 5000, 10000]
        
        for size in input_sizes:
            queries = self.create_test_queries(size)
            
            # Benchmark Python
            self.benchmark_operation(
                "Batch Validation",
                "Python",
                self.python_validate_queries,
                queries
            )
            
            # Benchmark Rust
            self.benchmark_operation(
                "Batch Validation",
                "Rust",
                validator.validate_batch,
                queries
            )
        
        # Save results
        self.save_results("query_validation_benchmark.json")
        
        # Generate plots
        self.plot_results()
    
    def test_regex_pattern_matching(self):
        """Test performance with complex patterns."""
        complex_patterns = [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",  # IP
            r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)"  # URL
        ]
        
        validator = QueryValidator(forbidden_patterns=complex_patterns)
        
        # Create queries with patterns
        test_queries = [
            "Contact me at user@example.com",
            "Server IP is 192.168.1.1",
            "Visit https://www.example.com/page",
            "Normal query without patterns",
        ] * 250  # Total 1000 queries
        
        # Benchmark
        start_time = time.perf_counter()
        results = validator.validate_batch(test_queries)
        rust_time = time.perf_counter() - start_time
        
        # Should complete quickly even with complex patterns
        assert rust_time < 0.5  # Under 500ms for 1000 queries
        assert len(results) == 1000


@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust modules not available")
class TestConcurrentPerformance(PerformanceBenchmark):
    """Test performance under concurrent load."""
    
    @pytest.mark.asyncio
    async def test_concurrent_analysis(self):
        """Test concurrent response analysis."""
        analyzer = ExpertAnalyzer()
        
        # Create responses for concurrent processing
        response_sets = []
        for i in range(20):
            responses = [{
                "confidence": 0.8,
                "expert_type": f"expert_{i}",
                "recommendations": [f"Rec {j}" for j in range(20)],
                "limitations": [f"Lim {j}" for j in range(10)]
            } for _ in range(100)]
            response_sets.append(responses)
        
        # Concurrent Rust processing
        start_time = time.time()
        tasks = []
        for responses in response_sets:
            task = asyncio.create_task(
                asyncio.to_thread(analyzer.analyze_responses, responses)
            )
            tasks.append(task)
        
        rust_results = await asyncio.gather(*tasks)
        rust_time = time.time() - start_time
        
        # Sequential Python processing for comparison
        start_time = time.time()
        python_results = []
        for responses in response_sets:
            python_results.append(self.python_analyze_responses(responses))
        python_time = time.time() - start_time
        
        # Rust with concurrency should be much faster
        assert rust_time < python_time
        assert len(rust_results) == len(python_results)
        
        # Results should be consistent
        for rust_res, python_res in zip(rust_results, python_results):
            assert rust_res['total_responses'] == python_res['total_responses']
    
    def python_analyze_responses(self, responses: List[Dict]) -> Dict:
        """Simple Python implementation for comparison."""
        return {
            "total_responses": len(responses),
            "average_confidence": sum(r.get('confidence', 0) for r in responses) / len(responses) if responses else 0
        }


@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust modules not available")
class TestRealWorldScenarios(PerformanceBenchmark):
    """Test performance in real-world scenarios."""
    
    @pytest.mark.asyncio
    async def test_full_expert_consultation_flow(self):
        """Benchmark a complete expert consultation."""
        validator = QueryValidator(min_length=20, max_length=5000)
        analyzer = ExpertAnalyzer(confidence_threshold=0.7)
        
        # Simulate a real query
        query_content = """
        I need to optimize a Python web application that's experiencing performance issues.
        The application handles 10,000 requests per second and uses Django with PostgreSQL.
        What are the best practices for improving performance while maintaining code quality?
        """
        
        # Measure full flow timing
        total_start = time.time()
        
        # 1. Validate query
        validation_start = time.time()
        is_valid = validator.is_valid_query(query_content)
        validation_time = time.time() - validation_start
        
        assert is_valid
        
        # 2. Simulate expert responses (would normally be async API calls)
        expert_responses = []
        expert_types = ["technical", "infrastructure", "database", "security", "devops"]
        
        for expert in expert_types:
            response = {
                "confidence": 0.75 + (hash(expert) % 20) / 100,
                "expert_type": expert,
                "recommendations": [
                    f"Use caching layers (Redis/Memcached)",
                    f"Implement database query optimization",
                    f"Add application-level profiling",
                    f"Use async processing for I/O operations",
                    f"Implement connection pooling"
                ],
                "limitations": [
                    f"Requires infrastructure changes",
                    f"Initial performance overhead from monitoring"
                ]
            }
            expert_responses.append(response)
        
        # 3. Analyze responses
        analysis_start = time.time()
        consensus = analyzer.analyze_responses(expert_responses)
        analysis_time = time.time() - analysis_start
        
        total_time = time.time() - total_start
        
        # Performance assertions
        assert validation_time < 0.001  # Validation should be instant
        assert analysis_time < 0.01     # Analysis should be very fast
        assert total_time < 0.05        # Entire flow under 50ms
        
        # Verify results
        assert consensus['total_responses'] == 5
        assert consensus['average_confidence'] > 0.75
        assert len(consensus['common_recommendations']) > 0
    
    def test_production_load_simulation(self):
        """Simulate production-level load."""
        analyzer = ExpertAnalyzer()
        validator = QueryValidator()
        
        # Simulate 1 hour of production traffic
        # Assuming 100 queries per minute
        queries_per_batch = 100
        batches = 60  # 60 minutes
        
        total_start = time.time()
        
        for batch in range(batches):
            # Generate queries
            queries = [f"Production query {batch}_{i}: " + "x" * (50 + i % 100) 
                      for i in range(queries_per_batch)]
            
            # Validate queries
            valid_queries = validator.validate_batch(queries)
            
            # Generate responses for valid queries
            valid_count = sum(valid_queries)
            if valid_count > 0:
                responses = []
                for i in range(valid_count):
                    responses.append({
                        "confidence": 0.7 + (i % 30) / 100,
                        "expert_type": f"expert_{i % 5}",
                        "recommendations": [f"Rec {j}" for j in range(5)],
                        "limitations": [f"Lim {j}" for j in range(2)]
                    })
                
                # Analyze responses
                analyzer.analyze_responses(responses)
        
        total_time = time.time() - total_start
        
        # Should handle 1 hour of traffic in seconds, not minutes
        assert total_time < 60  # Process 1 hour of traffic in under 1 minute
        
        queries_processed = queries_per_batch * batches
        throughput = queries_processed / total_time
        
        # Should maintain high throughput
        assert throughput > 100  # At least 100 queries per second


def run_all_benchmarks():
    """Run all performance benchmarks and generate report."""
    print("Running Circle of Experts Performance Benchmarks...")
    
    # Create output directory
    output_dir = "benchmark_results"
    os.makedirs(output_dir, exist_ok=True)
    
    # Run benchmarks
    benchmarks = [
        TestResponseAnalysisPerformance(),
        TestQueryValidationPerformance(),
        TestConcurrentPerformance(),
        TestRealWorldScenarios()
    ]
    
    all_results = []
    
    for benchmark in benchmarks:
        print(f"Running {benchmark.__class__.__name__}...")
        
        # Run test methods
        for method_name in dir(benchmark):
            if method_name.startswith("test_"):
                method = getattr(benchmark, method_name)
                try:
                    if asyncio.iscoroutinefunction(method):
                        asyncio.run(method())
                    else:
                        method()
                except Exception as e:
                    print(f"  Error in {method_name}: {e}")
        
        all_results.extend(benchmark.results)
    
    # Generate summary report
    summary = {
        "timestamp": datetime.now().isoformat(),
        "total_benchmarks": len(all_results),
        "rust_speedup_summary": calculate_speedup_summary(all_results)
    }
    
    with open(os.path.join(output_dir, "benchmark_summary.json"), 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\nBenchmark complete. Results saved to {output_dir}/")
    print_speedup_summary(summary["rust_speedup_summary"])


def calculate_speedup_summary(results: List[BenchmarkResult]) -> Dict[str, float]:
    """Calculate average speedup for each operation."""
    operations = {}
    
    for result in results:
        if result.operation not in operations:
            operations[result.operation] = {"python": [], "rust": []}
        
        impl_key = result.implementation.lower()
        if impl_key in operations[result.operation]:
            operations[result.operation][impl_key].append(result.duration)
    
    speedup_summary = {}
    
    for op_name, timings in operations.items():
        if timings["python"] and timings["rust"]:
            avg_python = statistics.mean(timings["python"])
            avg_rust = statistics.mean(timings["rust"])
            speedup = avg_python / avg_rust if avg_rust > 0 else 0
            speedup_summary[op_name] = round(speedup, 2)
    
    return speedup_summary


def print_speedup_summary(speedup_summary: Dict[str, float]):
    """Print a formatted speedup summary."""
    print("\n=== Rust Performance Speedup Summary ===")
    for operation, speedup in speedup_summary.items():
        print(f"{operation}: {speedup}x faster")
    
    avg_speedup = statistics.mean(speedup_summary.values()) if speedup_summary else 0
    print(f"\nAverage speedup: {avg_speedup:.2f}x")


if __name__ == "__main__":
    if RUST_AVAILABLE:
        run_all_benchmarks()
    else:
        print("Rust modules not available. Run 'make rust-build' first.")
        pytest.main([__file__, "-v"])