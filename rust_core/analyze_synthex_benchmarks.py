#!/usr/bin/env python3
"""
Analyze and visualize SYNTHEX benchmark results.
Provides detailed performance metrics and comparisons.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
import statistics
from datetime import datetime
from dataclasses import dataclass

@dataclass
class BenchmarkResult:
    """Represents a single benchmark result."""
    name: str
    mean: float
    median: float
    std_dev: float
    min: float
    max: float
    iterations: int
    throughput: Optional[float] = None

class SynthexBenchmarkAnalyzer:
    """Analyzes SYNTHEX benchmark results from Criterion output."""
    
    def __init__(self, criterion_dir: str = "target/criterion"):
        self.criterion_dir = Path(criterion_dir)
        self.results: Dict[str, Dict[str, BenchmarkResult]] = {}
        
    def load_results(self) -> None:
        """Load all benchmark results from Criterion output."""
        if not self.criterion_dir.exists():
            print(f"Error: Criterion directory not found: {self.criterion_dir}")
            return
            
        for group_dir in self.criterion_dir.iterdir():
            if group_dir.is_dir() and group_dir.name.startswith("synthex_"):
                self.results[group_dir.name] = self._load_group_results(group_dir)
                
    def _load_group_results(self, group_dir: Path) -> Dict[str, BenchmarkResult]:
        """Load results for a benchmark group."""
        group_results = {}
        
        for bench_dir in group_dir.iterdir():
            if bench_dir.is_dir():
                estimates_file = bench_dir / "base" / "estimates.json"
                if estimates_file.exists():
                    with open(estimates_file) as f:
                        data = json.load(f)
                        
                    result = BenchmarkResult(
                        name=bench_dir.name,
                        mean=data["mean"]["point_estimate"],
                        median=data["median"]["point_estimate"],
                        std_dev=data["std_dev"]["point_estimate"],
                        min=data["mean"]["confidence_interval"]["lower_bound"],
                        max=data["mean"]["confidence_interval"]["upper_bound"],
                        iterations=data.get("iterations", 0)
                    )
                    
                    # Check for throughput data
                    if "throughput" in data:
                        result.throughput = data["throughput"]["per_iteration"]
                        
                    group_results[bench_dir.name] = result
                    
        return group_results
        
    def print_summary(self) -> None:
        """Print a comprehensive summary of benchmark results."""
        print("\n" + "="*80)
        print("SYNTHEX PERFORMANCE BENCHMARK SUMMARY")
        print("="*80)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Single search performance
        if "synthex_single_search" in self.results:
            self._print_group_summary("Single Search Operations", self.results["synthex_single_search"])
            
        # Concurrent search performance
        if "synthex_concurrent_searches" in self.results:
            self._print_concurrent_summary("Concurrent Search Scalability", self.results["synthex_concurrent_searches"])
            
        # Memory operations
        if "synthex_memory_operations" in self.results:
            self._print_group_summary("Memory Operations", self.results["synthex_memory_operations"])
            
        # Cache performance
        if "synthex_cache" in self.results:
            self._print_cache_summary("Cache Performance", self.results["synthex_cache"])
            
        # End-to-end pipeline
        if "synthex_end_to_end" in self.results:
            self._print_group_summary("End-to-End Pipeline", self.results["synthex_end_to_end"])
            
    def _print_group_summary(self, title: str, results: Dict[str, BenchmarkResult]) -> None:
        """Print summary for a benchmark group."""
        print(f"\n{title}")
        print("-" * len(title))
        
        for name, result in sorted(results.items()):
            latency_ms = result.mean / 1_000_000  # Convert ns to ms
            print(f"\n{name}:")
            print(f"  Mean latency: {latency_ms:.3f} ms")
            print(f"  Median: {result.median/1_000_000:.3f} ms")
            print(f"  Std Dev: {result.std_dev/1_000_000:.3f} ms")
            print(f"  Range: [{result.min/1_000_000:.3f}, {result.max/1_000_000:.3f}] ms")
            
            if result.throughput:
                print(f"  Throughput: {result.throughput:.0f} ops/sec")
                
    def _print_concurrent_summary(self, title: str, results: Dict[str, BenchmarkResult]) -> None:
        """Print summary for concurrent operations."""
        print(f"\n{title}")
        print("-" * len(title))
        
        # Extract concurrency levels and sort
        concurrency_results = []
        for name, result in results.items():
            try:
                concurrency = int(name)
                concurrency_results.append((concurrency, result))
            except ValueError:
                continue
                
        concurrency_results.sort(key=lambda x: x[0])
        
        print("\nConcurrency | Latency (ms) | Throughput (ops/s) | Efficiency")
        print("-" * 60)
        
        baseline_throughput = None
        for concurrency, result in concurrency_results:
            latency_ms = result.mean / 1_000_000
            throughput = concurrency / (result.mean / 1_000_000_000)  # ops/sec
            
            if baseline_throughput is None:
                baseline_throughput = throughput / concurrency
                efficiency = 100.0
            else:
                efficiency = (throughput / concurrency) / baseline_throughput * 100
                
            print(f"{concurrency:>11} | {latency_ms:>12.3f} | {throughput:>18.0f} | {efficiency:>10.1f}%")
            
    def _print_cache_summary(self, title: str, results: Dict[str, BenchmarkResult]) -> None:
        """Print cache performance summary."""
        print(f"\n{title}")
        print("-" * len(title))
        
        if "cache_hit" in results and "cache_miss" in results:
            hit_latency = results["cache_hit"].mean / 1_000_000
            miss_latency = results["cache_miss"].mean / 1_000_000
            speedup = miss_latency / hit_latency
            
            print(f"\nCache Hit Latency: {hit_latency:.3f} ms")
            print(f"Cache Miss Latency: {miss_latency:.3f} ms")
            print(f"Cache Speedup: {speedup:.1f}x")
            print(f"Cache Efficiency: {(1 - hit_latency/miss_latency) * 100:.1f}%")
            
    def generate_report(self, output_file: str = "synthex_benchmark_report.md") -> None:
        """Generate a detailed markdown report."""
        with open(output_file, "w") as f:
            f.write("# SYNTHEX Performance Benchmark Report\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            self._write_executive_summary(f)
            
            # Detailed Results
            f.write("\n## Detailed Results\n\n")
            for group_name, results in sorted(self.results.items()):
                f.write(f"### {group_name.replace('synthex_', '').replace('_', ' ').title()}\n\n")
                self._write_group_details(f, results)
                
            # Performance Recommendations
            f.write("\n## Performance Recommendations\n\n")
            self._write_recommendations(f)
            
        print(f"\nDetailed report generated: {output_file}")
        
    def _write_executive_summary(self, f) -> None:
        """Write executive summary to report."""
        # Calculate key metrics
        single_search_latency = None
        if "synthex_single_search" in self.results and "simple_query" in self.results["synthex_single_search"]:
            single_search_latency = self.results["synthex_single_search"]["simple_query"].mean / 1_000_000
            
        concurrent_throughput = None
        if "synthex_concurrent_searches" in self.results and "100" in self.results["synthex_concurrent_searches"]:
            result = self.results["synthex_concurrent_searches"]["100"]
            concurrent_throughput = 100 / (result.mean / 1_000_000_000)
            
        f.write("### Key Performance Metrics\n\n")
        if single_search_latency:
            f.write(f"- **Single Search Latency**: {single_search_latency:.3f} ms\n")
        if concurrent_throughput:
            f.write(f"- **Concurrent Throughput (100 searches)**: {concurrent_throughput:,.0f} searches/sec\n")
            
        # Memory efficiency
        if "synthex_memory_operations" in self.results:
            f.write("\n### Memory Efficiency\n\n")
            for name, result in self.results["synthex_memory_operations"].items():
                if "aggregate_results" in name:
                    ops_per_sec = 1_000_000_000 / result.mean
                    f.write(f"- Result aggregation: {ops_per_sec:,.0f} operations/sec\n")
                    
    def _write_group_details(self, f, results: Dict[str, BenchmarkResult]) -> None:
        """Write detailed results for a group."""
        f.write("| Benchmark | Mean (ms) | Median (ms) | Std Dev (ms) | Min (ms) | Max (ms) |\n")
        f.write("|-----------|-----------|-------------|--------------|----------|----------|\n")
        
        for name, result in sorted(results.items()):
            f.write(f"| {name} | {result.mean/1_000_000:.3f} | {result.median/1_000_000:.3f} | ")
            f.write(f"{result.std_dev/1_000_000:.3f} | {result.min/1_000_000:.3f} | ")
            f.write(f"{result.max/1_000_000:.3f} |\n")
            
        f.write("\n")
        
    def _write_recommendations(self, f) -> None:
        """Write performance recommendations based on results."""
        f.write("Based on the benchmark results:\n\n")
        
        # Cache recommendations
        if "synthex_cache" in self.results:
            if "cache_hit" in self.results["synthex_cache"] and "cache_miss" in self.results["synthex_cache"]:
                hit = self.results["synthex_cache"]["cache_hit"].mean
                miss = self.results["synthex_cache"]["cache_miss"].mean
                if hit < miss * 0.5:
                    f.write("1. **Cache Performance**: Excellent cache efficiency detected. ")
                    f.write(f"Cache hits are {miss/hit:.1f}x faster than misses.\n\n")
                    
        # Concurrency recommendations
        if "synthex_concurrent_searches" in self.results:
            f.write("2. **Concurrency Scaling**: ")
            # Check scaling efficiency
            results = self.results["synthex_concurrent_searches"]
            if "10" in results and "100" in results:
                scaling_factor = (results["10"].mean * 10) / (results["100"].mean)
                if scaling_factor > 8:
                    f.write("Excellent scaling observed. System handles high concurrency efficiently.\n\n")
                else:
                    f.write(f"Scaling efficiency: {scaling_factor:.1f}x. Consider optimizing for higher concurrency.\n\n")
                    
        # Memory recommendations
        if "synthex_memory_operations" in self.results:
            f.write("3. **Memory Operations**: ")
            # Check for large result set handling
            large_results = [r for n, r in self.results["synthex_memory_operations"].items() if "10000" in n]
            if large_results:
                ops_per_sec = 1_000_000_000 / large_results[0].mean
                f.write(f"Can process {ops_per_sec:,.0f} large result sets per second.\n\n")


def main():
    """Main entry point."""
    analyzer = SynthexBenchmarkAnalyzer()
    
    print("Loading SYNTHEX benchmark results...")
    analyzer.load_results()
    
    if not analyzer.results:
        print("No benchmark results found. Please run the benchmarks first:")
        print("  cargo bench --bench synthex_bench")
        sys.exit(1)
        
    # Print summary to console
    analyzer.print_summary()
    
    # Generate detailed report
    analyzer.generate_report()
    
    # Performance grade
    print("\n" + "="*80)
    print("PERFORMANCE GRADE")
    print("="*80)
    
    # Calculate overall grade based on key metrics
    grade_points = 0
    grade_checks = 0
    
    # Check single search latency (target: < 10ms)
    if "synthex_single_search" in analyzer.results and "simple_query" in analyzer.results["synthex_single_search"]:
        latency = analyzer.results["synthex_single_search"]["simple_query"].mean / 1_000_000
        grade_checks += 1
        if latency < 10:
            grade_points += 1
            print(f"✅ Single search latency: {latency:.3f} ms (Target: < 10 ms)")
        else:
            print(f"❌ Single search latency: {latency:.3f} ms (Target: < 10 ms)")
            
    # Check concurrent throughput (target: > 1000 ops/sec at 100 concurrent)
    if "synthex_concurrent_searches" in analyzer.results and "100" in analyzer.results["synthex_concurrent_searches"]:
        result = analyzer.results["synthex_concurrent_searches"]["100"]
        throughput = 100 / (result.mean / 1_000_000_000)
        grade_checks += 1
        if throughput > 1000:
            grade_points += 1
            print(f"✅ Concurrent throughput: {throughput:,.0f} ops/sec (Target: > 1,000)")
        else:
            print(f"❌ Concurrent throughput: {throughput:,.0f} ops/sec (Target: > 1,000)")
            
    # Overall grade
    if grade_checks > 0:
        percentage = (grade_points / grade_checks) * 100
        grade = "A" if percentage >= 90 else "B" if percentage >= 80 else "C" if percentage >= 70 else "D"
        print(f"\nOverall Performance Grade: {grade} ({percentage:.0f}%)")
    
    print("\n" + "="*80)


if __name__ == "__main__":
    main()