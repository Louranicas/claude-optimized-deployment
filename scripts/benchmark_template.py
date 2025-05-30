"""
Performance Benchmark Template
Part of PRIME DIRECTIVE: DOCUMENT REALITY, NOT ASPIRATION

This template ensures all performance claims are backed by reproducible benchmarks.
"""

import time
import statistics
import json
import platform
import psutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Callable, Any


class PerformanceBenchmark:
    """Standard benchmark framework for CODE project."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.results = []
        self.environment = self._capture_environment()
    
    def _capture_environment(self) -> Dict[str, Any]:
        """Capture system environment for reproducibility."""
        return {
            'timestamp': datetime.now().isoformat(),
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'cpu': platform.processor(),
            'cpu_count': psutil.cpu_count(),
            'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2),
            'code_version': self._get_git_hash(),
        }
    
    def _get_git_hash(self) -> str:
        """Get current git commit hash."""
        try:
            import subprocess
            return subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip()[:8]
        except:
            return 'unknown'
    
    def benchmark_function(self, 
                          func: Callable,
                          args: tuple = (),
                          kwargs: dict = None,
                          iterations: int = 100,
                          warmup: int = 10) -> Dict[str, Any]:
        """Benchmark a single function with statistical analysis."""
        if kwargs is None:
            kwargs = {}
        
        # Warmup runs
        for _ in range(warmup):
            func(*args, **kwargs)
        
        # Actual benchmark
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        # Calculate statistics
        stats = {
            'iterations': iterations,
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0,
            'min': min(times),
            'max': max(times),
            'p95': sorted(times)[int(len(times) * 0.95)],
            'p99': sorted(times)[int(len(times) * 0.99)],
        }
        
        return stats
    
    def compare_implementations(self,
                               baseline_func: Callable,
                               optimized_func: Callable,
                               test_data: Any,
                               iterations: int = 100) -> Dict[str, Any]:
        """Compare baseline vs optimized implementation."""
        
        # Ensure both functions produce same result
        baseline_result = baseline_func(test_data)
        optimized_result = optimized_func(test_data)
        
        if baseline_result != optimized_result:
            raise ValueError("Functions produce different results!")
        
        # Benchmark both
        baseline_stats = self.benchmark_function(baseline_func, args=(test_data,), iterations=iterations)
        optimized_stats = self.benchmark_function(optimized_func, args=(test_data,), iterations=iterations)
        
        # Calculate improvement
        improvement = baseline_stats['median'] / optimized_stats['median']
        
        return {
            'baseline': baseline_stats,
            'optimized': optimized_stats,
            'improvement_factor': round(improvement, 2),
            'speedup_percentage': round((improvement - 1) * 100, 1),
            'valid_comparison': True,
            'test_data_size': len(test_data) if hasattr(test_data, '__len__') else 'N/A'
        }
    
    def save_results(self, filepath: Path = None):
        """Save benchmark results to JSON file."""
        if filepath is None:
            filepath = Path(f'benchmark_{self.name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        
        data = {
            'benchmark_name': self.name,
            'description': self.description,
            'environment': self.environment,
            'results': self.results
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filepath


# Example usage template
def example_benchmark():
    """Template for creating benchmarks."""
    
    # Define baseline Python implementation
    def python_service_check(services: List[tuple]) -> List[bool]:
        """Baseline Python implementation."""
        results = []
        for host, port in services:
            # Simulate connection check
            import socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((host, port)) == 0
                sock.close()
                results.append(result)
            except:
                results.append(False)
        return results
    
    # Define optimized implementation (if available)
    try:
        from code_rust_core import infrastructure
        
        def rust_service_check(services: List[tuple]) -> List[bool]:
            """Rust-optimized implementation."""
            scanner = infrastructure.ServiceScanner(timeout_ms=500)
            return scanner.scan_services(services)
        
        rust_available = True
    except ImportError:
        rust_available = False
        rust_service_check = None
    
    # Create benchmark
    bench = PerformanceBenchmark(
        name="service_scanning",
        description="Compare Python vs Rust service scanning performance"
    )
    
    # Test with different data sizes
    test_sizes = [1, 10, 50, 100]
    
    for size in test_sizes:
        # Generate test data
        test_services = [(f"10.0.0.{i}", 80) for i in range(1, size + 1)]
        
        if rust_available:
            # Compare implementations
            try:
                result = bench.compare_implementations(
                    baseline_func=python_service_check,
                    optimized_func=rust_service_check,
                    test_data=test_services,
                    iterations=10  # Fewer iterations for network operations
                )
                
                print(f"\nService scanning benchmark ({size} services):")
                print(f"Python median: {result['baseline']['median']*1000:.2f}ms")
                print(f"Rust median: {result['optimized']['median']*1000:.2f}ms")
                print(f"Improvement: {result['improvement_factor']}x ({result['speedup_percentage']}%)")
                
                bench.results.append({
                    'test_size': size,
                    'comparison': result
                })
            except Exception as e:
                print(f"Benchmark failed for size {size}: {e}")
        else:
            # Just benchmark Python
            stats = bench.benchmark_function(
                python_service_check,
                args=(test_services,),
                iterations=10
            )
            print(f"\nPython service scanning ({size} services):")
            print(f"Median time: {stats['median']*1000:.2f}ms")
            
            bench.results.append({
                'test_size': size,
                'python_only': stats
            })
    
    # Save results
    filepath = bench.save_results()
    print(f"\nBenchmark results saved to: {filepath}")
    
    return bench


def generate_benchmark_report(benchmark_file: Path) -> str:
    """Generate markdown report from benchmark results."""
    with open(benchmark_file, 'r') as f:
        data = json.load(f)
    
    report = [
        f"# Benchmark Report: {data['benchmark_name']}",
        f"**Description**: {data['description']}",
        f"**Date**: {data['environment']['timestamp']}",
        "",
        "## Environment",
        f"- Platform: {data['environment']['platform']}",
        f"- Python: {data['environment']['python_version']}",
        f"- CPU: {data['environment']['cpu']} ({data['environment']['cpu_count']} cores)",
        f"- Memory: {data['environment']['memory_gb']}GB",
        f"- Code Version: {data['environment']['code_version']}",
        "",
        "## Results",
        ""
    ]
    
    for result in data['results']:
        if 'comparison' in result:
            comp = result['comparison']
            report.extend([
                f"### Test Size: {result['test_size']} items",
                f"- Baseline Median: {comp['baseline']['median']*1000:.2f}ms",
                f"- Optimized Median: {comp['optimized']['median']*1000:.2f}ms",
                f"- **Improvement: {comp['improvement_factor']}x**",
                f"- Valid Comparison: {comp['valid_comparison']}",
                ""
            ])
        else:
            stats = result.get('python_only', {})
            report.extend([
                f"### Test Size: {result['test_size']} items",
                f"- Median Time: {stats.get('median', 0)*1000:.2f}ms",
                f"- Std Dev: {stats.get('stdev', 0)*1000:.2f}ms",
                ""
            ])
    
    report.extend([
        "## Methodology",
        "- Each test includes warmup runs",
        "- Statistical analysis includes mean, median, stdev, min, max, p95, p99",
        "- Results are reproducible using the environment information above",
        "",
        "## Interpretation",
        "- Improvement factors are based on median times",
        "- Network operations may show high variance",
        "- Results are specific to the test environment",
        ""
    ])
    
    return '\n'.join(report)


if __name__ == '__main__':
    # Run example benchmark
    bench = example_benchmark()
    
    # Generate report
    if bench.results:
        report = generate_benchmark_report(Path(f'benchmark_{bench.name}_*.json').glob('*').__next__())
        print("\n" + "="*50)
        print(report)
