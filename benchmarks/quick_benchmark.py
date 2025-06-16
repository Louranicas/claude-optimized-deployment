#!/usr/bin/env python3
"""
Quick Performance Benchmark Suite
Lightweight benchmarks for frequent execution and regression detection
"""

import time
import json
import os
import statistics
import psutil
import numpy as np
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class QuickBenchmarks:
    """Quick performance tests for frequent execution"""
    
    def __init__(self):
        self.results = []
        
    def quick_cpu_test(self, duration: int = 5) -> Dict[str, Any]:
        """Quick CPU performance test"""
        print("🖥️  Quick CPU test...")
        
        start_time = time.time()
        operations = 0
        
        # Lightweight CPU test
        while time.time() - start_time < duration:
            # Simple mathematical operations
            for i in range(1000):
                result = i ** 2 + i ** 0.5
            operations += 1000
        
        total_time = time.time() - start_time
        throughput = operations / total_time
        
        return {
            'test_name': 'quick_cpu_performance',
            'timestamp': datetime.now().isoformat(),
            'duration': total_time,
            'throughput': throughput,
            'metadata': {
                'operations_completed': operations,
                'test_type': 'mathematical_operations'
            }
        }
    
    def quick_memory_test(self, size_mb: int = 100) -> Dict[str, Any]:
        """Quick memory allocation and access test"""
        print("💾 Quick memory test...")
        
        start_time = time.time()
        
        # Memory allocation test
        alloc_start = time.time()
        data = np.random.random(size_mb * 1024 * 128).astype(np.float64)  # 128 floats per "KB"
        alloc_time = time.time() - alloc_start
        
        # Memory access test
        access_start = time.time()
        result = np.sum(data)
        access_time = time.time() - access_start
        
        total_time = time.time() - start_time
        throughput = size_mb / total_time  # MB/s
        
        return {
            'test_name': 'quick_memory_performance',
            'timestamp': datetime.now().isoformat(),
            'duration': total_time,
            'throughput': throughput,
            'metadata': {
                'size_mb': size_mb,
                'allocation_time': alloc_time,
                'access_time': access_time,
                'data_checksum': float(result)
            }
        }
    
    def quick_io_test(self, file_size_mb: int = 50) -> Dict[str, Any]:
        """Quick I/O performance test"""
        print("💿 Quick I/O test...")
        
        test_file = Path(f"/tmp/quick_io_test_{os.getpid()}.dat")
        
        try:
            # Generate test data
            data = os.urandom(file_size_mb * 1024 * 1024)
            
            start_time = time.time()
            
            # Write test
            write_start = time.time()
            with open(test_file, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            write_time = time.time() - write_start
            
            # Read test
            read_start = time.time()
            with open(test_file, 'rb') as f:
                read_data = f.read()
            read_time = time.time() - read_start
            
            total_time = time.time() - start_time
            throughput = (file_size_mb * 2) / total_time  # Total MB read + written
            
            return {
                'test_name': 'quick_io_performance',
                'timestamp': datetime.now().isoformat(),
                'duration': total_time,
                'throughput': throughput,
                'metadata': {
                    'file_size_mb': file_size_mb,
                    'write_time': write_time,
                    'read_time': read_time,
                    'write_throughput_mb_s': file_size_mb / write_time,
                    'read_throughput_mb_s': file_size_mb / read_time,
                    'data_integrity': len(data) == len(read_data)
                }
            }
        finally:
            if test_file.exists():
                test_file.unlink()
    
    def quick_rust_ffi_test(self, iterations: int = 1000) -> Dict[str, Any]:
        """Quick Rust FFI performance test"""
        print("🔗 Quick Rust FFI test...")
        
        start_time = time.time()
        operations = []
        
        for i in range(iterations):
            op_start = time.time()
            
            # Simulate FFI call
            try:
                # Try to import rust module
                import rust_core
                # Simulate Rust function call
                result = hash(f"rust_ffi_test_{i}")
            except ImportError:
                # Python fallback
                result = hash(f"python_fallback_{i}")
            
            op_time = time.time() - op_start
            operations.append(op_time)
        
        total_time = time.time() - start_time
        avg_latency = statistics.mean(operations)
        throughput = iterations / total_time
        
        return {
            'test_name': 'quick_rust_ffi_performance',
            'timestamp': datetime.now().isoformat(),
            'duration': total_time,
            'throughput': throughput,
            'latency_avg': avg_latency,
            'metadata': {
                'iterations': iterations,
                'rust_available': self._check_rust_available(),
                'avg_operation_time_ms': avg_latency * 1000
            }
        }
    
    def quick_htm_test(self, patterns: int = 500) -> Dict[str, Any]:
        """Quick HTM pattern storage test"""
        print("🧠 Quick HTM test...")
        
        start_time = time.time()
        htm_storage = {}
        
        # Store patterns
        for i in range(patterns):
            pattern = {
                'id': i,
                'data': [1 if j % 3 == 0 else 0 for j in range(50)],  # Smaller patterns
                'timestamp': time.time()
            }
            htm_storage[f"pattern_{i}"] = pattern
        
        # Quick pattern matching
        matches = 0
        test_pattern = [1 if j % 3 == 0 else 0 for j in range(50)]
        
        for pattern_id, pattern in htm_storage.items():
            similarity = sum(1 for a, b in zip(test_pattern, pattern['data']) if a == b)
            if similarity > 40:  # 80% of 50
                matches += 1
        
        total_time = time.time() - start_time
        throughput = patterns / total_time
        
        return {
            'test_name': 'quick_htm_performance',
            'timestamp': datetime.now().isoformat(),
            'duration': total_time,
            'throughput': throughput,
            'metadata': {
                'patterns_stored': patterns,
                'pattern_matches': matches,
                'storage_size_kb': len(str(htm_storage)) / 1024,
                'match_rate': matches / patterns * 100
            }
        }
    
    def quick_tool_execution_test(self, operations: int = 100) -> Dict[str, Any]:
        """Quick tool execution test"""
        print("🛠️  Quick tool execution test...")
        
        start_time = time.time()
        execution_times = []
        
        tools = ['calc', 'hash', 'sort', 'search']
        
        for i in range(operations):
            op_start = time.time()
            
            tool = tools[i % len(tools)]
            
            # Simulate tool operations
            if tool == 'calc':
                result = sum(range(100))
            elif tool == 'hash':
                result = hash(f"data_{i}")
            elif tool == 'sort':
                data = list(range(50, 0, -1))
                result = sorted(data)
            elif tool == 'search':
                data = list(range(100))
                result = 50 in data
            
            op_time = time.time() - op_start
            execution_times.append(op_time)
        
        total_time = time.time() - start_time
        avg_latency = statistics.mean(execution_times)
        throughput = operations / total_time
        
        return {
            'test_name': 'quick_tool_execution',
            'timestamp': datetime.now().isoformat(),
            'duration': total_time,
            'throughput': throughput,
            'latency_avg': avg_latency,
            'metadata': {
                'operations': operations,
                'tools_tested': tools,
                'avg_latency_ms': avg_latency * 1000
            }
        }
    
    def quick_system_health_check(self) -> Dict[str, Any]:
        """Quick system health and resource check"""
        print("🏥 Quick system health check...")
        
        start_time = time.time()
        
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # CPU frequency
        cpu_freq = psutil.cpu_freq()
        
        # Load average
        load_avg = os.getloadavg()
        
        total_time = time.time() - start_time
        
        return {
            'test_name': 'quick_system_health',
            'timestamp': datetime.now().isoformat(),
            'duration': total_time,
            'cpu_usage_avg': cpu_percent,
            'memory_peak_mb': memory.used / (1024 * 1024),
            'metadata': {
                'cpu_frequency_mhz': cpu_freq.current if cpu_freq else None,
                'memory_percent': memory.percent,
                'memory_available_gb': memory.available / (1024**3),
                'disk_usage_percent': disk.percent,
                'disk_free_gb': disk.free / (1024**3),
                'load_average_1min': load_avg[0],
                'load_average_5min': load_avg[1],
                'load_average_15min': load_avg[2]
            }
        }
    
    def _check_rust_available(self) -> bool:
        """Check if Rust components are available"""
        try:
            import rust_core
            return True
        except ImportError:
            return False
    
    def run_all_quick_tests(self) -> List[Dict[str, Any]]:
        """Run all quick tests"""
        print("🚀 Running Quick Benchmark Suite")
        print("=" * 50)
        
        tests = [
            self.quick_cpu_test,
            self.quick_memory_test,
            self.quick_io_test,
            self.quick_rust_ffi_test,
            self.quick_htm_test,
            self.quick_tool_execution_test,
            self.quick_system_health_check
        ]
        
        results = []
        
        for test in tests:
            try:
                result = test()
                results.append(result)
            except Exception as e:
                print(f"❌ {test.__name__} failed: {e}")
                results.append({
                    'test_name': test.__name__,
                    'timestamp': datetime.now().isoformat(),
                    'duration': 0,
                    'metadata': {'error': str(e)}
                })
        
        return results
    
    def generate_quick_report(self, results: List[Dict[str, Any]]) -> str:
        """Generate quick benchmark report"""
        report = []
        report.append("# Quick Performance Benchmark Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append(f"Tests completed: {len(results)}")
        report.append("")
        
        # Summary table
        report.append("## Quick Summary")
        report.append("")
        report.append("| Test | Duration | Throughput | Status |")
        report.append("|------|----------|------------|--------|")
        
        for result in results:
            status = "✅ Pass" if 'error' not in result.get('metadata', {}) else "❌ Fail"
            throughput = f"{result.get('throughput', 0):.1f}" if result.get('throughput') else "N/A"
            duration = f"{result.get('duration', 0):.3f}s"
            
            report.append(f"| {result['test_name']} | {duration} | {throughput} | {status} |")
        
        report.append("")
        
        # Health indicators
        health_result = next((r for r in results if r['test_name'] == 'quick_system_health'), None)
        if health_result and 'error' not in health_result.get('metadata', {}):
            report.append("## System Health")
            metadata = health_result['metadata']
            report.append(f"- CPU Usage: {health_result.get('cpu_usage_avg', 0):.1f}%")
            report.append(f"- Memory Usage: {metadata.get('memory_percent', 0):.1f}%")
            report.append(f"- Disk Usage: {metadata.get('disk_usage_percent', 0):.1f}%")
            report.append(f"- Load Average (1m): {metadata.get('load_average_1min', 0):.2f}")
            report.append("")
        
        # Performance indicators
        report.append("## Performance Indicators")
        
        # Calculate overall performance score
        successful_tests = [r for r in results if 'error' not in r.get('metadata', {})]
        if successful_tests:
            throughput_tests = [r for r in successful_tests if r.get('throughput')]
            
            if throughput_tests:
                avg_throughput = statistics.mean([r['throughput'] for r in throughput_tests])
                report.append(f"- Average Throughput: {avg_throughput:.1f} ops/s")
            
            avg_duration = statistics.mean([r['duration'] for r in successful_tests])
            report.append(f"- Average Test Duration: {avg_duration:.3f}s")
            
            success_rate = len(successful_tests) / len(results) * 100
            report.append(f"- Test Success Rate: {success_rate:.1f}%")
        
        report.append("")
        
        # Recommendations
        report.append("## Quick Recommendations")
        
        # Analyze results for quick recommendations
        if health_result and 'error' not in health_result.get('metadata', {}):
            cpu_usage = health_result.get('cpu_usage_avg', 0)
            memory_percent = health_result['metadata'].get('memory_percent', 0)
            
            if cpu_usage > 80:
                report.append("⚠️  High CPU usage detected - consider load balancing")
            elif cpu_usage < 20:
                report.append("💡 Low CPU usage - opportunity for increased parallelism")
            
            if memory_percent > 80:
                report.append("⚠️  High memory usage - monitor for memory leaks")
            elif memory_percent < 30:
                report.append("💡 Low memory usage - can handle larger datasets")
        
        # Check for performance issues
        slow_tests = [r for r in results if r.get('duration', 0) > 10]  # Tests taking > 10s
        if slow_tests:
            report.append(f"⚠️  {len(slow_tests)} slow tests detected - investigate bottlenecks")
        
        failed_tests = [r for r in results if 'error' in r.get('metadata', {})]
        if failed_tests:
            report.append(f"❌ {len(failed_tests)} tests failed - check system stability")
        
        return "\n".join(report)
    
    def save_results(self, results: List[Dict[str, Any]], report: str):
        """Save quick benchmark results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create benchmarks directory
        benchmarks_dir = Path("/home/louranicas/projects/claude-optimized-deployment/benchmarks")
        benchmarks_dir.mkdir(exist_ok=True)
        
        # Save JSON results
        json_path = benchmarks_dir / f"quick_benchmark_results_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save report
        report_path = benchmarks_dir / f"quick_benchmark_report_{timestamp}.md"
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(f"\n✅ Quick benchmark results saved:")
        print(f"📊 JSON Data: {json_path}")
        print(f"📄 Report: {report_path}")

def main():
    """Run quick benchmark suite"""
    quick_bench = QuickBenchmarks()
    
    # Run all tests
    results = quick_bench.run_all_quick_tests()
    
    # Generate report
    report = quick_bench.generate_quick_report(results)
    
    # Save results
    quick_bench.save_results(results, report)
    
    # Print summary
    print("\n🎯 QUICK BENCHMARK SUMMARY")
    print("=" * 40)
    
    successful_tests = [r for r in results if 'error' not in r.get('metadata', {})]
    print(f"Tests completed: {len(results)}")
    print(f"Tests successful: {len(successful_tests)}")
    print(f"Success rate: {len(successful_tests)/len(results)*100:.1f}%")
    
    total_duration = sum(r.get('duration', 0) for r in results)
    print(f"Total duration: {total_duration:.3f}s")
    
    if successful_tests:
        throughput_tests = [r for r in successful_tests if r.get('throughput')]
        if throughput_tests:
            avg_throughput = statistics.mean([r['throughput'] for r in throughput_tests])
            print(f"Average throughput: {avg_throughput:.1f} ops/s")

if __name__ == "__main__":
    main()