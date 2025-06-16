#!/usr/bin/env python3
"""
Comprehensive FFI Testing for Python-Rust Bridge
Tests performance, memory safety, and correctness of the bridge
"""

import pytest
import gc
import time
import threading
import multiprocessing
import ctypes
import sys
from typing import Any, List, Optional
import numpy as np
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import psutil
import json
from pathlib import Path

# Try to import the Rust module
try:
    from claude_deployment import _rust_core
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    _rust_core = None


@pytest.mark.ffi
@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust core not available")
class TestRustBridgeBasics:
    """Basic FFI bridge functionality tests"""
    
    def test_module_import(self):
        """Test that Rust module can be imported"""
        assert _rust_core is not None
        assert hasattr(_rust_core, "__version__")
        
    def test_basic_function_call(self):
        """Test basic function calls across FFI boundary"""
        # Test simple string processing
        result = _rust_core.process_string("Hello from Python")
        assert isinstance(result, str)
        assert "Hello" in result
        
    def test_numeric_operations(self):
        """Test numeric operations across FFI"""
        # Test integer operations
        result = _rust_core.add_integers(42, 58)
        assert result == 100
        
        # Test floating point
        result = _rust_core.multiply_floats(3.14, 2.0)
        assert abs(result - 6.28) < 0.001
        
    def test_error_handling(self):
        """Test error propagation from Rust to Python"""
        with pytest.raises(ValueError):
            _rust_core.divide_numbers(10, 0)
            
    def test_null_safety(self):
        """Test null pointer safety"""
        # Should handle None gracefully
        result = _rust_core.process_optional(None)
        assert result == "None"
        
        result = _rust_core.process_optional("Some value")
        assert result == "Some(Some value)"


@pytest.mark.ffi
@pytest.mark.performance
@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust core not available")
class TestRustBridgePerformance:
    """Performance tests for Python-Rust bridge"""
    
    def test_string_processing_performance(self, benchmark):
        """Benchmark string processing performance"""
        test_string = "x" * 1000  # 1KB string
        
        def rust_process():
            return _rust_core.process_large_string(test_string)
            
        result = benchmark(rust_process)
        assert len(result) > 0
        
    def test_array_processing_performance(self, benchmark):
        """Benchmark array processing performance"""
        # Create large numpy array
        data = np.random.rand(1_000_000).astype(np.float64)
        
        def rust_process():
            return _rust_core.sum_array(data)
            
        result = benchmark(rust_process)
        expected = np.sum(data)
        assert abs(result - expected) < 0.001
        
    def test_parallel_ffi_calls(self, benchmark):
        """Test parallel FFI calls performance"""
        def parallel_calls():
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = []
                for i in range(100):
                    futures.append(
                        executor.submit(_rust_core.compute_hash, f"data_{i}")
                    )
                results = [f.result() for f in futures]
                return results
                
        results = benchmark(parallel_calls)
        assert len(results) == 100
        assert len(set(results)) == 100  # All hashes should be unique


@pytest.mark.ffi
@pytest.mark.memory
@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust core not available")
class TestRustBridgeMemory:
    """Memory safety tests for Python-Rust bridge"""
    
    def test_memory_leak_prevention(self):
        """Test that bridge doesn't leak memory"""
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Perform many allocations
        for _ in range(1000):
            data = "x" * 10_000  # 10KB string
            result = _rust_core.process_large_string(data)
            del result
            
        # Force garbage collection
        gc.collect()
        time.sleep(0.1)
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Should not increase by more than 10MB
        assert memory_increase < 10 * 1024 * 1024
        
    def test_large_data_transfer(self):
        """Test transferring large data across FFI boundary"""
        # Create 100MB of data
        large_data = np.random.rand(100_000_000 // 8).astype(np.float64)
        
        start_memory = psutil.Process().memory_info().rss
        result = _rust_core.process_large_array(large_data)
        end_memory = psutil.Process().memory_info().rss
        
        assert result is not None
        # Memory should not double (no unnecessary copies)
        assert (end_memory - start_memory) < large_data.nbytes
        
    def test_reference_counting(self):
        """Test proper reference counting across FFI"""
        data = "test_data"
        
        # Get reference count
        initial_refs = sys.getrefcount(data)
        
        # Call Rust function that borrows the data
        result = _rust_core.borrow_string(data)
        
        # Reference count should be back to normal
        final_refs = sys.getrefcount(data)
        assert final_refs == initial_refs


@pytest.mark.ffi
@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust core not available")
class TestRustBridgeConcurrency:
    """Concurrency and thread safety tests"""
    
    def test_gil_release(self):
        """Test that Rust functions properly release the GIL"""
        import threading
        import time
        
        results = []
        
        def cpu_bound_rust():
            # This should release GIL
            result = _rust_core.cpu_intensive_task(1_000_000)
            results.append(result)
            
        def cpu_bound_python():
            # Pure Python CPU task
            total = 0
            for i in range(1_000_000):
                total += i
            results.append(total)
            
        # Run both in parallel
        t1 = threading.Thread(target=cpu_bound_rust)
        t2 = threading.Thread(target=cpu_bound_python)
        
        start = time.time()
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        duration = time.time() - start
        
        assert len(results) == 2
        # Should complete faster than sequential (GIL released)
        assert duration < 1.0  # Adjust based on system
        
    def test_thread_safety(self):
        """Test thread safety of Rust functions"""
        counter = _rust_core.create_atomic_counter()
        
        def increment_counter():
            for _ in range(1000):
                _rust_core.increment_atomic(counter)
                
        threads = []
        for _ in range(10):
            t = threading.Thread(target=increment_counter)
            threads.append(t)
            t.start()
            
        for t in threads:
            t.join()
            
        final_value = _rust_core.get_atomic_value(counter)
        assert final_value == 10000  # No race conditions
        
    def test_async_rust_integration(self):
        """Test async Rust function integration"""
        import asyncio
        
        async def test_async():
            # Test async Rust function
            result = await _rust_core.async_compute(42)
            assert result == 42 * 2
            
            # Test multiple concurrent async calls
            tasks = []
            for i in range(10):
                tasks.append(_rust_core.async_compute(i))
                
            results = await asyncio.gather(*tasks)
            assert results == [i * 2 for i in range(10)]
            
        asyncio.run(test_async())


@pytest.mark.ffi
@pytest.mark.gpu
@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust core not available")
class TestRustBridgeGPU:
    """GPU acceleration tests for Rust bridge"""
    
    @pytest.mark.skipif(not _rust_core or not hasattr(_rust_core, "gpu_available"), 
                        reason="GPU support not available")
    def test_gpu_availability(self):
        """Test GPU availability detection"""
        gpu_available = _rust_core.gpu_available()
        assert isinstance(gpu_available, bool)
        
        if gpu_available:
            gpu_info = _rust_core.get_gpu_info()
            assert "name" in gpu_info
            assert "memory" in gpu_info
            
    @pytest.mark.skipif(not _rust_core or not hasattr(_rust_core, "gpu_compute"), 
                        reason="GPU compute not available")
    def test_gpu_computation(self, benchmark):
        """Test GPU-accelerated computation"""
        # Create large matrix
        size = 1000
        matrix_a = np.random.rand(size, size).astype(np.float32)
        matrix_b = np.random.rand(size, size).astype(np.float32)
        
        def gpu_multiply():
            return _rust_core.gpu_matrix_multiply(matrix_a, matrix_b)
            
        result = benchmark(gpu_multiply)
        
        # Verify result shape
        assert result.shape == (size, size)
        
        # Spot check some values
        expected = np.dot(matrix_a, matrix_b)
        assert np.allclose(result[:10, :10], expected[:10, :10], rtol=1e-5)


@pytest.mark.ffi
@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust core not available")
class TestRustBridgeEdgeCases:
    """Edge case and stress tests"""
    
    def test_unicode_handling(self):
        """Test Unicode string handling across FFI"""
        test_strings = [
            "Hello 世界",
            "🦀 Rust 🐍 Python",
            "Ω≈ç√∫˜µ≤≥÷",
            "\u0000\u0001\u0002",  # Control characters
        ]
        
        for s in test_strings:
            result = _rust_core.process_unicode(s)
            assert s in result
            
    def test_extreme_values(self):
        """Test extreme numeric values"""
        # Test large integers
        result = _rust_core.handle_big_int(2**62)
        assert result == 2**62
        
        # Test infinity and NaN
        assert _rust_core.handle_float(float('inf')) == float('inf')
        assert _rust_core.is_nan(float('nan'))
        
    def test_recursive_data_structures(self):
        """Test handling of recursive data structures"""
        # Create nested structure
        data = {"level": 0}
        current = data
        for i in range(100):
            current["next"] = {"level": i + 1}
            current = current["next"]
            
        result = _rust_core.process_nested_dict(data)
        assert result["depth"] == 101
        
    def test_exception_in_callback(self):
        """Test exception handling in Python callbacks from Rust"""
        def bad_callback(x):
            raise ValueError("Intentional error")
            
        with pytest.raises(ValueError):
            _rust_core.call_python_callback(bad_callback, 42)


def run_ffi_test_suite():
    """Run the complete FFI test suite with reporting"""
    print("Running FFI Bridge Test Suite...")
    
    # Configure pytest
    args = [
        __file__,
        "-v",
        "--tb=short",
        "--benchmark-only",
        "--benchmark-json=ffi_benchmark_results.json",
        "-m", "ffi",
    ]
    
    # Run tests
    exit_code = pytest.main(args)
    
    # Load and display benchmark results
    if Path("ffi_benchmark_results.json").exists():
        with open("ffi_benchmark_results.json", "r") as f:
            results = json.load(f)
            
        print("\nFFI Performance Summary:")
        print("-" * 60)
        for benchmark in results.get("benchmarks", []):
            print(f"{benchmark['name']}: {benchmark['stats']['mean']:.6f}s")
            
    return exit_code


if __name__ == "__main__":
    exit(run_ffi_test_suite())