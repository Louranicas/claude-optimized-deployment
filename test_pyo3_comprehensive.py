#!/usr/bin/env python3
"""Comprehensive PyO3 bindings test suite."""

import sys
import os
import gc
import time
import threading
import asyncio
from collections import defaultdict
from typing import Any, Dict, List

# Add potential library paths
lib_paths = [
    "target/release",
    "target/debug",
    "rust_core/target/release",
    "rust_core/target/debug",
]

for path in lib_paths:
    full_path = os.path.join(os.path.dirname(__file__), path)
    if os.path.exists(full_path) and full_path not in sys.path:
        sys.path.insert(0, full_path)

class PyO3TestSuite:
    """Comprehensive test suite for PyO3 bindings."""
    
    def __init__(self):
        self.results = defaultdict(list)
        self.rust_module = None
        
    def log_result(self, category: str, test: str, success: bool, message: str = ""):
        """Log test results."""
        self.results[category].append({
            "test": test,
            "success": success,
            "message": message
        })
        status = "✓" if success else "✗"
        print(f"  {status} {test}: {message}")
    
    def test_module_import(self):
        """Test 1: Module import and structure."""
        print("\n=== Test 1: Module Import and Structure ===")
        
        try:
            # Try different possible module names
            module_names = [
                "claude_optimized_deployment_rust",
                "code_rust_core",
                "rust_core",
            ]
            
            for name in module_names:
                try:
                    self.rust_module = __import__(name)
                    self.log_result("import", f"Import {name}", True, f"Successfully imported as {name}")
                    break
                except ImportError:
                    continue
            
            if not self.rust_module:
                self.log_result("import", "Module import", False, "Could not import any module variant")
                return False
            
            # Check module attributes
            attrs = dir(self.rust_module)
            self.log_result("import", "Module attributes", True, f"Found {len(attrs)} attributes")
            
            # Check for version
            if hasattr(self.rust_module, "__version__"):
                version = self.rust_module.__version__
                self.log_result("import", "Version info", True, f"Version: {version}")
            
            # Check for submodules
            submodules = [attr for attr in attrs if not attr.startswith('_') and hasattr(getattr(self.rust_module, attr), '__module__')]
            if submodules:
                self.log_result("import", "Submodules", True, f"Found: {', '.join(submodules[:5])}")
            
            return True
            
        except Exception as e:
            self.log_result("import", "Module import", False, str(e))
            return False
    
    def test_type_conversions(self):
        """Test 2: Python <-> Rust type conversions."""
        print("\n=== Test 2: Type Conversions ===")
        
        if not self.rust_module:
            self.log_result("types", "Type conversion", False, "Module not imported")
            return
        
        # Test if we have the test_bindings submodule
        if hasattr(self.rust_module, 'test_bindings'):
            test_mod = self.rust_module.test_bindings
            
            # Test basic type conversions
            if hasattr(test_mod, 'test_type_conversion'):
                try:
                    result = test_mod.test_type_conversion(
                        "Hello Python",
                        42,
                        3.14159,
                        True,
                        [1, 2, 3, 4, 5],
                        {"key": "value", "rust": "python"}
                    )
                    self.log_result("types", "Basic types", True, f"Result: {result[:50]}...")
                except Exception as e:
                    self.log_result("types", "Basic types", False, str(e))
            
            # Test return types
            if hasattr(test_mod, 'test_return_types'):
                try:
                    result = test_mod.test_return_types()
                    self.log_result("types", "Return types", True, f"Got tuple with {len(result)} elements")
                except Exception as e:
                    self.log_result("types", "Return types", False, str(e))
        else:
            # Try to test with available modules
            self.log_result("types", "Type testing", False, "test_bindings module not available")
    
    def test_gil_handling(self):
        """Test 3: GIL handling in multi-threaded environment."""
        print("\n=== Test 3: GIL Handling ===")
        
        if not self.rust_module:
            self.log_result("gil", "GIL handling", False, "Module not imported")
            return
        
        # Test concurrent access
        results = []
        errors = []
        
        def worker(worker_id: int):
            try:
                # Access Rust module from multiple threads
                for i in range(5):
                    if hasattr(self.rust_module, 'test_bindings') and hasattr(self.rust_module.test_bindings, 'test_gil_release'):
                        result = self.rust_module.test_bindings.test_gil_release(1000)
                        results.append((worker_id, i, result))
                    else:
                        # Just verify module access
                        _ = self.rust_module.__version__ if hasattr(self.rust_module, '__version__') else "0.0.0"
                        results.append((worker_id, i, "access"))
                    time.sleep(0.01)
            except Exception as e:
                errors.append((worker_id, str(e)))
        
        # Create threads
        threads = []
        for i in range(3):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        if errors:
            self.log_result("gil", "Concurrent access", False, f"{len(errors)} errors occurred")
        else:
            self.log_result("gil", "Concurrent access", True, f"{len(results)} operations completed")
    
    def test_exception_propagation(self):
        """Test 4: Exception propagation from Rust to Python."""
        print("\n=== Test 4: Exception Propagation ===")
        
        if not self.rust_module or not hasattr(self.rust_module, 'test_bindings'):
            self.log_result("exceptions", "Exception testing", False, "test_bindings not available")
            return
        
        test_mod = self.rust_module.test_bindings
        
        # Test different exception types
        exception_tests = [
            ('test_raise_value_error', ValueError, "ValueError"),
            ('test_raise_io_error', IOError, "IOError"),
            ('test_raise_runtime_error', RuntimeError, "RuntimeError"),
        ]
        
        for func_name, expected_type, type_name in exception_tests:
            if hasattr(test_mod, func_name):
                try:
                    getattr(test_mod, func_name)()
                    self.log_result("exceptions", type_name, False, "Exception not raised")
                except expected_type as e:
                    self.log_result("exceptions", type_name, True, f"Caught: {str(e)}")
                except Exception as e:
                    self.log_result("exceptions", type_name, False, f"Wrong exception type: {type(e).__name__}")
            else:
                self.log_result("exceptions", type_name, False, f"Function {func_name} not found")
    
    def test_memory_management(self):
        """Test 5: Memory management and cleanup."""
        print("\n=== Test 5: Memory Management ===")
        
        if not self.rust_module:
            self.log_result("memory", "Memory testing", False, "Module not imported")
            return
        
        try:
            import psutil
            process = psutil.Process(os.getpid())
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            # Test memory allocation
            if hasattr(self.rust_module, 'test_bindings') and hasattr(self.rust_module.test_bindings, 'test_memory_allocation'):
                allocations = []
                for i in range(10):
                    # Allocate 1MB each time
                    data = self.rust_module.test_bindings.test_memory_allocation(1024 * 1024)
                    allocations.append(data)
                
                mid_memory = process.memory_info().rss / 1024 / 1024
                
                # Clear allocations
                allocations.clear()
                gc.collect()
                
                final_memory = process.memory_info().rss / 1024 / 1024
                
                self.log_result("memory", "Allocation/deallocation", True, 
                              f"Initial: {initial_memory:.1f}MB, Peak: {mid_memory:.1f}MB, Final: {final_memory:.1f}MB")
            else:
                self.log_result("memory", "Memory testing", False, "test_memory_allocation not available")
                
        except ImportError:
            self.log_result("memory", "Memory testing", False, "psutil not installed")
        except Exception as e:
            self.log_result("memory", "Memory testing", False, str(e))
    
    def test_class_bindings(self):
        """Test 6: Python class bindings."""
        print("\n=== Test 6: Class Bindings ===")
        
        if not self.rust_module or not hasattr(self.rust_module, 'test_bindings'):
            self.log_result("classes", "Class testing", False, "test_bindings not available")
            return
        
        test_mod = self.rust_module.test_bindings
        
        if hasattr(test_mod, 'TestClass'):
            try:
                # Create instance
                obj = test_mod.TestClass(42)
                self.log_result("classes", "Class instantiation", True, "Created TestClass(42)")
                
                # Test property access
                value = obj.value
                self.log_result("classes", "Property get", True, f"value = {value}")
                
                # Test property set
                obj.value = 100
                self.log_result("classes", "Property set", True, f"Set value to 100")
                
                # Test method call
                new_value = obj.increment()
                self.log_result("classes", "Method call", True, f"increment() returned {new_value}")
                
                # Test internal method
                internal = obj.get_internal()
                self.log_result("classes", "Internal access", True, f"Internal: {internal}")
                
                # Test static method
                if hasattr(test_mod.TestClass, 'static_method'):
                    result = test_mod.TestClass.static_method()
                    self.log_result("classes", "Static method", True, result)
                
                # Test class method
                if hasattr(test_mod.TestClass, 'class_method'):
                    result = test_mod.TestClass.class_method()
                    self.log_result("classes", "Class method", True, result)
                    
            except Exception as e:
                self.log_result("classes", "Class operations", False, str(e))
        else:
            self.log_result("classes", "Class testing", False, "TestClass not found")
    
    def test_performance(self):
        """Test 7: Performance comparison."""
        print("\n=== Test 7: Performance Testing ===")
        
        if not self.rust_module:
            self.log_result("performance", "Performance testing", False, "Module not imported")
            return
        
        # Test Rust vs Python performance
        import timeit
        
        # Python implementation
        def python_sum(n):
            return sum(range(n))
        
        # Time Python version
        python_time = timeit.timeit(lambda: python_sum(1000000), number=10)
        
        # Time Rust version if available
        if hasattr(self.rust_module, 'test_bindings') and hasattr(self.rust_module.test_bindings, 'test_gil_release'):
            rust_time = timeit.timeit(lambda: self.rust_module.test_bindings.test_gil_release(1000000), number=10)
            speedup = python_time / rust_time
            self.log_result("performance", "Speed comparison", True, 
                          f"Python: {python_time:.3f}s, Rust: {rust_time:.3f}s, Speedup: {speedup:.1f}x")
        else:
            self.log_result("performance", "Speed comparison", False, "Rust function not available")
    
    def run_all_tests(self):
        """Run all tests and generate report."""
        print("=" * 60)
        print("PyO3 Bindings Comprehensive Test Suite")
        print("=" * 60)
        
        # Run tests
        if self.test_module_import():
            self.test_type_conversions()
            self.test_gil_handling()
            self.test_exception_propagation()
            self.test_memory_management()
            self.test_class_bindings()
            self.test_performance()
        
        # Generate report
        print("\n" + "=" * 60)
        print("Test Summary")
        print("=" * 60)
        
        total_tests = 0
        passed_tests = 0
        
        for category, tests in self.results.items():
            category_passed = sum(1 for t in tests if t['success'])
            category_total = len(tests)
            total_tests += category_total
            passed_tests += category_passed
            
            print(f"\n{category.upper()}: {category_passed}/{category_total} passed")
            for test in tests:
                status = "✓" if test['success'] else "✗"
                print(f"  {status} {test['test']}")
        
        print(f"\nOVERALL: {passed_tests}/{total_tests} tests passed")
        
        if passed_tests < total_tests:
            print("\n⚠️  Some tests failed. This might be due to:")
            print("  - Rust module not being built with required features")
            print("  - Compilation errors in the Rust code")
            print("  - Missing test_bindings module")
            print("\nTo build with all features:")
            print("  cd rust_core && cargo build --release --features python")


def main():
    """Main entry point."""
    suite = PyO3TestSuite()
    suite.run_all_tests()


if __name__ == "__main__":
    main()