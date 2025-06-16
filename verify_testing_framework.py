#!/usr/bin/env python3
"""
Verify Testing Framework Installation and Configuration
"""

import sys
import os
import subprocess
import json
import time
import psutil
from pathlib import Path
from datetime import datetime
import multiprocessing


def check_system_specs():
    """Check system specifications"""
    print("\n🖥️  System Specifications:")
    print("-" * 50)
    
    # CPU
    cpu_count = multiprocessing.cpu_count()
    print(f"CPU Cores: {cpu_count}")
    print(f"CPU Usage: {psutil.cpu_percent(interval=1)}%")
    
    # Memory
    memory = psutil.virtual_memory()
    print(f"Total RAM: {memory.total / (1024**3):.1f} GB")
    print(f"Available RAM: {memory.available / (1024**3):.1f} GB")
    print(f"Memory Usage: {memory.percent}%")
    
    # Disk
    disk = psutil.disk_usage('/')
    print(f"Disk Total: {disk.total / (1024**3):.1f} GB")
    print(f"Disk Free: {disk.free / (1024**3):.1f} GB")
    
    # Check for GPU
    try:
        result = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.total', '--format=csv,noheader'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"GPU: {result.stdout.strip()}")
        else:
            print("GPU: Not available")
    except:
        print("GPU: Not available")
        
    return cpu_count >= 12 and memory.total >= 16 * 1024**3


def check_python_version():
    """Check Python version"""
    print("\n🐍 Python Environment:")
    print("-" * 50)
    
    version = sys.version_info
    print(f"Python Version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major == 3 and version.minor >= 10:
        print("✅ Python version is compatible")
        return True
    else:
        print("❌ Python 3.10+ required")
        return False


def check_dependencies():
    """Check required dependencies"""
    print("\n📦 Dependencies Check:")
    print("-" * 50)
    
    required_packages = [
        "pytest",
        "pytest-xdist",
        "pytest-cov",
        "pytest-benchmark",
        "pytest-asyncio",
        "pytest-timeout",
        "watchdog",
        "httpx",
        "fastapi",
        "psutil",
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package} - Missing")
            missing.append(package)
            
    if missing:
        print(f"\nInstall missing packages with:")
        print(f"pip install {' '.join(missing)}")
        
    return len(missing) == 0


def check_test_structure():
    """Check test directory structure"""
    print("\n📁 Test Structure Check:")
    print("-" * 50)
    
    required_dirs = [
        "tests",
        "tests/unit",
        "tests/integration",
        "tests/ffi",
        "tests/performance",
        "tests/security",
        "tests/framework",
    ]
    
    all_exist = True
    for dir_path in required_dirs:
        path = Path(dir_path)
        if path.exists():
            print(f"✅ {dir_path}")
        else:
            print(f"❌ {dir_path} - Missing")
            all_exist = False
            
    return all_exist


def run_sample_tests():
    """Run sample tests to verify framework"""
    print("\n🧪 Running Sample Tests:")
    print("-" * 50)
    
    # Create a simple test file
    test_file = Path("test_framework_verification.py")
    test_content = '''
import pytest
import time
import asyncio

def test_basic_assertion():
    """Basic test to verify pytest works"""
    assert 1 + 1 == 2

def test_parallel_execution():
    """Test that verifies parallel execution"""
    time.sleep(0.1)  # Simulate work
    assert True

@pytest.mark.asyncio
async def test_async_support():
    """Test async support"""
    await asyncio.sleep(0.1)
    assert True

@pytest.mark.benchmark
def test_benchmark_support(benchmark):
    """Test benchmark support"""
    def something():
        return sum(range(100))
    
    result = benchmark(something)
    assert result == 4950

@pytest.mark.parametrize("x,y,expected", [
    (1, 2, 3),
    (2, 3, 5),
    (3, 5, 8),
])
def test_parametrized(x, y, expected):
    """Test parametrized tests"""
    assert x + y == expected
'''
    
    with open(test_file, 'w') as f:
        f.write(test_content)
        
    try:
        # Run tests with parallel execution
        print("\nRunning tests with 4 workers...")
        start_time = time.time()
        
        result = subprocess.run([
            "pytest", str(test_file),
            "-n", "4",
            "--tb=short",
            "-v",
            "--benchmark-only",
        ], capture_output=True, text=True)
        
        duration = time.time() - start_time
        
        if result.returncode == 0:
            print(f"✅ Tests passed in {duration:.2f}s")
            print(f"   Output: {result.stdout.count('passed')} tests passed")
            return True
        else:
            print(f"❌ Tests failed")
            print(result.stdout)
            return False
            
    finally:
        # Cleanup
        if test_file.exists():
            test_file.unlink()


def verify_parallel_execution():
    """Verify parallel execution is working"""
    print("\n⚡ Parallel Execution Test:")
    print("-" * 50)
    
    # Create multiple test files
    test_files = []
    for i in range(4):
        test_file = Path(f"test_parallel_{i}.py")
        test_files.append(test_file)
        
        content = f'''
import time

def test_slow_{i}():
    """Slow test {i}"""
    time.sleep(1)
    assert True
'''
        with open(test_file, 'w') as f:
            f.write(content)
            
    try:
        # Run sequentially
        print("Running 4 tests sequentially...")
        start_seq = time.time()
        for test_file in test_files:
            subprocess.run(["pytest", str(test_file), "-q"], capture_output=True)
        seq_duration = time.time() - start_seq
        
        # Run in parallel
        print("Running 4 tests in parallel...")
        start_par = time.time()
        subprocess.run([
            "pytest", *[str(f) for f in test_files],
            "-n", "4", "-q"
        ], capture_output=True)
        par_duration = time.time() - start_par
        
        speedup = seq_duration / par_duration
        print(f"\nSequential: {seq_duration:.2f}s")
        print(f"Parallel: {par_duration:.2f}s")
        print(f"Speedup: {speedup:.1f}x")
        
        if speedup > 2:
            print("✅ Parallel execution is working efficiently")
            return True
        else:
            print("⚠️  Parallel execution speedup is lower than expected")
            return False
            
    finally:
        # Cleanup
        for test_file in test_files:
            if test_file.exists():
                test_file.unlink()


def check_coverage_tools():
    """Check coverage tools"""
    print("\n📊 Coverage Tools Check:")
    print("-" * 50)
    
    # Create a sample module and test
    module_file = Path("sample_module.py")
    test_file = Path("test_sample_module.py")
    
    module_content = '''
def add(a, b):
    """Add two numbers"""
    return a + b

def multiply(a, b):
    """Multiply two numbers"""
    return a * b

def divide(a, b):
    """Divide two numbers"""
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b
'''
    
    test_content = '''
from sample_module import add, multiply

def test_add():
    assert add(2, 3) == 5

def test_multiply():
    assert multiply(2, 3) == 6
'''
    
    with open(module_file, 'w') as f:
        f.write(module_content)
        
    with open(test_file, 'w') as f:
        f.write(test_content)
        
    try:
        # Run with coverage
        result = subprocess.run([
            "pytest", str(test_file),
            "--cov=sample_module",
            "--cov-report=json",
            "-q"
        ], capture_output=True, text=True)
        
        if result.returncode == 0 and Path("coverage.json").exists():
            with open("coverage.json", 'r') as f:
                coverage_data = json.load(f)
                
            coverage_percent = coverage_data.get("totals", {}).get("percent_covered", 0)
            print(f"✅ Coverage reporting works")
            print(f"   Sample coverage: {coverage_percent:.1f}%")
            return True
        else:
            print("❌ Coverage reporting failed")
            return False
            
    finally:
        # Cleanup
        for f in [module_file, test_file, Path("coverage.json"), Path(".coverage")]:
            if f.exists():
                f.unlink()


def main():
    """Main verification function"""
    print("🚀 Testing Framework Verification")
    print("=" * 50)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    checks = [
        ("System Specs", check_system_specs),
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Test Structure", check_test_structure),
        ("Sample Tests", run_sample_tests),
        ("Parallel Execution", verify_parallel_execution),
        ("Coverage Tools", check_coverage_tools),
    ]
    
    results = []
    for name, check_func in checks:
        try:
            passed = check_func()
            results.append((name, passed))
        except Exception as e:
            print(f"\n❌ Error in {name}: {e}")
            results.append((name, False))
            
    # Summary
    print("\n" + "=" * 50)
    print("📋 VERIFICATION SUMMARY")
    print("=" * 50)
    
    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{name:<20} {status}")
        if not passed:
            all_passed = False
            
    print("=" * 50)
    
    if all_passed:
        print("\n✅ Testing framework is fully operational!")
        print("\nYou can now run:")
        print("  - make -f Makefile.testing test")
        print("  - make -f Makefile.testing test-parallel")
        print("  - make -f Makefile.testing test-watch")
        return 0
    else:
        print("\n❌ Some checks failed. Please fix the issues above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())