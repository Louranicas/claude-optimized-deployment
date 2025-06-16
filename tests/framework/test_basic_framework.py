import pytest
import time
import multiprocessing
import asyncio

def test_framework_setup():
    """Test that the framework is properly set up"""
    assert True

def test_cpu_detection():
    """Test CPU core detection"""
    cores = multiprocessing.cpu_count()
    assert cores >= 4, f"Expected at least 4 cores, got {cores}"
    print(f"Detected {cores} CPU cores")

@pytest.mark.asyncio
async def test_async_support():
    """Test async functionality"""
    await asyncio.sleep(0.01)
    assert True

@pytest.mark.parametrize("n", [1, 2, 3, 4])
def test_parallel_execution(n):
    """Test parallel execution capability"""
    time.sleep(0.1)
    assert n > 0

def test_memory_allocation():
    """Test memory allocation"""
    data = bytearray(10 * 1024 * 1024)  # 10MB
    assert len(data) == 10 * 1024 * 1024
