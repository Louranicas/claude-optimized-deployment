"""
Core Rust integration module providing zero-overhead FFI bindings
"""

import asyncio
import ctypes
import mmap
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union

import msgpack
import numpy as np
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

# Import Rust extension module
try:
    from . import rust_core  # PyO3 module
except ImportError:
    rust_core = None
    logger = structlog.get_logger()
    logger.warning("Rust core module not available, using mock implementation")

logger = structlog.get_logger(__name__)


@dataclass
class RustConfig:
    """Configuration for Rust core integration"""
    server_type: str
    memory_gb: int
    thread_pool_size: int = 4
    enable_simd: bool = True
    enable_gpu: bool = False
    cache_size_mb: int = 512
    zero_copy: bool = True


class MemoryPool:
    """Shared memory pool for zero-copy data transfer"""
    
    def __init__(self, size_mb: int = 1024):
        self.size = size_mb * 1024 * 1024
        self.pools: Dict[str, mmap.mmap] = {}
        self.allocations: Dict[str, List[tuple]] = {}
        
    def allocate(self, name: str, size: int) -> memoryview:
        """Allocate memory region for zero-copy transfer"""
        if name not in self.pools:
            self.pools[name] = mmap.mmap(-1, self.size)
            self.allocations[name] = []
            
        pool = self.pools[name]
        allocations = self.allocations[name]
        
        # Find free space
        offset = 0
        for alloc_offset, alloc_size in sorted(allocations):
            if offset + size <= alloc_offset:
                break
            offset = alloc_offset + alloc_size
            
        if offset + size > self.size:
            raise MemoryError(f"Not enough space in pool {name}")
            
        allocations.append((offset, size))
        return memoryview(pool)[offset:offset + size]
        
    def free(self, name: str, offset: int):
        """Free allocated memory region"""
        if name in self.allocations:
            self.allocations[name] = [
                (o, s) for o, s in self.allocations[name] if o != offset
            ]
            
    def cleanup(self):
        """Clean up all memory pools"""
        for pool in self.pools.values():
            pool.close()
        self.pools.clear()
        self.allocations.clear()


class AsyncExecutor:
    """Async executor for Rust tokio runtime integration"""
    
    def __init__(self, thread_pool_size: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=thread_pool_size)
        self.loop = asyncio.get_event_loop()
        
    async def run_rust_async(self, func: Callable, *args, **kwargs) -> Any:
        """Run Rust async function in tokio runtime"""
        return await self.loop.run_in_executor(
            self.executor, func, *args, **kwargs
        )
        
    def shutdown(self):
        """Shutdown executor"""
        self.executor.shutdown(wait=True)


class RustBridge:
    """Bridge between Python and Rust core"""
    
    def __init__(self, config: RustConfig):
        self.config = config
        self.memory_pool = MemoryPool(config.cache_size_mb)
        self.executor = AsyncExecutor(config.thread_pool_size)
        self._rust_core = None
        self._initialize_rust_core()
        
    def _initialize_rust_core(self):
        """Initialize Rust core module"""
        if rust_core is None:
            logger.warning("Using mock Rust core implementation")
            return
            
        try:
            self._rust_core = rust_core.MCPCore(
                server_type=self.config.server_type,
                memory_gb=self.config.memory_gb,
                enable_simd=self.config.enable_simd,
                enable_gpu=self.config.enable_gpu,
            )
            logger.info("Rust core initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Rust core: {e}")
            raise
            
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def call_rust_method(self, method: str, *args, **kwargs) -> Any:
        """Call Rust method with automatic retry"""
        if self._rust_core is None:
            raise RuntimeError("Rust core not initialized")
            
        try:
            # Use zero-copy for large data
            if self.config.zero_copy and self._is_large_data(args):
                args = self._prepare_zero_copy(args)
                
            # Call Rust method
            result = await self.executor.run_rust_async(
                getattr(self._rust_core, method),
                *args,
                **kwargs
            )
            
            return self._process_result(result)
            
        except Exception as e:
            logger.error(f"Rust method call failed: {method}", error=str(e))
            raise
            
    def _is_large_data(self, data: tuple) -> bool:
        """Check if data is large enough for zero-copy"""
        total_size = 0
        for item in data:
            if isinstance(item, (bytes, bytearray)):
                total_size += len(item)
            elif isinstance(item, np.ndarray):
                total_size += item.nbytes
        return total_size > 1024 * 1024  # 1MB threshold
        
    def _prepare_zero_copy(self, args: tuple) -> tuple:
        """Prepare data for zero-copy transfer"""
        prepared = []
        for arg in args:
            if isinstance(arg, np.ndarray):
                # Convert numpy array to shared memory
                mem = self.memory_pool.allocate(f"array_{id(arg)}", arg.nbytes)
                mem[:] = arg.tobytes()
                prepared.append({
                    "type": "ndarray",
                    "shape": arg.shape,
                    "dtype": str(arg.dtype),
                    "memory_view": mem,
                })
            elif isinstance(arg, (bytes, bytearray)):
                # Use memory view for large binary data
                mem = self.memory_pool.allocate(f"bytes_{id(arg)}", len(arg))
                mem[:] = arg
                prepared.append({
                    "type": "bytes",
                    "memory_view": mem,
                })
            else:
                prepared.append(arg)
        return tuple(prepared)
        
    def _process_result(self, result: Any) -> Any:
        """Process result from Rust"""
        if isinstance(result, dict) and "memory_view" in result:
            # Reconstruct from shared memory
            if result["type"] == "ndarray":
                data = np.frombuffer(
                    result["memory_view"],
                    dtype=result["dtype"]
                ).reshape(result["shape"])
                return data.copy()  # Return copy to free memory
            elif result["type"] == "bytes":
                return bytes(result["memory_view"])
        return result
        
    def cleanup(self):
        """Clean up resources"""
        self.memory_pool.cleanup()
        self.executor.shutdown()
        if self._rust_core:
            self._rust_core.cleanup()


class RustMCPCore:
    """High-level Rust MCP core interface"""
    
    def __init__(self, server_type: str, memory_gb: int, **kwargs):
        config = RustConfig(
            server_type=server_type,
            memory_gb=memory_gb,
            **kwargs
        )
        self.bridge = RustBridge(config)
        self.server_type = server_type
        self.stats = {
            "requests_processed": 0,
            "errors": 0,
            "avg_latency_ms": 0,
        }
        
    async def process(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process request through Rust core"""
        try:
            # Serialize request
            serialized = msgpack.packb(request, use_bin_type=True)
            
            # Process through Rust
            start_time = asyncio.get_event_loop().time()
            result = await self.bridge.call_rust_method(
                "process_request",
                serialized
            )
            latency = (asyncio.get_event_loop().time() - start_time) * 1000
            
            # Update stats
            self._update_stats(latency)
            
            # Deserialize response
            return msgpack.unpackb(result, raw=False)
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error("Request processing failed", error=str(e))
            raise
            
    async def batch_process(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process multiple requests in batch"""
        serialized_batch = [
            msgpack.packb(req, use_bin_type=True) for req in requests
        ]
        
        results = await self.bridge.call_rust_method(
            "batch_process",
            serialized_batch
        )
        
        return [msgpack.unpackb(res, raw=False) for res in results]
        
    async def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics from Rust core"""
        rust_metrics = await self.bridge.call_rust_method("get_metrics")
        return {
            **rust_metrics,
            **self.stats,
        }
        
    def _update_stats(self, latency: float):
        """Update internal statistics"""
        self.stats["requests_processed"] += 1
        # Running average
        n = self.stats["requests_processed"]
        self.stats["avg_latency_ms"] = (
            (self.stats["avg_latency_ms"] * (n - 1) + latency) / n
        )
        
    def cleanup(self):
        """Clean up resources"""
        self.bridge.cleanup()


# Utility functions for external use
def create_memory_view(data: Union[bytes, np.ndarray], pool: MemoryPool) -> memoryview:
    """Create memory view for zero-copy operations"""
    if isinstance(data, np.ndarray):
        size = data.nbytes
    else:
        size = len(data)
        
    mem = pool.allocate(f"data_{id(data)}", size)
    if isinstance(data, np.ndarray):
        mem[:] = data.tobytes()
    else:
        mem[:] = data
        
    return mem


async def async_rust_call(func_name: str, *args, **kwargs) -> Any:
    """Direct async call to Rust function"""
    if rust_core is None:
        raise RuntimeError("Rust core not available")
        
    executor = AsyncExecutor()
    try:
        return await executor.run_rust_async(
            getattr(rust_core, func_name),
            *args,
            **kwargs
        )
    finally:
        executor.shutdown()


def serialize_request(request: Dict[str, Any]) -> bytes:
    """Serialize request for Rust processing"""
    return msgpack.packb(request, use_bin_type=True)


def deserialize_response(response: bytes) -> Dict[str, Any]:
    """Deserialize response from Rust"""
    return msgpack.unpackb(response, raw=False)