"""
Utility functions for MCP learning system
"""

import asyncio
import hashlib
import json
from typing import Any, Dict, List, Optional, Union

import msgpack
import numpy as np
import structlog

logger = structlog.get_logger(__name__)


def serialize_request(request: Dict[str, Any]) -> bytes:
    """Serialize request for processing"""
    return msgpack.packb(request, use_bin_type=True)


def deserialize_response(response: bytes) -> Dict[str, Any]:
    """Deserialize response from processing"""
    return msgpack.unpackb(response, raw=False)


def create_memory_view(data: Union[bytes, np.ndarray], pool: Any) -> memoryview:
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
    from . import rust_core
    
    if rust_core is None:
        raise RuntimeError("Rust core not available")
        
    from .core import AsyncExecutor
    
    executor = AsyncExecutor()
    try:
        return await executor.run_rust_async(
            getattr(rust_core, func_name),
            *args,
            **kwargs
        )
    finally:
        executor.shutdown()


def calculate_hash(data: Dict[str, Any]) -> str:
    """Calculate hash of dictionary data"""
    serialized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()


def normalize_command(command: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize command for consistent processing"""
    normalized = command.copy()
    
    # Ensure required fields
    if "type" not in normalized:
        normalized["type"] = "unknown"
        
    if "timestamp" not in normalized:
        from datetime import datetime
        normalized["timestamp"] = datetime.now()
        
    if "session_id" not in normalized:
        normalized["session_id"] = "default"
        
    return normalized


def batch_commands(commands: List[Dict[str, Any]], batch_size: int = 32) -> List[List[Dict[str, Any]]]:
    """Batch commands for processing"""
    batches = []
    for i in range(0, len(commands), batch_size):
        batches.append(commands[i:i + batch_size])
    return batches


async def parallel_process(
    items: List[Any],
    process_func: Any,
    max_concurrent: int = 10
) -> List[Any]:
    """Process items in parallel with concurrency limit"""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def process_with_semaphore(item):
        async with semaphore:
            return await process_func(item)
            
    tasks = [process_with_semaphore(item) for item in items]
    return await asyncio.gather(*tasks)


def extract_features(command: Dict[str, Any]) -> np.ndarray:
    """Extract numerical features from command"""
    features = []
    
    # Command type (hash to numeric)
    cmd_type_hash = int(hashlib.md5(command.get("type", "unknown").encode()).hexdigest()[:8], 16)
    features.append(cmd_type_hash % 1000)
    
    # Priority
    features.append(command.get("priority", 0))
    
    # Size features
    features.append(len(json.dumps(command)))
    features.append(len(command.keys()))
    
    # Time features
    if "timestamp" in command:
        from datetime import datetime
        ts = command["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        features.extend([ts.hour, ts.minute, ts.weekday()])
    else:
        features.extend([0, 0, 0])
        
    return np.array(features, dtype=np.float32)


def calculate_similarity(cmd1: Dict[str, Any], cmd2: Dict[str, Any]) -> float:
    """Calculate similarity between two commands"""
    # Type similarity
    type_sim = 1.0 if cmd1.get("type") == cmd2.get("type") else 0.0
    
    # Key overlap
    keys1 = set(cmd1.keys())
    keys2 = set(cmd2.keys())
    key_sim = len(keys1 & keys2) / len(keys1 | keys2) if keys1 | keys2 else 0.0
    
    # Value similarity for common keys
    common_keys = keys1 & keys2
    value_sim = 0.0
    
    for key in common_keys:
        if cmd1[key] == cmd2[key]:
            value_sim += 1.0
            
    value_sim = value_sim / len(common_keys) if common_keys else 0.0
    
    # Weighted average
    return 0.5 * type_sim + 0.3 * key_sim + 0.2 * value_sim


def filter_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Filter out sensitive data from commands/responses"""
    sensitive_keys = {"password", "token", "secret", "key", "auth", "credential"}
    
    filtered = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            filtered[key] = "***FILTERED***"
        elif isinstance(value, dict):
            filtered[key] = filter_sensitive_data(value)
        elif isinstance(value, list):
            filtered[key] = [
                filter_sensitive_data(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            filtered[key] = value
            
    return filtered


class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, max_calls: int, time_window: float):
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
        
    async def acquire(self):
        """Acquire permission to make a call"""
        now = asyncio.get_event_loop().time()
        
        # Remove old calls
        self.calls = [t for t in self.calls if now - t < self.time_window]
        
        if len(self.calls) >= self.max_calls:
            # Wait until we can make a call
            sleep_time = self.time_window - (now - self.calls[0])
            await asyncio.sleep(sleep_time)
            return await self.acquire()
            
        self.calls.append(now)


class CircuitBreaker:
    """Circuit breaker for fault tolerance"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half-open
        
    async def call(self, func, *args, **kwargs):
        """Call function with circuit breaker protection"""
        if self.state == "open":
            if (asyncio.get_event_loop().time() - self.last_failure_time) > self.recovery_timeout:
                self.state = "half-open"
            else:
                raise Exception("Circuit breaker is open")
                
        try:
            result = await func(*args, **kwargs)
            
            if self.state == "half-open":
                self.state = "closed"
                self.failures = 0
                
            return result
            
        except Exception as e:
            self.failures += 1
            self.last_failure_time = asyncio.get_event_loop().time()
            
            if self.failures >= self.failure_threshold:
                self.state = "open"
                logger.warning(f"Circuit breaker opened after {self.failures} failures")
                
            raise e


def validate_config(config: Dict[str, Any], schema: Dict[str, Any]) -> bool:
    """Validate configuration against schema"""
    for key, expected_type in schema.items():
        if key not in config:
            logger.error(f"Missing required config key: {key}")
            return False
            
        if not isinstance(config[key], expected_type):
            logger.error(f"Invalid type for {key}: expected {expected_type}, got {type(config[key])}")
            return False
            
    return True


def merge_configs(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Merge configuration dictionaries"""
    result = base.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
            
    return result


class ExponentialBackoff:
    """Exponential backoff for retries"""
    
    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0, factor: float = 2.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.factor = factor
        self.attempt = 0
        
    async def wait(self):
        """Wait with exponential backoff"""
        delay = min(self.base_delay * (self.factor ** self.attempt), self.max_delay)
        self.attempt += 1
        await asyncio.sleep(delay)
        
    def reset(self):
        """Reset backoff counter"""
        self.attempt = 0


async def retry_with_backoff(
    func,
    max_attempts: int = 3,
    backoff: Optional[ExponentialBackoff] = None
):
    """Retry function with exponential backoff"""
    if backoff is None:
        backoff = ExponentialBackoff()
        
    last_error = None
    
    for attempt in range(max_attempts):
        try:
            return await func()
        except Exception as e:
            last_error = e
            if attempt < max_attempts - 1:
                await backoff.wait()
            else:
                raise last_error
                
    raise last_error


def get_system_info() -> Dict[str, Any]:
    """Get system information for diagnostics"""
    import platform
    import psutil
    
    return {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": psutil.cpu_count(),
        "memory_total_gb": psutil.virtual_memory().total / (1024 ** 3),
        "memory_available_gb": psutil.virtual_memory().available / (1024 ** 3),
        "disk_usage_percent": psutil.disk_usage("/").percent,
    }


def format_duration(seconds: float) -> str:
    """Format duration in human-readable form"""
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"