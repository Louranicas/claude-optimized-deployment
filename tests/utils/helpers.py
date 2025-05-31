"""
Test helper functions for common testing operations.

This module provides utility functions to simplify test setup,
execution, and teardown.
"""

import asyncio
import json
import os
import tempfile
import shutil
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Callable, AsyncGenerator, Generator
import time
import logging
import sys


class TestHelpers:
    """Collection of test helper utilities."""
    
    @staticmethod
    @contextmanager
    def temporary_directory(prefix: str = "test_") -> Generator[Path, None, None]:
        """Create a temporary directory that's automatically cleaned up."""
        temp_dir = tempfile.mkdtemp(prefix=prefix)
        try:
            yield Path(temp_dir)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    @staticmethod
    @contextmanager
    def temporary_file(
        content: str = "",
        suffix: str = ".txt",
        mode: str = "w"
    ) -> Generator[Path, None, None]:
        """Create a temporary file with optional content."""
        fd, path = tempfile.mkstemp(suffix=suffix)
        try:
            if content:
                with os.fdopen(fd, mode) as f:
                    f.write(content)
            else:
                os.close(fd)
            yield Path(path)
        finally:
            try:
                os.unlink(path)
            except:
                pass
    
    @staticmethod
    @contextmanager
    def capture_logs(logger_name: Optional[str] = None, level: int = logging.INFO) -> Generator[List[logging.LogRecord], None, None]:
        """Capture log messages during test execution."""
        class LogCapture(logging.Handler):
            def __init__(self):
                super().__init__()
                self.records = []
            
            def emit(self, record):
                self.records.append(record)
        
        handler = LogCapture()
        handler.setLevel(level)
        
        logger = logging.getLogger(logger_name)
        logger.addHandler(handler)
        original_level = logger.level
        logger.setLevel(level)
        
        try:
            yield handler.records
        finally:
            logger.removeHandler(handler)
            logger.setLevel(original_level)
    
    @staticmethod
    @contextmanager
    def timer() -> Generator[Dict[str, float], None, None]:
        """Time the execution of a code block."""
        result = {"elapsed": 0.0, "start": 0.0, "end": 0.0}
        result["start"] = time.perf_counter()
        try:
            yield result
        finally:
            result["end"] = time.perf_counter()
            result["elapsed"] = result["end"] - result["start"]
    
    @staticmethod
    @asynccontextmanager
    async def async_timer() -> AsyncGenerator[Dict[str, float], None]:
        """Time the execution of an async code block."""
        result = {"elapsed": 0.0, "start": 0.0, "end": 0.0}
        result["start"] = time.perf_counter()
        try:
            yield result
        finally:
            result["end"] = time.perf_counter()
            result["elapsed"] = result["end"] - result["start"]
    
    @staticmethod
    def create_test_config(overrides: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a test configuration with sensible defaults."""
        config = {
            "environment": "test",
            "debug": True,
            "log_level": "DEBUG",
            "timeout": 30,
            "retry_attempts": 3,
            "retry_delay": 0.1,
            "max_workers": 2,
            "cache_enabled": False,
            "database": {
                "url": "sqlite:///:memory:",
                "pool_size": 1
            },
            "api": {
                "base_url": "http://localhost:8000",
                "timeout": 10
            },
            "features": {
                "experimental": True,
                "telemetry": False
            }
        }
        
        if overrides:
            deep_update(config, overrides)
        
        return config
    
    @staticmethod
    async def wait_for_condition(
        condition: Callable[[], bool],
        timeout: float = 5.0,
        interval: float = 0.1,
        message: str = "Condition not met"
    ) -> None:
        """Wait for a condition to become true."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if condition():
                return
            await asyncio.sleep(interval)
        
        raise TimeoutError(f"{message} after {timeout}s")
    
    @staticmethod
    async def run_with_timeout(
        coro: Callable,
        timeout: float,
        *args,
        **kwargs
    ) -> Any:
        """Run an async function with a timeout."""
        try:
            return await asyncio.wait_for(
                coro(*args, **kwargs),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            raise TimeoutError(f"Operation timed out after {timeout}s")
    
    @staticmethod
    def create_mock_environment(env_vars: Dict[str, str]) -> Dict[str, Optional[str]]:
        """Create a mock environment with specified variables."""
        original_env = {}
        
        for key, value in env_vars.items():
            original_env[key] = os.environ.get(key)
            os.environ[key] = value
        
        return original_env
    
    @staticmethod
    def restore_environment(original_env: Dict[str, Optional[str]]) -> None:
        """Restore environment variables to original state."""
        for key, value in original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    
    @staticmethod
    @contextmanager
    def mock_datetime(target_datetime: datetime) -> Generator[None, None, None]:
        """Mock datetime.now() to return a specific time."""
        import datetime as dt_module
        from unittest.mock import patch
        
        class MockDatetime(dt_module.datetime):
            @classmethod
            def now(cls, tz=None):
                return target_datetime
        
        with patch.object(dt_module, 'datetime', MockDatetime):
            yield
    
    @staticmethod
    def compare_json_files(file1: Path, file2: Path, ignore_keys: List[str] = None) -> bool:
        """Compare two JSON files, optionally ignoring certain keys."""
        with open(file1) as f1, open(file2) as f2:
            data1 = json.load(f1)
            data2 = json.load(f2)
        
        if ignore_keys:
            remove_keys(data1, ignore_keys)
            remove_keys(data2, ignore_keys)
        
        return data1 == data2
    
    @staticmethod
    async def retry_async(
        func: Callable,
        max_attempts: int = 3,
        delay: float = 1.0,
        backoff: float = 2.0,
        exceptions: tuple = (Exception,)
    ) -> Any:
        """Retry an async function with exponential backoff."""
        attempt = 0
        current_delay = delay
        
        while attempt < max_attempts:
            try:
                return await func()
            except exceptions as e:
                attempt += 1
                if attempt >= max_attempts:
                    raise
                
                await asyncio.sleep(current_delay)
                current_delay *= backoff
    
    @staticmethod
    def generate_test_id(prefix: str = "test") -> str:
        """Generate a unique test ID."""
        import uuid
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4()).split('-')[0]
        return f"{prefix}_{timestamp}_{unique_id}"
    
    @staticmethod
    @contextmanager
    def suppress_output() -> Generator[None, None, None]:
        """Suppress stdout and stderr during test execution."""
        import io
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        
        try:
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()
            yield
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr


# Async test helpers

async def create_test_server(
    handler: Callable,
    host: str = "127.0.0.1",
    port: int = 0
) -> Dict[str, Any]:
    """Create a test HTTP server."""
    from aiohttp import web
    
    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handler)
    
    runner = web.AppRunner(app)
    await runner.setup()
    
    site = web.TCPSite(runner, host, port)
    await site.start()
    
    # Get the actual port if 0 was specified
    actual_port = site._server.sockets[0].getsockname()[1]
    
    return {
        "app": app,
        "runner": runner,
        "site": site,
        "url": f"http://{host}:{actual_port}"
    }


async def cleanup_test_server(server_info: Dict[str, Any]) -> None:
    """Clean up a test HTTP server."""
    await server_info["runner"].cleanup()


# Data manipulation helpers

def deep_update(base: Dict[str, Any], updates: Dict[str, Any]) -> None:
    """Recursively update a dictionary."""
    for key, value in updates.items():
        if isinstance(value, dict) and key in base and isinstance(base[key], dict):
            deep_update(base[key], value)
        else:
            base[key] = value


def remove_keys(data: Union[Dict, List], keys: List[str]) -> None:
    """Recursively remove keys from a data structure."""
    if isinstance(data, dict):
        for key in keys:
            data.pop(key, None)
        for value in data.values():
            remove_keys(value, keys)
    elif isinstance(data, list):
        for item in data:
            remove_keys(item, keys)


def flatten_dict(
    data: Dict[str, Any],
    parent_key: str = "",
    separator: str = "."
) -> Dict[str, Any]:
    """Flatten a nested dictionary."""
    items = []
    
    for key, value in data.items():
        new_key = f"{parent_key}{separator}{key}" if parent_key else key
        
        if isinstance(value, dict):
            items.extend(flatten_dict(value, new_key, separator).items())
        else:
            items.append((new_key, value))
    
    return dict(items)


# Test data helpers

def load_test_fixture(fixture_name: str) -> Any:
    """Load a test fixture from the fixtures directory."""
    fixture_path = Path(__file__).parent.parent / "fixtures" / fixture_name
    
    if fixture_path.suffix == ".json":
        with open(fixture_path) as f:
            return json.load(f)
    elif fixture_path.suffix in [".yaml", ".yml"]:
        import yaml
        with open(fixture_path) as f:
            return yaml.safe_load(f)
    else:
        with open(fixture_path) as f:
            return f.read()


def save_test_output(
    data: Any,
    filename: str,
    output_dir: Optional[Path] = None
) -> Path:
    """Save test output for debugging."""
    if output_dir is None:
        output_dir = Path(__file__).parent.parent / "output"
    
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / filename
    
    if isinstance(data, (dict, list)):
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
    else:
        with open(output_path, "w") as f:
            f.write(str(data))
    
    return output_path


# Process helpers

async def run_subprocess(
    command: List[str],
    timeout: Optional[float] = None,
    capture_output: bool = True
) -> Dict[str, Any]:
    """Run a subprocess asynchronously."""
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE if capture_output else None,
        stderr=asyncio.subprocess.PIPE if capture_output else None
    )
    
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise TimeoutError(f"Process timed out after {timeout}s")
    
    return {
        "returncode": process.returncode,
        "stdout": stdout.decode() if stdout else "",
        "stderr": stderr.decode() if stderr else ""
    }


# Mock data generators

def create_mock_api_client(base_url: str = "http://test.local") -> Dict[str, Callable]:
    """Create a mock API client with common methods."""
    return {
        "get": lambda path: {"method": "GET", "url": f"{base_url}{path}"},
        "post": lambda path, data: {"method": "POST", "url": f"{base_url}{path}", "data": data},
        "put": lambda path, data: {"method": "PUT", "url": f"{base_url}{path}", "data": data},
        "delete": lambda path: {"method": "DELETE", "url": f"{base_url}{path}"}
    }


def create_test_database_session() -> Dict[str, Any]:
    """Create a mock database session."""
    storage = {}
    
    return {
        "query": lambda model: {"model": model, "filters": []},
        "add": lambda obj: storage.update({obj.get("id", len(storage)): obj}),
        "commit": lambda: None,
        "rollback": lambda: storage.clear(),
        "close": lambda: None,
        "_storage": storage
    }