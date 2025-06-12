"""
Lazy import module for heavy dependencies.

This module provides lazy loading capabilities for heavy dependencies to reduce
memory footprint and startup time. Dependencies are only loaded when actually used.

Memory optimizations:
- AI/ML libraries (transformers, langchain, torch): ~200MB saved if not used
- Cloud SDKs (boto3, azure, gcp): ~100MB saved if not used  
- Infrastructure tools (kubernetes, docker): ~75MB saved if not used
- Monitoring/telemetry: ~50MB saved if not used

Usage:
    from src.core.lazy_imports import LazyImport
    
    # Heavy dependency loaded only when accessed
    transformers = LazyImport("transformers")
    model = transformers.AutoModel.from_pretrained("model-name")
    
    # Or use context manager for cleanup
    with LazyImport("torch") as torch:
        tensor = torch.tensor([1, 2, 3])
"""

import importlib
import logging
import sys
import time
import tracemalloc
from typing import Any, Dict, Optional, Set, Union
from contextlib import contextmanager
from functools import wraps

logger = logging.getLogger(__name__)

# Track imported modules and their memory usage
_imported_modules: Dict[str, Dict[str, Any]] = {}
_memory_usage: Dict[str, int] = {}


class LazyImport:
    """
    Lazy import wrapper that loads modules only when accessed.
    
    Provides memory monitoring and conditional imports for optional features.
    """
    
    def __init__(
        self, 
        module_name: str, 
        package: Optional[str] = None,
        min_version: Optional[str] = None,
        fallback_module: Optional[str] = None,
        memory_limit_mb: Optional[int] = None
    ):
        """
        Initialize lazy import.
        
        Args:
            module_name: Name of module to import
            package: Package name for relative imports  
            min_version: Minimum required version
            fallback_module: Fallback module if main module fails
            memory_limit_mb: Maximum memory usage limit for import
        """
        self.module_name = module_name
        self.package = package
        self.min_version = min_version
        self.fallback_module = fallback_module
        self.memory_limit_mb = memory_limit_mb
        self._module: Optional[Any] = None
        self._import_time: Optional[float] = None
        self._memory_usage: Optional[int] = None
        
    def __getattr__(self, name: str) -> Any:
        """Lazy load module when attribute is accessed."""
        if self._module is None:
            self._load_module()
        return getattr(self._module, name)
    
    def __enter__(self):
        """Context manager entry."""
        if self._module is None:
            self._load_module()
        return self._module
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with optional cleanup."""
        # Optional: could implement module cleanup here
        pass
    
    def _load_module(self) -> None:
        """Load the module with memory monitoring."""
        if self._module is not None:
            return
            
        start_time = time.time()
        
        # Start memory monitoring
        if tracemalloc.is_tracing():
            snapshot_before = tracemalloc.take_snapshot()
        else:
            tracemalloc.start()
            snapshot_before = None
            
        try:
            # Try to import the main module
            self._module = importlib.import_module(self.module_name, self.package)
            
            # Check version if specified
            if self.min_version and hasattr(self._module, '__version__'):
                if not self._check_version(self._module.__version__, self.min_version):
                    raise ImportError(
                        f"{self.module_name} version {self._module.__version__} "
                        f"is below minimum required {self.min_version}"
                    )
            
            self._import_time = time.time() - start_time
            
            # Calculate memory usage
            if snapshot_before:
                snapshot_after = tracemalloc.take_snapshot()
                top_stats = snapshot_after.compare_to(snapshot_before, 'lineno')
                memory_used = sum(stat.size_diff for stat in top_stats if stat.size_diff > 0)
                self._memory_usage = memory_used
            else:
                # Fallback: get current memory usage
                current, peak = tracemalloc.get_traced_memory()
                self._memory_usage = current
                tracemalloc.stop()
            
            # Check memory limit
            if self.memory_limit_mb:
                memory_mb = self._memory_usage / (1024 * 1024)
                if memory_mb > self.memory_limit_mb:
                    logger.warning(
                        f"Module {self.module_name} uses {memory_mb:.1f}MB, "
                        f"exceeds limit of {self.memory_limit_mb}MB"
                    )
            
            # Track import for monitoring
            _imported_modules[self.module_name] = {
                'module': self._module,
                'import_time': self._import_time,
                'memory_usage': self._memory_usage,
                'timestamp': time.time()
            }
            
            logger.info(
                f"Lazy imported {self.module_name} in {self._import_time:.2f}s, "
                f"memory: {self._memory_usage / (1024 * 1024):.1f}MB"
            )
            
        except ImportError as e:
            # Try fallback module if specified
            if self.fallback_module:
                logger.warning(
                    f"Failed to import {self.module_name}, trying fallback {self.fallback_module}: {e}"
                )
                try:
                    self._module = importlib.import_module(self.fallback_module)
                    self._import_time = time.time() - start_time
                    logger.info(f"Using fallback module {self.fallback_module}")
                except ImportError:
                    pass
            
            if self._module is None:
                # Provide helpful error message with installation instructions
                install_suggestions = _get_install_suggestions(self.module_name)
                raise ImportError(
                    f"Failed to import {self.module_name}. {install_suggestions}"
                ) from e
    
    def _check_version(self, actual: str, required: str) -> bool:
        """Check if actual version meets minimum requirement."""
        try:
            from packaging import version
            return version.parse(actual) >= version.parse(required)
        except ImportError:
            # Fallback to simple string comparison
            return actual >= required
    
    @property
    def is_loaded(self) -> bool:
        """Check if module is loaded."""
        return self._module is not None
    
    @property
    def import_time(self) -> Optional[float]:
        """Get import time in seconds."""
        return self._import_time
    
    @property 
    def memory_usage(self) -> Optional[int]:
        """Get memory usage in bytes."""
        return self._memory_usage


def lazy_import(
    module_name: str,
    package: Optional[str] = None,
    min_version: Optional[str] = None,
    fallback_module: Optional[str] = None,
    memory_limit_mb: Optional[int] = None
) -> LazyImport:
    """
    Create a lazy import.
    
    Args:
        module_name: Name of module to import
        package: Package name for relative imports
        min_version: Minimum required version 
        fallback_module: Fallback module if main module fails
        memory_limit_mb: Maximum memory usage limit
        
    Returns:
        LazyImport instance
    """
    return LazyImport(
        module_name=module_name,
        package=package, 
        min_version=min_version,
        fallback_module=fallback_module,
        memory_limit_mb=memory_limit_mb
    )


def optional_import(module_name: str, default=None):
    """
    Import module optionally, returning default if not available.
    
    Args:
        module_name: Module to import
        default: Default value to return if import fails
        
    Returns:
        Imported module or default value
    """
    try:
        return importlib.import_module(module_name)
    except ImportError:
        logger.debug(f"Optional import {module_name} not available")
        return default


def conditional_import(condition: bool, module_name: str, default=None):
    """
    Import module conditionally based on runtime condition.
    
    Args:
        condition: Whether to attempt import
        module_name: Module to import
        default: Default value if not importing
        
    Returns:
        Imported module or default value
    """
    if condition:
        return optional_import(module_name, default)
    return default


def get_import_stats() -> Dict[str, Any]:
    """
    Get statistics about imported modules.
    
    Returns:
        Dictionary with import statistics
    """
    total_memory = sum(
        info.get('memory_usage', 0) for info in _imported_modules.values()
    )
    total_time = sum(
        info.get('import_time', 0) for info in _imported_modules.values()
    )
    
    return {
        'modules_imported': len(_imported_modules),
        'total_memory_bytes': total_memory,
        'total_memory_mb': total_memory / (1024 * 1024),
        'total_import_time': total_time,
        'modules': {
            name: {
                'memory_mb': info.get('memory_usage', 0) / (1024 * 1024),
                'import_time': info.get('import_time', 0),
                'timestamp': info.get('timestamp', 0)
            }
            for name, info in _imported_modules.items()
        }
    }


def clear_import_cache() -> None:
    """Clear the import cache (for testing)."""
    global _imported_modules, _memory_usage
    _imported_modules.clear()
    _memory_usage.clear()


def _get_install_suggestions(module_name: str) -> str:
    """Get installation suggestions for missing modules."""
    install_map = {
        'transformers': 'pip install .[ai] or pip install transformers',
        'langchain': 'pip install .[ai] or pip install langchain',
        'torch': 'pip install .[ai] or pip install torch',
        'ollama': 'pip install .[ai] or pip install ollama',
        'boto3': 'pip install .[cloud] or pip install boto3',
        'azure-mgmt': 'pip install .[cloud] or pip install azure-mgmt',
        'google-cloud': 'pip install .[cloud] or pip install google-cloud',
        'kubernetes': 'pip install .[infrastructure] or pip install kubernetes',
        'docker': 'pip install .[infrastructure] or pip install docker',
        'prometheus-client': 'pip install .[monitoring] or pip install prometheus-client',
        'opentelemetry-api': 'pip install .[monitoring] or pip install opentelemetry-api',
        'numpy': 'pip install .[data] or pip install numpy',
        'pandas': 'pip install .[data] or pip install pandas',
    }
    
    suggestion = install_map.get(module_name, f'pip install {module_name}')
    return f"To install: {suggestion}"


# Pre-configured lazy imports for common heavy dependencies
# These can be imported directly from this module

# AI/ML dependencies (very heavy - 200+ MB)
transformers = lazy_import('transformers', memory_limit_mb=200)
langchain = lazy_import('langchain', memory_limit_mb=100) 
torch = lazy_import('torch', memory_limit_mb=300)
ollama = lazy_import('ollama', memory_limit_mb=50)

# Cloud SDKs (heavy - 50-100 MB each)
boto3 = lazy_import('boto3', memory_limit_mb=100)
azure_mgmt = lazy_import('azure.mgmt', memory_limit_mb=75)
google_cloud = lazy_import('google.cloud', memory_limit_mb=75)

# Infrastructure tools (moderate - 25-75 MB)
kubernetes = lazy_import('kubernetes', memory_limit_mb=75)
docker = lazy_import('docker', memory_limit_mb=50)

# Monitoring tools (moderate - 25-50 MB)
prometheus_client = lazy_import('prometheus_client', memory_limit_mb=25)
opentelemetry = lazy_import('opentelemetry', memory_limit_mb=50)

# Data processing (heavy - 50-100 MB)
numpy = lazy_import('numpy', memory_limit_mb=100)
pandas = lazy_import('pandas', memory_limit_mb=150)


# Decorator for functions that use heavy dependencies
def requires_dependency(dependency_name: str, install_suggestion: Optional[str] = None):
    """
    Decorator for functions that require optional dependencies.
    
    Args:
        dependency_name: Name of required dependency
        install_suggestion: Custom installation suggestion
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Try to import the dependency
                importlib.import_module(dependency_name)
                return func(*args, **kwargs)
            except ImportError:
                suggestion = install_suggestion or _get_install_suggestions(dependency_name)
                raise ImportError(
                    f"Function {func.__name__} requires {dependency_name}. {suggestion}"
                )
        return wrapper
    return decorator


# Context manager for temporary heavy imports
@contextmanager
def temporary_import(module_name: str):
    """
    Context manager for temporarily importing heavy modules.
    
    The module is available only within the context and can be
    garbage collected afterwards.
    """
    module = None
    try:
        module = importlib.import_module(module_name)
        yield module
    finally:
        # Optional: could implement module cleanup
        if module_name in sys.modules:
            # Note: Removing from sys.modules doesn't guarantee memory cleanup
            # but helps with testing and explicit resource management
            pass