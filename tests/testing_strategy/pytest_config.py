"""
Comprehensive Pytest Configuration for Claude Optimized Deployment Testing
SYNTHEX Agent 8 - Testing Specialist

This module provides complete pytest configuration including:
- Custom markers for test categorization
- Fixtures for test environments
- Performance benchmarking setup
- Test data management
- Reporting and analytics
- Parallel execution configuration
"""

import pytest
import os
import sys
import json
import time
import logging
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import asyncio
import psutil
import gc
from concurrent.futures import ThreadPoolExecutor
import yaml


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    # Add custom markers
    markers = [
        "unit: Unit tests for individual components",
        "integration: Integration tests between components", 
        "e2e: End-to-end tests for complete workflows",
        "performance: Performance and benchmarking tests",
        "security: Security vulnerability tests",
        "load: Load testing and stress tests",
        "regression: Regression prevention tests",
        "fuzz: Fuzzing and property-based tests",
        "memory: Memory usage and leak detection tests",
        "slow: Tests that take more than 30 seconds",
        "fast: Tests that should complete under 1 second",
        "requires_network: Tests requiring network access",
        "requires_docker: Tests requiring Docker environment",
        "requires_database: Tests requiring database connection",
        "chapter_detection: Tests for chapter detection algorithms",
        "format_parser: Tests for document format parsers",
        "mcp_protocol: Tests for MCP protocol implementation",
        "expert_system: Tests for circle of experts functionality",
        "document_processing: Tests for document processing pipeline",
    ]
    
    for marker in markers:
        config.addinivalue_line("markers", marker)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('pytest.log'),
            logging.StreamHandler()
        ]
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add automatic markers."""
    for item in items:
        # Auto-mark slow tests
        if "slow" in item.nodeid or "performance" in item.nodeid:
            item.add_marker(pytest.mark.slow)
        
        # Auto-mark tests requiring external resources
        if "network" in item.nodeid or "api" in item.nodeid:
            item.add_marker(pytest.mark.requires_network)
        
        if "docker" in item.nodeid:
            item.add_marker(pytest.mark.requires_docker)
        
        if "database" in item.nodeid or "db" in item.nodeid:
            item.add_marker(pytest.mark.requires_database)
        
        # Auto-mark chapter detection tests
        if "chapter" in item.nodeid:
            item.add_marker(pytest.mark.chapter_detection)


def pytest_runtest_setup(item):
    """Setup before each test runs."""
    # Skip tests based on environment
    if item.get_closest_marker("requires_network") and os.getenv("SKIP_NETWORK_TESTS"):
        pytest.skip("Network tests disabled")
    
    if item.get_closest_marker("requires_docker") and not _docker_available():
        pytest.skip("Docker not available")
    
    if item.get_closest_marker("requires_database") and not _database_available():
        pytest.skip("Database not available")


def pytest_runtest_teardown(item, nextitem):
    """Cleanup after each test."""
    # Force garbage collection
    gc.collect()
    
    # Log memory usage for memory tests
    if item.get_closest_marker("memory"):
        memory_usage = psutil.Process().memory_info().rss / 1024 / 1024
        print(f"Memory usage after {item.name}: {memory_usage:.2f} MB")


def pytest_sessionstart(session):
    """Called after the Session object has been created."""
    print(f"Starting test session at {datetime.now()}")
    
    # Create test output directories
    test_output_dir = Path("test_output")
    test_output_dir.mkdir(exist_ok=True)
    
    (test_output_dir / "artifacts").mkdir(exist_ok=True)
    (test_output_dir / "reports").mkdir(exist_ok=True)
    (test_output_dir / "logs").mkdir(exist_ok=True)


def pytest_sessionfinish(session, exitstatus):
    """Called after whole test run finished."""
    print(f"Test session finished with exit status: {exitstatus}")
    
    # Generate summary report
    _generate_session_report(session, exitstatus)


# ============================================================================
# Custom Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def test_config():
    """Provide test configuration."""
    config_file = Path("test_config.yaml")
    if config_file.exists():
        with open(config_file) as f:
            return yaml.safe_load(f)
    
    # Default configuration
    return {
        "timeouts": {
            "unit": 30,
            "integration": 300,
            "e2e": 1800,
            "performance": 3600
        },
        "parallel": {
            "unit_tests": 4,
            "integration_tests": 2,
            "e2e_tests": 1
        },
        "resources": {
            "max_memory_mb": 4096,
            "max_cpu_percent": 80
        }
    }


@pytest.fixture(scope="session")
def performance_baseline():
    """Load performance baselines for regression testing."""
    baseline_file = Path("performance_baseline.json")
    if baseline_file.exists():
        with open(baseline_file) as f:
            return json.load(f)
    
    return {}


@pytest.fixture
def memory_monitor():
    """Monitor memory usage during tests."""
    class MemoryMonitor:
        def __init__(self):
            self.initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
            self.snapshots = []
        
        def snapshot(self, label: str = ""):
            """Take a memory snapshot."""
            current_memory = psutil.Process().memory_info().rss / 1024 / 1024
            self.snapshots.append({
                "label": label,
                "memory_mb": current_memory,
                "growth_mb": current_memory - self.initial_memory,
                "timestamp": datetime.now().isoformat()
            })
        
        def get_peak_memory(self) -> float:
            """Get peak memory usage."""
            if not self.snapshots:
                return self.initial_memory
            return max(s["memory_mb"] for s in self.snapshots)
        
        def get_memory_growth(self) -> float:
            """Get total memory growth."""
            if not self.snapshots:
                return 0
            return max(s["growth_mb"] for s in self.snapshots)
        
        def assert_memory_limit(self, max_growth_mb: float):
            """Assert memory growth is within limits."""
            growth = self.get_memory_growth()
            assert growth <= max_growth_mb, f"Memory growth {growth}MB exceeds limit {max_growth_mb}MB"
    
    return MemoryMonitor()


@pytest.fixture
def performance_timer():
    """Timer for performance testing."""
    class PerformanceTimer:
        def __init__(self):
            self.timings = {}
            self.start_times = {}
        
        def start(self, operation: str):
            """Start timing an operation."""
            self.start_times[operation] = time.perf_counter()
        
        def stop(self, operation: str) -> float:
            """Stop timing and return duration."""
            if operation not in self.start_times:
                raise ValueError(f"No start time recorded for {operation}")
            
            duration = time.perf_counter() - self.start_times[operation]
            self.timings[operation] = duration
            return duration
        
        def assert_time_limit(self, operation: str, max_seconds: float):
            """Assert operation completed within time limit."""
            if operation not in self.timings:
                raise ValueError(f"No timing recorded for {operation}")
            
            duration = self.timings[operation]
            assert duration <= max_seconds, f"{operation} took {duration}s, exceeds limit {max_seconds}s"
        
        def get_timing(self, operation: str) -> float:
            """Get timing for operation."""
            return self.timings.get(operation, 0.0)
    
    return PerformanceTimer()


@pytest.fixture
def test_data_generator():
    """Generate test data for various scenarios."""
    class TestDataGenerator:
        def __init__(self):
            self.cache = {}
        
        def generate_document(self, 
                            format: str,
                            size_kb: int = 10,
                            chapters: int = 5,
                            complexity: str = "simple") -> str:
            """Generate test document."""
            cache_key = f"{format}_{size_kb}_{chapters}_{complexity}"
            
            if cache_key in self.cache:
                return self.cache[cache_key]
            
            if format == "markdown":
                content = self._generate_markdown(size_kb, chapters, complexity)
            elif format == "latex":
                content = self._generate_latex(size_kb, chapters, complexity)
            elif format == "html":
                content = self._generate_html(size_kb, chapters, complexity)
            else:
                content = f"# Test Document\n\nContent for {format} format."
            
            self.cache[cache_key] = content
            return content
        
        def _generate_markdown(self, size_kb: int, chapters: int, complexity: str) -> str:
            """Generate Markdown content."""
            content = []
            target_size = size_kb * 1024
            current_size = 0
            
            for i in range(chapters):
                chapter_content = f"# Chapter {i+1}\n\n"
                
                if complexity == "complex":
                    chapter_content += f"## Section {i+1}.1\n\n"
                    chapter_content += f"### Subsection {i+1}.1.1\n\n"
                
                # Add content to reach target size
                para_size = target_size // chapters
                para_text = "Lorem ipsum dolor sit amet. " * (para_size // 30)
                chapter_content += para_text + "\n\n"
                
                content.append(chapter_content)
                current_size += len(chapter_content.encode('utf-8'))
                
                if current_size >= target_size:
                    break
            
            return "".join(content)
        
        def _generate_latex(self, size_kb: int, chapters: int, complexity: str) -> str:
            """Generate LaTeX content."""
            content = [r"\documentclass{article}", r"\begin{document}"]
            
            for i in range(chapters):
                if complexity == "complex":
                    content.append(rf"\part{{Part {i+1}}}")
                
                content.append(rf"\chapter{{Chapter {i+1}}}")
                content.append(rf"\section{{Section {i+1}.1}}")
                content.append("Lorem ipsum content here.")
            
            content.append(r"\end{document}")
            return "\n".join(content)
        
        def _generate_html(self, size_kb: int, chapters: int, complexity: str) -> str:
            """Generate HTML content."""
            content = ["<html><body>"]
            
            for i in range(chapters):
                content.append(f"<h1>Chapter {i+1}</h1>")
                
                if complexity == "complex":
                    content.append(f"<h2>Section {i+1}.1</h2>")
                    content.append(f"<h3>Subsection {i+1}.1.1</h3>")
                
                content.append("<p>Lorem ipsum content here.</p>")
            
            content.append("</body></html>")
            return "\n".join(content)
        
        def generate_error_scenarios(self) -> Dict[str, Any]:
            """Generate error scenarios for testing."""
            return {
                "empty_content": "",
                "null_content": None,
                "binary_content": b"\x00\x01\x02\x03",
                "huge_content": "x" * (10**6),  # 1MB of 'x'
                "malformed_markdown": "# Header\n### Missing H2\n# Another",
                "invalid_latex": r"\invalid{command}",
                "broken_html": "<h1>Unclosed header",
                "unicode_test": "# Ünïcödé Héädér 🚀",
                "mixed_encodings": "# Header\n\x80\x81\x82",
            }
    
    return TestDataGenerator()


@pytest.fixture
def resource_monitor():
    """Monitor system resources during tests."""
    class ResourceMonitor:
        def __init__(self):
            self.process = psutil.Process()
            self.initial_stats = self._get_stats()
            self.peak_stats = self.initial_stats.copy()
        
        def _get_stats(self) -> Dict[str, float]:
            """Get current resource statistics."""
            return {
                "memory_mb": self.process.memory_info().rss / 1024 / 1024,
                "cpu_percent": self.process.cpu_percent(),
                "open_files": len(self.process.open_files()),
                "threads": self.process.num_threads()
            }
        
        def update_peak(self):
            """Update peak resource usage."""
            current = self._get_stats()
            for key, value in current.items():
                if value > self.peak_stats[key]:
                    self.peak_stats[key] = value
        
        def get_resource_usage(self) -> Dict[str, Any]:
            """Get current and peak resource usage."""
            current = self._get_stats()
            return {
                "current": current,
                "peak": self.peak_stats,
                "growth": {
                    key: current[key] - self.initial_stats[key]
                    for key in current.keys()
                }
            }
        
        def assert_resource_limits(self, 
                                 max_memory_mb: float = 1000,
                                 max_cpu_percent: float = 80,
                                 max_open_files: int = 100):
            """Assert resource usage is within limits."""
            current = self._get_stats()
            
            assert current["memory_mb"] <= max_memory_mb, \
                f"Memory usage {current['memory_mb']:.2f}MB exceeds limit {max_memory_mb}MB"
            
            assert current["cpu_percent"] <= max_cpu_percent, \
                f"CPU usage {current['cpu_percent']:.1f}% exceeds limit {max_cpu_percent}%"
            
            assert current["open_files"] <= max_open_files, \
                f"Open files {current['open_files']} exceeds limit {max_open_files}"
    
    return ResourceMonitor()


# ============================================================================
# Test Utilities
# ============================================================================

def _docker_available() -> bool:
    """Check if Docker is available."""
    try:
        subprocess.run(["docker", "--version"], 
                      capture_output=True, check=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _database_available() -> bool:
    """Check if database is available."""
    # This would check for actual database connectivity
    # For now, just check if connection string is provided
    return bool(os.getenv("DATABASE_URL"))


def _generate_session_report(session, exitstatus):
    """Generate comprehensive test session report."""
    report = {
        "session_info": {
            "start_time": getattr(session, 'start_time', datetime.now().isoformat()),
            "end_time": datetime.now().isoformat(),
            "exit_status": exitstatus,
            "total_collected": len(session.items) if hasattr(session, 'items') else 0
        },
        "environment": {
            "python_version": sys.version,
            "platform": sys.platform,
            "working_directory": os.getcwd(),
            "environment_variables": {
                key: value for key, value in os.environ.items()
                if key.startswith(('TEST_', 'PYTEST_', 'CI_'))
            }
        },
        "system_resources": {
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": psutil.virtual_memory().total / (1024**3),
            "disk_free_gb": psutil.disk_usage('/').free / (1024**3)
        }
    }
    
    # Save report
    report_file = Path("test_output/reports/session_report.json")
    report_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"Session report saved to {report_file}")


# ============================================================================
# Pytest Plugins Configuration
# ============================================================================

pytest_plugins = [
    "pytest_asyncio",
    "pytest_benchmark", 
    "pytest_cov",
    "pytest_mock",
    "pytest_xdist",
    "pytest_timeout",
    "pytest_html"
]

# Configuration for pytest-benchmark
def pytest_benchmark_update_json(config, benchmarks, output_json):
    """Update benchmark JSON with additional metadata."""
    output_json["environment"] = {
        "python_version": sys.version,
        "cpu_count": psutil.cpu_count(),
        "memory_gb": psutil.virtual_memory().total / (1024**3)
    }


# Configuration for pytest-html
def pytest_html_report_title(report):
    """Customize HTML report title."""
    report.title = "Claude Optimized Deployment Test Report"


def pytest_html_results_summary(prefix, summary, postfix):
    """Customize HTML report summary."""
    prefix.extend([
        f"<p>Test run on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        f"<p>Python version: {sys.version.split()[0]}</p>",
        f"<p>Platform: {sys.platform}</p>"
    ])


# ============================================================================
# Custom Command Line Options
# ============================================================================

def pytest_addoption(parser):
    """Add custom command line options."""
    group = parser.getgroup("custom", "Custom testing options")
    
    group.addoption(
        "--test-category",
        action="store",
        default="all",
        help="Run specific test category: unit, integration, e2e, performance, security"
    )
    
    group.addoption(
        "--skip-slow",
        action="store_true",
        default=False,
        help="Skip slow tests (performance, load, stress tests)"
    )
    
    group.addoption(
        "--memory-limit",
        action="store",
        type=int,
        default=1000,
        help="Memory limit in MB for resource monitoring"
    )
    
    group.addoption(
        "--generate-test-data",
        action="store_true",
        default=False,
        help="Generate test data before running tests"
    )
    
    group.addoption(
        "--save-artifacts",
        action="store_true", 
        default=False,
        help="Save test artifacts (logs, screenshots, etc.)"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection based on command line options."""
    # Skip slow tests if requested
    if config.getoption("--skip-slow"):
        skip_slow = pytest.mark.skip(reason="--skip-slow option provided")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)
    
    # Filter by test category
    category = config.getoption("--test-category")
    if category != "all":
        filtered_items = []
        for item in items:
            if category in item.keywords:
                filtered_items.append(item)
        items[:] = filtered_items


# ============================================================================
# Example Test Configuration File
# ============================================================================

EXAMPLE_CONFIG = """
# test_config.yaml
# Comprehensive test configuration

timeouts:
  unit: 30              # 30 seconds for unit tests
  integration: 300      # 5 minutes for integration tests  
  e2e: 1800            # 30 minutes for end-to-end tests
  performance: 3600     # 1 hour for performance tests

parallel:
  unit_tests: 4         # 4 parallel workers for unit tests
  integration_tests: 2  # 2 parallel workers for integration tests
  e2e_tests: 1         # Sequential execution for e2e tests

resources:
  max_memory_mb: 4096   # 4GB memory limit
  max_cpu_percent: 80   # 80% CPU limit
  max_open_files: 1000  # File handle limit

test_data:
  generate_on_demand: true
  cache_enabled: true
  max_cache_size_mb: 1000
  
reporting:
  formats: ["json", "html", "junit"]
  include_artifacts: true
  include_coverage: true
  include_benchmarks: true

notifications:
  enabled: true
  on_failure: true
  on_regression: true
  channels: ["slack", "email"]

environments:
  development:
    database_url: "sqlite:///test_dev.db"
    log_level: "DEBUG"
    
  ci:
    database_url: "postgresql://test:test@localhost/test_ci"
    log_level: "INFO"
    skip_slow_tests: true
    
  staging:
    database_url: "postgresql://test:test@staging-db/test"
    log_level: "WARNING"
    include_security_tests: true
"""

def create_example_config():
    """Create example configuration file."""
    config_file = Path("test_config.yaml")
    if not config_file.exists():
        config_file.write_text(EXAMPLE_CONFIG.strip())
        print(f"Created example configuration: {config_file}")


if __name__ == "__main__":
    create_example_config()