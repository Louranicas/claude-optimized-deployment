"""
Integration test fixtures for Claude Optimized Deployment.

This module provides fixtures specifically for integration testing,
including database setup, external service mocks, and test data.
"""

import pytest
import asyncio
import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, AsyncGenerator
from unittest.mock import AsyncMock, Mock
import json

# Test Database Setup
@pytest.fixture(scope="session")
async def test_database():
    """Set up a test database for integration tests."""
    import sqlite3
    from contextlib import asynccontextmanager
    
    # Create temporary database
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(db_fd)
    
    # Initialize database schema
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create test tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS queries (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            query_type TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS responses (
            id TEXT PRIMARY KEY,
            query_id TEXT NOT NULL,
            expert_id TEXT NOT NULL,
            content TEXT NOT NULL,
            confidence REAL NOT NULL,
            cost REAL NOT NULL,
            response_time REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (query_id) REFERENCES queries (id)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user',
            api_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT NOT NULL,
            resource TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()
    
    yield db_path
    
    # Cleanup
    os.unlink(db_path)


@pytest.fixture
async def database_session(test_database):
    """Provide a database session for tests."""
    import sqlite3
    import uuid
    
    conn = sqlite3.connect(test_database)
    conn.row_factory = sqlite3.Row
    
    # Insert test data
    test_user_id = str(uuid.uuid4())
    test_query_id = str(uuid.uuid4())
    
    cursor = conn.cursor()
    
    # Insert test user
    cursor.execute("""
        INSERT INTO users (id, username, email, role, api_key)
        VALUES (?, ?, ?, ?, ?)
    """, (test_user_id, "testuser", "test@example.com", "admin", "test-api-key"))
    
    # Insert test query
    cursor.execute("""
        INSERT INTO queries (id, title, content, query_type, priority, metadata)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (test_query_id, "Test Query", "Test content", "technical", "high", 
          json.dumps({"tags": ["test"], "domain": "infrastructure"})))
    
    conn.commit()
    
    class DatabaseSession:
        def __init__(self, connection):
            self.conn = connection
            self.test_user_id = test_user_id
            self.test_query_id = test_query_id
        
        def execute(self, query, params=()):
            return self.conn.execute(query, params)
        
        def fetchone(self, query, params=()):
            return self.conn.execute(query, params).fetchone()
        
        def fetchall(self, query, params=()):
            return self.conn.execute(query, params).fetchall()
        
        def commit(self):
            self.conn.commit()
        
        def rollback(self):
            self.conn.rollback()
    
    session = DatabaseSession(conn)
    yield session
    
    conn.close()


# External Service Mocks
@pytest.fixture
def mock_redis_client():
    """Mock Redis client for caching tests."""
    class MockRedis:
        def __init__(self):
            self._store = {}
        
        async def get(self, key):
            return self._store.get(key)
        
        async def set(self, key, value, ex=None):
            self._store[key] = value
            return True
        
        async def delete(self, key):
            return self._store.pop(key, None) is not None
        
        async def exists(self, key):
            return key in self._store
        
        async def flushdb(self):
            self._store.clear()
            return True
        
        async def ping(self):
            return True
    
    return MockRedis()


@pytest.fixture
def mock_prometheus_client():
    """Mock Prometheus metrics client."""
    class MockPrometheus:
        def __init__(self):
            self.metrics = {}
        
        def inc(self, metric_name, labels=None):
            key = f"{metric_name}:{labels or ''}"
            self.metrics[key] = self.metrics.get(key, 0) + 1
        
        def set(self, metric_name, value, labels=None):
            key = f"{metric_name}:{labels or ''}"
            self.metrics[key] = value
        
        def observe(self, metric_name, value, labels=None):
            key = f"{metric_name}:{labels or ''}"
            if key not in self.metrics:
                self.metrics[key] = []
            self.metrics[key].append(value)
        
        def get_metric(self, metric_name, labels=None):
            key = f"{metric_name}:{labels or ''}"
            return self.metrics.get(key, 0)
    
    return MockPrometheus()


# Test Environment Setup
@pytest.fixture
def integration_test_config(tmp_path):
    """Provide integration test configuration."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    
    config = {
        "database": {
            "url": "sqlite:///test.db",
            "pool_size": 5,
            "max_overflow": 10
        },
        "redis": {
            "host": "localhost",
            "port": 6379,
            "db": 1
        },
        "monitoring": {
            "prometheus_url": "http://localhost:9090",
            "metrics_enabled": True
        },
        "mcp": {
            "servers": {
                "docker": {
                    "command": "docker-mcp-server",
                    "args": []
                },
                "kubernetes": {
                    "command": "k8s-mcp-server",
                    "args": []
                }
            }
        },
        "security": {
            "jwt_secret": "test-secret-key",
            "api_key_required": False,
            "rate_limiting": {
                "enabled": False
            }
        }
    }
    
    config_file = config_dir / "test_config.json"
    config_file.write_text(json.dumps(config, indent=2))
    
    return config


# Load Testing Fixtures
@pytest.fixture
def load_test_scenarios():
    """Provide load testing scenarios."""
    return {
        "light_load": {
            "concurrent_users": 10,
            "requests_per_second": 5,
            "duration_seconds": 30
        },
        "medium_load": {
            "concurrent_users": 50,
            "requests_per_second": 25,
            "duration_seconds": 60
        },
        "heavy_load": {
            "concurrent_users": 100,
            "requests_per_second": 50,
            "duration_seconds": 120
        },
        "stress_test": {
            "concurrent_users": 500,
            "requests_per_second": 200,
            "duration_seconds": 300
        }
    }


# File System Test Fixtures
@pytest.fixture
def test_workspace(tmp_path):
    """Create a test workspace with typical project structure."""
    workspace = tmp_path / "test_workspace"
    workspace.mkdir()
    
    # Create directory structure
    (workspace / "src").mkdir()
    (workspace / "tests").mkdir()
    (workspace / "config").mkdir()
    (workspace / "logs").mkdir()
    (workspace / "data").mkdir()
    
    # Create sample files
    (workspace / "src" / "__init__.py").touch()
    (workspace / "tests" / "__init__.py").touch()
    (workspace / "config" / "settings.json").write_text('{"env": "test"}')
    (workspace / "README.md").write_text("# Test Project")
    
    return workspace


# Network Test Fixtures
@pytest.fixture
def mock_http_server():
    """Mock HTTP server for network tests."""
    from unittest.mock import MagicMock
    
    class MockHTTPServer:
        def __init__(self):
            self.requests = []
            self.responses = {}
        
        def add_response(self, url, response_data, status_code=200):
            self.responses[url] = {
                "data": response_data,
                "status": status_code
            }
        
        async def request(self, method, url, **kwargs):
            self.requests.append({
                "method": method,
                "url": url,
                "kwargs": kwargs
            })
            
            if url in self.responses:
                response = self.responses[url]
                mock_response = MagicMock()
                mock_response.status_code = response["status"]
                mock_response.json.return_value = response["data"]
                mock_response.text = json.dumps(response["data"])
                return mock_response
            
            # Default response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"success": True}
            mock_response.text = '{"success": true}'
            return mock_response
    
    return MockHTTPServer()


# Performance Monitoring
@pytest.fixture
def performance_tracker():
    """Track performance metrics during integration tests."""
    import time
    import psutil
    import threading
    
    class PerformanceTracker:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.cpu_samples = []
            self.memory_samples = []
            self.monitoring = False
            self.monitor_thread = None
        
        def start_monitoring(self):
            self.start_time = time.time()
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_resources)
            self.monitor_thread.start()
        
        def stop_monitoring(self):
            self.end_time = time.time()
            self.monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join()
        
        def _monitor_resources(self):
            while self.monitoring:
                self.cpu_samples.append(psutil.cpu_percent())
                self.memory_samples.append(psutil.virtual_memory().percent)
                time.sleep(0.1)
        
        def get_report(self):
            duration = self.end_time - self.start_time if self.end_time else 0
            return {
                "duration": duration,
                "cpu_avg": sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0,
                "cpu_max": max(self.cpu_samples) if self.cpu_samples else 0,
                "memory_avg": sum(self.memory_samples) / len(self.memory_samples) if self.memory_samples else 0,
                "memory_max": max(self.memory_samples) if self.memory_samples else 0,
                "samples_count": len(self.cpu_samples)
            }
    
    return PerformanceTracker()


# Async Test Utilities
@pytest.fixture
async def async_test_timeout():
    """Provide timeout context for async tests."""
    return asyncio.wait_for


@pytest.fixture
def concurrent_execution():
    """Utility for running concurrent async operations."""
    async def run_concurrent(operations, max_concurrency=10):
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def limited_operation(op):
            async with semaphore:
                return await op
        
        return await asyncio.gather(*[limited_operation(op) for op in operations])
    
    return run_concurrent