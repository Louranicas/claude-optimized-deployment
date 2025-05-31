"""
Global pytest configuration and fixtures for Claude Optimized Deployment tests.

This module provides common fixtures, mocks, and utilities used across all tests.
"""

import pytest
import asyncio
import os
import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, AsyncGenerator, Generator
from unittest.mock import Mock, AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import uuid

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.circle_of_experts import (
    ExpertManager,
    QueryHandler,
    ResponseCollector,
    ExpertQuery,
    ExpertResponse,
    QueryPriority,
    QueryType,
    ExpertType,
    ResponseStatus
)
from src.mcp.manager import MCPManager
from src.mcp.protocols import MCPTool, MCPToolParameter


# ============================================================================
# Event Loop Configuration
# ============================================================================

@pytest.fixture(scope="session")
def event_loop_policy():
    """Set event loop policy for async tests."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.get_event_loop_policy()


@pytest.fixture
def event_loop(event_loop_policy):
    """Create an event loop for async tests."""
    loop = event_loop_policy.new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# Common Test Data
# ============================================================================

@pytest.fixture
def test_data_dir(tmp_path) -> Path:
    """Provide a temporary directory for test data."""
    return tmp_path / "test_data"


@pytest.fixture
def sample_query_data() -> Dict[str, Any]:
    """Provide sample query data for testing."""
    return {
        "title": "Test Query",
        "content": "This is a test query for infrastructure optimization",
        "requester": "test_user",
        "query_type": QueryType.TECHNICAL,
        "priority": QueryPriority.HIGH,
        "metadata": {
            "domain": "infrastructure",
            "tags": ["testing", "optimization"],
            "deadline": (datetime.now() + timedelta(hours=2)).isoformat()
        }
    }


@pytest.fixture
def sample_expert_response() -> Dict[str, Any]:
    """Provide sample expert response data."""
    return {
        "expert_id": "claude-3.5",
        "expert_type": ExpertType.CLAUDE,
        "confidence": 0.95,
        "reasoning": "Based on analysis of the infrastructure requirements...",
        "recommendations": [
            "Implement caching at the API layer",
            "Use connection pooling for database",
            "Enable HTTP/2 for better performance"
        ],
        "response_time": 1.5,
        "cost": 0.02
    }


# ============================================================================
# Mock Factories
# ============================================================================

@pytest.fixture
def mock_expert_manager() -> Mock:
    """Create a mock ExpertManager."""
    manager = Mock(spec=ExpertManager)
    manager.initialize = AsyncMock()
    manager.cleanup = AsyncMock()
    manager.health_check = AsyncMock(return_value={
        "claude-3.5": {"status": "healthy", "latency": 0.1},
        "gpt-4": {"status": "healthy", "latency": 0.2},
        "gemini-pro": {"status": "healthy", "latency": 0.15}
    })
    manager.get_available_experts = Mock(return_value=[
        {"id": "claude-3.5", "type": ExpertType.CLAUDE, "cost_per_token": 0.01},
        {"id": "gpt-4", "type": ExpertType.OPENAI, "cost_per_token": 0.03},
        {"id": "gemini-pro", "type": ExpertType.GEMINI, "cost_per_token": 0.001}
    ])
    return manager


@pytest.fixture
def mock_query_handler() -> Mock:
    """Create a mock QueryHandler."""
    handler = Mock(spec=QueryHandler)
    handler.process_query = AsyncMock()
    handler.validate_query = Mock(return_value=True)
    handler.estimate_cost = Mock(return_value={"estimated_cost": 0.15, "expert_count": 3})
    return handler


@pytest.fixture
def mock_response_collector() -> Mock:
    """Create a mock ResponseCollector."""
    collector = Mock(spec=ResponseCollector)
    collector.collect_responses = AsyncMock()
    collector.aggregate_responses = Mock()
    collector.calculate_consensus = Mock(return_value={
        "consensus_level": 0.85,
        "primary_recommendation": "Implement caching",
        "confidence": 0.9
    })
    return collector


@pytest.fixture
def mock_mcp_manager() -> Mock:
    """Create a mock MCPManager with all servers."""
    manager = Mock(spec=MCPManager)
    manager.initialize = AsyncMock()
    manager.cleanup = AsyncMock()
    manager.get_available_tools = Mock(return_value=[
        "desktop-commander.execute_command",
        "docker.docker_build",
        "kubernetes.kubectl_apply",
        "azure-devops.create_pipeline",
        "prometheus.prometheus_query"
    ])
    manager.call_tool = AsyncMock(return_value={
        "success": True,
        "result": {"output": "Command executed successfully"}
    })
    return manager


# ============================================================================
# AI Provider Mocks
# ============================================================================

@pytest.fixture
def mock_claude_api():
    """Mock Anthropic Claude API."""
    with patch("anthropic.AsyncAnthropic") as mock:
        client = AsyncMock()
        mock.return_value = client
        
        # Mock message creation
        message_mock = AsyncMock()
        message_mock.content = [MagicMock(text="Claude response: Implement caching for better performance")]
        client.messages.create = AsyncMock(return_value=message_mock)
        
        yield client


@pytest.fixture
def mock_openai_api():
    """Mock OpenAI API."""
    with patch("openai.AsyncOpenAI") as mock:
        client = AsyncMock()
        mock.return_value = client
        
        # Mock chat completion
        completion_mock = MagicMock()
        completion_mock.choices = [
            MagicMock(message=MagicMock(content="GPT-4 response: Use connection pooling"))
        ]
        client.chat.completions.create = AsyncMock(return_value=completion_mock)
        
        yield client


@pytest.fixture
def mock_gemini_api():
    """Mock Google Gemini API."""
    with patch("google.generativeai.GenerativeModel") as mock:
        model = MagicMock()
        mock.return_value = model
        
        # Mock generate content
        response_mock = MagicMock()
        response_mock.text = "Gemini response: Enable HTTP/2 for better performance"
        model.generate_content_async = AsyncMock(return_value=response_mock)
        
        yield model


# ============================================================================
# MCP Server Mocks
# ============================================================================

@pytest.fixture
def mock_docker_server():
    """Mock Docker MCP server."""
    server = AsyncMock()
    server.get_server_info = AsyncMock(return_value={
        "name": "docker",
        "version": "1.0.0",
        "description": "Docker container management"
    })
    server.get_tools = Mock(return_value=[
        MCPTool(
            name="docker_build",
            description="Build Docker image",
            parameters=[
                MCPToolParameter(name="dockerfile_path", type="string", required=True),
                MCPToolParameter(name="image_tag", type="string", required=True)
            ]
        )
    ])
    server.call_tool = AsyncMock(return_value={
        "success": True,
        "result": {"image_id": "sha256:abc123", "build_time": 45.2}
    })
    return server


@pytest.fixture
def mock_kubernetes_server():
    """Mock Kubernetes MCP server."""
    server = AsyncMock()
    server.get_server_info = AsyncMock(return_value={
        "name": "kubernetes",
        "version": "1.0.0",
        "description": "Kubernetes cluster management"
    })
    server.get_tools = Mock(return_value=[
        MCPTool(
            name="kubectl_apply",
            description="Apply Kubernetes manifest",
            parameters=[
                MCPToolParameter(name="manifest_path", type="string", required=True),
                MCPToolParameter(name="namespace", type="string", required=False)
            ]
        )
    ])
    server.call_tool = AsyncMock(return_value={
        "success": True,
        "result": {"resources_created": 3, "namespace": "default"}
    })
    return server


# ============================================================================
# Test Environment Setup
# ============================================================================

@pytest.fixture
def test_env_vars(monkeypatch):
    """Set up test environment variables."""
    env_vars = {
        "ENVIRONMENT": "testing",
        "LOG_LEVEL": "DEBUG",
        "ANTHROPIC_API_KEY": "test-claude-key",
        "OPENAI_API_KEY": "test-openai-key",
        "GOOGLE_GEMINI_API_KEY": "test-gemini-key",
        "BRAVE_API_KEY": "test-brave-key",
        "SLACK_BOT_TOKEN": "test-slack-token",
        "AWS_ACCESS_KEY_ID": "test-aws-key",
        "AWS_SECRET_ACCESS_KEY": "test-aws-secret",
        "AZURE_DEVOPS_TOKEN": "test-azure-token"
    }
    
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    
    return env_vars


@pytest.fixture
def clean_env(monkeypatch):
    """Remove all environment variables for isolated testing."""
    # Store original env
    original_env = dict(os.environ)
    
    # Clear all env vars
    for key in list(os.environ.keys()):
        monkeypatch.delenv(key, raising=False)
    
    yield
    
    # Restore original env
    for key, value in original_env.items():
        monkeypatch.setenv(key, value)


# ============================================================================
# Database and Storage Fixtures
# ============================================================================

@pytest.fixture
async def mock_drive_manager():
    """Mock Google Drive manager."""
    manager = AsyncMock()
    manager.initialize = AsyncMock()
    manager.save_query = AsyncMock(return_value="query_123")
    manager.save_response = AsyncMock(return_value="response_456")
    manager.get_query = AsyncMock(return_value={
        "id": "query_123",
        "title": "Test Query",
        "content": "Test content"
    })
    return manager


@pytest.fixture
def temp_db(tmp_path) -> Path:
    """Create a temporary SQLite database for testing."""
    db_path = tmp_path / "test.db"
    return db_path


# ============================================================================
# Performance Testing Fixtures
# ============================================================================

@pytest.fixture
def performance_monitor():
    """Monitor performance metrics during tests."""
    class PerformanceMonitor:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.metrics = {}
        
        def start(self):
            self.start_time = datetime.now()
        
        def stop(self):
            self.end_time = datetime.now()
            self.metrics["duration"] = (self.end_time - self.start_time).total_seconds()
        
        def record_metric(self, name: str, value: Any):
            self.metrics[name] = value
        
        def get_report(self) -> Dict[str, Any]:
            return {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "metrics": self.metrics
            }
    
    return PerformanceMonitor()


# ============================================================================
# Integration Test Fixtures
# ============================================================================

@pytest.fixture
async def integration_test_setup(test_env_vars, tmp_path):
    """Set up integration test environment."""
    # Create test directories
    test_dir = tmp_path / "integration_test"
    test_dir.mkdir(exist_ok=True)
    
    config_dir = test_dir / "config"
    config_dir.mkdir(exist_ok=True)
    
    logs_dir = test_dir / "logs"
    logs_dir.mkdir(exist_ok=True)
    
    # Create test configuration
    config = {
        "test_id": f"integration_{uuid.uuid4().hex[:8]}",
        "environment": "testing",
        "directories": {
            "root": str(test_dir),
            "config": str(config_dir),
            "logs": str(logs_dir)
        }
    }
    
    config_file = config_dir / "test_config.json"
    config_file.write_text(json.dumps(config, indent=2))
    
    yield config
    
    # Cleanup is handled by tmp_path


# ============================================================================
# Async Utilities
# ============================================================================

@pytest.fixture
def async_timeout():
    """Provide configurable timeout for async operations."""
    return 30.0  # 30 seconds default


@pytest.fixture
async def async_context_manager():
    """Example async context manager for testing."""
    class AsyncContextManager:
        async def __aenter__(self):
            await asyncio.sleep(0.1)  # Simulate async setup
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            await asyncio.sleep(0.1)  # Simulate async cleanup
    
    return AsyncContextManager()


# ============================================================================
# Error Injection Fixtures
# ============================================================================

@pytest.fixture
def error_scenarios():
    """Provide common error scenarios for testing."""
    return {
        "network_timeout": asyncio.TimeoutError("Network request timed out"),
        "api_error": Exception("API returned error: 500 Internal Server Error"),
        "auth_error": Exception("Authentication failed: Invalid API key"),
        "rate_limit": Exception("Rate limit exceeded"),
        "invalid_input": ValueError("Invalid input format"),
        "resource_not_found": FileNotFoundError("Resource not found")
    }


@pytest.fixture
def flaky_mock():
    """Create a mock that fails intermittently."""
    class FlakyMock:
        def __init__(self, failure_rate=0.3):
            self.failure_rate = failure_rate
            self.call_count = 0
        
        async def call(self, *args, **kwargs):
            self.call_count += 1
            import random
            if random.random() < self.failure_rate:
                raise Exception("Flaky error occurred")
            return {"success": True, "call_count": self.call_count}
    
    return FlakyMock()


# ============================================================================
# Cleanup Fixtures
# ============================================================================

@pytest.fixture(autouse=True)
async def cleanup_async_tasks():
    """Ensure all async tasks are cleaned up after each test."""
    yield
    
    # Cancel any remaining tasks
    tasks = [t for t in asyncio.all_tasks() if not t.done()]
    for task in tasks:
        task.cancel()
    
    # Wait for cancellation
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)