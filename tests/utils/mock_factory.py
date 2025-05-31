"""
Mock factory for creating test doubles.

This module provides factory functions for creating mock objects
used throughout the test suite.
"""

from typing import Dict, Any, List, Optional, Union
from unittest.mock import Mock, AsyncMock, MagicMock
from datetime import datetime, timedelta
import uuid
import random

from src.circle_of_experts import (
    ExpertQuery,
    ExpertResponse,
    QueryPriority,
    QueryType,
    ExpertType,
    ResponseStatus
)
from src.mcp.protocols import MCPTool, MCPToolParameter


class MockFactory:
    """Factory for creating mock objects."""
    
    @staticmethod
    def create_expert_query(**kwargs) -> ExpertQuery:
        """Create a mock ExpertQuery with sensible defaults."""
        defaults = {
            "title": f"Test Query {uuid.uuid4().hex[:8]}",
            "content": "This is a test query content for testing purposes",
            "requester": "test_user",
            "query_type": QueryType.TECHNICAL,
            "priority": QueryPriority.MEDIUM,
            "metadata": {
                "test": True,
                "created_at": datetime.now().isoformat()
            }
        }
        defaults.update(kwargs)
        return ExpertQuery(**defaults)
    
    @staticmethod
    def create_expert_response(**kwargs) -> ExpertResponse:
        """Create a mock ExpertResponse with sensible defaults."""
        defaults = {
            "query_id": str(uuid.uuid4()),
            "expert_id": "test-expert-1",
            "expert_type": ExpertType.CLAUDE,
            "content": "This is a test response with recommendations",
            "confidence": 0.85,
            "reasoning": "Based on analysis of the query...",
            "recommendations": [
                "Recommendation 1: Do this",
                "Recommendation 2: Do that",
                "Recommendation 3: Consider this"
            ],
            "status": ResponseStatus.COMPLETED,
            "response_time": 1.5,
            "cost": 0.02,
            "metadata": {
                "model_version": "test-v1",
                "tokens_used": 150
            }
        }
        defaults.update(kwargs)
        return ExpertResponse(**defaults)
    
    @staticmethod
    def create_mcp_tool(**kwargs) -> MCPTool:
        """Create a mock MCPTool."""
        defaults = {
            "name": "test_tool",
            "description": "A test tool for testing",
            "parameters": [
                MCPToolParameter(
                    name="param1",
                    type="string",
                    description="First parameter",
                    required=True
                ),
                MCPToolParameter(
                    name="param2",
                    type="number",
                    description="Second parameter",
                    required=False,
                    default=42
                )
            ]
        }
        defaults.update(kwargs)
        return MCPTool(**defaults)
    
    @staticmethod
    def create_mock_expert(expert_type: ExpertType = ExpertType.CLAUDE, **kwargs) -> Mock:
        """Create a mock expert with configured behavior."""
        expert = Mock()
        expert.expert_id = kwargs.get("expert_id", f"{expert_type.value}-test")
        expert.expert_type = expert_type
        expert.is_available = AsyncMock(return_value=True)
        expert.health_check = AsyncMock(return_value={
            "status": "healthy",
            "latency": 0.1,
            "version": "test-v1"
        })
        
        # Configure query handling
        async def mock_query(query: ExpertQuery) -> ExpertResponse:
            await asyncio.sleep(0.1)  # Simulate processing time
            return MockFactory.create_expert_response(
                query_id=query.id,
                expert_id=expert.expert_id,
                expert_type=expert.expert_type
            )
        
        expert.query = AsyncMock(side_effect=mock_query)
        
        # Apply any additional kwargs
        for key, value in kwargs.items():
            setattr(expert, key, value)
        
        return expert
    
    @staticmethod
    def create_mock_mcp_server(server_name: str = "test-server", **kwargs) -> Mock:
        """Create a mock MCP server."""
        server = AsyncMock()
        
        # Basic server info
        server.get_server_info = AsyncMock(return_value={
            "name": server_name,
            "version": kwargs.get("version", "1.0.0"),
            "description": kwargs.get("description", f"Test {server_name} server")
        })
        
        # Tools
        tools = kwargs.get("tools", [
            MockFactory.create_mcp_tool(name=f"{server_name}_tool1"),
            MockFactory.create_mcp_tool(name=f"{server_name}_tool2")
        ])
        server.get_tools = Mock(return_value=tools)
        
        # Tool execution
        async def mock_call_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
            await asyncio.sleep(0.05)  # Simulate processing
            return {
                "success": True,
                "result": {
                    "output": f"Executed {tool_name} with {arguments}",
                    "timestamp": datetime.now().isoformat()
                }
            }
        
        server.call_tool = AsyncMock(side_effect=mock_call_tool)
        
        # Apply additional kwargs
        for key, value in kwargs.items():
            if key not in ["tools", "version", "description"]:
                setattr(server, key, value)
        
        return server
    
    @staticmethod
    def create_mock_ai_client(provider: str = "openai", **kwargs) -> Mock:
        """Create a mock AI provider client."""
        client = AsyncMock()
        
        if provider == "openai":
            # Mock OpenAI client
            completion_mock = MagicMock()
            completion_mock.choices = [
                MagicMock(message=MagicMock(content="Test OpenAI response"))
            ]
            client.chat.completions.create = AsyncMock(return_value=completion_mock)
            
        elif provider == "anthropic":
            # Mock Anthropic client
            message_mock = AsyncMock()
            message_mock.content = [MagicMock(text="Test Claude response")]
            client.messages.create = AsyncMock(return_value=message_mock)
            
        elif provider == "google":
            # Mock Google Gemini client
            response_mock = MagicMock()
            response_mock.text = "Test Gemini response"
            client.generate_content_async = AsyncMock(return_value=response_mock)
        
        # Apply additional configuration
        for key, value in kwargs.items():
            setattr(client, key, value)
        
        return client
    
    @staticmethod
    def create_mock_database(**kwargs) -> Mock:
        """Create a mock database connection."""
        db = Mock()
        
        # Storage
        db._storage = {}
        
        # Mock methods
        async def mock_save(key: str, value: Any) -> str:
            db._storage[key] = value
            return key
        
        async def mock_get(key: str) -> Optional[Any]:
            return db._storage.get(key)
        
        async def mock_delete(key: str) -> bool:
            if key in db._storage:
                del db._storage[key]
                return True
            return False
        
        db.save = AsyncMock(side_effect=mock_save)
        db.get = AsyncMock(side_effect=mock_get)
        db.delete = AsyncMock(side_effect=mock_delete)
        db.list_keys = Mock(return_value=list(db._storage.keys()))
        
        return db
    
    @staticmethod
    def create_mock_http_client(**kwargs) -> Mock:
        """Create a mock HTTP client."""
        client = Mock()
        
        # Default responses
        default_responses = {
            "/health": {"status": "healthy"},
            "/api/v1/status": {"status": "ok", "version": "1.0.0"}
        }
        
        responses = kwargs.get("responses", default_responses)
        
        async def mock_get(url: str, **params) -> Mock:
            response = Mock()
            response.status_code = 200
            response.json = Mock(return_value=responses.get(url, {"error": "Not found"}))
            response.text = Mock(return_value=str(responses.get(url, "Not found")))
            return response
        
        async def mock_post(url: str, json: Dict[str, Any] = None, **params) -> Mock:
            response = Mock()
            response.status_code = 201
            response.json = Mock(return_value={"id": str(uuid.uuid4()), "data": json})
            return response
        
        client.get = AsyncMock(side_effect=mock_get)
        client.post = AsyncMock(side_effect=mock_post)
        client.put = AsyncMock(side_effect=mock_post)
        client.delete = AsyncMock(return_value=Mock(status_code=204))
        
        return client
    
    @staticmethod
    def create_mock_file_system(base_path: str = "/tmp/test", **kwargs) -> Mock:
        """Create a mock file system."""
        fs = Mock()
        
        # Virtual file system
        fs._files = kwargs.get("files", {})
        fs._dirs = kwargs.get("dirs", {base_path})
        
        def mock_exists(path: str) -> bool:
            return path in fs._files or path in fs._dirs
        
        def mock_read(path: str) -> str:
            if path in fs._files:
                return fs._files[path]
            raise FileNotFoundError(f"File not found: {path}")
        
        def mock_write(path: str, content: str) -> None:
            fs._files[path] = content
            # Add parent directories
            parts = path.split("/")
            for i in range(1, len(parts)):
                fs._dirs.add("/".join(parts[:i]))
        
        def mock_mkdir(path: str) -> None:
            fs._dirs.add(path)
        
        fs.exists = Mock(side_effect=mock_exists)
        fs.read = Mock(side_effect=mock_read)
        fs.write = Mock(side_effect=mock_write)
        fs.mkdir = Mock(side_effect=mock_mkdir)
        fs.list_dir = Mock(return_value=list(fs._files.keys()))
        
        return fs
    
    @staticmethod
    def create_mock_metrics_collector(**kwargs) -> Mock:
        """Create a mock metrics collector."""
        collector = Mock()
        
        # Metrics storage
        collector._metrics = {}
        collector._counters = {}
        collector._timers = {}
        
        def record_metric(name: str, value: float, tags: Dict[str, str] = None) -> None:
            key = (name, tuple(sorted(tags.items())) if tags else ())
            if key not in collector._metrics:
                collector._metrics[key] = []
            collector._metrics[key].append({
                "value": value,
                "timestamp": datetime.now(),
                "tags": tags or {}
            })
        
        def increment_counter(name: str, value: int = 1, tags: Dict[str, str] = None) -> None:
            key = (name, tuple(sorted(tags.items())) if tags else ())
            if key not in collector._counters:
                collector._counters[key] = 0
            collector._counters[key] += value
        
        collector.record_metric = Mock(side_effect=record_metric)
        collector.increment_counter = Mock(side_effect=increment_counter)
        collector.get_metrics = Mock(return_value=collector._metrics)
        collector.get_counters = Mock(return_value=collector._counters)
        
        return collector


# Convenience functions for common mock scenarios

def create_failing_mock(exception: Exception = None) -> Mock:
    """Create a mock that always fails."""
    if exception is None:
        exception = Exception("Mock failure")
    
    mock = Mock()
    mock.side_effect = exception
    mock.call = Mock(side_effect=exception)
    return mock


def create_slow_mock(delay: float = 1.0, return_value: Any = None) -> AsyncMock:
    """Create a mock that simulates slow operations."""
    async def slow_operation(*args, **kwargs):
        await asyncio.sleep(delay)
        return return_value or {"status": "completed", "duration": delay}
    
    return AsyncMock(side_effect=slow_operation)


def create_flaky_mock(success_rate: float = 0.7, success_value: Any = None, 
                     failure_exception: Exception = None) -> AsyncMock:
    """Create a mock that succeeds/fails randomly."""
    if failure_exception is None:
        failure_exception = Exception("Flaky failure")
    
    async def flaky_operation(*args, **kwargs):
        if random.random() < success_rate:
            return success_value or {"status": "success"}
        raise failure_exception
    
    return AsyncMock(side_effect=flaky_operation)


def create_progressive_mock(responses: List[Any]) -> Mock:
    """Create a mock that returns different values on successive calls."""
    return Mock(side_effect=responses)


# Import asyncio for async mock implementations
import asyncio