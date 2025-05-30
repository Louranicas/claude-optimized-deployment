"""
Comprehensive tests for Circle of Experts feature.

Tests all components including models, Drive integration, and core functionality.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path
import json

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
from src.circle_of_experts.drive import DriveManager
from src.circle_of_experts.utils import RetryPolicy, with_retry


class TestModels:
    """Test the data models."""
    
    def test_expert_query_creation(self):
        """Test creating an expert query."""
        query = ExpertQuery(
            title="Test Query",
            content="This is a test query content",
            requester="test_user",
            query_type=QueryType.TECHNICAL,
            priority=QueryPriority.HIGH
        )
        
        assert query.title == "Test Query"
        assert query.content == "This is a test query content"
        assert query.requester == "test_user"
        assert query.query_type == QueryType.TECHNICAL
        assert query.priority == QueryPriority.HIGH
        assert query.id is not None
    
    def test_expert_query_validation(self):
        """Test query validation."""
        # Test deadline validation
        with pytest.raises(ValueError, match="Deadline must be after creation time"):
            ExpertQuery(
                title="Test",
                content="Test content",
                requester="user",
                deadline=datetime.utcnow() - timedelta(hours=1)
            )
    
    def test_expert_query_to_markdown(self):
        """Test converting query to markdown."""
        query = ExpertQuery(
            title="Test Query",
            content="This is the query content",
            requester="test_user",
            tags=["python", "optimization"]
        )
        
        markdown = query.to_markdown()
        
        assert "# Test Query" in markdown
        assert "This is the query content" in markdown
        assert "test_user" in markdown
        assert "python, optimization" in markdown
    
    def test_expert_response_creation(self):
        """Test creating an expert response."""
        response = ExpertResponse(
            query_id="test_query_123",
            expert_type=ExpertType.GPT4,
            content="This is the response",
            confidence=0.85
        )
        
        assert response.query_id == "test_query_123"
        assert response.expert_type == ExpertType.GPT4
        assert response.content == "This is the response"
        assert response.confidence == 0.85
        assert response.status == ResponseStatus.PENDING
    
    def test_expert_response_completion(self):
        """Test marking response as completed."""
        response = ExpertResponse(
            query_id="test_query_123",
            expert_type=ExpertType.CLAUDE
        )
        
        response.mark_completed()
        
        assert response.status == ResponseStatus.COMPLETED
        assert response.completed_at is not None
        assert response.processing_time is not None


class TestDriveManager:
    """Test Google Drive integration."""
    
    @pytest.fixture
    def mock_drive_service(self):
        """Create a mock Drive service."""
        service = Mock()
        service.files.return_value = Mock()
        return service
    
    @pytest.fixture
    def drive_manager(self, mock_drive_service, monkeypatch):
        """Create DriveManager with mocked service."""
        manager = DriveManager(credentials_path="fake_path.json")
        monkeypatch.setattr(manager, '_service', mock_drive_service)
        return manager
    
    @pytest.mark.asyncio
    async def test_ensure_responses_folder(self, drive_manager, mock_drive_service):
        """Test ensuring responses folder exists."""
        # Mock folder already exists
        mock_drive_service.files().list().execute.return_value = {
            'files': [{'id': 'folder_123', 'name': 'circle_of_experts_responses'}]
        }
        
        folder_id = await drive_manager.ensure_responses_folder()
        
        assert folder_id == 'folder_123'
        assert drive_manager._responses_folder_id == 'folder_123'
    
    @pytest.mark.asyncio
    async def test_upload_query(self, drive_manager, mock_drive_service, tmp_path):
        """Test uploading a query."""
        query = ExpertQuery(
            title="Test Query",
            content="Test content",
            requester="test_user"
        )
        
        # Mock file creation
        mock_drive_service.files().create().execute.return_value = {'id': 'file_123'}
        
        # Patch temp file creation
        with patch('pathlib.Path.write_text'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.unlink'):
            
            file_id = await drive_manager.upload_query(query)
        
        assert file_id == 'file_123'
    
    @pytest.mark.asyncio
    async def test_list_queries(self, drive_manager, mock_drive_service):
        """Test listing queries."""
        mock_drive_service.files().list().execute.return_value = {
            'files': [
                {'id': 'file_1', 'name': 'query_123.md'},
                {'id': 'file_2', 'name': 'query_456.md'}
            ]
        }
        
        files = await drive_manager.list_queries()
        
        assert len(files) == 2
        assert files[0]['id'] == 'file_1'
        assert files[1]['id'] == 'file_2'


class TestQueryHandler:
    """Test query handling functionality."""
    
    @pytest.fixture
    def mock_drive_manager(self):
        """Create mock drive manager."""
        manager = AsyncMock(spec=DriveManager)
        manager.upload_query = AsyncMock(return_value="file_123")
        manager.list_queries = AsyncMock(return_value=[])
        return manager
    
    @pytest.fixture
    def query_handler(self, mock_drive_manager):
        """Create query handler with mocked drive."""
        return QueryHandler(mock_drive_manager)
    
    @pytest.mark.asyncio
    async def test_create_query(self, query_handler):
        """Test creating a query."""
        query = await query_handler.create_query(
            title="Test Query",
            content="This is a test query",
            requester="test_user",
            query_type=QueryType.TECHNICAL,
            priority=QueryPriority.HIGH,
            tags=["test", "python"]
        )
        
        assert query.title == "Test Query"
        assert query.content == "This is a test query"
        assert query.requester == "test_user"
        assert query.query_type == QueryType.TECHNICAL
        assert query.priority == QueryPriority.HIGH
        assert "test" in query.tags
        assert "python" in query.tags
    
    @pytest.mark.asyncio
    async def test_submit_query(self, query_handler, mock_drive_manager):
        """Test submitting a query."""
        query = await query_handler.create_query(
            title="Test",
            content="Test content",
            requester="user"
        )
        
        file_id = await query_handler.submit_query(query)
        
        assert file_id == "file_123"
        mock_drive_manager.upload_query.assert_called_once_with(query)
    
    @pytest.mark.asyncio
    async def test_submit_batch(self, query_handler, mock_drive_manager):
        """Test batch query submission."""
        queries = [
            await query_handler.create_query(
                title=f"Query {i}",
                content=f"Content {i}",
                requester="user"
            )
            for i in range(3)
        ]
        
        results = await query_handler.submit_batch(queries)
        
        assert len(results) == 3
        assert mock_drive_manager.upload_query.call_count == 3
    
    @pytest.mark.asyncio
    async def test_create_code_review_query(self, query_handler):
        """Test creating a code review query."""
        code = """
def hello_world():
    print("Hello, World!")
"""
        
        query = await query_handler.create_code_review_query(
            code=code,
            language="python",
            requester="developer",
            focus_areas=["style", "performance"]
        )
        
        assert query.query_type == QueryType.REVIEW
        assert "python" in query.tags
        assert "```python" in query.content
        assert "style" in query.content
        assert "performance" in query.content


class TestResponseCollector:
    """Test response collection functionality."""
    
    @pytest.fixture
    def mock_drive_manager(self):
        """Create mock drive manager."""
        manager = AsyncMock(spec=DriveManager)
        manager.watch_for_responses = AsyncMock(return_value=[])
        manager.list_responses = AsyncMock(return_value=[])
        manager.upload_response = AsyncMock(return_value="consensus_file_123")
        return manager
    
    @pytest.fixture
    def response_collector(self, mock_drive_manager):
        """Create response collector with mocked drive."""
        return ResponseCollector(mock_drive_manager)
    
    @pytest.mark.asyncio
    async def test_collect_responses(self, response_collector, mock_drive_manager):
        """Test collecting responses."""
        # Mock responses
        mock_responses = [
            ExpertResponse(
                query_id="query_123",
                expert_type=ExpertType.GPT4,
                content="Response 1",
                confidence=0.8
            ),
            ExpertResponse(
                query_id="query_123",
                expert_type=ExpertType.CLAUDE,
                content="Response 2",
                confidence=0.9
            )
        ]
        
        mock_drive_manager.watch_for_responses.return_value = mock_responses
        
        responses = await response_collector.collect_responses(
            query_id="query_123",
            timeout=10.0,
            min_responses=2
        )
        
        assert len(responses) == 2
        assert responses[0].expert_type == ExpertType.GPT4
        assert responses[1].expert_type == ExpertType.CLAUDE
    
    @pytest.mark.asyncio
    async def test_aggregate_responses(self, response_collector):
        """Test response aggregation."""
        # Add test responses
        responses = [
            ExpertResponse(
                query_id="query_123",
                expert_type=ExpertType.GPT4,
                content="Response 1",
                confidence=0.8,
                recommendations=["Use async", "Add tests"],
                processing_time=2.5
            ),
            ExpertResponse(
                query_id="query_123",
                expert_type=ExpertType.CLAUDE,
                content="Response 2",
                confidence=0.9,
                recommendations=["Use async", "Add documentation"],
                processing_time=3.0
            )
        ]
        
        response_collector._responses["query_123"] = responses
        
        aggregation = await response_collector.aggregate_responses("query_123")
        
        assert aggregation["response_count"] == 2
        assert aggregation["average_confidence"] == 0.85
        assert "Use async" in [r.lower() for r in aggregation["common_recommendations"]]
        assert len(aggregation["all_recommendations"]) >= 3


class TestExpertManager:
    """Test the main ExpertManager orchestrator."""
    
    @pytest.fixture
    def mock_components(self):
        """Create mocked components."""
        drive_manager = AsyncMock(spec=DriveManager)
        query_handler = AsyncMock(spec=QueryHandler)
        response_collector = AsyncMock(spec=ResponseCollector)
        
        return drive_manager, query_handler, response_collector
    
    @pytest.fixture
    def expert_manager(self, mock_components, monkeypatch):
        """Create ExpertManager with mocked components."""
        drive_manager, query_handler, response_collector = mock_components
        
        manager = ExpertManager(credentials_path="fake_path.json")
        
        # Replace components with mocks
        monkeypatch.setattr(manager, 'drive_manager', drive_manager)
        monkeypatch.setattr(manager, 'query_handler', query_handler)
        monkeypatch.setattr(manager, 'response_collector', response_collector)
        
        return manager
    
    @pytest.mark.asyncio
    async def test_consult_experts(self, expert_manager, mock_components):
        """Test consulting experts end-to-end."""
        _, query_handler, response_collector = mock_components
        
        # Mock query creation and submission
        mock_query = ExpertQuery(
            title="Test Query",
            content="Test content",
            requester="user"
        )
        query_handler.create_query.return_value = mock_query
        query_handler.submit_query.return_value = "file_123"
        
        # Mock response collection
        mock_responses = [
            ExpertResponse(
                query_id=mock_query.id,
                expert_type=ExpertType.GPT4,
                content="Test response",
                confidence=0.85
            )
        ]
        response_collector.collect_responses.return_value = mock_responses
        response_collector.aggregate_responses.return_value = {
            "response_count": 1,
            "average_confidence": 0.85
        }
        
        # Consult experts
        result = await expert_manager.consult_experts(
            title="Test Query",
            content="Test content",
            requester="user",
            wait_for_responses=True,
            response_timeout=10.0
        )
        
        assert result["status"] == "completed"
        assert "query" in result
        assert "responses" in result
        assert len(result["responses"]) == 1
        assert result["aggregation"]["average_confidence"] == 0.85


class TestRetryMechanism:
    """Test retry utilities."""
    
    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        """Test retry decorator on failing function."""
        call_count = 0
        
        @with_retry(RetryPolicy(max_attempts=3, backoff_factor=0.1))
        async def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Temporary failure")
            return "success"
        
        result = await failing_function()
        
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_retry_exhaustion(self):
        """Test retry exhaustion."""
        @with_retry(RetryPolicy(max_attempts=2, backoff_factor=0.1))
        async def always_failing():
            raise Exception("Always fails")
        
        with pytest.raises(Exception, match="Always fails"):
            await always_failing()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
