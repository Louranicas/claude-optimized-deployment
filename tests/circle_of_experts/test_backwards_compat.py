"""
Backwards compatibility tests for Circle of Experts.

Ensures that the Rust-accelerated implementation maintains full compatibility
with the existing Python API and doesn't break any existing functionality.
"""

import pytest
import asyncio
from typing import List, Dict, Any, Optional
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import json
import os
from pathlib import Path

from src.circle_of_experts import (
    ExpertManager,
    QueryHandler,
    ResponseCollector,
    ExpertQuery,
    ExpertResponse,
    ConsensusResponse,
    QueryPriority,
    QueryType,
    ExpertType,
    ResponseStatus
)
from src.circle_of_experts.drive import DriveManager
from src.circle_of_experts.experts import create_expert
from src.circle_of_experts.utils import RetryPolicy, with_retry

# Try to import enhanced manager with Rust support
try:
    from src.circle_of_experts.core.enhanced_expert_manager import EnhancedExpertManager
    ENHANCED_AVAILABLE = True
except ImportError:
    ENHANCED_AVAILABLE = False
    EnhancedExpertManager = None


class TestAPICompatibility:
    """Test that all public APIs remain compatible."""
    
    @pytest.fixture
    def mock_drive_manager(self):
        """Create a mock drive manager."""
        manager = Mock(spec=DriveManager)
        manager.ensure_folders = Mock()
        manager.upload_query = AsyncMock(return_value="query_123")
        manager.get_responses = AsyncMock(return_value=[])
        manager.list_queries = AsyncMock(return_value=[])
        manager.upload_consensus = AsyncMock(return_value="consensus_123")
        return manager
    
    @pytest.fixture
    def standard_manager(self, mock_drive_manager):
        """Create a standard expert manager."""
        with patch('src.circle_of_experts.core.expert_manager.DriveManager', return_value=mock_drive_manager):
            return ExpertManager()
    
    @pytest.fixture
    def enhanced_manager(self, mock_drive_manager):
        """Create an enhanced expert manager."""
        if not ENHANCED_AVAILABLE:
            pytest.skip("Enhanced manager not available")
        
        with patch('src.circle_of_experts.core.expert_manager.DriveManager', return_value=mock_drive_manager):
            return EnhancedExpertManager(use_rust_acceleration=True)
    
    def test_manager_initialization(self, standard_manager, enhanced_manager):
        """Test that both managers initialize with same interface."""
        # Check same attributes exist
        assert hasattr(standard_manager, 'submit_query')
        assert hasattr(enhanced_manager, 'submit_query')
        
        assert hasattr(standard_manager, 'get_query_status')
        assert hasattr(enhanced_manager, 'get_query_status')
        
        assert hasattr(standard_manager, 'get_expert_health')
        assert hasattr(enhanced_manager, 'get_expert_health')
    
    @pytest.mark.asyncio
    async def test_submit_query_interface(self, standard_manager, enhanced_manager):
        """Test submit_query maintains same interface."""
        query = ExpertQuery(
            title="Test Query",
            content="Test content for backwards compatibility",
            requester="test_user",
            query_type=QueryType.TECHNICAL,
            priority=QueryPriority.MEDIUM
        )
        
        # Mock expert responses
        mock_responses = [
            ExpertResponse(
                query_id=query.id,
                expert_type=ExpertType.TECHNICAL,
                confidence=0.9,
                response="Test response"
            )
        ]
        
        # Test standard manager
        with patch.object(standard_manager, '_collect_expert_responses', return_value=mock_responses):
            standard_result = await standard_manager.submit_query(query)
        
        # Test enhanced manager
        with patch.object(enhanced_manager, '_collect_expert_responses', return_value=mock_responses):
            enhanced_result = await enhanced_manager.submit_query(query)
        
        # Results should have same structure
        assert type(standard_result) == type(enhanced_result)
        assert hasattr(standard_result, 'query_id')
        assert hasattr(enhanced_result, 'query_id')
        assert standard_result.query_id == enhanced_result.query_id
    
    @pytest.mark.asyncio
    async def test_query_parameters_compatibility(self, enhanced_manager):
        """Test all query parameters work with enhanced manager."""
        test_cases = [
            # Different query types
            ExpertQuery(
                title="Technical Query",
                content="Technical question",
                requester="user1",
                query_type=QueryType.TECHNICAL
            ),
            ExpertQuery(
                title="Research Query",
                content="Research question",
                requester="user2",
                query_type=QueryType.RESEARCH
            ),
            # Different priorities
            ExpertQuery(
                title="High Priority",
                content="Urgent question",
                requester="user3",
                priority=QueryPriority.HIGH
            ),
            ExpertQuery(
                title="Low Priority",
                content="Non-urgent question",
                requester="user4",
                priority=QueryPriority.LOW
            ),
            # With metadata
            ExpertQuery(
                title="Query with Metadata",
                content="Question with extra data",
                requester="user5",
                metadata={"project": "test", "version": "1.0"}
            )
        ]
        
        for query in test_cases:
            with patch.object(enhanced_manager, '_collect_expert_responses', return_value=[]):
                result = await enhanced_manager.submit_query(query)
                assert result is not None
    
    def test_response_structure_compatibility(self):
        """Test that response structures remain compatible."""
        # Create responses using standard format
        response1 = ExpertResponse(
            query_id="test_123",
            expert_type=ExpertType.TECHNICAL,
            confidence=0.9,
            response="Technical response",
            recommendations=["Rec 1", "Rec 2"],
            limitations=["Lim 1"]
        )
        
        response2 = ExpertResponse(
            query_id="test_123",
            expert_type=ExpertType.INFRASTRUCTURE,
            confidence=0.85,
            response="Infrastructure response",
            reasoning="Because of X and Y",
            confidence_factors={"experience": 0.9, "relevance": 0.8}
        )
        
        # Verify all fields accessible
        assert response1.query_id == "test_123"
        assert response1.expert_type == ExpertType.TECHNICAL
        assert response1.confidence == 0.9
        assert len(response1.recommendations) == 2
        
        assert response2.reasoning == "Because of X and Y"
        assert response2.confidence_factors["experience"] == 0.9
    
    @pytest.mark.asyncio
    async def test_expert_health_compatibility(self, standard_manager, enhanced_manager):
        """Test expert health check compatibility."""
        # Mock expert availability
        with patch('src.circle_of_experts.experts.expert_factory.create_expert') as mock_create:
            mock_expert = AsyncMock()
            mock_expert.health_check = AsyncMock(return_value=True)
            mock_create.return_value = mock_expert
            
            # Test standard manager
            standard_health = await standard_manager.get_expert_health()
            
            # Test enhanced manager
            enhanced_health = await enhanced_manager.get_expert_health()
            
            # Should return same structure
            assert isinstance(standard_health, dict)
            assert isinstance(enhanced_health, dict)
            
            # Should have same keys
            for expert_type in ExpertType:
                assert expert_type.value in standard_health
                assert expert_type.value in enhanced_health


class TestBehaviorCompatibility:
    """Test that behavior remains consistent."""
    
    @pytest.fixture
    def mock_experts(self):
        """Create mock experts with predictable behavior."""
        experts = {}
        
        for expert_type in ExpertType:
            expert = AsyncMock()
            expert.consult = AsyncMock(return_value={
                "response": f"Response from {expert_type.value}",
                "confidence": 0.8,
                "expert_type": expert_type.value,
                "recommendations": ["Recommendation 1", "Recommendation 2"],
                "limitations": ["Limitation 1"]
            })
            expert.health_check = AsyncMock(return_value=True)
            experts[expert_type] = expert
        
        return experts
    
    @pytest.mark.asyncio
    async def test_consensus_building_compatibility(self):
        """Test that consensus building produces compatible results."""
        # Create test responses
        responses = [
            ExpertResponse(
                query_id="test",
                expert_type=ExpertType.TECHNICAL,
                confidence=0.9,
                response="Use caching",
                recommendations=["Implement Redis", "Use CDN"],
                limitations=["Complexity"]
            ),
            ExpertResponse(
                query_id="test",
                expert_type=ExpertType.INFRASTRUCTURE,
                confidence=0.85,
                response="Scale horizontally",
                recommendations=["Add load balancer", "Use CDN"],
                limitations=["Cost"]
            ),
            ExpertResponse(
                query_id="test",
                expert_type=ExpertType.RESEARCH,
                confidence=0.8,
                response="Follow best practices",
                recommendations=["Monitor performance", "Use CDN"],
                limitations=["Time"]
            )
        ]
        
        # Test with standard manager
        standard_collector = ResponseCollector()
        standard_consensus = standard_collector.build_consensus(responses)
        
        # If enhanced collector available, test it too
        try:
            from src.circle_of_experts.core.enhanced_response_collector import EnhancedResponseCollector
            enhanced_collector = EnhancedResponseCollector(use_rust_acceleration=True)
            enhanced_consensus = enhanced_collector.build_consensus(responses)
            
            # Consensus should be similar
            assert standard_consensus.average_confidence == enhanced_consensus.average_confidence
            assert standard_consensus.participating_experts == enhanced_consensus.participating_experts
            
            # Common recommendations should overlap significantly
            standard_recs = set(r.lower() for r in standard_consensus.common_recommendations)
            enhanced_recs = set(r.lower() for r in enhanced_consensus.common_recommendations)
            overlap = len(standard_recs & enhanced_recs) / len(standard_recs) if standard_recs else 0
            assert overlap > 0.5  # At least 50% overlap
            
        except ImportError:
            # Enhanced collector not available, skip comparison
            pass
    
    @pytest.mark.asyncio
    async def test_error_handling_compatibility(self):
        """Test that error handling remains consistent."""
        # Test with invalid query
        invalid_query = ExpertQuery(
            title="",  # Empty title
            content="x" * 10001,  # Too long
            requester="test"
        )
        
        # Both managers should handle this gracefully
        standard_manager = ExpertManager()
        
        with pytest.raises(ValueError):
            await standard_manager.submit_query(invalid_query)
        
        if ENHANCED_AVAILABLE:
            enhanced_manager = EnhancedExpertManager()
            with pytest.raises(ValueError):
                await enhanced_manager.submit_query(invalid_query)
    
    @pytest.mark.asyncio
    async def test_retry_behavior_compatibility(self):
        """Test that retry behavior remains consistent."""
        retry_policy = RetryPolicy(max_attempts=3, initial_delay=0.1)
        
        call_count = 0
        
        @with_retry(retry_policy)
        async def flaky_operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Temporary failure")
            return "Success"
        
        result = await flaky_operation()
        assert result == "Success"
        assert call_count == 3


class TestDataCompatibility:
    """Test data format compatibility."""
    
    def test_query_serialization_compatibility(self):
        """Test that queries serialize the same way."""
        query = ExpertQuery(
            title="Test Query",
            content="Test content",
            requester="user",
            query_type=QueryType.TECHNICAL,
            priority=QueryPriority.HIGH,
            metadata={"key": "value"}
        )
        
        # Standard serialization
        standard_dict = query.to_dict()
        
        # Should contain all expected fields
        assert "id" in standard_dict
        assert "title" in standard_dict
        assert "content" in standard_dict
        assert "requester" in standard_dict
        assert "query_type" in standard_dict
        assert "priority" in standard_dict
        assert "metadata" in standard_dict
        assert "created_at" in standard_dict
        
        # Should deserialize correctly
        deserialized = ExpertQuery.from_dict(standard_dict)
        assert deserialized.id == query.id
        assert deserialized.title == query.title
        assert deserialized.content == query.content
    
    def test_response_serialization_compatibility(self):
        """Test that responses serialize the same way."""
        response = ExpertResponse(
            query_id="test_123",
            expert_type=ExpertType.TECHNICAL,
            confidence=0.9,
            response="Test response",
            recommendations=["Rec 1", "Rec 2"],
            limitations=["Lim 1"],
            reasoning="Because X",
            confidence_factors={"factor1": 0.8}
        )
        
        # Serialize
        response_dict = response.to_dict()
        
        # Check all fields present
        assert response_dict["query_id"] == "test_123"
        assert response_dict["expert_type"] == "technical"
        assert response_dict["confidence"] == 0.9
        assert len(response_dict["recommendations"]) == 2
        
        # Deserialize
        deserialized = ExpertResponse.from_dict(response_dict)
        assert deserialized.query_id == response.query_id
        assert deserialized.expert_type == response.expert_type
    
    def test_consensus_serialization_compatibility(self):
        """Test consensus response serialization."""
        consensus = ConsensusResponse(
            query_id="test_123",
            average_confidence=0.85,
            participating_experts=[ExpertType.TECHNICAL, ExpertType.RESEARCH],
            common_recommendations=["Use caching", "Monitor performance"],
            unique_limitations=["Cost", "Complexity"],
            consensus_level="high"
        )
        
        # Serialize
        consensus_dict = consensus.to_dict()
        
        # Verify structure
        assert consensus_dict["query_id"] == "test_123"
        assert consensus_dict["average_confidence"] == 0.85
        assert len(consensus_dict["participating_experts"]) == 2
        assert len(consensus_dict["common_recommendations"]) == 2
        
        # Should include timestamps
        assert "created_at" in consensus_dict


class TestConfigurationCompatibility:
    """Test configuration compatibility."""
    
    def test_environment_variables(self):
        """Test that environment variables work the same."""
        env_vars = {
            "GOOGLE_CREDENTIALS_PATH": "/path/to/creds.json",
            "QUERIES_FOLDER_ID": "folder123",
            "RESPONSES_FOLDER_ID": "folder456",
            "LOG_LEVEL": "DEBUG"
        }
        
        with patch.dict(os.environ, env_vars):
            # Standard manager
            standard_manager = ExpertManager()
            
            # Enhanced manager if available
            if ENHANCED_AVAILABLE:
                enhanced_manager = EnhancedExpertManager()
                
                # Both should respect environment variables
                assert standard_manager.log_level == enhanced_manager.log_level
    
    def test_initialization_parameters(self):
        """Test that initialization parameters are compatible."""
        params = {
            "credentials_path": "/custom/path.json",
            "queries_folder_id": "custom_folder",
            "responses_folder_id": "custom_responses",
            "log_level": "WARNING",
            "log_file": Path("custom.log")
        }
        
        # Should work with standard manager
        with patch('src.circle_of_experts.core.expert_manager.DriveManager'):
            standard_manager = ExpertManager(**params)
            assert standard_manager.log_level == "WARNING"
        
        # Should work with enhanced manager
        if ENHANCED_AVAILABLE:
            with patch('src.circle_of_experts.core.expert_manager.DriveManager'):
                enhanced_manager = EnhancedExpertManager(**params)
                assert enhanced_manager.log_level == "WARNING"


class TestMigrationPath:
    """Test migration from standard to enhanced implementation."""
    
    @pytest.mark.asyncio
    async def test_drop_in_replacement(self):
        """Test that enhanced manager is a drop-in replacement."""
        if not ENHANCED_AVAILABLE:
            pytest.skip("Enhanced manager not available")
        
        # Original code pattern
        async def original_code():
            manager = ExpertManager()
            query = ExpertQuery(
                title="Test",
                content="Test query",
                requester="user"
            )
            
            with patch.object(manager, '_collect_expert_responses', return_value=[]):
                result = await manager.submit_query(query)
            return result
        
        # Enhanced code pattern (should work identically)
        async def enhanced_code():
            manager = EnhancedExpertManager()  # Only change
            query = ExpertQuery(
                title="Test",
                content="Test query",
                requester="user"
            )
            
            with patch.object(manager, '_collect_expert_responses', return_value=[]):
                result = await manager.submit_query(query)
            return result
        
        # Both should work
        original_result = await original_code()
        enhanced_result = await enhanced_code()
        
        assert original_result is not None
        assert enhanced_result is not None
    
    def test_feature_flags(self):
        """Test feature flags for gradual migration."""
        if not ENHANCED_AVAILABLE:
            pytest.skip("Enhanced manager not available")
        
        # Can disable Rust acceleration
        manager_no_rust = EnhancedExpertManager(use_rust_acceleration=False)
        assert hasattr(manager_no_rust, 'use_rust_acceleration')
        assert manager_no_rust.use_rust_acceleration is False
        
        # Can enable Rust acceleration
        manager_with_rust = EnhancedExpertManager(use_rust_acceleration=True)
        assert manager_with_rust.use_rust_acceleration is True
    
    def test_version_compatibility(self):
        """Test version compatibility checks."""
        from src.circle_of_experts import __version__
        
        # Version should be defined
        assert __version__ is not None
        
        # Should follow semantic versioning
        parts = __version__.split('.')
        assert len(parts) >= 2  # At least major.minor


class TestExistingTestCompatibility:
    """Ensure all existing tests still pass with enhanced implementation."""
    
    @pytest.mark.asyncio
    async def test_existing_unit_tests_pass(self):
        """Run a subset of existing unit tests with enhanced manager."""
        if not ENHANCED_AVAILABLE:
            pytest.skip("Enhanced manager not available")
        
        # Import and run existing test
        from tests.circle_of_experts.test_circle_of_experts import TestModels
        
        # Existing model tests should still pass
        test_models = TestModels()
        test_models.test_expert_query_creation()
        test_models.test_expert_query_validation()
    
    def test_existing_integration_patterns(self):
        """Test that existing integration patterns still work."""
        # Common integration pattern: creating custom expert
        expert_config = {
            "name": "custom_expert",
            "type": ExpertType.TECHNICAL,
            "api_endpoint": "https://api.example.com",
            "api_key": "test_key"
        }
        
        # Should be able to create expert
        with patch('src.circle_of_experts.experts.expert_factory.create_expert') as mock_create:
            mock_expert = Mock()
            mock_create.return_value = mock_expert
            
            expert = create_expert(expert_config["type"], expert_config)
            assert expert is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])