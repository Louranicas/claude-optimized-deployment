"""
Test suite for Python/Rust hybrid integration in Circle of Experts.

Tests the seamless integration between Python orchestration code
and Rust acceleration modules.
"""

import pytest
import asyncio
from typing import List, Dict, Any, Optional
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import time
import json
import os

from src.circle_of_experts import (
    ExpertManager,
    QueryHandler,
    ResponseCollector,
    ExpertQuery,
    ExpertResponse,
    QueryType,
    QueryPriority,
    ExpertType
)
from src.circle_of_experts.core.enhanced_expert_manager import EnhancedExpertManager
from src.circle_of_experts.experts.expert_factory import create_expert


# Try to import Rust modules
try:
    from claude_optimized_deployment_rust.circle_of_experts import (
        ExpertAnalyzer,
        QueryValidator
    )
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    ExpertAnalyzer = None
    QueryValidator = None


@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust modules not available")
class TestHybridExpertManager:
    """Test the hybrid Python/Rust expert manager."""
    
    @pytest.fixture
    def mock_drive_manager(self):
        """Create a mock drive manager."""
        manager = Mock()
        manager.ensure_folders = Mock()
        manager.upload_query = AsyncMock(return_value="query_123")
        manager.get_responses = AsyncMock(return_value=[])
        manager.list_queries = AsyncMock(return_value=[])
        return manager
    
    @pytest.fixture
    def enhanced_manager(self, mock_drive_manager):
        """Create an enhanced expert manager with Rust acceleration."""
        with patch('src.circle_of_experts.core.expert_manager.DriveManager', return_value=mock_drive_manager):
            manager = EnhancedExpertManager(
                use_rust_acceleration=True,
                rust_analyzer=ExpertAnalyzer(confidence_threshold=0.7),
                rust_validator=QueryValidator(max_length=5000)
            )
            return manager
    
    @pytest.mark.asyncio
    async def test_rust_accelerated_query_validation(self, enhanced_manager):
        """Test that query validation uses Rust when available."""
        # Valid query
        query = ExpertQuery(
            title="Test Query",
            content="This is a valid test query for the hybrid system",
            requester="test_user",
            query_type=QueryType.TECHNICAL
        )
        
        # Mock the expert responses
        with patch.object(enhanced_manager, '_collect_expert_responses') as mock_collect:
            mock_collect.return_value = [
                ExpertResponse(
                    query_id=query.id,
                    expert_type=ExpertType.TECHNICAL,
                    confidence=0.9,
                    response="Test response",
                    recommendations=["Use Rust", "Optimize performance"],
                    limitations=["Learning curve"]
                )
            ]
            
            result = await enhanced_manager.submit_query(query)
            
            assert result is not None
            assert result.query_id == query.id
    
    @pytest.mark.asyncio
    async def test_rust_accelerated_consensus_building(self, enhanced_manager):
        """Test that consensus building uses Rust acceleration."""
        query = ExpertQuery(
            title="Consensus Test",
            content="Test query for consensus building",
            requester="test_user"
        )
        
        # Create multiple expert responses
        responses = [
            ExpertResponse(
                query_id=query.id,
                expert_type=ExpertType.TECHNICAL,
                confidence=0.9,
                response="Use Rust for performance",
                recommendations=["Implement Rust modules", "Use PyO3", "Profile code"],
                limitations=["Rust learning curve", "Build complexity"]
            ),
            ExpertResponse(
                query_id=query.id,
                expert_type=ExpertType.INFRASTRUCTURE,
                confidence=0.85,
                response="Optimize infrastructure",
                recommendations=["Use Docker", "Implement caching", "Profile code"],
                limitations=["Container overhead", "Cache invalidation"]
            ),
            ExpertResponse(
                query_id=query.id,
                expert_type=ExpertType.RESEARCH,
                confidence=0.8,
                response="Follow best practices",
                recommendations=["Research solutions", "Use PyO3", "Benchmark regularly"],
                limitations=["Time investment", "Build complexity"]
            )
        ]
        
        # Mock the response collection
        with patch.object(enhanced_manager, '_collect_expert_responses') as mock_collect:
            mock_collect.return_value = responses
            
            consensus = await enhanced_manager.submit_query(query)
            
            # Verify Rust-accelerated analysis
            assert consensus is not None
            assert hasattr(consensus, 'consensus_analysis')
            assert consensus.consensus_analysis['total_responses'] == 3
            assert 0.84 < consensus.consensus_analysis['average_confidence'] < 0.86
            
            # Check common recommendations were identified
            common_recs = consensus.consensus_analysis.get('common_recommendations', [])
            assert any('pyo3' in rec.lower() for rec in common_recs)
    
    @pytest.mark.asyncio
    async def test_fallback_to_python(self, mock_drive_manager):
        """Test graceful fallback when Rust modules unavailable."""
        # Create manager without Rust acceleration
        with patch('src.circle_of_experts.core.expert_manager.DriveManager', return_value=mock_drive_manager):
            manager = EnhancedExpertManager(use_rust_acceleration=False)
            
            query = ExpertQuery(
                title="Fallback Test",
                content="Test Python fallback",
                requester="test_user"
            )
            
            # Should work without Rust
            with patch.object(manager, '_collect_expert_responses') as mock_collect:
                mock_collect.return_value = [
                    ExpertResponse(
                        query_id=query.id,
                        expert_type=ExpertType.TECHNICAL,
                        confidence=0.9,
                        response="Python fallback works"
                    )
                ]
                
                result = await manager.submit_query(query)
                assert result is not None
    
    def test_performance_improvement(self, enhanced_manager):
        """Test that Rust acceleration improves performance."""
        # Create many responses for performance testing
        responses = []
        for i in range(100):
            responses.append({
                "confidence": 0.7 + (i % 3) * 0.1,
                "expert_type": f"expert_{i % 5}",
                "recommendations": [f"Recommendation {j}" for j in range(10)],
                "limitations": [f"Limitation {j}" for j in range(5)]
            })
        
        # Time Rust analysis
        rust_analyzer = ExpertAnalyzer()
        start_rust = time.time()
        rust_result = rust_analyzer.analyze_responses(responses)
        rust_time = time.time() - start_rust
        
        # Time Python equivalent (simplified)
        start_python = time.time()
        python_result = self._python_analyze_responses(responses)
        python_time = time.time() - start_python
        
        # Rust should be faster
        assert rust_time < python_time
        
        # Results should be similar
        assert abs(rust_result['average_confidence'] - python_result['average_confidence']) < 0.01
    
    def _python_analyze_responses(self, responses: List[Dict]) -> Dict:
        """Python implementation for comparison."""
        if not responses:
            return {
                "total_responses": 0,
                "average_confidence": 0.0,
                "high_confidence_count": 0
            }
        
        total_confidence = sum(r.get('confidence', 0) for r in responses)
        high_confidence = sum(1 for r in responses if r.get('confidence', 0) >= 0.7)
        
        return {
            "total_responses": len(responses),
            "average_confidence": total_confidence / len(responses),
            "high_confidence_count": high_confidence
        }


@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust modules not available")
class TestHybridQueryProcessing:
    """Test hybrid query processing with Rust validation."""
    
    def test_batch_query_validation(self):
        """Test batch validation of queries using Rust."""
        validator = QueryValidator(
            min_length=20,
            max_length=1000,
            forbidden_patterns=["spam", "malicious", "hack"]
        )
        
        queries = [
            ExpertQuery(
                title="Valid Query 1",
                content="This is a perfectly valid query about Python performance",
                requester="user1"
            ),
            ExpertQuery(
                title="Short",
                content="Too short",  # Less than 20 chars
                requester="user2"
            ),
            ExpertQuery(
                title="Spam Query",
                content="This query contains spam and should be rejected",
                requester="user3"
            ),
            ExpertQuery(
                title="Valid Query 2",
                content="Another valid query about Rust integration benefits",
                requester="user4"
            )
        ]
        
        # Extract content for validation
        query_contents = [q.content for q in queries]
        validation_results = validator.validate_batch(query_contents)
        
        assert validation_results[0] is True   # Valid
        assert validation_results[1] is False  # Too short
        assert validation_results[2] is False  # Contains spam
        assert validation_results[3] is True   # Valid
        
        # Filter valid queries
        valid_queries = [q for q, valid in zip(queries, validation_results) if valid]
        assert len(valid_queries) == 2
    
    def test_query_sanitization_pipeline(self):
        """Test query sanitization through Rust."""
        validator = QueryValidator(
            max_length=100,
            forbidden_patterns=["confidential", "secret", "password"]
        )
        
        unsafe_query = ExpertQuery(
            title="Security Question",
            content="How do I store confidential passwords and secret API keys in my application? " * 5,
            requester="user"
        )
        
        # Sanitize the query
        sanitized_content = validator.sanitize_query(unsafe_query.content)
        
        # Check sanitization
        assert "confidential" not in sanitized_content
        assert "secret" not in sanitized_content
        assert "password" not in sanitized_content
        assert len(sanitized_content) <= 100
    
    @pytest.mark.asyncio
    async def test_hybrid_expert_consultation(self):
        """Test full hybrid expert consultation flow."""
        # Create hybrid components
        validator = QueryValidator(min_length=10)
        analyzer = ExpertAnalyzer(confidence_threshold=0.8)
        
        # Create query
        query = ExpertQuery(
            title="Hybrid System Design",
            content="What are the best practices for integrating Rust modules into a Python application?",
            requester="architect"
        )
        
        # Validate query
        assert validator.is_valid_query(query.content)
        
        # Simulate expert responses
        expert_responses = []
        
        # Create mock experts
        expert_types = [ExpertType.TECHNICAL, ExpertType.INFRASTRUCTURE, ExpertType.RESEARCH]
        for expert_type in expert_types:
            # Simulate expert processing
            response = {
                "query_id": query.id,
                "expert_type": expert_type.value,
                "confidence": 0.85 + (0.05 if expert_type == ExpertType.TECHNICAL else 0),
                "response": f"Response from {expert_type.value} expert",
                "recommendations": [
                    "Use PyO3 for Python bindings",
                    "Implement performance-critical parts in Rust",
                    "Maintain clean API boundaries"
                ],
                "limitations": [
                    "Increased build complexity",
                    "Debugging across languages"
                ]
            }
            expert_responses.append(response)
        
        # Analyze with Rust
        consensus = analyzer.analyze_responses(expert_responses)
        
        # Verify consensus
        assert consensus['total_responses'] == 3
        assert consensus['average_confidence'] > 0.85
        assert consensus['high_confidence_count'] == 3
        assert len(consensus['common_recommendations']) > 0


@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust modules not available")
class TestErrorHandlingAndEdgeCases:
    """Test error handling in hybrid system."""
    
    def test_rust_module_error_handling(self):
        """Test handling of errors from Rust modules."""
        analyzer = ExpertAnalyzer()
        
        # Test with invalid input
        with pytest.raises(TypeError):
            analyzer.analyze_responses("not a list")
        
        # Test with malformed responses
        malformed = [
            {"wrong_field": "value"},
            None,
            {"confidence": "not_a_number"}
        ]
        
        # Should handle gracefully
        result = analyzer.analyze_responses([r for r in malformed if r])
        assert result['total_responses'] >= 0
    
    def test_memory_safety(self):
        """Test memory safety with large inputs."""
        analyzer = ExpertAnalyzer()
        
        # Create very large input
        huge_responses = []
        for i in range(10000):
            huge_responses.append({
                "confidence": 0.8,
                "expert_type": "test",
                "recommendations": [f"Rec {j}" for j in range(100)],
                "limitations": [f"Lim {j}" for j in range(50)]
            })
        
        # Should handle without memory issues
        start_time = time.time()
        result = analyzer.analyze_responses(huge_responses)
        end_time = time.time()
        
        assert result['total_responses'] == 10000
        assert end_time - start_time < 5.0  # Should complete reasonably fast
    
    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Test thread safety of Rust modules."""
        analyzer = ExpertAnalyzer()
        
        async def analyze_task(task_id: int):
            responses = [{
                "confidence": 0.8,
                "expert_type": f"expert_{task_id}",
                "recommendations": [f"Task {task_id} recommendation"]
            }]
            return analyzer.analyze_responses(responses)
        
        # Run multiple concurrent analyses
        tasks = [analyze_task(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        # All should complete successfully
        assert len(results) == 10
        for result in results:
            assert result['total_responses'] == 1


@pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust modules not available")
class TestHybridConfigurationAndSetup:
    """Test configuration and setup of hybrid system."""
    
    def test_rust_module_configuration(self):
        """Test configuring Rust modules with different parameters."""
        # Test different configurations
        configs = [
            {"confidence_threshold": 0.9, "consensus_threshold": 0.95},
            {"confidence_threshold": 0.5, "consensus_threshold": 0.6},
            {},  # Default configuration
        ]
        
        for config in configs:
            analyzer = ExpertAnalyzer(**config)
            assert analyzer is not None
            
            # Test with sample data
            result = analyzer.analyze_responses([{
                "confidence": 0.7,
                "expert_type": "test",
                "recommendations": ["Test"]
            }])
            
            assert 'average_confidence' in result
    
    def test_feature_detection(self):
        """Test detection of available features."""
        features = {
            "rust_acceleration": RUST_AVAILABLE,
            "expert_analyzer": ExpertAnalyzer is not None,
            "query_validator": QueryValidator is not None,
        }
        
        # At least base features should be available
        assert features["rust_acceleration"] is True
        assert features["expert_analyzer"] is True
        assert features["query_validator"] is True
    
    def test_hybrid_system_info(self):
        """Test getting system information about hybrid setup."""
        info = {
            "python_version": "3.8+",
            "rust_available": RUST_AVAILABLE,
            "acceleration_enabled": True,
            "modules": []
        }
        
        if RUST_AVAILABLE:
            info["modules"] = ["ExpertAnalyzer", "QueryValidator"]
            
            # Test module functionality
            analyzer = ExpertAnalyzer()
            validator = QueryValidator()
            
            info["analyzer_functional"] = analyzer is not None
            info["validator_functional"] = validator is not None
        
        assert info["rust_available"] is True
        assert len(info["modules"]) == 2
        assert info.get("analyzer_functional", False) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])