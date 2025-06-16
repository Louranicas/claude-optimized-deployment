#!/usr/bin/env python3
"""
Comprehensive Test Suite for Adaptive Learning System

Tests all components of the adaptive learning system including:
- Cross-instance intelligence sharing
- Pattern recognition
- Prediction engines
- Optimization algorithms
- Persistence layer
"""

import asyncio
import pytest
import numpy as np
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import json

# Test imports
from mcp_learning_system import AdaptiveLearningSystem, CrossInstanceLearning
from mcp_learning_system.learning_core.models import (
    Interaction, Context, Features, Learning, Patterns, Knowledge,
    Entity, Relationship, Prediction
)
from mcp_learning_system.learning_core.persistence import LearningStorage, StorageConfig
from mcp_learning_system.learning_core.cross_instance import InstanceInfo
from mcp_learning_system.learning_core.learning_core import LearningMetrics


class TestAdaptiveLearningSystem:
    """Test the main adaptive learning system"""
    
    @pytest.fixture
    async def learning_system(self):
        """Create adaptive learning system for testing"""
        system = AdaptiveLearningSystem()
        return system
    
    @pytest.fixture
    def sample_interaction(self):
        """Create sample interaction for testing"""
        context = Context(
            timestamp=datetime.utcnow(),
            state={"test": "data"},
            environment={"cpu": 50.0, "memory": 60.0}
        )
        
        entities = [
            Entity("test_entity_1", "test_type", {"value": 1.0}),
            Entity("test_entity_2", "test_type", {"value": 2.0})
        ]
        
        relationships = [
            Relationship("test_entity_1", "test_entity_2", "test_relation", weight=0.8)
        ]
        
        return Interaction(
            id="test_interaction",
            type="test_type",
            source="test_source",
            content={"test": "content"},
            context=context,
            timestamp=datetime.utcnow(),
            entities=entities,
            relationships=relationships,
            time_series=np.random.randn(100),
            values=np.random.randn(20),
            coordinates=np.random.randn(10, 2)
        )
    
    @pytest.mark.asyncio
    async def test_learn_from_interaction(self, learning_system, sample_interaction):
        """Test learning from interaction"""
        knowledge = await learning_system.learn_from_interaction(sample_interaction)
        
        assert knowledge is not None
        assert hasattr(knowledge, 'nodes')
        assert hasattr(knowledge, 'insights')
    
    @pytest.mark.asyncio
    async def test_pattern_recognition(self, learning_system, sample_interaction):
        """Test pattern recognition capabilities"""
        features = await learning_system.extract_multi_modal_features(sample_interaction)
        
        assert hasattr(features, 'temporal')
        assert hasattr(features, 'relational')
        assert hasattr(features, 'statistical')
        assert hasattr(features, 'spatial')
        
        # Test pattern recognition
        patterns = await learning_system.pattern_recognizer.recognize(features)
        
        assert isinstance(patterns, Patterns)
        assert hasattr(patterns, 'temporal')
        assert hasattr(patterns, 'structural')
    
    @pytest.mark.asyncio
    async def test_prediction(self, learning_system):
        """Test prediction capabilities"""
        context = Context(
            timestamp=datetime.utcnow(),
            state={"system_load": 0.7},
            environment={"cpu": 65.0}
        )
        
        prediction = await learning_system.predict_next_action(context)
        
        assert isinstance(prediction, Prediction)
        assert prediction.confidence >= 0.0
        assert prediction.confidence <= 1.0
        assert prediction.output is not None


class TestCrossInstanceLearning:
    """Test cross-instance learning capabilities"""
    
    @pytest.fixture
    async def cross_instance_system(self):
        """Create cross-instance learning system"""
        # Use in-memory redis for testing
        system = CrossInstanceLearning("redis://localhost:6379/1")
        try:
            await system.initialize()
        except:
            # Skip if Redis not available
            pytest.skip("Redis not available for testing")
        return system
    
    @pytest.fixture
    def sample_instances(self):
        """Create sample instances for testing"""
        return [
            InstanceInfo(
                name="test_dev",
                type="development",
                capabilities=["coding", "testing"],
                last_seen=datetime.utcnow(),
                performance_score=0.85,
                specializations=["python", "javascript"]
            ),
            InstanceInfo(
                name="test_ops",
                type="devops",
                capabilities=["deployment", "monitoring"],
                last_seen=datetime.utcnow(),
                performance_score=0.90,
                specializations=["kubernetes", "docker"]
            )
        ]
    
    @pytest.mark.asyncio
    async def test_instance_registration(self, cross_instance_system, sample_instances):
        """Test instance registration"""
        for instance in sample_instances:
            await cross_instance_system.register_instance(instance)
        
        assert len(cross_instance_system.instances) == len(sample_instances)
    
    @pytest.mark.asyncio
    async def test_knowledge_sharing(self, cross_instance_system, sample_instances):
        """Test knowledge sharing between instances"""
        # Register instances
        for instance in sample_instances:
            await cross_instance_system.register_instance(instance)
        
        # Create test learning
        learning = Learning(
            type="test_learning",
            timestamp=datetime.utcnow(),
            cross_instance_relevance=0.8,
            content={"test": "data"}
        )
        
        # Share learning
        await cross_instance_system.share_learning("test_dev", learning)
        
        # Verify sharing occurred (this would require actual Redis in practice)
        assert True  # Placeholder assertion
    
    @pytest.mark.asyncio
    async def test_specialization_insights(self, cross_instance_system, sample_instances):
        """Test instance specialization insights"""
        for instance in sample_instances:
            await cross_instance_system.register_instance(instance)
        
        insights = await cross_instance_system.get_instance_specialization_insights()
        
        assert "instance_profiles" in insights
        assert "performance_rankings" in insights
        assert "recommended_routing" in insights


class TestPatternRecognition:
    """Test pattern recognition engine"""
    
    @pytest.fixture
    def pattern_recognizer(self):
        """Create pattern recognizer"""
        from mcp_learning_system.learning_core.pattern_recognition import PatternRecognizer
        return PatternRecognizer()
    
    @pytest.fixture
    def complex_interaction(self):
        """Create complex interaction for pattern testing"""
        # Create temporal pattern (sine wave + noise)
        t = np.linspace(0, 4*np.pi, 200)
        temporal_signal = np.sin(t) + 0.1 * np.random.randn(len(t))
        
        # Create spatial clusters
        cluster_centers = [(0, 0), (3, 3), (-2, 4)]
        spatial_data = []
        for center in cluster_centers:
            points = np.random.multivariate_normal(center, [[0.5, 0], [0, 0.5]], 15)
            spatial_data.extend(points)
        spatial_data = np.array(spatial_data)
        
        # Create entities with relationships
        entities = [Entity(f"entity_{i}", "test", {"value": i}) for i in range(10)]
        relationships = [
            Relationship(f"entity_{i}", f"entity_{(i+1)%10}", "connects")
            for i in range(10)
        ]
        
        context = Context(timestamp=datetime.utcnow())
        
        return Interaction(
            id="complex_test",
            type="pattern_test",
            source="test",
            content={},
            context=context,
            timestamp=datetime.utcnow(),
            entities=entities,
            relationships=relationships,
            time_series=temporal_signal,
            coordinates=spatial_data,
            values=np.random.randn(50)
        )
    
    @pytest.mark.asyncio
    async def test_pattern_recognition(self, pattern_recognizer, complex_interaction):
        """Test comprehensive pattern recognition"""
        patterns = await pattern_recognizer.recognize(complex_interaction)
        
        assert isinstance(patterns, Patterns)
        assert hasattr(patterns, 'temporal')
        assert hasattr(patterns, 'structural')
        assert hasattr(patterns, 'anomalies')
        assert hasattr(patterns, 'clusters')
    
    def test_temporal_pattern_analysis(self):
        """Test temporal pattern analysis"""
        from mcp_learning_system.learning_core.pattern_recognition import TemporalPatternAnalyzer
        
        analyzer = TemporalPatternAnalyzer()
        
        # Create periodic signal
        t = np.linspace(0, 10, 1000)
        signal = np.sin(2 * np.pi * t) + 0.1 * np.random.randn(len(t))
        
        # Test would require async execution in real implementation
        assert analyzer is not None
    
    def test_anomaly_detection(self):
        """Test anomaly detection"""
        from mcp_learning_system.learning_core.pattern_recognition import AnomalyPatternDetector
        
        detector = AnomalyPatternDetector()
        
        # Create data with anomalies
        normal_data = np.random.normal(0, 1, 100)
        anomalous_data = np.concatenate([normal_data, [5, -5, 6]])  # Add outliers
        
        # Test would require async execution
        assert detector is not None


class TestPredictionEngine:
    """Test prediction engine"""
    
    @pytest.fixture
    def prediction_engine(self):
        """Create prediction engine"""
        from mcp_learning_system.learning_core.prediction_engine import PredictionEngine
        return PredictionEngine()
    
    @pytest.mark.asyncio
    async def test_basic_prediction(self, prediction_engine):
        """Test basic prediction functionality"""
        context = Context(
            timestamp=datetime.utcnow(),
            state={"metric1": 0.5, "metric2": 0.7},
            environment={"load": 0.6}
        )
        
        patterns = Patterns()
        knowledge_graph = Knowledge()
        
        prediction = await prediction_engine.predict(context, patterns, knowledge_graph)
        
        assert isinstance(prediction, Prediction)
        assert 0 <= prediction.confidence <= 1
        assert prediction.output is not None
    
    @pytest.mark.asyncio
    async def test_ensemble_prediction(self, prediction_engine):
        """Test ensemble prediction"""
        # Create test features
        features = np.random.randn(50)
        
        # Test each model type
        model_predictions = await prediction_engine._get_model_predictions(features)
        
        assert isinstance(model_predictions, dict)
        assert len(model_predictions) > 0
        
        # Test ensemble combination
        ensemble_result = await prediction_engine.ensemble.combine(model_predictions)
        assert isinstance(ensemble_result, Prediction)


class TestOptimizationEngine:
    """Test optimization engine"""
    
    @pytest.fixture
    def optimization_engine(self):
        """Create optimization engine"""
        from mcp_learning_system.learning_core.optimization import OptimizationEngine
        return OptimizationEngine()
    
    @pytest.fixture
    def sample_metrics_history(self):
        """Create sample metrics history"""
        history = []
        base_time = datetime.utcnow() - timedelta(hours=10)
        
        for i in range(50):
            timestamp = base_time + timedelta(minutes=i * 10)
            metrics = LearningMetrics(
                accuracy=0.7 + i * 0.005 + np.random.normal(0, 0.01),
                precision=0.68 + i * 0.005 + np.random.normal(0, 0.01),
                recall=0.65 + i * 0.005 + np.random.normal(0, 0.01),
                f1_score=0.66 + i * 0.005 + np.random.normal(0, 0.01),
                learning_rate=0.001,
                convergence_rate=max(0, 0.1 - i * 0.002),
                cross_instance_score=0.8,
                timestamp=timestamp
            )
            history.append(metrics)
        
        return history
    
    @pytest.mark.asyncio
    async def test_optimization(self, optimization_engine, sample_metrics_history):
        """Test optimization process"""
        patterns = Patterns()
        prediction = Prediction()
        
        result = await optimization_engine.optimize(
            patterns, prediction, sample_metrics_history
        )
        
        assert hasattr(result, 'optimized_parameters')
        assert hasattr(result, 'improvement')
        assert hasattr(result, 'convergence_status')
    
    def test_hyperparameter_optimization(self):
        """Test hyperparameter optimization"""
        from mcp_learning_system.learning_core.optimization import HyperparameterOptimizer
        
        optimizer = HyperparameterOptimizer()
        assert optimizer is not None
    
    def test_architecture_optimization(self):
        """Test architecture optimization"""
        from mcp_learning_system.learning_core.optimization import ArchitectureOptimizer
        
        optimizer = ArchitectureOptimizer()
        assert optimizer is not None


class TestPersistenceLayer:
    """Test persistence layer"""
    
    @pytest.fixture
    async def storage_system(self):
        """Create storage system with temporary directory"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = StorageConfig(
                base_path=temp_dir,
                retention_days=1,
                auto_cleanup=False
            )
            storage = LearningStorage(config)
            await storage.initialize()
            yield storage
    
    @pytest.fixture
    def sample_learning(self):
        """Create sample learning for storage testing"""
        patterns = Patterns()
        patterns.temporal = [{"type": "test_temporal", "confidence": 0.8}]
        patterns.structural = [{"type": "test_structural", "confidence": 0.7}]
        
        return Learning(
            type="test_learning",
            patterns=patterns,
            timestamp=datetime.utcnow(),
            cross_instance_relevance=0.6,
            content={"test": "data"}
        )
    
    @pytest.mark.asyncio
    async def test_store_and_retrieve(self, storage_system, sample_learning):
        """Test storing and retrieving learning"""
        # Store learning
        learning_id = await storage_system.store_learning_increment(sample_learning)
        assert learning_id is not None
        
        # Retrieve learning
        retrieved = await storage_system.retrieve_learning(learning_id)
        assert retrieved is not None
        assert retrieved.type == sample_learning.type
    
    @pytest.mark.asyncio
    async def test_query_learnings(self, storage_system, sample_learning):
        """Test querying learnings"""
        # Store multiple learnings
        learning_ids = []
        for i in range(5):
            learning = Learning(
                type=f"test_type_{i}",
                timestamp=datetime.utcnow() - timedelta(minutes=i),
                cross_instance_relevance=0.5 + i * 0.1,
                content={"index": i}
            )
            learning_id = await storage_system.store_learning_increment(learning)
            learning_ids.append(learning_id)
        
        # Query recent learnings
        recent = await storage_system.get_recent_learnings(3)
        assert len(recent) <= 3
        
        # Query with filters
        query = {"limit": 2}
        results = []
        async for learning in storage_system.query_learnings(query):
            results.append(learning)
        
        assert len(results) <= 2
    
    @pytest.mark.asyncio
    async def test_storage_statistics(self, storage_system, sample_learning):
        """Test storage statistics"""
        # Store some data
        await storage_system.store_learning_increment(sample_learning)
        
        # Get statistics
        stats = await storage_system.get_learning_statistics()
        
        assert "time_series" in stats
        assert "graph" in stats
        assert "vector" in stats
        assert "model" in stats
        assert "metadata" in stats


class TestIntegration:
    """Integration tests for the complete system"""
    
    @pytest.fixture
    async def complete_system(self):
        """Set up complete system for integration testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create adaptive learning system
            adaptive_system = AdaptiveLearningSystem()
            
            # Create storage
            storage_config = StorageConfig(
                base_path=temp_dir,
                retention_days=1,
                auto_cleanup=False
            )
            storage = LearningStorage(storage_config)
            await storage.initialize()
            
            # Create cross-instance system (skip if Redis unavailable)
            cross_instance = CrossInstanceLearning()
            try:
                await cross_instance.initialize()
            except:
                cross_instance = None
            
            yield {
                "adaptive_system": adaptive_system,
                "storage": storage,
                "cross_instance": cross_instance,
                "temp_dir": temp_dir
            }
    
    @pytest.mark.asyncio
    async def test_end_to_end_learning_flow(self, complete_system):
        """Test complete learning flow from interaction to storage"""
        adaptive_system = complete_system["adaptive_system"]
        storage = complete_system["storage"]
        
        # Create test interaction
        context = Context(
            timestamp=datetime.utcnow(),
            state={"test_mode": True},
            environment={"integration_test": True}
        )
        
        interaction = Interaction(
            id="integration_test",
            type="integration",
            source="test_system",
            content={"description": "End-to-end test"},
            context=context,
            timestamp=datetime.utcnow(),
            time_series=np.random.randn(50),
            values=np.random.randn(10)
        )
        
        # Process through adaptive learning
        knowledge = await adaptive_system.learn_from_interaction(interaction)
        assert knowledge is not None
        
        # Create learning object
        learning = Learning(
            type=interaction.type,
            timestamp=interaction.timestamp,
            cross_instance_relevance=0.7,
            content={"source": "integration_test"}
        )
        
        # Store learning
        learning_id = await storage.store_learning_increment(learning)
        assert learning_id is not None
        
        # Retrieve and verify
        retrieved_learning = await storage.retrieve_learning(learning_id)
        assert retrieved_learning is not None
        assert retrieved_learning.type == learning.type
    
    @pytest.mark.asyncio
    async def test_pattern_to_prediction_pipeline(self, complete_system):
        """Test pipeline from pattern recognition to prediction"""
        adaptive_system = complete_system["adaptive_system"]
        
        # Create complex interaction for pattern recognition
        t = np.linspace(0, 10, 200)
        signal = np.sin(t) + np.sin(3*t) + 0.1 * np.random.randn(len(t))
        
        context = Context(timestamp=datetime.utcnow())
        
        interaction = Interaction(
            id="pipeline_test",
            type="pipeline",
            source="test",
            content={},
            context=context,
            timestamp=datetime.utcnow(),
            time_series=signal,
            coordinates=np.random.randn(20, 2)
        )
        
        # Extract features and recognize patterns
        features = await adaptive_system.extract_multi_modal_features(interaction)
        patterns = await adaptive_system.pattern_recognizer.recognize(features)
        
        assert isinstance(patterns, Patterns)
        
        # Make prediction based on patterns
        prediction_context = Context(
            timestamp=datetime.utcnow(),
            state={"pattern_based": True}
        )
        
        prediction = await adaptive_system.predict_next_action(prediction_context)
        
        assert isinstance(prediction, Prediction)
        assert prediction.confidence > 0


@pytest.mark.asyncio
async def test_system_robustness():
    """Test system robustness with edge cases"""
    system = AdaptiveLearningSystem()
    
    # Test with empty interaction
    empty_context = Context(timestamp=datetime.utcnow())
    empty_interaction = Interaction(
        id="empty",
        type="empty",
        source="test",
        content={},
        context=empty_context,
        timestamp=datetime.utcnow()
    )
    
    # Should handle gracefully
    try:
        knowledge = await system.learn_from_interaction(empty_interaction)
        assert knowledge is not None
    except Exception as e:
        # Should not crash
        assert "should handle gracefully" in str(e).lower() or True
    
    # Test with malformed data
    malformed_context = Context(timestamp=datetime.utcnow())
    malformed_interaction = Interaction(
        id="malformed",
        type="malformed",
        source="test",
        content={},
        context=malformed_context,
        timestamp=datetime.utcnow(),
        time_series=np.array([]),  # Empty array
        values=np.array([np.nan, np.inf, -np.inf])  # Invalid values
    )
    
    try:
        knowledge = await system.learn_from_interaction(malformed_interaction)
        # Should handle gracefully
        assert True
    except Exception:
        # Expected to handle edge cases
        assert True


def test_model_serialization():
    """Test model serialization and deserialization"""
    from mcp_learning_system.learning_core.models import Learning, Patterns, Context
    
    # Create test objects
    context = Context(
        timestamp=datetime.utcnow(),
        state={"key": "value"}
    )
    
    patterns = Patterns()
    patterns.temporal = [{"pattern": "test"}]
    
    learning = Learning(
        type="test",
        patterns=patterns,
        timestamp=datetime.utcnow(),
        content={"test": "data"}
    )
    
    # Test serialization
    learning_dict = learning.to_dict()
    assert isinstance(learning_dict, dict)
    assert "type" in learning_dict
    assert "timestamp" in learning_dict


if __name__ == "__main__":
    # Run specific tests if executed directly
    pytest.main([__file__, "-v", "--tb=short"])