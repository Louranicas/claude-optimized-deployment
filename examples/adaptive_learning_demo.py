#!/usr/bin/env python3
"""
Adaptive Learning System Demonstration

This script demonstrates the complete adaptive learning system with
cross-instance intelligence sharing and continuous improvement.
"""

import asyncio
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
import sys
import json

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_learning_system import AdaptiveLearningSystem, CrossInstanceLearning
from mcp_learning_system.learning_core.models import (
    Interaction, Context, Features, Entity, Relationship
)
from mcp_learning_system.learning_core.persistence import LearningStorage, StorageConfig


class LearningDemo:
    """Demonstration of the adaptive learning system"""
    
    def __init__(self):
        self.adaptive_system = AdaptiveLearningSystem()
        self.cross_instance = CrossInstanceLearning()
        self.storage = LearningStorage(StorageConfig(
            base_path="/tmp/learning_demo",
            retention_days=7
        ))
        
    async def initialize(self):
        """Initialize the demo system"""
        print("🚀 Initializing Adaptive Learning System...")
        
        # Initialize cross-instance learning
        await self.cross_instance.initialize()
        
        # Initialize storage
        await self.storage.initialize()
        
        # Register demo instances
        await self._register_demo_instances()
        
        print("✅ System initialized successfully!")
    
    async def _register_demo_instances(self):
        """Register demo MCP instances"""
        from mcp_learning_system.learning_core.cross_instance import InstanceInfo
        
        instances = [
            InstanceInfo(
                name="development_server",
                type="development",
                capabilities=["code_analysis", "bug_detection", "optimization"],
                last_seen=datetime.utcnow(),
                performance_score=0.85,
                specializations=["python", "javascript", "rust"]
            ),
            InstanceInfo(
                name="devops_server",
                type="devops",
                capabilities=["deployment", "monitoring", "scaling"],
                last_seen=datetime.utcnow(),
                performance_score=0.92,
                specializations=["kubernetes", "docker", "ci_cd"]
            ),
            InstanceInfo(
                name="bash_god_server",
                type="bash_god",
                capabilities=["command_execution", "system_admin", "automation"],
                last_seen=datetime.utcnow(),
                performance_score=0.88,
                specializations=["bash", "linux", "automation"]
            ),
            InstanceInfo(
                name="quality_server",
                type="quality",
                capabilities=["testing", "validation", "quality_assurance"],
                last_seen=datetime.utcnow(),
                performance_score=0.90,
                specializations=["testing", "quality", "validation"]
            )
        ]
        
        for instance in instances:
            await self.cross_instance.register_instance(instance)
        
        print(f"📡 Registered {len(instances)} MCP instances")
    
    async def simulate_interactions(self, num_interactions: int = 50):
        """Simulate learning interactions across instances"""
        print(f"🎯 Simulating {num_interactions} learning interactions...")
        
        interaction_types = [
            "deployment_request",
            "code_review",
            "system_monitoring",
            "quality_check",
            "performance_analysis",
            "security_scan"
        ]
        
        sources = ["development_server", "devops_server", "bash_god_server", "quality_server"]
        
        learnings = []
        
        for i in range(num_interactions):
            # Create simulated interaction
            interaction = self._create_simulated_interaction(
                interaction_id=f"sim_{i}",
                interaction_type=np.random.choice(interaction_types),
                source=np.random.choice(sources)
            )
            
            # Process through adaptive learning
            knowledge = await self.adaptive_system.learn_from_interaction(interaction)
            
            # Store learning
            learning_id = await self.storage.store_learning_increment(
                self._create_learning_from_knowledge(interaction, knowledge)
            )
            
            learnings.append(learning_id)
            
            if (i + 1) % 10 == 0:
                print(f"  📚 Processed {i + 1}/{num_interactions} interactions")
        
        print(f"✅ Generated {len(learnings)} learning instances")
        return learnings
    
    def _create_simulated_interaction(self, interaction_id: str, 
                                    interaction_type: str, source: str) -> Interaction:
        """Create a simulated interaction"""
        # Create context based on interaction type
        context = Context(
            timestamp=datetime.utcnow(),
            state={
                "interaction_type": interaction_type,
                "source_instance": source,
                "session_id": f"session_{np.random.randint(1, 100)}"
            },
            environment={
                "cpu_usage": np.random.uniform(20, 80),
                "memory_usage": np.random.uniform(30, 70),
                "active_connections": np.random.randint(10, 100)
            }
        )
        
        # Create entities based on type
        entities = self._create_entities_for_type(interaction_type)
        
        # Create relationships
        relationships = self._create_relationships_for_entities(entities)
        
        # Create simulated time series data
        time_series = np.random.randn(100) + np.sin(np.linspace(0, 4*np.pi, 100))
        
        # Create interaction
        interaction = Interaction(
            id=interaction_id,
            type=interaction_type,
            source=source,
            content={
                "description": f"Simulated {interaction_type} from {source}",
                "complexity": np.random.uniform(0.1, 1.0),
                "priority": np.random.choice(["low", "medium", "high"])
            },
            context=context,
            timestamp=datetime.utcnow(),
            entities=entities,
            relationships=relationships,
            time_series=time_series,
            values=np.random.randn(20),
            coordinates=np.random.randn(10, 2)  # 2D spatial data
        )
        
        return interaction
    
    def _create_entities_for_type(self, interaction_type: str) -> List[Entity]:
        """Create entities based on interaction type"""
        entities = []
        
        if interaction_type == "deployment_request":
            entities = [
                Entity("app_1", "application", {"language": "python", "version": "3.9"}),
                Entity("env_prod", "environment", {"type": "production", "region": "us-east-1"}),
                Entity("container_1", "container", {"image": "python:3.9-slim", "cpu": "1000m"})
            ]
        elif interaction_type == "code_review":
            entities = [
                Entity("file_1", "source_file", {"language": "python", "lines": 250}),
                Entity("func_1", "function", {"complexity": 8, "test_coverage": 0.85}),
                Entity("bug_1", "potential_bug", {"severity": "medium", "type": "logic_error"})
            ]
        elif interaction_type == "system_monitoring":
            entities = [
                Entity("server_1", "server", {"cpu": 65.5, "memory": 78.2, "disk": 45.1}),
                Entity("service_1", "service", {"status": "healthy", "response_time": 120}),
                Entity("alert_1", "alert", {"level": "warning", "metric": "high_cpu"})
            ]
        elif interaction_type == "quality_check":
            entities = [
                Entity("test_suite", "test_collection", {"total_tests": 150, "passed": 147}),
                Entity("coverage", "metric", {"line_coverage": 0.92, "branch_coverage": 0.88}),
                Entity("quality_gate", "gate", {"status": "passed", "score": 8.5})
            ]
        
        return entities
    
    def _create_relationships_for_entities(self, entities: List[Entity]) -> List[Relationship]:
        """Create relationships between entities"""
        relationships = []
        
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                entity1, entity2 = entities[i], entities[j]
                
                # Create random relationship
                rel_types = ["depends_on", "affects", "monitors", "contains", "triggers"]
                rel_type = np.random.choice(rel_types)
                
                relationships.append(Relationship(
                    source=entity1.id,
                    target=entity2.id,
                    type=rel_type,
                    weight=np.random.uniform(0.3, 1.0)
                ))
        
        return relationships
    
    def _create_learning_from_knowledge(self, interaction: Interaction, 
                                      knowledge) -> 'Learning':
        """Convert knowledge to Learning object"""
        from mcp_learning_system.learning_core.models import Learning, Patterns
        
        # Create patterns from knowledge
        patterns = Patterns()
        if hasattr(knowledge, 'nodes'):
            patterns.temporal = knowledge.nodes[:5]  # First 5 as temporal
            patterns.structural = knowledge.nodes[5:10]  # Next 5 as structural
        
        learning = Learning(
            type=interaction.type,
            patterns=patterns,
            source_interaction=interaction,
            timestamp=interaction.timestamp,
            cross_instance_relevance=np.random.uniform(0.3, 0.9),
            content={
                "interaction_summary": f"Learning from {interaction.type}",
                "entities_count": len(interaction.entities or []),
                "relationships_count": len(interaction.relationships or [])
            }
        )
        
        return learning
    
    async def demonstrate_cross_instance_learning(self):
        """Demonstrate cross-instance learning capabilities"""
        print("🔄 Demonstrating cross-instance learning...")
        
        # Query knowledge across instances
        query = "performance optimization patterns"
        context = {"domain": "web_applications", "priority": "high"}
        
        cross_knowledge = await self.cross_instance.query_cross_instance_knowledge(
            query, context
        )
        
        print(f"  🧠 Retrieved cross-instance knowledge with {len(cross_knowledge.insights)} insights")
        
        # Get instance specialization insights
        insights = await self.cross_instance.get_instance_specialization_insights()
        
        print("  📊 Instance Performance Rankings:")
        for category, ranking in insights.get("performance_rankings", {}).items():
            print(f"    {category}: {', '.join(ranking[:3])}")
        
        print("  🎯 Recommended Task Routing:")
        for task, instance in insights.get("recommended_routing", {}).items():
            print(f"    {task} → {instance}")
        
        # Synchronize models across instances
        await self.cross_instance.synchronize_models()
        print("  🔄 Synchronized models across instances")
    
    async def demonstrate_pattern_recognition(self):
        """Demonstrate advanced pattern recognition"""
        print("🔍 Demonstrating pattern recognition capabilities...")
        
        # Create test interaction with complex patterns
        test_interaction = self._create_complex_interaction()
        
        # Extract features and recognize patterns
        features = await self.adaptive_system.extract_multi_modal_features(test_interaction)
        patterns = await self.adaptive_system.pattern_recognizer.recognize(features)
        
        print(f"  🎯 Detected Patterns:")
        print(f"    - Temporal patterns: {len(patterns.temporal)}")
        print(f"    - Structural patterns: {len(patterns.structural)}")
        print(f"    - Anomalies: {len(patterns.anomalies)}")
        print(f"    - Clusters: {len(patterns.clusters)}")
        print(f"    - Meta-patterns: {len(patterns.meta_patterns)}")
        print(f"    - Correlations: {len(patterns.correlations)}")
        
        # Show pattern confidence
        if patterns.temporal:
            avg_confidence = np.mean([p.confidence for p in patterns.temporal if hasattr(p, 'confidence')])
            print(f"    - Average pattern confidence: {avg_confidence:.3f}")
    
    def _create_complex_interaction(self) -> Interaction:
        """Create a complex interaction for pattern recognition demo"""
        # Create complex temporal data with multiple patterns
        t = np.linspace(0, 10, 1000)
        
        # Combine multiple signals
        signal1 = np.sin(2 * np.pi * 1 * t)  # 1 Hz sine wave
        signal2 = 0.5 * np.sin(2 * np.pi * 3 * t)  # 3 Hz sine wave
        signal3 = 0.3 * np.sin(2 * np.pi * 0.5 * t)  # 0.5 Hz sine wave
        noise = 0.1 * np.random.randn(len(t))
        
        # Add anomalies
        anomaly_indices = np.random.choice(len(t), 10, replace=False)
        signal = signal1 + signal2 + signal3 + noise
        signal[anomaly_indices] += np.random.uniform(2, 5, len(anomaly_indices))
        
        # Create spatial data with clusters
        cluster_centers = [(2, 3), (-1, 4), (5, -2)]
        spatial_data = []
        for center in cluster_centers:
            cluster_points = np.random.multivariate_normal(
                center, [[0.5, 0.1], [0.1, 0.5]], 20
            )
            spatial_data.extend(cluster_points)
        
        spatial_data = np.array(spatial_data)
        
        # Create complex entities and relationships
        entities = [
            Entity(f"entity_{i}", f"type_{i%3}", {"value": np.random.randn()})
            for i in range(15)
        ]
        
        relationships = []
        for i in range(len(entities)):
            for j in range(i + 1, min(i + 4, len(entities))):
                relationships.append(Relationship(
                    entities[i].id, entities[j].id, "complex_relation",
                    weight=np.random.uniform(0.1, 1.0)
                ))
        
        context = Context(
            timestamp=datetime.utcnow(),
            state={"complexity": "high", "pattern_type": "multi_modal"},
            environment={"scenario": "complex_pattern_demo"}
        )
        
        return Interaction(
            id="complex_demo",
            type="complex_analysis",
            source="demo_system",
            content={"description": "Complex multi-modal pattern demo"},
            context=context,
            timestamp=datetime.utcnow(),
            entities=entities,
            relationships=relationships,
            time_series=signal,
            values=np.random.randn(50),
            coordinates=spatial_data
        )
    
    async def demonstrate_prediction_engine(self):
        """Demonstrate prediction capabilities"""
        print("🔮 Demonstrating prediction engine...")
        
        # Create context for prediction
        context = Context(
            timestamp=datetime.utcnow(),
            state={
                "system_load": 0.75,
                "active_users": 1500,
                "last_deployment": "2024-01-15"
            },
            environment={
                "cpu_usage": 68.5,
                "memory_usage": 72.1,
                "network_latency": 45.2
            }
        )
        
        # Make prediction
        prediction = await self.adaptive_system.predict_next_action(context)
        
        print(f"  🎯 Prediction Results:")
        print(f"    - Confidence: {prediction.confidence:.3f}")
        print(f"    - Model: {prediction.model}")
        print(f"    - Output keys: {list(prediction.output.keys())}")
        
        if prediction.temporal_adjustment:
            print(f"    - Temporal factors: {list(prediction.temporal_adjustment.keys())}")
        
        if prediction.causal_factors:
            print(f"    - Causal factors detected: {len(prediction.causal_factors.get('direct_causes', []))}")
        
        # Demonstrate sequence prediction
        context_sequence = [context]
        sequence_predictions = await self.adaptive_system.prediction_ensemble.predict_sequence(
            context_sequence, horizon=3
        )
        
        print(f"  📈 Sequence Predictions: {len(sequence_predictions)} future states predicted")
    
    async def demonstrate_optimization(self):
        """Demonstrate optimization capabilities"""
        print("⚡ Demonstrating optimization engine...")
        
        # Create mock metrics history
        from mcp_learning_system.learning_core.learning_core import LearningMetrics
        
        metrics_history = []
        base_time = datetime.utcnow() - timedelta(hours=24)
        
        for i in range(100):
            timestamp = base_time + timedelta(minutes=i * 15)
            
            # Simulate improving then plateauing performance
            if i < 60:
                accuracy = 0.6 + (i / 60) * 0.3 + np.random.normal(0, 0.02)
            else:
                accuracy = 0.9 + np.random.normal(0, 0.01)
            
            metrics = LearningMetrics(
                accuracy=accuracy,
                precision=accuracy * 0.95,
                recall=accuracy * 0.92,
                f1_score=accuracy * 0.93,
                learning_rate=0.001,
                convergence_rate=max(0, 0.1 - i * 0.001),
                cross_instance_score=0.8 + np.random.normal(0, 0.05),
                timestamp=timestamp
            )
            metrics_history.append(metrics)
        
        # Run optimization
        from mcp_learning_system.learning_core.models import Patterns, Prediction
        
        optimization_result = await self.adaptive_system.learning_core.optimization_engine.optimize(
            Patterns(),
            Prediction(),
            metrics_history
        )
        
        print(f"  🎯 Optimization Results:")
        print(f"    - Strategy: {optimization_result.metadata.get('strategy', 'unknown')}")
        print(f"    - Improvement: {optimization_result.improvement:.4f}")
        print(f"    - Status: {optimization_result.convergence_status}")
        print(f"    - Iterations: {optimization_result.iterations}")
        print(f"    - Optimized parameters: {list(optimization_result.optimized_parameters.keys())}")
    
    async def demonstrate_storage_system(self):
        """Demonstrate storage and retrieval capabilities"""
        print("💾 Demonstrating storage system...")
        
        # Get storage statistics
        stats = await self.storage.get_learning_statistics()
        
        print(f"  📊 Storage Statistics:")
        for system, stat in stats.items():
            if isinstance(stat, dict):
                print(f"    {system}:")
                for key, value in stat.items():
                    if isinstance(value, (int, float)):
                        print(f"      - {key}: {value}")
        
        # Query recent learnings
        recent_learnings = await self.storage.get_recent_learnings(10)
        print(f"  📚 Retrieved {len(recent_learnings)} recent learnings")
        
        # Demonstrate querying
        query = {
            "order_by": "timestamp",
            "order": "desc",
            "limit": 5
        }
        
        count = 0
        async for learning in self.storage.query_learnings(query):
            count += 1
        
        print(f"  🔍 Query returned {count} learnings")
    
    async def run_complete_demo(self):
        """Run the complete demonstration"""
        print("🎪 Starting Complete Adaptive Learning System Demo")
        print("=" * 60)
        
        try:
            # Initialize system
            await self.initialize()
            print()
            
            # Simulate learning interactions
            await self.simulate_interactions(25)
            print()
            
            # Demonstrate each component
            await self.demonstrate_pattern_recognition()
            print()
            
            await self.demonstrate_prediction_engine()
            print()
            
            await self.demonstrate_cross_instance_learning()
            print()
            
            await self.demonstrate_optimization()
            print()
            
            await self.demonstrate_storage_system()
            print()
            
            print("🎉 Demo completed successfully!")
            print("=" * 60)
            
            # Print final summary
            await self._print_summary()
            
        except Exception as e:
            print(f"❌ Demo failed with error: {e}")
            import traceback
            traceback.print_exc()
    
    async def _print_summary(self):
        """Print demo summary"""
        print("\n📋 DEMO SUMMARY")
        print("-" * 40)
        
        # System status
        storage_stats = await self.storage.get_learning_statistics()
        instance_insights = await self.cross_instance.get_instance_specialization_insights()
        
        print(f"🏗️  System Components:")
        print(f"   ✅ Adaptive Learning System")
        print(f"   ✅ Cross-Instance Learning")
        print(f"   ✅ Pattern Recognition Engine")
        print(f"   ✅ Prediction Engine")
        print(f"   ✅ Optimization Engine")
        print(f"   ✅ Storage System")
        
        print(f"\n🤖 Registered Instances: {len(instance_insights.get('instance_profiles', {}))}")
        for name, profile in instance_insights.get('instance_profiles', {}).items():
            print(f"   - {name}: {profile['type']} (score: {profile['performance_score']:.2f})")
        
        print(f"\n📈 Performance Metrics:")
        print(f"   - Total learnings stored: {storage_stats.get('metadata', {}).get('total_learnings', 0)}")
        print(f"   - Cross-instance collaboration patterns: {len(instance_insights.get('collaboration_patterns', []))}")
        print(f"   - Storage systems active: {len([k for k, v in storage_stats.items() if v])}")
        
        print(f"\n🎯 Key Capabilities Demonstrated:")
        print(f"   ✓ Multi-modal pattern recognition")
        print(f"   ✓ Cross-instance intelligence sharing")
        print(f"   ✓ Predictive modeling with uncertainty")
        print(f"   ✓ Continuous optimization")
        print(f"   ✓ Efficient data persistence")
        print(f"   ✓ Real-time learning adaptation")


async def main():
    """Main demo function"""
    demo = LearningDemo()
    await demo.run_complete_demo()


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main())