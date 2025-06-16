"""
Comprehensive demonstration of MCP Learning System capabilities
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List

from mcp_learning import (
    LearningMCPServer,
    WorkflowOrchestrator,
    CrossInstanceCoordinator,
    FederatedLearner,
    OrchestrationConfig,
)


class MCPLearningDemo:
    """Demonstrate MCP learning system features"""
    
    def __init__(self):
        self.server = None
        self.orchestrator = None
        self.coordinator = None
        
    async def setup(self):
        """Initialize demo components"""
        # Create learning server with full features
        config = OrchestrationConfig(
            enable_learning=True,
            enable_cross_instance=True,
            enable_federated=True,
            model_update_interval=timedelta(minutes=1),
        )
        
        self.server = LearningMCPServer(
            server_type="filesystem",
            memory_gb=8,
            learning_enabled=True,
            config=config
        )
        
        self.orchestrator = WorkflowOrchestrator(self.server)
        
        # Setup cross-instance coordination
        self.coordinator = CrossInstanceCoordinator(config)
        await self.coordinator.initialize()
        
        print("✅ MCP Learning System initialized")
        
    async def demo_adaptive_learning(self):
        """Demonstrate adaptive learning from command patterns"""
        print("\n🧠 Demonstrating Adaptive Learning...")
        
        # Simulate user workflow patterns
        workflows = [
            # Pattern 1: Read -> Process -> Write
            [
                {"type": "file_read", "path": "/data/input.csv"},
                {"type": "data_process", "operation": "clean"},
                {"type": "data_process", "operation": "transform"},
                {"type": "file_write", "path": "/data/output.csv"},
            ],
            # Pattern 2: Multiple reads -> Aggregate -> Write
            [
                {"type": "file_read", "path": "/data/file1.csv"},
                {"type": "file_read", "path": "/data/file2.csv"},
                {"type": "file_read", "path": "/data/file3.csv"},
                {"type": "data_process", "operation": "aggregate"},
                {"type": "file_write", "path": "/data/summary.csv"},
            ],
            # Pattern 3: API workflow
            [
                {"type": "api_auth", "service": "github"},
                {"type": "api_fetch", "endpoint": "/repos"},
                {"type": "data_process", "operation": "filter"},
                {"type": "api_push", "endpoint": "/issues"},
            ],
        ]
        
        # Train on patterns
        for i in range(5):  # Repeat to strengthen patterns
            for workflow in workflows:
                session_id = f"demo_session_{i}"
                
                for j, command in enumerate(workflow):
                    command["session_id"] = session_id
                    command["timestamp"] = datetime.now()
                    
                    response = await self.server.process_with_learning(command)
                    
                    # Show learning insights
                    if "learning_insights" in response and j > 0:
                        insights = response["learning_insights"]
                        if insights.get("next_commands"):
                            print(f"  📊 Predicted next commands: {insights['next_commands'][:2]}")
                            
        print("  ✓ Learned 3 workflow patterns")
        
    async def demo_pattern_recognition(self):
        """Demonstrate pattern recognition capabilities"""
        print("\n🔍 Demonstrating Pattern Recognition...")
        
        # Generate temporal patterns
        times = [
            datetime.now().replace(hour=9, minute=0),   # Morning batch
            datetime.now().replace(hour=13, minute=0),  # Afternoon batch
            datetime.now().replace(hour=17, minute=0),  # Evening batch
        ]
        
        # Simulate daily patterns
        for day in range(7):
            for time_slot in times:
                command = {
                    "type": "scheduled_backup",
                    "timestamp": time_slot + timedelta(days=day),
                    "session_id": "pattern_demo"
                }
                await self.server.process_with_learning(command)
                
        # Analyze discovered patterns
        if self.server.pattern_recognizer:
            patterns = self.server.pattern_recognizer.analyze_patterns()
            
            print(f"  ✓ Discovered {patterns['summary']['total_patterns']} patterns")
            print(f"  ✓ Sequence patterns: {patterns['summary']['sequence_patterns']}")
            print(f"  ✓ Temporal patterns: {patterns['summary']['temporal_patterns']}")
            
    async def demo_workflow_optimization(self):
        """Demonstrate workflow optimization"""
        print("\n⚡ Demonstrating Workflow Optimization...")
        
        # Register complex workflow
        self.orchestrator.register_workflow("data_pipeline", [
            {"type": "file_read", "path": "${input_path}", "format": "csv"},
            {"type": "data_validate", "schema": "${schema}"},
            {"type": "data_clean", "remove_nulls": True},
            {"type": "data_transform", "operations": ["normalize", "aggregate"]},
            {"type": "data_enrich", "source": "external_api"},
            {"type": "file_write", "path": "${output_path}", "format": "parquet"},
        ])
        
        # Execute without optimization
        print("  Running baseline workflow...")
        start_time = asyncio.get_event_loop().time()
        
        result1 = await self.orchestrator.execute_workflow(
            "data_pipeline",
            {
                "input_path": "/data/raw/sales.csv",
                "output_path": "/data/processed/sales.parquet",
                "schema": "sales_schema_v2"
            },
            optimize=False
        )
        
        baseline_time = asyncio.get_event_loop().time() - start_time
        
        # Execute with optimization
        print("  Running optimized workflow...")
        start_time = asyncio.get_event_loop().time()
        
        result2 = await self.orchestrator.execute_workflow(
            "data_pipeline",
            {
                "input_path": "/data/raw/sales.csv",
                "output_path": "/data/processed/sales_optimized.parquet",
                "schema": "sales_schema_v2"
            },
            optimize=True
        )
        
        optimized_time = asyncio.get_event_loop().time() - start_time
        
        improvement = ((baseline_time - optimized_time) / baseline_time) * 100
        print(f"  ✓ Performance improvement: {improvement:.1f}%")
        
    async def demo_anomaly_detection(self):
        """Demonstrate anomaly detection"""
        print("\n🚨 Demonstrating Anomaly Detection...")
        
        # Normal command pattern
        for i in range(50):
            command = {
                "type": "api_call",
                "endpoint": f"/api/v1/data/{i}",
                "method": "GET",
                "session_id": "anomaly_demo",
                "response_time": 50 + (i % 20),  # Normal variance
            }
            await self.server.process_with_learning(command)
            
        # Inject anomalies
        anomalies = [
            {
                "type": "api_call",
                "endpoint": "/api/v1/admin/delete_all",  # Suspicious endpoint
                "method": "DELETE",
                "session_id": "anomaly_demo",
                "response_time": 5000,  # Very slow
            },
            {
                "type": "unknown_command",  # Unknown command type
                "payload": "x" * 10000,  # Unusually large
                "session_id": "anomaly_demo",
            },
        ]
        
        for anomaly in anomalies:
            response = await self.server.process_with_learning(anomaly)
            
            if "learning_insights" in response:
                if response["learning_insights"].get("anomaly_detected"):
                    print(f"  ⚠️  Anomaly detected: {anomaly['type']}")
                    
        print("  ✓ Anomaly detection active")
        
    async def demo_cross_instance_learning(self):
        """Demonstrate cross-instance learning"""
        print("\n🌐 Demonstrating Cross-Instance Learning...")
        
        # Share patterns with other instances
        patterns = [
            {
                "pattern_id": "workflow_optimization_1",
                "pattern_type": "sequence",
                "confidence": 0.95,
                "elements": ["read", "validate", "transform", "write"],
            }
        ]
        
        await self.coordinator.share_patterns(patterns)
        print("  ✓ Shared patterns with cluster")
        
        # Get patterns from other instances
        shared_patterns = await self.coordinator.get_shared_patterns()
        print(f"  ✓ Received {len(shared_patterns)} patterns from peers")
        
        # Coordinate model update
        model_metrics = {
            "accuracy": 0.92,
            "loss": 0.15,
            "samples_processed": 10000,
        }
        
        should_update = await self.coordinator.coordinate_model_update(model_metrics)
        print(f"  ✓ Model update decision: {'Yes' if should_update else 'No'}")
        
    async def demo_federated_learning(self):
        """Demonstrate federated learning"""
        print("\n🤝 Demonstrating Federated Learning...")
        
        if not self.coordinator:
            print("  ⚠️  Federated learning requires cross-instance coordination")
            return
            
        federated = FederatedLearner(self.coordinator)
        
        # Simulate federated learning round
        success = await federated.coordinate_federated_round(self.server.learning_engine)
        
        if success:
            print("  ✓ Completed federated learning round")
        else:
            print("  ℹ️  Waiting for more participants...")
            
    async def demo_performance_report(self):
        """Generate comprehensive performance report"""
        print("\n📊 Generating Performance Report...")
        
        report = await self.server.get_performance_report()
        
        print("\n  === MCP Learning System Report ===")
        print(f"  Server Type: {report['server_type']}")
        print(f"  Commands Processed: {report['commands_processed']}")
        print(f"  Learning Cycles: {report['learning_cycles']}")
        print(f"  Active Sessions: {report['active_sessions']}")
        
        if "performance_metrics" in report:
            perf = report["performance_metrics"]
            print(f"\n  Performance Metrics:")
            print(f"    - Average Execution Time: {perf.get('avg_execution_time_ms', 0):.2f}ms")
            print(f"    - P95 Execution Time: {perf.get('p95_execution_time_ms', 0):.2f}ms")
            print(f"    - Error Rate: {perf.get('error_rate', 0):.2%}")
            
        if "learning_metrics" in report:
            learn = report["learning_metrics"]
            print(f"\n  Learning Metrics:")
            print(f"    - Commands Learned: {learn.get('commands_processed', 0)}")
            print(f"    - Workflows Optimized: {learn.get('workflows_optimized', 0)}")
            print(f"    - Anomalies Detected: {learn.get('anomalies_detected', 0)}")
            
    async def cleanup(self):
        """Clean up demo resources"""
        if self.coordinator:
            await self.coordinator.cleanup()
        if self.server:
            await self.server.cleanup()
        print("\n✅ Demo cleanup complete")


async def main():
    """Run the complete demo"""
    print("🚀 MCP Learning System Demo")
    print("=" * 50)
    
    demo = MCPLearningDemo()
    
    try:
        await demo.setup()
        
        # Run all demonstrations
        await demo.demo_adaptive_learning()
        await demo.demo_pattern_recognition()
        await demo.demo_workflow_optimization()
        await demo.demo_anomaly_detection()
        await demo.demo_cross_instance_learning()
        await demo.demo_federated_learning()
        await demo.demo_performance_report()
        
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        await demo.cleanup()


if __name__ == "__main__":
    asyncio.run(main())