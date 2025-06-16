"""
Integration tests for MCP learning system
"""

import asyncio
import pytest
from datetime import datetime
from typing import Dict, Any, List

from mcp_learning import (
    LearningMCPServer,
    PatternRecognizer,
    CommandSequence,
    LearningEngine,
    WorkflowOrchestrator,
)


@pytest.fixture
async def learning_server():
    """Create test learning server"""
    server = LearningMCPServer(
        server_type="test",
        memory_gb=4,
        learning_enabled=True
    )
    yield server
    await server.cleanup()


@pytest.fixture
def sample_commands() -> List[Dict[str, Any]]:
    """Generate sample commands for testing"""
    return [
        {
            "type": "file_read",
            "action": "read",
            "path": "/test/file1.txt",
            "session_id": "test_session",
            "timestamp": datetime.now()
        },
        {
            "type": "file_write",
            "action": "write",
            "path": "/test/file2.txt",
            "content": "test content",
            "session_id": "test_session",
            "timestamp": datetime.now()
        },
        {
            "type": "file_read",
            "action": "read",
            "path": "/test/file2.txt",
            "session_id": "test_session",
            "timestamp": datetime.now()
        },
    ]


class TestLearningIntegration:
    """Test learning system integration"""
    
    @pytest.mark.asyncio
    async def test_process_with_learning(self, learning_server, sample_commands):
        """Test processing with learning enabled"""
        for command in sample_commands:
            response = await learning_server.process_with_learning(command)
            
            assert response is not None
            assert "status" in response
            
            # Check if learning insights are included
            if learning_server.learning_enabled:
                assert "learning_insights" in response
                
    @pytest.mark.asyncio
    async def test_pattern_recognition(self, learning_server, sample_commands):
        """Test pattern recognition"""
        # Process commands to build patterns
        for command in sample_commands * 5:  # Repeat to create patterns
            await learning_server.process_with_learning(command)
            
        # Get predictions
        predictions = await learning_server.predict_next_commands({
            "session_id": "test_session"
        })
        
        assert isinstance(predictions, list)
        
    @pytest.mark.asyncio
    async def test_workflow_optimization(self, learning_server, sample_commands):
        """Test workflow optimization"""
        # Create workflow
        orchestrator = WorkflowOrchestrator(learning_server)
        
        orchestrator.register_workflow("test_workflow", [
            {"type": "file_read", "path": "${input_file}"},
            {"type": "process", "action": "transform"},
            {"type": "file_write", "path": "${output_file}"},
        ])
        
        # Execute workflow
        result = await orchestrator.execute_workflow(
            "test_workflow",
            {
                "input_file": "/test/input.txt",
                "output_file": "/test/output.txt"
            },
            optimize=True
        )
        
        assert result["status"] in ["success", "error"]
        assert "workflow_id" in result
        
    def test_pattern_analyzer(self):
        """Test pattern analyzer"""
        recognizer = PatternRecognizer()
        
        # Create test sequences
        for i in range(10):
            sequence = CommandSequence(
                commands=[
                    {"type": "read", "timestamp": datetime.now()},
                    {"type": "process", "timestamp": datetime.now()},
                    {"type": "write", "timestamp": datetime.now()},
                ],
                timestamp=datetime.now(),
                session_id=f"session_{i}"
            )
            recognizer.sequence_miner.add_sequence(sequence)
            
        # Analyze patterns
        patterns = recognizer.analyze_patterns()
        
        assert "sequence_patterns" in patterns
        assert "temporal_patterns" in patterns
        assert "summary" in patterns
        
    @pytest.mark.asyncio
    async def test_performance_metrics(self, learning_server):
        """Test performance metrics collection"""
        # Process some commands
        for i in range(10):
            command = {
                "type": "test_command",
                "id": i,
                "session_id": "metrics_test"
            }
            await learning_server.process_with_learning(command)
            
        # Get performance report
        report = await learning_server.get_performance_report()
        
        assert "commands_processed" in report
        assert report["commands_processed"] == 10
        assert "performance_metrics" in report
        assert "learning_metrics" in report
        
    @pytest.mark.asyncio
    async def test_learning_persistence(self, learning_server, tmp_path):
        """Test model persistence"""
        # Train with some data
        for i in range(50):
            command = {
                "type": f"cmd_type_{i % 5}",
                "value": i,
                "session_id": "persistence_test"
            }
            await learning_server.process_with_learning(command)
            
        # Save checkpoint
        learning_server.config.checkpoint_dir = str(tmp_path)
        await learning_server._save_checkpoint()
        
        # Verify checkpoint was saved
        checkpoints = list(tmp_path.glob("*.pkl"))
        assert len(checkpoints) > 0
        
    def test_anomaly_detection(self):
        """Test anomaly detection"""
        engine = LearningEngine()
        
        # Normal commands
        for i in range(100):
            command = {"type": "normal", "value": i}
            metrics = {"execution_time": 50 + (i % 10), "cpu_usage": 30}
            engine.anomaly_detector.detect_anomaly(command, metrics)
            
        # Anomalous command
        anomaly_cmd = {"type": "anomaly", "value": 999}
        anomaly_metrics = {"execution_time": 5000, "cpu_usage": 95}
        
        is_anomaly, score = engine.anomaly_detector.detect_anomaly(anomaly_cmd, anomaly_metrics)
        
        # After training, it should detect anomalies
        if engine.anomaly_detector.is_fitted:
            assert score != 0  # Should have a non-zero anomaly score


class TestErrorHandling:
    """Test error handling in learning system"""
    
    @pytest.mark.asyncio
    async def test_invalid_command_handling(self, learning_server):
        """Test handling of invalid commands"""
        invalid_command = {
            # Missing required fields
            "invalid": True
        }
        
        response = await learning_server.process_with_learning(invalid_command)
        
        # Should handle gracefully
        assert response is not None
        assert "status" in response
        
    @pytest.mark.asyncio
    async def test_learning_disabled(self):
        """Test system with learning disabled"""
        server = LearningMCPServer(
            server_type="test",
            memory_gb=4,
            learning_enabled=False
        )
        
        command = {"type": "test", "action": "read"}
        response = await server.process_with_learning(command)
        
        # Should work without learning
        assert response is not None
        assert "learning_insights" not in response
        
        await server.cleanup()


@pytest.mark.asyncio
async def test_concurrent_processing(learning_server):
    """Test concurrent command processing"""
    commands = [
        {
            "type": f"concurrent_test_{i}",
            "id": i,
            "session_id": f"session_{i % 3}"
        }
        for i in range(20)
    ]
    
    # Process concurrently
    tasks = [
        learning_server.process_with_learning(cmd)
        for cmd in commands
    ]
    
    results = await asyncio.gather(*tasks)
    
    assert len(results) == 20
    assert all("status" in r for r in results)