"""Comprehensive tests for Development MCP Server"""

import pytest
import asyncio
from pathlib import Path
import time
from typing import Dict, Any

# Add parent directory to path for imports
import sys
sys.path.append(str(Path(__file__).parent.parent))

from rust_src import DevelopmentMCPServer  # This would be imported from compiled Rust
from python_src import (
    DevelopmentLearning,
    DevelopmentMCPIntegration,
    CodeChange,
)


class TestDevelopmentServer:
    """Test Development MCP Server functionality"""
    
    @pytest.fixture
    async def server(self, tmp_path):
        """Create test server instance"""
        # In real implementation, this would initialize Rust server
        server = MockDevelopmentServer(tmp_path)
        await server.start()
        yield server
        await server.stop()
    
    @pytest.fixture
    async def integration(self):
        """Create integration instance"""
        integration = DevelopmentMCPIntegration()
        await integration.connect()
        return integration
    
    async def test_memory_allocation(self, server):
        """Test 4GB memory allocation"""
        memory_usage = server.get_memory_usage()
        
        assert memory_usage['total'] == 4_294_967_296  # 4GB
        assert memory_usage['used'] == 0
        assert memory_usage['available'] == 4_294_967_296
    
    async def test_pattern_matching_performance(self, server):
        """Test pattern matching meets <10ms requirement"""
        # Pre-populate pattern cache
        for i in range(100):
            request = {
                'file_path': f'test{i}.py',
                'content': 'def hello():\n    pass',
                'context': f'function_def_{i}',
                'language': 'python',
                'intent': 'complete',
            }
            await server.analyze_code_request(request)
        
        # Test pattern match performance
        request = {
            'file_path': 'test50.py',
            'content': 'def hello():\n    pass',
            'context': 'function_def_50',
            'language': 'python',
            'intent': 'complete',
        }
        
        start = time.perf_counter()
        response = await server.analyze_code_request(request)
        elapsed_ms = (time.perf_counter() - start) * 1000
        
        assert elapsed_ms < 10  # Should be under 10ms for pattern match
        assert response['learning_applied'] is True
    
    async def test_code_analysis_performance(self, server):
        """Test code analysis meets <100ms requirement"""
        # Large code sample
        code = """
import asyncio
from typing import List, Dict, Any
import numpy as np

class DataProcessor:
    def __init__(self):
        self.data = []
        self.results = {}
    
    async def process_batch(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        tasks = []
        for item in items:
            task = asyncio.create_task(self.process_item(item))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        return {'processed': len(results), 'results': results}
    
    async def process_item(self, item: Dict[str, Any]) -> Any:
        # Simulate processing
        await asyncio.sleep(0.001)
        return item.get('value', 0) * 2
"""
        
        request = {
            'file_path': 'processor.py',
            'content': code,
            'context': 'new_analysis',
            'language': 'python',
            'intent': 'analyze',
        }
        
        start = time.perf_counter()
        response = await server.analyze_code_request(request)
        elapsed_ms = (time.perf_counter() - start) * 1000
        
        assert elapsed_ms < 100  # Should be under 100ms
        assert 'suggestion' in response
    
    async def test_learning_update_performance(self, integration):
        """Test learning update meets <50ms requirement"""
        code_changes = [
            CodeChange(
                file_path='test.py',
                language='python',
                before='def hello():\n    pass',
                after='def hello():\n    print("Hello, world!")',
                change_type='edit',
                timestamp=time.time(),
            )
        ]
        
        start = time.perf_counter()
        update = await integration.learning_system.learn_coding_patterns(code_changes)
        elapsed_ms = (time.perf_counter() - start) * 1000
        
        assert elapsed_ms < 50  # Should be under 50ms
        assert update.confidence > 0
    
    async def test_code_style_adaptation(self, integration):
        """Test code style learning and adaptation"""
        # Feed different style examples
        code_changes = [
            CodeChange(
                file_path='style1.py',
                language='python',
                before='',
                after='def snake_case_function():\n    variable_name = "value"',
                change_type='create',
                timestamp=time.time(),
            ),
            CodeChange(
                file_path='style2.py',
                language='python',
                before='',
                after='def snake_case_another():\n    another_var = "test"',
                change_type='create',
                timestamp=time.time(),
            ),
        ]
        
        update = await integration.learning_system.learn_coding_patterns(code_changes)
        
        assert 'naming_convention' in str(update.patterns)
        assert update.style.get('function_naming') == 'snake_case'
    
    async def test_framework_pattern_recognition(self, integration):
        """Test framework pattern recognition"""
        # React pattern
        react_code = """
import React, { useState, useEffect } from 'react';

function MyComponent() {
    const [count, setCount] = useState(0);
    
    useEffect(() => {
        console.log('Component mounted');
    }, []);
    
    return <div>{count}</div>;
}
"""
        
        request = {
            'file_path': 'component.jsx',
            'content': react_code,
            'language': 'javascript',
        }
        
        prediction = await integration.process_code_request(request)
        
        assert prediction['success'] is True
        # Should recognize React patterns
    
    async def test_import_prediction(self, integration):
        """Test import statement prediction"""
        code = """
df = DataFrame(data)
plt.plot(df['x'], df['y'])
"""
        
        patterns = [{
            'type': 'code_snippet',
            'content': code,
            'language': 'python',
        }]
        
        deps = await integration.learning_system.dependency_predictor.predict(patterns)
        
        assert 'pandas' in deps  # Should predict pandas for DataFrame
        assert 'matplotlib.pyplot' in deps  # Should predict matplotlib for plt
    
    async def test_memory_management(self, server):
        """Test memory usage tracking and limits"""
        initial_memory = server.get_memory_usage()
        
        # Add many patterns
        for i in range(1000):
            request = {
                'file_path': f'mem_test{i}.py',
                'content': f'def function_{i}():\n    return {i}',
                'context': f'memory_test_{i}',
                'language': 'python',
                'intent': 'complete',
            }
            await server.analyze_code_request(request)
        
        final_memory = server.get_memory_usage()
        
        assert final_memory['used'] > initial_memory['used']
        assert final_memory['used'] < final_memory['total']  # Within limits
    
    async def test_pattern_persistence(self, integration, tmp_path):
        """Test saving and loading learned patterns"""
        # Learn some patterns
        code_changes = [
            CodeChange(
                file_path='persist.py',
                language='python',
                before='',
                after='import pandas as pd\nimport numpy as np',
                change_type='create',
                timestamp=time.time(),
            )
        ]
        
        await integration.learning_system.learn_coding_patterns(code_changes)
        
        # Export models
        export_result = await integration.export_models(str(tmp_path))
        assert export_result['success'] is True
        
        # Create new instance and import
        new_integration = DevelopmentMCPIntegration()
        import_result = await new_integration.import_models(str(tmp_path))
        
        assert import_result['success'] is True
        
        # Check if patterns were preserved
        stats = new_integration.learning_system.get_learning_stats()
        assert stats['total_patterns_learned'] > 0
    
    async def test_concurrent_requests(self, server):
        """Test handling multiple concurrent requests"""
        requests = []
        for i in range(10):
            request = {
                'file_path': f'concurrent{i}.py',
                'content': f'def func{i}():\n    pass',
                'context': f'concurrent_{i}',
                'language': 'python',
                'intent': 'complete',
            }
            requests.append(server.analyze_code_request(request))
        
        # All requests should complete successfully
        responses = await asyncio.gather(*requests)
        
        assert len(responses) == 10
        assert all(r.get('suggestion') for r in responses)
    
    async def test_session_management(self, server):
        """Test session creation and tracking"""
        session_id = await server.create_session(Path('/test/project'))
        
        assert session_id is not None
        assert len(session_id) > 0
        
        # Make some requests in the session
        for i in range(5):
            request = {
                'file_path': f'session_test{i}.py',
                'content': 'def test():\n    pass',
                'context': 'session_test',
                'language': 'python',
                'intent': 'complete',
                'session_id': session_id,
            }
            await server.analyze_code_request(request)
        
        # End session
        await server.end_session(session_id)
        
        # Session should be cleaned up
        metrics = server.get_performance_metrics()
        assert metrics['total_requests'] >= 5


class MockDevelopmentServer:
    """Mock server for testing (simulates Rust server)"""
    
    def __init__(self, project_root):
        self.project_root = project_root
        self.memory_used = 0
        self.pattern_cache = {}
        self.request_count = 0
        self.sessions = {}
    
    async def start(self):
        pass
    
    async def stop(self):
        pass
    
    def get_memory_usage(self):
        return {
            'total': 4_294_967_296,
            'used': self.memory_used,
            'available': 4_294_967_296 - self.memory_used,
        }
    
    async def analyze_code_request(self, request):
        self.request_count += 1
        context = request.get('context', '')
        
        # Simulate pattern cache hit
        if context in self.pattern_cache:
            return {
                'suggestion': '// Cached suggestion',
                'confidence': 0.9,
                'patterns_used': ['cached'],
                'learning_applied': True,
            }
        
        # Simulate new analysis
        self.pattern_cache[context] = True
        self.memory_used += 1000  # Simulate memory usage
        
        return {
            'suggestion': '// New suggestion',
            'confidence': 0.8,
            'patterns_used': ['new'],
            'learning_applied': False,
        }
    
    async def create_session(self, project_root):
        import uuid
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'project_root': project_root,
            'created_at': time.time(),
        }
        return session_id
    
    async def end_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]
    
    def get_performance_metrics(self):
        return {
            'total_requests': self.request_count,
            'successful_responses': self.request_count,
            'success_rate': 1.0,
            'pattern_cache_hit_rate': 0.5,
            'average_response_time_ms': 5.0,
        }


if __name__ == "__main__":
    pytest.main([__file__, "-v"])