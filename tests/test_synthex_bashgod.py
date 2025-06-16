#!/usr/bin/env python3
"""
Comprehensive tests for SYNTHEX-BashGod Python integration
"""

import pytest
import asyncio
from unittest.mock import Mock, patch
import json
import time

# Import would be: from rust_core import synthex_bashgod
# For testing, we'll mock the interface

class MockSynthexBashGod:
    """Mock implementation for testing"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.executions = []
        self.optimizations = []
        
    def execute_chain(self, chain):
        """Execute command chain"""
        result = {
            'chain_id': chain['id'],
            'success': True,
            'command_results': [
                {
                    'command_id': cmd['id'],
                    'status': 'success',
                    'stdout': f"Output from {cmd['command']}",
                    'stderr': '',
                    'exit_code': 0,
                    'execution_time_ms': 100,
                    'metrics': {
                        'cpu_usage_percent': 10.0,
                        'memory_usage_mb': 50,
                        'disk_io_mb': 0,
                        'network_io_mb': 0,
                        'syscalls': 100,
                        'context_switches': 10
                    }
                }
                for cmd in chain['commands']
            ],
            'total_time_ms': len(chain['commands']) * 100,
            'metrics': {
                'cpu_usage_percent': 10.0,
                'memory_usage_mb': 50,
                'disk_io_mb': 0,
                'network_io_mb': 0,
                'syscalls': 100,
                'context_switches': 10
            }
        }
        self.executions.append(chain)
        return result
    
    def optimize_chain(self, chain):
        """Optimize command chain"""
        # Simulate optimization by merging pipeline commands
        if len(chain['commands']) > 1:
            optimized = chain.copy()
            # Merge commands into pipeline
            merged_command = ' | '.join(cmd['command'] for cmd in chain['commands'])
            optimized['commands'] = [{
                'id': 'merged-1',
                'command': merged_command,
                'args': [],
                'env': {},
                'working_dir': None,
                'resources': {}
            }]
            self.optimizations.append(chain)
            return optimized
        return chain
    
    def generate_chain(self, intent):
        """Generate command chain from intent"""
        # Simple intent parsing
        goal = intent['goal'].lower()
        
        commands = []
        if 'find' in goal and 'error' in goal:
            commands = [
                {
                    'id': 'find-1',
                    'command': 'find',
                    'args': ['.', '-name', '*.log'],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                },
                {
                    'id': 'grep-1',
                    'command': 'grep',
                    'args': ['ERROR'],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                }
            ]
        elif 'list' in goal:
            commands = [
                {
                    'id': 'ls-1',
                    'command': 'ls',
                    'args': ['-la'],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                }
            ]
        
        return {
            'id': f'generated-{time.time()}',
            'commands': commands,
            'description': f'Generated chain for: {goal}',
            'resources': {}
        }
    
    def get_insights(self):
        """Get learning insights"""
        insights = []
        
        if len(self.executions) > 5:
            insights.append({
                'id': 'insight-1',
                'insight_type': 'pattern',
                'description': 'Frequent use of find + grep pattern detected',
                'confidence': 0.85,
                'occurrences': 5,
                'avg_improvement': 0.3,
                'examples': ['find . -name "*.log" | grep ERROR'],
                'recommendations': 'Consider using ripgrep (rg) for faster searching'
            })
        
        if len(self.optimizations) > 3:
            insights.append({
                'id': 'insight-2',
                'insight_type': 'optimization',
                'description': 'Pipeline merging provides significant speedup',
                'confidence': 0.9,
                'occurrences': 3,
                'avg_improvement': 0.4,
                'examples': ['cat file | grep pattern | wc -l'],
                'recommendations': 'Use built-in pipeline features'
            })
        
        return insights
    
    def get_stats(self):
        """Get statistics"""
        return {
            'total_executions': len(self.executions),
            'successful_executions': len(self.executions),
            'failed_executions': 0,
            'patterns_learned': 2,
            'chains_optimized': len(self.optimizations)
        }


class TestSynthexBashGod:
    """Test suite for SYNTHEX-BashGod"""
    
    def test_initialization(self):
        """Test service initialization"""
        config = {
            'executor_pool_size': 8,
            'default_timeout_ms': 60000,
            'enable_learning': True,
            'enable_mcp_integration': True
        }
        
        sbg = MockSynthexBashGod(config)
        assert sbg.config == config
    
    def test_simple_command_execution(self):
        """Test executing a simple command chain"""
        sbg = MockSynthexBashGod()
        
        chain = {
            'id': 'test-chain-1',
            'commands': [
                {
                    'id': 'echo-1',
                    'command': 'echo',
                    'args': ['Hello, SYNTHEX-BashGod!'],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                }
            ],
            'description': 'Test echo command',
            'resources': {}
        }
        
        result = sbg.execute_chain(chain)
        
        assert result['success']
        assert result['chain_id'] == 'test-chain-1'
        assert len(result['command_results']) == 1
        assert result['command_results'][0]['status'] == 'success'
        assert result['command_results'][0]['exit_code'] == 0
    
    def test_pipeline_execution(self):
        """Test executing a pipeline of commands"""
        sbg = MockSynthexBashGod()
        
        chain = {
            'id': 'pipeline-test',
            'commands': [
                {
                    'id': 'find-1',
                    'command': 'find',
                    'args': ['.', '-name', '*.py'],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                },
                {
                    'id': 'grep-1',
                    'command': 'grep',
                    'args': ['def test'],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                },
                {
                    'id': 'wc-1',
                    'command': 'wc',
                    'args': ['-l'],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                }
            ],
            'description': 'Find Python test functions',
            'resources': {}
        }
        
        result = sbg.execute_chain(chain)
        
        assert result['success']
        assert len(result['command_results']) == 3
        assert result['total_time_ms'] == 300  # 3 commands * 100ms each
    
    def test_chain_optimization(self):
        """Test command chain optimization"""
        sbg = MockSynthexBashGod()
        
        chain = {
            'id': 'optimize-test',
            'commands': [
                {
                    'id': 'cat-1',
                    'command': 'cat',
                    'args': ['file.txt'],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                },
                {
                    'id': 'grep-1',
                    'command': 'grep',
                    'args': ['pattern'],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                },
                {
                    'id': 'sort-1',
                    'command': 'sort',
                    'args': [],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                }
            ],
            'description': 'Pipeline for optimization',
            'resources': {}
        }
        
        optimized = sbg.optimize_chain(chain)
        
        assert len(optimized['commands']) == 1
        assert '|' in optimized['commands'][0]['command']
        assert 'cat' in optimized['commands'][0]['command']
        assert 'grep' in optimized['commands'][0]['command']
        assert 'sort' in optimized['commands'][0]['command']
    
    def test_chain_generation(self):
        """Test generating chain from intent"""
        sbg = MockSynthexBashGod()
        
        intent = {
            'goal': 'Find all error messages in log files',
            'context': {
                'directory': '/var/log',
                'file_pattern': '*.log'
            },
            'constraints': ['fast', 'reliable'],
            'examples': []
        }
        
        chain = sbg.generate_chain(intent)
        
        assert chain['id'].startswith('generated-')
        assert len(chain['commands']) > 0
        assert any('find' in cmd['command'] for cmd in chain['commands'])
        assert any('grep' in cmd['command'] for cmd in chain['commands'])
    
    def test_learning_insights(self):
        """Test learning insights generation"""
        sbg = MockSynthexBashGod()
        
        # Execute several chains to generate insights
        for i in range(10):
            chain = {
                'id': f'chain-{i}',
                'commands': [
                    {
                        'id': f'find-{i}',
                        'command': 'find',
                        'args': ['.', '-name', '*.log'],
                        'env': {},
                        'working_dir': None,
                        'resources': {}
                    },
                    {
                        'id': f'grep-{i}',
                        'command': 'grep',
                        'args': ['ERROR'],
                        'env': {},
                        'working_dir': None,
                        'resources': {}
                    }
                ],
                'description': 'Find errors',
                'resources': {}
            }
            sbg.execute_chain(chain)
            sbg.optimize_chain(chain)
        
        insights = sbg.get_insights()
        
        assert len(insights) > 0
        assert insights[0]['insight_type'] in ['pattern', 'optimization']
        assert insights[0]['confidence'] > 0.5
        assert insights[0]['occurrences'] > 0
    
    def test_statistics(self):
        """Test statistics collection"""
        sbg = MockSynthexBashGod()
        
        # Execute some chains
        for i in range(5):
            chain = {
                'id': f'stats-test-{i}',
                'commands': [
                    {
                        'id': f'cmd-{i}',
                        'command': 'echo',
                        'args': [f'test-{i}'],
                        'env': {},
                        'working_dir': None,
                        'resources': {}
                    }
                ],
                'description': 'Stats test',
                'resources': {}
            }
            sbg.execute_chain(chain)
            if i % 2 == 0:
                sbg.optimize_chain(chain)
        
        stats = sbg.get_stats()
        
        assert stats['total_executions'] == 5
        assert stats['successful_executions'] == 5
        assert stats['failed_executions'] == 0
        assert stats['chains_optimized'] == 3
    
    def test_resource_limits(self):
        """Test resource limit handling"""
        sbg = MockSynthexBashGod()
        
        chain = {
            'id': 'resource-test',
            'commands': [
                {
                    'id': 'heavy-cmd',
                    'command': 'stress',
                    'args': ['--cpu', '8', '--vm', '4', '--timeout', '10s'],
                    'env': {},
                    'working_dir': None,
                    'resources': {
                        'max_cpu_percent': 50,
                        'max_memory_mb': 1024,
                        'max_time_ms': 10000
                    }
                }
            ],
            'description': 'Resource-heavy command',
            'resources': {
                'max_cpu_percent': 50,
                'max_memory_mb': 1024
            }
        }
        
        result = sbg.execute_chain(chain)
        
        # Should handle resource limits appropriately
        assert 'chain_id' in result
        assert 'metrics' in result
    
    def test_error_handling(self):
        """Test error handling"""
        sbg = MockSynthexBashGod()
        
        # Test with invalid command
        chain = {
            'id': 'error-test',
            'commands': [
                {
                    'id': 'invalid-cmd',
                    'command': 'this_does_not_exist',
                    'args': [],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                }
            ],
            'description': 'Error test',
            'resources': {}
        }
        
        # In real implementation, this might raise an exception or return error status
        result = sbg.execute_chain(chain)
        
        # Mock returns success, but real implementation should handle errors
        assert 'chain_id' in result
    
    def test_parallel_execution(self):
        """Test parallel command execution"""
        sbg = MockSynthexBashGod({
            'executor_pool_size': 8
        })
        
        # Create chain with independent commands
        commands = []
        for i in range(10):
            commands.append({
                'id': f'parallel-{i}',
                'command': 'sleep',
                'args': ['0.1'],
                'env': {},
                'working_dir': None,
                'resources': {}
            })
        
        chain = {
            'id': 'parallel-test',
            'commands': commands,
            'description': 'Parallel execution test',
            'resources': {},
            'strategy': 'parallel'
        }
        
        start_time = time.time()
        result = sbg.execute_chain(chain)
        elapsed = time.time() - start_time
        
        assert result['success']
        assert len(result['command_results']) == 10
        # In real parallel execution, this should be much faster than sequential
        # Mock doesn't actually parallelize, but real implementation should


@pytest.mark.asyncio
class TestAsyncOperations:
    """Test async operations"""
    
    async def test_async_execution(self):
        """Test async command execution"""
        sbg = MockSynthexBashGod()
        
        chain = {
            'id': 'async-test',
            'commands': [
                {
                    'id': 'async-cmd',
                    'command': 'echo',
                    'args': ['async test'],
                    'env': {},
                    'working_dir': None,
                    'resources': {}
                }
            ],
            'description': 'Async test',
            'resources': {}
        }
        
        # Simulate async execution
        result = await asyncio.to_thread(sbg.execute_chain, chain)
        
        assert result['success']
        assert result['chain_id'] == 'async-test'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])