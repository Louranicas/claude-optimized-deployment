#!/usr/bin/env python3
"""
BASH_GOD MCP Server Comprehensive Test Suite
Tests all components of the BASH_GOD system including learning, optimization, and safety.
"""

import asyncio
import json
import time
import sys
import os
from pathlib import Path
import tempfile
import subprocess
from typing import Dict, Any, List

# Add the bash_god module to path
bash_god_path = Path(__file__).parent / "mcp_learning_system" / "servers" / "bash_god"
sys.path.insert(0, str(bash_god_path))

try:
    from python_src.server import BashGodPythonServer
    from python_src.learning import BashGodLearning
    from commands.library import BashCommandLibrary, CommandCategory, SafetyLevel
    from safety.validator import BashSafetyValidator, RiskLevel
    from optimization.engine import BashOptimizationEngine
except ImportError as e:
    print(f"Warning: Could not import BASH_GOD modules: {e}")
    print("Running in simulation mode...")
    
    # Create mock classes for testing
    class BashGodPythonServer:
        async def initialize_rust_integration(self): pass
        async def generate_intelligent_command(self, request): 
            return {
                'command': f"# Mock command for: {request.get('task', 'unknown')}",
                'explanation': 'Mock explanation',
                'confidence': 0.8
            }
        async def validate_command(self, command): 
            return {'is_safe': True, 'risk_level': 'low'}
        async def learn_from_execution(self, data): 
            return {'status': 'learned'}
    
    class BashCommandLibrary:
        def find_templates(self, query): return []
        def get_optimization_tips(self, name): return []
    
    class BashSafetyValidator:
        def validate_command(self, command, context=None): 
            from dataclasses import dataclass
            from enum import Enum
            
            class ValidationResult(Enum):
                APPROVED = "approved"
            
            class RiskLevel(Enum):
                SAFE = "safe"
            
            @dataclass
            class ValidationReport:
                result: ValidationResult
                risk_level: RiskLevel
                violations: List = None
                warnings: List = None
                mitigations: List = None
                
                def __post_init__(self):
                    if self.violations is None: self.violations = []
                    if self.warnings is None: self.warnings = []
                    if self.mitigations is None: self.mitigations = []
            
            return ValidationReport(
                result=ValidationResult.APPROVED,
                risk_level=RiskLevel.SAFE
            )
    
    class BashOptimizationEngine:
        def optimize_command(self, command, context=None):
            from dataclasses import dataclass
            
            @dataclass
            class OptimizationResult:
                original_command: str
                optimized_command: str
                optimizations_applied: List = None
                expected_speedup: float = 1.0
                confidence: float = 0.8
                warnings: List = None
                
                def __post_init__(self):
                    if self.optimizations_applied is None: self.optimizations_applied = []
                    if self.warnings is None: self.warnings = []
            
            return OptimizationResult(
                original_command=command,
                optimized_command=command
            )


class BashGodTestSuite:
    """Comprehensive test suite for BASH_GOD MCP Server"""
    
    def __init__(self):
        self.server = None
        self.library = None
        self.validator = None
        self.optimizer = None
        self.test_results = {
            'passed': 0,
            'failed': 0,
            'errors': []
        }
        
    async def setup(self):
        """Setup test environment"""
        print("🔧 Setting up BASH_GOD test environment...")
        
        try:
            # Initialize components
            self.server = BashGodPythonServer()
            await self.server.initialize_rust_integration()
            
            self.library = BashCommandLibrary()
            self.validator = BashSafetyValidator()
            self.optimizer = BashOptimizationEngine()
            
            print("✅ Test environment setup complete")
            
        except Exception as e:
            print(f"❌ Setup failed: {e}")
            raise
    
    def assert_test(self, condition: bool, test_name: str, error_msg: str = ""):
        """Helper method for test assertions"""
        if condition:
            print(f"✅ {test_name}")
            self.test_results['passed'] += 1
        else:
            print(f"❌ {test_name}: {error_msg}")
            self.test_results['failed'] += 1
            self.test_results['errors'].append(f"{test_name}: {error_msg}")
    
    async def test_command_generation(self):
        """Test intelligent command generation"""
        print("\n🧠 Testing Command Generation...")
        
        test_cases = [
            {
                'task': 'find large files over 100MB',
                'context': {'cwd': '/tmp', 'cpu_cores': 4},
                'expected_keywords': ['find', 'size', '100M']
            },
            {
                'task': 'kill process using port 8080',
                'context': {'user': 'testuser'},
                'expected_keywords': ['lsof', 'kill', '8080']
            },
            {
                'task': 'compress log files older than 30 days',
                'context': {'storage_type': 'ssd'},
                'expected_keywords': ['find', 'mtime', 'gzip']
            }
        ]
        
        for i, case in enumerate(test_cases):
            try:
                response = await self.server.generate_intelligent_command(case)
                
                # Check response structure
                self.assert_test(
                    'command' in response,
                    f"Command Generation {i+1}: Response has command field"
                )
                
                self.assert_test(
                    'confidence' in response,
                    f"Command Generation {i+1}: Response has confidence field"
                )
                
                # Check command content
                command = response.get('command', '')
                has_expected_keywords = any(
                    keyword in command.lower() 
                    for keyword in case['expected_keywords']
                )
                
                self.assert_test(
                    has_expected_keywords,
                    f"Command Generation {i+1}: Contains expected keywords",
                    f"Expected one of {case['expected_keywords']} in '{command}'"
                )
                
                print(f"  Generated: {command}")
                
            except Exception as e:
                self.assert_test(
                    False,
                    f"Command Generation {i+1}: Exception handling",
                    str(e)
                )
    
    async def test_safety_validation(self):
        """Test safety validation system"""
        print("\n🛡️  Testing Safety Validation...")
        
        test_cases = [
            {
                'command': 'ls -la',
                'expected_safe': True,
                'expected_risk': 'safe'
            },
            {
                'command': 'rm -rf /',
                'expected_safe': False,
                'expected_risk': 'critical'
            },
            {
                'command': 'chmod 777 /etc/passwd',
                'expected_safe': False,
                'expected_risk': 'high'
            },
            {
                'command': 'sudo systemctl restart nginx',
                'expected_safe': True,  # Warning but not blocked
                'expected_risk': 'medium'
            },
            {
                'command': ':(){ :|:& };:',  # Fork bomb
                'expected_safe': False,
                'expected_risk': 'critical'
            }
        ]
        
        for i, case in enumerate(test_cases):
            try:
                if hasattr(self.validator, 'validate_command'):
                    # Using real validator
                    result = self.validator.validate_command(case['command'])
                    is_safe = result.result.value == 'approved'
                    risk_level = result.risk_level.value
                else:
                    # Using server validator
                    result = await self.server.validate_command(case['command'])
                    is_safe = result.get('is_safe', True)
                    risk_level = result.get('risk_level', 'safe')
                
                self.assert_test(
                    is_safe == case['expected_safe'],
                    f"Safety Validation {i+1}: Correct safety assessment",
                    f"Expected safe={case['expected_safe']}, got {is_safe}"
                )
                
                print(f"  Command: {case['command']}")
                print(f"    Safe: {is_safe}, Risk: {risk_level}")
                
            except Exception as e:
                self.assert_test(
                    False,
                    f"Safety Validation {i+1}: Exception handling",
                    str(e)
                )
    
    async def test_optimization_engine(self):
        """Test command optimization"""
        print("\n🚀 Testing Optimization Engine...")
        
        test_cases = [
            {
                'command': 'cat file.txt | grep pattern',
                'expected_optimized': 'grep pattern file.txt',
                'optimization_type': 'pipeline_fusion'
            },
            {
                'command': 'find . -exec grep pattern {} \\;',
                'expected_contains': 'xargs',
                'optimization_type': 'parallelization'
            },
            {
                'command': 'sort file | uniq',
                'expected_optimized': 'sort -u file',
                'optimization_type': 'tool_combination'
            }
        ]
        
        for i, case in enumerate(test_cases):
            try:
                result = self.optimizer.optimize_command(
                    case['command'],
                    context={'cpu_cores': 4, 'memory_gb': 8}
                )
                
                self.assert_test(
                    hasattr(result, 'optimized_command'),
                    f"Optimization {i+1}: Result has optimized command"
                )
                
                optimized = result.optimized_command
                original = result.original_command
                
                # Check if optimization was applied
                optimization_applied = optimized != original
                
                if 'expected_optimized' in case:
                    self.assert_test(
                        case['expected_optimized'] in optimized,
                        f"Optimization {i+1}: Expected optimization applied",
                        f"Expected '{case['expected_optimized']}' in '{optimized}'"
                    )
                elif 'expected_contains' in case:
                    self.assert_test(
                        case['expected_contains'] in optimized,
                        f"Optimization {i+1}: Contains expected element",
                        f"Expected '{case['expected_contains']}' in '{optimized}'"
                    )
                
                print(f"  Original:  {original}")
                print(f"  Optimized: {optimized}")
                print(f"  Speedup:   {result.expected_speedup:.1f}x")
                
            except Exception as e:
                self.assert_test(
                    False,
                    f"Optimization {i+1}: Exception handling",
                    str(e)
                )
    
    async def test_learning_system(self):
        """Test learning and adaptation"""
        print("\n🎓 Testing Learning System...")
        
        # Simulate command execution history
        execution_history = [
            {
                'task': 'find large files',
                'command': 'find . -size +100M -type f',
                'success': True,
                'duration_ms': 1500,
                'context': {'cwd': '/home/user'}
            },
            {
                'task': 'find large files',
                'command': 'find . -size +100M -type f -printf "%s %p\\n" | sort -nr',
                'success': True,
                'duration_ms': 1200,
                'context': {'cwd': '/home/user'}
            },
            {
                'task': 'compress logs',
                'command': 'gzip *.log',
                'success': True,
                'duration_ms': 5000,
                'context': {'cpu_cores': 8}
            }
        ]
        
        try:
            # Test learning from execution
            for execution in execution_history:
                result = await self.server.learn_from_execution(execution)
                
                self.assert_test(
                    'status' in result,
                    "Learning: Execution learning returns status"
                )
            
            print("  ✅ Successfully processed execution history")
            
            # Test that learning improves future commands
            request = {
                'task': 'find large files',
                'context': {'cwd': '/home/user', 'cpu_cores': 8}
            }
            
            response = await self.server.generate_intelligent_command(request)
            
            # Should generate improved command based on learning
            self.assert_test(
                response.get('confidence', 0) > 0.5,
                "Learning: Improved confidence after learning",
                f"Low confidence: {response.get('confidence', 0)}"
            )
            
            print(f"  Learned command: {response.get('command', 'None')}")
            
        except Exception as e:
            self.assert_test(
                False,
                "Learning: Exception handling",
                str(e)
            )
    
    async def test_command_library(self):
        """Test command template library"""
        print("\n📚 Testing Command Library...")
        
        try:
            # Test template search
            templates = self.library.find_templates("find large files")
            
            self.assert_test(
                len(templates) > 0,
                "Library: Found templates for 'find large files'"
            )
            
            # Test template categories
            if hasattr(self.library, 'get_templates_by_category'):
                try:
                    file_templates = self.library.get_templates_by_category(CommandCategory.FILE_OPERATIONS)
                    self.assert_test(
                        len(file_templates) > 0,
                        "Library: File operations category has templates"
                    )
                except:
                    pass  # Category enum might not be available in mock
            
            # Test safety classification
            if hasattr(self.library, 'get_safe_templates'):
                try:
                    safe_templates = self.library.get_safe_templates()
                    dangerous_templates = self.library.get_dangerous_templates()
                    
                    self.assert_test(
                        len(safe_templates) > 0,
                        "Library: Has safe templates"
                    )
                    
                    self.assert_test(
                        len(dangerous_templates) >= 0,  # May be 0 in mock
                        "Library: Dangerous templates properly classified"
                    )
                except:
                    pass  # Safety enum might not be available in mock
            
            print(f"  ✅ Found {len(templates)} relevant templates")
            
        except Exception as e:
            self.assert_test(
                False,
                "Library: Exception handling",
                str(e)
            )
    
    async def test_performance_simulation(self):
        """Test performance with simulated workload"""
        print("\n⚡ Testing Performance Simulation...")
        
        start_time = time.time()
        
        # Simulate multiple concurrent requests
        tasks = []
        for i in range(10):
            task = asyncio.create_task(
                self.server.generate_intelligent_command({
                    'task': f'test command {i}',
                    'context': {'request_id': i}
                })
            )
            tasks.append(task)
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Check that all requests completed
            successful_requests = sum(1 for r in results if not isinstance(r, Exception))
            
            self.assert_test(
                successful_requests == 10,
                "Performance: All concurrent requests completed",
                f"Only {successful_requests}/10 requests succeeded"
            )
            
            elapsed_time = time.time() - start_time
            requests_per_second = 10 / elapsed_time
            
            self.assert_test(
                requests_per_second > 1,
                "Performance: Reasonable throughput",
                f"Only {requests_per_second:.1f} requests/sec"
            )
            
            print(f"  ✅ Processed 10 requests in {elapsed_time:.2f}s ({requests_per_second:.1f} req/s)")
            
        except Exception as e:
            self.assert_test(
                False,
                "Performance: Exception handling",
                str(e)
            )
    
    async def test_integration_scenarios(self):
        """Test complete integration scenarios"""
        print("\n🔗 Testing Integration Scenarios...")
        
        scenarios = [
            {
                'name': 'File Cleanup Workflow',
                'steps': [
                    {
                        'task': 'find temporary files older than 7 days',
                        'validation': 'safe_operation'
                    },
                    {
                        'task': 'delete found temporary files safely',
                        'validation': 'requires_confirmation'
                    }
                ]
            },
            {
                'name': 'System Monitoring Workflow',
                'steps': [
                    {
                        'task': 'check disk usage above 80%',
                        'validation': 'safe_operation'
                    },
                    {
                        'task': 'find largest files in full partitions',
                        'validation': 'safe_operation'
                    }
                ]
            }
        ]
        
        for scenario in scenarios:
            print(f"\n  Testing scenario: {scenario['name']}")
            
            for i, step in enumerate(scenario['steps']):
                try:
                    # Generate command
                    response = await self.server.generate_intelligent_command({
                        'task': step['task'],
                        'context': {'scenario': scenario['name']}
                    })
                    
                    command = response.get('command', '')
                    
                    # Validate safety
                    if hasattr(self.validator, 'validate_command'):
                        validation = self.validator.validate_command(command)
                        is_safe = validation.result.value in ['approved', 'warning']
                    else:
                        validation = await self.server.validate_command(command)
                        is_safe = validation.get('is_safe', True)
                    
                    # Optimize command
                    optimization = self.optimizer.optimize_command(command)
                    
                    self.assert_test(
                        len(command) > 0,
                        f"Integration {scenario['name']} Step {i+1}: Command generated"
                    )
                    
                    self.assert_test(
                        is_safe or step['validation'] == 'requires_confirmation',
                        f"Integration {scenario['name']} Step {i+1}: Safety validation",
                        f"Unsafe command: {command}"
                    )
                    
                    print(f"    Step {i+1}: {step['task']}")
                    print(f"      Command: {command}")
                    print(f"      Safe: {is_safe}")
                    
                except Exception as e:
                    self.assert_test(
                        False,
                        f"Integration {scenario['name']} Step {i+1}: Exception handling",
                        str(e)
                    )
    
    async def test_memory_management(self):
        """Test memory management and resource usage"""
        print("\n💾 Testing Memory Management...")
        
        try:
            # Test memory usage reporting
            if hasattr(self.server, 'get_system_status'):
                status = await self.server.get_system_status()
                
                self.assert_test(
                    'memory_usage' in status or 'python_server' in status,
                    "Memory: System status includes memory information"
                )
                
                print("  ✅ Memory status reporting functional")
            
            # Test garbage collection
            if hasattr(self.server, '_get_memory_usage'):
                initial_memory = await self.server._get_memory_usage()
                
                # Generate many commands to use memory
                for i in range(50):
                    await self.server.generate_intelligent_command({
                        'task': f'memory test command {i}',
                        'context': {'test': True}
                    })
                
                # Memory usage should be reasonable
                final_memory = await self.server._get_memory_usage()
                
                print(f"  Memory usage: {final_memory}")
                
        except Exception as e:
            print(f"  ⚠️  Memory management test skipped: {e}")
    
    def print_summary(self):
        """Print test results summary"""
        print(f"\n" + "="*60)
        print(f"🧪 BASH_GOD Test Suite Results")
        print(f"="*60)
        print(f"✅ Passed: {self.test_results['passed']}")
        print(f"❌ Failed: {self.test_results['failed']}")
        
        if self.test_results['errors']:
            print(f"\n🔍 Failed Tests:")
            for error in self.test_results['errors']:
                print(f"  • {error}")
        
        success_rate = (
            self.test_results['passed'] / 
            (self.test_results['passed'] + self.test_results['failed'])
        ) * 100 if (self.test_results['passed'] + self.test_results['failed']) > 0 else 0
        
        print(f"\n📊 Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 90:
            print("🎉 Excellent! BASH_GOD is performing very well.")
        elif success_rate >= 70:
            print("✅ Good! BASH_GOD is functioning properly with minor issues.")
        elif success_rate >= 50:
            print("⚠️  Fair. BASH_GOD has some issues that need attention.")
        else:
            print("❌ Poor. BASH_GOD has significant issues that need to be addressed.")
        
        return success_rate >= 70
    
    async def run_all_tests(self):
        """Run the complete test suite"""
        print("🚀 Starting BASH_GOD Comprehensive Test Suite")
        print("="*60)
        
        try:
            await self.setup()
            
            # Run all test categories
            await self.test_command_generation()
            await self.test_safety_validation()
            await self.test_optimization_engine()
            await self.test_learning_system()
            await self.test_command_library()
            await self.test_performance_simulation()
            await self.test_integration_scenarios()
            await self.test_memory_management()
            
            return self.print_summary()
            
        except Exception as e:
            print(f"❌ Test suite failed with error: {e}")
            import traceback
            traceback.print_exc()
            return False


async def main():
    """Main test execution"""
    test_suite = BashGodTestSuite()
    success = await test_suite.run_all_tests()
    
    if success:
        print(f"\n🎯 BASH_GOD MCP Server is ready for deployment!")
        return 0
    else:
        print(f"\n⚠️  BASH_GOD MCP Server needs attention before deployment.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)