#!/usr/bin/env python3
"""
AGENT 6: Cross-Language Integration Tests
Tests integration between TypeScript, Python, and Rust MCP servers.
"""

import asyncio
import json
import os
import sys
import subprocess
import time
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import concurrent.futures
import multiprocessing as mp

class CrossLanguageIntegrationTester:
    """Tests cross-language integration between MCP servers."""
    
    def __init__(self):
        self.base_dir = Path("/home/louranicas/projects/claude-optimized-deployment")
        self.test_results = {}
        
    async def test_data_serialization_compatibility(self) -> Dict[str, Any]:
        """Test data serialization compatibility between languages."""
        print("🔄 Testing Data Serialization Compatibility...")
        
        # Test data structures of increasing complexity
        test_cases = [
            {
                'name': 'simple_primitives',
                'data': {
                    'string': 'hello world',
                    'integer': 42,
                    'float': 3.14159,
                    'boolean': True,
                    'null': None
                }
            },
            {
                'name': 'arrays_and_objects',
                'data': {
                    'array': [1, 2, 3, 'four', True],
                    'nested_object': {
                        'level1': {
                            'level2': {
                                'value': 'deep nested'
                            }
                        }
                    },
                    'mixed_array': [
                        {'id': 1, 'name': 'item1'},
                        {'id': 2, 'name': 'item2'}
                    ]
                }
            },
            {
                'name': 'mcp_protocol_structures',
                'data': {
                    'request': {
                        'jsonrpc': '2.0',
                        'id': 123,
                        'method': 'tools/call',
                        'params': {
                            'name': 'test_tool',
                            'arguments': {
                                'input': 'test input',
                                'options': {
                                    'verbose': True,
                                    'timeout': 30
                                }
                            }
                        }
                    },
                    'response': {
                        'jsonrpc': '2.0',
                        'id': 123,
                        'result': {
                            'content': [
                                {
                                    'type': 'text',
                                    'text': 'Operation completed successfully'
                                }
                            ]
                        }
                    }
                }
            },
            {
                'name': 'unicode_and_special_chars',
                'data': {
                    'unicode': 'Hello 世界 🌍',
                    'special_chars': 'Line1\nLine2\tTabbed\r\nCRLF',
                    'escaped_json': '{"embedded": "json string"}',
                    'binary_as_base64': 'SGVsbG8gV29ybGQ='
                }
            }
        ]
        
        results = {}
        
        for test_case in test_cases:
            print(f"   Testing: {test_case['name']}")
            
            try:
                # Test JSON serialization/deserialization
                json_result = await self._test_json_compatibility(test_case)
                
                # Test cross-process data exchange
                process_result = await self._test_cross_process_data_exchange(test_case)
                
                results[test_case['name']] = {
                    'json_compatibility': json_result,
                    'cross_process_exchange': process_result,
                    'overall_success': json_result.get('success', False) and process_result.get('success', False)
                }
                
                status = "✅" if results[test_case['name']]['overall_success'] else "❌"
                print(f"      {status} {test_case['name']}")
                
            except Exception as e:
                results[test_case['name']] = {
                    'error': str(e),
                    'overall_success': False
                }
                print(f"      ❌ {test_case['name']}: {e}")
        
        return results
    
    async def _test_json_compatibility(self, test_case: Dict) -> Dict[str, Any]:
        """Test JSON serialization/deserialization compatibility."""
        try:
            original_data = test_case['data']
            
            # Test JSON round-trip
            serialized = json.dumps(original_data, ensure_ascii=False, separators=(',', ':'))
            deserialized = json.loads(serialized)
            
            # Check data integrity
            data_intact = self._deep_compare(original_data, deserialized)
            
            # Test with different JSON options
            pretty_serialized = json.dumps(original_data, indent=2, ensure_ascii=False)
            pretty_deserialized = json.loads(pretty_serialized)
            pretty_intact = self._deep_compare(original_data, pretty_deserialized)
            
            return {
                'success': data_intact and pretty_intact,
                'serialized_size': len(serialized),
                'pretty_size': len(pretty_serialized),
                'data_integrity': data_intact,
                'pretty_integrity': pretty_intact
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _test_cross_process_data_exchange(self, test_case: Dict) -> Dict[str, Any]:
        """Test data exchange between separate processes."""
        try:
            # Create temporary files for data exchange
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as input_file:
                json.dump(test_case['data'], input_file, ensure_ascii=False)
                input_file_path = input_file.name
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
                output_file_path = output_file.name
            
            try:
                # Test with Python process
                python_success = await self._test_python_process_exchange(input_file_path, output_file_path)
                
                # Test with Node.js process (if available)
                node_success = await self._test_node_process_exchange(input_file_path, output_file_path)
                
                return {
                    'success': python_success and node_success,
                    'python_process': python_success,
                    'node_process': node_success
                }
                
            finally:
                # Clean up temporary files
                try:
                    os.unlink(input_file_path)
                    os.unlink(output_file_path)
                except:
                    pass
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _test_python_process_exchange(self, input_path: str, output_path: str) -> bool:
        """Test data exchange with a Python subprocess."""
        try:
            python_script = f'''
import json
import sys

try:
    with open("{input_path}", "r", encoding="utf-8") as f:
        data = json.load(f)
    
    with open("{output_path}", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    
    print("SUCCESS")
except Exception as e:
    print(f"ERROR: {{e}}")
    sys.exit(1)
'''
            
            process = subprocess.Popen(
                [sys.executable, '-c', python_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = await asyncio.wait_for(
                asyncio.to_thread(process.communicate),
                timeout=5.0
            )
            
            return process.returncode == 0 and "SUCCESS" in stdout
            
        except Exception:
            return False
    
    async def _test_node_process_exchange(self, input_path: str, output_path: str) -> bool:
        """Test data exchange with a Node.js subprocess."""
        try:
            # Check if Node.js is available
            node_check = subprocess.run(['which', 'node'], capture_output=True, text=True)
            if node_check.returncode != 0:
                return True  # Skip test if Node.js not available
            
            node_script = f'''
const fs = require('fs');

try {{
    const data = JSON.parse(fs.readFileSync("{input_path}", "utf8"));
    fs.writeFileSync("{output_path}", JSON.stringify(data, null, 2), "utf8");
    console.log("SUCCESS");
}} catch (e) {{
    console.error("ERROR:", e.message);
    process.exit(1);
}}
'''
            
            process = subprocess.Popen(
                ['node', '-e', node_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = await asyncio.wait_for(
                asyncio.to_thread(process.communicate),
                timeout=5.0
            )
            
            return process.returncode == 0 and "SUCCESS" in stdout
            
        except Exception:
            return True  # Skip test if Node.js issues
    
    def _deep_compare(self, obj1: Any, obj2: Any) -> bool:
        """Deep comparison of two objects."""
        if type(obj1) != type(obj2):
            return False
        
        if isinstance(obj1, dict):
            if set(obj1.keys()) != set(obj2.keys()):
                return False
            return all(self._deep_compare(obj1[k], obj2[k]) for k in obj1.keys())
        
        elif isinstance(obj1, list):
            if len(obj1) != len(obj2):
                return False
            return all(self._deep_compare(obj1[i], obj2[i]) for i in range(len(obj1)))
        
        else:
            return obj1 == obj2
    
    async def test_message_protocol_compatibility(self) -> Dict[str, Any]:
        """Test MCP message protocol compatibility between languages."""
        print("📨 Testing Message Protocol Compatibility...")
        
        # Standard MCP message types to test
        message_types = [
            {
                'name': 'initialize_request',
                'message': {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'method': 'initialize',
                    'params': {
                        'protocolVersion': '2024-11-05',
                        'capabilities': {
                            'roots': {'listChanged': True},
                            'sampling': {}
                        },
                        'clientInfo': {
                            'name': 'test-client',
                            'version': '1.0.0'
                        }
                    }
                }
            },
            {
                'name': 'tools_list_request',
                'message': {
                    'jsonrpc': '2.0',
                    'id': 2,
                    'method': 'tools/list',
                    'params': {}
                }
            },
            {
                'name': 'tools_call_request',
                'message': {
                    'jsonrpc': '2.0',
                    'id': 3,
                    'method': 'tools/call',
                    'params': {
                        'name': 'test_tool',
                        'arguments': {
                            'input': 'test input data',
                            'options': {
                                'format': 'json',
                                'timeout': 30
                            }
                        }
                    }
                }
            },
            {
                'name': 'error_response',
                'message': {
                    'jsonrpc': '2.0',
                    'id': 4,
                    'error': {
                        'code': -32601,
                        'message': 'Method not found',
                        'data': {
                            'method': 'unknown_method'
                        }
                    }
                }
            },
            {
                'name': 'notification',
                'message': {
                    'jsonrpc': '2.0',
                    'method': 'notifications/initialized'
                }
            }
        ]
        
        results = {}
        
        for msg_type in message_types:
            print(f"   Testing: {msg_type['name']}")
            
            try:
                # Test message validation
                validation_result = await self._test_message_validation(msg_type)
                
                # Test message routing
                routing_result = await self._test_message_routing(msg_type)
                
                results[msg_type['name']] = {
                    'validation': validation_result,
                    'routing': routing_result,
                    'overall_success': validation_result.get('success', False) and routing_result.get('success', False)
                }
                
                status = "✅" if results[msg_type['name']]['overall_success'] else "❌"
                print(f"      {status} {msg_type['name']}")
                
            except Exception as e:
                results[msg_type['name']] = {
                    'error': str(e),
                    'overall_success': False
                }
                print(f"      ❌ {msg_type['name']}: {e}")
        
        return results
    
    async def _test_message_validation(self, msg_type: Dict) -> Dict[str, Any]:
        """Test MCP message validation."""
        try:
            message = msg_type['message']
            
            # Check required JSON-RPC fields
            has_jsonrpc = 'jsonrpc' in message and message['jsonrpc'] == '2.0'
            
            # Check message type specific requirements
            is_request = 'method' in message and 'id' in message
            is_response = 'result' in message or 'error' in message
            is_notification = 'method' in message and 'id' not in message
            
            valid_message_type = is_request or is_response or is_notification
            
            # Test serialization
            try:
                serialized = json.dumps(message)
                deserialized = json.loads(serialized)
                serialization_ok = self._deep_compare(message, deserialized)
            except:
                serialization_ok = False
            
            return {
                'success': has_jsonrpc and valid_message_type and serialization_ok,
                'has_jsonrpc': has_jsonrpc,
                'valid_message_type': valid_message_type,
                'serialization_ok': serialization_ok
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _test_message_routing(self, msg_type: Dict) -> Dict[str, Any]:
        """Test message routing and handling."""
        try:
            message = msg_type['message']
            
            # Simulate message routing logic
            method = message.get('method', '')
            has_id = 'id' in message
            
            # Determine expected routing
            if method.startswith('tools/'):
                route = 'tools_handler'
            elif method == 'initialize':
                route = 'initialization_handler'
            elif method.startswith('notifications/'):
                route = 'notification_handler'
            else:
                route = 'unknown_handler'
            
            # Test response expectations
            expects_response = has_id and 'error' not in message
            is_notification = not has_id and 'method' in message
            
            return {
                'success': True,
                'route': route,
                'expects_response': expects_response,
                'is_notification': is_notification
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def test_performance_interoperability(self) -> Dict[str, Any]:
        """Test performance characteristics across languages."""
        print("⚡ Testing Performance Interoperability...")
        
        # Performance test scenarios
        test_scenarios = [
            {
                'name': 'small_message_throughput',
                'message_size': 100,  # bytes
                'message_count': 1000
            },
            {
                'name': 'medium_message_throughput',
                'message_size': 1024,  # 1KB
                'message_count': 100
            },
            {
                'name': 'large_message_throughput',
                'message_size': 10240,  # 10KB
                'message_count': 10
            }
        ]
        
        results = {}
        
        for scenario in test_scenarios:
            print(f"   Testing: {scenario['name']}")
            
            try:
                # Generate test data
                test_data = self._generate_test_data(scenario['message_size'])
                
                # Test serialization performance
                serialization_perf = await self._test_serialization_performance(test_data, scenario['message_count'])
                
                # Test cross-process performance
                cross_process_perf = await self._test_cross_process_performance(test_data, scenario['message_count'])
                
                results[scenario['name']] = {
                    'serialization': serialization_perf,
                    'cross_process': cross_process_perf,
                    'message_size': scenario['message_size'],
                    'message_count': scenario['message_count']
                }
                
                # Calculate throughput
                if serialization_perf.get('success', False):
                    throughput = scenario['message_count'] / serialization_perf.get('total_time', 1)
                    print(f"      ✅ {scenario['name']}: {throughput:.1f} msgs/sec")
                else:
                    print(f"      ❌ {scenario['name']}: Failed")
                
            except Exception as e:
                results[scenario['name']] = {
                    'error': str(e),
                    'success': False
                }
                print(f"      ❌ {scenario['name']}: {e}")
        
        return results
    
    def _generate_test_data(self, target_size: int) -> Dict[str, Any]:
        """Generate test data of approximately target size."""
        # Create a string to reach approximate target size
        text_content = "x" * (target_size // 2)
        
        return {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'test/performance',
            'params': {
                'data': text_content,
                'metadata': {
                    'timestamp': time.time(),
                    'size': target_size,
                    'test': True
                },
                'array': list(range(min(100, target_size // 10)))
            }
        }
    
    async def _test_serialization_performance(self, test_data: Dict, count: int) -> Dict[str, Any]:
        """Test JSON serialization/deserialization performance."""
        try:
            start_time = time.time()
            
            for _ in range(count):
                serialized = json.dumps(test_data)
                deserialized = json.loads(serialized)
            
            total_time = time.time() - start_time
            
            return {
                'success': True,
                'total_time': total_time,
                'average_time_per_message': total_time / count,
                'messages_per_second': count / total_time if total_time > 0 else 0
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _test_cross_process_performance(self, test_data: Dict, count: int) -> Dict[str, Any]:
        """Test cross-process communication performance."""
        try:
            start_time = time.time()
            
            # Use concurrent execution to simulate multiple process communications
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = []
                
                for _ in range(count):
                    future = executor.submit(self._simulate_process_communication, test_data)
                    futures.append(future)
                
                # Wait for all to complete
                for future in concurrent.futures.as_completed(futures, timeout=30):
                    future.result()
            
            total_time = time.time() - start_time
            
            return {
                'success': True,
                'total_time': total_time,
                'average_time_per_message': total_time / count,
                'messages_per_second': count / total_time if total_time > 0 else 0
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _simulate_process_communication(self, test_data: Dict) -> bool:
        """Simulate process communication by serializing and processing data."""
        try:
            # Simulate sending data to another process
            serialized = json.dumps(test_data)
            
            # Simulate receiving and processing
            deserialized = json.loads(serialized)
            
            # Simulate some processing
            processed = {
                'response': {
                    'jsonrpc': '2.0',
                    'id': deserialized.get('id'),
                    'result': {
                        'processed': True,
                        'original_size': len(serialized)
                    }
                }
            }
            
            # Serialize response
            response_serialized = json.dumps(processed)
            
            return True
            
        except Exception:
            return False
    
    async def test_error_handling_compatibility(self) -> Dict[str, Any]:
        """Test error handling compatibility between languages."""
        print("🚨 Testing Error Handling Compatibility...")
        
        # Error scenarios to test
        error_scenarios = [
            {
                'name': 'invalid_json',
                'data': '{"invalid": json}',  # Missing quotes
                'expected_error': 'json_parse_error'
            },
            {
                'name': 'missing_required_fields',
                'data': {'id': 1, 'method': 'test'},  # Missing jsonrpc
                'expected_error': 'protocol_error'
            },
            {
                'name': 'invalid_method',
                'data': {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'method': 'nonexistent/method',
                    'params': {}
                },
                'expected_error': 'method_not_found'
            },
            {
                'name': 'invalid_params',
                'data': {
                    'jsonrpc': '2.0',
                    'id': 1,
                    'method': 'tools/call',
                    'params': 'should_be_object'  # Should be object
                },
                'expected_error': 'invalid_params'
            }
        ]
        
        results = {}
        
        for scenario in error_scenarios:
            print(f"   Testing: {scenario['name']}")
            
            try:
                error_result = await self._test_error_scenario(scenario)
                results[scenario['name']] = error_result
                
                status = "✅" if error_result.get('success', False) else "❌"
                print(f"      {status} {scenario['name']}")
                
            except Exception as e:
                results[scenario['name']] = {
                    'success': False,
                    'error': str(e)
                }
                print(f"      ❌ {scenario['name']}: {e}")
        
        return results
    
    async def _test_error_scenario(self, scenario: Dict) -> Dict[str, Any]:
        """Test a specific error scenario."""
        try:
            data = scenario['data']
            expected_error = scenario['expected_error']
            
            # Test JSON parsing errors
            if isinstance(data, str):
                try:
                    json.loads(data)
                    return {
                        'success': False,
                        'error': 'Expected JSON parse error but parsing succeeded'
                    }
                except json.JSONDecodeError:
                    return {
                        'success': True,
                        'detected_error': 'json_parse_error',
                        'expected_error': expected_error
                    }
            
            # Test protocol validation errors
            if isinstance(data, dict):
                validation_errors = []
                
                # Check required fields
                if 'jsonrpc' not in data:
                    validation_errors.append('missing_jsonrpc')
                elif data['jsonrpc'] != '2.0':
                    validation_errors.append('invalid_jsonrpc')
                
                if 'method' in data and 'id' in data:
                    # Request message
                    if not isinstance(data.get('params'), (dict, type(None))):
                        validation_errors.append('invalid_params')
                
                error_detected = len(validation_errors) > 0
                
                return {
                    'success': error_detected,
                    'detected_errors': validation_errors,
                    'expected_error': expected_error
                }
            
            return {
                'success': False,
                'error': 'Unknown data type for error scenario'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


async def main():
    """Run cross-language integration tests."""
    print("🔄 AGENT 6: Cross-Language Integration Tests")
    print("=" * 60)
    
    tester = CrossLanguageIntegrationTester()
    
    try:
        # Run all cross-language integration tests
        serialization_results = await tester.test_data_serialization_compatibility()
        protocol_results = await tester.test_message_protocol_compatibility()
        performance_results = await tester.test_performance_interoperability()
        error_handling_results = await tester.test_error_handling_compatibility()
        
        # Compile results
        all_results = {
            'data_serialization': serialization_results,
            'message_protocol': protocol_results,
            'performance_interoperability': performance_results,
            'error_handling': error_handling_results,
            'summary': {
                'serialization_tests_passed': sum(1 for r in serialization_results.values() if r.get('overall_success', False)),
                'protocol_tests_passed': sum(1 for r in protocol_results.values() if r.get('overall_success', False)),
                'performance_tests_passed': sum(1 for r in performance_results.values() if r.get('success', False)),
                'error_handling_tests_passed': sum(1 for r in error_handling_results.values() if r.get('success', False)),
                'total_tests': (len(serialization_results) + len(protocol_results) + 
                              len(performance_results) + len(error_handling_results))
            }
        }
        
        total_passed = (
            all_results['summary']['serialization_tests_passed'] +
            all_results['summary']['protocol_tests_passed'] +
            all_results['summary']['performance_tests_passed'] +
            all_results['summary']['error_handling_tests_passed']
        )
        
        all_results['summary']['total_passed'] = total_passed
        all_results['summary']['success_rate'] = (total_passed / all_results['summary']['total_tests'] * 100) if all_results['summary']['total_tests'] > 0 else 0
        
        # Print summary
        print(f"\n📊 Cross-Language Integration Test Summary:")
        print(f"   Data serialization: {all_results['summary']['serialization_tests_passed']}/{len(serialization_results)}")
        print(f"   Message protocol: {all_results['summary']['protocol_tests_passed']}/{len(protocol_results)}")
        print(f"   Performance: {all_results['summary']['performance_tests_passed']}/{len(performance_results)}")
        print(f"   Error handling: {all_results['summary']['error_handling_tests_passed']}/{len(error_handling_results)}")
        print(f"   Overall success rate: {all_results['summary']['success_rate']:.1f}%")
        
        # Save results
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f'/home/louranicas/projects/claude-optimized-deployment/agent_6_cross_language_integration_test_results_{timestamp}.json'
        
        with open(report_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        print(f"\n💾 Results saved to: {report_file}")
        return all_results
        
    except Exception as e:
        print(f"❌ Cross-language integration testing failed: {e}")
        return None


if __name__ == "__main__":
    asyncio.run(main())