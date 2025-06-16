#!/usr/bin/env python3
"""
AGENT 6: Real MCP Server Communication Tests
Specialized module for testing actual MCP server processes with real JSON-RPC communication.
"""

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
import socket
import signal
import os

class RealMCPServerTester:
    """Tests real MCP servers with actual process communication."""
    
    def __init__(self):
        self.base_dir = Path("/home/louranicas/projects/claude-optimized-deployment")
        self.active_processes = {}
        self.test_results = {}
        
    async def test_npm_mcp_servers(self) -> Dict[str, Any]:
        """Test official npm MCP servers."""
        print("🔧 Testing npm MCP Servers...")
        
        # List of working npm servers based on Agent 5 findings
        npm_servers = [
            {
                'name': 'filesystem',
                'package': '@modelcontextprotocol/server-filesystem',
                'args': ['/tmp']  # Safe test directory
            },
            {
                'name': 'memory',
                'package': '@modelcontextprotocol/server-memory',
                'args': []
            },
            {
                'name': 'brave-search',
                'package': '@modelcontextprotocol/server-brave-search',
                'args': [],
                'env': {'BRAVE_API_KEY': 'BSAigVAUU4-V72PjB48t8_CqN00Hh5z'}
            }
        ]
        
        results = {}
        
        for server_config in npm_servers:
            print(f"\n🎯 Testing {server_config['name']}...")
            try:
                result = await self._test_npm_server(server_config)
                results[server_config['name']] = result
                
                status = "✅ PASS" if result.get('success', False) else "❌ FAIL"
                print(f"   {status}: {result.get('summary', 'No summary')}")
                
            except Exception as e:
                results[server_config['name']] = {
                    'success': False,
                    'error': str(e),
                    'summary': f"Exception during test: {e}"
                }
                print(f"   ❌ FAIL: {e}")
        
        return results
    
    async def _test_npm_server(self, server_config: Dict) -> Dict[str, Any]:
        """Test an individual npm MCP server."""
        server_name = server_config['name']
        package = server_config['package']
        args = server_config.get('args', [])
        env = server_config.get('env', {})
        
        result = {
            'server_name': server_name,
            'package': package,
            'success': False,
            'startup_time': 0,
            'handshake_success': False,
            'tools_discovered': 0,
            'tool_execution_success': False,
            'error': None
        }
        
        process = None
        try:
            # Start the server process
            start_time = time.time()
            
            cmd = ['npx', '-y', package] + args
            process_env = {**os.environ, **env}
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=process_env,
                preexec_fn=os.setsid  # Create new process group for clean termination
            )
            
            self.active_processes[server_name] = process
            
            # Wait for server to start (max 10 seconds)
            startup_timeout = 10
            startup_success = False
            
            for i in range(startup_timeout * 10):  # Check every 100ms
                if process.poll() is not None:
                    # Process died
                    stderr_output = process.stderr.read()
                    result['error'] = f"Process died during startup: {stderr_output}"
                    return result
                
                await asyncio.sleep(0.1)
                
                # Try a simple ping to see if server is responsive
                if i > 10:  # Wait at least 1 second before trying
                    try:
                        # Send initialize request
                        init_request = {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2024-11-05",
                                "capabilities": {}
                            }
                        }
                        
                        request_json = json.dumps(init_request) + '\n'
                        process.stdin.write(request_json)
                        process.stdin.flush()
                        
                        # Try to read response (non-blocking)
                        if process.stdout.readable():
                            startup_success = True
                            break
                            
                    except:
                        continue
            
            result['startup_time'] = time.time() - start_time
            
            if not startup_success:
                result['error'] = f"Server failed to start within {startup_timeout} seconds"
                return result
            
            # Test MCP handshake
            try:
                handshake_result = await self._test_mcp_handshake(process)
                result['handshake_success'] = handshake_result.get('success', False)
                if not result['handshake_success']:
                    result['error'] = handshake_result.get('error', 'Handshake failed')
                    return result
            except Exception as e:
                result['error'] = f"Handshake error: {e}"
                return result
            
            # Test tool discovery
            try:
                tools_result = await self._test_tool_discovery(process)
                result['tools_discovered'] = tools_result.get('tool_count', 0)
                
                if result['tools_discovered'] > 0:
                    # Test tool execution
                    execution_result = await self._test_tool_execution(process, tools_result.get('tools', []))
                    result['tool_execution_success'] = execution_result.get('success', False)
                
            except Exception as e:
                result['error'] = f"Tool testing error: {e}"
                return result
            
            # If we got this far, the test was successful
            result['success'] = True
            result['summary'] = f"Server working: {result['tools_discovered']} tools, handshake OK"
            
        except Exception as e:
            result['error'] = str(e)
            result['summary'] = f"Test failed: {e}"
        
        finally:
            # Clean up process
            if process and process.poll() is None:
                try:
                    # Send SIGTERM to process group
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    await asyncio.sleep(1)
                    
                    # If still running, send SIGKILL
                    if process.poll() is None:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except:
                    pass
            
            if server_name in self.active_processes:
                del self.active_processes[server_name]
        
        return result
    
    async def _test_mcp_handshake(self, process: subprocess.Popen) -> Dict[str, Any]:
        """Test MCP initialize/initialized handshake."""
        try:
            # Send initialize request
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "roots": {"listChanged": True},
                        "sampling": {}
                    },
                    "clientInfo": {
                        "name": "agent-6-integration-tester",
                        "version": "1.0.0"
                    }
                }
            }
            
            request_json = json.dumps(init_request) + '\n'
            process.stdin.write(request_json)
            process.stdin.flush()
            
            # Read response with timeout
            response = await asyncio.wait_for(
                asyncio.to_thread(self._read_json_response, process),
                timeout=5.0
            )
            
            if not response:
                return {'success': False, 'error': 'No response received'}
            
            # Check if response is valid
            if 'result' not in response:
                return {'success': False, 'error': f'Invalid response: {response}'}
            
            # Send initialized notification
            initialized_notification = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }
            
            notification_json = json.dumps(initialized_notification) + '\n'
            process.stdin.write(notification_json)
            process.stdin.flush()
            
            return {
                'success': True,
                'server_info': response.get('result', {}),
                'protocol_version': response.get('result', {}).get('protocolVersion'),
                'capabilities': response.get('result', {}).get('capabilities', {})
            }
            
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Handshake timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _test_tool_discovery(self, process: subprocess.Popen) -> Dict[str, Any]:
        """Test tool discovery via tools/list."""
        try:
            # Send tools/list request
            tools_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }
            
            request_json = json.dumps(tools_request) + '\n'
            process.stdin.write(request_json)
            process.stdin.flush()
            
            # Read response
            response = await asyncio.wait_for(
                asyncio.to_thread(self._read_json_response, process),
                timeout=5.0
            )
            
            if not response or 'result' not in response:
                return {'success': False, 'error': 'No tools list received'}
            
            tools = response.get('result', {}).get('tools', [])
            
            return {
                'success': True,
                'tool_count': len(tools),
                'tools': tools
            }
            
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Tool discovery timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _test_tool_execution(self, process: subprocess.Popen, tools: List[Dict]) -> Dict[str, Any]:
        """Test executing a tool if available."""
        if not tools:
            return {'success': False, 'error': 'No tools available'}
        
        try:
            # Use the first tool for testing
            tool = tools[0]
            tool_name = tool.get('name')
            
            if not tool_name:
                return {'success': False, 'error': 'Tool has no name'}
            
            # Prepare minimal arguments based on tool schema
            tool_args = {}
            
            # For filesystem tools, provide safe test paths
            if 'path' in tool.get('inputSchema', {}).get('properties', {}):
                tool_args['path'] = '/tmp'
            
            # For search tools, provide test query
            if 'query' in tool.get('inputSchema', {}).get('properties', {}):
                tool_args['query'] = 'test'
            
            # Send tool execution request
            call_request = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": tool_args
                }
            }
            
            request_json = json.dumps(call_request) + '\n'
            process.stdin.write(request_json)
            process.stdin.flush()
            
            # Read response
            response = await asyncio.wait_for(
                asyncio.to_thread(self._read_json_response, process),
                timeout=10.0
            )
            
            if not response:
                return {'success': False, 'error': 'No tool execution response'}
            
            if 'error' in response:
                return {
                    'success': False, 
                    'error': f"Tool execution error: {response['error']}"
                }
            
            if 'result' in response:
                return {
                    'success': True,
                    'tool_name': tool_name,
                    'result': response['result']
                }
            
            return {'success': False, 'error': 'Unexpected response format'}
            
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Tool execution timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _read_json_response(self, process: subprocess.Popen) -> Optional[Dict]:
        """Read a JSON response from the process stdout."""
        try:
            # Read line by line until we get a complete JSON
            for _ in range(10):  # Max 10 attempts
                line = process.stdout.readline()
                if not line:
                    return None
                
                line = line.strip()
                if not line:
                    continue
                
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
            
            return None
        except Exception:
            return None
    
    async def test_python_mcp_servers(self) -> Dict[str, Any]:
        """Test custom Python MCP servers."""
        print("🐍 Testing Python MCP Servers...")
        
        python_servers = [
            {
                'name': 'development-server',
                'script': self.base_dir / 'mcp_learning_system' / 'servers' / 'development' / 'server.py'
            },
            {
                'name': 'devops-server', 
                'script': self.base_dir / 'mcp_learning_system' / 'servers' / 'devops' / 'server.py'
            }
        ]
        
        results = {}
        
        for server_config in python_servers:
            print(f"\n🎯 Testing {server_config['name']}...")
            
            if not server_config['script'].exists():
                results[server_config['name']] = {
                    'success': False,
                    'error': f"Script not found: {server_config['script']}",
                    'summary': "Server script missing"
                }
                print(f"   ❌ FAIL: Script not found")
                continue
            
            try:
                result = await self._test_python_server(server_config)
                results[server_config['name']] = result
                
                status = "✅ PASS" if result.get('success', False) else "❌ FAIL"
                print(f"   {status}: {result.get('summary', 'No summary')}")
                
            except Exception as e:
                results[server_config['name']] = {
                    'success': False,
                    'error': str(e),
                    'summary': f"Exception during test: {e}"
                }
                print(f"   ❌ FAIL: {e}")
        
        return results
    
    async def _test_python_server(self, server_config: Dict) -> Dict[str, Any]:
        """Test a Python MCP server."""
        server_name = server_config['name']
        script_path = server_config['script']
        
        result = {
            'server_name': server_name,
            'script_path': str(script_path),
            'success': False,
            'startup_time': 0,
            'import_success': False,
            'error': None
        }
        
        try:
            # Test if the Python script can be imported/executed
            start_time = time.time()
            
            # Try to run the script as a subprocess to test imports
            process = subprocess.Popen(
                [sys.executable, '-c', f'import sys; sys.path.insert(0, "{script_path.parent}"); exec(open("{script_path}").read())'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for completion or timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    asyncio.to_thread(process.communicate),
                    timeout=5.0
                )
                
                result['startup_time'] = time.time() - start_time
                
                if process.returncode == 0:
                    result['import_success'] = True
                    result['success'] = True
                    result['summary'] = "Python server imports and runs successfully"
                else:
                    result['error'] = f"Script failed with return code {process.returncode}: {stderr}"
                    result['summary'] = "Python server has import/runtime errors"
                
            except asyncio.TimeoutError:
                process.kill()
                result['error'] = "Script execution timeout"
                result['summary'] = "Python server startup timeout"
            
        except Exception as e:
            result['error'] = str(e)
            result['summary'] = f"Test failed: {e}"
        
        return result
    
    async def test_rust_mcp_servers(self) -> Dict[str, Any]:
        """Test Rust MCP servers."""
        print("🦀 Testing Rust MCP Servers...")
        
        rust_servers = [
            {
                'name': 'quality-server',
                'manifest': self.base_dir / 'mcp_learning_system' / 'servers' / 'quality' / 'Cargo.toml'
            },
            {
                'name': 'bash-god-server',
                'manifest': self.base_dir / 'mcp_learning_system' / 'servers' / 'bash_god' / 'Cargo.toml'
            }
        ]
        
        results = {}
        
        for server_config in rust_servers:
            print(f"\n🎯 Testing {server_config['name']}...")
            
            if not server_config['manifest'].exists():
                results[server_config['name']] = {
                    'success': False,
                    'error': f"Cargo.toml not found: {server_config['manifest']}",
                    'summary': "Rust manifest missing"
                }
                print(f"   ❌ FAIL: Cargo.toml not found")
                continue
            
            try:
                result = await self._test_rust_server(server_config)
                results[server_config['name']] = result
                
                status = "✅ PASS" if result.get('success', False) else "❌ FAIL"
                print(f"   {status}: {result.get('summary', 'No summary')}")
                
            except Exception as e:
                results[server_config['name']] = {
                    'success': False,
                    'error': str(e),
                    'summary': f"Exception during test: {e}"
                }
                print(f"   ❌ FAIL: {e}")
        
        return results
    
    async def _test_rust_server(self, server_config: Dict) -> Dict[str, Any]:
        """Test a Rust MCP server."""
        server_name = server_config['name']
        manifest_path = server_config['manifest']
        
        result = {
            'server_name': server_name,
            'manifest_path': str(manifest_path),
            'success': False,
            'build_time': 0,
            'build_success': False,
            'error': None
        }
        
        try:
            # Test if the Rust project can be compiled
            start_time = time.time()
            
            process = subprocess.Popen(
                ['cargo', 'check', '--manifest-path', str(manifest_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=manifest_path.parent
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    asyncio.to_thread(process.communicate),
                    timeout=30.0  # Rust builds can take longer
                )
                
                result['build_time'] = time.time() - start_time
                
                if process.returncode == 0:
                    result['build_success'] = True
                    result['success'] = True
                    result['summary'] = f"Rust server compiles successfully ({result['build_time']:.1f}s)"
                else:
                    result['error'] = f"Cargo check failed: {stderr}"
                    result['summary'] = "Rust server has compilation errors"
                
            except asyncio.TimeoutError:
                process.kill()
                result['error'] = "Rust compilation timeout"
                result['summary'] = "Rust server compilation timeout (>30s)"
            
        except Exception as e:
            result['error'] = str(e)
            result['summary'] = f"Test failed: {e}"
        
        return result
    
    async def cleanup_all_processes(self):
        """Clean up all active test processes."""
        for server_name, process in self.active_processes.items():
            try:
                if process.poll() is None:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    await asyncio.sleep(0.5)
                    if process.poll() is None:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except:
                pass
        
        self.active_processes.clear()


async def main():
    """Run real MCP server communication tests."""
    print("🔧 AGENT 6: Real MCP Server Communication Tests")
    print("=" * 60)
    
    tester = RealMCPServerTester()
    
    try:
        # Test all server types
        npm_results = await tester.test_npm_mcp_servers()
        python_results = await tester.test_python_mcp_servers()
        rust_results = await tester.test_rust_mcp_servers()
        
        # Compile results
        all_results = {
            'npm_servers': npm_results,
            'python_servers': python_results,
            'rust_servers': rust_results,
            'summary': {
                'npm_working': sum(1 for r in npm_results.values() if r.get('success', False)),
                'python_working': sum(1 for r in python_results.values() if r.get('success', False)),
                'rust_working': sum(1 for r in rust_results.values() if r.get('success', False)),
                'total_working': 0,
                'total_tested': len(npm_results) + len(python_results) + len(rust_results)
            }
        }
        
        all_results['summary']['total_working'] = (
            all_results['summary']['npm_working'] + 
            all_results['summary']['python_working'] + 
            all_results['summary']['rust_working']
        )
        
        # Print summary
        print(f"\n📊 Real MCP Server Test Summary:")
        print(f"   npm servers working: {all_results['summary']['npm_working']}/{len(npm_results)}")
        print(f"   Python servers working: {all_results['summary']['python_working']}/{len(python_results)}")
        print(f"   Rust servers working: {all_results['summary']['rust_working']}/{len(rust_results)}")
        print(f"   Total working: {all_results['summary']['total_working']}/{all_results['summary']['total_tested']}")
        
        # Save results
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f'/home/louranicas/projects/claude-optimized-deployment/agent_6_real_mcp_server_test_results_{timestamp}.json'
        
        with open(report_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        print(f"\n💾 Results saved to: {report_file}")
        return all_results
        
    except Exception as e:
        print(f"❌ Real MCP server testing failed: {e}")
        return None
    
    finally:
        await tester.cleanup_all_processes()


if __name__ == "__main__":
    asyncio.run(main())