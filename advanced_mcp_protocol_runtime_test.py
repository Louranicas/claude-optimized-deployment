#!/usr/bin/env python3
"""
AGENT 5 - Advanced MCP Protocol Runtime Testing

This script performs real-time MCP protocol compliance testing by actually starting
and communicating with MCP server instances using proper JSON-RPC over stdio.

RUNTIME TESTING SCOPE:
- Start real MCP server processes
- Perform actual JSON-RPC handshake
- Test real tool execution  
- Validate actual message formats
- Test error handling with real errors
- Performance testing with real latency
- Connection stability testing
"""

import asyncio
import json
import subprocess
import logging
import time
import os
import signal
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import tempfile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MCPRuntimeTester:
    """Real-time MCP protocol testing"""
    
    def __init__(self):
        self.test_results = {}
        self.active_processes = []
        
        # Real MCP servers that can be runtime tested
        self.testable_servers = {
            "filesystem": {
                "command": ["npx", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "description": "File system operations",
                "expected_tools": ["read_file", "write_file", "create_directory", "list_directory"],
                "test_safe": True
            },
            "memory": {
                "command": ["npx", "@modelcontextprotocol/server-memory"],
                "description": "Memory storage",
                "expected_tools": ["create_entities", "search_entities", "read_entity"],
                "test_safe": True
            },
            "sequential-thinking": {
                "command": ["npx", "@modelcontextprotocol/server-sequential-thinking"],
                "description": "Sequential thinking",
                "expected_tools": ["thinking_prompt"],
                "test_safe": True
            },
            # Custom servers in the project
            "bash-god": {
                "command": ["python3", "mcp_learning_system/servers/bash_god/python_src/server.py"],
                "description": "Advanced bash command generation",
                "expected_tools": ["generate_command", "analyze_command", "suggest_optimizations"],
                "test_safe": False  # Potentially unsafe due to bash execution
            }
        }

    async def run_runtime_tests(self) -> Dict[str, Any]:
        """Run comprehensive runtime MCP protocol tests"""
        logger.info("🚀 Starting Runtime MCP Protocol Testing")
        logger.info(f"📋 Testing {len(self.testable_servers)} servers with real processes")
        
        start_time = time.time()
        
        try:
            for server_name, server_config in self.testable_servers.items():
                logger.info(f"\n🧪 Runtime testing {server_name}...")
                
                if not server_config["test_safe"]:
                    logger.warning(f"⚠️ Skipping {server_name} - potentially unsafe for automated testing")
                    self.test_results[server_name] = {
                        "status": "SKIPPED",
                        "reason": "Unsafe for automated testing",
                        "tests": {}
                    }
                    continue
                
                try:
                    result = await self._test_server_runtime(server_name, server_config)
                    self.test_results[server_name] = result
                    
                    if result.get("status") == "SUCCESS":
                        logger.info(f"✅ {server_name}: Runtime tests passed")
                    else:
                        logger.error(f"❌ {server_name}: Runtime tests failed - {result.get('error', 'Unknown')}")
                        
                except Exception as e:
                    logger.error(f"❌ {server_name}: Runtime testing failed - {str(e)}")
                    self.test_results[server_name] = {
                        "status": "ERROR",
                        "error": str(e),
                        "tests": {}
                    }
                    
                # Small delay between server tests
                await asyncio.sleep(1)
                
        finally:
            # Clean up any remaining processes
            await self._cleanup_processes()
            
        end_time = time.time()
        
        return self._generate_runtime_report(end_time - start_time)

    async def _test_server_runtime(self, server_name: str, server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test individual MCP server with real runtime communication"""
        
        result = {
            "server_name": server_name,
            "timestamp": datetime.now().isoformat(),
            "status": "UNKNOWN",
            "tests": {},
            "performance": {},
            "protocol_compliance": {}
        }
        
        process = None
        try:
            # Start the MCP server process
            logger.info(f"🔧 Starting {server_name} process...")
            process = await self._start_server_process(server_config["command"])
            
            if not process:
                result["status"] = "FAILED"
                result["error"] = "Failed to start server process"
                return result
            
            self.active_processes.append(process)
            
            # Wait for process to initialize
            await asyncio.sleep(2)
            
            # Test MCP protocol compliance
            test_suite = [
                ("process_startup", self._test_process_startup),
                ("initialize_handshake", self._test_initialize_handshake),
                ("tools_list", self._test_tools_list),
                ("tool_execution", self._test_tool_execution),
                ("error_handling", self._test_runtime_error_handling),
                ("performance", self._test_runtime_performance),
                ("protocol_compliance", self._test_protocol_messages)
            ]
            
            tests_passed = 0
            total_tests = len(test_suite)
            
            for test_name, test_func in test_suite:
                try:
                    test_result = await test_func(process, server_name, server_config)
                    result["tests"][test_name] = test_result
                    
                    if test_result.get("status") == "PASS":
                        tests_passed += 1
                        
                    # Collect performance metrics
                    if "performance" in test_result:
                        result["performance"][test_name] = test_result["performance"]
                        
                except Exception as e:
                    logger.error(f"Test {test_name} failed: {str(e)}")
                    result["tests"][test_name] = {
                        "status": "ERROR",
                        "error": str(e)
                    }
            
            # Calculate overall status
            compliance_score = (tests_passed / total_tests * 100) if total_tests > 0 else 0
            result["compliance_score"] = compliance_score
            
            if compliance_score >= 90:
                result["status"] = "SUCCESS"
            elif compliance_score >= 70:
                result["status"] = "WARNING"
            else:
                result["status"] = "FAILED"
                
        except Exception as e:
            result["status"] = "ERROR"
            result["error"] = str(e)
            
        finally:
            # Clean up the process
            if process:
                await self._cleanup_process(process)
                
        return result

    async def _start_server_process(self, command: List[str]) -> Optional[subprocess.Popen]:
        """Start MCP server process with proper stdio handling"""
        try:
            # Check if we're in the right directory
            cwd = Path.cwd()
            
            # For npm commands, make sure we're in mcp_servers directory
            if command[0] == "npx":
                mcp_servers_path = cwd / "mcp_servers"
                if mcp_servers_path.exists():
                    work_dir = str(mcp_servers_path)
                else:
                    work_dir = str(cwd)
            else:
                work_dir = str(cwd)
            
            logger.info(f"🔧 Starting command: {' '.join(command)} in {work_dir}")
            
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=work_dir
            )
            
            # Give process time to start
            await asyncio.sleep(1)
            
            # Check if process is still running
            if process.poll() is None:
                logger.info(f"✅ Process started successfully (PID: {process.pid})")
                return process
            else:
                stderr = process.stderr.read() if process.stderr else ""
                logger.error(f"❌ Process failed to start. Error: {stderr}")
                return None
                
        except Exception as e:
            logger.error(f"❌ Failed to start process: {str(e)}")
            return None

    async def _test_process_startup(self, process: subprocess.Popen, server_name: str, 
                                  server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test if the process started successfully"""
        try:
            if process.poll() is None:
                return {
                    "status": "PASS",
                    "message": "Process started successfully",
                    "pid": process.pid
                }
            else:
                stderr_output = ""
                if process.stderr:
                    try:
                        stderr_output = process.stderr.read()
                    except:
                        stderr_output = "Could not read stderr"
                        
                return {
                    "status": "FAIL",
                    "message": "Process failed to start or exited early",
                    "return_code": process.returncode,
                    "stderr": stderr_output
                }
                
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e)
            }

    async def _test_initialize_handshake(self, process: subprocess.Popen, server_name: str,
                                       server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test MCP initialize handshake"""
        try:
            # Send initialize request
            initialize_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "roots": {
                            "listChanged": True
                        },
                        "sampling": {}
                    },
                    "clientInfo": {
                        "name": "mcp-protocol-tester",
                        "version": "1.0.0"
                    }
                }
            }
            
            # Send request to server
            request_json = json.dumps(initialize_request) + "\n"
            
            try:
                process.stdin.write(request_json)
                process.stdin.flush()
            except Exception as e:
                return {
                    "status": "FAIL",
                    "error": f"Failed to send initialize request: {str(e)}"
                }
            
            # Try to read response with timeout
            try:
                # Wait for response with timeout
                response_line = await asyncio.wait_for(
                    self._read_line_async(process.stdout),
                    timeout=5.0
                )
                
                if response_line:
                    response = json.loads(response_line.strip())
                    
                    # Validate response structure
                    if (response.get("jsonrpc") == "2.0" and 
                        response.get("id") == 1 and
                        "result" in response):
                        
                        result = response["result"]
                        
                        # Check for required fields
                        if ("protocolVersion" in result and 
                            "capabilities" in result and
                            "serverInfo" in result):
                            
                            return {
                                "status": "PASS",
                                "response": response,
                                "server_info": result.get("serverInfo"),
                                "capabilities": result.get("capabilities")
                            }
                        else:
                            return {
                                "status": "FAIL",
                                "error": "Missing required fields in initialize response",
                                "response": response
                            }
                    else:
                        return {
                            "status": "FAIL", 
                            "error": "Invalid initialize response format",
                            "response": response
                        }
                else:
                    return {
                        "status": "FAIL",
                        "error": "No response received to initialize request"
                    }
                    
            except asyncio.TimeoutError:
                return {
                    "status": "FAIL",
                    "error": "Timeout waiting for initialize response"
                }
            except json.JSONDecodeError as e:
                return {
                    "status": "FAIL",
                    "error": f"Invalid JSON in response: {str(e)}",
                    "raw_response": response_line
                }
                
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e)
            }

    async def _test_tools_list(self, process: subprocess.Popen, server_name: str,
                             server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test tools/list method"""
        try:
            # Send tools/list request
            tools_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }
            
            request_json = json.dumps(tools_request) + "\n"
            
            try:
                process.stdin.write(request_json)
                process.stdin.flush()
            except Exception as e:
                return {
                    "status": "FAIL",
                    "error": f"Failed to send tools/list request: {str(e)}"
                }
            
            # Read response
            try:
                response_line = await asyncio.wait_for(
                    self._read_line_async(process.stdout),
                    timeout=5.0
                )
                
                if response_line:
                    response = json.loads(response_line.strip())
                    
                    if (response.get("jsonrpc") == "2.0" and
                        response.get("id") == 2 and
                        "result" in response):
                        
                        result = response["result"]
                        
                        if "tools" in result and isinstance(result["tools"], list):
                            tools = result["tools"]
                            
                            # Validate tool schema
                            tool_issues = []
                            for tool in tools:
                                if not isinstance(tool, dict):
                                    tool_issues.append("Tool is not an object")
                                    continue
                                    
                                required_fields = ["name", "description", "inputSchema"]
                                missing = [f for f in required_fields if f not in tool]
                                if missing:
                                    tool_issues.append(f"Tool missing fields: {missing}")
                            
                            if tool_issues:
                                return {
                                    "status": "WARN",
                                    "tools_count": len(tools),
                                    "tools": [t.get("name", "unknown") for t in tools],
                                    "issues": tool_issues
                                }
                            else:
                                return {
                                    "status": "PASS",
                                    "tools_count": len(tools),
                                    "tools": [t.get("name", "unknown") for t in tools],
                                    "response": response
                                }
                        else:
                            return {
                                "status": "FAIL",
                                "error": "Missing or invalid tools array in response"
                            }
                    else:
                        return {
                            "status": "FAIL",
                            "error": "Invalid tools/list response format",
                            "response": response
                        }
                else:
                    return {
                        "status": "FAIL",
                        "error": "No response received to tools/list request"
                    }
                    
            except asyncio.TimeoutError:
                return {
                    "status": "FAIL",
                    "error": "Timeout waiting for tools/list response"
                }
            except json.JSONDecodeError as e:
                return {
                    "status": "FAIL",
                    "error": f"Invalid JSON in tools/list response: {str(e)}"
                }
                
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e)
            }

    async def _test_tool_execution(self, process: subprocess.Popen, server_name: str,
                                 server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test actual tool execution"""
        try:
            # First get the list of tools
            tools_result = await self._test_tools_list(process, server_name, server_config)
            
            if tools_result.get("status") != "PASS" or not tools_result.get("tools"):
                return {
                    "status": "SKIP",
                    "reason": "No tools available or tools/list failed"
                }
            
            # Try to execute a safe tool
            available_tools = tools_result.get("tools", [])
            safe_tools = ["list_directory", "read_entity", "thinking_prompt"]
            
            tool_to_test = None
            for tool in safe_tools:
                if tool in available_tools:
                    tool_to_test = tool
                    break
            
            if not tool_to_test:
                # Try first available tool with minimal parameters
                tool_to_test = available_tools[0] if available_tools else None
            
            if not tool_to_test:
                return {
                    "status": "SKIP",
                    "reason": "No suitable tool found for testing"
                }
            
            # Prepare safe test parameters based on tool
            test_params = {}
            if tool_to_test == "list_directory":
                test_params = {"path": "/tmp"}
            elif tool_to_test == "thinking_prompt":
                test_params = {"query": "test query"}
            elif tool_to_test == "read_entity":
                test_params = {"entityId": "test"}
            
            # Send tool execution request
            tool_request = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": tool_to_test,
                    "arguments": test_params
                }
            }
            
            request_json = json.dumps(tool_request) + "\n"
            
            start_time = time.time()
            
            try:
                process.stdin.write(request_json)
                process.stdin.flush()
            except Exception as e:
                return {
                    "status": "FAIL",
                    "error": f"Failed to send tool execution request: {str(e)}"
                }
            
            # Read response with timeout
            try:
                response_line = await asyncio.wait_for(
                    self._read_line_async(process.stdout),
                    timeout=10.0  # Longer timeout for tool execution
                )
                
                end_time = time.time()
                execution_time = end_time - start_time
                
                if response_line:
                    response = json.loads(response_line.strip())
                    
                    if response.get("jsonrpc") == "2.0" and response.get("id") == 3:
                        
                        if "result" in response:
                            # Successful execution
                            result = response["result"]
                            
                            # Validate result format
                            if "content" in result and isinstance(result["content"], list):
                                return {
                                    "status": "PASS",
                                    "tool_tested": tool_to_test,
                                    "execution_time_ms": execution_time * 1000,
                                    "result_content_blocks": len(result["content"]),
                                    "performance": {
                                        "execution_time_ms": execution_time * 1000
                                    }
                                }
                            else:
                                return {
                                    "status": "WARN",
                                    "tool_tested": tool_to_test,
                                    "issue": "Result missing content array or content not array",
                                    "response": response
                                }
                                
                        elif "error" in response:
                            # Tool execution error (might be expected for some tools)
                            error = response["error"]
                            return {
                                "status": "WARN",
                                "tool_tested": tool_to_test,
                                "tool_error": error,
                                "message": "Tool returned error (may be expected behavior)"
                            }
                        else:
                            return {
                                "status": "FAIL",
                                "error": "Tool execution response missing result or error",
                                "response": response
                            }
                    else:
                        return {
                            "status": "FAIL",
                            "error": "Invalid tool execution response format",
                            "response": response
                        }
                else:
                    return {
                        "status": "FAIL",
                        "error": "No response received to tool execution request"
                    }
                    
            except asyncio.TimeoutError:
                return {
                    "status": "FAIL",
                    "error": f"Timeout waiting for tool execution response (tool: {tool_to_test})"
                }
            except json.JSONDecodeError as e:
                return {
                    "status": "FAIL",
                    "error": f"Invalid JSON in tool execution response: {str(e)}"
                }
                
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e)
            }

    async def _test_runtime_error_handling(self, process: subprocess.Popen, server_name: str,
                                         server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test error handling with invalid requests"""
        try:
            error_tests = []
            
            # Test 1: Invalid method
            invalid_method_request = {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "invalid/method",
                "params": {}
            }
            
            error_tests.append({
                "name": "invalid_method",
                "request": invalid_method_request,
                "expected_error_code": -32601
            })
            
            # Test 2: Invalid JSON-RPC format
            invalid_format_request = {
                "jsonrpc": "1.0",  # Wrong version
                "id": 11,
                "method": "tools/list",
                "params": {}
            }
            
            error_tests.append({
                "name": "invalid_jsonrpc_version",
                "request": invalid_format_request,
                "expected_error_code": -32600
            })
            
            error_results = []
            
            for test in error_tests:
                try:
                    request_json = json.dumps(test["request"]) + "\n"
                    
                    process.stdin.write(request_json)
                    process.stdin.flush()
                    
                    # Wait for error response
                    response_line = await asyncio.wait_for(
                        self._read_line_async(process.stdout),
                        timeout=3.0
                    )
                    
                    if response_line:
                        response = json.loads(response_line.strip())
                        
                        if "error" in response:
                            error = response["error"]
                            error_code = error.get("code")
                            
                            error_results.append({
                                "test": test["name"],
                                "status": "PASS" if error_code == test["expected_error_code"] else "WARN",
                                "received_error_code": error_code,
                                "expected_error_code": test["expected_error_code"],
                                "error_message": error.get("message", "")
                            })
                        else:
                            error_results.append({
                                "test": test["name"],
                                "status": "FAIL",
                                "issue": "No error returned for invalid request",
                                "response": response
                            })
                    else:
                        error_results.append({
                            "test": test["name"],
                            "status": "FAIL", 
                            "issue": "No response to invalid request"
                        })
                        
                except asyncio.TimeoutError:
                    error_results.append({
                        "test": test["name"],
                        "status": "WARN",
                        "issue": "Timeout - server may have ignored invalid request"
                    })
                except Exception as e:
                    error_results.append({
                        "test": test["name"],
                        "status": "ERROR",
                        "error": str(e)
                    })
            
            # Calculate overall error handling score
            passed_tests = sum(1 for r in error_results if r["status"] == "PASS")
            total_tests = len(error_results)
            
            return {
                "status": "PASS" if passed_tests == total_tests else "WARN",
                "error_tests_run": total_tests,
                "error_tests_passed": passed_tests,
                "error_handling_results": error_results
            }
            
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e)
            }

    async def _test_runtime_performance(self, process: subprocess.Popen, server_name: str,
                                      server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test runtime performance characteristics"""
        try:
            performance_metrics = {
                "response_times": [],
                "memory_usage": 0,
                "cpu_usage": 0
            }
            
            # Run multiple requests to measure response times
            num_requests = 5
            
            for i in range(num_requests):
                start_time = time.time()
                
                # Send tools/list request
                request = {
                    "jsonrpc": "2.0",
                    "id": 100 + i,
                    "method": "tools/list",
                    "params": {}
                }
                
                request_json = json.dumps(request) + "\n"
                
                try:
                    process.stdin.write(request_json)
                    process.stdin.flush()
                    
                    # Wait for response
                    response_line = await asyncio.wait_for(
                        self._read_line_async(process.stdout),
                        timeout=5.0
                    )
                    
                    end_time = time.time()
                    response_time = end_time - start_time
                    performance_metrics["response_times"].append(response_time)
                    
                except asyncio.TimeoutError:
                    performance_metrics["response_times"].append(5.0)  # Timeout value
                except Exception:
                    performance_metrics["response_times"].append(None)  # Error
                    
                # Small delay between requests
                await asyncio.sleep(0.1)
            
            # Calculate statistics
            valid_times = [t for t in performance_metrics["response_times"] if t is not None]
            
            if valid_times:
                avg_response_time = sum(valid_times) / len(valid_times)
                min_response_time = min(valid_times)
                max_response_time = max(valid_times)
                
                performance_score = 100
                if avg_response_time > 1.0:
                    performance_score -= 20
                if max_response_time > 2.0:
                    performance_score -= 10
                if len(valid_times) < num_requests:
                    performance_score -= 30
                
                return {
                    "status": "PASS" if performance_score >= 70 else "WARN",
                    "performance_score": performance_score,
                    "avg_response_time_ms": avg_response_time * 1000,
                    "min_response_time_ms": min_response_time * 1000,
                    "max_response_time_ms": max_response_time * 1000,
                    "successful_requests": len(valid_times),
                    "total_requests": num_requests,
                    "performance": {
                        "avg_response_time_ms": avg_response_time * 1000,
                        "requests_per_second": len(valid_times) / sum(valid_times) if sum(valid_times) > 0 else 0
                    }
                }
            else:
                return {
                    "status": "FAIL",
                    "error": "No successful requests for performance measurement"
                }
                
        except Exception as e:
            return {
                "status": "ERROR",
                "error": str(e)
            }

    async def _test_protocol_messages(self, process: subprocess.Popen, server_name: str,
                                    server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test protocol message compliance"""
        try:
            # Test sending notifications (no response expected)
            notification = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }
            
            notification_json = json.dumps(notification) + "\n"
            
            try:
                process.stdin.write(notification_json)
                process.stdin.flush()
                
                # Notifications shouldn't generate responses
                # Wait briefly and check if any unexpected response comes
                try:
                    unexpected_response = await asyncio.wait_for(
                        self._read_line_async(process.stdout),
                        timeout=1.0
                    )
                    
                    if unexpected_response:
                        return {
                            "status": "WARN",
                            "issue": "Server responded to notification (should not respond)",
                            "unexpected_response": unexpected_response
                        }
                except asyncio.TimeoutError:
                    # This is expected - no response to notification
                    pass
                
                return {
                    "status": "PASS",
                    "message": "Protocol messaging compliance verified"
                }
                
            except Exception as e:
                return {
                    "status": "FAIL",
                    "error": f"Failed to send notification: {str(e)}"
                }
                
        except Exception as e:
            return {
                "status": "ERROR", 
                "error": str(e)
            }

    async def _read_line_async(self, stream) -> Optional[str]:
        """Read a line from stream asynchronously"""
        loop = asyncio.get_event_loop()
        
        try:
            # Use run_in_executor to make blocking readline non-blocking
            line = await loop.run_in_executor(None, stream.readline)
            return line if line else None
        except Exception:
            return None

    async def _cleanup_process(self, process: subprocess.Popen):
        """Clean up a process safely"""
        try:
            if process.poll() is None:  # Process is still running
                logger.info(f"🧹 Cleaning up process PID {process.pid}")
                
                # Try graceful termination first
                process.terminate()
                
                try:
                    # Wait for graceful shutdown
                    await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=3.0)
                    logger.info(f"✅ Process {process.pid} terminated gracefully")
                except asyncio.TimeoutError:
                    # Force kill if necessary
                    logger.warning(f"⚠️ Force killing process {process.pid}")
                    process.kill()
                    await asyncio.to_thread(process.wait)
                    
            if process in self.active_processes:
                self.active_processes.remove(process)
                
        except Exception as e:
            logger.error(f"❌ Error cleaning up process: {str(e)}")

    async def _cleanup_processes(self):
        """Clean up all active processes"""
        logger.info(f"🧹 Cleaning up {len(self.active_processes)} active processes")
        
        cleanup_tasks = []
        for process in self.active_processes.copy():
            cleanup_tasks.append(self._cleanup_process(process))
        
        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)
        
        self.active_processes.clear()

    def _generate_runtime_report(self, total_time: float) -> Dict[str, Any]:
        """Generate runtime testing report"""
        
        # Calculate overall metrics
        total_servers = len(self.test_results)
        successful_servers = sum(1 for r in self.test_results.values() 
                               if r.get("status") == "SUCCESS")
        
        # Collect performance data
        performance_summary = {}
        for server_name, results in self.test_results.items():
            if "performance" in results:
                performance_summary[server_name] = results["performance"]
        
        # Generate compliance summary
        compliance_summary = {}
        for server_name, results in self.test_results.items():
            compliance_summary[server_name] = {
                "status": results.get("status", "UNKNOWN"),
                "compliance_score": results.get("compliance_score", 0),
                "tests_run": len(results.get("tests", {})),
                "tests_passed": sum(1 for t in results.get("tests", {}).values() 
                                  if t.get("status") == "PASS")
            }
        
        return {
            "runtime_test_summary": {
                "timestamp": datetime.now().isoformat(),
                "total_runtime_seconds": round(total_time, 2),
                "servers_tested": total_servers,
                "servers_successful": successful_servers,
                "success_rate": round((successful_servers / total_servers * 100) if total_servers > 0 else 0, 1)
            },
            "detailed_results": self.test_results,
            "compliance_summary": compliance_summary,
            "performance_summary": performance_summary,
            "recommendations": self._generate_runtime_recommendations()
        }

    def _generate_runtime_recommendations(self) -> List[str]:
        """Generate recommendations based on runtime test results"""
        recommendations = []
        
        # Analyze results for common issues
        failed_servers = [name for name, result in self.test_results.items() 
                         if result.get("status") in ["FAILED", "ERROR"]]
        
        if failed_servers:
            recommendations.append(f"Fix runtime issues in {len(failed_servers)} servers: {', '.join(failed_servers)}")
        
        # Check for performance issues
        slow_servers = []
        for server_name, results in self.test_results.items():
            if "performance" in results:
                for test_name, perf_data in results["performance"].items():
                    if isinstance(perf_data, dict) and perf_data.get("avg_response_time_ms", 0) > 1000:
                        slow_servers.append(server_name)
                        break
        
        if slow_servers:
            recommendations.append(f"Optimize performance for slow servers: {', '.join(set(slow_servers))}")
        
        recommendations.extend([
            "Set up automated runtime testing in CI/CD pipeline",
            "Implement health checks for all MCP servers",
            "Add monitoring and alerting for server failures",
            "Document deployment and configuration requirements"
        ])
        
        return recommendations

async def main():
    """Run advanced MCP runtime protocol testing"""
    
    print("🚀 AGENT 5 - Advanced MCP Protocol Runtime Testing")
    print("=" * 80)
    print("🎯 Mission: Test real MCP server processes with actual JSON-RPC communication")
    print("📋 Scope: Process startup, handshake, tools, errors, performance")
    print("⚠️  Note: Only testing safe servers to avoid system modifications")
    print()
    
    tester = MCPRuntimeTester()
    
    try:
        # Run runtime tests
        runtime_report = await tester.run_runtime_tests()
        
        # Display results
        print("\n" + "=" * 80)
        print("📊 MCP RUNTIME PROTOCOL TEST RESULTS")
        print("=" * 80)
        
        summary = runtime_report["runtime_test_summary"]
        print(f"🎯 Servers Tested: {summary['servers_tested']}")
        print(f"✅ Successful: {summary['servers_successful']}")
        print(f"📈 Success Rate: {summary['success_rate']}%")
        print(f"⏱️ Total Runtime: {summary['total_runtime_seconds']} seconds")
        
        # Server-by-server results
        print("\n" + "=" * 80)
        print("🏗️  RUNTIME TEST RESULTS BY SERVER")
        print("=" * 80)
        
        compliance_summary = runtime_report["compliance_summary"]
        for server_name, summary in compliance_summary.items():
            status = summary["status"]
            score = summary["compliance_score"]
            tests_passed = summary["tests_passed"]
            tests_total = summary["tests_run"]
            
            if status == "SUCCESS":
                icon = "✅"
            elif status == "WARNING":
                icon = "⚠️"
            elif status == "SKIPPED":
                icon = "⏭️"
            else:
                icon = "❌"
                
            print(f"{icon} {server_name:20}: {status:8} - {score:5.1f}% ({tests_passed}/{tests_total} tests)")
        
        # Performance summary
        if runtime_report["performance_summary"]:
            print("\n" + "=" * 80)
            print("⚡ RUNTIME PERFORMANCE METRICS")
            print("=" * 80)
            
            for server_name, perf_data in runtime_report["performance_summary"].items():
                print(f"\n📊 {server_name}:")
                for test_name, metrics in perf_data.items():
                    if isinstance(metrics, dict):
                        for metric, value in metrics.items():
                            if isinstance(value, float):
                                print(f"   {metric}: {value:.2f}")
                            else:
                                print(f"   {metric}: {value}")
        
        # Recommendations
        print("\n" + "=" * 80)
        print("💡 RUNTIME TESTING RECOMMENDATIONS")
        print("=" * 80)
        
        for i, rec in enumerate(runtime_report["recommendations"], 1):
            print(f"{i}. {rec}")
        
        # Save report
        report_path = Path("mcp_runtime_protocol_test_report.json")
        with open(report_path, 'w') as f:
            json.dump(runtime_report, f, indent=2, default=str)
        
        print(f"\n📄 Detailed runtime report saved to: {report_path}")
        
        print("\n✅ AGENT 5 Advanced MCP Runtime Testing - COMPLETE")
        
        return summary["success_rate"] >= 50  # 50% success threshold
        
    except Exception as e:
        logger.error(f"❌ Runtime testing failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)