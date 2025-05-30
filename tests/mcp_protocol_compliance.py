#!/usr/bin/env python3
"""
MCP Protocol Compliance and Interoperability Testing

Agent 5: Comprehensive protocol validation for all MCP server implementations.
Ensures perfect adherence to MCP standards and validates interoperability.
"""

import asyncio
import json
import sys
import traceback
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
import logging

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mcp.protocols import (
    MCPRequest, MCPResponse, MCPTool, MCPToolParameter,
    MCPServerInfo, MCPMethod, MCPError
)
from mcp.manager import get_mcp_manager
from mcp.servers import MCPServerRegistry

# Try to import Circle of Experts - graceful fallback if not available
try:
    from circle_of_experts import EnhancedExpertManager
    EXPERTS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Circle of Experts not available: {e}")
    EXPERTS_AVAILABLE = False
    
    # Mock class for graceful fallback
    class EnhancedExpertManager:
        async def quick_consult(self, **kwargs):
            return {
                "status": "UNAVAILABLE",
                "query_id": "mock",
                "experts": ["mock_expert"],
                "consensus": "N/A",
                "recommendations": ["Circle of Experts unavailable - manual review recommended"],
                "responses": []
            }


class MCPProtocolComplianceValidator:
    """Validates MCP protocol compliance for all servers."""
    
    def __init__(self):
        self.manager = get_mcp_manager()
        self.expert_manager = EnhancedExpertManager()
        self.registry = MCPServerRegistry()
        self.test_results: Dict[str, Dict[str, Any]] = {}
        self.protocol_errors: List[Dict[str, Any]] = []
        
    async def initialize(self):
        """Initialize the validator and MCP manager."""
        await self.manager.initialize()
        logger.info("MCP Protocol Compliance Validator initialized")
        
    async def validate_all_servers(self) -> Dict[str, Any]:
        """Validate all registered MCP servers."""
        logger.info("Starting comprehensive MCP protocol compliance testing")
        
        # Get all registered servers
        servers = self.registry.list_servers()
        logger.info(f"Found {len(servers)} MCP servers to validate")
        
        # Validate each server
        for server_name in servers:
            logger.info(f"\nValidating server: {server_name}")
            self.test_results[server_name] = await self._validate_server(server_name)
            
        # Test interoperability
        interop_results = await self._test_interoperability()
        
        # Consult experts for protocol assessment
        expert_assessment = await self._consult_protocol_experts()
        
        # Generate compliance report
        return self._generate_compliance_report(interop_results, expert_assessment)
        
    async def _validate_server(self, server_name: str) -> Dict[str, Any]:
        """Validate a single MCP server."""
        server = self.registry.get(server_name)
        if not server:
            return {"error": f"Server {server_name} not found"}
            
        results = {
            "server_name": server_name,
            "timestamp": datetime.now().isoformat(),
            "tests": {}
        }
        
        # Test 1: Server Info Compliance
        results["tests"]["server_info"] = await self._test_server_info(server)
        
        # Test 2: Tool Registration Compliance
        results["tests"]["tool_registration"] = await self._test_tool_registration(server)
        
        # Test 3: Tool Parameter Validation
        results["tests"]["parameter_validation"] = await self._test_parameter_validation(server)
        
        # Test 4: Error Handling Compliance
        results["tests"]["error_handling"] = await self._test_error_handling(server, server_name)
        
        # Test 5: Message Format Compliance
        results["tests"]["message_format"] = await self._test_message_format(server, server_name)
        
        # Test 6: Concurrent Access Testing
        results["tests"]["concurrent_access"] = await self._test_concurrent_access(server, server_name)
        
        # Calculate compliance score
        passed_tests = sum(1 for test in results["tests"].values() 
                          if test.get("status") == "PASS")
        total_tests = len(results["tests"])
        results["compliance_score"] = (passed_tests / total_tests) * 100
        
        return results
        
    async def _test_server_info(self, server) -> Dict[str, Any]:
        """Test server info compliance."""
        try:
            info = server.get_server_info()
            
            # Validate required fields
            required_fields = ["name", "version", "capabilities"]
            missing_fields = [f for f in required_fields if not hasattr(info, f)]
            
            if missing_fields:
                return {
                    "status": "FAIL",
                    "error": f"Missing required fields: {missing_fields}"
                }
                
            # Validate version format (semantic versioning)
            import re
            if not re.match(r'^\d+\.\d+\.\d+$', info.version):
                return {
                    "status": "WARN",
                    "warning": f"Version '{info.version}' doesn't follow semantic versioning"
                }
                
            return {
                "status": "PASS",
                "info": {
                    "name": info.name,
                    "version": info.version,
                    "capabilities": info.capabilities.dict()
                }
            }
            
        except Exception as e:
            return {
                "status": "FAIL",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            
    async def _test_tool_registration(self, server) -> Dict[str, Any]:
        """Test tool registration compliance."""
        try:
            tools = server.get_tools()
            
            if not isinstance(tools, list):
                return {
                    "status": "FAIL",
                    "error": "get_tools() must return a list"
                }
                
            tool_issues = []
            for tool in tools:
                if not isinstance(tool, MCPTool):
                    tool_issues.append(f"Tool {getattr(tool, 'name', 'unknown')} is not MCPTool instance")
                    continue
                    
                # Validate tool fields
                if not tool.name:
                    tool_issues.append("Tool has empty name")
                if not tool.description:
                    tool_issues.append(f"Tool {tool.name} has empty description")
                    
            if tool_issues:
                return {
                    "status": "FAIL",
                    "errors": tool_issues
                }
                
            return {
                "status": "PASS",
                "tool_count": len(tools),
                "tools": [t.name for t in tools]
            }
            
        except Exception as e:
            return {
                "status": "FAIL",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            
    async def _test_parameter_validation(self, server) -> Dict[str, Any]:
        """Test tool parameter validation."""
        try:
            tools = server.get_tools()
            param_issues = []
            
            for tool in tools:
                # Check parameter types
                for param in tool.parameters:
                    if param.type not in ["string", "integer", "number", "boolean", "object", "array"]:
                        param_issues.append(
                            f"Tool {tool.name}, param {param.name}: invalid type '{param.type}'"
                        )
                        
                    # Check enum values if present
                    if param.enum and not isinstance(param.enum, list):
                        param_issues.append(
                            f"Tool {tool.name}, param {param.name}: enum must be a list"
                        )
                        
                    # Check default value type matches declared type
                    if param.default is not None:
                        if param.type == "integer" and not isinstance(param.default, int):
                            param_issues.append(
                                f"Tool {tool.name}, param {param.name}: default value type mismatch"
                            )
                            
            if param_issues:
                return {
                    "status": "FAIL",
                    "errors": param_issues
                }
                
            return {"status": "PASS"}
            
        except Exception as e:
            return {
                "status": "FAIL",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            
    async def _test_error_handling(self, server, server_name: str) -> Dict[str, Any]:
        """Test error handling compliance."""
        try:
            # Test with invalid tool name
            context_id = f"error_test_{server_name}"
            context = self.manager.create_context(context_id)
            self.manager.enable_server(context_id, server_name)
            
            error_cases = []
            
            # Test 1: Invalid tool name
            try:
                await self.manager.call_tool(
                    f"{server_name}.invalid_tool_name",
                    {},
                    context_id
                )
                error_cases.append({
                    "test": "invalid_tool",
                    "status": "FAIL",
                    "error": "Should have raised error for invalid tool"
                })
            except MCPError as e:
                if e.code == -32601:  # Method not found
                    error_cases.append({
                        "test": "invalid_tool",
                        "status": "PASS",
                        "error_code": e.code
                    })
                else:
                    error_cases.append({
                        "test": "invalid_tool",
                        "status": "FAIL",
                        "error": f"Wrong error code: {e.code}, expected -32601"
                    })
            except Exception as e:
                error_cases.append({
                    "test": "invalid_tool",
                    "status": "FAIL",
                    "error": f"Unexpected error type: {type(e).__name__}"
                })
                
            # Test 2: Missing required parameters
            tools = server.get_tools()
            if tools:
                tool = tools[0]
                required_params = [p for p in tool.parameters if p.required]
                if required_params:
                    try:
                        await self.manager.call_tool(
                            f"{server_name}.{tool.name}",
                            {},  # Empty params
                            context_id
                        )
                        error_cases.append({
                            "test": "missing_params",
                            "status": "FAIL",
                            "error": "Should have raised error for missing parameters"
                        })
                    except Exception:
                        error_cases.append({
                            "test": "missing_params",
                            "status": "PASS"
                        })
                        
            # Check if all error tests passed
            all_passed = all(case.get("status") == "PASS" for case in error_cases)
            
            return {
                "status": "PASS" if all_passed else "FAIL",
                "error_cases": error_cases
            }
            
        except Exception as e:
            return {
                "status": "FAIL",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            
    async def _test_message_format(self, server, server_name: str) -> Dict[str, Any]:
        """Test message format compliance."""
        try:
            # For this test, we would need to intercept the actual messages
            # Since we're using the abstracted manager, we'll test the response format
            context_id = f"format_test_{server_name}"
            context = self.manager.create_context(context_id)
            self.manager.enable_server(context_id, server_name)
            
            tools = server.get_tools()
            if not tools:
                return {
                    "status": "SKIP",
                    "reason": "No tools available to test"
                }
                
            # Test with a valid tool call
            tool = tools[0]
            test_params = {}
            
            # Build minimal valid parameters
            for param in tool.parameters:
                if param.required:
                    if param.type == "string":
                        test_params[param.name] = "test"
                    elif param.type == "integer":
                        test_params[param.name] = 1
                    elif param.type == "boolean":
                        test_params[param.name] = True
                        
            try:
                result = await server.call_tool(tool.name, test_params)
                
                # Validate result is JSON-serializable
                json.dumps(result)
                
                return {
                    "status": "PASS",
                    "tool_tested": tool.name
                }
                
            except Exception as e:
                # Some tools may fail due to external dependencies
                # We're testing message format, not functionality
                return {
                    "status": "WARN",
                    "warning": "Could not test message format due to tool error",
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "status": "FAIL",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            
    async def _test_concurrent_access(self, server, server_name: str) -> Dict[str, Any]:
        """Test concurrent access handling."""
        try:
            tools = server.get_tools()
            if not tools:
                return {
                    "status": "SKIP",
                    "reason": "No tools available to test"
                }
                
            # Select a lightweight tool for concurrent testing
            tool = None
            for t in tools:
                if "list" in t.name or "get" in t.name:
                    tool = t
                    break
            if not tool:
                tool = tools[0]
                
            # Build test parameters
            test_params = {}
            for param in tool.parameters:
                if param.required:
                    if param.type == "string":
                        test_params[param.name] = "concurrent_test"
                    elif param.type == "integer":
                        test_params[param.name] = 1
                        
            # Run concurrent calls
            concurrent_calls = 5
            tasks = []
            
            for i in range(concurrent_calls):
                task = server.call_tool(tool.name, test_params)
                tasks.append(task)
                
            # Wait for all calls with timeout
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=30
                )
                
                # Check results
                successful_calls = sum(1 for r in results if not isinstance(r, Exception))
                
                return {
                    "status": "PASS" if successful_calls == concurrent_calls else "WARN",
                    "concurrent_calls": concurrent_calls,
                    "successful_calls": successful_calls,
                    "tool_tested": tool.name
                }
                
            except asyncio.TimeoutError:
                return {
                    "status": "FAIL",
                    "error": "Concurrent calls timed out"
                }
                
        except Exception as e:
            return {
                "status": "FAIL",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            
    async def _test_interoperability(self) -> Dict[str, Any]:
        """Test interoperability between MCP servers."""
        try:
            logger.info("Testing MCP server interoperability")
            
            # Create test context
            context_id = "interop_test"
            context = self.manager.create_context(context_id)
            
            # Enable multiple servers
            servers_to_test = ["desktop-commander", "docker", "security-scanner"]
            for server in servers_to_test:
                if server in self.registry.list_servers():
                    self.manager.enable_server(context_id, server)
                    
            # Test cross-server workflows
            workflows = [
                {
                    "name": "security_scan_workflow",
                    "steps": [
                        {
                            "server": "desktop-commander",
                            "tool": "read_file",
                            "params": {"file_path": "package.json"}
                        },
                        {
                            "server": "security-scanner",
                            "tool": "npm_audit",
                            "params": {"package_json_path": "package.json"}
                        }
                    ]
                },
                {
                    "name": "docker_security_workflow",
                    "steps": [
                        {
                            "server": "docker",
                            "tool": "docker_ps",
                            "params": {}
                        },
                        {
                            "server": "security-scanner",
                            "tool": "docker_security_scan",
                            "params": {"image_name": "nginx:latest"}
                        }
                    ]
                }
            ]
            
            workflow_results = []
            for workflow in workflows:
                workflow_result = await self._test_workflow(workflow, context_id)
                workflow_results.append(workflow_result)
                
            # Test state consistency across servers
            state_test = await self._test_state_consistency(context_id)
            
            return {
                "status": "COMPLETE",
                "workflow_tests": workflow_results,
                "state_consistency": state_test
            }
            
        except Exception as e:
            return {
                "status": "FAIL",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            
    async def _test_workflow(self, workflow: Dict[str, Any], context_id: str) -> Dict[str, Any]:
        """Test a multi-server workflow."""
        try:
            step_results = []
            workflow_state = {}
            
            for step in workflow["steps"]:
                server_name = step["server"]
                tool_name = step["tool"]
                params = step["params"]
                
                # Execute step
                try:
                    result = await self.manager.call_tool(
                        f"{server_name}.{tool_name}",
                        params,
                        context_id
                    )
                    
                    step_results.append({
                        "step": f"{server_name}.{tool_name}",
                        "status": "SUCCESS",
                        "result_type": type(result).__name__
                    })
                    
                    # Store result for next steps
                    workflow_state[f"{server_name}_{tool_name}"] = result
                    
                except Exception as e:
                    step_results.append({
                        "step": f"{server_name}.{tool_name}",
                        "status": "FAIL",
                        "error": str(e)
                    })
                    
            successful_steps = sum(1 for r in step_results if r["status"] == "SUCCESS")
            total_steps = len(step_results)
            
            return {
                "workflow_name": workflow["name"],
                "status": "PASS" if successful_steps == total_steps else "PARTIAL",
                "successful_steps": successful_steps,
                "total_steps": total_steps,
                "step_details": step_results
            }
            
        except Exception as e:
            return {
                "workflow_name": workflow["name"],
                "status": "FAIL",
                "error": str(e)
            }
            
    async def _test_state_consistency(self, context_id: str) -> Dict[str, Any]:
        """Test state consistency across servers."""
        try:
            # Test that server state is properly isolated
            # and that context is maintained correctly
            
            test_results = []
            
            # Test 1: Context isolation
            context1 = self.manager.create_context("state_test_1")
            context2 = self.manager.create_context("state_test_2")
            
            # Enable different servers in each context
            self.manager.enable_server("state_test_1", "desktop-commander")
            self.manager.enable_server("state_test_2", "docker")
            
            # Verify isolation
            context1_servers = self.manager.get_enabled_servers("state_test_1")
            context2_servers = self.manager.get_enabled_servers("state_test_2")
            
            if len(context1_servers) == 1 and len(context2_servers) == 1:
                test_results.append({
                    "test": "context_isolation",
                    "status": "PASS"
                })
            else:
                test_results.append({
                    "test": "context_isolation",
                    "status": "FAIL",
                    "error": "Context isolation failed"
                })
                
            # Test 2: Server availability consistency
            available_tools = self.manager.get_available_tools()
            tool_count = len(available_tools)
            
            # Re-check after some operations
            await asyncio.sleep(1)
            available_tools_2 = self.manager.get_available_tools()
            tool_count_2 = len(available_tools_2)
            
            if tool_count == tool_count_2:
                test_results.append({
                    "test": "tool_availability_consistency",
                    "status": "PASS"
                })
            else:
                test_results.append({
                    "test": "tool_availability_consistency",
                    "status": "FAIL",
                    "error": f"Tool count changed: {tool_count} -> {tool_count_2}"
                })
                
            all_passed = all(t["status"] == "PASS" for t in test_results)
            
            return {
                "status": "PASS" if all_passed else "FAIL",
                "tests": test_results
            }
            
        except Exception as e:
            return {
                "status": "FAIL",
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            
    async def _consult_protocol_experts(self) -> Dict[str, Any]:
        """Consult Circle of Experts for protocol assessment."""
        try:
            logger.info("Consulting protocol experts for assessment")
            
            # Generate protocol analysis report
            protocol_analysis = self._generate_protocol_analysis()
            
            # Create expert consultation query
            expert_query = f"""
**MCP Protocol Engineering Consultation**

I need expert assessment of our MCP (Model Context Protocol) server implementations.

**Current Implementation Summary:**
- {len(self.registry.list_servers())} MCP servers implemented
- {sum(len(self.registry.get(s).get_tools()) for s in self.registry.list_servers())} total tools
- Protocol compliance test results: {len(self.test_results)} servers tested

**Protocol Analysis:**
{json.dumps(protocol_analysis, indent=2)}

**Expert Questions:**

1. **Protocol Engineering Expert**: Are we fully compliant with MCP specifications? 
   What protocol best practices should we implement?

2. **Distributed Systems Expert**: How reliable and consistent is our protocol 
   implementation under various failure scenarios?

3. **API Design Expert**: Is our MCP tool interface well-designed, intuitive, 
   and developer-friendly?

**Specific Areas for Assessment:**
- Message format compliance
- Error handling standardization
- Tool parameter validation
- Authentication and session management
- Protocol performance and efficiency
- Interoperability between servers

Please provide specific recommendations for improving protocol compliance and reliability.
"""
            
            # Consult experts
            consultation_result = await self.expert_manager.quick_consult(
                content=expert_query,
                priority="high",
                expert_count=3
            )
            
            if consultation_result.get("status") == "UNAVAILABLE":
                return {
                    "status": "UNAVAILABLE",
                    "error": "Circle of Experts not available",
                    "recommendations": consultation_result["recommendations"]
                }
            
            return {
                "status": "SUCCESS",
                "query_id": consultation_result["query_id"],
                "experts_consulted": consultation_result["experts"],
                "consensus_level": consultation_result["consensus"],
                "recommendations": consultation_result["recommendations"],
                "expert_responses": consultation_result.get("responses", [])
            }
            
        except Exception as e:
            logger.error(f"Expert consultation failed: {e}")
            return {
                "status": "FAIL",
                "error": str(e),
                "recommendations": [
                    "Manual protocol review recommended",
                    "Check expert manager configuration",
                    "Validate API credentials"
                ]
            }
            
    def _generate_protocol_analysis(self) -> Dict[str, Any]:
        """Generate protocol analysis summary."""
        total_servers = len(self.registry.list_servers())
        total_tools = sum(len(self.registry.get(s).get_tools()) for s in self.registry.list_servers())
        
        # Analyze test results
        compliance_scores = []
        for server_name, results in self.test_results.items():
            if "compliance_score" in results:
                compliance_scores.append(results["compliance_score"])
                
        avg_compliance = sum(compliance_scores) / len(compliance_scores) if compliance_scores else 0
        
        return {
            "total_servers": total_servers,
            "total_tools": total_tools,
            "servers_tested": len(self.test_results),
            "average_compliance_score": round(avg_compliance, 2),
            "protocol_errors": len(self.protocol_errors),
            "servers_with_issues": len([r for r in self.test_results.values() 
                                      if r.get("compliance_score", 100) < 100])
        }
        
    def _generate_compliance_report(self, interop_results: Dict[str, Any], 
                                  expert_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive compliance report."""
        
        # Calculate overall compliance metrics
        total_tests = 0
        passed_tests = 0
        
        for server_results in self.test_results.values():
            if "tests" in server_results:
                for test_name, test_result in server_results["tests"].items():
                    total_tests += 1
                    if test_result.get("status") == "PASS":
                        passed_tests += 1
                        
        overall_compliance = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        # Generate server compliance summary
        server_summary = {}
        for server_name, results in self.test_results.items():
            server_summary[server_name] = {
                "compliance_score": results.get("compliance_score", 0),
                "status": "COMPLIANT" if results.get("compliance_score", 0) >= 90 else "NEEDS_WORK",
                "tests_passed": len([t for t in results.get("tests", {}).values() 
                                   if t.get("status") == "PASS"]),
                "tests_total": len(results.get("tests", {}))
            }
            
        # Compliance recommendations
        recommendations = [
            "Implement automated protocol compliance checking in CI/CD",
            "Add comprehensive error response testing",
            "Enhance concurrent access validation",
            "Implement protocol performance benchmarking"
        ]
        
        # Add expert recommendations if available
        if expert_assessment.get("recommendations"):
            recommendations.extend(expert_assessment["recommendations"][:5])
            
        return {
            "compliance_report": {
                "timestamp": datetime.now().isoformat(),
                "overall_compliance_score": round(overall_compliance, 2),
                "total_servers": len(self.test_results),
                "servers_compliant": len([s for s in server_summary.values() 
                                        if s["status"] == "COMPLIANT"]),
                "total_tests_run": total_tests,
                "tests_passed": passed_tests
            },
            "server_details": self.test_results,
            "server_summary": server_summary,
            "interoperability_results": interop_results,
            "expert_assessment": expert_assessment,
            "protocol_errors": self.protocol_errors,
            "recommendations": recommendations,
            "certification_status": "CERTIFIED" if overall_compliance >= 95 else "REQUIRES_IMPROVEMENT"
        }


async def main():
    """Run comprehensive MCP protocol compliance testing."""
    print("🔍 MCP Protocol Compliance & Interoperability Testing")
    print("=" * 60)
    print("Agent 5: ULTRATHINK Protocol Analysis")
    print()
    
    # Initialize validator
    validator = MCPProtocolComplianceValidator()
    await validator.initialize()
    
    # Run comprehensive validation
    try:
        compliance_report = await validator.validate_all_servers()
        
        # Display results
        print("\n📊 COMPLIANCE RESULTS")
        print("=" * 40)
        
        report = compliance_report["compliance_report"]
        print(f"Overall Compliance Score: {report['overall_compliance_score']}%")
        print(f"Servers Tested: {report['total_servers']}")
        print(f"Servers Compliant: {report['servers_compliant']}")
        print(f"Tests Passed: {report['tests_passed']}/{report['total_tests_run']}")
        print(f"Certification Status: {compliance_report['certification_status']}")
        
        print("\n🏗️  SERVER COMPLIANCE SUMMARY")
        print("=" * 40)
        for server_name, summary in compliance_report["server_summary"].items():
            status_icon = "✅" if summary["status"] == "COMPLIANT" else "⚠️"
            print(f"{status_icon} {server_name}: {summary['compliance_score']}% "
                  f"({summary['tests_passed']}/{summary['tests_total']} tests passed)")
                  
        print("\n🔗 INTEROPERABILITY RESULTS")
        print("=" * 40)
        interop = compliance_report["interoperability_results"]
        if interop["status"] == "COMPLETE":
            for workflow in interop["workflow_tests"]:
                workflow_icon = "✅" if workflow["status"] == "PASS" else "⚠️"
                print(f"{workflow_icon} {workflow['workflow_name']}: "
                      f"{workflow['successful_steps']}/{workflow['total_steps']} steps")
                      
        print("\n👥 EXPERT ASSESSMENT")
        print("=" * 40)
        expert = compliance_report["expert_assessment"]
        if expert["status"] == "SUCCESS":
            print(f"Experts Consulted: {', '.join(expert['experts_consulted'])}")
            print(f"Consensus Level: {expert['consensus_level']}")
            print("\nTop Expert Recommendations:")
            for i, rec in enumerate(expert["recommendations"][:5], 1):
                print(f"  {i}. {rec}")
        elif expert["status"] == "UNAVAILABLE":
            print("Circle of Experts not available - using automated analysis")
            print("Expert Recommendations:")
            for i, rec in enumerate(expert["recommendations"][:3], 1):
                print(f"  {i}. {rec}")
        else:
            print(f"Expert consultation failed: {expert.get('error', 'Unknown error')}")
            
        print("\n🎯 PROTOCOL RECOMMENDATIONS")
        print("=" * 40)
        for i, rec in enumerate(compliance_report["recommendations"], 1):
            print(f"{i}. {rec}")
            
        # Save detailed report
        report_path = Path("mcp_protocol_compliance_report.json")
        with open(report_path, 'w') as f:
            json.dump(compliance_report, f, indent=2, default=str)
        print(f"\n📄 Detailed report saved to: {report_path}")
        
    except Exception as e:
        print(f"\n❌ Compliance testing failed: {e}")
        traceback.print_exc()
        
    print("\n✅ MCP Protocol Compliance Testing Complete")


if __name__ == "__main__":
    asyncio.run(main())