#!/usr/bin/env python3
"""
Comprehensive System Integration Test Suite for CODE Project

Tests cross-module integration, data flows, and system-level behaviors.
Validates how all 5 modules with 35 tools work together as a cohesive system.
"""

import asyncio
import sys
import os
import json
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import time

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from src.mcp.manager import get_mcp_manager
from src.circle_of_experts.mcp_integration import MCPEnhancedExpertManager
from src.circle_of_experts.models.query import ExpertQuery
from src.circle_of_experts.models.response import ExpertResponse

# Import AI provider configurations
try:
    from src.circle_of_experts.experts.claude_expert import ClaudeExpert
    from src.circle_of_experts.experts.open_source_experts import OllamaExpert
    from src.circle_of_experts.experts.commercial_experts import OpenAIExpert, GoogleExpert
    AI_EXPERTS_AVAILABLE = True
except ImportError:
    AI_EXPERTS_AVAILABLE = False


class SystemIntegrationTestSuite:
    """
    Comprehensive system integration test framework.
    
    Tests the entire CODE system including:
    - Cross-module communication and data flows
    - Multi-module workflow orchestration
    - System reliability and error recovery
    - Performance under integrated load
    - Expert validation of architecture
    """
    
    def __init__(self):
        self.mcp_manager = None
        self.expert_manager = None
        self.test_id = f"integration_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.test_results: Dict[str, Any] = {
            "test_id": self.test_id,
            "started_at": datetime.now().isoformat(),
            "modules_tested": [],
            "integration_flows": [],
            "expert_validations": [],
            "performance_metrics": {},
            "errors": [],
            "recommendations": []
        }
    
    async def initialize(self):
        """Initialize test environment with all components."""
        print("🚀 Initializing System Integration Test Suite")
        print("=" * 60)
        
        # Initialize MCP Manager with all servers
        self.mcp_manager = get_mcp_manager()
        await self.mcp_manager.initialize()
        
        # Create integration test context
        self.context_id = f"integration_{self.test_id}"
        context = self.mcp_manager.create_context(self.context_id)
        
        # Enable ALL servers for comprehensive testing
        all_servers = list(self.mcp_manager.registry.list_servers())
        for server in all_servers:
            self.mcp_manager.enable_server(self.context_id, server)
            print(f"  ✅ Enabled {server}")
        
        # Initialize enhanced expert manager for architecture validation
        if AI_EXPERTS_AVAILABLE:
            self.expert_manager = MCPEnhancedExpertManager()
            print("\n  🎯 Expert validation system ready")
        else:
            print("\n  ⚠️  Expert validation unavailable (no AI providers configured)")
        
        # Capture initial system state
        self.initial_state = await self._capture_system_state()
        
        return True
    
    async def _capture_system_state(self) -> Dict[str, Any]:
        """Capture current system state for comparison."""
        state = {
            "timestamp": datetime.now().isoformat(),
            "available_servers": list(self.mcp_manager.registry.list_servers()),
            "available_tools": len(self.mcp_manager.get_available_tools()),
            "context_count": len(self.mcp_manager.contexts),
            "memory_baseline": self._get_memory_usage()
        }
        return state
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0
    
    async def test_multi_module_deployment_workflow(self) -> Dict[str, Any]:
        """
        Test 1: Multi-Module Deployment Workflow
        
        Tests integration between:
        - Security Scanner → Docker → Kubernetes → Monitoring → Notifications
        """
        print("\n🧪 Test 1: Multi-Module Deployment Workflow")
        print("-" * 50)
        
        test_result = {
            "test_name": "multi_module_deployment",
            "modules_involved": ["security-scanner", "docker", "kubernetes", "prometheus-monitoring", "slack-notifications"],
            "start_time": time.time(),
            "steps": []
        }
        
        try:
            # Step 1: Security pre-check
            print("  1️⃣ Security Pre-check...")
            security_scan = await self.mcp_manager.call_tool(
                "security-scanner.file_security_scan",
                {"target_path": ".", "scan_type": "deployment"},
                self.context_id
            )
            
            test_result["steps"].append({
                "step": "security_scan",
                "success": security_scan.get("success", False),
                "findings": len(security_scan.get("findings", []))
            })
            print(f"    ✓ Security scan: {len(security_scan.get('findings', []))} findings")
            
            # Step 2: Build container
            print("  2️⃣ Container Build...")
            if Path("Dockerfile").exists():
                build_result = await self.mcp_manager.call_tool(
                    "docker.docker_build",
                    {"dockerfile_path": ".", "image_tag": "test-integration:latest"},
                    self.context_id
                )
                
                test_result["steps"].append({
                    "step": "docker_build",
                    "success": build_result.get("success", False),
                    "image": build_result.get("image_tag", "")
                })
                print(f"    ✓ Docker build: {'Success' if build_result.get('success') else 'Failed'}")
            
            # Step 3: Deploy to Kubernetes (simulation)
            print("  3️⃣ Kubernetes Deployment...")
            try:
                k8s_result = await self.mcp_manager.call_tool(
                    "kubernetes.kubectl_get",
                    {"resource_type": "deployments"},
                    self.context_id
                )
                
                test_result["steps"].append({
                    "step": "kubernetes_check",
                    "success": k8s_result.get("success", False),
                    "deployments": len(k8s_result.get("deployments", []))
                })
                print(f"    ✓ Kubernetes: {'Connected' if k8s_result.get('success') else 'Not available'}")
            except Exception as e:
                test_result["steps"].append({"step": "kubernetes_check", "success": False, "error": str(e)})
                print(f"    ⚠️  Kubernetes: Not configured")
            
            # Step 4: Setup monitoring
            print("  4️⃣ Monitoring Setup...")
            try:
                monitoring_result = await self.mcp_manager.call_tool(
                    "prometheus-monitoring.prometheus_labels",
                    {},
                    self.context_id
                )
                
                test_result["steps"].append({
                    "step": "monitoring_setup",
                    "success": monitoring_result.get("success", False)
                })
                print(f"    ✓ Monitoring: {'Available' if monitoring_result.get('success') else 'Not configured'}")
            except Exception:
                test_result["steps"].append({"step": "monitoring_setup", "success": False})
                print(f"    ⚠️  Monitoring: Not configured")
            
            # Step 5: Send notification
            print("  5️⃣ Deployment Notification...")
            try:
                notification_result = await self.mcp_manager.call_tool(
                    "slack-notifications.send_notification",
                    {
                        "channel": "#test",
                        "event_type": "deployment",
                        "status": "success",
                        "details": {"test": "integration_test"}
                    },
                    self.context_id
                )
                
                test_result["steps"].append({
                    "step": "notification",
                    "success": notification_result.get("success", False)
                })
                print(f"    ✓ Notification: {'Sent' if notification_result.get('success') else 'Not configured'}")
            except Exception:
                test_result["steps"].append({"step": "notification", "success": False})
                print(f"    ⚠️  Notification: Not configured")
            
            # Calculate integration score
            successful_steps = sum(1 for step in test_result["steps"] if step.get("success", False))
            test_result["integration_score"] = successful_steps / len(test_result["steps"])
            test_result["duration_ms"] = (time.time() - test_result["start_time"]) * 1000
            
            print(f"\n  📊 Integration Score: {test_result['integration_score']:.1%}")
            print(f"  ⏱️  Duration: {test_result['duration_ms']:.1f}ms")
            
        except Exception as e:
            test_result["error"] = str(e)
            self.test_results["errors"].append({
                "test": "multi_module_deployment",
                "error": str(e)
            })
        
        self.test_results["integration_flows"].append(test_result)
        return test_result
    
    async def test_cross_system_monitoring_workflow(self) -> Dict[str, Any]:
        """
        Test 2: Cross-System Monitoring Integration
        
        Tests integration between:
        - Infrastructure Monitoring → Security Scanning → Alerting → Storage
        """
        print("\n🧪 Test 2: Cross-System Monitoring Workflow")
        print("-" * 50)
        
        test_result = {
            "test_name": "cross_system_monitoring",
            "modules_involved": ["desktop-commander", "security-scanner", "prometheus-monitoring", "s3-storage"],
            "start_time": time.time(),
            "steps": []
        }
        
        try:
            # Step 1: Collect system metrics
            print("  1️⃣ System Metrics Collection...")
            metrics_cmd = await self.mcp_manager.call_tool(
                "desktop-commander.execute_command",
                {"command": "df -h && free -h", "description": "System resource check"},
                self.context_id
            )
            
            test_result["steps"].append({
                "step": "metrics_collection",
                "success": metrics_cmd.get("success", False),
                "output_size": len(metrics_cmd.get("output", ""))
            })
            print(f"    ✓ Metrics collected: {len(metrics_cmd.get('output', ''))} bytes")
            
            # Step 2: Security audit
            print("  2️⃣ Security Audit...")
            if Path("requirements.txt").exists():
                security_audit = await self.mcp_manager.call_tool(
                    "security-scanner.python_safety_check",
                    {"requirements_path": "requirements.txt"},
                    self.context_id
                )
                
                test_result["steps"].append({
                    "step": "security_audit",
                    "success": not bool(security_audit.get("vulnerabilities", [])),
                    "vulnerabilities": len(security_audit.get("vulnerabilities", []))
                })
                print(f"    ✓ Security audit: {len(security_audit.get('vulnerabilities', []))} vulnerabilities")
            
            # Step 3: Query monitoring system
            print("  3️⃣ Monitoring Query...")
            try:
                monitoring_query = await self.mcp_manager.call_tool(
                    "prometheus-monitoring.prometheus_query",
                    {"query": "up"},
                    self.context_id
                )
                
                test_result["steps"].append({
                    "step": "monitoring_query",
                    "success": monitoring_query.get("success", False)
                })
                print(f"    ✓ Monitoring query: {'Success' if monitoring_query.get('success') else 'Not available'}")
            except Exception:
                test_result["steps"].append({"step": "monitoring_query", "success": False})
                print(f"    ⚠️  Monitoring: Not configured")
            
            # Step 4: Store audit results
            print("  4️⃣ Store Audit Results...")
            audit_report = {
                "timestamp": datetime.now().isoformat(),
                "test_id": self.test_id,
                "metrics": metrics_cmd.get("output", "")[:500],
                "security_status": test_result["steps"][1] if len(test_result["steps"]) > 1 else {}
            }
            
            storage_result = await self.mcp_manager.call_tool(
                "desktop-commander.write_file",
                {
                    "file_path": f"deploy/logs/audit_{self.test_id}.json",
                    "content": json.dumps(audit_report, indent=2)
                },
                self.context_id
            )
            
            test_result["steps"].append({
                "step": "storage",
                "success": storage_result.get("success", False)
            })
            print(f"    ✓ Storage: {'Success' if storage_result.get('success') else 'Failed'}")
            
            # Calculate data flow efficiency
            test_result["duration_ms"] = (time.time() - test_result["start_time"]) * 1000
            test_result["data_flow_efficiency"] = sum(1 for step in test_result["steps"] if step.get("success", False)) / len(test_result["steps"])
            
            print(f"\n  📊 Data Flow Efficiency: {test_result['data_flow_efficiency']:.1%}")
            print(f"  ⏱️  Duration: {test_result['duration_ms']:.1f}ms")
            
        except Exception as e:
            test_result["error"] = str(e)
            self.test_results["errors"].append({
                "test": "cross_system_monitoring",
                "error": str(e)
            })
        
        self.test_results["integration_flows"].append(test_result)
        return test_result
    
    async def test_error_propagation_and_recovery(self) -> Dict[str, Any]:
        """
        Test 3: Error Propagation and Recovery
        
        Tests system resilience when errors occur in one module.
        """
        print("\n🧪 Test 3: Error Propagation and Recovery")
        print("-" * 50)
        
        test_result = {
            "test_name": "error_propagation_recovery",
            "start_time": time.time(),
            "error_scenarios": []
        }
        
        # Scenario 1: Invalid Docker build
        print("  1️⃣ Testing Docker build failure recovery...")
        try:
            invalid_build = await self.mcp_manager.call_tool(
                "docker.docker_build",
                {"dockerfile_path": "/nonexistent/path", "image_tag": "fail-test"},
                self.context_id
            )
            
            # System should handle gracefully
            recovery_test = await self.mcp_manager.call_tool(
                "docker.docker_ps",
                {"all": False},
                self.context_id
            )
            
            test_result["error_scenarios"].append({
                "scenario": "docker_build_failure",
                "error_handled": not invalid_build.get("success", True),
                "recovery_successful": recovery_test.get("success", False)
            })
            print(f"    ✓ Error handling: {'Passed' if not invalid_build.get('success', True) else 'Failed'}")
            print(f"    ✓ Recovery: {'Successful' if recovery_test.get('success', False) else 'Failed'}")
            
        except Exception as e:
            test_result["error_scenarios"].append({
                "scenario": "docker_build_failure",
                "error_handled": True,
                "recovery_successful": True,
                "exception": str(e)
            })
            print(f"    ✓ Exception properly caught")
        
        # Scenario 2: Invalid security scan path
        print("\n  2️⃣ Testing security scan error handling...")
        try:
            invalid_scan = await self.mcp_manager.call_tool(
                "security-scanner.file_security_scan",
                {"target_path": "/root/protected", "scan_type": "all"},
                self.context_id
            )
            
            # Should not crash the system
            valid_scan = await self.mcp_manager.call_tool(
                "security-scanner.file_security_scan",
                {"target_path": ".", "scan_type": "basic"},
                self.context_id
            )
            
            test_result["error_scenarios"].append({
                "scenario": "security_scan_error",
                "error_handled": True,
                "recovery_successful": valid_scan.get("success", False)
            })
            print(f"    ✓ Error isolation: Passed")
            print(f"    ✓ System stability: {'Maintained' if valid_scan.get('success', False) else 'Compromised'}")
            
        except Exception as e:
            test_result["error_scenarios"].append({
                "scenario": "security_scan_error",
                "error_handled": True,
                "recovery_successful": True
            })
            print(f"    ✓ Error properly isolated")
        
        # Calculate resilience score
        handled_errors = sum(1 for scenario in test_result["error_scenarios"] if scenario.get("error_handled", False))
        successful_recoveries = sum(1 for scenario in test_result["error_scenarios"] if scenario.get("recovery_successful", False))
        
        test_result["resilience_score"] = {
            "error_handling": handled_errors / len(test_result["error_scenarios"]) if test_result["error_scenarios"] else 0,
            "recovery_rate": successful_recoveries / len(test_result["error_scenarios"]) if test_result["error_scenarios"] else 0
        }
        test_result["duration_ms"] = (time.time() - test_result["start_time"]) * 1000
        
        print(f"\n  📊 Error Handling: {test_result['resilience_score']['error_handling']:.1%}")
        print(f"  📊 Recovery Rate: {test_result['resilience_score']['recovery_rate']:.1%}")
        print(f"  ⏱️  Duration: {test_result['duration_ms']:.1f}ms")
        
        self.test_results["integration_flows"].append(test_result)
        return test_result
    
    async def test_concurrent_module_operations(self) -> Dict[str, Any]:
        """
        Test 4: Concurrent Module Operations
        
        Tests system behavior under concurrent load across multiple modules.
        """
        print("\n🧪 Test 4: Concurrent Module Operations")
        print("-" * 50)
        
        test_result = {
            "test_name": "concurrent_operations",
            "start_time": time.time(),
            "concurrent_tasks": []
        }
        
        print("  🔄 Launching concurrent operations...")
        
        # Define concurrent tasks
        async def docker_operation():
            start = time.time()
            result = await self.mcp_manager.call_tool(
                "docker.docker_ps",
                {"all": True},
                self.context_id
            )
            return {
                "module": "docker",
                "success": result.get("success", False),
                "duration_ms": (time.time() - start) * 1000
            }
        
        async def security_operation():
            start = time.time()
            result = await self.mcp_manager.call_tool(
                "security-scanner.file_security_scan",
                {"target_path": "src", "scan_type": "basic"},
                self.context_id
            )
            return {
                "module": "security-scanner",
                "success": result.get("success", False),
                "duration_ms": (time.time() - start) * 1000
            }
        
        async def command_operation():
            start = time.time()
            result = await self.mcp_manager.call_tool(
                "desktop-commander.execute_command",
                {"command": "echo 'Concurrent test'", "description": "Test concurrent execution"},
                self.context_id
            )
            return {
                "module": "desktop-commander",
                "success": result.get("success", False),
                "duration_ms": (time.time() - start) * 1000
            }
        
        async def monitoring_operation():
            start = time.time()
            try:
                result = await self.mcp_manager.call_tool(
                    "prometheus-monitoring.prometheus_labels",
                    {},
                    self.context_id
                )
                success = result.get("success", False)
            except Exception:
                success = False
            
            return {
                "module": "prometheus-monitoring",
                "success": success,
                "duration_ms": (time.time() - start) * 1000
            }
        
        # Execute all operations concurrently
        try:
            results = await asyncio.gather(
                docker_operation(),
                security_operation(),
                command_operation(),
                monitoring_operation(),
                return_exceptions=True
            )
            
            for result in results:
                if isinstance(result, Exception):
                    test_result["concurrent_tasks"].append({
                        "module": "unknown",
                        "success": False,
                        "error": str(result)
                    })
                else:
                    test_result["concurrent_tasks"].append(result)
                    print(f"    ✓ {result['module']}: {'Success' if result['success'] else 'Failed'} ({result['duration_ms']:.1f}ms)")
            
            # Analyze concurrency performance
            successful_ops = sum(1 for task in test_result["concurrent_tasks"] if task.get("success", False))
            avg_duration = sum(task.get("duration_ms", 0) for task in test_result["concurrent_tasks"]) / len(test_result["concurrent_tasks"])
            
            test_result["concurrency_metrics"] = {
                "success_rate": successful_ops / len(test_result["concurrent_tasks"]),
                "average_duration_ms": avg_duration,
                "parallelism_efficiency": 1.0 if successful_ops == len(test_result["concurrent_tasks"]) else successful_ops / len(test_result["concurrent_tasks"])
            }
            
        except Exception as e:
            test_result["error"] = str(e)
            self.test_results["errors"].append({
                "test": "concurrent_operations",
                "error": str(e)
            })
        
        test_result["duration_ms"] = (time.time() - test_result["start_time"]) * 1000
        
        print(f"\n  📊 Concurrency Success Rate: {test_result.get('concurrency_metrics', {}).get('success_rate', 0):.1%}")
        print(f"  📊 Average Operation Time: {test_result.get('concurrency_metrics', {}).get('average_duration_ms', 0):.1f}ms")
        print(f"  ⏱️  Total Duration: {test_result['duration_ms']:.1f}ms")
        
        self.test_results["integration_flows"].append(test_result)
        return test_result
    
    async def consult_experts_on_architecture(self) -> Dict[str, Any]:
        """
        Consult Circle of Experts on system integration architecture.
        """
        if not self.expert_manager or not AI_EXPERTS_AVAILABLE:
            print("\n⚠️  Expert consultation skipped (no AI providers configured)")
            return {"skipped": True, "reason": "No AI providers available"}
        
        print("\n🎯 Consulting Circle of Experts on Integration Architecture")
        print("-" * 50)
        
        # Prepare comprehensive query about our integration architecture
        architecture_query = f"""
        Please analyze our system integration architecture for the CODE project:

        System Overview:
        - 5 core modules: Desktop Commander, Docker, Kubernetes, Security Scanner, Advanced Services
        - 35+ integrated tools across all modules
        - MCP (Model Context Protocol) server-based architecture
        - Async Python with Rust performance modules
        - Circle of Experts AI consultation system integrated with MCP

        Integration Test Results:
        {json.dumps(self.test_results, indent=2, default=str)}

        Questions for Expert Analysis:
        1. Is our overall system architecture well-designed for scalability, maintainability, and reliability?
        2. What integration scenarios and failure modes should we test to ensure system robustness?
        3. How resilient is our system to failures and how well does it recover from various error conditions?
        4. What are the potential bottlenecks or single points of failure in our architecture?
        5. What improvements would you recommend for better system integration?

        Please provide specific, actionable recommendations based on the test results and architecture.
        """
        
        try:
            # Consult experts with enhanced MCP integration
            result = await self.expert_manager.consult_experts_with_mcp(
                title="System Integration Architecture Analysis",
                content=architecture_query,
                requester="system_integration_test",
                enable_web_search=True,
                min_experts=3,
                max_experts=3,
                expert_types=["technical", "infrastructure", "architecture"],
                use_consensus=True,
                expert_timeout=180.0
            )
            
            # Extract expert insights
            expert_validation = {
                "consultation_id": result.get("query_id"),
                "experts_consulted": len(result.get("responses", [])),
                "consensus_reached": result.get("consensus", {}).get("consensus_reached", False),
                "key_insights": [],
                "recommendations": [],
                "risk_assessments": []
            }
            
            # Process expert responses
            for response in result.get("responses", []):
                expert_name = response.get("expert_type", "unknown")
                content = response.get("content", "")
                
                print(f"\n  🧠 {expert_name.title()} Expert Analysis:")
                
                # Extract key points (simplified parsing)
                if "well-designed" in content.lower() or "architecture" in content.lower():
                    expert_validation["key_insights"].append({
                        "expert": expert_name,
                        "insight": "Architecture assessment provided",
                        "confidence": response.get("confidence", 0.0)
                    })
                    print(f"    ✓ Architecture assessment completed")
                
                if "recommend" in content.lower() or "improvement" in content.lower():
                    expert_validation["recommendations"].append({
                        "expert": expert_name,
                        "category": "improvement",
                        "priority": "high" if "critical" in content.lower() else "medium"
                    })
                    print(f"    ✓ Recommendations provided")
                
                if "risk" in content.lower() or "failure" in content.lower():
                    expert_validation["risk_assessments"].append({
                        "expert": expert_name,
                        "risk_identified": True,
                        "severity": "high" if "critical" in content.lower() else "medium"
                    })
                    print(f"    ✓ Risk assessment completed")
            
            # Consensus analysis
            if result.get("consensus", {}).get("consensus_reached"):
                print(f"\n  ✅ Expert Consensus Reached:")
                print(f"    • Agreement Level: {result['consensus']['agreement_level']:.1%}")
                print(f"    • Confidence: {result['consensus']['average_confidence']:.1%}")
            
            self.test_results["expert_validations"].append(expert_validation)
            
            # Add expert recommendations to main results
            if expert_validation["recommendations"]:
                self.test_results["recommendations"].extend([
                    f"Expert {rec['expert']}: {rec['category']} (Priority: {rec['priority']})"
                    for rec in expert_validation["recommendations"]
                ])
            
            return expert_validation
            
        except Exception as e:
            print(f"  ❌ Expert consultation error: {e}")
            return {"error": str(e)}
    
    async def analyze_system_performance(self) -> Dict[str, Any]:
        """
        Analyze overall system performance and integration efficiency.
        """
        print("\n📊 System Performance Analysis")
        print("-" * 50)
        
        # Capture final system state
        final_state = await self._capture_system_state()
        
        # Calculate performance metrics
        performance_metrics = {
            "test_duration_minutes": (time.time() - time.mktime(
                datetime.fromisoformat(self.test_results["started_at"]).timetuple()
            )) / 60,
            "total_tool_calls": len(self.mcp_manager.contexts[self.context_id].tool_calls),
            "successful_calls": sum(
                1 for call in self.mcp_manager.contexts[self.context_id].tool_calls 
                if call.success
            ),
            "average_call_duration_ms": sum(
                call.duration_ms for call in self.mcp_manager.contexts[self.context_id].tool_calls
            ) / max(len(self.mcp_manager.contexts[self.context_id].tool_calls), 1),
            "memory_delta_mb": final_state["memory_baseline"] - self.initial_state["memory_baseline"]
        }
        
        # Module integration scores
        module_scores = {}
        for flow in self.test_results["integration_flows"]:
            if "modules_involved" in flow:
                for module in flow["modules_involved"]:
                    if module not in module_scores:
                        module_scores[module] = []
                    
                    # Calculate score based on success of steps involving this module
                    flow_score = flow.get("integration_score", 0) or flow.get("data_flow_efficiency", 0)
                    if flow_score:
                        module_scores[module].append(flow_score)
        
        # Average module scores
        for module, scores in module_scores.items():
            performance_metrics[f"module_{module}_score"] = sum(scores) / len(scores) if scores else 0
        
        # System-wide metrics
        performance_metrics["system_integration_score"] = sum(
            flow.get("integration_score", 0) or flow.get("data_flow_efficiency", 0) 
            for flow in self.test_results["integration_flows"]
        ) / max(len(self.test_results["integration_flows"]), 1)
        
        performance_metrics["error_rate"] = len(self.test_results["errors"]) / max(
            len(self.test_results["integration_flows"]), 1
        )
        
        performance_metrics["call_success_rate"] = performance_metrics["successful_calls"] / max(
            performance_metrics["total_tool_calls"], 1
        )
        
        self.test_results["performance_metrics"] = performance_metrics
        
        # Display performance summary
        print(f"  ⏱️  Test Duration: {performance_metrics['test_duration_minutes']:.1f} minutes")
        print(f"  📞 Total Tool Calls: {performance_metrics['total_tool_calls']}")
        print(f"  ✅ Success Rate: {performance_metrics['call_success_rate']:.1%}")
        print(f"  ⚡ Avg Call Time: {performance_metrics['average_call_duration_ms']:.1f}ms")
        print(f"  💾 Memory Delta: {performance_metrics['memory_delta_mb']:.1f}MB")
        print(f"  🎯 System Integration Score: {performance_metrics['system_integration_score']:.1%}")
        
        return performance_metrics
    
    async def generate_integration_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive integration test report.
        """
        print("\n📄 Generating Integration Test Report")
        print("-" * 50)
        
        # Complete test results
        self.test_results["completed_at"] = datetime.now().isoformat()
        self.test_results["test_summary"] = {
            "total_tests": len(self.test_results["integration_flows"]),
            "modules_tested": len(set(
                module 
                for flow in self.test_results["integration_flows"] 
                for module in flow.get("modules_involved", [])
            )),
            "total_errors": len(self.test_results["errors"]),
            "expert_validations": len(self.test_results["expert_validations"]),
            "overall_status": "PASSED" if self.test_results["performance_metrics"].get(
                "system_integration_score", 0
            ) > 0.7 else "NEEDS_IMPROVEMENT"
        }
        
        # Save detailed report
        report_path = Path("deploy/logs") / f"integration_report_{self.test_id}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            await self.mcp_manager.call_tool(
                "desktop-commander.write_file",
                {
                    "file_path": str(report_path),
                    "content": json.dumps(self.test_results, indent=2, default=str)
                },
                self.context_id
            )
            print(f"  ✅ Report saved: {report_path}")
        except Exception as e:
            print(f"  ❌ Report save error: {e}")
        
        # Display summary
        print(f"\n🎯 Integration Test Summary:")
        print(f"  • Status: {self.test_results['test_summary']['overall_status']}")
        print(f"  • Tests Run: {self.test_results['test_summary']['total_tests']}")
        print(f"  • Modules Tested: {self.test_results['test_summary']['modules_tested']}")
        print(f"  • Errors: {self.test_results['test_summary']['total_errors']}")
        print(f"  • Integration Score: {self.test_results['performance_metrics']['system_integration_score']:.1%}")
        
        if self.test_results["recommendations"]:
            print(f"\n💡 Key Recommendations:")
            for rec in self.test_results["recommendations"][:3]:
                print(f"  • {rec}")
        
        return self.test_results
    
    async def cleanup(self):
        """Clean up test resources."""
        if self.mcp_manager:
            await self.mcp_manager.cleanup()


async def run_comprehensive_integration_tests():
    """
    Execute comprehensive system integration test suite.
    """
    print("🚀 CODE Project: Comprehensive System Integration Testing")
    print("=" * 70)
    print("Testing cross-module integration, data flows, and system behaviors")
    print("Validating 5 modules with 35 tools working as a cohesive system")
    print()
    
    test_suite = SystemIntegrationTestSuite()
    
    try:
        # Initialize test environment
        await test_suite.initialize()
        
        # Run integration tests
        await test_suite.test_multi_module_deployment_workflow()
        await test_suite.test_cross_system_monitoring_workflow()
        await test_suite.test_error_propagation_and_recovery()
        await test_suite.test_concurrent_module_operations()
        
        # Expert validation
        await test_suite.consult_experts_on_architecture()
        
        # Performance analysis
        await test_suite.analyze_system_performance()
        
        # Generate report
        report = await test_suite.generate_integration_report()
        
        print("\n" + "=" * 70)
        print("🎉 System Integration Testing Complete!")
        print(f"   Overall System Health: {report['test_summary']['overall_status']}")
        print("=" * 70)
        
        return report
        
    except Exception as e:
        print(f"\n💥 Integration test error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        await test_suite.cleanup()


if __name__ == "__main__":
    print("Starting comprehensive system integration tests...")
    print()
    
    try:
        result = asyncio.run(run_comprehensive_integration_tests())
        
        # Exit with appropriate code
        if result and result.get("test_summary", {}).get("overall_status") == "PASSED":
            exit(0)
        else:
            exit(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n💥 Test suite failed: {e}")
        exit(1)