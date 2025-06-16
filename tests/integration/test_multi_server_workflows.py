#!/usr/bin/env python3
"""
Integration tests for multi-server MCP workflows
Tests complex scenarios involving multiple MCP servers working together
"""

import pytest
import asyncio
import time
import json
from typing import Dict, Any, List
from pathlib import Path
import sys

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "mocks"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from mcp_server_mocks import (
    create_all_mock_servers,
    MockDesktopCommanderServer,
    MockDockerServer,
    MockKubernetesServer,
    MockSecurityScannerServer,
    MockPrometheusServer,
    MockBraveSearchServer
)


class MockMCPOrchestrator:
    """Mock orchestrator for managing multiple MCP servers"""
    
    def __init__(self):
        self.servers = {}
        self.workflow_history = []
        self.context_data = {}
    
    def register_server(self, name: str, server):
        """Register an MCP server"""
        self.servers[name] = server
    
    async def execute_workflow(self, workflow_definition: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a multi-step workflow across servers"""
        workflow_id = f"workflow_{int(time.time())}"
        workflow_result = {
            "workflow_id": workflow_id,
            "steps": [],
            "success": True,
            "start_time": time.time(),
            "context": {}
        }
        
        try:
            for step_idx, step in enumerate(workflow_definition["steps"]):
                step_result = await self._execute_step(step, workflow_result["context"])
                workflow_result["steps"].append(step_result)
                
                # Update context with step results
                if step_result["success"] and step.get("save_to_context"):
                    for key, value_path in step["save_to_context"].items():
                        workflow_result["context"][key] = self._extract_value(
                            step_result["result"], value_path
                        )
                
                # Stop on failure if not marked as optional
                if not step_result["success"] and not step.get("optional", False):
                    workflow_result["success"] = False
                    break
        
        except Exception as e:
            workflow_result["success"] = False
            workflow_result["error"] = str(e)
        
        workflow_result["end_time"] = time.time()
        workflow_result["duration"] = workflow_result["end_time"] - workflow_result["start_time"]
        
        self.workflow_history.append(workflow_result)
        return workflow_result
    
    async def _execute_step(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single workflow step"""
        step_start_time = time.time()
        
        try:
            server_name = step["server"]
            tool_name = step["tool"]
            parameters = step.get("parameters", {})
            
            # Substitute context variables in parameters
            parameters = self._substitute_context_variables(parameters, context)
            
            if server_name not in self.servers:
                raise Exception(f"Server {server_name} not found")
            
            server = self.servers[server_name]
            result = await server.call_tool(tool_name, parameters)
            
            return {
                "step_name": step.get("name", f"{server_name}.{tool_name}"),
                "server": server_name,
                "tool": tool_name,
                "parameters": parameters,
                "success": True,
                "result": result,
                "duration": time.time() - step_start_time
            }
            
        except Exception as e:
            return {
                "step_name": step.get("name", f"{server_name}.{tool_name}"),
                "server": server_name,
                "tool": tool_name,
                "success": False,
                "error": str(e),
                "duration": time.time() - step_start_time
            }
    
    def _substitute_context_variables(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Substitute context variables in parameters"""
        if isinstance(parameters, dict):
            result = {}
            for key, value in parameters.items():
                if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                    context_key = value[2:-1]
                    result[key] = context.get(context_key, value)
                elif isinstance(value, (dict, list)):
                    result[key] = self._substitute_context_variables(value, context)
                else:
                    result[key] = value
            return result
        elif isinstance(parameters, list):
            return [self._substitute_context_variables(item, context) for item in parameters]
        else:
            return parameters
    
    def _extract_value(self, data: Dict[str, Any], path: str) -> Any:
        """Extract value from nested data using dot notation"""
        keys = path.split(".")
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current


@pytest.fixture
async def orchestrator():
    """Create orchestrator with all mock servers"""
    orch = MockMCPOrchestrator()
    
    # Register all servers
    servers = create_all_mock_servers()
    for name, server in servers.items():
        orch.register_server(name, server)
    
    yield orch
    
    # Cleanup
    for server in servers.values():
        server.cleanup()


@pytest.mark.integration
class TestDevOpsWorkflows:
    """Test DevOps-related workflows"""
    
    async def test_build_deploy_monitor_workflow(self, orchestrator):
        """Test complete build -> deploy -> monitor workflow"""
        workflow = {
            "name": "build-deploy-monitor",
            "description": "Build container, deploy to K8s, monitor metrics",
            "steps": [
                {
                    "name": "build_container",
                    "server": "docker",
                    "tool": "docker_build",
                    "parameters": {
                        "dockerfile_path": "./Dockerfile",
                        "tag": "myapp:latest"
                    },
                    "save_to_context": {
                        "image_id": "result.image_id",
                        "image_tag": "result.tag"
                    }
                },
                {
                    "name": "deploy_to_kubernetes",
                    "server": "kubernetes",
                    "tool": "kubectl_apply",
                    "parameters": {
                        "manifest": {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "metadata": {
                                "name": "myapp-deployment",
                                "namespace": "default"
                            },
                            "spec": {
                                "replicas": 3,
                                "selector": {
                                    "matchLabels": {
                                        "app": "myapp"
                                    }
                                },
                                "template": {
                                    "metadata": {
                                        "labels": {
                                            "app": "myapp"
                                        }
                                    },
                                    "spec": {
                                        "containers": [
                                            {
                                                "name": "myapp",
                                                "image": "${image_tag}",
                                                "ports": [{"containerPort": 8080}]
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    },
                    "save_to_context": {
                        "deployment_name": "result.name",
                        "namespace": "result.namespace"
                    }
                },
                {
                    "name": "verify_deployment",
                    "server": "kubernetes",
                    "tool": "kubectl_get",
                    "parameters": {
                        "resource_type": "deployment",
                        "name": "myapp-deployment",
                        "namespace": "default"
                    }
                },
                {
                    "name": "check_metrics",
                    "server": "prometheus-monitoring",
                    "tool": "prometheus_query",
                    "parameters": {
                        "query": "up{job=\"myapp\"}"
                    }
                }
            ]
        }
        
        result = await orchestrator.execute_workflow(workflow)
        
        assert result["success"] is True
        assert len(result["steps"]) == 4
        assert all(step["success"] for step in result["steps"])
        
        # Verify context propagation
        assert "image_id" in result["context"]
        assert "image_tag" in result["context"]
        assert result["context"]["image_tag"] == "myapp:latest"
        
        # Verify deployment step used context variable
        deploy_step = result["steps"][1]
        deployed_image = deploy_step["parameters"]["manifest"]["spec"]["template"]["spec"]["containers"][0]["image"]
        assert deployed_image == "myapp:latest"
    
    async def test_security_scan_workflow(self, orchestrator):
        """Test security scanning workflow"""
        workflow = {
            "name": "security-scan",
            "description": "Comprehensive security scanning",
            "steps": [
                {
                    "name": "scan_dependencies",
                    "server": "security-scanner",
                    "tool": "scan_dependencies",
                    "parameters": {
                        "manifest_path": "./package.json",
                        "scan_type": "comprehensive"
                    },
                    "save_to_context": {
                        "dep_vulnerabilities": "result.total_vulnerabilities"
                    }
                },
                {
                    "name": "scan_container",
                    "server": "security-scanner",
                    "tool": "scan_container",
                    "parameters": {
                        "image": "myapp:latest",
                        "severity_threshold": "medium"
                    },
                    "save_to_context": {
                        "container_vulnerabilities": "result.total_vulnerabilities"
                    }
                },
                {
                    "name": "scan_code",
                    "server": "security-scanner",
                    "tool": "scan_code",
                    "parameters": {
                        "source_path": "./src",
                        "language": "python"
                    },
                    "save_to_context": {
                        "code_issues": "result.total_issues"
                    }
                }
            ]
        }
        
        result = await orchestrator.execute_workflow(workflow)
        
        assert result["success"] is True
        assert len(result["steps"]) == 3
        assert all(step["success"] for step in result["steps"])
        
        # Verify security scan results
        assert "dep_vulnerabilities" in result["context"]
        assert "container_vulnerabilities" in result["context"]
        assert "code_issues" in result["context"]
    
    async def test_disaster_recovery_workflow(self, orchestrator):
        """Test disaster recovery workflow"""
        workflow = {
            "name": "disaster-recovery",
            "description": "Backup, restore, and verify system",
            "steps": [
                {
                    "name": "backup_config",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "kubectl get all -n production -o yaml > backup.yaml"
                    },
                    "save_to_context": {
                        "backup_status": "result.exit_code"
                    }
                },
                {
                    "name": "simulate_failure",
                    "server": "kubernetes",
                    "tool": "kubectl_delete",
                    "parameters": {
                        "resource_type": "deployment",
                        "name": "myapp-deployment",
                        "namespace": "production"
                    },
                    "optional": True
                },
                {
                    "name": "restore_from_backup",
                    "server": "kubernetes",
                    "tool": "kubectl_apply",
                    "parameters": {
                        "manifest": {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "metadata": {
                                "name": "myapp-deployment",
                                "namespace": "production"
                            },
                            "spec": {
                                "replicas": 2
                            }
                        }
                    }
                },
                {
                    "name": "verify_recovery",
                    "server": "prometheus-monitoring",
                    "tool": "prometheus_query",
                    "parameters": {
                        "query": "up{namespace=\"production\"}"
                    }
                }
            ]
        }
        
        result = await orchestrator.execute_workflow(workflow)
        
        assert result["success"] is True
        assert len(result["steps"]) == 4
        
        # Even if deletion fails (optional), workflow should continue
        assert result["steps"][2]["success"] is True  # restore
        assert result["steps"][3]["success"] is True  # verify


@pytest.mark.integration
class TestDataProcessingWorkflows:
    """Test data processing workflows"""
    
    async def test_etl_pipeline_workflow(self, orchestrator):
        """Test Extract-Transform-Load pipeline"""
        workflow = {
            "name": "etl-pipeline",
            "description": "Extract data, transform, and load to destination",
            "steps": [
                {
                    "name": "extract_data",
                    "server": "desktop-commander",
                    "tool": "read_file",
                    "parameters": {
                        "path": "/data/source.csv"
                    },
                    "save_to_context": {
                        "raw_data": "result.content"
                    }
                },
                {
                    "name": "transform_data",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "python transform_script.py --input /data/source.csv --output /data/transformed.csv"
                    },
                    "save_to_context": {
                        "transform_status": "result.exit_code"
                    }
                },
                {
                    "name": "validate_transformation",
                    "server": "desktop-commander",
                    "tool": "read_file",
                    "parameters": {
                        "path": "/data/transformed.csv"
                    },
                    "save_to_context": {
                        "transformed_data": "result.content"
                    }
                },
                {
                    "name": "deploy_to_container",
                    "server": "docker",
                    "tool": "docker_run",
                    "parameters": {
                        "image": "postgres:13",
                        "environment": {
                            "POSTGRES_DB": "analytics"
                        },
                        "ports": ["5432:5432"]
                    },
                    "save_to_context": {
                        "db_container": "result.container_id"
                    }
                },
                {
                    "name": "load_data",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "psql -h localhost -d analytics -c \"COPY data FROM '/data/transformed.csv' WITH CSV HEADER\""
                    }
                }
            ]
        }
        
        result = await orchestrator.execute_workflow(workflow)
        
        assert result["success"] is True
        assert len(result["steps"]) == 5
        assert all(step["success"] for step in result["steps"])
        
        # Verify data flow
        assert "raw_data" in result["context"]
        assert "transformed_data" in result["context"]
        assert "db_container" in result["context"]
    
    async def test_ml_pipeline_workflow(self, orchestrator):
        """Test machine learning pipeline"""
        workflow = {
            "name": "ml-pipeline",
            "description": "Train model, validate, and deploy",
            "steps": [
                {
                    "name": "prepare_training_environment",
                    "server": "docker",
                    "tool": "docker_run",
                    "parameters": {
                        "image": "tensorflow/tensorflow:latest-gpu",
                        "environment": {
                            "CUDA_VISIBLE_DEVICES": "0"
                        }
                    },
                    "save_to_context": {
                        "training_container": "result.container_id"
                    }
                },
                {
                    "name": "train_model",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "python train_model.py --data /data/training --epochs 10"
                    },
                    "save_to_context": {
                        "training_status": "result.exit_code"
                    }
                },
                {
                    "name": "validate_model",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "python validate_model.py --model /models/latest.h5 --test-data /data/test"
                    },
                    "save_to_context": {
                        "validation_score": "result.stdout"
                    }
                },
                {
                    "name": "deploy_model_service",
                    "server": "kubernetes",
                    "tool": "kubectl_apply",
                    "parameters": {
                        "manifest": {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "metadata": {
                                "name": "ml-model-service",
                                "namespace": "ml"
                            },
                            "spec": {
                                "replicas": 3,
                                "selector": {
                                    "matchLabels": {
                                        "app": "ml-model"
                                    }
                                },
                                "template": {
                                    "metadata": {
                                        "labels": {
                                            "app": "ml-model"
                                        }
                                    },
                                    "spec": {
                                        "containers": [
                                            {
                                                "name": "model-server",
                                                "image": "ml-model:latest",
                                                "ports": [{"containerPort": 8080}]
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    }
                },
                {
                    "name": "monitor_model_performance",
                    "server": "prometheus-monitoring",
                    "tool": "prometheus_query",
                    "parameters": {
                        "query": "model_prediction_latency_seconds"
                    }
                }
            ]
        }
        
        result = await orchestrator.execute_workflow(workflow)
        
        assert result["success"] is True
        assert len(result["steps"]) == 5
        assert all(step["success"] for step in result["steps"])


@pytest.mark.integration
class TestErrorRecoveryWorkflows:
    """Test error handling and recovery in workflows"""
    
    async def test_workflow_with_optional_failures(self, orchestrator):
        """Test workflow continues when optional steps fail"""
        workflow = {
            "name": "optional-failures",
            "description": "Workflow with optional steps that may fail",
            "steps": [
                {
                    "name": "mandatory_step",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "echo 'mandatory step'"
                    }
                },
                {
                    "name": "optional_failing_step",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "rm -rf /"  # This will fail due to security
                    },
                    "optional": True
                },
                {
                    "name": "final_step",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "echo 'final step'"
                    }
                }
            ]
        }
        
        result = await orchestrator.execute_workflow(workflow)
        
        assert result["success"] is True  # Overall workflow succeeds
        assert len(result["steps"]) == 3
        assert result["steps"][0]["success"] is True   # mandatory step
        assert result["steps"][1]["success"] is False  # optional failing step
        assert result["steps"][2]["success"] is True   # final step
    
    async def test_workflow_stops_on_mandatory_failure(self, orchestrator):
        """Test workflow stops when mandatory step fails"""
        workflow = {
            "name": "mandatory-failure",
            "description": "Workflow that stops on mandatory failure",
            "steps": [
                {
                    "name": "first_step",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "echo 'first step'"
                    }
                },
                {
                    "name": "failing_mandatory_step",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "rm -rf /"  # This will fail due to security
                    },
                    "optional": False
                },
                {
                    "name": "should_not_execute",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "echo 'should not execute'"
                    }
                }
            ]
        }
        
        result = await orchestrator.execute_workflow(workflow)
        
        assert result["success"] is False  # Overall workflow fails
        assert len(result["steps"]) == 2   # Third step not executed
        assert result["steps"][0]["success"] is True   # first step
        assert result["steps"][1]["success"] is False  # failing step
    
    async def test_context_variable_substitution(self, orchestrator):
        """Test context variable substitution between steps"""
        workflow = {
            "name": "context-substitution",
            "description": "Test context variable substitution",
            "steps": [
                {
                    "name": "create_container",
                    "server": "docker",
                    "tool": "docker_run",
                    "parameters": {
                        "image": "nginx:latest"
                    },
                    "save_to_context": {
                        "container_id": "result.container_id",
                        "image_name": "result.image"
                    }
                },
                {
                    "name": "verify_container",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "echo 'Container ${container_id} running ${image_name}'"
                    }
                }
            ]
        }
        
        result = await orchestrator.execute_workflow(workflow)
        
        assert result["success"] is True
        assert len(result["steps"]) == 2
        assert all(step["success"] for step in result["steps"])
        
        # Verify context was saved
        assert "container_id" in result["context"]
        assert "image_name" in result["context"]
        assert result["context"]["image_name"] == "nginx:latest"
        
        # Verify context substitution occurred
        verify_step = result["steps"][1]
        command = verify_step["parameters"]["command"]
        assert result["context"]["container_id"] in command
        assert result["context"]["image_name"] in command


@pytest.mark.integration
@pytest.mark.performance
class TestWorkflowPerformance:
    """Test workflow performance characteristics"""
    
    async def test_parallel_workflow_execution(self, orchestrator):
        """Test executing multiple workflows in parallel"""
        workflow_template = {
            "name": "parallel-test",
            "description": "Template for parallel execution",
            "steps": [
                {
                    "name": "search_step",
                    "server": "brave",
                    "tool": "brave_web_search",
                    "parameters": {
                        "query": "test query {idx}",
                        "count": 5
                    }
                }
            ]
        }
        
        # Create multiple workflow instances
        workflows = []
        for i in range(5):
            workflow = json.loads(json.dumps(workflow_template))  # Deep copy
            workflow["name"] = f"parallel-test-{i}"
            workflow["steps"][0]["parameters"]["query"] = f"test query {i}"
            workflows.append(workflow)
        
        # Execute workflows in parallel
        start_time = time.time()
        tasks = [orchestrator.execute_workflow(workflow) for workflow in workflows]
        results = await asyncio.gather(*tasks)
        execution_time = time.time() - start_time
        
        # Verify all workflows succeeded
        assert len(results) == 5
        assert all(result["success"] for result in results)
        
        # Performance check - parallel execution should be faster than sequential
        assert execution_time < 5.0  # Should complete within 5 seconds
        
        # Verify each workflow has unique results
        queries = [result["steps"][0]["parameters"]["query"] for result in results]
        assert len(set(queries)) == 5  # All queries should be unique
    
    async def test_long_running_workflow(self, orchestrator):
        """Test workflow with many steps"""
        steps = []
        for i in range(20):
            steps.append({
                "name": f"step_{i}",
                "server": "desktop-commander",
                "tool": "execute_command",
                "parameters": {
                    "command": f"echo 'Step {i} completed'"
                }
            })
        
        workflow = {
            "name": "long-running-workflow",
            "description": "Workflow with many steps",
            "steps": steps
        }
        
        start_time = time.time()
        result = await orchestrator.execute_workflow(workflow)
        execution_time = time.time() - start_time
        
        assert result["success"] is True
        assert len(result["steps"]) == 20
        assert all(step["success"] for step in result["steps"])
        
        # Performance check
        assert execution_time < 10.0  # Should complete within 10 seconds
        assert len(orchestrator.workflow_history) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])