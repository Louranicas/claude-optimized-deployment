#!/usr/bin/env python3
"""
End-to-end tests for real-world MCP deployment scenarios
Tests complete user journeys and production-like workflows
"""

import pytest
import asyncio
import time
import json
import tempfile
import os
from typing import Dict, Any, List
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "mocks"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from mcp_server_mocks import create_all_mock_servers
from test_multi_server_workflows import MockMCPOrchestrator


class RealWorldTestEnvironment:
    """Test environment that simulates real-world conditions"""
    
    def __init__(self):
        self.temp_dir = None
        self.test_files = {}
        self.environment_variables = {}
        self.mock_external_services = {}
        
    async def setup(self):
        """Set up test environment"""
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp(prefix="mcp_e2e_test_")
        
        # Create mock project structure
        await self._create_mock_project()
        
        # Set up environment variables
        self._setup_environment_variables()
        
        # Initialize mock external services
        await self._setup_mock_external_services()
    
    async def teardown(self):
        """Clean up test environment"""
        # Clean up temporary files
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)
    
    async def _create_mock_project(self):
        """Create a mock project structure"""
        project_structure = {
            "Dockerfile": """
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["python", "app.py"]
""",
            "requirements.txt": """
flask==2.3.0
requests==2.31.0
gunicorn==21.2.0
""",
            "app.py": """
from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "version": "1.0.0"})

@app.route('/')
def hello():
    return jsonify({"message": "Hello from MCP test app!"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
""",
            "k8s/deployment.yaml": """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: test-app
  template:
    metadata:
      labels:
        app: test-app
    spec:
      containers:
      - name: test-app
        image: test-app:latest
        ports:
        - containerPort: 8080
        env:
        - name: ENV
          value: "production"
---
apiVersion: v1
kind: Service
metadata:
  name: test-app-service
  namespace: default
spec:
  selector:
    app: test-app
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
""",
            "package.json": """
{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.0",
    "lodash": "4.17.15"
  },
  "devDependencies": {
    "jest": "29.0.0"
  }
}
""",
            ".github/workflows/ci.yml": """
name: CI/CD Pipeline
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Run tests
      run: |
        python -m pytest tests/
    
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Security scan
      run: |
        pip install safety bandit
        safety check
        bandit -r .
    
  deploy:
    needs: [test, security]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
    - uses: actions/checkout@v3
    - name: Deploy to production
      run: |
        docker build -t test-app:latest .
        kubectl apply -f k8s/deployment.yaml
"""
        }
        
        # Create files
        for relative_path, content in project_structure.items():
            file_path = Path(self.temp_dir) / relative_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            self.test_files[relative_path] = str(file_path)
    
    def _setup_environment_variables(self):
        """Set up environment variables for testing"""
        self.environment_variables = {
            "ENVIRONMENT": "test",
            "PROJECT_ROOT": self.temp_dir,
            "DOCKER_REGISTRY": "test-registry.com",
            "KUBERNETES_NAMESPACE": "test",
            "PROMETHEUS_URL": "http://prometheus-test:9090",
            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/test",
            "AWS_REGION": "us-east-1",
            "AWS_ACCESS_KEY_ID": "test-key",
            "AWS_SECRET_ACCESS_KEY": "test-secret"
        }
        
        # Apply environment variables
        for key, value in self.environment_variables.items():
            os.environ[key] = value
    
    async def _setup_mock_external_services(self):
        """Set up mock external services"""
        self.mock_external_services = {
            "docker_registry": MagicMock(),
            "kubernetes_cluster": MagicMock(),
            "prometheus": MagicMock(),
            "slack": MagicMock(),
            "aws": MagicMock()
        }


@pytest.fixture
async def test_environment():
    """Create and setup test environment"""
    env = RealWorldTestEnvironment()
    await env.setup()
    yield env
    await env.teardown()


@pytest.fixture
async def production_orchestrator(test_environment):
    """Create orchestrator with production-like setup"""
    orchestrator = MockMCPOrchestrator()
    
    # Register all servers
    servers = create_all_mock_servers()
    for name, server in servers.items():
        orchestrator.register_server(name, server)
    
    yield orchestrator
    
    # Cleanup
    for server in servers.values():
        server.cleanup()


@pytest.mark.e2e
class TestCompleteDevOpsPipeline:
    """Test complete DevOps pipeline from development to production"""
    
    async def test_full_cicd_pipeline(self, test_environment, production_orchestrator):
        """Test complete CI/CD pipeline"""
        pipeline_workflow = {
            "name": "complete-cicd-pipeline",
            "description": "Full CI/CD pipeline from code to production",
            "steps": [
                # 1. Code Quality and Security
                {
                    "name": "dependency_security_scan",
                    "server": "security-scanner",
                    "tool": "scan_dependencies",
                    "parameters": {
                        "manifest_path": f"{test_environment.temp_dir}/package.json",
                        "scan_type": "comprehensive"
                    },
                    "save_to_context": {
                        "security_issues": "result.total_vulnerabilities"
                    }
                },
                {
                    "name": "static_code_analysis",
                    "server": "security-scanner",
                    "tool": "scan_code",
                    "parameters": {
                        "source_path": f"{test_environment.temp_dir}",
                        "language": "python"
                    },
                    "save_to_context": {
                        "code_quality_score": "result.total_issues"
                    }
                },
                
                # 2. Build and Test
                {
                    "name": "run_unit_tests",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": f"cd {test_environment.temp_dir} && python -m pytest tests/ -v"
                    },
                    "save_to_context": {
                        "test_exit_code": "result.exit_code"
                    }
                },
                {
                    "name": "build_docker_image",
                    "server": "docker",
                    "tool": "docker_build",
                    "parameters": {
                        "dockerfile_path": f"{test_environment.temp_dir}/Dockerfile",
                        "tag": "test-app:${BUILD_NUMBER}",
                        "build_args": {
                            "BUILD_DATE": "2024-01-01",
                            "VERSION": "1.0.0"
                        }
                    },
                    "save_to_context": {
                        "image_id": "result.image_id",
                        "image_tag": "result.tag"
                    }
                },
                
                # 3. Security Testing
                {
                    "name": "container_security_scan",
                    "server": "security-scanner",
                    "tool": "scan_container",
                    "parameters": {
                        "image": "${image_tag}",
                        "severity_threshold": "medium"
                    },
                    "save_to_context": {
                        "container_vulnerabilities": "result.total_vulnerabilities"
                    }
                },
                
                # 4. Deploy to Staging
                {
                    "name": "deploy_to_staging",
                    "server": "kubernetes",
                    "tool": "kubectl_apply",
                    "parameters": {
                        "manifest": {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "metadata": {
                                "name": "test-app-staging",
                                "namespace": "staging"
                            },
                            "spec": {
                                "replicas": 2,
                                "selector": {
                                    "matchLabels": {
                                        "app": "test-app",
                                        "env": "staging"
                                    }
                                },
                                "template": {
                                    "metadata": {
                                        "labels": {
                                            "app": "test-app",
                                            "env": "staging"
                                        }
                                    },
                                    "spec": {
                                        "containers": [
                                            {
                                                "name": "test-app",
                                                "image": "${image_tag}",
                                                "ports": [{"containerPort": 8080}],
                                                "env": [{"name": "ENV", "value": "staging"}]
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    },
                    "save_to_context": {
                        "staging_deployment": "result.name"
                    }
                },
                
                # 5. Integration Testing
                {
                    "name": "integration_tests",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "curl -f http://test-app-staging/health"
                    },
                    "save_to_context": {
                        "health_check_status": "result.exit_code"
                    }
                },
                
                # 6. Performance Testing
                {
                    "name": "load_testing",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "ab -n 1000 -c 10 http://test-app-staging/"
                    },
                    "save_to_context": {
                        "load_test_status": "result.exit_code"
                    }
                },
                
                # 7. Production Deployment (if tests pass)
                {
                    "name": "deploy_to_production",
                    "server": "kubernetes",
                    "tool": "kubectl_apply",
                    "parameters": {
                        "manifest": {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "metadata": {
                                "name": "test-app-production",
                                "namespace": "production"
                            },
                            "spec": {
                                "replicas": 5,
                                "selector": {
                                    "matchLabels": {
                                        "app": "test-app",
                                        "env": "production"
                                    }
                                },
                                "template": {
                                    "metadata": {
                                        "labels": {
                                            "app": "test-app",
                                            "env": "production"
                                        }
                                    },
                                    "spec": {
                                        "containers": [
                                            {
                                                "name": "test-app",
                                                "image": "${image_tag}",
                                                "ports": [{"containerPort": 8080}],
                                                "env": [{"name": "ENV", "value": "production"}],
                                                "resources": {
                                                    "requests": {
                                                        "cpu": "100m",
                                                        "memory": "128Mi"
                                                    },
                                                    "limits": {
                                                        "cpu": "500m",
                                                        "memory": "512Mi"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    },
                    "save_to_context": {
                        "production_deployment": "result.name"
                    }
                },
                
                # 8. Post-deployment Monitoring
                {
                    "name": "setup_monitoring",
                    "server": "prometheus-monitoring",
                    "tool": "prometheus_query",
                    "parameters": {
                        "query": "up{job=\"test-app\",env=\"production\"}"
                    },
                    "save_to_context": {
                        "monitoring_status": "result.status"
                    }
                }
            ]
        }
        
        # Add BUILD_NUMBER to context
        production_orchestrator.context_data = {"BUILD_NUMBER": "123"}
        
        result = await production_orchestrator.execute_workflow(pipeline_workflow)
        
        # Verify pipeline execution
        assert result["success"] is True, f"Pipeline failed: {result.get('error', 'Unknown error')}"
        assert len(result["steps"]) == 9
        
        # Verify critical steps succeeded
        critical_steps = [
            "dependency_security_scan",
            "build_docker_image", 
            "deploy_to_staging",
            "deploy_to_production"
        ]
        
        for step_name in critical_steps:
            step = next((s for s in result["steps"] if s["step_name"] == step_name), None)
            assert step is not None, f"Critical step {step_name} not found"
            assert step["success"] is True, f"Critical step {step_name} failed: {step.get('error')}"
        
        # Verify context propagation
        assert "image_id" in result["context"]
        assert "image_tag" in result["context"]
        assert "staging_deployment" in result["context"]
        assert "production_deployment" in result["context"]
        
        # Verify image tag substitution occurred
        build_step = next(s for s in result["steps"] if s["step_name"] == "build_docker_image")
        expected_tag = build_step["result"]["tag"]
        
        prod_step = next(s for s in result["steps"] if s["step_name"] == "deploy_to_production")
        deployed_image = prod_step["parameters"]["manifest"]["spec"]["template"]["spec"]["containers"][0]["image"]
        assert deployed_image == expected_tag
    
    async def test_disaster_recovery_scenario(self, test_environment, production_orchestrator):
        """Test complete disaster recovery scenario"""
        disaster_recovery_workflow = {
            "name": "disaster-recovery-scenario",
            "description": "Complete disaster recovery and restoration",
            "steps": [
                # 1. Detect outage
                {
                    "name": "detect_outage",
                    "server": "prometheus-monitoring",
                    "tool": "prometheus_query",
                    "parameters": {
                        "query": "up{job=\"test-app\"}"
                    },
                    "save_to_context": {
                        "service_status": "result.data.result"
                    }
                },
                
                # 2. Create backup of current state
                {
                    "name": "backup_current_state",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "kubectl get all -n production -o yaml > /backup/production-state.yaml"
                    },
                    "save_to_context": {
                        "backup_status": "result.exit_code"
                    }
                },
                
                # 3. Search for known solutions
                {
                    "name": "search_incident_solutions",
                    "server": "brave",
                    "tool": "brave_web_search",
                    "parameters": {
                        "query": "kubernetes deployment not responding troubleshooting",
                        "count": 5
                    },
                    "save_to_context": {
                        "incident_solutions": "result.results"
                    }
                },
                
                # 4. Attempt automatic recovery
                {
                    "name": "restart_failed_pods",
                    "server": "kubernetes",
                    "tool": "kubectl_delete",
                    "parameters": {
                        "resource_type": "pod",
                        "name": "test-app-production",
                        "namespace": "production"
                    },
                    "optional": True
                },
                
                # 5. Redeploy if restart fails
                {
                    "name": "redeploy_application",
                    "server": "kubernetes",
                    "tool": "kubectl_apply",
                    "parameters": {
                        "manifest": {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "metadata": {
                                "name": "test-app-production",
                                "namespace": "production"
                            },
                            "spec": {
                                "replicas": 3,
                                "selector": {
                                    "matchLabels": {
                                        "app": "test-app"
                                    }
                                },
                                "template": {
                                    "metadata": {
                                        "labels": {
                                            "app": "test-app"
                                        }
                                    },
                                    "spec": {
                                        "containers": [
                                            {
                                                "name": "test-app",
                                                "image": "test-app:latest",
                                                "ports": [{"containerPort": 8080}]
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    },
                    "save_to_context": {
                        "recovery_deployment": "result.name"
                    }
                },
                
                # 6. Verify recovery
                {
                    "name": "verify_recovery",
                    "server": "prometheus-monitoring",
                    "tool": "prometheus_query",
                    "parameters": {
                        "query": "up{job=\"test-app\"}"
                    },
                    "save_to_context": {
                        "recovery_status": "result.status"
                    }
                },
                
                # 7. Run health checks
                {
                    "name": "comprehensive_health_check",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "curl -f http://test-app/health && echo 'Health check passed'"
                    },
                    "save_to_context": {
                        "final_health_status": "result.exit_code"
                    }
                }
            ]
        }
        
        result = await production_orchestrator.execute_workflow(disaster_recovery_workflow)
        
        assert result["success"] is True
        assert len(result["steps"]) == 7
        
        # Verify recovery steps
        recovery_steps = ["backup_current_state", "redeploy_application", "verify_recovery"]
        for step_name in recovery_steps:
            step = next(s for s in result["steps"] if s["step_name"] == step_name)
            assert step["success"] is True, f"Recovery step {step_name} failed"
        
        # Verify we have incident solutions
        assert "incident_solutions" in result["context"]
        assert len(result["context"]["incident_solutions"]) > 0
    
    async def test_security_incident_response(self, test_environment, production_orchestrator):
        """Test security incident response workflow"""
        security_incident_workflow = {
            "name": "security-incident-response",
            "description": "Respond to security incident",
            "steps": [
                # 1. Initial security scan
                {
                    "name": "emergency_security_scan",
                    "server": "security-scanner",
                    "tool": "scan_dependencies",
                    "parameters": {
                        "manifest_path": f"{test_environment.temp_dir}/package.json",
                        "scan_type": "emergency"
                    },
                    "save_to_context": {
                        "critical_vulnerabilities": "result.high_severity"
                    }
                },
                
                # 2. Container security audit
                {
                    "name": "audit_running_containers",
                    "server": "security-scanner",
                    "tool": "scan_container", 
                    "parameters": {
                        "image": "test-app:latest",
                        "severity_threshold": "high"
                    },
                    "save_to_context": {
                        "container_security_status": "result.passed"
                    }
                },
                
                # 3. Search for vulnerability information
                {
                    "name": "research_vulnerabilities",
                    "server": "brave",
                    "tool": "brave_news_search",
                    "parameters": {
                        "query": "CVE security vulnerability python flask",
                        "count": 10
                    },
                    "save_to_context": {
                        "vulnerability_news": "result.results"
                    }
                },
                
                # 4. Immediate containment
                {
                    "name": "isolate_affected_pods",
                    "server": "kubernetes",
                    "tool": "kubectl_apply",
                    "parameters": {
                        "manifest": {
                            "apiVersion": "networking.k8s.io/v1",
                            "kind": "NetworkPolicy",
                            "metadata": {
                                "name": "security-isolation",
                                "namespace": "production"
                            },
                            "spec": {
                                "podSelector": {
                                    "matchLabels": {
                                        "app": "test-app"
                                    }
                                },
                                "policyTypes": ["Ingress", "Egress"],
                                "ingress": [],
                                "egress": []
                            }
                        }
                    },
                    "save_to_context": {
                        "isolation_policy": "result.name"
                    }
                },
                
                # 5. Deploy patched version
                {
                    "name": "deploy_security_patch",
                    "server": "docker",
                    "tool": "docker_build",
                    "parameters": {
                        "dockerfile_path": f"{test_environment.temp_dir}/Dockerfile",
                        "tag": "test-app:security-patch",
                        "build_args": {
                            "SECURITY_PATCH": "true"
                        }
                    },
                    "save_to_context": {
                        "patched_image": "result.tag"
                    }
                },
                
                # 6. Rolling update with patched image
                {
                    "name": "rolling_security_update",
                    "server": "kubernetes",
                    "tool": "kubectl_apply",
                    "parameters": {
                        "manifest": {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "metadata": {
                                "name": "test-app-production",
                                "namespace": "production"
                            },
                            "spec": {
                                "replicas": 3,
                                "strategy": {
                                    "type": "RollingUpdate",
                                    "rollingUpdate": {
                                        "maxUnavailable": 1,
                                        "maxSurge": 1
                                    }
                                },
                                "selector": {
                                    "matchLabels": {
                                        "app": "test-app"
                                    }
                                },
                                "template": {
                                    "metadata": {
                                        "labels": {
                                            "app": "test-app",
                                            "security-patched": "true"
                                        }
                                    },
                                    "spec": {
                                        "containers": [
                                            {
                                                "name": "test-app",
                                                "image": "${patched_image}",
                                                "ports": [{"containerPort": 8080}]
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    },
                    "save_to_context": {
                        "patched_deployment": "result.name"
                    }
                },
                
                # 7. Verify patch deployment
                {
                    "name": "verify_security_patch",
                    "server": "security-scanner",
                    "tool": "scan_container",
                    "parameters": {
                        "image": "${patched_image}",
                        "severity_threshold": "critical"
                    },
                    "save_to_context": {
                        "patch_verification": "result.passed"
                    }
                },
                
                # 8. Monitor for continued threats
                {
                    "name": "monitor_security_metrics",
                    "server": "prometheus-monitoring",
                    "tool": "prometheus_query",
                    "parameters": {
                        "query": "security_incidents_total"
                    },
                    "save_to_context": {
                        "ongoing_incidents": "result.data.result"
                    }
                }
            ]
        }
        
        result = await production_orchestrator.execute_workflow(security_incident_workflow)
        
        assert result["success"] is True
        assert len(result["steps"]) == 8
        
        # Verify security response steps
        critical_security_steps = [
            "emergency_security_scan",
            "isolate_affected_pods", 
            "deploy_security_patch",
            "rolling_security_update"
        ]
        
        for step_name in critical_security_steps:
            step = next(s for s in result["steps"] if s["step_name"] == step_name)
            assert step["success"] is True, f"Security step {step_name} failed"
        
        # Verify security context
        assert "critical_vulnerabilities" in result["context"]
        assert "patched_image" in result["context"]
        assert "vulnerability_news" in result["context"]


@pytest.mark.e2e
@pytest.mark.performance
class TestProductionLoadScenarios:
    """Test production load and stress scenarios"""
    
    async def test_high_load_deployment(self, test_environment, production_orchestrator):
        """Test deployment under high load conditions"""
        high_load_workflow = {
            "name": "high-load-deployment",
            "description": "Deploy and scale under high load",
            "steps": [
                # 1. Deploy initial version
                {
                    "name": "initial_deployment",
                    "server": "kubernetes",
                    "tool": "kubectl_apply",
                    "parameters": {
                        "manifest": {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "metadata": {
                                "name": "load-test-app",
                                "namespace": "production"
                            },
                            "spec": {
                                "replicas": 2,
                                "selector": {
                                    "matchLabels": {
                                        "app": "load-test-app"
                                    }
                                },
                                "template": {
                                    "metadata": {
                                        "labels": {
                                            "app": "load-test-app"
                                        }
                                    },
                                    "spec": {
                                        "containers": [
                                            {
                                                "name": "app",
                                                "image": "test-app:latest",
                                                "ports": [{"containerPort": 8080}],
                                                "resources": {
                                                    "requests": {
                                                        "cpu": "100m",
                                                        "memory": "128Mi"
                                                    },
                                                    "limits": {
                                                        "cpu": "500m",
                                                        "memory": "512Mi"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    }
                },
                
                # 2. Monitor baseline metrics
                {
                    "name": "baseline_metrics",
                    "server": "prometheus-monitoring",
                    "tool": "prometheus_query",
                    "parameters": {
                        "query": "cpu_usage_percent{app=\"load-test-app\"}"
                    },
                    "save_to_context": {
                        "baseline_cpu": "result.data.result"
                    }
                },
                
                # 3. Simulate load increase
                {
                    "name": "simulate_traffic_spike",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "ab -n 10000 -c 100 http://load-test-app/"
                    }
                },
                
                # 4. Monitor under load
                {
                    "name": "monitor_under_load",
                    "server": "prometheus-monitoring",
                    "tool": "prometheus_query",
                    "parameters": {
                        "query": "cpu_usage_percent{app=\"load-test-app\"}"
                    },
                    "save_to_context": {
                        "load_cpu": "result.data.result"
                    }
                },
                
                # 5. Auto-scale based on metrics
                {
                    "name": "scale_up_deployment",
                    "server": "kubernetes",
                    "tool": "kubectl_apply",
                    "parameters": {
                        "manifest": {
                            "apiVersion": "apps/v1",
                            "kind": "Deployment",
                            "metadata": {
                                "name": "load-test-app",
                                "namespace": "production"
                            },
                            "spec": {
                                "replicas": 6
                            }
                        }
                    }
                },
                
                # 6. Verify scaling
                {
                    "name": "verify_scaling",
                    "server": "kubernetes",
                    "tool": "kubectl_get",
                    "parameters": {
                        "resource_type": "deployment",
                        "name": "load-test-app",
                        "namespace": "production"
                    },
                    "save_to_context": {
                        "scaled_deployment": "result.items"
                    }
                },
                
                # 7. Test sustained load
                {
                    "name": "sustained_load_test",
                    "server": "desktop-commander",
                    "tool": "execute_command",
                    "parameters": {
                        "command": "ab -n 50000 -c 200 -t 300 http://load-test-app/"
                    }
                },
                
                # 8. Final performance verification
                {
                    "name": "final_performance_check",
                    "server": "prometheus-monitoring",
                    "tool": "prometheus_query_range",
                    "parameters": {
                        "query": "response_time_seconds{app=\"load-test-app\"}",
                        "start": str(int(time.time()) - 600),
                        "end": str(int(time.time())),
                        "step": "15s"
                    },
                    "save_to_context": {
                        "performance_timeline": "result.data.result"
                    }
                }
            ]
        }
        
        result = await production_orchestrator.execute_workflow(high_load_workflow)
        
        assert result["success"] is True
        assert len(result["steps"]) == 8
        assert all(step["success"] for step in result["steps"])
        
        # Verify scaling occurred
        assert "scaled_deployment" in result["context"]
        assert "performance_timeline" in result["context"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])