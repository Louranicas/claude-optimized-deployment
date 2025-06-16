#!/usr/bin/env python3
"""
Test Data Management System for MCP Server Testing
Provides consistent test data, fixtures, and mock responses across all test suites
"""

import json
import yaml
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
import uuid
import random
import string
import os


@dataclass
class TestUser:
    """Test user data structure"""
    id: str
    username: str
    email: str
    role: str = "user"
    permissions: List[str] = field(default_factory=list)
    api_key: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class TestEnvironment:
    """Test environment configuration"""
    name: str
    type: str  # unit, integration, e2e, performance
    servers: List[str] = field(default_factory=list)
    databases: Dict[str, str] = field(default_factory=dict)
    external_services: Dict[str, str] = field(default_factory=dict)
    environment_variables: Dict[str, str] = field(default_factory=dict)
    temp_directory: Optional[str] = None


@dataclass
class TestScenario:
    """Test scenario with data and expected outcomes"""
    name: str
    description: str
    input_data: Dict[str, Any] = field(default_factory=dict)
    expected_outputs: Dict[str, Any] = field(default_factory=dict)
    mock_responses: Dict[str, Any] = field(default_factory=dict)
    setup_steps: List[str] = field(default_factory=list)
    teardown_steps: List[str] = field(default_factory=list)


class TestDataManager:
    """Manages test data, fixtures, and mock responses"""
    
    def __init__(self, base_path: Optional[str] = None):
        self.base_path = Path(base_path) if base_path else Path(__file__).parent
        self.fixtures_path = self.base_path / "data"
        self.temp_path = self.base_path / "temp"
        self.cache = {}
        
        # Ensure directories exist
        self.fixtures_path.mkdir(exist_ok=True)
        self.temp_path.mkdir(exist_ok=True)
    
    def load_fixture(self, name: str, file_type: str = "json") -> Any:
        """Load a fixture file"""
        cache_key = f"{name}.{file_type}"
        
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        file_path = self.fixtures_path / f"{name}.{file_type}"
        
        if not file_path.exists():
            raise FileNotFoundError(f"Fixture file {file_path} not found")
        
        if file_type == "json":
            with open(file_path, 'r') as f:
                data = json.load(f)
        elif file_type == "yaml":
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
        elif file_type == "txt":
            with open(file_path, 'r') as f:
                data = f.read()
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
        
        self.cache[cache_key] = data
        return data
    
    def save_fixture(self, name: str, data: Any, file_type: str = "json"):
        """Save data as a fixture file"""
        file_path = self.fixtures_path / f"{name}.{file_type}"
        
        if file_type == "json":
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        elif file_type == "yaml":
            with open(file_path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)
        elif file_type == "txt":
            with open(file_path, 'w') as f:
                f.write(str(data))
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
        
        # Update cache
        cache_key = f"{name}.{file_type}"
        self.cache[cache_key] = data
    
    def generate_test_users(self, count: int = 5) -> List[TestUser]:
        """Generate test users with various roles and permissions"""
        roles_permissions = {
            "admin": ["create", "read", "update", "delete", "manage_users", "manage_servers"],
            "user": ["read", "update"],
            "viewer": ["read"],
            "developer": ["read", "update", "create", "deploy"],
            "security": ["read", "scan", "audit"]
        }
        
        users = []
        for i in range(count):
            role = random.choice(list(roles_permissions.keys()))
            user = TestUser(
                id=str(uuid.uuid4()),
                username=f"testuser{i+1}",
                email=f"testuser{i+1}@example.com",
                role=role,
                permissions=roles_permissions[role].copy(),
                api_key=self._generate_api_key()
            )
            users.append(user)
        
        return users
    
    def generate_docker_fixtures(self) -> Dict[str, Any]:
        """Generate Docker-related test fixtures"""
        return {
            "images": [
                {
                    "name": "nginx",
                    "tag": "latest",
                    "size": "133MB",
                    "created": (datetime.now() - timedelta(days=7)).isoformat()
                },
                {
                    "name": "python",
                    "tag": "3.11-slim",
                    "size": "45MB",
                    "created": (datetime.now() - timedelta(days=3)).isoformat()
                },
                {
                    "name": "postgres",
                    "tag": "15-alpine",
                    "size": "78MB",
                    "created": (datetime.now() - timedelta(days=1)).isoformat()
                }
            ],
            "containers": [
                {
                    "id": "abc123def456",
                    "name": "test-nginx",
                    "image": "nginx:latest",
                    "status": "running",
                    "ports": ["80:8080"],
                    "created": (datetime.now() - timedelta(hours=2)).isoformat()
                },
                {
                    "id": "def456ghi789",
                    "name": "test-app",
                    "image": "python:3.11-slim",
                    "status": "exited",
                    "ports": [],
                    "created": (datetime.now() - timedelta(hours=1)).isoformat()
                }
            ],
            "networks": [
                {
                    "name": "bridge",
                    "driver": "bridge",
                    "scope": "local"
                },
                {
                    "name": "test-network",
                    "driver": "bridge",
                    "scope": "local"
                }
            ]
        }
    
    def generate_kubernetes_fixtures(self) -> Dict[str, Any]:
        """Generate Kubernetes-related test fixtures"""
        return {
            "namespaces": [
                {"name": "default", "status": "Active"},
                {"name": "kube-system", "status": "Active"},
                {"name": "test", "status": "Active"},
                {"name": "production", "status": "Active"}
            ],
            "deployments": [
                {
                    "name": "nginx-deployment",
                    "namespace": "default",
                    "replicas": 3,
                    "ready_replicas": 3,
                    "image": "nginx:latest",
                    "created": (datetime.now() - timedelta(hours=4)).isoformat()
                },
                {
                    "name": "app-deployment",
                    "namespace": "production",
                    "replicas": 5,
                    "ready_replicas": 4,
                    "image": "myapp:v1.2.3",
                    "created": (datetime.now() - timedelta(days=2)).isoformat()
                }
            ],
            "services": [
                {
                    "name": "nginx-service",
                    "namespace": "default",
                    "type": "LoadBalancer",
                    "cluster_ip": "10.96.0.1",
                    "external_ip": "192.168.1.100",
                    "ports": [{"port": 80, "target_port": 8080}]
                }
            ],
            "pods": [
                {
                    "name": "nginx-pod-1",
                    "namespace": "default",
                    "status": "Running",
                    "node": "worker-1",
                    "ip": "10.244.1.5",
                    "created": (datetime.now() - timedelta(hours=2)).isoformat()
                },
                {
                    "name": "nginx-pod-2",
                    "namespace": "default",
                    "status": "Running",
                    "node": "worker-2",
                    "ip": "10.244.2.5",
                    "created": (datetime.now() - timedelta(hours=2)).isoformat()
                }
            ]
        }
    
    def generate_security_fixtures(self) -> Dict[str, Any]:
        """Generate security-related test fixtures"""
        return {
            "vulnerabilities": [
                {
                    "id": "CVE-2023-0001",
                    "severity": "high",
                    "package": "requests",
                    "version": "2.28.0",
                    "fixed_version": "2.28.1",
                    "description": "Security vulnerability in requests library",
                    "published": (datetime.now() - timedelta(days=30)).isoformat()
                },
                {
                    "id": "CVE-2023-0002",
                    "severity": "medium",
                    "package": "flask",
                    "version": "2.1.0",
                    "fixed_version": "2.1.3",
                    "description": "XSS vulnerability in Flask templating",
                    "published": (datetime.now() - timedelta(days=45)).isoformat()
                },
                {
                    "id": "CVE-2023-0003",
                    "severity": "low",
                    "package": "urllib3",
                    "version": "1.26.8",
                    "fixed_version": "1.26.12",
                    "description": "Information disclosure in urllib3",
                    "published": (datetime.now() - timedelta(days=60)).isoformat()
                }
            ],
            "scan_results": {
                "dependencies": {
                    "total_packages": 150,
                    "vulnerable_packages": 3,
                    "high_severity": 1,
                    "medium_severity": 1,
                    "low_severity": 1,
                    "scan_time": 2.5
                },
                "container": {
                    "image": "myapp:latest",
                    "total_layers": 8,
                    "vulnerable_layers": 2,
                    "total_vulnerabilities": 12,
                    "critical": 0,
                    "high": 3,
                    "medium": 6,
                    "low": 3,
                    "scan_time": 15.2
                },
                "code": {
                    "files_scanned": 45,
                    "lines_of_code": 5678,
                    "issues_found": 8,
                    "security_issues": 2,
                    "quality_issues": 6,
                    "scan_time": 8.7
                }
            }
        }
    
    def generate_prometheus_fixtures(self) -> Dict[str, Any]:
        """Generate Prometheus metrics test fixtures"""
        now = int(datetime.now().timestamp())
        
        return {
            "metrics": {
                "cpu_usage": {
                    "metric": {"__name__": "cpu_usage_percent", "instance": "localhost:9090"},
                    "values": [
                        [now - 300, "45.2"],
                        [now - 240, "52.1"],
                        [now - 180, "48.7"],
                        [now - 120, "51.3"],
                        [now - 60, "47.9"],
                        [now, "49.5"]
                    ]
                },
                "memory_usage": {
                    "metric": {"__name__": "memory_usage_bytes", "instance": "localhost:9090"},
                    "values": [
                        [now - 300, "2147483648"],
                        [now - 240, "2234567890"],
                        [now - 180, "2198765432"],
                        [now - 120, "2256789012"],
                        [now - 60, "2187654321"],
                        [now, "2223456789"]
                    ]
                },
                "http_requests": {
                    "metric": {"__name__": "http_requests_total", "method": "GET", "status": "200"},
                    "values": [
                        [now - 300, "1000"],
                        [now - 240, "1150"],
                        [now - 180, "1280"],
                        [now - 120, "1420"],
                        [now - 60, "1580"],
                        [now, "1750"]
                    ]
                }
            },
            "alerts": [
                {
                    "name": "HighCPUUsage",
                    "severity": "warning",
                    "description": "CPU usage above 80%",
                    "state": "firing",
                    "active_since": (datetime.now() - timedelta(minutes=5)).isoformat()
                },
                {
                    "name": "LowDiskSpace",
                    "severity": "critical",
                    "description": "Disk space below 10%",
                    "state": "resolved",
                    "active_since": (datetime.now() - timedelta(hours=2)).isoformat(),
                    "resolved_at": (datetime.now() - timedelta(minutes=30)).isoformat()
                }
            ]
        }
    
    def generate_search_fixtures(self) -> Dict[str, Any]:
        """Generate search-related test fixtures"""
        return {
            "web_results": [
                {
                    "title": "MCP Protocol Documentation",
                    "url": "https://docs.mcp.com/protocol",
                    "snippet": "Model Context Protocol (MCP) is a universal standard for connecting AI assistants to data sources.",
                    "rank": 1
                },
                {
                    "title": "MCP Server Implementation Guide",
                    "url": "https://docs.mcp.com/servers",
                    "snippet": "Learn how to implement MCP servers for various services and tools.",
                    "rank": 2
                },
                {
                    "title": "MCP Testing Best Practices",
                    "url": "https://blog.mcp.com/testing",
                    "snippet": "Best practices for testing MCP server implementations and workflows.",
                    "rank": 3
                }
            ],
            "news_results": [
                {
                    "title": "MCP Protocol Adoption Grows",
                    "url": "https://news.ai.com/mcp-adoption",
                    "snippet": "Major AI platforms announce support for MCP protocol",
                    "published": (datetime.now() - timedelta(days=2)).isoformat(),
                    "source": "AI News Daily"
                },
                {
                    "title": "Security Updates for MCP Servers",
                    "url": "https://security.mcp.com/updates",
                    "snippet": "Important security updates released for MCP server implementations",
                    "published": (datetime.now() - timedelta(days=5)).isoformat(),
                    "source": "MCP Security Team"
                }
            ]
        }
    
    def create_test_files(self, scenarios: List[str]) -> Dict[str, str]:
        """Create temporary test files for various scenarios"""
        test_files = {}
        
        for scenario in scenarios:
            if scenario == "dockerfile":
                content = """
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["python", "app.py"]
"""
            elif scenario == "requirements.txt":
                content = """
flask==2.3.0
requests==2.31.0
pydantic==2.0.0
pytest==7.4.0
"""
            elif scenario == "kubernetes_manifest":
                content = """
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
"""
            elif scenario == "package.json":
                content = json.dumps({
                    "name": "test-app",
                    "version": "1.0.0",
                    "dependencies": {
                        "express": "4.18.2",
                        "lodash": "4.17.21"
                    },
                    "devDependencies": {
                        "jest": "29.5.0"
                    }
                }, indent=2)
            elif scenario == "python_code":
                content = """
import os
import sys
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/')
def hello():
    return jsonify({"message": "Hello World"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
"""
            else:
                content = f"# Test file for {scenario}"
            
            # Create temporary file
            temp_file = self.temp_path / f"test_{scenario}_{uuid.uuid4().hex[:8]}"
            with open(temp_file, 'w') as f:
                f.write(content)
            
            test_files[scenario] = str(temp_file)
        
        return test_files
    
    def create_test_environment(self, env_type: str) -> TestEnvironment:
        """Create a test environment configuration"""
        base_servers = ["desktop-commander", "docker", "kubernetes"]
        
        environments = {
            "unit": TestEnvironment(
                name="unit-test",
                type="unit",
                servers=["desktop-commander"],
                environment_variables={
                    "TEST_MODE": "unit",
                    "LOG_LEVEL": "ERROR"
                }
            ),
            "integration": TestEnvironment(
                name="integration-test",
                type="integration",
                servers=base_servers,
                databases={
                    "redis": "redis://localhost:6379",
                    "postgres": "postgresql://test:test@localhost:5432/test"
                },
                environment_variables={
                    "TEST_MODE": "integration",
                    "LOG_LEVEL": "INFO"
                }
            ),
            "e2e": TestEnvironment(
                name="e2e-test",
                type="e2e",
                servers=base_servers + ["security-scanner", "prometheus-monitoring", "brave"],
                databases={
                    "redis": "redis://localhost:6379",
                    "postgres": "postgresql://test:test@localhost:5432/test"
                },
                external_services={
                    "docker_registry": "localhost:5000",
                    "kubernetes_cluster": "https://localhost:6443"
                },
                environment_variables={
                    "TEST_MODE": "e2e",
                    "LOG_LEVEL": "DEBUG"
                }
            ),
            "performance": TestEnvironment(
                name="performance-test",
                type="performance",
                servers=base_servers,
                environment_variables={
                    "TEST_MODE": "performance",
                    "LOG_LEVEL": "WARN",
                    "PERFORMANCE_MONITORING": "true"
                }
            )
        }
        
        env = environments.get(env_type)
        if not env:
            raise ValueError(f"Unknown environment type: {env_type}")
        
        # Create temporary directory for this environment
        env.temp_directory = str(self.temp_path / f"env_{env_type}_{uuid.uuid4().hex[:8]}")
        os.makedirs(env.temp_directory, exist_ok=True)
        
        return env
    
    def generate_test_scenarios(self, category: str) -> List[TestScenario]:
        """Generate test scenarios for different categories"""
        scenarios = []
        
        if category == "security":
            scenarios.extend([
                TestScenario(
                    name="sql_injection_test",
                    description="Test SQL injection vulnerability detection",
                    input_data={
                        "query": "SELECT * FROM users WHERE id = '1' OR '1'='1'"
                    },
                    expected_outputs={
                        "vulnerability_detected": True,
                        "severity": "high",
                        "type": "sql_injection"
                    }
                ),
                TestScenario(
                    name="xss_test",
                    description="Test XSS vulnerability detection",
                    input_data={
                        "content": "<script>alert('xss')</script>"
                    },
                    expected_outputs={
                        "vulnerability_detected": True,
                        "severity": "medium",
                        "type": "xss"
                    }
                )
            ])
        
        elif category == "performance":
            scenarios.extend([
                TestScenario(
                    name="high_load_test",
                    description="Test system under high load",
                    input_data={
                        "concurrent_requests": 1000,
                        "duration_seconds": 60
                    },
                    expected_outputs={
                        "max_response_time": 2.0,
                        "success_rate": 0.95,
                        "throughput_rps": 500
                    }
                ),
                TestScenario(
                    name="memory_stress_test",
                    description="Test memory usage under stress",
                    input_data={
                        "memory_pressure": "high",
                        "duration_seconds": 300
                    },
                    expected_outputs={
                        "max_memory_mb": 1024,
                        "memory_leaks": False,
                        "gc_frequency": "normal"
                    }
                )
            ])
        
        elif category == "integration":
            scenarios.extend([
                TestScenario(
                    name="multi_server_workflow",
                    description="Test workflow across multiple servers",
                    input_data={
                        "workflow_steps": [
                            {"server": "docker", "action": "build"},
                            {"server": "kubernetes", "action": "deploy"},
                            {"server": "prometheus-monitoring", "action": "monitor"}
                        ]
                    },
                    expected_outputs={
                        "all_steps_successful": True,
                        "total_duration": 300,
                        "context_preserved": True
                    }
                )
            ])
        
        return scenarios
    
    def _generate_api_key(self) -> str:
        """Generate a mock API key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    def cleanup_temp_files(self):
        """Clean up temporary files and directories"""
        if self.temp_path.exists():
            shutil.rmtree(self.temp_path)
            self.temp_path.mkdir(exist_ok=True)
    
    def export_fixtures(self, output_dir: str):
        """Export all fixtures to a directory"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        fixtures = {
            "users": self.generate_test_users(10),
            "docker": self.generate_docker_fixtures(),
            "kubernetes": self.generate_kubernetes_fixtures(),
            "security": self.generate_security_fixtures(),
            "prometheus": self.generate_prometheus_fixtures(),
            "search": self.generate_search_fixtures()
        }
        
        for name, data in fixtures.items():
            if isinstance(data, list) and data and hasattr(data[0], '__dict__'):
                # Convert dataclass objects to dicts
                data = [asdict(item) if hasattr(item, '__dict__') else item for item in data]
            
            output_file = output_path / f"{name}.json"
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        
        print(f"Fixtures exported to {output_dir}")


# Global instance
test_data_manager = TestDataManager()


def get_test_data_manager() -> TestDataManager:
    """Get the global test data manager instance"""
    return test_data_manager


if __name__ == "__main__":
    # Generate and save all fixtures
    manager = TestDataManager()
    
    # Create fixture files
    manager.save_fixture("users", [asdict(user) for user in manager.generate_test_users(10)])
    manager.save_fixture("docker", manager.generate_docker_fixtures())
    manager.save_fixture("kubernetes", manager.generate_kubernetes_fixtures())
    manager.save_fixture("security", manager.generate_security_fixtures())
    manager.save_fixture("prometheus", manager.generate_prometheus_fixtures())
    manager.save_fixture("search", manager.generate_search_fixtures())
    
    # Create test scenarios
    for category in ["security", "performance", "integration"]:
        scenarios = manager.generate_test_scenarios(category)
        manager.save_fixture(f"scenarios_{category}", [asdict(scenario) for scenario in scenarios])
    
    print("✅ All test fixtures generated successfully!")
    print(f"📁 Fixtures saved to: {manager.fixtures_path}")
    
    # Create test files for common scenarios
    test_files = manager.create_test_files([
        "dockerfile", "requirements.txt", "kubernetes_manifest", 
        "package.json", "python_code"
    ])
    
    print(f"📄 Test files created: {len(test_files)} files")
    
    # Export all fixtures
    manager.export_fixtures("./test_data_export")