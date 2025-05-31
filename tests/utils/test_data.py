"""
Test data generators for comprehensive testing.

This module provides functions to generate realistic test data
for various components of the system.
"""

import random
import string
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import json
from pathlib import Path

from src.circle_of_experts import QueryType, QueryPriority, ExpertType, ResponseStatus


class TestDataGenerator:
    """Generate test data for various components."""
    
    # Sample data pools
    DOMAINS = ["infrastructure", "security", "performance", "architecture", "deployment"]
    TECHNOLOGIES = ["kubernetes", "docker", "aws", "azure", "python", "rust", "react", "nodejs"]
    ACTIONS = ["optimize", "implement", "refactor", "debug", "deploy", "configure", "migrate"]
    PROBLEMS = ["high latency", "memory leak", "security vulnerability", "scaling issue", "integration failure"]
    
    @staticmethod
    def generate_query_content(domain: Optional[str] = None) -> str:
        """Generate realistic query content."""
        if not domain:
            domain = random.choice(TestDataGenerator.DOMAINS)
        
        action = random.choice(TestDataGenerator.ACTIONS)
        tech = random.choice(TestDataGenerator.TECHNOLOGIES)
        problem = random.choice(TestDataGenerator.PROBLEMS)
        
        templates = [
            f"How can I {action} our {tech} {domain} to resolve {problem}?",
            f"We're experiencing {problem} in our {tech} environment. What's the best approach to {action} the {domain}?",
            f"Need expert advice on how to {action} {tech} for better {domain} management.",
            f"Our team needs to {action} the {domain} layer using {tech}. What are the best practices?",
            f"Critical: {problem} detected in {tech} {domain}. How should we proceed to {action} this?"
        ]
        
        return random.choice(templates)
    
    @staticmethod
    def generate_expert_response(query_content: str, expert_type: ExpertType) -> Dict[str, Any]:
        """Generate realistic expert response based on query."""
        # Extract context from query
        tech_mentioned = next((t for t in TestDataGenerator.TECHNOLOGIES if t in query_content.lower()), "technology")
        action_mentioned = next((a for a in TestDataGenerator.ACTIONS if a in query_content.lower()), "improve")
        
        recommendations = [
            f"Implement caching layer for {tech_mentioned} to improve performance",
            f"Use connection pooling to reduce overhead",
            f"Enable monitoring and alerting for better observability",
            f"Consider horizontal scaling for better resilience",
            f"Apply security best practices including encryption and authentication"
        ]
        
        reasoning = f"Based on my analysis as a {expert_type.value} expert, the best approach to {action_mentioned} your {tech_mentioned} system involves several key considerations..."
        
        return {
            "content": f"To address your query about {tech_mentioned}, I recommend the following approach...",
            "confidence": random.uniform(0.7, 0.95),
            "reasoning": reasoning,
            "recommendations": random.sample(recommendations, k=random.randint(2, 4)),
            "response_time": random.uniform(0.5, 3.0),
            "cost": random.uniform(0.01, 0.05)
        }
    
    @staticmethod
    def generate_deployment_manifest(app_name: str = None) -> Dict[str, Any]:
        """Generate a Kubernetes deployment manifest."""
        if not app_name:
            app_name = f"test-app-{uuid.uuid4().hex[:8]}"
        
        return {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": app_name,
                "labels": {
                    "app": app_name,
                    "environment": "test",
                    "version": "1.0.0"
                }
            },
            "spec": {
                "replicas": random.randint(1, 5),
                "selector": {
                    "matchLabels": {
                        "app": app_name
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": app_name
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": app_name,
                            "image": f"{app_name}:latest",
                            "ports": [{
                                "containerPort": 8080
                            }],
                            "resources": {
                                "requests": {
                                    "memory": "128Mi",
                                    "cpu": "100m"
                                },
                                "limits": {
                                    "memory": "256Mi",
                                    "cpu": "200m"
                                }
                            }
                        }]
                    }
                }
            }
        }
    
    @staticmethod
    def generate_docker_compose() -> Dict[str, Any]:
        """Generate a Docker Compose configuration."""
        services = {}
        num_services = random.randint(2, 5)
        
        for i in range(num_services):
            service_name = f"service-{i+1}"
            services[service_name] = {
                "image": f"test/{service_name}:latest",
                "ports": [f"{8080+i}:8080"],
                "environment": {
                    "ENV": "test",
                    "LOG_LEVEL": "debug",
                    "SERVICE_NAME": service_name
                },
                "depends_on": [f"service-{j+1}" for j in range(i) if j < i]
            }
        
        return {
            "version": "3.8",
            "services": services,
            "networks": {
                "test-network": {
                    "driver": "bridge"
                }
            }
        }
    
    @staticmethod
    def generate_prometheus_metrics() -> List[Dict[str, Any]]:
        """Generate sample Prometheus metrics."""
        metrics = []
        metric_names = [
            "http_requests_total",
            "http_request_duration_seconds",
            "cpu_usage_percent",
            "memory_usage_bytes",
            "active_connections",
            "error_rate"
        ]
        
        for metric_name in metric_names:
            for i in range(random.randint(5, 15)):
                timestamp = datetime.now() - timedelta(minutes=i*5)
                metrics.append({
                    "metric": metric_name,
                    "value": random.uniform(0, 100) if "percent" in metric_name else random.randint(100, 10000),
                    "timestamp": timestamp.isoformat(),
                    "labels": {
                        "instance": f"server-{random.randint(1, 3)}",
                        "job": "test-app",
                        "environment": "test"
                    }
                })
        
        return metrics
    
    @staticmethod
    def generate_security_scan_results() -> Dict[str, Any]:
        """Generate security scan results."""
        vulnerabilities = []
        severity_levels = ["critical", "high", "medium", "low"]
        vulnerability_types = ["SQL Injection", "XSS", "CSRF", "Outdated Dependencies", "Weak Encryption"]
        
        num_vulnerabilities = random.randint(0, 10)
        for i in range(num_vulnerabilities):
            vulnerabilities.append({
                "id": f"VULN-{uuid.uuid4().hex[:8]}",
                "type": random.choice(vulnerability_types),
                "severity": random.choice(severity_levels),
                "description": f"Potential security issue detected in component",
                "file": f"src/module{random.randint(1, 5)}/file{random.randint(1, 10)}.py",
                "line": random.randint(1, 500),
                "recommendation": "Update to latest version or apply security patch"
            })
        
        return {
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "summary": {
                "critical": len([v for v in vulnerabilities if v["severity"] == "critical"]),
                "high": len([v for v in vulnerabilities if v["severity"] == "high"]),
                "medium": len([v for v in vulnerabilities if v["severity"] == "medium"]),
                "low": len([v for v in vulnerabilities if v["severity"] == "low"])
            }
        }
    
    @staticmethod
    def generate_test_files(base_path: Path, num_files: int = 5) -> Dict[str, str]:
        """Generate test files with content."""
        files = {}
        
        file_types = {
            ".py": "# Python test file\nimport os\n\ndef test_function():\n    return 'test'",
            ".js": "// JavaScript test file\nconst test = () => {\n  return 'test';\n};",
            ".yaml": "# YAML test file\nname: test\nversion: 1.0.0\nconfig:\n  key: value",
            ".json": '{\n  "name": "test",\n  "version": "1.0.0"\n}',
            ".md": "# Test Documentation\n\nThis is a test file for documentation.",
            ".rs": "// Rust test file\nfn main() {\n    println!(\"Hello, test!\");\n}"
        }
        
        for i in range(num_files):
            ext = random.choice(list(file_types.keys()))
            filename = f"test_file_{i}{ext}"
            filepath = base_path / filename
            files[str(filepath)] = file_types[ext]
        
        return files
    
    @staticmethod
    def generate_api_response(endpoint: str, method: str = "GET") -> Dict[str, Any]:
        """Generate mock API response data."""
        if "health" in endpoint:
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "services": {
                    "database": "up",
                    "cache": "up",
                    "queue": "up"
                }
            }
        elif "user" in endpoint:
            return {
                "id": str(uuid.uuid4()),
                "username": f"user_{random.randint(1000, 9999)}",
                "email": f"user{random.randint(1, 100)}@test.com",
                "created_at": datetime.now().isoformat()
            }
        elif "deployment" in endpoint:
            return {
                "deployment_id": str(uuid.uuid4()),
                "status": random.choice(["pending", "running", "completed", "failed"]),
                "started_at": datetime.now().isoformat(),
                "progress": random.randint(0, 100),
                "logs": ["Initializing deployment...", "Building containers...", "Deploying to cluster..."]
            }
        else:
            return {
                "message": "Generic API response",
                "data": {"key": "value"},
                "timestamp": datetime.now().isoformat()
            }
    
    @staticmethod
    def generate_environment_config() -> Dict[str, str]:
        """Generate environment configuration."""
        return {
            "ENVIRONMENT": "test",
            "LOG_LEVEL": random.choice(["DEBUG", "INFO", "WARNING"]),
            "API_KEY": f"test-key-{uuid.uuid4().hex}",
            "DATABASE_URL": "postgresql://test:test@localhost/testdb",
            "REDIS_URL": "redis://localhost:6379/0",
            "SECRET_KEY": ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
            "MAX_WORKERS": str(random.randint(2, 8)),
            "TIMEOUT": str(random.randint(30, 300)),
            "FEATURE_FLAG_A": random.choice(["true", "false"]),
            "FEATURE_FLAG_B": random.choice(["true", "false"])
        }
    
    @staticmethod
    def generate_performance_data(duration_minutes: int = 60) -> List[Dict[str, Any]]:
        """Generate performance monitoring data."""
        data = []
        start_time = datetime.now() - timedelta(minutes=duration_minutes)
        
        for i in range(duration_minutes):
            timestamp = start_time + timedelta(minutes=i)
            data.append({
                "timestamp": timestamp.isoformat(),
                "cpu_percent": random.uniform(10, 90),
                "memory_mb": random.randint(100, 1000),
                "disk_io_mb": random.uniform(0, 50),
                "network_in_mb": random.uniform(0, 10),
                "network_out_mb": random.uniform(0, 10),
                "request_count": random.randint(10, 1000),
                "error_count": random.randint(0, 10),
                "avg_response_time_ms": random.uniform(10, 500)
            })
        
        return data
    
    @staticmethod
    def generate_git_commit_info() -> Dict[str, Any]:
        """Generate git commit information."""
        commit_messages = [
            "feat: Add new feature for better performance",
            "fix: Resolve memory leak in worker process",
            "refactor: Improve code structure for maintainability",
            "docs: Update API documentation",
            "test: Add integration tests for new module",
            "chore: Update dependencies to latest versions"
        ]
        
        return {
            "commit_hash": ''.join(random.choices(string.hexdigits.lower(), k=40)),
            "author": f"Test User <test{random.randint(1, 10)}@example.com>",
            "timestamp": datetime.now().isoformat(),
            "message": random.choice(commit_messages),
            "files_changed": random.randint(1, 20),
            "insertions": random.randint(10, 500),
            "deletions": random.randint(5, 200)
        }


# Utility functions for specific test scenarios

def create_large_dataset(size: int = 1000) -> List[Dict[str, Any]]:
    """Create a large dataset for performance testing."""
    return [
        {
            "id": i,
            "uuid": str(uuid.uuid4()),
            "name": f"Item {i}",
            "value": random.uniform(0, 1000),
            "category": random.choice(["A", "B", "C", "D"]),
            "created_at": (datetime.now() - timedelta(days=random.randint(0, 365))).isoformat(),
            "metadata": {
                "tag1": random.choice(["red", "blue", "green"]),
                "tag2": random.randint(1, 100),
                "tag3": random.choice([True, False])
            }
        }
        for i in range(size)
    ]


def create_nested_structure(depth: int = 3, breadth: int = 3) -> Dict[str, Any]:
    """Create a nested data structure for testing."""
    if depth == 0:
        return {"value": random.randint(1, 100)}
    
    result = {}
    for i in range(breadth):
        key = f"level_{depth}_item_{i}"
        result[key] = create_nested_structure(depth - 1, breadth)
    
    return result


def create_time_series_data(
    metric_name: str,
    start_time: datetime,
    end_time: datetime,
    interval_seconds: int = 60
) -> List[Tuple[datetime, float]]:
    """Create time series data for testing."""
    data = []
    current_time = start_time
    value = random.uniform(50, 100)
    
    while current_time <= end_time:
        # Add some randomness and trend
        value += random.uniform(-5, 5)
        value = max(0, min(200, value))  # Keep within bounds
        
        data.append((current_time, value))
        current_time += timedelta(seconds=interval_seconds)
    
    return data


def create_error_scenarios() -> List[Dict[str, Any]]:
    """Create various error scenarios for testing."""
    return [
        {
            "type": "NetworkError",
            "message": "Connection timeout after 30 seconds",
            "code": "ETIMEDOUT",
            "retry_after": 60
        },
        {
            "type": "ValidationError",
            "message": "Invalid input format",
            "field": "email",
            "value": "not-an-email"
        },
        {
            "type": "AuthenticationError",
            "message": "Invalid API key",
            "code": "AUTH_FAILED",
            "details": "The provided API key is not valid"
        },
        {
            "type": "RateLimitError",
            "message": "Rate limit exceeded",
            "limit": 100,
            "window": "1h",
            "retry_after": 3600
        },
        {
            "type": "ServerError",
            "message": "Internal server error",
            "code": 500,
            "request_id": str(uuid.uuid4())
        }
    ]