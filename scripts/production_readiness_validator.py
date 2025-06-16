#!/usr/bin/env python3
"""
Production Readiness Validator for MCP Servers
Comprehensive validation of all production readiness criteria
"""

import os
import json
import yaml
import subprocess
import asyncio
import aiohttp
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import hashlib
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of a validation check"""
    category: str
    check_name: str
    status: str  # PASS, FAIL, WARNING, SKIP
    score: int  # 0-100
    message: str
    details: Dict[str, Any] = None
    remediation: str = ""

@dataclass
class ComplianceResult:
    """Compliance validation result"""
    framework: str
    requirement: str
    status: str
    evidence: List[str]
    risk_level: str
    remediation: str = ""

class ProductionReadinessValidator:
    """Comprehensive production readiness validation"""
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.results = []
        self.compliance_results = []
        self.start_time = datetime.now()
        
    def _load_config(self, config_path: str) -> Dict:
        """Load validation configuration"""
        with open(config_path, 'r') as f:
            return json.load(f)
    
    async def validate_all(self) -> Dict[str, Any]:
        """Run all production readiness validations"""
        logger.info("Starting comprehensive production readiness validation")
        
        # Core infrastructure validation
        await self._validate_containerization()
        await self._validate_kubernetes_deployment()
        await self._validate_security_configuration()
        await self._validate_monitoring_observability()
        await self._validate_performance_requirements()
        await self._validate_disaster_recovery()
        await self._validate_compliance()
        await self._validate_documentation()
        await self._validate_automation()
        
        return self._generate_final_report()
    
    async def _validate_containerization(self):
        """Validate container build and security"""
        logger.info("Validating containerization...")
        
        # Check Docker files exist
        docker_files = [
            "mcp_servers/Dockerfile.mcp-typescript",
            "mcp_learning_system/Dockerfile.learning-python", 
            "mcp_learning_system/servers/Dockerfile.rust-server"
        ]
        
        for dockerfile in docker_files:
            if os.path.exists(dockerfile):
                # Validate Dockerfile best practices
                await self._validate_dockerfile(dockerfile)
            else:
                self.results.append(ValidationResult(
                    category="Containerization",
                    check_name=f"Dockerfile exists: {dockerfile}",
                    status="FAIL",
                    score=0,
                    message=f"Dockerfile not found: {dockerfile}",
                    remediation="Create Dockerfile following security best practices"
                ))
        
        # Check multi-stage builds
        await self._check_multistage_builds()
        
        # Validate security scanning
        await self._validate_container_security()
        
        # Check image optimization
        await self._validate_image_optimization()
    
    async def _validate_dockerfile(self, dockerfile_path: str):
        """Validate individual Dockerfile"""
        with open(dockerfile_path, 'r') as f:
            content = f.read()
        
        checks = [
            ("Multi-stage build", "FROM" in content and "AS builder" in content),
            ("Non-root user", "USER" in content and "USER root" not in content),
            ("Security updates", "apt-get update" in content or "apk update" in content),
            ("Health check", "HEALTHCHECK" in content),
            ("Minimal base image", "alpine" in content or "slim" in content),
            ("No hardcoded secrets", "password" not in content.lower() and "secret" not in content.lower())
        ]
        
        for check_name, condition in checks:
            status = "PASS" if condition else "FAIL"
            score = 100 if condition else 0
            
            self.results.append(ValidationResult(
                category="Containerization",
                check_name=f"{dockerfile_path}: {check_name}",
                status=status,
                score=score,
                message=f"Dockerfile {check_name.lower()}: {'✓' if condition else '✗'}",
                remediation=f"Implement {check_name.lower()} in {dockerfile_path}" if not condition else ""
            ))
    
    async def _check_multistage_builds(self):
        """Check for multi-stage build implementation"""
        try:
            # Check if images can be built successfully
            result = subprocess.run([
                'docker', 'build', '--target', 'security-scan', 
                '-f', 'mcp_servers/Dockerfile.mcp-typescript', '.'
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                self.results.append(ValidationResult(
                    category="Containerization",
                    check_name="Multi-stage build functionality",
                    status="PASS",
                    score=100,
                    message="Multi-stage builds working correctly"
                ))
            else:
                self.results.append(ValidationResult(
                    category="Containerization", 
                    check_name="Multi-stage build functionality",
                    status="FAIL",
                    score=0,
                    message=f"Multi-stage build failed: {result.stderr}",
                    remediation="Fix Dockerfile syntax and dependencies"
                ))
        except Exception as e:
            self.results.append(ValidationResult(
                category="Containerization",
                check_name="Multi-stage build functionality",
                status="FAIL",
                score=0,
                message=f"Could not test multi-stage build: {e}",
                remediation="Ensure Docker is available and Dockerfiles are valid"
            ))
    
    async def _validate_container_security(self):
        """Validate container security configuration"""
        # Check for security scanning integration
        ci_file = ".github/workflows/mcp-production-deployment.yml"
        if os.path.exists(ci_file):
            with open(ci_file, 'r') as f:
                ci_content = f.read()
            
            security_checks = [
                ("Trivy scanning", "trivy" in ci_content.lower()),
                ("Vulnerability thresholds", "critical" in ci_content.lower()),
                ("Security gates", "security-scan" in ci_content.lower()),
                ("SARIF upload", "sarif" in ci_content.lower())
            ]
            
            for check_name, condition in security_checks:
                status = "PASS" if condition else "WARNING"
                score = 100 if condition else 60
                
                self.results.append(ValidationResult(
                    category="Container Security",
                    check_name=check_name,
                    status=status,
                    score=score,
                    message=f"Container security {check_name.lower()}: {'✓' if condition else '⚠'}",
                    remediation=f"Implement {check_name.lower()} in CI/CD pipeline" if not condition else ""
                ))
    
    async def _validate_image_optimization(self):
        """Validate image size optimization"""
        # Check for optimization techniques in Dockerfiles
        optimization_checks = [
            ("Layer caching", ".dockerignore"),
            ("Dependency optimization", "requirements.txt"),
            ("Build cache", "DOCKER_BUILDKIT"),
            ("Size optimization", "alpine")
        ]
        
        for check_name, indicator in optimization_checks:
            found = False
            
            # Check across all Dockerfiles and related files
            for root, dirs, files in os.walk('.'):
                for file in files:
                    if file.endswith(('.dockerfile', 'Dockerfile')) or file == indicator:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r') as f:
                                if indicator in f.read():
                                    found = True
                                    break
                        except:
                            continue
                if found:
                    break
            
            status = "PASS" if found else "WARNING"
            score = 100 if found else 70
            
            self.results.append(ValidationResult(
                category="Image Optimization",
                check_name=check_name,
                status=status,
                score=score,
                message=f"Image optimization {check_name.lower()}: {'✓' if found else '⚠'}",
                remediation=f"Implement {check_name.lower()} for better image efficiency" if not found else ""
            ))
    
    async def _validate_kubernetes_deployment(self):
        """Validate Kubernetes deployment configuration"""
        logger.info("Validating Kubernetes deployment...")
        
        # Check manifest files exist
        k8s_files = [
            "k8s/mcp-deployment.yaml",
            "k8s/rbac.yaml", 
            "k8s/network-policies.yaml",
            "k8s/secrets.yaml"
        ]
        
        for k8s_file in k8s_files:
            if os.path.exists(k8s_file):
                await self._validate_k8s_manifest(k8s_file)
            else:
                self.results.append(ValidationResult(
                    category="Kubernetes",
                    check_name=f"Manifest exists: {os.path.basename(k8s_file)}",
                    status="FAIL",
                    score=0,
                    message=f"Kubernetes manifest not found: {k8s_file}",
                    remediation=f"Create {k8s_file} with proper configuration"
                ))
        
        # Validate Kubernetes best practices
        await self._validate_k8s_best_practices()
        
        # Check Helm charts if available
        await self._validate_helm_charts()
    
    async def _validate_k8s_manifest(self, manifest_path: str):
        """Validate individual Kubernetes manifest"""
        try:
            with open(manifest_path, 'r') as f:
                manifests = list(yaml.safe_load_all(f))
            
            security_checks = []
            resource_checks = []
            
            for manifest in manifests:
                if not manifest:
                    continue
                
                kind = manifest.get('kind', '')
                
                if kind == 'Deployment':
                    # Security context checks
                    spec = manifest.get('spec', {})
                    template = spec.get('template', {})
                    pod_spec = template.get('spec', {})
                    containers = pod_spec.get('containers', [])
                    
                    for container in containers:
                        security_context = container.get('securityContext', {})
                        
                        security_checks.extend([
                            ("runAsNonRoot", security_context.get('runAsNonRoot') == True),
                            ("readOnlyRootFilesystem", security_context.get('readOnlyRootFilesystem') == True),
                            ("allowPrivilegeEscalation", security_context.get('allowPrivilegeEscalation') == False),
                            ("capabilities dropped", security_context.get('capabilities', {}).get('drop') == ['ALL'])
                        ])
                        
                        # Resource checks
                        resources = container.get('resources', {})
                        resource_checks.extend([
                            ("CPU requests", 'requests' in resources and 'cpu' in resources['requests']),
                            ("Memory requests", 'requests' in resources and 'memory' in resources['requests']),
                            ("CPU limits", 'limits' in resources and 'cpu' in resources['limits']),
                            ("Memory limits", 'limits' in resources and 'memory' in resources['limits'])
                        ])
            
            # Evaluate checks
            for check_name, condition in security_checks + resource_checks:
                status = "PASS" if condition else "FAIL"
                score = 100 if condition else 0
                category = "Kubernetes Security" if check_name in [c[0] for c in security_checks] else "Resource Management"
                
                self.results.append(ValidationResult(
                    category=category,
                    check_name=f"{os.path.basename(manifest_path)}: {check_name}",
                    status=status,
                    score=score,
                    message=f"K8s {check_name}: {'✓' if condition else '✗'}",
                    remediation=f"Configure {check_name} in {manifest_path}" if not condition else ""
                ))
                
        except Exception as e:
            self.results.append(ValidationResult(
                category="Kubernetes",
                check_name=f"Manifest validation: {os.path.basename(manifest_path)}",
                status="FAIL",
                score=0,
                message=f"Could not validate manifest: {e}",
                remediation=f"Fix YAML syntax in {manifest_path}"
            ))
    
    async def _validate_k8s_best_practices(self):
        """Validate Kubernetes best practices"""
        best_practices = [
            ("Namespace isolation", "namespace.yaml"),
            ("Network policies", "network-policies.yaml"),
            ("RBAC configuration", "rbac.yaml"),
            ("Pod disruption budgets", "pdb.yaml"),
            ("Horizontal pod autoscaler", "hpa" in open("k8s/mcp-deployment.yaml").read() if os.path.exists("k8s/mcp-deployment.yaml") else False),
            ("Resource quotas", "resourcequota"),
            ("Security policies", "securitycontext")
        ]
        
        for practice, indicator in best_practices:
            if isinstance(indicator, str) and indicator.endswith('.yaml'):
                # Check if file exists
                found = os.path.exists(f"k8s/{indicator}")
            elif isinstance(indicator, bool):
                found = indicator
            else:
                # Check if indicator is mentioned in manifests
                found = False
                for root, dirs, files in os.walk('k8s'):
                    for file in files:
                        if file.endswith('.yaml'):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r') as f:
                                    if indicator.lower() in f.read().lower():
                                        found = True
                                        break
                            except:
                                continue
                    if found:
                        break
            
            status = "PASS" if found else "WARNING"
            score = 100 if found else 70
            
            self.results.append(ValidationResult(
                category="Kubernetes Best Practices",
                check_name=practice,
                status=status,
                score=score,
                message=f"K8s best practice {practice}: {'✓' if found else '⚠'}",
                remediation=f"Implement {practice} for better reliability" if not found else ""
            ))
    
    async def _validate_helm_charts(self):
        """Validate Helm charts if available"""
        helm_dir = "helm"
        if os.path.exists(helm_dir):
            # Check Chart.yaml
            chart_file = os.path.join(helm_dir, "Chart.yaml")
            if os.path.exists(chart_file):
                self.results.append(ValidationResult(
                    category="Helm",
                    check_name="Chart.yaml exists",
                    status="PASS",
                    score=100,
                    message="Helm chart configured"
                ))
                
                # Validate chart structure
                required_files = ["values.yaml", "templates/deployment.yaml", "templates/service.yaml"]
                for required_file in required_files:
                    file_path = os.path.join(helm_dir, required_file)
                    exists = os.path.exists(file_path)
                    
                    self.results.append(ValidationResult(
                        category="Helm",
                        check_name=f"Required file: {required_file}",
                        status="PASS" if exists else "WARNING",
                        score=100 if exists else 80,
                        message=f"Helm file {required_file}: {'✓' if exists else '⚠'}",
                        remediation=f"Create {required_file} for complete Helm chart" if not exists else ""
                    ))
        else:
            self.results.append(ValidationResult(
                category="Helm",
                check_name="Helm charts available",
                status="WARNING",
                score=70,
                message="Helm charts not found (optional but recommended)",
                remediation="Create Helm charts for simplified deployment management"
            ))
    
    async def _validate_security_configuration(self):
        """Validate security configuration"""
        logger.info("Validating security configuration...")
        
        # Check security policies
        await self._validate_security_policies()
        
        # Check secrets management
        await self._validate_secrets_management()
        
        # Check RBAC configuration
        await self._validate_rbac()
        
        # Check network security
        await self._validate_network_security()
        
        # Check vulnerability scanning
        await self._validate_vulnerability_scanning()
    
    async def _validate_security_policies(self):
        """Validate security policies"""
        security_files = [
            ("Pod Security Policy", "k8s/pod-security-policies.yaml"),
            ("Security Context", "k8s/security-context.yaml"),
            ("Network Policy", "k8s/network-policies.yaml")
        ]
        
        for policy_name, file_path in security_files:
            exists = os.path.exists(file_path)
            
            self.results.append(ValidationResult(
                category="Security Policies",
                check_name=policy_name,
                status="PASS" if exists else "FAIL",
                score=100 if exists else 0,
                message=f"{policy_name}: {'✓' if exists else '✗'}",
                remediation=f"Create {file_path} with appropriate security policies" if not exists else ""
            ))
            
            if exists:
                # Validate policy content
                await self._validate_security_policy_content(file_path, policy_name)
    
    async def _validate_security_policy_content(self, file_path: str, policy_name: str):
        """Validate security policy content"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            security_controls = {
                "Pod Security Policy": [
                    ("runAsNonRoot", "runAsNonRoot: true" in content),
                    ("readOnlyRootFilesystem", "readOnlyRootFilesystem: true" in content),
                    ("allowPrivilegeEscalation", "allowPrivilegeEscalation: false" in content)
                ],
                "Network Policy": [
                    ("Ingress rules", "ingress:" in content),
                    ("Egress rules", "egress:" in content),
                    ("Pod selector", "podSelector:" in content)
                ]
            }
            
            controls = security_controls.get(policy_name, [])
            for control_name, condition in controls:
                self.results.append(ValidationResult(
                    category="Security Controls",
                    check_name=f"{policy_name}: {control_name}",
                    status="PASS" if condition else "FAIL",
                    score=100 if condition else 0,
                    message=f"Security control {control_name}: {'✓' if condition else '✗'}",
                    remediation=f"Configure {control_name} in {file_path}" if not condition else ""
                ))
                
        except Exception as e:
            self.results.append(ValidationResult(
                category="Security Policies",
                check_name=f"{policy_name} content validation",
                status="FAIL",
                score=0,
                message=f"Could not validate {policy_name}: {e}",
                remediation=f"Fix syntax and content in {file_path}"
            ))
    
    async def _validate_secrets_management(self):
        """Validate secrets management"""
        secrets_file = "k8s/secrets.yaml"
        
        if os.path.exists(secrets_file):
            with open(secrets_file, 'r') as f:
                content = f.read()
            
            secrets_checks = [
                ("No hardcoded secrets", "password:" not in content and "secret:" not in content),
                ("Base64 encoding", "data:" in content),
                ("Proper structure", "apiVersion: v1" in content and "kind: Secret" in content)
            ]
            
            for check_name, condition in secrets_checks:
                self.results.append(ValidationResult(
                    category="Secrets Management",
                    check_name=check_name,
                    status="PASS" if condition else "FAIL",
                    score=100 if condition else 0,
                    message=f"Secrets {check_name.lower()}: {'✓' if condition else '✗'}",
                    remediation=f"Fix {check_name.lower()} in secrets configuration" if not condition else ""
                ))
        else:
            self.results.append(ValidationResult(
                category="Secrets Management",
                check_name="Secrets configuration exists",
                status="FAIL",
                score=0,
                message="Secrets configuration not found",
                remediation="Create k8s/secrets.yaml with proper secret management"
            ))
    
    async def _validate_rbac(self):
        """Validate RBAC configuration"""
        rbac_file = "k8s/rbac.yaml"
        
        if os.path.exists(rbac_file):
            with open(rbac_file, 'r') as f:
                content = f.read()
            
            rbac_checks = [
                ("ServiceAccount", "kind: ServiceAccount" in content),
                ("Role/ClusterRole", "kind: Role" in content or "kind: ClusterRole" in content),
                ("RoleBinding", "kind: RoleBinding" in content or "kind: ClusterRoleBinding" in content),
                ("Minimal permissions", "resources:" in content and "verbs:" in content)
            ]
            
            for check_name, condition in rbac_checks:
                self.results.append(ValidationResult(
                    category="RBAC",
                    check_name=check_name,
                    status="PASS" if condition else "FAIL", 
                    score=100 if condition else 0,
                    message=f"RBAC {check_name}: {'✓' if condition else '✗'}",
                    remediation=f"Configure {check_name} in RBAC setup" if not condition else ""
                ))
        else:
            self.results.append(ValidationResult(
                category="RBAC",
                check_name="RBAC configuration exists",
                status="FAIL",
                score=0,
                message="RBAC configuration not found",
                remediation="Create k8s/rbac.yaml with proper RBAC setup"
            ))
    
    async def _validate_network_security(self):
        """Validate network security configuration"""
        network_policies_file = "k8s/network-policies.yaml"
        
        if os.path.exists(network_policies_file):
            with open(network_policies_file, 'r') as f:
                content = f.read()
            
            network_checks = [
                ("Default deny", "policyTypes:" in content),
                ("Ingress control", "ingress:" in content),
                ("Egress control", "egress:" in content),
                ("Namespace isolation", "namespaceSelector:" in content)
            ]
            
            for check_name, condition in network_checks:
                self.results.append(ValidationResult(
                    category="Network Security",
                    check_name=check_name,
                    status="PASS" if condition else "WARNING",
                    score=100 if condition else 70,
                    message=f"Network security {check_name.lower()}: {'✓' if condition else '⚠'}",
                    remediation=f"Implement {check_name.lower()} for better network security" if not condition else ""
                ))
        else:
            self.results.append(ValidationResult(
                category="Network Security",
                check_name="Network policies exist",
                status="FAIL",
                score=0,
                message="Network policies not configured",
                remediation="Create k8s/network-policies.yaml for network segmentation"
            ))
    
    async def _validate_vulnerability_scanning(self):
        """Validate vulnerability scanning setup"""
        ci_file = ".github/workflows/mcp-production-deployment.yml"
        
        if os.path.exists(ci_file):
            with open(ci_file, 'r') as f:
                content = f.read()
            
            scanning_checks = [
                ("Container scanning", "trivy" in content.lower()),
                ("Dependency scanning", "safety" in content.lower() or "snyk" in content.lower()),
                ("Code scanning", "bandit" in content.lower() or "semgrep" in content.lower()),
                ("Security gates", "security-scan" in content.lower())
            ]
            
            for check_name, condition in scanning_checks:
                self.results.append(ValidationResult(
                    category="Vulnerability Scanning",
                    check_name=check_name,
                    status="PASS" if condition else "WARNING",
                    score=100 if condition else 70,
                    message=f"Vulnerability {check_name.lower()}: {'✓' if condition else '⚠'}",
                    remediation=f"Implement {check_name.lower()} in CI/CD pipeline" if not condition else ""
                ))
    
    async def _validate_monitoring_observability(self):
        """Validate monitoring and observability"""
        logger.info("Validating monitoring and observability...")
        
        # Check monitoring configuration
        monitoring_files = [
            ("Prometheus config", "monitoring/prometheus.yml"),
            ("Grafana config", "monitoring/grafana-datasources.yml"),
            ("Alert rules", "monitoring/alert_rules.yaml"),
            ("Alert manager", "monitoring/alertmanager.yml")
        ]
        
        for config_name, file_path in monitoring_files:
            exists = os.path.exists(file_path)
            
            self.results.append(ValidationResult(
                category="Monitoring",
                check_name=config_name,
                status="PASS" if exists else "WARNING",
                score=100 if exists else 70,
                message=f"{config_name}: {'✓' if exists else '⚠'}",
                remediation=f"Create {file_path} for comprehensive monitoring" if not exists else ""
            ))
        
        # Check logging configuration
        await self._validate_logging_setup()
        
        # Check health checks
        await self._validate_health_checks()
        
        # Check metrics endpoints
        await self._validate_metrics_endpoints()
    
    async def _validate_logging_setup(self):
        """Validate logging configuration"""
        logging_indicators = [
            ("Structured logging", "json"),
            ("Log aggregation", "elasticsearch" or "logstash"),
            ("Log retention", "retention"),
            ("Security logs", "audit")
        ]
        
        # Check across all files for logging configuration
        for indicator_name, keyword in logging_indicators:
            found = False
            
            for root, dirs, files in os.walk('.'):
                if 'node_modules' in root or '.git' in root:
                    continue
                    
                for file in files:
                    if file.endswith(('.yaml', '.yml', '.json', '.py', '.ts', '.js')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r') as f:
                                if keyword.lower() in f.read().lower():
                                    found = True
                                    break
                        except:
                            continue
                if found:
                    break
            
            status = "PASS" if found else "WARNING"
            score = 100 if found else 70
            
            self.results.append(ValidationResult(
                category="Logging",
                check_name=indicator_name,
                status=status,
                score=score,
                message=f"Logging {indicator_name.lower()}: {'✓' if found else '⚠'}",
                remediation=f"Implement {indicator_name.lower()} for better observability" if not found else ""
            ))
    
    async def _validate_health_checks(self):
        """Validate health check implementation"""
        # Check Dockerfile health checks
        dockerfile_health_checks = []
        
        for root, dirs, files in os.walk('.'):
            for file in files:
                if file.startswith('Dockerfile'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            has_healthcheck = "HEALTHCHECK" in content
                            dockerfile_health_checks.append((file_path, has_healthcheck))
                    except:
                        continue
        
        # Check Kubernetes health checks
        k8s_health_checks = []
        if os.path.exists("k8s/mcp-deployment.yaml"):
            with open("k8s/mcp-deployment.yaml", 'r') as f:
                content = f.read()
                has_liveness = "livenessProbe" in content
                has_readiness = "readinessProbe" in content
                k8s_health_checks = [("Liveness probe", has_liveness), ("Readiness probe", has_readiness)]
        
        # Evaluate checks
        for file_path, has_check in dockerfile_health_checks:
            self.results.append(ValidationResult(
                category="Health Checks",
                check_name=f"Docker health check: {os.path.basename(file_path)}",
                status="PASS" if has_check else "WARNING",
                score=100 if has_check else 70,
                message=f"Docker health check in {os.path.basename(file_path)}: {'✓' if has_check else '⚠'}",
                remediation=f"Add HEALTHCHECK to {file_path}" if not has_check else ""
            ))
        
        for check_name, has_check in k8s_health_checks:
            self.results.append(ValidationResult(
                category="Health Checks",
                check_name=f"Kubernetes {check_name.lower()}",
                status="PASS" if has_check else "FAIL",
                score=100 if has_check else 0,
                message=f"K8s {check_name.lower()}: {'✓' if has_check else '✗'}",
                remediation=f"Add {check_name.lower()} to Kubernetes deployments" if not has_check else ""
            ))
    
    async def _validate_metrics_endpoints(self):
        """Validate metrics endpoints configuration"""
        # Check for metrics endpoints in code and configuration
        metrics_indicators = [
            ("Prometheus metrics", "/metrics"),
            ("Custom metrics", "prometheus"),
            ("Application metrics", "histogram" or "counter" or "gauge"),
            ("Business metrics", "business" or "kpi")
        ]
        
        for indicator_name, keyword in metrics_indicators:
            found = False
            
            # Search in source code and configuration files
            for root, dirs, files in os.walk('.'):
                if 'node_modules' in root or '.git' in root:
                    continue
                    
                for file in files:
                    if file.endswith(('.py', '.ts', '.js', '.yaml', '.yml')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r') as f:
                                if keyword.lower() in f.read().lower():
                                    found = True
                                    break
                        except:
                            continue
                if found:
                    break
            
            status = "PASS" if found else "WARNING"
            score = 100 if found else 70
            
            self.results.append(ValidationResult(
                category="Metrics",
                check_name=indicator_name,
                status=status,
                score=score,
                message=f"Metrics {indicator_name.lower()}: {'✓' if found else '⚠'}",
                remediation=f"Implement {indicator_name.lower()} for better monitoring" if not found else ""
            ))
    
    async def _validate_performance_requirements(self):
        """Validate performance requirements and SLAs"""
        logger.info("Validating performance requirements...")
        
        # Check for performance testing
        await self._validate_performance_testing()
        
        # Check resource configuration
        await self._validate_resource_configuration()
        
        # Check auto-scaling configuration
        await self._validate_autoscaling()
        
        # Check performance SLAs documentation
        await self._validate_performance_slas()
    
    async def _validate_performance_testing(self):
        """Validate performance testing implementation"""
        perf_test_files = [
            "tests/production_testing_suite.py",
            "tests/mcp_stress_testing.py",
            "tests/performance/"
        ]
        
        for test_file in perf_test_files:
            exists = os.path.exists(test_file)
            
            self.results.append(ValidationResult(
                category="Performance Testing",
                check_name=f"Performance tests: {os.path.basename(test_file)}",
                status="PASS" if exists else "WARNING",
                score=100 if exists else 70,
                message=f"Performance test {os.path.basename(test_file)}: {'✓' if exists else '⚠'}",
                remediation=f"Create {test_file} for performance validation" if not exists else ""
            ))
        
        # Check CI/CD integration
        ci_file = ".github/workflows/mcp-production-deployment.yml"
        if os.path.exists(ci_file):
            with open(ci_file, 'r') as f:
                content = f.read()
                has_perf_tests = "performance" in content.lower() or "load" in content.lower()
                
                self.results.append(ValidationResult(
                    category="Performance Testing",
                    check_name="CI/CD performance integration",
                    status="PASS" if has_perf_tests else "WARNING",
                    score=100 if has_perf_tests else 70,
                    message=f"Performance testing in CI/CD: {'✓' if has_perf_tests else '⚠'}",
                    remediation="Add performance testing to CI/CD pipeline" if not has_perf_tests else ""
                ))
    
    async def _validate_resource_configuration(self):
        """Validate resource requests and limits"""
        if os.path.exists("k8s/mcp-deployment.yaml"):
            with open("k8s/mcp-deployment.yaml", 'r') as f:
                content = f.read()
            
            resource_checks = [
                ("CPU requests", "cpu:" in content and "requests:" in content),
                ("Memory requests", "memory:" in content and "requests:" in content),
                ("CPU limits", "cpu:" in content and "limits:" in content),
                ("Memory limits", "memory:" in content and "limits:" in content),
                ("Resource quotas", "resourcequota" in content.lower())
            ]
            
            for check_name, condition in resource_checks:
                self.results.append(ValidationResult(
                    category="Resource Management",
                    check_name=check_name,
                    status="PASS" if condition else "WARNING",
                    score=100 if condition else 70,
                    message=f"Resource {check_name.lower()}: {'✓' if condition else '⚠'}",
                    remediation=f"Configure {check_name.lower()} for proper resource management" if not condition else ""
                ))
    
    async def _validate_autoscaling(self):
        """Validate auto-scaling configuration"""
        if os.path.exists("k8s/mcp-deployment.yaml"):
            with open("k8s/mcp-deployment.yaml", 'r') as f:
                content = f.read()
            
            autoscaling_checks = [
                ("Horizontal Pod Autoscaler", "HorizontalPodAutoscaler" in content),
                ("Scaling metrics", "metrics:" in content and "cpu" in content),
                ("Min/Max replicas", "minReplicas:" in content and "maxReplicas:" in content),
                ("Scaling behavior", "behavior:" in content or "scaleUp:" in content)
            ]
            
            for check_name, condition in autoscaling_checks:
                self.results.append(ValidationResult(
                    category="Auto-scaling",
                    check_name=check_name,
                    status="PASS" if condition else "WARNING",
                    score=100 if condition else 70,
                    message=f"Auto-scaling {check_name.lower()}: {'✓' if condition else '⚠'}",
                    remediation=f"Configure {check_name.lower()} for automatic scaling" if not condition else ""
                ))
    
    async def _validate_performance_slas(self):
        """Validate performance SLA documentation"""
        sla_indicators = [
            ("Response time SLA", "response time" and "sla"),
            ("Throughput SLA", "throughput" and "rps"),
            ("Availability SLA", "availability" and "99.9"),
            ("Performance targets", "performance" and "target")
        ]
        
        # Check documentation for SLA mentions
        doc_files = []
        for root, dirs, files in os.walk('.'):
            for file in files:
                if file.endswith(('.md', '.rst', '.txt')) and 'README' not in file:
                    doc_files.append(os.path.join(root, file))
        
        for indicator_name, keywords in sla_indicators:
            found = False
            
            for doc_file in doc_files:
                try:
                    with open(doc_file, 'r') as f:
                        content = f.read().lower()
                        if all(keyword in content for keyword in keywords.split(' and ')):
                            found = True
                            break
                except:
                    continue
            
            status = "PASS" if found else "WARNING"
            score = 100 if found else 70
            
            self.results.append(ValidationResult(
                category="Performance SLAs",
                check_name=indicator_name,
                status=status,
                score=score,
                message=f"Performance SLA {indicator_name.lower()}: {'✓' if found else '⚠'}",
                remediation=f"Document {indicator_name.lower()} in SLA documentation" if not found else ""
            ))
    
    async def _validate_disaster_recovery(self):
        """Validate disaster recovery capabilities"""
        logger.info("Validating disaster recovery...")
        
        # Check backup procedures
        await self._validate_backup_procedures()
        
        # Check recovery procedures
        await self._validate_recovery_procedures()
        
        # Check business continuity
        await self._validate_business_continuity()
    
    async def _validate_backup_procedures(self):
        """Validate backup procedures"""
        backup_indicators = [
            ("Database backups", "backup" and "database"),
            ("Configuration backups", "backup" and "config"),
            ("Application data backups", "backup" and "data"),
            ("Backup verification", "backup" and "verify"),
            ("Backup retention", "backup" and "retention")
        ]
        
        # Check scripts and documentation for backup procedures
        for indicator_name, keywords in backup_indicators:
            found = False
            
            for root, dirs, files in os.walk('.'):
                if '.git' in root:
                    continue
                    
                for file in files:
                    if file.endswith(('.sh', '.py', '.md', '.yaml', '.yml')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read().lower()
                                if all(keyword in content for keyword in keywords.split(' and ')):
                                    found = True
                                    break
                        except:
                            continue
                if found:
                    break
            
            status = "PASS" if found else "WARNING"
            score = 100 if found else 60
            
            self.results.append(ValidationResult(
                category="Backup Procedures",
                check_name=indicator_name,
                status=status,
                score=score,
                message=f"Backup {indicator_name.lower()}: {'✓' if found else '⚠'}",
                remediation=f"Implement {indicator_name.lower()} for disaster recovery" if not found else ""
            ))
    
    async def _validate_recovery_procedures(self):
        """Validate recovery procedures"""
        recovery_indicators = [
            ("Recovery documentation", "docs/" and "recovery"),
            ("Recovery scripts", "recovery" and ".sh"),
            ("RTO targets", "rto" or "recovery time"),
            ("RPO targets", "rpo" or "recovery point"),
            ("Rollback procedures", "rollback" and "procedure")
        ]
        
        for indicator_name, keywords in recovery_indicators:
            found = False
            
            for root, dirs, files in os.walk('.'):
                if '.git' in root:
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read().lower()
                            if ' and ' in keywords:
                                if all(keyword in content for keyword in keywords.split(' and ')):
                                    found = True
                                    break
                            else:
                                if any(keyword in content for keyword in keywords.split(' or ')):
                                    found = True
                                    break
                    except:
                        continue
                if found:
                    break
            
            status = "PASS" if found else "WARNING"
            score = 100 if found else 60
            
            self.results.append(ValidationResult(
                category="Recovery Procedures",
                check_name=indicator_name,
                status=status,
                score=score,
                message=f"Recovery {indicator_name.lower()}: {'✓' if found else '⚠'}",
                remediation=f"Document {indicator_name.lower()} for disaster recovery" if not found else ""
            ))
    
    async def _validate_business_continuity(self):
        """Validate business continuity planning"""
        continuity_checks = [
            ("Multi-region deployment", "region" and "failover"),
            ("Load balancing", "load" and "balancer"),
            ("Circuit breaker", "circuit" and "breaker"),
            ("Graceful degradation", "graceful" and "degradation"),
            ("Incident response", "incident" and "response")
        ]
        
        for check_name, keywords in continuity_checks:
            found = False
            
            for root, dirs, files in os.walk('.'):
                if '.git' in root:
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read().lower()
                            if all(keyword in content for keyword in keywords.split(' and ')):
                                found = True
                                break
                    except:
                        continue
                if found:
                    break
            
            status = "PASS" if found else "WARNING"
            score = 100 if found else 70
            
            self.results.append(ValidationResult(
                category="Business Continuity",
                check_name=check_name,
                status=status,
                score=score,
                message=f"Business continuity {check_name.lower()}: {'✓' if found else '⚠'}",
                remediation=f"Implement {check_name.lower()} for business continuity" if not found else ""
            ))
    
    async def _validate_compliance(self):
        """Validate compliance requirements"""
        logger.info("Validating compliance requirements...")
        
        # SOC2 compliance
        await self._validate_soc2_compliance()
        
        # GDPR compliance
        await self._validate_gdpr_compliance()
        
        # Security compliance
        await self._validate_security_compliance()
        
        # Audit logging
        await self._validate_audit_logging()
    
    async def _validate_soc2_compliance(self):
        """Validate SOC2 compliance requirements"""
        soc2_controls = [
            ("Access controls", "rbac" or "authentication"),
            ("Data encryption", "encryption" or "tls"),
            ("Audit logging", "audit" and "log"),
            ("Change management", "change" and "approval"),
            ("Incident response", "incident" and "response"),
            ("Backup procedures", "backup" and "procedure"),
            ("Monitoring controls", "monitoring" and "alert")
        ]
        
        for control_name, keywords in soc2_controls:
            found = self._search_for_compliance_evidence(keywords)
            
            compliance_result = ComplianceResult(
                framework="SOC2",
                requirement=control_name,
                status="COMPLIANT" if found else "NON_COMPLIANT",
                evidence=found if isinstance(found, list) else [found] if found else [],
                risk_level="HIGH" if not found else "LOW",
                remediation=f"Implement {control_name.lower()} for SOC2 compliance" if not found else ""
            )
            
            self.compliance_results.append(compliance_result)
            
            self.results.append(ValidationResult(
                category="SOC2 Compliance",
                check_name=control_name,
                status="PASS" if found else "FAIL",
                score=100 if found else 0,
                message=f"SOC2 {control_name.lower()}: {'✓' if found else '✗'}",
                remediation=compliance_result.remediation
            ))
    
    async def _validate_gdpr_compliance(self):
        """Validate GDPR compliance requirements"""
        gdpr_requirements = [
            ("Data protection", "privacy" or "protection"),
            ("Consent management", "consent" and "management"),
            ("Data retention", "retention" and "policy"),
            ("Right to erasure", "delete" or "erasure"),
            ("Data portability", "export" or "portability"),
            ("Privacy by design", "privacy" and "design"),
            ("Data breach notification", "breach" and "notification")
        ]
        
        for requirement_name, keywords in gdpr_requirements:
            found = self._search_for_compliance_evidence(keywords)
            
            compliance_result = ComplianceResult(
                framework="GDPR",
                requirement=requirement_name,
                status="COMPLIANT" if found else "NON_COMPLIANT",
                evidence=found if isinstance(found, list) else [found] if found else [],
                risk_level="HIGH" if not found else "LOW",
                remediation=f"Implement {requirement_name.lower()} for GDPR compliance" if not found else ""
            )
            
            self.compliance_results.append(compliance_result)
            
            self.results.append(ValidationResult(
                category="GDPR Compliance",
                check_name=requirement_name,
                status="PASS" if found else "WARNING",
                score=100 if found else 50,
                message=f"GDPR {requirement_name.lower()}: {'✓' if found else '⚠'}",
                remediation=compliance_result.remediation
            ))
    
    async def _validate_security_compliance(self):
        """Validate security compliance (OWASP, etc.)"""
        security_requirements = [
            ("Input validation", "validation" and "input"),
            ("Output encoding", "encoding" or "sanitization"),
            ("Authentication", "authentication" and "secure"),
            ("Session management", "session" and "management"),
            ("Authorization", "authorization" or "rbac"),
            ("Error handling", "error" and "handling"),
            ("Security logging", "security" and "log"),
            ("Cryptography", "crypto" or "encryption")
        ]
        
        for requirement_name, keywords in security_requirements:
            found = self._search_for_compliance_evidence(keywords)
            
            self.results.append(ValidationResult(
                category="Security Compliance",
                check_name=requirement_name,
                status="PASS" if found else "WARNING",
                score=100 if found else 60,
                message=f"Security {requirement_name.lower()}: {'✓' if found else '⚠'}",
                remediation=f"Implement {requirement_name.lower()} for security compliance" if not found else ""
            ))
    
    async def _validate_audit_logging(self):
        """Validate audit logging implementation"""
        audit_requirements = [
            ("User actions", "user" and "action" and "log"),
            ("System changes", "system" and "change" and "log"),
            ("Security events", "security" and "event" and "log"),
            ("Data access", "data" and "access" and "log"),
            ("Log integrity", "log" and "integrity"),
            ("Log retention", "log" and "retention"),
            ("Log monitoring", "log" and "monitoring")
        ]
        
        for requirement_name, keywords in audit_requirements:
            found = self._search_for_compliance_evidence(keywords)
            
            self.results.append(ValidationResult(
                category="Audit Logging",
                check_name=requirement_name,
                status="PASS" if found else "WARNING",
                score=100 if found else 70,
                message=f"Audit {requirement_name.lower()}: {'✓' if found else '⚠'}",
                remediation=f"Implement {requirement_name.lower()} for audit compliance" if not found else ""
            ))
    
    def _search_for_compliance_evidence(self, keywords: str) -> bool:
        """Search for compliance evidence in codebase"""
        for root, dirs, files in os.walk('.'):
            if '.git' in root or 'node_modules' in root:
                continue
                
            for file in files:
                if file.endswith(('.py', '.ts', '.js', '.md', '.yaml', '.yml', '.json')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read().lower()
                            
                            if ' and ' in keywords:
                                if all(keyword in content for keyword in keywords.split(' and ')):
                                    return True
                            else:
                                if any(keyword in content for keyword in keywords.split(' or ')):
                                    return True
                    except:
                        continue
        
        return False
    
    async def _validate_documentation(self):
        """Validate documentation completeness"""
        logger.info("Validating documentation...")
        
        required_docs = [
            ("README.md", "Project overview and setup instructions"),
            ("docs/PRODUCTION_DEPLOYMENT_GUIDE.md", "Production deployment guide"),
            ("docs/OPERATIONS_RUNBOOK.md", "Operations and troubleshooting"),
            ("docs/ARCHITECTURE.md", "System architecture documentation"),
            ("docs/API_DOCUMENTATION.md", "API documentation"),
            ("docs/SECURITY.md", "Security documentation"),
            ("CONTRIBUTING.md", "Contribution guidelines"),
            ("LICENSE", "License information")
        ]
        
        for doc_file, description in required_docs:
            exists = os.path.exists(doc_file)
            
            if exists:
                # Check if documentation is comprehensive
                with open(doc_file, 'r') as f:
                    content = f.read()
                    is_comprehensive = len(content) > 1000  # Basic heuristic
                
                status = "PASS" if is_comprehensive else "WARNING"
                score = 100 if is_comprehensive else 70
                message = f"Documentation {doc_file}: {'✓ Comprehensive' if is_comprehensive else '⚠ Basic'}"
            else:
                status = "FAIL" if "GUIDE" in doc_file or "RUNBOOK" in doc_file else "WARNING"
                score = 0 if status == "FAIL" else 50
                message = f"Documentation {doc_file}: ✗ Missing"
            
            self.results.append(ValidationResult(
                category="Documentation",
                check_name=description,
                status=status,
                score=score,
                message=message,
                remediation=f"Create or enhance {doc_file}" if not exists or not is_comprehensive else ""
            ))
    
    async def _validate_automation(self):
        """Validate automation and CI/CD"""
        logger.info("Validating automation...")
        
        # Check CI/CD pipeline
        ci_file = ".github/workflows/mcp-production-deployment.yml"
        if os.path.exists(ci_file):
            with open(ci_file, 'r') as f:
                content = f.read()
            
            automation_checks = [
                ("Automated testing", "test" in content.lower()),
                ("Security scanning", "security" in content.lower()),
                ("Build automation", "build" in content.lower()),
                ("Deployment automation", "deploy" in content.lower()),
                ("Blue-green deployment", "blue-green" in content.lower()),
                ("Rollback capability", "rollback" in content.lower()),
                ("Performance testing", "performance" in content.lower())
            ]
            
            for check_name, condition in automation_checks:
                self.results.append(ValidationResult(
                    category="Automation",
                    check_name=check_name,
                    status="PASS" if condition else "WARNING",
                    score=100 if condition else 70,
                    message=f"Automation {check_name.lower()}: {'✓' if condition else '⚠'}",
                    remediation=f"Implement {check_name.lower()} in CI/CD pipeline" if not condition else ""
                ))
        else:
            self.results.append(ValidationResult(
                category="Automation",
                check_name="CI/CD pipeline exists",
                status="FAIL",
                score=0,
                message="CI/CD pipeline not found",
                remediation="Create .github/workflows/mcp-production-deployment.yml"
            ))
        
        # Check deployment scripts
        script_checks = [
            ("Deployment scripts", "deploy.sh" or "deploy.py"),
            ("Health check scripts", "health" and "check"),
            ("Backup scripts", "backup.sh" or "backup.py"),
            ("Monitoring setup", "monitoring" and "setup")
        ]
        
        for check_name, indicator in script_checks:
            found = False
            
            for root, dirs, files in os.walk('.'):
                if '.git' in root:
                    continue
                    
                for file in files:
                    if ' and ' in indicator:
                        if all(keyword in file.lower() for keyword in indicator.split(' and ')):
                            found = True
                            break
                    else:
                        if any(keyword in file.lower() for keyword in indicator.split(' or ')):
                            found = True
                            break
                if found:
                    break
            
            status = "PASS" if found else "WARNING"
            score = 100 if found else 70
            
            self.results.append(ValidationResult(
                category="Automation Scripts",
                check_name=check_name,
                status=status,
                score=score,
                message=f"Automation {check_name.lower()}: {'✓' if found else '⚠'}",
                remediation=f"Create {check_name.lower()} for operational efficiency" if not found else ""
            ))
    
    def _generate_final_report(self) -> Dict[str, Any]:
        """Generate comprehensive production readiness report"""
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        # Calculate scores by category
        categories = {}
        for result in self.results:
            if result.category not in categories:
                categories[result.category] = {'total_score': 0, 'max_score': 0, 'count': 0}
            
            categories[result.category]['total_score'] += result.score
            categories[result.category]['max_score'] += 100
            categories[result.category]['count'] += 1
        
        category_scores = {}
        for category, data in categories.items():
            category_scores[category] = {
                'score': (data['total_score'] / data['max_score']) * 100 if data['max_score'] > 0 else 0,
                'checks': data['count']
            }
        
        # Calculate overall score
        total_score = sum(result.score for result in self.results)
        max_score = len(self.results) * 100
        overall_score = (total_score / max_score) * 100 if max_score > 0 else 0
        
        # Determine production readiness
        critical_failures = [r for r in self.results if r.status == "FAIL" and r.category in ["Security", "Containerization", "Kubernetes"]]
        
        if overall_score >= 95 and len(critical_failures) == 0:
            readiness_level = "PRODUCTION_READY"
            readiness_grade = "A"
        elif overall_score >= 85 and len(critical_failures) <= 2:
            readiness_level = "PRODUCTION_READY_WITH_MINOR_ISSUES"
            readiness_grade = "B"
        elif overall_score >= 70 and len(critical_failures) <= 5:
            readiness_level = "PRODUCTION_READY_WITH_REMEDIATION"
            readiness_grade = "C"
        else:
            readiness_level = "NOT_PRODUCTION_READY"
            readiness_grade = "F"
        
        # Generate recommendations
        recommendations = []
        
        # High priority recommendations
        for result in self.results:
            if result.status == "FAIL" and result.remediation:
                recommendations.append({
                    "priority": "HIGH",
                    "category": result.category,
                    "issue": result.check_name,
                    "recommendation": result.remediation
                })
        
        # Medium priority recommendations
        for result in self.results:
            if result.status == "WARNING" and result.score < 80 and result.remediation:
                recommendations.append({
                    "priority": "MEDIUM",
                    "category": result.category,
                    "issue": result.check_name,
                    "recommendation": result.remediation
                })
        
        # Compliance summary
        compliance_summary = {}
        for compliance in self.compliance_results:
            if compliance.framework not in compliance_summary:
                compliance_summary[compliance.framework] = {
                    "compliant": 0,
                    "non_compliant": 0,
                    "total": 0
                }
            
            compliance_summary[compliance.framework]["total"] += 1
            if compliance.status == "COMPLIANT":
                compliance_summary[compliance.framework]["compliant"] += 1
            else:
                compliance_summary[compliance.framework]["non_compliant"] += 1
        
        # Final report
        report = {
            "metadata": {
                "validation_timestamp": end_time.isoformat(),
                "duration_seconds": duration.total_seconds(),
                "validator_version": "1.0.0",
                "environment": "production_validation"
            },
            "summary": {
                "overall_score": round(overall_score, 2),
                "readiness_level": readiness_level,
                "readiness_grade": readiness_grade,
                "production_ready": readiness_level.startswith("PRODUCTION_READY"),
                "total_checks": len(self.results),
                "passed_checks": len([r for r in self.results if r.status == "PASS"]),
                "failed_checks": len([r for r in self.results if r.status == "FAIL"]),
                "warning_checks": len([r for r in self.results if r.status == "WARNING"]),
                "critical_failures": len(critical_failures)
            },
            "category_scores": category_scores,
            "detailed_results": [asdict(result) for result in self.results],
            "compliance_results": [asdict(compliance) for compliance in self.compliance_results],
            "compliance_summary": compliance_summary,
            "recommendations": recommendations,
            "deployment_checklist": self._generate_deployment_checklist(),
            "next_steps": self._generate_next_steps(readiness_level)
        }
        
        return report
    
    def _generate_deployment_checklist(self) -> List[Dict[str, Any]]:
        """Generate deployment checklist"""
        checklist = [
            {
                "phase": "Pre-deployment",
                "items": [
                    {"task": "All unit tests passing", "status": "required"},
                    {"task": "Security scans clean", "status": "required"},
                    {"task": "Performance benchmarks met", "status": "required"},
                    {"task": "Database backups verified", "status": "required"},
                    {"task": "Rollback plan prepared", "status": "required"}
                ]
            },
            {
                "phase": "Deployment",
                "items": [
                    {"task": "Blue-green deployment initiated", "status": "required"},
                    {"task": "Health checks passing", "status": "required"},
                    {"task": "Smoke tests executed", "status": "required"},
                    {"task": "Performance validation", "status": "required"},
                    {"task": "Security validation", "status": "required"}
                ]
            },
            {
                "phase": "Post-deployment",
                "items": [
                    {"task": "Monitoring alerts configured", "status": "required"},
                    {"task": "Performance metrics validated", "status": "required"},
                    {"task": "Error rates within SLA", "status": "required"},
                    {"task": "Documentation updated", "status": "recommended"},
                    {"task": "Team notification sent", "status": "recommended"}
                ]
            }
        ]
        
        return checklist
    
    def _generate_next_steps(self, readiness_level: str) -> List[str]:
        """Generate next steps based on readiness level"""
        if readiness_level == "PRODUCTION_READY":
            return [
                "System is ready for production deployment",
                "Execute deployment using standard procedures",
                "Monitor system performance post-deployment",
                "Schedule regular production readiness reviews"
            ]
        elif readiness_level == "PRODUCTION_READY_WITH_MINOR_ISSUES":
            return [
                "Address warning-level issues before deployment",
                "Deploy with increased monitoring",
                "Plan remediation for identified issues",
                "Schedule follow-up validation in 2 weeks"
            ]
        elif readiness_level == "PRODUCTION_READY_WITH_REMEDIATION":
            return [
                "Resolve all critical failures before deployment",
                "Implement high-priority recommendations",
                "Re-run validation after remediation",
                "Consider staged deployment approach"
            ]
        else:
            return [
                "Block production deployment until critical issues resolved",
                "Address all FAIL status items",
                "Implement comprehensive remediation plan",
                "Re-validate entire system before proceeding"
            ]

async def main():
    """Main function for production readiness validation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='MCP Production Readiness Validator')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--output', default='production_readiness_report.json', help='Output file path')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run validation
    validator = ProductionReadinessValidator(args.config)
    report = await validator.validate_all()
    
    # Save report
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\n" + "="*80)
    print("MCP PRODUCTION READINESS VALIDATION REPORT")
    print("="*80)
    print(f"Overall Score: {report['summary']['overall_score']:.1f}%")
    print(f"Readiness Level: {report['summary']['readiness_level']}")
    print(f"Readiness Grade: {report['summary']['readiness_grade']}")
    print(f"Production Ready: {'✅ YES' if report['summary']['production_ready'] else '❌ NO'}")
    
    print(f"\nValidation Results:")
    print(f"  Total Checks: {report['summary']['total_checks']}")
    print(f"  Passed: {report['summary']['passed_checks']}")
    print(f"  Failed: {report['summary']['failed_checks']}")
    print(f"  Warnings: {report['summary']['warning_checks']}")
    print(f"  Critical Failures: {report['summary']['critical_failures']}")
    
    print(f"\nCategory Scores:")
    for category, score_data in report['category_scores'].items():
        print(f"  {category}: {score_data['score']:.1f}% ({score_data['checks']} checks)")
    
    if report['recommendations']:
        print(f"\nTop Recommendations:")
        high_priority = [r for r in report['recommendations'] if r['priority'] == 'HIGH'][:5]
        for i, rec in enumerate(high_priority, 1):
            print(f"  {i}. {rec['category']}: {rec['recommendation']}")
    
    print(f"\nNext Steps:")
    for i, step in enumerate(report['next_steps'], 1):
        print(f"  {i}. {step}")
    
    print(f"\nDetailed report saved to: {args.output}")
    
    # Exit with appropriate code
    exit_code = 0 if report['summary']['production_ready'] else 1
    return exit_code

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)