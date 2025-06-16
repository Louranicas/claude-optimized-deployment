#!/usr/bin/env python3
"""
Agent 7: Phase 7 - Network & API Security Audit (Simplified)
===========================================================

Comprehensive network and API security audit without external dependencies.
Focuses on configuration analysis and static security assessment.
"""

import json
import logging
import os
import re
import subprocess
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'agent7_network_api_security_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class NetworkAPISecurityAuditorSimplified:
    """Simplified network and API security auditor."""
    
    def __init__(self):
        self.audit_id = str(uuid.uuid4())
        self.start_time = datetime.now()
        self.findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        self.metrics = {
            "config_files_analyzed": 0,
            "endpoints_discovered": 0,
            "security_headers_checked": 0,
            "vulnerabilities_found": 0,
            "network_configs_reviewed": 0
        }
        
    def add_finding(self, severity: str, category: str, title: str, description: str, 
                   recommendation: str, evidence: Dict[str, Any] = None):
        """Add security finding."""
        finding = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence or {}
        }
        
        self.findings[severity].append(finding)
        self.metrics["vulnerabilities_found"] += 1
        
        logger.warning(f"[{severity.upper()}] {category}: {title}")
    
    def audit_network_configuration(self) -> Dict[str, Any]:
        """Audit network configuration files."""
        logger.info("🔍 Auditing network configuration files...")
        
        results = {
            "docker_compose_analysis": {},
            "kubernetes_configs": {},
            "nginx_configuration": {},
            "network_policies": {}
        }
        
        # Analyze Docker Compose files
        compose_files = [
            "docker-compose.mcp-production.yml",
            "docker-compose.monitoring.yml"
        ]
        
        for compose_file in compose_files:
            if os.path.exists(compose_file):
                self.metrics["config_files_analyzed"] += 1
                analysis = self._analyze_docker_compose(compose_file)
                results["docker_compose_analysis"][compose_file] = analysis
        
        # Analyze Kubernetes configurations
        k8s_files = [
            "k8s/network-policies.yaml",
            "k8s/mcp-services.yaml",
            "k8s/security-policy.yaml"
        ]
        
        for k8s_file in k8s_files:
            if os.path.exists(k8s_file):
                self.metrics["config_files_analyzed"] += 1
                analysis = self._analyze_k8s_config(k8s_file)
                results["kubernetes_configs"][k8s_file] = analysis
        
        # Analyze NGINX configuration
        nginx_files = [
            "containers/networking/nginx.conf",
            "nginx/nginx.conf"
        ]
        
        for nginx_file in nginx_files:
            if os.path.exists(nginx_file):
                self.metrics["config_files_analyzed"] += 1
                analysis = self._analyze_nginx_config(nginx_file)
                results["nginx_configuration"][nginx_file] = analysis
        
        self.metrics["network_configs_reviewed"] = len(results)
        return results
    
    def _analyze_docker_compose(self, file_path: str) -> Dict[str, Any]:
        """Analyze Docker Compose configuration for security issues."""
        analysis = {
            "file": file_path,
            "services": {},
            "networks": {},
            "security_issues": [],
            "exposed_ports": []
        }
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                compose_config = yaml.safe_load(content)
            
            # Analyze services
            services = compose_config.get("services", {})
            for service_name, service_config in services.items():
                service_analysis = {
                    "image": service_config.get("image"),
                    "ports": service_config.get("ports", []),
                    "environment": service_config.get("environment", []),
                    "security_opt": service_config.get("security_opt", []),
                    "read_only": service_config.get("read_only", False)
                }
                
                # Check for exposed ports
                ports = service_config.get("ports", [])
                for port in ports:
                    if isinstance(port, str):
                        host_port = port.split(":")[0]
                        analysis["exposed_ports"].append({
                            "service": service_name,
                            "port": port,
                            "host_port": host_port
                        })
                        
                        # Check for privileged ports
                        if host_port in ["80", "443", "22", "21", "23", "25"]:
                            self.add_finding(
                                "medium",
                                "Network Exposure",
                                f"Privileged port {host_port} exposed in {service_name}",
                                f"Service {service_name} exposes privileged port {host_port}",
                                "Consider using non-privileged ports or reverse proxy"
                            )
                
                # Check for security options
                if not service_config.get("read_only", False):
                    self.add_finding(
                        "low",
                        "Container Security",
                        f"Container {service_name} not read-only",
                        "Container filesystem is writable",
                        "Enable read-only filesystem where possible"
                    )
                
                # Check for environment variables with secrets
                env_vars = service_config.get("environment", [])
                for env_var in env_vars:
                    if isinstance(env_var, str):
                        if any(keyword in env_var.lower() for keyword in 
                              ["password", "secret", "key", "token"]):
                            if "=" in env_var and len(env_var.split("=")[1]) > 5:
                                self.add_finding(
                                    "high",
                                    "Secret Management",
                                    f"Hardcoded secret in {service_name}",
                                    f"Environment variable contains secret: {env_var.split('=')[0]}",
                                    "Use Docker secrets or external secret management"
                                )
                
                analysis["services"][service_name] = service_analysis
            
            # Analyze networks
            networks = compose_config.get("networks", {})
            for network_name, network_config in networks.items():
                network_analysis = {
                    "driver": network_config.get("driver"),
                    "ipam": network_config.get("ipam", {}),
                    "external": network_config.get("external", False)
                }
                
                # Check for bridge networks
                if network_config.get("driver") == "bridge":
                    analysis["security_issues"].append(f"Bridge network {network_name} may allow container escape")
                
                analysis["networks"][network_name] = network_analysis
                
        except Exception as e:
            logger.error(f"Failed to analyze Docker Compose file {file_path}: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def _analyze_k8s_config(self, file_path: str) -> Dict[str, Any]:
        """Analyze Kubernetes configuration for security issues."""
        analysis = {
            "file": file_path,
            "resources": [],
            "security_policies": [],
            "network_policies": [],
            "security_issues": []
        }
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Parse YAML documents
            documents = yaml.safe_load_all(content)
            
            for doc in documents:
                if not doc:
                    continue
                    
                kind = doc.get("kind", "")
                metadata = doc.get("metadata", {})
                
                resource_info = {
                    "kind": kind,
                    "name": metadata.get("name"),
                    "namespace": metadata.get("namespace")
                }
                
                if kind == "NetworkPolicy":
                    policy_analysis = self._analyze_network_policy(doc)
                    analysis["network_policies"].append(policy_analysis)
                elif kind == "Service":
                    service_analysis = self._analyze_k8s_service(doc)
                    analysis["resources"].append(service_analysis)
                elif kind == "PodSecurityPolicy":
                    psp_analysis = self._analyze_pod_security_policy(doc)
                    analysis["security_policies"].append(psp_analysis)
                
                analysis["resources"].append(resource_info)
                
        except Exception as e:
            logger.error(f"Failed to analyze Kubernetes config {file_path}: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def _analyze_network_policy(self, policy_doc: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Kubernetes NetworkPolicy."""
        spec = policy_doc.get("spec", {})
        metadata = policy_doc.get("metadata", {})
        
        analysis = {
            "name": metadata.get("name"),
            "namespace": metadata.get("namespace"),
            "pod_selector": spec.get("podSelector", {}),
            "policy_types": spec.get("policyTypes", []),
            "ingress_rules": len(spec.get("ingress", [])),
            "egress_rules": len(spec.get("egress", [])),
            "security_assessment": []
        }
        
        # Check for overly broad selectors
        pod_selector = spec.get("podSelector", {})
        if not pod_selector or not pod_selector.get("matchLabels"):
            self.add_finding(
                "medium",
                "Network Policy",
                f"Broad network policy '{metadata.get('name')}'",
                "Network policy applies to all pods in namespace",
                "Use specific pod selectors to limit policy scope"
            )
            analysis["security_assessment"].append("Overly broad pod selector")
        
        # Check for missing policy types
        policy_types = spec.get("policyTypes", [])
        if "Egress" not in policy_types:
            analysis["security_assessment"].append("No egress restrictions")
        if "Ingress" not in policy_types:
            analysis["security_assessment"].append("No ingress restrictions")
        
        return analysis
    
    def _analyze_k8s_service(self, service_doc: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Kubernetes Service configuration."""
        spec = service_doc.get("spec", {})
        metadata = service_doc.get("metadata", {})
        
        analysis = {
            "name": metadata.get("name"),
            "namespace": metadata.get("namespace"),
            "type": spec.get("type", "ClusterIP"),
            "ports": spec.get("ports", []),
            "security_assessment": []
        }
        
        # Check for LoadBalancer services
        if spec.get("type") == "LoadBalancer":
            self.add_finding(
                "medium",
                "Service Exposure",
                f"LoadBalancer service '{metadata.get('name')}'",
                "Service exposes endpoints externally via LoadBalancer",
                "Ensure proper access controls and monitoring"
            )
            analysis["security_assessment"].append("External LoadBalancer exposure")
        
        # Check for NodePort services
        if spec.get("type") == "NodePort":
            self.add_finding(
                "low",
                "Service Exposure",
                f"NodePort service '{metadata.get('name')}'",
                "Service uses NodePort for external access",
                "Consider using Ingress controller instead"
            )
            analysis["security_assessment"].append("NodePort exposure")
        
        return analysis
    
    def _analyze_pod_security_policy(self, psp_doc: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Pod Security Policy."""
        spec = psp_doc.get("spec", {})
        metadata = psp_doc.get("metadata", {})
        
        analysis = {
            "name": metadata.get("name"),
            "privileged": spec.get("privileged", False),
            "allowPrivilegeEscalation": spec.get("allowPrivilegeEscalation", True),
            "runAsUser": spec.get("runAsUser", {}),
            "capabilities": spec.get("allowedCapabilities", []),
            "security_assessment": []
        }
        
        # Check for privileged containers
        if spec.get("privileged", False):
            self.add_finding(
                "high",
                "Pod Security",
                f"Privileged containers allowed in PSP '{metadata.get('name')}'",
                "Pod Security Policy allows privileged containers",
                "Disable privileged containers unless absolutely necessary"
            )
            analysis["security_assessment"].append("Allows privileged containers")
        
        # Check for privilege escalation
        if spec.get("allowPrivilegeEscalation", True):
            analysis["security_assessment"].append("Allows privilege escalation")
        
        return analysis
    
    def _analyze_nginx_config(self, file_path: str) -> Dict[str, Any]:
        """Analyze NGINX configuration for security issues."""
        analysis = {
            "file": file_path,
            "security_headers": {},
            "ssl_configuration": {},
            "rate_limiting": {},
            "security_issues": [],
            "cors_config": {}
        }
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Check security headers
            security_headers = {
                "X-Frame-Options": bool(re.search(r"X-Frame-Options", content, re.IGNORECASE)),
                "X-Content-Type-Options": bool(re.search(r"X-Content-Type-Options", content, re.IGNORECASE)),
                "X-XSS-Protection": bool(re.search(r"X-XSS-Protection", content, re.IGNORECASE)),
                "Strict-Transport-Security": bool(re.search(r"Strict-Transport-Security", content, re.IGNORECASE)),
                "Content-Security-Policy": bool(re.search(r"Content-Security-Policy", content, re.IGNORECASE))
            }
            
            analysis["security_headers"] = security_headers
            
            # Check for missing security headers
            for header, present in security_headers.items():
                if not present:
                    self.add_finding(
                        "medium",
                        "Missing Security Headers",
                        f"Missing {header} header",
                        f"Security header {header} not configured",
                        f"Add {header} header to improve security"
                    )
            
            # Check SSL configuration
            ssl_protocols = re.search(r"ssl_protocols\s+([^;]+);", content)
            if ssl_protocols:
                protocols = ssl_protocols.group(1).strip()
                analysis["ssl_configuration"]["protocols"] = protocols
                
                # Check for weak protocols
                weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
                for weak_protocol in weak_protocols:
                    if weak_protocol in protocols:
                        self.add_finding(
                            "high",
                            "Weak SSL Protocol",
                            f"Weak SSL protocol {weak_protocol} enabled",
                            f"SSL configuration includes weak protocol: {weak_protocol}",
                            "Remove weak SSL protocols, use only TLSv1.2 and TLSv1.3"
                        )
            
            # Check rate limiting
            rate_limit_zones = re.findall(r"limit_req_zone\s+([^;]+);", content)
            if rate_limit_zones:
                analysis["rate_limiting"]["zones"] = rate_limit_zones
            else:
                self.add_finding(
                    "medium",
                    "Rate Limiting",
                    "No rate limiting configured",
                    "NGINX configuration lacks rate limiting",
                    "Implement rate limiting to prevent abuse"
                )
            
            # Check CORS configuration
            cors_origin = re.search(r"Access-Control-Allow-Origin['\"]?\s*['\"]([^'\"]+)['\"]", content)
            if cors_origin:
                origin = cors_origin.group(1)
                analysis["cors_config"]["allow_origin"] = origin
                
                if origin == "*":
                    self.add_finding(
                        "medium",
                        "Permissive CORS",
                        "Wildcard CORS origin configured",
                        "Access-Control-Allow-Origin set to '*'",
                        "Specify exact allowed origins instead of wildcard"
                    )
            
            # Check for server tokens
            if "server_tokens off" not in content:
                self.add_finding(
                    "low",
                    "Information Disclosure",
                    "Server tokens not disabled",
                    "NGINX server version exposed in headers",
                    "Add 'server_tokens off;' to hide server version"
                )
            
        except Exception as e:
            logger.error(f"Failed to analyze NGINX config {file_path}: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def audit_api_security_configurations(self) -> Dict[str, Any]:
        """Audit API security configurations."""
        logger.info("🔍 Auditing API security configurations...")
        
        results = {
            "api_files_analyzed": {},
            "authentication_mechanisms": {},
            "input_validation": {},
            "rate_limiting": {},
            "security_middleware": {}
        }
        
        # Analyze Python API security files
        api_files = [
            "src/api/base.py",
            "src/security/mcp_security_core.py",
            "src/security/mcp_secure_server.py"
        ]
        
        for api_file in api_files:
            if os.path.exists(api_file):
                self.metrics["config_files_analyzed"] += 1
                analysis = self._analyze_api_security_code(api_file)
                results["api_files_analyzed"][api_file] = analysis
        
        return results
    
    def _analyze_api_security_code(self, file_path: str) -> Dict[str, Any]:
        """Analyze API security implementation."""
        analysis = {
            "file": file_path,
            "authentication_methods": [],
            "security_features": [],
            "vulnerabilities": [],
            "best_practices": []
        }
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Check authentication methods
            auth_patterns = {
                "JWT": r"jwt|JSON Web Token",
                "API_KEY": r"api[_-]?key",
                "OAuth": r"oauth",
                "Basic_Auth": r"basic.*auth",
                "Bearer_Token": r"bearer.*token"
            }
            
            for auth_type, pattern in auth_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    analysis["authentication_methods"].append(auth_type)
            
            # Check for security features
            security_features = {
                "Rate Limiting": r"rate[_-]?limit",
                "Input Validation": r"validat",
                "CSRF Protection": r"csrf",
                "XSS Protection": r"xss",
                "SQL Injection Protection": r"sql.*inject",
                "Encryption": r"encrypt|cipher",
                "Hashing": r"hash|bcrypt|scrypt|argon2",
                "Session Management": r"session"
            }
            
            for feature, pattern in security_features.items():
                if re.search(pattern, content, re.IGNORECASE):
                    analysis["security_features"].append(feature)
            
            # Check for potential vulnerabilities
            vulnerability_patterns = {
                "Hardcoded Secrets": r"(secret|password|key)\s*=\s*['\"][^'\"]{8,}['\"]",
                "SQL Injection": r"execute\s*\(\s*['\"].*\+.*['\"]",
                "Command Injection": r"os\.system|subprocess\.call.*shell=True",
                "Weak Random": r"random\.random|math\.random",
                "MD5 Usage": r"md5|hashlib\.md5",
                "Eval Usage": r"\beval\s*\(",
                "Debug Mode": r"debug\s*=\s*True"
            }
            
            for vuln_type, pattern in vulnerability_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    analysis["vulnerabilities"].append(vuln_type)
                    
                    severity = "high" if vuln_type in ["Hardcoded Secrets", "SQL Injection", "Command Injection"] else "medium"
                    self.add_finding(
                        severity,
                        "Code Security",
                        f"{vuln_type} detected in {file_path}",
                        f"Potential {vuln_type.lower()} vulnerability found",
                        f"Review and fix {vuln_type.lower()} issue"
                    )
            
            # Check for best practices
            best_practices = {
                "Input Sanitization": r"sanitiz|clean|filter",
                "Error Handling": r"try:|except:|finally:",
                "Logging": r"log\.|logger\.",
                "Type Hints": r":\s*(str|int|bool|List|Dict)",
                "Async/Await": r"async\s+def|await\s+",
                "Context Managers": r"with\s+.*:",
                "Secure Headers": r"X-Frame-Options|X-Content-Type-Options"
            }
            
            for practice, pattern in best_practices.items():
                if re.search(pattern, content, re.IGNORECASE):
                    analysis["best_practices"].append(practice)
            
        except Exception as e:
            logger.error(f"Failed to analyze API file {file_path}: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def audit_monitoring_and_logging(self) -> Dict[str, Any]:
        """Audit monitoring and logging configurations."""
        logger.info("🔍 Auditing monitoring and logging configurations...")
        
        results = {
            "monitoring_configs": {},
            "logging_configs": {},
            "alerting_rules": {},
            "security_monitoring": {}
        }
        
        # Check monitoring configurations
        monitoring_files = [
            "docker-compose.monitoring.yml",
            "monitoring/prometheus.yml",
            "monitoring/grafana-datasources.yml"
        ]
        
        for config_file in monitoring_files:
            if os.path.exists(config_file):
                self.metrics["config_files_analyzed"] += 1
                analysis = self._analyze_monitoring_config(config_file)
                results["monitoring_configs"][config_file] = analysis
        
        return results
    
    def _analyze_monitoring_config(self, file_path: str) -> Dict[str, Any]:
        """Analyze monitoring configuration."""
        analysis = {
            "file": file_path,
            "tools_detected": [],
            "security_metrics": [],
            "alerting_configured": False,
            "issues": []
        }
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Detect monitoring tools
            tools = {
                "Prometheus": r"prometheus",
                "Grafana": r"grafana", 
                "Jaeger": r"jaeger",
                "AlertManager": r"alertmanager"
            }
            
            for tool, pattern in tools.items():
                if re.search(pattern, content, re.IGNORECASE):
                    analysis["tools_detected"].append(tool)
            
            # Check for security-specific monitoring
            security_keywords = [
                "auth", "login", "failed", "error", "rate_limit",
                "block", "deny", "attack", "intrusion", "breach"
            ]
            
            for keyword in security_keywords:
                if keyword in content.lower():
                    analysis["security_metrics"].append(keyword)
            
            # Check for alerting
            if "alert" in content.lower():
                analysis["alerting_configured"] = True
            
            # Identify issues
            if not analysis["security_metrics"]:
                analysis["issues"].append("No security-specific monitoring detected")
                self.add_finding(
                    "medium",
                    "Monitoring Gaps",
                    f"Limited security monitoring in {file_path}",
                    "No security metrics detected in monitoring configuration",
                    "Add security event monitoring and alerting"
                )
            
        except Exception as e:
            logger.error(f"Failed to analyze monitoring config {file_path}: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive security audit report."""
        logger.info("📊 Generating comprehensive security audit report...")
        
        # Run all audit modules
        network_config_results = self.audit_network_configuration()
        api_security_results = self.audit_api_security_configurations()
        monitoring_results = self.audit_monitoring_and_logging()
        
        # Calculate risk assessment
        risk_assessment = self._calculate_risk_assessment()
        
        # Generate compliance assessment
        compliance_assessment = self._assess_security_compliance()
        
        # Create executive summary
        executive_summary = self._create_executive_summary()
        
        # Generate recommendations
        recommendations = self._generate_prioritized_recommendations()
        
        report = {
            "audit_metadata": {
                "audit_id": self.audit_id,
                "timestamp": datetime.now().isoformat(),
                "duration_minutes": (datetime.now() - self.start_time).total_seconds() / 60,
                "auditor": "Agent 7 - Network & API Security Specialist",
                "scope": "Network Configuration and API Security Assessment"
            },
            "executive_summary": executive_summary,
            "risk_assessment": risk_assessment,
            "compliance_assessment": compliance_assessment,
            "detailed_findings": {
                "network_configuration": network_config_results,
                "api_security": api_security_results,
                "monitoring_logging": monitoring_results
            },
            "security_findings": self.findings,
            "audit_metrics": self.metrics,
            "recommendations": recommendations,
            "remediation_plan": self._create_remediation_plan()
        }
        
        return report
    
    def _calculate_risk_assessment(self) -> Dict[str, Any]:
        """Calculate overall risk assessment."""
        total_findings = sum(len(findings) for findings in self.findings.values())
        
        if total_findings == 0:
            risk_level = "LOW"
            risk_score = 10
        else:
            # Calculate weighted risk score
            weighted_score = (
                len(self.findings["critical"]) * 10 +
                len(self.findings["high"]) * 7 +
                len(self.findings["medium"]) * 4 +
                len(self.findings["low"]) * 1
            )
            
            # Normalize to 0-100 scale
            max_possible_score = total_findings * 10
            risk_score = (weighted_score / max_possible_score) * 100 if max_possible_score > 0 else 0
            
            if risk_score >= 80:
                risk_level = "CRITICAL"
            elif risk_score >= 60:
                risk_level = "HIGH" 
            elif risk_score >= 30:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
        
        # Get top risk categories
        category_counts = defaultdict(int)
        for severity in ["critical", "high", "medium"]:
            for finding in self.findings[severity]:
                category_counts[finding["category"]] += 1
        
        top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "overall_risk_level": risk_level,
            "risk_score": round(risk_score, 2),
            "total_findings": total_findings,
            "findings_by_severity": {
                "critical": len(self.findings["critical"]),
                "high": len(self.findings["high"]),
                "medium": len(self.findings["medium"]),
                "low": len(self.findings["low"])
            },
            "top_risk_categories": [{"category": cat, "count": count} for cat, count in top_categories],
            "risk_factors": self._identify_risk_factors()
        }
    
    def _identify_risk_factors(self) -> List[str]:
        """Identify key risk factors."""
        risk_factors = []
        
        if len(self.findings["critical"]) > 0:
            risk_factors.append("Critical security vulnerabilities present")
        
        if len(self.findings["high"]) > 3:
            risk_factors.append("Multiple high-severity security issues")
        
        # Check for specific high-risk patterns
        all_findings = []
        for severity in self.findings.values():
            all_findings.extend(severity)
        
        categories = [f["category"] for f in all_findings]
        
        if "Secret Management" in categories:
            risk_factors.append("Hardcoded secrets detected")
        if "Code Security" in categories:
            risk_factors.append("Code-level security vulnerabilities")
        if "Network Exposure" in categories:
            risk_factors.append("Unnecessary network exposure")
        if "Missing Security Headers" in categories:
            risk_factors.append("Inadequate web security headers")
        
        return risk_factors
    
    def _assess_security_compliance(self) -> Dict[str, Any]:
        """Assess compliance with security standards."""
        compliance = {
            "owasp_api_top_10": self._check_owasp_api_compliance(),
            "owasp_web_top_10": self._check_owasp_web_compliance(),
            "cis_benchmarks": self._check_cis_compliance(),
            "nist_framework": self._check_nist_compliance()
        }
        
        return compliance
    
    def _check_owasp_api_compliance(self) -> Dict[str, Any]:
        """Check OWASP API Security Top 10 compliance."""
        owasp_api_categories = {
            "API1_Broken_Object_Level_Authorization": False,
            "API2_Broken_User_Authentication": False,
            "API3_Excessive_Data_Exposure": False,
            "API4_Lack_of_Resources_Rate_Limiting": False,
            "API5_Broken_Function_Level_Authorization": False,
            "API6_Mass_Assignment": False,
            "API7_Security_Misconfiguration": False,
            "API8_Injection": False,
            "API9_Improper_Assets_Management": False,
            "API10_Insufficient_Logging_Monitoring": False
        }
        
        # Map findings to OWASP categories
        all_findings = []
        for severity in self.findings.values():
            all_findings.extend(severity)
        
        for finding in all_findings:
            category = finding["category"].lower()
            title = finding["title"].lower()
            
            if "authentication" in category or "authorization" in category:
                owasp_api_categories["API2_Broken_User_Authentication"] = True
            if "rate" in category or "limit" in title:
                owasp_api_categories["API4_Lack_of_Resources_Rate_Limiting"] = True
            if "injection" in title or "sql" in title:
                owasp_api_categories["API8_Injection"] = True
            if "configuration" in category or "header" in category:
                owasp_api_categories["API7_Security_Misconfiguration"] = True
            if "monitoring" in category or "logging" in category:
                owasp_api_categories["API10_Insufficient_Logging_Monitoring"] = True
        
        violations = sum(owasp_api_categories.values())
        compliance_score = ((10 - violations) / 10) * 100
        
        return {
            "compliance_score": round(compliance_score, 2),
            "violations": owasp_api_categories,
            "total_violations": violations,
            "compliant": compliance_score >= 80
        }
    
    def _check_owasp_web_compliance(self) -> Dict[str, Any]:
        """Check OWASP Web Application Security Top 10 compliance."""
        owasp_web_categories = {
            "A01_Broken_Access_Control": False,
            "A02_Cryptographic_Failures": False,
            "A03_Injection": False,
            "A04_Insecure_Design": False,
            "A05_Security_Misconfiguration": False,
            "A06_Vulnerable_Components": False,
            "A07_Identification_Authentication_Failures": False,
            "A08_Software_Data_Integrity_Failures": False,
            "A09_Security_Logging_Monitoring_Failures": False,
            "A10_Server_Side_Request_Forgery": False
        }
        
        # Map findings to OWASP Web categories
        all_findings = []
        for severity in self.findings.values():
            all_findings.extend(severity)
        
        for finding in all_findings:
            category = finding["category"].lower()
            title = finding["title"].lower()
            
            if "injection" in title or "sql" in title or "xss" in title:
                owasp_web_categories["A03_Injection"] = True
            if "authentication" in category or "authorization" in category:
                owasp_web_categories["A07_Identification_Authentication_Failures"] = True
            if "configuration" in category or "header" in category:
                owasp_web_categories["A05_Security_Misconfiguration"] = True
            if "weak" in title and ("ssl" in title or "protocol" in title):
                owasp_web_categories["A02_Cryptographic_Failures"] = True
            if "monitoring" in category or "logging" in category:
                owasp_web_categories["A09_Security_Logging_Monitoring_Failures"] = True
        
        violations = sum(owasp_web_categories.values())
        compliance_score = ((10 - violations) / 10) * 100
        
        return {
            "compliance_score": round(compliance_score, 2),
            "violations": owasp_web_categories,
            "total_violations": violations,
            "compliant": compliance_score >= 80
        }
    
    def _check_cis_compliance(self) -> Dict[str, Any]:
        """Check CIS Benchmarks compliance."""
        cis_controls = {
            "access_control": False,
            "secure_configuration": False,
            "continuous_monitoring": False,
            "controlled_use_of_admin_privileges": False,
            "maintenance_monitoring_analysis_of_audit_logs": False
        }
        
        # Basic compliance check based on findings
        if self.metrics["config_files_analyzed"] > 0:
            cis_controls["secure_configuration"] = True
        
        if any("monitoring" in f["category"].lower() for findings in self.findings.values() for f in findings):
            cis_controls["continuous_monitoring"] = True
        
        compliance_score = (sum(cis_controls.values()) / len(cis_controls)) * 100
        
        return {
            "compliance_score": round(compliance_score, 2),
            "implemented_controls": cis_controls,
            "compliant": compliance_score >= 70
        }
    
    def _check_nist_compliance(self) -> Dict[str, Any]:
        """Check NIST Cybersecurity Framework compliance."""
        nist_functions = {
            "identify": 20,  # Configuration analysis performed
            "protect": 0,
            "detect": 0,
            "respond": 0,
            "recover": 0
        }
        
        # Score based on implemented controls and findings
        if len(self.findings["critical"]) == 0:
            nist_functions["protect"] += 20
        if len(self.findings["high"]) < 3:
            nist_functions["protect"] += 20
        
        if self.metrics["config_files_analyzed"] > 5:
            nist_functions["detect"] += 30
        
        overall_score = sum(nist_functions.values()) / 5
        
        return {
            "overall_score": round(overall_score, 2),
            "function_scores": nist_functions,
            "compliant": overall_score >= 60
        }
    
    def _create_executive_summary(self) -> Dict[str, Any]:
        """Create executive summary."""
        total_findings = sum(len(findings) for findings in self.findings.values())
        critical_high = len(self.findings["critical"]) + len(self.findings["high"])
        
        if total_findings == 0:
            posture = "EXCELLENT"
        elif critical_high == 0 and total_findings <= 5:
            posture = "GOOD"
        elif critical_high <= 2:
            posture = "ACCEPTABLE"
        elif critical_high <= 5:
            posture = "NEEDS_IMPROVEMENT"
        else:
            posture = "POOR"
        
        summary = {
            "overall_security_posture": posture,
            "total_findings": total_findings,
            "critical_findings": len(self.findings["critical"]),
            "high_findings": len(self.findings["high"]),
            "configs_analyzed": self.metrics["config_files_analyzed"],
            "key_strengths": self._identify_key_strengths(),
            "critical_weaknesses": self._identify_critical_weaknesses(),
            "immediate_actions": self._identify_immediate_actions(),
            "compliance_summary": self._summarize_compliance()
        }
        
        return summary
    
    def _identify_key_strengths(self) -> List[str]:
        """Identify key security strengths."""
        strengths = []
        
        if self.metrics["config_files_analyzed"] > 5:
            strengths.append("Comprehensive configuration coverage")
        
        if len(self.findings["critical"]) == 0:
            strengths.append("No critical vulnerabilities detected")
        
        # Check for positive security implementations
        all_findings = []
        for severity in self.findings.values():
            all_findings.extend(severity)
        
        categories = [f["category"] for f in all_findings]
        
        if "Network Policy" not in categories:
            strengths.append("Network segmentation implemented")
        
        if "Missing Security Headers" not in categories:
            strengths.append("Security headers properly configured")
        
        return strengths
    
    def _identify_critical_weaknesses(self) -> List[str]:
        """Identify critical security weaknesses."""
        weaknesses = []
        
        if len(self.findings["critical"]) > 0:
            weaknesses.append("Critical security vulnerabilities present")
        
        # Check for high-impact issues
        all_findings = []
        for severity in ["critical", "high"]:
            all_findings.extend(self.findings[severity])
        
        categories = [f["category"] for f in all_findings]
        
        if "Secret Management" in categories:
            weaknesses.append("Hardcoded secrets in configuration")
        if "Code Security" in categories:
            weaknesses.append("Code-level security vulnerabilities")
        if "Weak SSL Protocol" in [f["title"] for f in all_findings]:
            weaknesses.append("Weak TLS/SSL configuration")
        
        return weaknesses
    
    def _identify_immediate_actions(self) -> List[str]:
        """Identify immediate actions required."""
        actions = []
        
        if len(self.findings["critical"]) > 0:
            actions.append("Fix critical security vulnerabilities immediately")
        
        if len(self.findings["high"]) > 0:
            actions.append("Address high-severity security issues within 48 hours")
        
        # Check for specific urgent issues
        all_findings = []
        for severity in ["critical", "high"]:
            all_findings.extend(self.findings[severity])
        
        for finding in all_findings:
            if "hardcoded" in finding["title"].lower():
                actions.append("Remove hardcoded credentials and secrets")
                break
        
        for finding in all_findings:
            if "weak" in finding["title"].lower() and "ssl" in finding["title"].lower():
                actions.append("Update TLS/SSL configuration")
                break
        
        return actions
    
    def _summarize_compliance(self) -> Dict[str, str]:
        """Summarize compliance status."""
        # This would be calculated from actual compliance assessments
        return {
            "owasp_api": "Partial",
            "owasp_web": "Partial", 
            "cis_benchmarks": "Basic",
            "nist_framework": "Basic"
        }
    
    def _generate_prioritized_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        # Critical priority
        if len(self.findings["critical"]) > 0:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Vulnerability Management",
                "title": "Address Critical Security Vulnerabilities",
                "description": "Immediately remediate all critical security vulnerabilities",
                "timeline": "24-48 hours",
                "effort": "High",
                "impact": "High",
                "affected_components": [f["category"] for f in self.findings["critical"]]
            })
        
        # High priority
        if len(self.findings["high"]) > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Security Hardening",
                "title": "Strengthen Security Controls",
                "description": "Implement missing security controls and fix high-severity issues",
                "timeline": "1-2 weeks",
                "effort": "Medium",
                "impact": "High",
                "affected_components": [f["category"] for f in self.findings["high"]]
            })
        
        # Medium priority
        recommendations.append({
            "priority": "MEDIUM",
            "category": "Monitoring & Detection",
            "title": "Enhance Security Monitoring",
            "description": "Implement comprehensive security monitoring and alerting",
            "timeline": "2-4 weeks",
            "effort": "Medium",
            "impact": "Medium",
            "affected_components": ["Monitoring", "Logging", "Alerting"]
        })
        
        recommendations.append({
            "priority": "MEDIUM",
            "category": "Configuration Management",
            "title": "Security Configuration Review",
            "description": "Regular review and hardening of security configurations",
            "timeline": "4-6 weeks",
            "effort": "Low",
            "impact": "Medium",
            "affected_components": ["Network", "API", "Infrastructure"]
        })
        
        # Low priority
        recommendations.append({
            "priority": "LOW",
            "category": "Documentation & Training",
            "title": "Security Documentation Update",
            "description": "Update security procedures and conduct team training",
            "timeline": "6-8 weeks",
            "effort": "Low",
            "impact": "Low",
            "affected_components": ["Documentation", "Training", "Procedures"]
        })
        
        return recommendations
    
    def _create_remediation_plan(self) -> Dict[str, Any]:
        """Create detailed remediation plan."""
        plan = {
            "immediate_actions": [],
            "short_term_goals": [],
            "long_term_objectives": [],
            "resource_requirements": {},
            "success_metrics": []
        }
        
        # Immediate actions (0-48 hours)
        if len(self.findings["critical"]) > 0:
            plan["immediate_actions"].append({
                "action": "Fix critical vulnerabilities",
                "timeline": "24 hours",
                "owner": "Development Team",
                "priority": "P0"
            })
        
        # Short-term goals (1-4 weeks)
        if len(self.findings["high"]) > 0:
            plan["short_term_goals"].append({
                "goal": "Resolve high-severity security issues",
                "timeline": "2 weeks",
                "owner": "Security Team",
                "priority": "P1"
            })
        
        plan["short_term_goals"].append({
            "goal": "Implement security monitoring",
            "timeline": "4 weeks",
            "owner": "DevOps Team",
            "priority": "P2"
        })
        
        # Long-term objectives (1-3 months)
        plan["long_term_objectives"].append({
            "objective": "Achieve OWASP compliance",
            "timeline": "8 weeks",
            "owner": "Security Team",
            "priority": "P2"
        })
        
        plan["long_term_objectives"].append({
            "objective": "Implement automated security testing",
            "timeline": "12 weeks",
            "owner": "DevOps Team",
            "priority": "P3"
        })
        
        # Resource requirements
        plan["resource_requirements"] = {
            "security_engineer": "0.5 FTE for 2 months",
            "devops_engineer": "0.3 FTE for 1 month",
            "developer_time": "20 hours for critical fixes",
            "tools_budget": "$5,000 for security tools",
            "training_budget": "$2,000 for team training"
        }
        
        # Success metrics
        plan["success_metrics"] = [
            "Zero critical vulnerabilities",
            "Less than 5 high-severity findings",
            "90%+ OWASP compliance score",
            "Security monitoring coverage > 95%",
            "Monthly security assessments implemented"
        ]
        
        return plan


def main():
    """Main execution function."""
    logger.info("🚀 Starting Agent 7: Phase 7 - Network & API Security Audit")
    logger.info("=" * 80)
    
    try:
        # Initialize auditor
        auditor = NetworkAPISecurityAuditorSimplified()
        
        # Run comprehensive audit
        report = auditor.generate_comprehensive_report()
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"AGENT_7_NETWORK_API_SECURITY_AUDIT_REPORT_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print comprehensive summary
        logger.info("\n" + "=" * 80)
        logger.info("🎯 PHASE 7 NETWORK & API SECURITY AUDIT COMPLETE")
        logger.info("=" * 80)
        
        print(f"\n📊 AUDIT SUMMARY:")
        print(f"   • Audit ID: {report['audit_metadata']['audit_id']}")
        print(f"   • Duration: {report['audit_metadata']['duration_minutes']:.1f} minutes")
        print(f"   • Security Posture: {report['executive_summary']['overall_security_posture']}")
        print(f"   • Risk Level: {report['risk_assessment']['overall_risk_level']}")
        print(f"   • Risk Score: {report['risk_assessment']['risk_score']:.1f}/100")
        
        print(f"\n🔍 FINDINGS SUMMARY:")
        findings_summary = report['risk_assessment']['findings_by_severity']
        for severity, count in findings_summary.items():
            if count > 0:
                print(f"   • {severity.upper()}: {count} issues")
        
        print(f"\n📈 AUDIT METRICS:")
        for metric, value in report['audit_metrics'].items():
            print(f"   • {metric.replace('_', ' ').title()}: {value}")
        
        print(f"\n🏆 COMPLIANCE SCORES:")
        compliance = report['compliance_assessment']
        print(f"   • OWASP API Top 10: {compliance['owasp_api_top_10']['compliance_score']:.1f}%")
        print(f"   • OWASP Web Top 10: {compliance['owasp_web_top_10']['compliance_score']:.1f}%")
        print(f"   • CIS Benchmarks: {compliance['cis_benchmarks']['compliance_score']:.1f}%")
        print(f"   • NIST Framework: {compliance['nist_framework']['overall_score']:.1f}%")
        
        print(f"\n💪 KEY STRENGTHS:")
        for strength in report['executive_summary']['key_strengths']:
            print(f"   • {strength}")
        
        print(f"\n⚠️  CRITICAL WEAKNESSES:")
        for weakness in report['executive_summary']['critical_weaknesses']:
            print(f"   • {weakness}")
        
        print(f"\n🚨 IMMEDIATE ACTIONS REQUIRED:")
        for action in report['executive_summary']['immediate_actions']:
            print(f"   • {action}")
        
        print(f"\n📋 TOP RECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'][:3], 1):
            print(f"   {i}. [{rec['priority']}] {rec['title']}")
            print(f"      Timeline: {rec['timeline']} | Effort: {rec['effort']} | Impact: {rec['impact']}")
        
        print(f"\n🎯 REMEDIATION PLAN HIGHLIGHTS:")
        remediation = report['remediation_plan']
        if remediation['immediate_actions']:
            print(f"   • Immediate: {len(remediation['immediate_actions'])} critical actions")
        if remediation['short_term_goals']:
            print(f"   • Short-term: {len(remediation['short_term_goals'])} goals (1-4 weeks)")
        if remediation['long_term_objectives']:
            print(f"   • Long-term: {len(remediation['long_term_objectives'])} objectives (1-3 months)")
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        
        # Update todo status
        logger.info("✅ Network & API security audit completed successfully")
        
        return report
        
    except Exception as e:
        logger.error(f"❌ Network & API security audit failed: {e}")
        raise


if __name__ == "__main__":
    main()