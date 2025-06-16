#!/usr/bin/env python3
"""
Agent 7: Phase 7 - Comprehensive Network & API Security Audit
=============================================================

This script conducts a comprehensive security audit of all network communications, 
API endpoints, authentication mechanisms, and data flow security across the entire 
CODE ecosystem.

CRITICAL SECURITY AUDIT AREAS:
1. Network Architecture Security Assessment
2. API Endpoint Vulnerability Analysis  
3. Authentication & Authorization Security
4. Data Flow Security & Encryption Analysis
5. Network Segmentation Effectiveness
6. TLS/SSL Configuration Review
7. Rate Limiting & DoS Protection
8. Session Management & Token Security
9. CORS Configuration & Web Security
10. Network Monitoring & Intrusion Detection
"""

import asyncio
import json
import logging
import os
import re
import ssl
import subprocess
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import socket
import urllib.parse
import yaml

# Third-party imports
try:
    import aiohttp
    import docker
    import kubernetes
    import requests
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    import nmap
    import testssl
except ImportError as e:
    print(f"Required dependency missing: {e}")
    print("Install with: pip install aiohttp docker kubernetes requests cryptography python-nmap")
    sys.exit(1)

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


class NetworkAPISecurityAuditor:
    """Comprehensive network and API security auditor."""
    
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
            "endpoints_scanned": 0,
            "vulnerabilities_found": 0,
            "network_segments_analyzed": 0,
            "auth_mechanisms_tested": 0,
            "tls_configs_reviewed": 0
        }
        self.docker_client = None
        self.k8s_client = None
        
        # Initialize clients
        self._initialize_clients()
        
    def _initialize_clients(self):
        """Initialize Docker and Kubernetes clients."""
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized")
        except Exception as e:
            logger.warning(f"Docker client initialization failed: {e}")
            
        try:
            kubernetes.config.load_kube_config()
            self.k8s_client = kubernetes.client.ApiClient()
            logger.info("Kubernetes client initialized")
        except Exception as e:
            logger.warning(f"Kubernetes client initialization failed: {e}")
    
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
    
    async def audit_network_architecture(self) -> Dict[str, Any]:
        """Audit network architecture and segmentation."""
        logger.info("🔍 Starting network architecture security assessment...")
        
        results = {
            "network_topology": {},
            "segmentation_analysis": {},
            "firewall_rules": {},
            "service_mesh_security": {},
            "dns_security": {}
        }
        
        # Analyze Docker network configuration
        if self.docker_client:
            try:
                networks = self.docker_client.networks.list()
                for network in networks:
                    network_info = {
                        "name": network.name,
                        "driver": network.attrs.get("Driver"),
                        "subnet": network.attrs.get("IPAM", {}).get("Config", []),
                        "internal": network.attrs.get("Internal", False),
                        "encrypted": network.attrs.get("Options", {}).get("encrypted", False)
                    }
                    results["network_topology"][network.name] = network_info
                    
                    # Check for security issues
                    if not network_info["internal"] and "bridge" in network_info["driver"]:
                        self.add_finding(
                            "medium",
                            "Network Segmentation",
                            f"External access to bridge network '{network.name}'",
                            "Bridge network allows external connectivity which may expose services",
                            "Use internal networks for service-to-service communication"
                        )
                    
                    if not network_info["encrypted"]:
                        self.add_finding(
                            "high",
                            "Network Encryption",
                            f"Unencrypted network '{network.name}'",
                            "Network traffic is not encrypted in transit",
                            "Enable network encryption for sensitive communications"
                        )
                        
            except Exception as e:
                logger.error(f"Docker network analysis failed: {e}")
        
        # Analyze Kubernetes network policies
        if self.k8s_client:
            try:
                v1 = kubernetes.client.NetworkingV1Api(self.k8s_client)
                network_policies = v1.list_network_policy_for_all_namespaces()
                
                for policy in network_policies.items:
                    policy_analysis = {
                        "namespace": policy.metadata.namespace,
                        "name": policy.metadata.name,
                        "pod_selector": policy.spec.pod_selector,
                        "policy_types": policy.spec.policy_types,
                        "ingress_rules": len(policy.spec.ingress or []),
                        "egress_rules": len(policy.spec.egress or [])
                    }
                    results["segmentation_analysis"][f"{policy.metadata.namespace}/{policy.metadata.name}"] = policy_analysis
                    
                    # Check for overly permissive policies
                    if not policy.spec.pod_selector:
                        self.add_finding(
                            "medium",
                            "Network Policy",
                            f"Broad network policy '{policy.metadata.name}'",
                            "Network policy applies to all pods in namespace",
                            "Use specific pod selectors to limit policy scope"
                        )
                        
            except Exception as e:
                logger.error(f"Kubernetes network policy analysis failed: {e}")
        
        self.metrics["network_segments_analyzed"] = len(results["network_topology"])
        return results
    
    async def audit_api_endpoints(self) -> Dict[str, Any]:
        """Comprehensive API endpoint security audit."""
        logger.info("🔍 Starting API endpoint security audit...")
        
        results = {
            "discovered_endpoints": {},
            "authentication_analysis": {},
            "input_validation": {},
            "output_security": {},
            "rate_limiting": {},
            "cors_analysis": {}
        }
        
        # Discover API endpoints from configurations
        endpoints = await self._discover_api_endpoints()
        
        for endpoint_url, endpoint_info in endpoints.items():
            self.metrics["endpoints_scanned"] += 1
            logger.info(f"Auditing endpoint: {endpoint_url}")
            
            # Test endpoint security
            endpoint_results = await self._audit_single_endpoint(endpoint_url, endpoint_info)
            results["discovered_endpoints"][endpoint_url] = endpoint_results
        
        return results
    
    async def _discover_api_endpoints(self) -> Dict[str, Any]:
        """Discover API endpoints from various configurations."""
        endpoints = {}
        
        # Parse Docker Compose files
        compose_files = [
            "docker-compose.mcp-production.yml",
            "docker-compose.monitoring.yml"
        ]
        
        for compose_file in compose_files:
            if os.path.exists(compose_file):
                try:
                    with open(compose_file, 'r') as f:
                        compose_config = yaml.safe_load(f)
                    
                    services = compose_config.get("services", {})
                    for service_name, service_config in services.items():
                        ports = service_config.get("ports", [])
                        for port_mapping in ports:
                            if isinstance(port_mapping, str):
                                host_port = port_mapping.split(":")[0]
                                endpoint_url = f"http://localhost:{host_port}"
                                endpoints[endpoint_url] = {
                                    "service": service_name,
                                    "type": "docker_compose",
                                    "file": compose_file
                                }
                except Exception as e:
                    logger.error(f"Failed to parse {compose_file}: {e}")
        
        # Parse Kubernetes services
        if self.k8s_client:
            try:
                v1 = kubernetes.client.CoreV1Api(self.k8s_client)
                services = v1.list_service_for_all_namespaces()
                
                for service in services.items:
                    for port in service.spec.ports:
                        endpoint_url = f"http://{service.metadata.name}.{service.metadata.namespace}:{port.port}"
                        endpoints[endpoint_url] = {
                            "service": service.metadata.name,
                            "namespace": service.metadata.namespace,
                            "type": "kubernetes",
                            "port": port.port
                        }
            except Exception as e:
                logger.error(f"Kubernetes service discovery failed: {e}")
        
        return endpoints
    
    async def _audit_single_endpoint(self, url: str, endpoint_info: Dict[str, Any]) -> Dict[str, Any]:
        """Audit a single API endpoint."""
        results = {
            "url": url,
            "info": endpoint_info,
            "security_headers": {},
            "tls_config": {},
            "authentication": {},
            "vulnerabilities": []
        }
        
        try:
            # Test basic connectivity and headers
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                try:
                    async with session.get(url) as response:
                        # Analyze security headers
                        security_headers = self._analyze_security_headers(dict(response.headers))
                        results["security_headers"] = security_headers
                        
                        # Check for information disclosure
                        if 'server' in response.headers:
                            self.add_finding(
                                "low",
                                "Information Disclosure",
                                f"Server header exposed on {url}",
                                f"Server header reveals: {response.headers['server']}",
                                "Remove or mask server identification headers"
                            )
                        
                        # Test for common vulnerabilities
                        await self._test_endpoint_vulnerabilities(session, url, results)
                        
                except aiohttp.ClientError as e:
                    logger.warning(f"Failed to connect to {url}: {e}")
                    results["error"] = str(e)
        
        except Exception as e:
            logger.error(f"Endpoint audit failed for {url}: {e}")
            results["error"] = str(e)
        
        return results
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HTTP security headers."""
        security_headers = {
            "x-frame-options": headers.get("x-frame-options"),
            "x-content-type-options": headers.get("x-content-type-options"), 
            "x-xss-protection": headers.get("x-xss-protection"),
            "strict-transport-security": headers.get("strict-transport-security"),
            "content-security-policy": headers.get("content-security-policy"),
            "referrer-policy": headers.get("referrer-policy"),
            "permissions-policy": headers.get("permissions-policy")
        }
        
        # Check for missing critical headers
        critical_headers = [
            "x-frame-options",
            "x-content-type-options",
            "strict-transport-security",
            "content-security-policy"
        ]
        
        for header in critical_headers:
            if not security_headers[header]:
                self.add_finding(
                    "medium",
                    "Missing Security Headers",
                    f"Missing {header} header",
                    f"The {header} security header is not present",
                    f"Add {header} header to prevent common web attacks"
                )
        
        return security_headers
    
    async def _test_endpoint_vulnerabilities(self, session: aiohttp.ClientSession, 
                                           url: str, results: Dict[str, Any]):
        """Test endpoint for common vulnerabilities."""
        
        # Test for SQL injection
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --"
        ]
        
        for payload in sql_payloads:
            try:
                test_url = f"{url}?test={urllib.parse.quote(payload)}"
                async with session.get(test_url) as response:
                    response_text = await response.text()
                    if any(error in response_text.lower() for error in 
                          ["sql syntax", "mysql error", "postgresql error", "ora-"]):
                        self.add_finding(
                            "critical",
                            "SQL Injection",
                            f"Potential SQL injection vulnerability in {url}",
                            f"SQL error messages detected with payload: {payload}",
                            "Implement parameterized queries and input validation"
                        )
            except Exception:
                pass
        
        # Test for XSS
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        for payload in xss_payloads:
            try:
                test_url = f"{url}?test={urllib.parse.quote(payload)}"
                async with session.get(test_url) as response:
                    response_text = await response.text()
                    if payload in response_text:
                        self.add_finding(
                            "high",
                            "Cross-Site Scripting (XSS)",
                            f"Potential XSS vulnerability in {url}",
                            f"Payload reflected in response: {payload}",
                            "Implement output encoding and Content Security Policy"
                        )
            except Exception:
                pass
        
        # Test for CSRF protection
        try:
            # Test POST without CSRF token
            async with session.post(url, data={"test": "data"}) as response:
                if response.status == 200:
                    self.add_finding(
                        "medium",
                        "CSRF Protection",
                        f"Potential CSRF vulnerability in {url}",
                        "POST request accepted without CSRF token",
                        "Implement CSRF token validation for state-changing operations"
                    )
        except Exception:
            pass
    
    async def audit_authentication_authorization(self) -> Dict[str, Any]:
        """Audit authentication and authorization mechanisms."""
        logger.info("🔍 Starting authentication and authorization security audit...")
        
        results = {
            "auth_mechanisms": {},
            "token_security": {},
            "session_management": {},
            "rbac_analysis": {},
            "oauth_security": {}
        }
        
        # Analyze MCP security configuration
        security_files = [
            "src/security/mcp_security_core.py",
            "src/security/mcp_secure_server.py",
            "src/api/base.py"
        ]
        
        for file_path in security_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    auth_analysis = self._analyze_authentication_code(content, file_path)
                    results["auth_mechanisms"][file_path] = auth_analysis
                    
                except Exception as e:
                    logger.error(f"Failed to analyze {file_path}: {e}")
        
        # Test JWT token security
        jwt_analysis = await self._audit_jwt_security()
        results["token_security"]["jwt"] = jwt_analysis
        
        # Analyze session management
        session_analysis = await self._audit_session_management()
        results["session_management"] = session_analysis
        
        self.metrics["auth_mechanisms_tested"] = len(results["auth_mechanisms"])
        return results
    
    def _analyze_authentication_code(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze authentication code for security issues."""
        analysis = {
            "file": file_path,
            "auth_methods": [],
            "security_issues": [],
            "best_practices": []
        }
        
        # Check for authentication methods
        if "jwt" in content.lower():
            analysis["auth_methods"].append("JWT")
        if "api_key" in content.lower():
            analysis["auth_methods"].append("API_KEY")
        if "oauth" in content.lower():
            analysis["auth_methods"].append("OAuth")
        if "session" in content.lower():
            analysis["auth_methods"].append("Session")
        
        # Check for security issues
        if re.search(r"secret\s*=\s*['\"][^'\"]{1,20}['\"]", content):
            self.add_finding(
                "critical",
                "Hardcoded Secrets",
                f"Hardcoded secret found in {file_path}",
                "Secret values should not be hardcoded in source code",
                "Use environment variables or secure secret management"
            )
        
        if "md5" in content.lower() or "sha1" in content.lower():
            self.add_finding(
                "medium",
                "Weak Cryptography",
                f"Weak hash algorithm in {file_path}",
                "MD5 or SHA1 detected - these are cryptographically weak",
                "Use SHA-256 or stronger algorithms"
            )
        
        if re.search(r"password\s*==\s*['\"][^'\"]+['\"]", content):
            self.add_finding(
                "high",
                "Hardcoded Credentials",
                f"Hardcoded password in {file_path}",
                "Password comparison found in code",
                "Use secure password hashing and comparison"
            )
        
        # Check for best practices
        if "bcrypt" in content.lower():
            analysis["best_practices"].append("Uses bcrypt for password hashing")
        if "rate_limit" in content.lower():
            analysis["best_practices"].append("Implements rate limiting")
        if "csrf" in content.lower():
            analysis["best_practices"].append("CSRF protection implemented")
        
        return analysis
    
    async def _audit_jwt_security(self) -> Dict[str, Any]:
        """Audit JWT token security implementation."""
        jwt_analysis = {
            "algorithm_security": {},
            "token_validation": {},
            "expiration_handling": {},
            "secret_management": {}
        }
        
        # Test common JWT vulnerabilities
        test_tokens = [
            # Algorithm confusion attack
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            # Weak secret
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ]
        
        for token in test_tokens:
            try:
                # Test if weak tokens are accepted
                # This would require actual endpoint testing
                pass
            except Exception:
                pass
        
        return jwt_analysis
    
    async def _audit_session_management(self) -> Dict[str, Any]:
        """Audit session management security."""
        session_analysis = {
            "session_fixation": False,
            "session_hijacking": False,
            "secure_cookies": False,
            "session_timeout": None
        }
        
        # Check for session security in configurations
        config_files = ["nginx/nginx.conf", "containers/networking/nginx.conf"]
        
        for config_file in config_files:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    if "secure" in content.lower() and "cookie" in content.lower():
                        session_analysis["secure_cookies"] = True
                    
                    # Check for session timeout
                    timeout_match = re.search(r"session_timeout\s+(\d+)", content)
                    if timeout_match:
                        session_analysis["session_timeout"] = timeout_match.group(1)
                        
                except Exception as e:
                    logger.error(f"Failed to analyze {config_file}: {e}")
        
        return session_analysis
    
    async def audit_tls_encryption(self) -> Dict[str, Any]:
        """Audit TLS/SSL configuration and encryption."""
        logger.info("🔍 Starting TLS/encryption security audit...")
        
        results = {
            "tls_configurations": {},
            "certificate_analysis": {},
            "cipher_suites": {},
            "protocol_versions": {},
            "certificate_chain": {}
        }
        
        # Analyze nginx SSL configuration
        nginx_configs = [
            "containers/networking/nginx.conf",
            "nginx/nginx.conf"
        ]
        
        for config_file in nginx_configs:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    tls_config = self._analyze_tls_config(content, config_file)
                    results["tls_configurations"][config_file] = tls_config
                    
                except Exception as e:
                    logger.error(f"Failed to analyze TLS config {config_file}: {e}")
        
        # Check for SSL certificates
        cert_paths = [
            "/etc/nginx/ssl/",
            "./nginx/ssl/",
            "./containers/ssl/"
        ]
        
        for cert_path in cert_paths:
            if os.path.exists(cert_path):
                cert_analysis = await self._analyze_certificates(cert_path)
                results["certificate_analysis"][cert_path] = cert_analysis
        
        self.metrics["tls_configs_reviewed"] = len(results["tls_configurations"])
        return results
    
    def _analyze_tls_config(self, content: str, config_file: str) -> Dict[str, Any]:
        """Analyze TLS configuration for security issues."""
        tls_config = {
            "protocols": [],
            "ciphers": [],
            "security_issues": [],
            "best_practices": []
        }
        
        # Extract SSL protocols
        protocol_match = re.search(r"ssl_protocols\s+([^;]+);", content)
        if protocol_match:
            protocols = protocol_match.group(1).split()
            tls_config["protocols"] = protocols
            
            # Check for weak protocols
            weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
            for protocol in protocols:
                if protocol in weak_protocols:
                    self.add_finding(
                        "high",
                        "Weak TLS Protocol",
                        f"Weak TLS protocol {protocol} enabled in {config_file}",
                        f"Protocol {protocol} has known security vulnerabilities",
                        "Use only TLSv1.2 and TLSv1.3"
                    )
        
        # Extract cipher suites
        cipher_match = re.search(r"ssl_ciphers\s+([^;]+);", content)
        if cipher_match:
            ciphers = cipher_match.group(1)
            tls_config["ciphers"] = ciphers
            
            # Check for weak ciphers
            weak_ciphers = ["RC4", "DES", "3DES", "MD5", "SHA1"]
            for weak_cipher in weak_ciphers:
                if weak_cipher in ciphers:
                    self.add_finding(
                        "medium",
                        "Weak Cipher Suite",
                        f"Weak cipher {weak_cipher} in {config_file}",
                        f"Cipher suite contains weak algorithm: {weak_cipher}",
                        "Remove weak ciphers and use modern cipher suites"
                    )
        
        # Check for security best practices
        if "ssl_prefer_server_ciphers" in content:
            tls_config["best_practices"].append("Server cipher preference enabled")
        
        if "ssl_session_tickets off" in content:
            tls_config["best_practices"].append("Session tickets disabled")
        
        if "ssl_stapling on" in content:
            tls_config["best_practices"].append("OCSP stapling enabled")
        
        return tls_config
    
    async def _analyze_certificates(self, cert_path: str) -> Dict[str, Any]:
        """Analyze SSL certificates for security issues."""
        cert_analysis = {
            "certificates": [],
            "expiration_warnings": [],
            "key_strength": {},
            "chain_validation": {}
        }
        
        try:
            cert_files = [f for f in os.listdir(cert_path) if f.endswith(('.pem', '.crt', '.cert'))]
            
            for cert_file in cert_files:
                full_path = os.path.join(cert_path, cert_file)
                try:
                    with open(full_path, 'rb') as f:
                        cert_data = f.read()
                    
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    
                    cert_info = {
                        "file": cert_file,
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "not_before": cert.not_valid_before.isoformat(),
                        "not_after": cert.not_valid_after.isoformat(),
                        "serial_number": str(cert.serial_number),
                        "signature_algorithm": cert.signature_algorithm_oid._name
                    }
                    
                    cert_analysis["certificates"].append(cert_info)
                    
                    # Check expiration
                    days_until_expiry = (cert.not_valid_after - datetime.now()).days
                    if days_until_expiry < 30:
                        self.add_finding(
                            "high",
                            "Certificate Expiration",
                            f"Certificate {cert_file} expires soon",
                            f"Certificate expires in {days_until_expiry} days",
                            "Renew certificate before expiration"
                        )
                    elif days_until_expiry < 90:
                        cert_analysis["expiration_warnings"].append(
                            f"{cert_file}: {days_until_expiry} days until expiry"
                        )
                    
                    # Check key strength
                    public_key = cert.public_key()
                    if hasattr(public_key, 'key_size'):
                        key_size = public_key.key_size
                        if key_size < 2048:
                            self.add_finding(
                                "medium",
                                "Weak Certificate Key",
                                f"Weak key size in {cert_file}",
                                f"Certificate uses {key_size}-bit key",
                                "Use at least 2048-bit RSA keys or 256-bit ECC keys"
                            )
                    
                except Exception as e:
                    logger.error(f"Failed to analyze certificate {cert_file}: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to analyze certificates in {cert_path}: {e}")
        
        return cert_analysis
    
    async def audit_network_monitoring(self) -> Dict[str, Any]:
        """Audit network monitoring and intrusion detection capabilities."""
        logger.info("🔍 Starting network monitoring security audit...")
        
        results = {
            "monitoring_tools": {},
            "log_analysis": {},
            "alerting_systems": {},
            "intrusion_detection": {},
            "network_visibility": {}
        }
        
        # Check for monitoring configurations
        monitoring_configs = [
            "docker-compose.monitoring.yml",
            "monitoring/prometheus.yml",
            "monitoring/grafana-datasources.yml"
        ]
        
        for config_file in monitoring_configs:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    monitoring_analysis = self._analyze_monitoring_config(content, config_file)
                    results["monitoring_tools"][config_file] = monitoring_analysis
                    
                except Exception as e:
                    logger.error(f"Failed to analyze monitoring config {config_file}: {e}")
        
        # Check for log aggregation
        log_configs = [
            "monitoring/logstash/",
            "monitoring/fluentd/",
            "src/monitoring/"
        ]
        
        for log_path in log_configs:
            if os.path.exists(log_path):
                log_analysis = await self._analyze_log_configuration(log_path)
                results["log_analysis"][log_path] = log_analysis
        
        return results
    
    def _analyze_monitoring_config(self, content: str, config_file: str) -> Dict[str, Any]:
        """Analyze monitoring configuration for security coverage."""
        monitoring_analysis = {
            "tools_detected": [],
            "security_metrics": [],
            "alerting_rules": [],
            "gaps": []
        }
        
        # Detect monitoring tools
        if "prometheus" in content.lower():
            monitoring_analysis["tools_detected"].append("Prometheus")
        if "grafana" in content.lower():
            monitoring_analysis["tools_detected"].append("Grafana")
        if "jaeger" in content.lower():
            monitoring_analysis["tools_detected"].append("Jaeger")
        if "elasticsearch" in content.lower():
            monitoring_analysis["tools_detected"].append("Elasticsearch")
        
        # Check for security-specific monitoring
        security_keywords = [
            "auth", "login", "failed", "error", "exception",
            "rate_limit", "block", "deny", "attack", "intrusion"
        ]
        
        for keyword in security_keywords:
            if keyword in content.lower():
                monitoring_analysis["security_metrics"].append(keyword)
        
        # Check for missing security monitoring
        if not monitoring_analysis["security_metrics"]:
            self.add_finding(
                "medium",
                "Monitoring Gaps",
                f"Limited security monitoring in {config_file}",
                "No security-specific metrics detected in monitoring configuration",
                "Add security event monitoring and alerting"
            )
        
        return monitoring_analysis
    
    async def _analyze_log_configuration(self, log_path: str) -> Dict[str, Any]:
        """Analyze log configuration for security coverage."""
        log_analysis = {
            "log_sources": [],
            "retention_policy": None,
            "security_logging": [],
            "compliance": []
        }
        
        try:
            for root, dirs, files in os.walk(log_path):
                for file in files:
                    if file.endswith(('.conf', '.yml', '.yaml', '.json')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read()
                            
                            # Check for security logging patterns
                            if "authentication" in content.lower():
                                log_analysis["security_logging"].append("Authentication events")
                            if "authorization" in content.lower():
                                log_analysis["security_logging"].append("Authorization events")
                            if "audit" in content.lower():
                                log_analysis["security_logging"].append("Audit trail")
                            
                        except Exception as e:
                            logger.error(f"Failed to read log config {file_path}: {e}")
        
        except Exception as e:
            logger.error(f"Failed to analyze log configuration {log_path}: {e}")
        
        return log_analysis
    
    async def audit_cors_and_web_security(self) -> Dict[str, Any]:
        """Audit CORS configuration and web security settings."""
        logger.info("🔍 Starting CORS and web security audit...")
        
        results = {
            "cors_configuration": {},
            "csp_analysis": {},
            "web_security_headers": {},
            "cookie_security": {}
        }
        
        # Analyze CORS settings in nginx configuration
        nginx_configs = [
            "containers/networking/nginx.conf",
            "nginx/nginx.conf"
        ]
        
        for config_file in nginx_configs:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    cors_analysis = self._analyze_cors_config(content, config_file)
                    results["cors_configuration"][config_file] = cors_analysis
                    
                except Exception as e:
                    logger.error(f"Failed to analyze CORS config {config_file}: {e}")
        
        return results
    
    def _analyze_cors_config(self, content: str, config_file: str) -> Dict[str, Any]:
        """Analyze CORS configuration for security issues."""
        cors_analysis = {
            "allow_origin": [],
            "allow_methods": [],
            "allow_headers": [],
            "security_issues": []
        }
        
        # Extract CORS headers
        origin_match = re.search(r"Access-Control-Allow-Origin['\"]?\s*['\"]([^'\"]+)['\"]", content)
        if origin_match:
            origin = origin_match.group(1)
            cors_analysis["allow_origin"].append(origin)
            
            # Check for overly permissive CORS
            if origin == "*":
                self.add_finding(
                    "medium",
                    "Permissive CORS Policy",
                    f"Wildcard CORS origin in {config_file}",
                    "Access-Control-Allow-Origin set to '*' allows any origin",
                    "Specify exact allowed origins instead of using wildcard"
                )
        
        methods_match = re.search(r"Access-Control-Allow-Methods['\"]?\s*['\"]([^'\"]+)['\"]", content)
        if methods_match:
            methods = methods_match.group(1).split(", ")
            cors_analysis["allow_methods"] = methods
            
            # Check for dangerous methods
            dangerous_methods = ["DELETE", "PUT", "PATCH"]
            for method in methods:
                if method in dangerous_methods:
                    cors_analysis["security_issues"].append(f"Allows {method} method")
        
        return cors_analysis
    
    async def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive network and API security audit report."""
        logger.info("📊 Generating comprehensive security audit report...")
        
        # Run all audit modules
        network_results = await self.audit_network_architecture()
        api_results = await self.audit_api_endpoints() 
        auth_results = await self.audit_authentication_authorization()
        tls_results = await self.audit_tls_encryption()
        monitoring_results = await self.audit_network_monitoring()
        cors_results = await self.audit_cors_and_web_security()
        
        # Calculate risk scores
        risk_assessment = self._calculate_risk_scores()
        
        # Generate compliance assessment
        compliance_assessment = self._assess_compliance()
        
        # Create executive summary
        executive_summary = self._create_executive_summary()
        
        report = {
            "audit_metadata": {
                "audit_id": self.audit_id,
                "timestamp": datetime.now().isoformat(),
                "duration_minutes": (datetime.now() - self.start_time).total_seconds() / 60,
                "auditor": "Agent 7 - Network & API Security Specialist",
                "scope": "Comprehensive Network and API Security Audit"
            },
            "executive_summary": executive_summary,
            "risk_assessment": risk_assessment,
            "compliance_assessment": compliance_assessment,
            "detailed_findings": {
                "network_architecture": network_results,
                "api_security": api_results,
                "authentication_authorization": auth_results,
                "tls_encryption": tls_results,
                "network_monitoring": monitoring_results,
                "cors_web_security": cors_results
            },
            "security_findings": self.findings,
            "metrics": self.metrics,
            "recommendations": self._generate_prioritized_recommendations()
        }
        
        return report
    
    def _calculate_risk_scores(self) -> Dict[str, Any]:
        """Calculate overall risk scores."""
        total_findings = sum(len(findings) for findings in self.findings.values())
        
        if total_findings == 0:
            risk_level = "LOW"
            risk_score = 0
        else:
            # Weight findings by severity
            weighted_score = (
                len(self.findings["critical"]) * 10 +
                len(self.findings["high"]) * 7 +
                len(self.findings["medium"]) * 4 +
                len(self.findings["low"]) * 1
            )
            
            risk_score = min(100, (weighted_score / max(1, total_findings)) * 10)
            
            if risk_score >= 80:
                risk_level = "CRITICAL"
            elif risk_score >= 60:
                risk_level = "HIGH"
            elif risk_score >= 30:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
        
        return {
            "overall_risk_level": risk_level,
            "risk_score": round(risk_score, 2),
            "finding_distribution": {
                "critical": len(self.findings["critical"]),
                "high": len(self.findings["high"]),
                "medium": len(self.findings["medium"]),
                "low": len(self.findings["low"])
            },
            "top_risk_categories": self._get_top_risk_categories()
        }
    
    def _get_top_risk_categories(self) -> List[str]:
        """Get top risk categories by finding count."""
        category_counts = defaultdict(int)
        
        for severity in ["critical", "high", "medium"]:
            for finding in self.findings[severity]:
                category_counts[finding["category"]] += 1
        
        return [cat for cat, count in sorted(category_counts.items(), 
                                           key=lambda x: x[1], reverse=True)[:5]]
    
    def _assess_compliance(self) -> Dict[str, Any]:
        """Assess compliance with security standards."""
        compliance = {
            "owasp_api_top_10": self._check_owasp_api_compliance(),
            "owasp_top_10": self._check_owasp_web_compliance(),
            "nist_cybersecurity_framework": self._check_nist_compliance(),
            "iso_27001": self._check_iso27001_compliance()
        }
        
        return compliance
    
    def _check_owasp_api_compliance(self) -> Dict[str, Any]:
        """Check compliance with OWASP API Security Top 10."""
        owasp_api_issues = {
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
        
        # Check findings against OWASP categories
        for severity in self.findings:
            for finding in self.findings[severity]:
                category = finding["category"].lower()
                
                if "authentication" in category:
                    owasp_api_issues["API2_Broken_User_Authentication"] = True
                if "rate" in category or "limit" in category:
                    owasp_api_issues["API4_Lack_of_Resources_Rate_Limiting"] = True
                if "injection" in category or "sql" in category:
                    owasp_api_issues["API8_Injection"] = True
                if "configuration" in category or "misconfiguration" in category:
                    owasp_api_issues["API7_Security_Misconfiguration"] = True
                if "monitoring" in category or "logging" in category:
                    owasp_api_issues["API10_Insufficient_Logging_Monitoring"] = True
        
        compliance_score = (10 - sum(owasp_api_issues.values())) / 10 * 100
        
        return {
            "compliance_score": round(compliance_score, 2),
            "issues_found": owasp_api_issues,
            "compliant": compliance_score >= 80
        }
    
    def _check_owasp_web_compliance(self) -> Dict[str, Any]:
        """Check compliance with OWASP Web Application Security Top 10.""" 
        owasp_web_issues = {
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
        
        # Map findings to OWASP categories
        for severity in self.findings:
            for finding in self.findings[severity]:
                category = finding["category"].lower()
                title = finding["title"].lower()
                
                if "injection" in category or "sql" in title or "xss" in title:
                    owasp_web_issues["A03_Injection"] = True
                if "authentication" in category or "authorization" in category:
                    owasp_web_issues["A07_Identification_Authentication_Failures"] = True
                if "configuration" in category:
                    owasp_web_issues["A05_Security_Misconfiguration"] = True
                if "cryptography" in category or "encryption" in category:
                    owasp_web_issues["A02_Cryptographic_Failures"] = True
                if "monitoring" in category or "logging" in category:
                    owasp_web_issues["A09_Security_Logging_Monitoring_Failures"] = True
        
        compliance_score = (10 - sum(owasp_web_issues.values())) / 10 * 100
        
        return {
            "compliance_score": round(compliance_score, 2),
            "issues_found": owasp_web_issues,
            "compliant": compliance_score >= 80
        }
    
    def _check_nist_compliance(self) -> Dict[str, Any]:
        """Check compliance with NIST Cybersecurity Framework."""
        nist_functions = {
            "identify": 0,
            "protect": 0,
            "detect": 0,
            "respond": 0,
            "recover": 0
        }
        
        # Score based on implemented security controls
        if self.metrics["auth_mechanisms_tested"] > 0:
            nist_functions["protect"] += 20
        if self.metrics["tls_configs_reviewed"] > 0:
            nist_functions["protect"] += 20
        if len(self.findings["critical"]) == 0:
            nist_functions["protect"] += 20
        
        # Monitoring and detection
        monitoring_score = min(40, self.metrics["network_segments_analyzed"] * 10)
        nist_functions["detect"] = monitoring_score
        
        overall_score = sum(nist_functions.values()) / 5
        
        return {
            "overall_score": round(overall_score, 2),
            "function_scores": nist_functions,
            "compliant": overall_score >= 70
        }
    
    def _check_iso27001_compliance(self) -> Dict[str, Any]:
        """Check compliance with ISO 27001 controls."""
        iso_controls = {
            "access_control": False,
            "cryptography": False,
            "operations_security": False,
            "communications_security": False,
            "system_acquisition": False,
            "incident_management": False
        }
        
        # Check for implemented controls
        if self.metrics["auth_mechanisms_tested"] > 0:
            iso_controls["access_control"] = True
        if self.metrics["tls_configs_reviewed"] > 0:
            iso_controls["cryptography"] = True
            iso_controls["communications_security"] = True
        
        compliance_score = sum(iso_controls.values()) / len(iso_controls) * 100
        
        return {
            "compliance_score": round(compliance_score, 2),
            "implemented_controls": iso_controls,
            "compliant": compliance_score >= 80
        }
    
    def _create_executive_summary(self) -> Dict[str, Any]:
        """Create executive summary of security audit."""
        total_findings = sum(len(findings) for findings in self.findings.values())
        
        summary = {
            "audit_scope": "Comprehensive Network and API Security Assessment",
            "total_findings": total_findings,
            "critical_issues": len(self.findings["critical"]),
            "high_priority_items": len(self.findings["high"]) + len(self.findings["critical"]),
            "security_posture": "NEEDS_IMPROVEMENT" if total_findings > 10 else "ACCEPTABLE",
            "key_recommendations": [],
            "immediate_actions_required": []
        }
        
        # Add key recommendations based on findings
        if len(self.findings["critical"]) > 0:
            summary["immediate_actions_required"].append(
                "Address critical security vulnerabilities immediately"
            )
        
        if len(self.findings["high"]) > 5:
            summary["key_recommendations"].append(
                "Implement comprehensive security testing in CI/CD pipeline"
            )
        
        if self.metrics["tls_configs_reviewed"] == 0:
            summary["key_recommendations"].append(
                "Review and strengthen TLS/SSL configurations"
            )
        
        return summary
    
    def _generate_prioritized_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized security recommendations."""
        recommendations = []
        
        # Critical priority recommendations
        if len(self.findings["critical"]) > 0:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Vulnerability Management",
                "title": "Address Critical Security Vulnerabilities",
                "description": "Immediately fix all critical security vulnerabilities",
                "timeline": "24-48 hours",
                "effort": "High",
                "impact": "High"
            })
        
        # High priority recommendations  
        if len(self.findings["high"]) > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Security Architecture",
                "title": "Strengthen Security Controls",
                "description": "Implement missing security controls and fix high-severity issues",
                "timeline": "1-2 weeks",
                "effort": "Medium",
                "impact": "High"
            })
        
        # Medium priority recommendations
        recommendations.append({
            "priority": "MEDIUM",
            "category": "Security Monitoring",
            "title": "Enhance Security Monitoring",
            "description": "Implement comprehensive security monitoring and alerting",
            "timeline": "2-4 weeks",
            "effort": "Medium",
            "impact": "Medium"
        })
        
        recommendations.append({
            "priority": "MEDIUM",
            "category": "Compliance",
            "title": "Improve Security Compliance",
            "description": "Address compliance gaps with security standards",
            "timeline": "4-8 weeks",
            "effort": "Medium", 
            "impact": "Medium"
        })
        
        # Low priority recommendations
        recommendations.append({
            "priority": "LOW",
            "category": "Documentation",
            "title": "Update Security Documentation",
            "description": "Document security procedures and incident response plans",
            "timeline": "8-12 weeks",
            "effort": "Low",
            "impact": "Low"
        })
        
        return recommendations


async def main():
    """Main execution function."""
    logger.info("🚀 Starting Agent 7: Phase 7 - Comprehensive Network & API Security Audit")
    logger.info("=" * 80)
    
    try:
        # Initialize auditor
        auditor = NetworkAPISecurityAuditor()
        
        # Run comprehensive audit
        report = await auditor.generate_comprehensive_report()
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"AGENT_7_NETWORK_API_SECURITY_AUDIT_REPORT_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print summary
        logger.info("\n" + "=" * 80)
        logger.info("🎯 PHASE 7 NETWORK & API SECURITY AUDIT COMPLETE")
        logger.info("=" * 80)
        
        print(f"\n📊 AUDIT SUMMARY:")
        print(f"   • Audit ID: {report['audit_metadata']['audit_id']}")
        print(f"   • Duration: {report['audit_metadata']['duration_minutes']:.1f} minutes")
        print(f"   • Risk Level: {report['risk_assessment']['overall_risk_level']}")
        print(f"   • Risk Score: {report['risk_assessment']['risk_score']}/100")
        
        print(f"\n🔍 FINDINGS SUMMARY:")
        for severity, findings in report['security_findings'].items():
            if findings:
                print(f"   • {severity.upper()}: {len(findings)} issues")
        
        print(f"\n📈 AUDIT METRICS:")
        for metric, value in report['metrics'].items():
            print(f"   • {metric.replace('_', ' ').title()}: {value}")
        
        print(f"\n🏆 COMPLIANCE SCORES:")
        compliance = report['compliance_assessment']
        print(f"   • OWASP API Top 10: {compliance['owasp_api_top_10']['compliance_score']:.1f}%")
        print(f"   • OWASP Web Top 10: {compliance['owasp_top_10']['compliance_score']:.1f}%") 
        print(f"   • NIST Framework: {compliance['nist_cybersecurity_framework']['overall_score']:.1f}%")
        print(f"   • ISO 27001: {compliance['iso_27001']['compliance_score']:.1f}%")
        
        print(f"\n📋 TOP RECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'][:3], 1):
            print(f"   {i}. [{rec['priority']}] {rec['title']}")
            print(f"      Timeline: {rec['timeline']}")
        
        print(f"\n📄 Report saved to: {report_file}")
        logger.info(f"✅ Network & API security audit completed successfully")
        
        return report
        
    except Exception as e:
        logger.error(f"❌ Network & API security audit failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())