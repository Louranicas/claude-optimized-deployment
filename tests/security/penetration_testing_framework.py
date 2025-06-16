#!/usr/bin/env python3
"""
Automated Penetration Testing Framework
WARNING: This framework is for security testing of your own systems only.
Never use against systems you don't own or have explicit permission to test.
"""

import asyncio
import json
import logging
import subprocess
import time
import socket
import ssl
import requests
import random
import string
import re
import os
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urljoin, urlparse
import concurrent.futures
from contextlib import contextmanager
import tempfile

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class PenetrationTestResult:
    """Penetration test result data structure"""
    test_id: str
    test_name: str
    category: str
    target: str
    vulnerability_found: bool
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    evidence: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    cve_references: Optional[List[str]] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()

@dataclass
class TestTarget:
    """Target configuration for penetration testing"""
    name: str
    host: str
    ports: List[int]
    protocols: List[str]  # http, https, ssh, etc.
    test_categories: List[str]
    credentials: Optional[Dict[str, str]] = None
    custom_payloads: Optional[List[str]] = None

class PenetrationTestingConfig:
    """Configuration for penetration testing framework"""
    
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load penetration testing configuration"""
        default_config = {
            "general": {
                "max_threads": 10,
                "timeout": 30,
                "user_agent": "PenTest-Framework/1.0",
                "rate_limit": 1.0,  # seconds between requests
                "max_redirects": 5
            },
            "network_scanning": {
                "enabled": True,
                "port_scan_timeout": 5,
                "service_detection": True,
                "version_detection": False  # Disabled to avoid being too aggressive
            },
            "web_application": {
                "enabled": True,
                "sql_injection_tests": True,
                "xss_tests": True,
                "directory_traversal": True,
                "command_injection": True,
                "file_upload_tests": False,  # Disabled by default
                "authentication_bypass": True,
                "session_management": True,
                "cors_misconfiguration": True
            },
            "authentication": {
                "brute_force_enabled": False,  # Disabled by default to avoid lockouts
                "default_credentials": True,
                "weak_passwords": ["admin", "password", "123456", "test"],
                "password_policy_check": True
            },
            "ssl_tls": {
                "enabled": True,
                "check_certificate": True,
                "check_protocols": True,
                "check_ciphers": True,
                "check_heartbleed": False  # Disabled to avoid potential issues
            },
            "api_testing": {
                "enabled": True,
                "rest_api_tests": True,
                "graphql_tests": False,
                "soap_tests": False,
                "api_versioning": True,
                "rate_limiting": True
            },
            "reporting": {
                "detailed_output": True,
                "include_false_positives": False,
                "severity_threshold": "LOW",
                "export_formats": ["json", "html"]
            }
        }
        
        if config_file and os.path.exists(config_file):
            import yaml
            with open(config_file, 'r') as f:
                file_config = yaml.safe_load(f)
                self._deep_update(default_config, file_config)
        
        return default_config
    
    def _deep_update(self, base_dict: Dict, update_dict: Dict):
        """Deep update dictionary"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

class NetworkScanner:
    """Network scanning and service enumeration"""
    
    def __init__(self, config: PenetrationTestingConfig):
        self.config = config.config["network_scanning"]
        self.general_config = config.config["general"]
    
    async def scan_target(self, target: TestTarget) -> List[PenetrationTestResult]:
        """Scan target for open ports and services"""
        results = []
        
        if not self.config["enabled"]:
            return results
        
        # Port scanning
        open_ports = await self._scan_ports(target.host, target.ports)
        
        for port in open_ports:
            # Service detection
            service_info = await self._detect_service(target.host, port)
            
            results.append(PenetrationTestResult(
                test_id=f"port_scan_{target.host}_{port}",
                test_name="Open Port Detection",
                category="network_scanning",
                target=f"{target.host}:{port}",
                vulnerability_found=True,
                severity="INFO",
                description=f"Open port detected: {port}",
                evidence={
                    "port": port,
                    "service": service_info.get("service", "unknown"),
                    "version": service_info.get("version", "unknown"),
                    "banner": service_info.get("banner", "")
                },
                remediation="Review if this service should be exposed and ensure it's properly secured"
            ))
        
        return results
    
    async def _scan_ports(self, host: str, ports: List[int]) -> List[int]:
        """Scan for open ports"""
        open_ports = []
        timeout = self.config["port_scan_timeout"]
        
        async def scan_port(port: int) -> bool:
            try:
                # Create connection with timeout
                future = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(future, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return True
            except:
                return False
        
        # Scan ports concurrently with rate limiting
        semaphore = asyncio.Semaphore(self.general_config["max_threads"])
        
        async def scan_with_semaphore(port: int):
            async with semaphore:
                if await scan_port(port):
                    open_ports.append(port)
                await asyncio.sleep(0.1)  # Small delay to avoid overwhelming target
        
        tasks = [scan_with_semaphore(port) for port in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return sorted(open_ports)
    
    async def _detect_service(self, host: str, port: int) -> Dict[str, str]:
        """Detect service running on port"""
        service_info = {"service": "unknown", "version": "unknown", "banner": ""}
        
        if not self.config["service_detection"]:
            return service_info
        
        try:
            # Try to grab banner
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            
            # Send a generic request and read response
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=3)
            banner = response.decode('utf-8', errors='ignore').strip()
            
            writer.close()
            await writer.wait_closed()
            
            service_info["banner"] = banner
            
            # Basic service detection based on port and banner
            if port == 22:
                service_info["service"] = "ssh"
            elif port in [80, 8080]:
                service_info["service"] = "http"
            elif port in [443, 8443]:
                service_info["service"] = "https"
            elif port == 21:
                service_info["service"] = "ftp"
            elif port == 25:
                service_info["service"] = "smtp"
            elif "SSH" in banner:
                service_info["service"] = "ssh"
            elif "HTTP" in banner:
                service_info["service"] = "http"
            
        except Exception as e:
            logger.debug(f"Service detection failed for {host}:{port}: {e}")
        
        return service_info

class WebApplicationTester:
    """Web application security testing"""
    
    def __init__(self, config: PenetrationTestingConfig):
        self.config = config.config["web_application"]
        self.general_config = config.config["general"]
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.general_config["user_agent"]
        })
    
    async def test_web_application(self, target: TestTarget) -> List[PenetrationTestResult]:
        """Test web application for common vulnerabilities"""
        results = []
        
        if not self.config["enabled"]:
            return results
        
        # Determine base URLs
        base_urls = []
        for protocol in target.protocols:
            if protocol in ["http", "https"]:
                for port in target.ports:
                    if (protocol == "http" and port in [80, 8080]) or \
                       (protocol == "https" and port in [443, 8443]):
                        base_url = f"{protocol}://{target.host}:{port}"
                        base_urls.append(base_url)
        
        for base_url in base_urls:
            # Test each vulnerability category
            if self.config["sql_injection_tests"]:
                sql_results = await self._test_sql_injection(base_url)
                results.extend(sql_results)
            
            if self.config["xss_tests"]:
                xss_results = await self._test_xss(base_url)
                results.extend(xss_results)
            
            if self.config["directory_traversal"]:
                traversal_results = await self._test_directory_traversal(base_url)
                results.extend(traversal_results)
            
            if self.config["command_injection"]:
                command_results = await self._test_command_injection(base_url)
                results.extend(command_results)
            
            if self.config["authentication_bypass"]:
                auth_results = await self._test_authentication_bypass(base_url)
                results.extend(auth_results)
            
            if self.config["cors_misconfiguration"]:
                cors_results = await self._test_cors_misconfiguration(base_url)
                results.extend(cors_results)
        
        return results
    
    async def _test_sql_injection(self, base_url: str) -> List[PenetrationTestResult]:
        """Test for SQL injection vulnerabilities"""
        results = []
        
        # Common SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT 1,2,3--",
            "admin'--",
            "' OR 1=1#",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        ]
        
        # Common parameters to test
        test_params = ["id", "user", "username", "email", "search", "q", "name"]
        
        for param in test_params:
            for payload in payloads:
                try:
                    # Test GET parameter
                    test_url = f"{base_url}/?{param}={payload}"
                    response = await self._make_request("GET", test_url)
                    
                    if self._detect_sql_error(response.text if response else ""):
                        results.append(PenetrationTestResult(
                            test_id=f"sql_injection_{base_url}_{param}",
                            test_name="SQL Injection",
                            category="web_application",
                            target=test_url,
                            vulnerability_found=True,
                            severity="HIGH",
                            description=f"SQL injection vulnerability detected in parameter '{param}'",
                            evidence={
                                "parameter": param,
                                "payload": payload,
                                "response_snippet": response.text[:500] if response else ""
                            },
                            remediation="Use parameterized queries and input validation",
                            cve_references=["CWE-89"]
                        ))
                
                except Exception as e:
                    logger.debug(f"SQL injection test failed: {e}")
                
                # Rate limiting
                await asyncio.sleep(self.general_config["rate_limit"])
        
        return results
    
    async def _test_xss(self, base_url: str) -> List[PenetrationTestResult]:
        """Test for Cross-Site Scripting vulnerabilities"""
        results = []
        
        # XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]
        
        test_params = ["search", "q", "query", "input", "comment", "message"]
        
        for param in test_params:
            for payload in payloads:
                try:
                    # Test reflected XSS
                    test_url = f"{base_url}/?{param}={payload}"
                    response = await self._make_request("GET", test_url)
                    
                    if response and payload in response.text:
                        results.append(PenetrationTestResult(
                            test_id=f"xss_reflected_{base_url}_{param}",
                            test_name="Reflected XSS",
                            category="web_application",
                            target=test_url,
                            vulnerability_found=True,
                            severity="MEDIUM",
                            description=f"Reflected XSS vulnerability in parameter '{param}'",
                            evidence={
                                "parameter": param,
                                "payload": payload,
                                "reflected_in_response": True
                            },
                            remediation="Implement proper output encoding and Content Security Policy",
                            cve_references=["CWE-79"]
                        ))
                
                except Exception as e:
                    logger.debug(f"XSS test failed: {e}")
                
                await asyncio.sleep(self.general_config["rate_limit"])
        
        return results
    
    async def _test_directory_traversal(self, base_url: str) -> List[PenetrationTestResult]:
        """Test for directory traversal vulnerabilities"""
        results = []
        
        # Directory traversal payloads
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        test_params = ["file", "path", "page", "include", "template", "doc"]
        
        for param in test_params:
            for payload in payloads:
                try:
                    test_url = f"{base_url}/?{param}={payload}"
                    response = await self._make_request("GET", test_url)
                    
                    if response and self._detect_directory_traversal(response.text):
                        results.append(PenetrationTestResult(
                            test_id=f"directory_traversal_{base_url}_{param}",
                            test_name="Directory Traversal",
                            category="web_application",
                            target=test_url,
                            vulnerability_found=True,
                            severity="HIGH",
                            description=f"Directory traversal vulnerability in parameter '{param}'",
                            evidence={
                                "parameter": param,
                                "payload": payload,
                                "system_file_accessed": True
                            },
                            remediation="Implement proper input validation and file access controls",
                            cve_references=["CWE-22"]
                        ))
                
                except Exception as e:
                    logger.debug(f"Directory traversal test failed: {e}")
                
                await asyncio.sleep(self.general_config["rate_limit"])
        
        return results
    
    async def _test_command_injection(self, base_url: str) -> List[PenetrationTestResult]:
        """Test for command injection vulnerabilities"""
        results = []
        
        # Command injection payloads
        payloads = [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`",
            "$(uname -a)",
            "; ping -c 1 127.0.0.1"
        ]
        
        test_params = ["cmd", "command", "exec", "system", "ping", "host"]
        
        for param in test_params:
            for payload in payloads:
                try:
                    test_url = f"{base_url}/?{param}={payload}"
                    response = await self._make_request("GET", test_url)
                    
                    if response and self._detect_command_output(response.text):
                        results.append(PenetrationTestResult(
                            test_id=f"command_injection_{base_url}_{param}",
                            test_name="Command Injection",
                            category="web_application",
                            target=test_url,
                            vulnerability_found=True,
                            severity="CRITICAL",
                            description=f"Command injection vulnerability in parameter '{param}'",
                            evidence={
                                "parameter": param,
                                "payload": payload,
                                "command_output_detected": True
                            },
                            remediation="Never execute user input as system commands; use safe APIs",
                            cve_references=["CWE-78"]
                        ))
                
                except Exception as e:
                    logger.debug(f"Command injection test failed: {e}")
                
                await asyncio.sleep(self.general_config["rate_limit"])
        
        return results
    
    async def _test_authentication_bypass(self, base_url: str) -> List[PenetrationTestResult]:
        """Test for authentication bypass vulnerabilities"""
        results = []
        
        # Common authentication bypass techniques
        bypass_attempts = [
            {"path": "/admin", "description": "Direct admin access"},
            {"path": "/admin/", "description": "Admin with trailing slash"},
            {"path": "//admin", "description": "Double slash bypass"},
            {"path": "/admin%2e", "description": "URL encoding bypass"},
            {"path": "/admin/../admin", "description": "Path traversal bypass"},
        ]
        
        for attempt in bypass_attempts:
            try:
                test_url = urljoin(base_url, attempt["path"])
                response = await self._make_request("GET", test_url)
                
                if response and response.status_code == 200:
                    # Check if we got an admin interface without authentication
                    if self._detect_admin_interface(response.text):
                        results.append(PenetrationTestResult(
                            test_id=f"auth_bypass_{base_url}_{attempt['path']}",
                            test_name="Authentication Bypass",
                            category="web_application",
                            target=test_url,
                            vulnerability_found=True,
                            severity="HIGH",
                            description=f"Authentication bypass: {attempt['description']}",
                            evidence={
                                "bypass_path": attempt["path"],
                                "status_code": response.status_code,
                                "admin_interface_detected": True
                            },
                            remediation="Implement proper access controls and authentication checks",
                            cve_references=["CWE-862"]
                        ))
            
            except Exception as e:
                logger.debug(f"Authentication bypass test failed: {e}")
            
            await asyncio.sleep(self.general_config["rate_limit"])
        
        return results
    
    async def _test_cors_misconfiguration(self, base_url: str) -> List[PenetrationTestResult]:
        """Test for CORS misconfigurations"""
        results = []
        
        try:
            # Test with malicious origin
            headers = {"Origin": "https://evil.com"}
            response = await self._make_request("GET", base_url, headers=headers)
            
            if response:
                cors_header = response.headers.get("Access-Control-Allow-Origin", "")
                if cors_header == "*" or "evil.com" in cors_header:
                    results.append(PenetrationTestResult(
                        test_id=f"cors_misconfiguration_{base_url}",
                        test_name="CORS Misconfiguration",
                        category="web_application",
                        target=base_url,
                        vulnerability_found=True,
                        severity="MEDIUM",
                        description="CORS policy allows requests from arbitrary origins",
                        evidence={
                            "access_control_allow_origin": cors_header,
                            "malicious_origin_allowed": True
                        },
                        remediation="Configure CORS to only allow trusted origins",
                        cve_references=["CWE-942"]
                    ))
        
        except Exception as e:
            logger.debug(f"CORS test failed: {e}")
        
        return results
    
    async def _make_request(self, method: str, url: str, headers: Dict[str, str] = None, 
                           data: Dict[str, str] = None) -> Optional[requests.Response]:
        """Make HTTP request with proper error handling"""
        try:
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    self.session.request,
                    method, url,
                    headers=headers,
                    data=data,
                    timeout=self.general_config["timeout"],
                    allow_redirects=True,
                    verify=False  # For testing purposes
                )
                response = await loop.run_in_executor(None, lambda: future.result())
                return response
        except Exception as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None
    
    def _detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL error messages in response"""
        sql_errors = [
            "sql syntax error",
            "mysql_fetch_array",
            "ora-01756",
            "microsoft ole db provider",
            "unclosed quotation mark",
            "syntax error or access violation"
        ]
        
        response_lower = response_text.lower()
        return any(error in response_lower for error in sql_errors)
    
    def _detect_directory_traversal(self, response_text: str) -> bool:
        """Detect successful directory traversal"""
        indicators = [
            "root:x:0:0:",  # /etc/passwd content
            "[boot loader]",  # Windows boot.ini
            "127.0.0.1",  # hosts file
            "# localhost"
        ]
        
        return any(indicator in response_text for indicator in indicators)
    
    def _detect_command_output(self, response_text: str) -> bool:
        """Detect command execution output"""
        indicators = [
            "uid=", "gid=",  # id command output
            "Linux", "Windows NT",  # uname output
            "bin/bash", "bin/sh",  # shell paths
            "PING ", "ping statistics"  # ping output
        ]
        
        return any(indicator in response_text for indicator in indicators)
    
    def _detect_admin_interface(self, response_text: str) -> bool:
        """Detect admin interface in response"""
        indicators = [
            "admin panel", "administration",
            "dashboard", "control panel",
            "user management", "system settings"
        ]
        
        response_lower = response_text.lower()
        return any(indicator in response_lower for indicator in indicators)

class SSLTLSTester:
    """SSL/TLS security testing"""
    
    def __init__(self, config: PenetrationTestingConfig):
        self.config = config.config["ssl_tls"]
    
    async def test_ssl_tls(self, target: TestTarget) -> List[PenetrationTestResult]:
        """Test SSL/TLS configuration"""
        results = []
        
        if not self.config["enabled"]:
            return results
        
        # Test HTTPS ports
        https_ports = [port for port in target.ports if port in [443, 8443]]
        
        for port in https_ports:
            if self.config["check_certificate"]:
                cert_results = await self._test_certificate(target.host, port)
                results.extend(cert_results)
            
            if self.config["check_protocols"]:
                protocol_results = await self._test_protocols(target.host, port)
                results.extend(protocol_results)
            
            if self.config["check_ciphers"]:
                cipher_results = await self._test_ciphers(target.host, port)
                results.extend(cipher_results)
        
        return results
    
    async def _test_certificate(self, host: str, port: int) -> List[PenetrationTestResult]:
        """Test SSL certificate"""
        results = []
        
        try:
            # Get certificate information
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    
                    # Check certificate expiration
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.datetime.now()).days
                    
                    if days_until_expiry < 30:
                        severity = "HIGH" if days_until_expiry < 7 else "MEDIUM"
                        results.append(PenetrationTestResult(
                            test_id=f"ssl_cert_expiry_{host}_{port}",
                            test_name="SSL Certificate Expiry",
                            category="ssl_tls",
                            target=f"{host}:{port}",
                            vulnerability_found=True,
                            severity=severity,
                            description=f"SSL certificate expires in {days_until_expiry} days",
                            evidence={
                                "expiry_date": cert['notAfter'],
                                "days_until_expiry": days_until_expiry
                            },
                            remediation="Renew SSL certificate before expiration"
                        ))
                    
                    # Check for self-signed certificates
                    if cert.get('issuer') == cert.get('subject'):
                        results.append(PenetrationTestResult(
                            test_id=f"ssl_self_signed_{host}_{port}",
                            test_name="Self-Signed Certificate",
                            category="ssl_tls",
                            target=f"{host}:{port}",
                            vulnerability_found=True,
                            severity="MEDIUM",
                            description="Self-signed SSL certificate detected",
                            evidence={"issuer": str(cert.get('issuer'))},
                            remediation="Use a certificate from a trusted CA"
                        ))
        
        except Exception as e:
            logger.debug(f"Certificate test failed for {host}:{port}: {e}")
        
        return results
    
    async def _test_protocols(self, host: str, port: int) -> List[PenetrationTestResult]:
        """Test SSL/TLS protocol versions"""
        results = []
        
        # Test for weak protocols
        weak_protocols = [
            (ssl.PROTOCOL_SSLv23, "SSLv2/v3"),
            (ssl.PROTOCOL_TLSv1, "TLSv1.0"),
            (ssl.PROTOCOL_TLSv1_1, "TLSv1.1")
        ]
        
        for protocol, name in weak_protocols:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock) as ssock:
                        # If connection succeeds, weak protocol is supported
                        results.append(PenetrationTestResult(
                            test_id=f"ssl_weak_protocol_{host}_{port}_{name}",
                            test_name="Weak SSL/TLS Protocol",
                            category="ssl_tls",
                            target=f"{host}:{port}",
                            vulnerability_found=True,
                            severity="HIGH",
                            description=f"Weak SSL/TLS protocol {name} is supported",
                            evidence={"protocol": name},
                            remediation="Disable weak SSL/TLS protocols and use TLS 1.2 or higher"
                        ))
            
            except Exception:
                # Connection failed, which is good - protocol not supported
                pass
        
        return results
    
    async def _test_ciphers(self, host: str, port: int) -> List[PenetrationTestResult]:
        """Test SSL/TLS cipher suites"""
        results = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    
                    if cipher:
                        cipher_name = cipher[0]
                        
                        # Check for weak ciphers
                        weak_ciphers = ["RC4", "DES", "MD5", "NULL"]
                        
                        for weak in weak_ciphers:
                            if weak in cipher_name:
                                results.append(PenetrationTestResult(
                                    test_id=f"ssl_weak_cipher_{host}_{port}",
                                    test_name="Weak SSL/TLS Cipher",
                                    category="ssl_tls",
                                    target=f"{host}:{port}",
                                    vulnerability_found=True,
                                    severity="MEDIUM",
                                    description=f"Weak cipher suite detected: {cipher_name}",
                                    evidence={"cipher": cipher_name},
                                    remediation="Configure strong cipher suites only"
                                ))
                                break
        
        except Exception as e:
            logger.debug(f"Cipher test failed for {host}:{port}: {e}")
        
        return results

class PenetrationTestingFramework:
    """Main penetration testing framework"""
    
    def __init__(self, config_file: str = None):
        self.config = PenetrationTestingConfig(config_file)
        self.network_scanner = NetworkScanner(self.config)
        self.web_tester = WebApplicationTester(self.config)
        self.ssl_tester = SSLTLSTester(self.config)
        self.results: List[PenetrationTestResult] = []
    
    async def run_penetration_test(self, targets: List[TestTarget]) -> Dict[str, Any]:
        """Run comprehensive penetration test"""
        logger.info("Starting penetration testing framework")
        start_time = time.time()
        
        for target in targets:
            logger.info(f"Testing target: {target.name} ({target.host})")
            
            # Network scanning
            network_results = await self.network_scanner.scan_target(target)
            self.results.extend(network_results)
            
            # Web application testing
            if "web" in target.test_categories:
                web_results = await self.web_tester.test_web_application(target)
                self.results.extend(web_results)
            
            # SSL/TLS testing
            if "ssl" in target.test_categories:
                ssl_results = await self.ssl_tester.test_ssl_tls(target)
                self.results.extend(ssl_results)
        
        execution_time = time.time() - start_time
        
        # Generate report
        report = self._generate_report(targets, execution_time)
        
        logger.info(f"Penetration testing completed in {execution_time:.2f} seconds")
        return report
    
    def _generate_report(self, targets: List[TestTarget], execution_time: float) -> Dict[str, Any]:
        """Generate penetration testing report"""
        
        # Categorize results
        vulnerabilities_by_severity = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": []
        }
        
        vulnerabilities_by_category = {}
        
        for result in self.results:
            if result.vulnerability_found:
                vulnerabilities_by_severity[result.severity].append(result)
                
                if result.category not in vulnerabilities_by_category:
                    vulnerabilities_by_category[result.category] = []
                vulnerabilities_by_category[result.category].append(result)
        
        # Calculate risk score
        risk_score = (
            len(vulnerabilities_by_severity["CRITICAL"]) * 10 +
            len(vulnerabilities_by_severity["HIGH"]) * 7 +
            len(vulnerabilities_by_severity["MEDIUM"]) * 4 +
            len(vulnerabilities_by_severity["LOW"]) * 1
        )
        
        # Determine overall risk level
        if len(vulnerabilities_by_severity["CRITICAL"]) > 0:
            risk_level = "CRITICAL"
        elif len(vulnerabilities_by_severity["HIGH"]) > 0:
            risk_level = "HIGH"
        elif len(vulnerabilities_by_severity["MEDIUM"]) > 2:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        report = {
            "metadata": {
                "framework_version": "1.0.0",
                "test_timestamp": datetime.now(timezone.utc).isoformat(),
                "execution_time_seconds": execution_time,
                "targets_tested": len(targets),
                "total_tests": len(self.results)
            },
            "executive_summary": {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "total_vulnerabilities": sum(len(vulns) for vulns in vulnerabilities_by_severity.values()),
                "critical_vulnerabilities": len(vulnerabilities_by_severity["CRITICAL"]),
                "high_vulnerabilities": len(vulnerabilities_by_severity["HIGH"]),
                "medium_vulnerabilities": len(vulnerabilities_by_severity["MEDIUM"]),
                "low_vulnerabilities": len(vulnerabilities_by_severity["LOW"])
            },
            "targets": [
                {
                    "name": target.name,
                    "host": target.host,
                    "ports": target.ports,
                    "test_categories": target.test_categories
                }
                for target in targets
            ],
            "vulnerabilities_by_severity": {
                severity: [asdict(vuln) for vuln in vulns]
                for severity, vulns in vulnerabilities_by_severity.items()
            },
            "vulnerabilities_by_category": {
                category: [asdict(vuln) for vuln in vulns]
                for category, vulns in vulnerabilities_by_category.items()
            },
            "recommendations": self._generate_recommendations(vulnerabilities_by_severity),
            "remediation_priorities": self._generate_remediation_priorities(vulnerabilities_by_severity)
        }
        
        return report
    
    def _generate_recommendations(self, vulnerabilities_by_severity: Dict[str, List]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if vulnerabilities_by_severity["CRITICAL"]:
            recommendations.append("IMMEDIATE ACTION REQUIRED: Address critical vulnerabilities immediately")
        
        if vulnerabilities_by_severity["HIGH"]:
            recommendations.append("HIGH PRIORITY: Fix high-severity vulnerabilities within 24-48 hours")
        
        if vulnerabilities_by_severity["MEDIUM"]:
            recommendations.append("Schedule fixes for medium-severity vulnerabilities within 1-2 weeks")
        
        # Category-specific recommendations
        categories = set()
        for severity_vulns in vulnerabilities_by_severity.values():
            for vuln in severity_vulns:
                categories.add(vuln.category)
        
        if "web_application" in categories:
            recommendations.append("Implement secure coding practices and input validation")
        
        if "ssl_tls" in categories:
            recommendations.append("Update SSL/TLS configuration and certificates")
        
        if "network_scanning" in categories:
            recommendations.append("Review network exposure and implement proper firewall rules")
        
        return recommendations
    
    def _generate_remediation_priorities(self, vulnerabilities_by_severity: Dict[str, List]) -> List[Dict[str, str]]:
        """Generate remediation priorities"""
        priorities = []
        
        # Critical vulnerabilities first
        for vuln in vulnerabilities_by_severity["CRITICAL"]:
            priorities.append({
                "priority": "1 - CRITICAL",
                "vulnerability": vuln.test_name,
                "target": vuln.target,
                "remediation": vuln.remediation or "Immediate remediation required"
            })
        
        # High vulnerabilities second
        for vuln in vulnerabilities_by_severity["HIGH"][:5]:  # Top 5 high-severity
            priorities.append({
                "priority": "2 - HIGH",
                "vulnerability": vuln.test_name,
                "target": vuln.target,
                "remediation": vuln.remediation or "High priority remediation"
            })
        
        return priorities
    
    async def save_report(self, report: Dict[str, Any], output_dir: str = "pentest_reports"):
        """Save penetration testing report"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON report
        json_path = output_path / f"pentest_report_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # HTML report
        html_path = output_path / f"pentest_report_{timestamp}.html"
        await self._generate_html_report(report, html_path)
        
        logger.info(f"Penetration testing reports saved to {output_path}")
    
    async def _generate_html_report(self, report: Dict[str, Any], output_path: Path):
        """Generate HTML penetration testing report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Penetration Testing Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; font-weight: bold; }}
        .low {{ color: #28a745; }}
        .summary {{ margin: 20px 0; padding: 15px; background-color: #f1f3f4; border-radius: 5px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .vuln-details {{ margin: 10px 0; padding: 10px; border-left: 4px solid #007bff; background-color: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Penetration Testing Report</h1>
        <p><strong>Generated:</strong> {report['metadata']['test_timestamp']}</p>
        <p><strong>Execution Time:</strong> {report['metadata']['execution_time_seconds']:.2f} seconds</p>
        <p><strong>Targets Tested:</strong> {report['metadata']['targets_tested']}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Overall Risk Level:</strong> <span class="{report['executive_summary']['risk_level'].lower()}">{report['executive_summary']['risk_level']}</span></p>
        <p><strong>Risk Score:</strong> {report['executive_summary']['risk_score']}</p>
        
        <h3>Vulnerability Breakdown</h3>
        <ul>
            <li class="critical">Critical: {report['executive_summary']['critical_vulnerabilities']}</li>
            <li class="high">High: {report['executive_summary']['high_vulnerabilities']}</li>
            <li class="medium">Medium: {report['executive_summary']['medium_vulnerabilities']}</li>
            <li class="low">Low: {report['executive_summary']['low_vulnerabilities']}</li>
        </ul>
    </div>
    
    <h2>📋 Recommendations</h2>
    <ul>
        {"".join(f"<li>{rec}</li>" for rec in report['recommendations'])}
    </ul>
    
    <h2>🎯 Remediation Priorities</h2>
    <table>
        <tr>
            <th>Priority</th>
            <th>Vulnerability</th>
            <th>Target</th>
            <th>Remediation</th>
        </tr>
        {"".join(f'''
        <tr>
            <td>{priority['priority']}</td>
            <td>{priority['vulnerability']}</td>
            <td>{priority['target']}</td>
            <td>{priority['remediation']}</td>
        </tr>
        ''' for priority in report['remediation_priorities'])}
    </table>
    
    <h2>🔍 Detailed Vulnerabilities</h2>
    <!-- Detailed vulnerability information would be added here -->
    
    <div style="margin-top: 50px; padding: 20px; background-color: #fff3cd; border-radius: 5px;">
        <h3>⚠️ Disclaimer</h3>
        <p>This penetration testing report is for authorized security testing purposes only. 
        All tests were conducted on systems owned or explicitly authorized for testing. 
        Unauthorized testing of systems is illegal and unethical.</p>
    </div>
    
</body>
</html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)

# Example usage and main function
async def main():
    """Main function for penetration testing framework"""
    
    # Example target configuration
    targets = [
        TestTarget(
            name="Local Test Server",
            host="127.0.0.1",
            ports=[80, 443, 8080],
            protocols=["http", "https"],
            test_categories=["web", "ssl"]
        )
    ]
    
    # WARNING: Only test systems you own or have explicit permission to test
    print("⚠️  WARNING: Only use this framework on systems you own or have explicit permission to test!")
    print("   Unauthorized penetration testing is illegal and unethical.")
    
    response = input("Do you confirm you have authorization to test the configured targets? (yes/no): ")
    if response.lower() != "yes":
        print("Testing aborted. Only test authorized systems.")
        return
    
    # Initialize and run framework
    framework = PenetrationTestingFramework()
    report = await framework.run_penetration_test(targets)
    
    # Save report
    await framework.save_report(report)
    
    print(f"\n🔍 Penetration Testing Complete!")
    print(f"Risk Level: {report['executive_summary']['risk_level']}")
    print(f"Total Vulnerabilities: {report['executive_summary']['total_vulnerabilities']}")
    print(f"Critical: {report['executive_summary']['critical_vulnerabilities']}")
    print(f"High: {report['executive_summary']['high_vulnerabilities']}")

if __name__ == "__main__":
    asyncio.run(main())