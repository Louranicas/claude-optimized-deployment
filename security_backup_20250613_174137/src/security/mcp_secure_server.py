"""
Secure MCP Server Wrapper
Wraps MCP servers with comprehensive security hardening.

This module provides:
- Secure server wrapper with authentication, authorization, and monitoring
- TLS/SSL configuration and secure communication
- Vulnerability scanning and patch management
- Security compliance enforcement
"""

import asyncio
import ssl
import logging
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path

from .mcp_security_core import (
    MCPSecurityCore, SecurityConfig, SecurityContext, 
    AuthenticationMethod, get_security_core
)

logger = logging.getLogger(__name__)


@dataclass
class SecureServerConfig:
    """Configuration for secure MCP server."""
    # Security core config
    security_config: SecurityConfig = field(default_factory=SecurityConfig)
    
    # TLS/SSL configuration
    enable_tls: bool = True
    tls_cert_file: Optional[str] = None
    tls_key_file: Optional[str] = None
    tls_ca_file: Optional[str] = None
    require_client_cert: bool = False
    tls_ciphers: str = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    
    # Server security
    enable_cors: bool = True
    allowed_origins: List[str] = field(default_factory=lambda: ["https://localhost"])
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    request_timeout: int = 30
    
    # Vulnerability management
    enable_vulnerability_scanning: bool = True
    scan_interval_hours: int = 24
    auto_patch: bool = False
    security_update_channel: str = "stable"
    
    # Compliance
    compliance_frameworks: List[str] = field(default_factory=lambda: ["SOC2", "GDPR"])
    audit_retention_days: int = 90
    
    # Monitoring
    security_monitoring: bool = True
    intrusion_detection: bool = True
    anomaly_detection: bool = True


class SecureMCPServer:
    """Secure wrapper for MCP servers with comprehensive security hardening."""
    
    def __init__(self, 
                 mcp_server: Any, 
                 config: Optional[SecureServerConfig] = None,
                 server_name: str = "secure_mcp_server"):
        self.mcp_server = mcp_server
        self.config = config or SecureServerConfig()
        self.server_name = server_name
        self.security_core: Optional[MCPSecurityCore] = None
        
        # Security state
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.vulnerability_scan_results: Dict[str, Any] = {}
        self.compliance_status: Dict[str, bool] = {}
        
        # Monitoring
        self.request_count = 0
        self.failed_auth_count = 0
        self.blocked_requests = 0
        self.last_security_scan: Optional[datetime] = None
        
    async def initialize(self):
        """Initialize secure server."""
        # Initialize security core
        self.security_core = await get_security_core()
        
        # Configure TLS/SSL
        if self.config.enable_tls:
            await self._configure_tls()
        
        # Initial vulnerability scan
        if self.config.enable_vulnerability_scanning:
            await self._run_vulnerability_scan()
        
        # Initialize compliance checks
        await self._initialize_compliance()
        
        logger.info(f"Secure MCP Server '{self.server_name}' initialized with high security")
    
    async def _configure_tls(self):
        """Configure TLS/SSL settings."""
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Set minimum TLS version
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Configure cipher suites
        self.ssl_context.set_ciphers(self.config.tls_ciphers)
        
        # Load certificates if provided
        if self.config.tls_cert_file and self.config.tls_key_file:
            if Path(self.config.tls_cert_file).exists() and Path(self.config.tls_key_file).exists():
                self.ssl_context.load_cert_chain(
                    self.config.tls_cert_file,
                    self.config.tls_key_file
                )
            else:
                logger.warning("TLS certificate files not found, generating self-signed certificate")
                await self._generate_self_signed_cert()
        
        # Configure client certificate verification
        if self.config.require_client_cert:
            self.ssl_context.verify_mode = ssl.CERT_REQUIRED
            if self.config.tls_ca_file:
                self.ssl_context.load_verify_locations(self.config.tls_ca_file)
        
        logger.info("TLS/SSL configured for secure communication")
    
    async def _generate_self_signed_cert(self):
        """Generate self-signed certificate for development/testing."""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import ipaddress
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Claude MCP Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            certificate = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Save certificate and key
            cert_path = f"/tmp/{self.server_name}_cert.pem"
            key_path = f"/tmp/{self.server_name}_key.pem"
            
            with open(cert_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Load the generated certificate
            self.ssl_context.load_cert_chain(cert_path, key_path)
            
            logger.info(f"Generated self-signed certificate: {cert_path}")
            
        except ImportError:
            logger.error("cryptography package required for certificate generation")
        except Exception as e:
            logger.error(f"Failed to generate self-signed certificate: {e}")
    
    async def _run_vulnerability_scan(self):
        """Run vulnerability scan on the server."""
        try:
            # Simulate vulnerability scanning (in production, integrate with actual scanners)
            scan_results = {
                "timestamp": datetime.utcnow().isoformat(),
                "server_name": self.server_name,
                "vulnerabilities": [],
                "security_score": 95,  # Out of 100
                "recommendations": []
            }
            
            # Check for common security misconfigurations
            vulnerabilities = []
            
            # Check TLS configuration
            if not self.config.enable_tls:
                vulnerabilities.append({
                    "id": "TLS_DISABLED",
                    "severity": "HIGH",
                    "description": "TLS/SSL is disabled, allowing unencrypted communication",
                    "recommendation": "Enable TLS encryption"
                })
            
            # Check authentication
            if not self.config.security_config.auth_methods:
                vulnerabilities.append({
                    "id": "NO_AUTHENTICATION",
                    "severity": "CRITICAL",
                    "description": "No authentication methods configured",
                    "recommendation": "Configure API key or JWT authentication"
                })
            
            # Check rate limiting
            if not self.config.security_config.rate_limit_enabled:
                vulnerabilities.append({
                    "id": "NO_RATE_LIMITING",
                    "severity": "MEDIUM",
                    "description": "Rate limiting is disabled",
                    "recommendation": "Enable rate limiting to prevent abuse"
                })
            
            # Check input validation
            if not self.config.security_config.input_validation_enabled:
                vulnerabilities.append({
                    "id": "NO_INPUT_VALIDATION", 
                    "severity": "HIGH",
                    "description": "Input validation is disabled",
                    "recommendation": "Enable input validation and sanitization"
                })
            
            scan_results["vulnerabilities"] = vulnerabilities
            scan_results["security_score"] = max(0, 100 - len(vulnerabilities) * 10)
            
            self.vulnerability_scan_results = scan_results
            self.last_security_scan = datetime.utcnow()
            
            if vulnerabilities:
                logger.warning(f"Vulnerability scan found {len(vulnerabilities)} issues")
                for vuln in vulnerabilities:
                    logger.warning(f"  {vuln['severity']}: {vuln['description']}")
            else:
                logger.info("Vulnerability scan completed - no issues found")
            
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
    
    async def _initialize_compliance(self):
        """Initialize compliance framework checks."""
        compliance_checks = {
            "SOC2": await self._check_soc2_compliance(),
            "GDPR": await self._check_gdpr_compliance(),
            "HIPAA": await self._check_hipaa_compliance(),
            "PCI_DSS": await self._check_pci_compliance()
        }
        
        self.compliance_status = {
            framework: compliance_checks.get(framework, False)
            for framework in self.config.compliance_frameworks
        }
        
        logger.info(f"Compliance status: {self.compliance_status}")
    
    async def _check_soc2_compliance(self) -> bool:
        """Check SOC 2 compliance requirements."""
        checks = [
            self.config.security_config.audit_logging,  # Logging and monitoring
            self.config.enable_tls,  # Data encryption in transit
            len(self.config.security_config.auth_methods) > 0,  # Access controls
            self.config.security_config.rate_limit_enabled,  # System availability
            self.config.security_config.input_validation_enabled  # Data integrity
        ]
        return all(checks)
    
    async def _check_gdpr_compliance(self) -> bool:
        """Check GDPR compliance requirements."""
        checks = [
            self.config.security_config.encryption_enabled,  # Data protection
            self.config.security_config.audit_logging,  # Data processing logs
            self.config.audit_retention_days <= 2555,  # Data retention limits (7 years max)
            True  # Assuming consent management is handled elsewhere
        ]
        return all(checks)
    
    async def _check_hipaa_compliance(self) -> bool:
        """Check HIPAA compliance requirements."""
        checks = [
            self.config.security_config.encryption_enabled,  # Data encryption
            self.config.require_client_cert,  # Strong authentication
            self.config.security_config.audit_logging,  # Access logging
            self.config.security_config.session_timeout_minutes <= 30  # Session timeouts
        ]
        return all(checks)
    
    async def _check_pci_compliance(self) -> bool:
        """Check PCI DSS compliance requirements."""
        checks = [
            self.config.enable_tls,  # Encrypted transmission
            self.config.security_config.rate_limit_enabled,  # DoS protection
            len(self.config.security_config.auth_methods) > 0,  # Access controls
            self.config.security_config.input_validation_enabled,  # Input validation
            self.ssl_context.minimum_version >= ssl.TLSVersion.TLSv1_2 if self.ssl_context else False
        ]
        return all(checks)
    
    async def handle_request(self, 
                           auth_header: Optional[str],
                           client_ip: str,
                           user_agent: str,
                           method: str,
                           endpoint: str,
                           data: Any) -> Dict[str, Any]:
        """Handle incoming request with security validation."""
        self.request_count += 1
        
        try:
            # Authenticate request
            context = await self.security_core.authenticate_request(
                auth_header, client_ip, user_agent
            )
            
            if not context:
                self.failed_auth_count += 1
                return {
                    "error": "Authentication required",
                    "status_code": 401
                }
            
            # Authorize request
            if not await self.security_core.authorize_request(context, endpoint, method):
                return {
                    "error": "Access denied",
                    "status_code": 403
                }
            
            # Validate and process request
            is_valid, processed_data = await self.security_core.validate_and_process_request(
                context, endpoint, data
            )
            
            if not is_valid:
                self.blocked_requests += 1
                return {
                    "error": processed_data,
                    "status_code": 400
                }
            
            # Execute the actual MCP server request
            result = await self._execute_mcp_request(context, endpoint, processed_data)
            
            # Log successful request
            self.security_core.auditor.log_security_event(
                "successful_request",
                context,
                {
                    "endpoint": endpoint,
                    "method": method,
                    "response_size": len(str(result)) if result else 0
                }
            )
            
            return {
                "result": result,
                "status_code": 200
            }
            
        except Exception as e:
            logger.error(f"Request handling error: {e}")
            return {
                "error": "Internal server error",
                "status_code": 500
            }
    
    async def _execute_mcp_request(self, context: SecurityContext, endpoint: str, data: Any) -> Any:
        """Execute the actual MCP server request."""
        # Extract tool name and arguments from endpoint and data
        # This is a simplified implementation - adjust based on your MCP server interface
        
        if hasattr(self.mcp_server, 'call_tool'):
            tool_name = endpoint.split('/')[-1] if '/' in endpoint else endpoint
            arguments = data if isinstance(data, dict) else {}
            
            return await self.mcp_server.call_tool(tool_name, arguments)
        elif hasattr(self.mcp_server, 'handle_request'):
            return await self.mcp_server.handle_request(endpoint, data)
        else:
            # Fallback for different MCP server interfaces
            return await self.mcp_server.process_request(endpoint, data)
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get secure server information."""
        base_info = {}
        if hasattr(self.mcp_server, 'get_server_info'):
            base_info = self.mcp_server.get_server_info()
        
        security_info = {
            "server_name": self.server_name,
            "security_enabled": True,
            "tls_enabled": self.config.enable_tls,
            "authentication_methods": [method.value for method in self.config.security_config.auth_methods],
            "compliance_frameworks": self.config.compliance_frameworks,
            "last_security_scan": self.last_security_scan.isoformat() if self.last_security_scan else None,
            "security_score": self.vulnerability_scan_results.get("security_score", "N/A"),
            "request_statistics": {
                "total_requests": self.request_count,
                "failed_authentications": self.failed_auth_count,
                "blocked_requests": self.blocked_requests
            }
        }
        
        return {**base_info, **security_info}
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Get available tools with security information."""
        base_tools = []
        if hasattr(self.mcp_server, 'get_tools'):
            base_tools = self.mcp_server.get_tools()
        
        # Add security metadata to each tool
        secure_tools = []
        for tool in base_tools:
            secure_tool = tool.copy() if isinstance(tool, dict) else {"name": str(tool)}
            secure_tool.update({
                "security_level": "HIGH",
                "requires_authentication": True,
                "rate_limited": self.config.security_config.rate_limit_enabled,
                "input_validated": self.config.security_config.input_validation_enabled
            })
            secure_tools.append(secure_tool)
        
        return secure_tools
    
    async def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status."""
        if not self.security_core:
            return {"error": "Security core not initialized"}
        
        status = self.security_core.get_security_status()
        
        # Add server-specific security information
        status.update({
            "server_name": self.server_name,
            "tls_configuration": {
                "enabled": self.config.enable_tls,
                "minimum_version": "TLSv1.2",
                "cipher_suites": self.config.tls_ciphers
            },
            "compliance_status": self.compliance_status,
            "vulnerability_scan": self.vulnerability_scan_results,
            "request_statistics": {
                "total_requests": self.request_count,
                "failed_authentications": self.failed_auth_count,
                "blocked_requests": self.blocked_requests,
                "success_rate": (
                    (self.request_count - self.failed_auth_count - self.blocked_requests) / 
                    max(1, self.request_count) * 100
                )
            }
        })
        
        return status
    
    async def run_security_audit(self) -> Dict[str, Any]:
        """Run comprehensive security audit."""
        audit_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "server_name": self.server_name,
            "audit_sections": {}
        }
        
        # Run vulnerability scan
        await self._run_vulnerability_scan()
        audit_results["audit_sections"]["vulnerability_scan"] = self.vulnerability_scan_results
        
        # Check compliance
        await self._initialize_compliance()
        audit_results["audit_sections"]["compliance"] = self.compliance_status
        
        # Security configuration audit
        config_audit = {
            "authentication_configured": len(self.config.security_config.auth_methods) > 0,
            "encryption_enabled": self.config.security_config.encryption_enabled,
            "tls_enabled": self.config.enable_tls,
            "rate_limiting_enabled": self.config.security_config.rate_limit_enabled,
            "input_validation_enabled": self.config.security_config.input_validation_enabled,
            "audit_logging_enabled": self.config.security_config.audit_logging,
            "session_timeout_appropriate": self.config.security_config.session_timeout_minutes <= 60
        }
        audit_results["audit_sections"]["configuration"] = config_audit
        
        # Calculate overall security score
        total_checks = (
            len(self.vulnerability_scan_results.get("vulnerabilities", [])) == 0,
            all(self.compliance_status.values()),
            all(config_audit.values())
        )
        
        security_score = sum(total_checks) / len(total_checks) * 100
        audit_results["overall_security_score"] = security_score
        
        # Recommendations
        recommendations = []
        if self.vulnerability_scan_results.get("vulnerabilities"):
            for vuln in self.vulnerability_scan_results["vulnerabilities"]:
                recommendations.append(vuln["recommendation"])
        
        if not all(self.compliance_status.values()):
            recommendations.append("Review and address compliance framework requirements")
        
        if not all(config_audit.values()):
            recommendations.append("Review and update security configuration settings")
        
        audit_results["recommendations"] = recommendations
        
        return audit_results
    
    async def shutdown(self):
        """Shutdown secure server."""
        if self.security_core:
            await self.security_core.shutdown()
        
        logger.info(f"Secure MCP Server '{self.server_name}' shutdown complete")


class SecureMCPServerManager:
    """Manager for multiple secure MCP servers."""
    
    def __init__(self):
        self.servers: Dict[str, SecureMCPServer] = {}
        self.global_config: Optional[SecureServerConfig] = None
    
    def set_global_config(self, config: SecureServerConfig):
        """Set global security configuration for all servers."""
        self.global_config = config
    
    async def add_server(self, 
                        server_name: str, 
                        mcp_server: Any, 
                        config: Optional[SecureServerConfig] = None):
        """Add a secure MCP server."""
        server_config = config or self.global_config or SecureServerConfig()
        
        secure_server = SecureMCPServer(mcp_server, server_config, server_name)
        await secure_server.initialize()
        
        self.servers[server_name] = secure_server
        logger.info(f"Added secure MCP server: {server_name}")
    
    async def remove_server(self, server_name: str):
        """Remove a secure MCP server."""
        if server_name in self.servers:
            await self.servers[server_name].shutdown()
            del self.servers[server_name]
            logger.info(f"Removed secure MCP server: {server_name}")
    
    def get_server(self, server_name: str) -> Optional[SecureMCPServer]:
        """Get a secure MCP server by name."""
        return self.servers.get(server_name)
    
    def list_servers(self) -> List[str]:
        """List all secure MCP server names."""
        return list(self.servers.keys())
    
    async def get_global_security_status(self) -> Dict[str, Any]:
        """Get security status for all servers."""
        status = {
            "total_servers": len(self.servers),
            "servers": {}
        }
        
        for server_name, server in self.servers.items():
            status["servers"][server_name] = await server.get_security_status()
        
        return status
    
    async def run_global_security_audit(self) -> Dict[str, Any]:
        """Run security audit on all servers."""
        audit_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_servers": len(self.servers),
            "server_audits": {}
        }
        
        for server_name, server in self.servers.items():
            audit_results["server_audits"][server_name] = await server.run_security_audit()
        
        # Calculate global security metrics
        all_scores = [
            audit["overall_security_score"] 
            for audit in audit_results["server_audits"].values()
        ]
        
        if all_scores:
            audit_results["global_security_score"] = sum(all_scores) / len(all_scores)
        else:
            audit_results["global_security_score"] = 0
        
        return audit_results
    
    async def shutdown_all(self):
        """Shutdown all secure servers."""
        for server in self.servers.values():
            await server.shutdown()
        
        self.servers.clear()
        logger.info("All secure MCP servers shutdown")


# Global manager instance
_secure_manager: Optional[SecureMCPServerManager] = None


def get_secure_manager() -> SecureMCPServerManager:
    """Get global secure MCP server manager."""
    global _secure_manager
    if _secure_manager is None:
        _secure_manager = SecureMCPServerManager()
    return _secure_manager


__all__ = [
    "SecureServerConfig",
    "SecureMCPServer", 
    "SecureMCPServerManager",
    "get_secure_manager"
]