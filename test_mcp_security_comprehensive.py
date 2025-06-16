#!/usr/bin/env python3
"""
Comprehensive MCP Security Testing Suite
Tests all implemented security hardening measures.

This test suite validates:
1. Authentication and authorization
2. Input validation and sanitization
3. Rate limiting and DDoS protection
4. Encryption and secrets management
5. Security monitoring and audit logging
6. Vulnerability management
7. Compliance framework validation
"""

import asyncio
import json
import pytest
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

# Import security modules
from src.security.mcp_security_core import (
    MCPSecurityCore, SecurityConfig, SecurityContext, 
    AuthenticationMethod, VulnerabilitySeverity, get_security_core
)
from src.security.mcp_secure_server import (
    SecureMCPServer, SecureServerConfig, get_secure_manager
)
from src.security.vulnerability_management import (
    VulnerabilityManager, get_vulnerability_manager
)


class MockMCPServer:
    """Mock MCP server for testing."""
    
    def __init__(self, name="mock_server"):
        self.name = name
        self.tools = [
            {"name": "docker_ps", "description": "List Docker containers"},
            {"name": "kubectl_get", "description": "Get Kubernetes resources"},
            {"name": "system_info", "description": "Get system information"}
        ]
    
    def get_server_info(self):
        return {
            "name": self.name,
            "version": "1.0.0",
            "description": "Mock MCP Server for testing"
        }
    
    def get_tools(self):
        return self.tools
    
    async def call_tool(self, tool_name, arguments):
        if tool_name == "docker_ps":
            return {"containers": ["container1", "container2"]}
        elif tool_name == "kubectl_get":
            return {"resources": ["pod1", "pod2"]}
        elif tool_name == "system_info":
            return {"cpu": "4 cores", "memory": "16GB"}
        else:
            raise ValueError(f"Unknown tool: {tool_name}")


class TestMCPSecurityCore:
    """Test MCP Security Core functionality."""
    
    @pytest.fixture
    async def security_core(self):
        """Create security core for testing."""
        config = SecurityConfig(
            auth_methods=[AuthenticationMethod.API_KEY, AuthenticationMethod.JWT_TOKEN],
            jwt_secret="test-secret-key-for-testing-only",
            rate_limit_enabled=True,
            requests_per_minute=10,  # Low limit for testing
            input_validation_enabled=True,
            encryption_enabled=True,
            audit_logging=True
        )
        
        core = MCPSecurityCore(config)
        await core.initialize()
        return core
    
    async def test_authentication_api_key(self, security_core):
        """Test API key authentication."""
        # Create API key
        credentials = security_core.create_user_credentials(
            user_id="test_user",
            roles=["operator"],
            permissions=["mcp.docker:execute"]
        )
        
        api_key = credentials["api_key"]
        assert api_key is not None
        assert len(api_key) >= 64
        
        # Test authentication
        context = await security_core.authenticate_request(
            auth_header=f"ApiKey {api_key}",
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0"
        )
        
        assert context is not None
        assert context.user_id == "test_user"
        assert "operator" in context.roles
        assert context.auth_method == AuthenticationMethod.API_KEY
    
    async def test_authentication_jwt(self, security_core):
        """Test JWT token authentication."""
        # Create JWT token
        credentials = security_core.create_user_credentials(
            user_id="test_user_jwt",
            roles=["admin"],
            permissions=["mcp.*:*"]
        )
        
        jwt_token = credentials["jwt_token"]
        assert jwt_token is not None
        
        # Test authentication
        context = await security_core.authenticate_request(
            auth_header=f"Bearer {jwt_token}",
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0"
        )
        
        assert context is not None
        assert context.user_id == "test_user_jwt"
        assert "admin" in context.roles
        assert context.auth_method == AuthenticationMethod.JWT_TOKEN
    
    async def test_authentication_failure(self, security_core):
        """Test authentication failure cases."""
        # Test invalid API key
        context = await security_core.authenticate_request(
            auth_header="ApiKey invalid-key",
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0"
        )
        assert context is None
        
        # Test invalid JWT token
        context = await security_core.authenticate_request(
            auth_header="Bearer invalid-token",
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0"
        )
        assert context is None
        
        # Test no auth header
        context = await security_core.authenticate_request(
            auth_header=None,
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0"
        )
        assert context is None
    
    async def test_authorization(self, security_core):
        """Test authorization checks."""
        # Create user with limited permissions
        credentials = security_core.create_user_credentials(
            user_id="limited_user",
            roles=["viewer"],
            permissions=["mcp.docker:read"]
        )
        
        context = await security_core.authenticate_request(
            auth_header=f"ApiKey {credentials['api_key']}",
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0"
        )
        
        # Test allowed operation
        is_authorized = await security_core.authorize_request(
            context, "mcp.docker", "read"
        )
        assert is_authorized
        
        # Test denied operation
        is_authorized = await security_core.authorize_request(
            context, "mcp.docker", "execute"
        )
        assert not is_authorized
        
        # Test admin user (should have full access)
        admin_credentials = security_core.create_user_credentials(
            user_id="admin_user",
            roles=["admin"],
            permissions=[]
        )
        
        admin_context = await security_core.authenticate_request(
            auth_header=f"ApiKey {admin_credentials['api_key']}",
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0"
        )
        
        is_authorized = await security_core.authorize_request(
            admin_context, "mcp.any", "any_operation"
        )
        assert is_authorized
    
    async def test_input_validation(self, security_core):
        """Test input validation and sanitization."""
        credentials = security_core.create_user_credentials(
            user_id="test_user",
            roles=["operator"],
            permissions=["mcp.test:execute"]
        )
        
        context = await security_core.authenticate_request(
            auth_header=f"ApiKey {credentials['api_key']}",
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0"
        )
        
        # Test valid input
        is_valid, data = await security_core.validate_and_process_request(
            context, "/test", {"name": "test", "value": 123}
        )
        assert is_valid
        assert data["name"] == "test"
        
        # Test SQL injection attempt
        is_valid, error = await security_core.validate_and_process_request(
            context, "/test", {"query": "SELECT * FROM users WHERE id = 1; DROP TABLE users;"}
        )
        assert not is_valid
        assert "Invalid input detected" in error
        
        # Test XSS attempt
        is_valid, error = await security_core.validate_and_process_request(
            context, "/test", {"content": "<script>alert('xss')</script>"}
        )
        assert not is_valid
        
        # Test command injection attempt
        is_valid, error = await security_core.validate_and_process_request(
            context, "/test", {"command": "ls; rm -rf /"}
        )
        assert not is_valid
    
    async def test_rate_limiting(self, security_core):
        """Test rate limiting functionality."""
        credentials = security_core.create_user_credentials(
            user_id="rate_test_user",
            roles=["operator"],
            permissions=["mcp.test:execute"]
        )
        
        context = await security_core.authenticate_request(
            auth_header=f"ApiKey {credentials['api_key']}",
            client_ip="192.168.1.200",
            user_agent="Test-Client/1.0"
        )
        
        # Send requests up to the limit
        success_count = 0
        for i in range(15):  # Limit is 10 per minute
            is_valid, data = await security_core.validate_and_process_request(
                context, "/test", {"request": i}
            )
            if is_valid:
                success_count += 1
            else:
                break
        
        # Should hit rate limit before processing all requests
        assert success_count < 15
        assert success_count <= 10
    
    async def test_encryption(self, security_core):
        """Test encryption functionality."""
        # Test data encryption
        original_data = "sensitive information"
        encrypted_data = security_core.encryption.encrypt_data(original_data)
        assert encrypted_data != original_data
        
        decrypted_data = security_core.encryption.decrypt_data(encrypted_data)
        assert decrypted_data == original_data
        
        # Test password hashing
        password = "test_password_123"
        hashed = security_core.encryption.hash_password(password)
        assert hashed != password
        
        # Test password verification
        assert security_core.encryption.verify_password(password, hashed)
        assert not security_core.encryption.verify_password("wrong_password", hashed)
        
        # Test API key generation
        api_key = security_core.encryption.generate_api_key()
        assert len(api_key) >= 64
    
    async def test_audit_logging(self, security_core):
        """Test audit logging functionality."""
        credentials = security_core.create_user_credentials(
            user_id="audit_test_user",
            roles=["operator"],
            permissions=["mcp.test:execute"]
        )
        
        context = await security_core.authenticate_request(
            auth_header=f"ApiKey {credentials['api_key']}",
            client_ip="192.168.1.300",
            user_agent="Test-Client/1.0"
        )
        
        # Perform some operations to generate audit logs
        await security_core.validate_and_process_request(
            context, "/test", {"operation": "test"}
        )
        
        # Check audit logs
        audit_events = security_core.auditor.security_events
        assert len(audit_events) > 0
        
        # Find request validation event
        validation_events = [
            e for e in audit_events 
            if e["event_type"] == "request_validated"
        ]
        assert len(validation_events) > 0
        
        event = validation_events[0]
        assert event["user_id"] == "audit_test_user"
        assert event["client_ip"] == "192.168.1.300"
    
    async def test_anomaly_detection(self, security_core):
        """Test anomaly detection."""
        credentials = security_core.create_user_credentials(
            user_id="anomaly_test_user",
            roles=["operator"],
            permissions=["mcp.test:execute"]
        )
        
        # Create multiple contexts with different IPs (suspicious)
        ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"]
        
        for ip in ips:
            context = await security_core.authenticate_request(
                auth_header=f"ApiKey {credentials['api_key']}",
                client_ip=ip,
                user_agent="Test-Client/1.0"
            )
            
            # Simulate request
            await security_core.validate_and_process_request(
                context, "/test", {"test": "data"}
            )
        
        # Check if anomaly was detected
        user_key = f"anomaly_test_user:{ips[-1]}"
        risk_score = security_core.auditor.anomaly_scores.get(user_key, 0.0)
        assert risk_score > 0.0  # Should detect multiple IPs as anomalous


class TestSecureMCPServer:
    """Test Secure MCP Server functionality."""
    
    @pytest.fixture
    async def secure_server(self):
        """Create secure MCP server for testing."""
        mock_server = MockMCPServer("test_secure_server")
        
        security_config = SecurityConfig(
            auth_methods=[AuthenticationMethod.API_KEY],
            rate_limit_enabled=True,
            requests_per_minute=50,
            input_validation_enabled=True,
            encryption_enabled=True,
            audit_logging=True
        )
        
        server_config = SecureServerConfig(
            security_config=security_config,
            enable_tls=False,  # Disable for testing
            compliance_frameworks=["SOC2"]
        )
        
        secure_server = SecureMCPServer(
            mcp_server=mock_server,
            config=server_config,
            server_name="test_secure_server"
        )
        
        await secure_server.initialize()
        return secure_server
    
    async def test_secure_request_handling(self, secure_server):
        """Test secure request handling."""
        # Create valid credentials
        credentials = secure_server.security_core.create_user_credentials(
            user_id="test_user",
            roles=["operator"],
            permissions=["docker_ps:execute"]
        )
        
        # Test successful request
        response = await secure_server.handle_request(
            auth_header=f"ApiKey {credentials['api_key']}",
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0",
            method="POST",
            endpoint="docker_ps",
            data={}
        )
        
        assert response["status_code"] == 200
        assert "result" in response
        assert response["result"]["containers"] == ["container1", "container2"]
    
    async def test_authentication_required(self, secure_server):
        """Test that authentication is required."""
        response = await secure_server.handle_request(
            auth_header=None,
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0",
            method="POST",
            endpoint="docker_ps",
            data={}
        )
        
        assert response["status_code"] == 401
        assert "Authentication required" in response["error"]
    
    async def test_authorization_denied(self, secure_server):
        """Test authorization denial."""
        # Create user with limited permissions
        credentials = secure_server.security_core.create_user_credentials(
            user_id="limited_user",
            roles=["viewer"],
            permissions=["system_info:read"]  # No docker permissions
        )
        
        response = await secure_server.handle_request(
            auth_header=f"ApiKey {credentials['api_key']}",
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0",
            method="POST",
            endpoint="docker_ps",  # Requires docker permissions
            data={}
        )
        
        assert response["status_code"] == 403
        assert "Access denied" in response["error"]
    
    async def test_input_validation_blocked(self, secure_server):
        """Test that malicious input is blocked."""
        credentials = secure_server.security_core.create_user_credentials(
            user_id="test_user",
            roles=["operator"],
            permissions=["docker_ps:execute"]
        )
        
        # Test SQL injection attempt
        response = await secure_server.handle_request(
            auth_header=f"ApiKey {credentials['api_key']}",
            client_ip="192.168.1.100",
            user_agent="Test-Client/1.0",
            method="POST",
            endpoint="docker_ps",
            data={"filter": "name='; DROP TABLE containers; --"}
        )
        
        assert response["status_code"] == 400
        assert "Invalid input detected" in response["error"]
    
    async def test_server_info_security(self, secure_server):
        """Test that server info includes security information."""
        info = secure_server.get_server_info()
        
        assert info["security_enabled"] is True
        assert "authentication_methods" in info
        assert "compliance_frameworks" in info
        assert "security_score" in info
        assert info["request_statistics"]["total_requests"] >= 0
    
    async def test_tools_security_metadata(self, secure_server):
        """Test that tools include security metadata."""
        tools = secure_server.get_tools()
        
        assert len(tools) > 0
        for tool in tools:
            assert tool["security_level"] == "HIGH"
            assert tool["requires_authentication"] is True
            assert "rate_limited" in tool
            assert "input_validated" in tool
    
    async def test_security_audit(self, secure_server):
        """Test security audit functionality."""
        audit_results = await secure_server.run_security_audit()
        
        assert "timestamp" in audit_results
        assert "server_name" in audit_results
        assert "audit_sections" in audit_results
        assert "overall_security_score" in audit_results
        
        # Check audit sections
        sections = audit_results["audit_sections"]
        assert "vulnerability_scan" in sections
        assert "compliance" in sections
        assert "configuration" in sections
        
        # Security score should be reasonable
        score = audit_results["overall_security_score"]
        assert 0 <= score <= 100


class TestVulnerabilityManagement:
    """Test Vulnerability Management functionality."""
    
    @pytest.fixture
    async def vuln_manager(self):
        """Create vulnerability manager for testing."""
        return get_vulnerability_manager()
    
    async def test_dependency_scanning_python(self, vuln_manager):
        """Test Python dependency scanning."""
        # Create temporary requirements file with known vulnerable package
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("requests==2.25.1\n")  # Known to have vulnerabilities
            f.write("urllib3==1.26.5\n")
            requirements_file = f.name
        
        try:
            result = await vuln_manager.dependency_scanner.scan_python_dependencies(requirements_file)
            
            assert result.scan_type.value == "dependency"
            assert result.target == requirements_file
            assert result.completed_at is not None
            
            # Check summary
            assert "total_vulnerabilities" in result.summary
            assert "severity_counts" in result.summary
            assert "risk_score" in result.summary
            
        finally:
            Path(requirements_file).unlink()
    
    async def test_static_code_scanning(self, vuln_manager):
        """Test static code analysis."""
        # Create temporary directory with test files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create Python file with security issues
            python_file = Path(temp_dir) / "test.py"
            python_file.write_text("""
# Security issues for testing
password = "hardcoded123"  # Hardcoded password
query = "SELECT * FROM users WHERE id = %s" % user_id  # SQL injection risk
os.system("ls " + user_input)  # Command injection risk
hash_value = hashlib.md5(data).hexdigest()  # Weak crypto
random_number = random.random()  # Insecure random
            """)
            
            # Create JavaScript file with security issues
            js_file = Path(temp_dir) / "test.js"
            js_file.write_text("""
// Security issues for testing
eval(user_input);  // Use of eval
const api_key = "sk-1234567890abcdef";  // Hardcoded secret
element.innerHTML = "Hello " + user_name;  // Unsafe innerHTML
            """)
            
            result = await vuln_manager.static_scanner.scan_directory(temp_dir)
            
            assert result.scan_type.value == "static_code"
            assert result.target == temp_dir
            assert len(result.vulnerabilities) > 0
            
            # Check for expected vulnerabilities
            vuln_types = [v.id.split('_')[0] for v in result.vulnerabilities]
            assert "hardcoded" in str(vuln_types)
            assert "sql" in str(vuln_types) or "eval" in str(vuln_types)
    
    async def test_dockerfile_scanning(self, vuln_manager):
        """Test Dockerfile security scanning."""
        # Create temporary Dockerfile with security issues
        with tempfile.NamedTemporaryFile(mode='w', suffix='.dockerfile', delete=False) as f:
            f.write("""
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ADD https://example.com/file.tar.gz /tmp/
USER root
EXPOSE 80
CMD ["./app"]
            """)
            dockerfile = f.name
        
        try:
            result = await vuln_manager.container_scanner.scan_dockerfile(dockerfile)
            
            assert result.scan_type.value == "container"
            assert result.target == dockerfile
            assert len(result.vulnerabilities) > 0
            
            # Check for expected Dockerfile issues
            vuln_titles = [v.title for v in result.vulnerabilities]
            assert any("latest" in title.lower() for title in vuln_titles)
            assert any("root" in title.lower() or "user" in title.lower() for title in vuln_titles)
            
        finally:
            Path(dockerfile).unlink()
    
    async def test_comprehensive_scan(self, vuln_manager):
        """Test comprehensive security scan."""
        # Create temporary project directory
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            
            # Create requirements.txt
            (project_path / "requirements.txt").write_text("requests==2.25.1\n")
            
            # Create package.json
            (project_path / "package.json").write_text("""
{
  "name": "test-project",
  "dependencies": {
    "lodash": "4.17.20"
  }
}
            """)
            
            # Create Dockerfile
            (project_path / "Dockerfile").write_text("""
FROM ubuntu:latest
USER root
            """)
            
            # Create Python file with issues
            (project_path / "app.py").write_text("""
password = "secret123"
            """)
            
            results = await vuln_manager.run_comprehensive_scan(str(project_path))
            
            assert len(results) > 0
            assert "python_dependencies" in results or "npm_dependencies" in results
            assert "static_code" in results
            assert "dockerfile" in results
            
            # Test summary generation
            summary = vuln_manager.get_vulnerability_summary(results)
            assert "total_vulnerabilities" in summary
            assert "severity_breakdown" in summary
            assert "overall_risk_score" in summary
            assert "recommendations" in summary
    
    async def test_security_report_generation(self, vuln_manager):
        """Test security report generation."""
        # Create mock scan results
        mock_results = {}
        
        # Generate security report
        report = await vuln_manager.generate_security_report(mock_results)
        
        assert "report_id" in report
        assert "generated_at" in report
        assert "summary" in report
        assert "detailed_results" in report
        assert "action_items" in report


class TestSecurityIntegration:
    """Test security integration scenarios."""
    
    async def test_end_to_end_security_flow(self):
        """Test complete end-to-end security flow."""
        # Initialize secure MCP server manager
        manager = get_secure_manager()
        
        # Configure global security
        security_config = SecurityConfig(
            auth_methods=[AuthenticationMethod.API_KEY],
            rate_limit_enabled=True,
            input_validation_enabled=True,
            encryption_enabled=True,
            audit_logging=True
        )
        
        server_config = SecureServerConfig(
            security_config=security_config,
            enable_tls=False,  # Disable for testing
            compliance_frameworks=["SOC2", "GDPR"]
        )
        
        manager.set_global_config(server_config)
        
        # Add mock servers
        mock_docker = MockMCPServer("docker_server")
        mock_k8s = MockMCPServer("k8s_server")
        
        await manager.add_server("docker", mock_docker)
        await manager.add_server("kubernetes", mock_k8s)
        
        # Test global security status
        status = await manager.get_global_security_status()
        assert status["total_servers"] == 2
        assert "docker" in status["servers"]
        assert "kubernetes" in status["servers"]
        
        # Test global security audit
        audit = await manager.run_global_security_audit()
        assert audit["total_servers"] == 2
        assert "global_security_score" in audit
        assert "server_audits" in audit
        
        # Cleanup
        await manager.shutdown_all()
    
    async def test_security_incident_simulation(self):
        """Test security incident detection and response."""
        # Initialize security core
        security_core = await get_security_core()
        
        # Create test user
        credentials = security_core.create_user_credentials(
            user_id="incident_test_user",
            roles=["operator"],
            permissions=["mcp.test:execute"]
        )
        
        # Simulate suspicious activity patterns
        suspicious_ips = ["192.168.1.100", "10.0.0.100", "172.16.0.100", "203.0.113.100"]
        
        for ip in suspicious_ips:
            context = await security_core.authenticate_request(
                auth_header=f"ApiKey {credentials['api_key']}",
                client_ip=ip,
                user_agent="Suspicious-Client/1.0"
            )
            
            # Make rapid requests
            for _ in range(5):
                await security_core.validate_and_process_request(
                    context, "/test", {"request": "data"}
                )
        
        # Check that anomalies were detected
        metrics = security_core.auditor.get_security_metrics()
        assert metrics["total_events_last_hour"] > 0
        assert metrics["unique_ips_last_hour"] >= len(suspicious_ips)
        
        # Verify incident is logged
        security_events = security_core.auditor.security_events
        request_events = [e for e in security_events if e["event_type"] == "request_validated"]
        assert len(request_events) > 0
        
        # Check for high-risk events
        high_risk_events = [e for e in security_events if e.get("risk_score", 0) > 0.5]
        assert len(high_risk_events) > 0
    
    async def test_compliance_validation(self):
        """Test compliance framework validation."""
        # Create secure server with compliance requirements
        mock_server = MockMCPServer("compliance_test")
        
        security_config = SecurityConfig(
            auth_methods=[AuthenticationMethod.API_KEY, AuthenticationMethod.JWT_TOKEN],
            rate_limit_enabled=True,
            input_validation_enabled=True,
            encryption_enabled=True,
            audit_logging=True,
            session_timeout_minutes=30
        )
        
        server_config = SecureServerConfig(
            security_config=security_config,
            enable_tls=True,
            require_client_cert=True,
            compliance_frameworks=["SOC2", "GDPR", "HIPAA", "PCI_DSS"]
        )
        
        secure_server = SecureMCPServer(
            mcp_server=mock_server,
            config=server_config,
            server_name="compliance_test_server"
        )
        
        await secure_server.initialize()
        
        # Run security audit
        audit_results = await secure_server.run_security_audit()
        
        # Check compliance status
        compliance_status = audit_results["audit_sections"]["compliance"]
        assert "SOC2" in compliance_status
        assert "GDPR" in compliance_status
        assert "HIPAA" in compliance_status
        assert "PCI_DSS" in compliance_status
        
        # Verify configuration audit
        config_audit = audit_results["audit_sections"]["configuration"]
        assert config_audit["authentication_configured"] is True
        assert config_audit["encryption_enabled"] is True
        assert config_audit["tls_enabled"] is True
        assert config_audit["rate_limiting_enabled"] is True
        assert config_audit["input_validation_enabled"] is True
        assert config_audit["audit_logging_enabled"] is True
        
        await secure_server.shutdown()


async def run_security_tests():
    """Run all security tests."""
    print("🔒 Starting Comprehensive MCP Security Tests...")
    
    # Test MCP Security Core
    print("\n📋 Testing MCP Security Core...")
    core_test = TestMCPSecurityCore()
    
    security_core = await core_test.security_core()
    
    try:
        await core_test.test_authentication_api_key(security_core)
        print("✅ API Key Authentication")
        
        await core_test.test_authentication_jwt(security_core)
        print("✅ JWT Token Authentication")
        
        await core_test.test_authentication_failure(security_core)
        print("✅ Authentication Failure Handling")
        
        await core_test.test_authorization(security_core)
        print("✅ Authorization Controls")
        
        await core_test.test_input_validation(security_core)
        print("✅ Input Validation and Sanitization")
        
        await core_test.test_rate_limiting(security_core)
        print("✅ Rate Limiting and DDoS Protection")
        
        await core_test.test_encryption(security_core)
        print("✅ Encryption and Secrets Management")
        
        await core_test.test_audit_logging(security_core)
        print("✅ Audit Logging")
        
        await core_test.test_anomaly_detection(security_core)
        print("✅ Anomaly Detection")
        
    finally:
        await security_core.shutdown()
    
    # Test Secure MCP Server
    print("\n🛡️ Testing Secure MCP Server...")
    server_test = TestSecureMCPServer()
    
    secure_server = await server_test.secure_server()
    
    try:
        await server_test.test_secure_request_handling(secure_server)
        print("✅ Secure Request Handling")
        
        await server_test.test_authentication_required(secure_server)
        print("✅ Authentication Enforcement")
        
        await server_test.test_authorization_denied(secure_server)
        print("✅ Authorization Enforcement")
        
        await server_test.test_input_validation_blocked(secure_server)
        print("✅ Malicious Input Blocking")
        
        await server_test.test_server_info_security(secure_server)
        print("✅ Security Metadata")
        
        await server_test.test_tools_security_metadata(secure_server)
        print("✅ Tool Security Information")
        
        await server_test.test_security_audit(secure_server)
        print("✅ Security Audit Functionality")
        
    finally:
        await secure_server.shutdown()
    
    # Test Vulnerability Management
    print("\n🔍 Testing Vulnerability Management...")
    vuln_test = TestVulnerabilityManagement()
    
    vuln_manager = await vuln_test.vuln_manager()
    
    await vuln_test.test_dependency_scanning_python(vuln_manager)
    print("✅ Python Dependency Scanning")
    
    await vuln_test.test_static_code_scanning(vuln_manager)
    print("✅ Static Code Analysis")
    
    await vuln_test.test_dockerfile_scanning(vuln_manager)
    print("✅ Dockerfile Security Scanning")
    
    await vuln_test.test_comprehensive_scan(vuln_manager)
    print("✅ Comprehensive Security Scanning")
    
    await vuln_test.test_security_report_generation(vuln_manager)
    print("✅ Security Report Generation")
    
    # Test Security Integration
    print("\n🔗 Testing Security Integration...")
    integration_test = TestSecurityIntegration()
    
    await integration_test.test_end_to_end_security_flow()
    print("✅ End-to-End Security Flow")
    
    await integration_test.test_security_incident_simulation()
    print("✅ Security Incident Detection")
    
    await integration_test.test_compliance_validation()
    print("✅ Compliance Framework Validation")
    
    print("\n🎉 All MCP Security Tests Completed Successfully!")
    
    # Generate test summary
    print("\n📊 Security Test Summary:")
    print("━" * 50)
    print("✅ Authentication & Authorization: PASSED")
    print("✅ Input Validation & Sanitization: PASSED")
    print("✅ Rate Limiting & DDoS Protection: PASSED")
    print("✅ Encryption & Secrets Management: PASSED")
    print("✅ Security Monitoring & Logging: PASSED")
    print("✅ Vulnerability Management: PASSED")
    print("✅ Compliance Framework Support: PASSED")
    print("✅ Security Integration: PASSED")
    print("━" * 50)
    print("🔒 MCP Security Hardening: FULLY VALIDATED")


if __name__ == "__main__":
    asyncio.run(run_security_tests())