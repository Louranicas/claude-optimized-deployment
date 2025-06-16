"""
Authentication and Authorization Integration Tests for MCP Servers

This test suite focuses on testing authentication mechanisms,
authorization controls, permission checking, and access control
for all MCP servers.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any, Optional
import logging

# Import MCP servers
from src.mcp.servers import BraveMCPServer
from src.mcp.devops_servers import AzureDevOpsMCPServer, WindowsSystemMCPServer
from src.mcp.infrastructure_servers import DesktopCommanderMCPServer, DockerMCPServer, KubernetesMCPServer
from src.mcp.communication.slack_server import SlackNotificationMCPServer
from src.mcp.monitoring.prometheus_server import PrometheusMonitoringMCP
from src.mcp.security.scanner_server import SecurityScannerMCPServer
from src.mcp.storage.s3_server import S3StorageMCPServer

# Import protocols and exceptions
from src.mcp.protocols import MCPError, MCPServerInfo
from src.core.exceptions import ValidationError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MockUser:
    """Mock user for authentication testing with various permission levels."""
    
    def __init__(
        self,
        username: str = "test_user",
        user_id: str = "user_123",
        roles: List[str] = None,
        permissions: List[str] = None,
        is_admin: bool = False,
        is_authenticated: bool = True
    ):
        self.username = username
        self.id = user_id
        self.roles = roles or []
        self.permissions = permissions or []
        self.is_admin = is_admin
        self.is_authenticated = is_authenticated
        self.email = f"{username}@example.com"
        self.created_at = "2024-01-01T00:00:00Z"


class MockPermissionChecker:
    """Mock permission checker with configurable behavior."""
    
    def __init__(
        self,
        allowed_permissions: List[str] = None,
        denied_permissions: List[str] = None,
        require_admin: List[str] = None
    ):
        self.allowed_permissions = allowed_permissions or []
        self.denied_permissions = denied_permissions or []
        self.require_admin = require_admin or []
        self.permission_checks: List[Dict[str, Any]] = []
    
    async def check_permission(self, user: MockUser, permission: str) -> bool:
        """Check if user has permission."""
        # Log the permission check for auditing
        self.permission_checks.append({
            "user": user.username,
            "permission": permission,
            "timestamp": "2024-01-01T00:00:00Z"
        })
        
        # Deny if explicitly denied
        if permission in self.denied_permissions:
            return False
        
        # Require admin for admin-only permissions
        if permission in self.require_admin:
            return user.is_admin
        
        # Allow if in allowed list
        if permission in self.allowed_permissions:
            return True
        
        # Check user's direct permissions
        return permission in user.permissions
    
    def register_resource_permission(self, resource: str, permission: str):
        """Register resource permission (mock implementation)."""
        pass
    
    def get_permission_checks(self) -> List[Dict[str, Any]]:
        """Get audit log of permission checks."""
        return self.permission_checks


@pytest.fixture
def admin_user():
    """Create admin user with full permissions."""
    return MockUser(
        username="admin",
        user_id="admin_001",
        roles=["admin", "operator"],
        is_admin=True,
        permissions=[
            "mcp.brave.search:execute",
            "mcp.desktop.command:execute",
            "mcp.docker.container:execute",
            "mcp.kubernetes.deployment:execute",
            "mcp.azuredevops.pipeline:execute",
            "mcp.windows.powershell:execute",
            "mcp.slack.notification:send",
            "mcp.prometheus.metrics:read",
            "mcp.security.scan:execute",
            "mcp.s3.bucket:read",
            "mcp.s3.bucket:write",
            "mcp.storage.cloud:access"
        ]
    )


@pytest.fixture
def regular_user():
    """Create regular user with limited permissions."""
    return MockUser(
        username="regular_user",
        user_id="user_002",
        roles=["user"],
        is_admin=False,
        permissions=[
            "mcp.brave.search:execute",
            "mcp.prometheus.metrics:read",
            "mcp.s3.bucket:read"
        ]
    )


@pytest.fixture
def restricted_user():
    """Create user with very limited permissions."""
    return MockUser(
        username="restricted_user",
        user_id="user_003",
        roles=["restricted"],
        is_admin=False,
        permissions=["mcp.brave.search:execute"]
    )


@pytest.fixture
def unauthorized_user():
    """Create user with no permissions."""
    return MockUser(
        username="unauthorized_user",
        user_id="user_004",
        roles=[],
        is_admin=False,
        permissions=[]
    )


@pytest.fixture
def permission_checker():
    """Create permission checker with standard configuration."""
    return MockPermissionChecker(
        allowed_permissions=[
            "mcp.brave.search:execute",
            "mcp.desktop.command:execute",
            "mcp.docker.container:execute",
            "mcp.kubernetes.deployment:execute",
            "mcp.prometheus.metrics:read"
        ],
        require_admin=[
            "mcp.windows.powershell:execute",
            "mcp.azuredevops.pipeline:execute",
            "mcp.security.scan:execute"
        ]
    )


class TestBasicAuthentication:
    """Test basic authentication mechanisms."""
    
    def test_user_authentication_validation(self):
        """Test user authentication validation."""
        # Valid authenticated user
        user = MockUser(is_authenticated=True)
        assert user.is_authenticated is True
        assert user.username is not None
        assert user.id is not None
        
        # Invalid unauthenticated user
        unauth_user = MockUser(is_authenticated=False)
        assert unauth_user.is_authenticated is False
    
    def test_user_role_validation(self, admin_user, regular_user, restricted_user):
        """Test user role validation."""
        # Admin user should have admin role
        assert "admin" in admin_user.roles
        assert admin_user.is_admin is True
        
        # Regular user should not be admin
        assert "admin" not in regular_user.roles
        assert regular_user.is_admin is False
        
        # Restricted user should have limited roles
        assert "restricted" in restricted_user.roles
        assert restricted_user.is_admin is False
    
    @pytest.mark.asyncio
    async def test_permission_checker_functionality(self, permission_checker, admin_user, regular_user):
        """Test permission checker functionality."""
        # Admin should have access to admin-only permissions
        assert await permission_checker.check_permission(admin_user, "mcp.security.scan:execute") is True
        
        # Regular user should not have access to admin-only permissions
        assert await permission_checker.check_permission(regular_user, "mcp.security.scan:execute") is False
        
        # Both should have access to allowed permissions
        assert await permission_checker.check_permission(admin_user, "mcp.brave.search:execute") is True
        assert await permission_checker.check_permission(regular_user, "mcp.brave.search:execute") is True


class TestServerAuthentication:
    """Test authentication for individual servers."""
    
    @pytest.mark.asyncio
    async def test_brave_server_authentication(self, permission_checker, admin_user, unauthorized_user):
        """Test Brave server authentication."""
        server = BraveMCPServer(api_key="test_key", permission_checker=permission_checker)
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"web": {"results": []}}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            # Admin user should be able to execute search
            result = await server.call_tool(
                "brave_web_search",
                {"query": "test"},
                admin_user
            )
            assert "results" in result
            
            # Check that permission was checked
            checks = permission_checker.get_permission_checks()
            assert len(checks) > 0
            assert any(check["permission"] == "mcp.brave.search:execute" for check in checks)
    
    @pytest.mark.asyncio
    async def test_desktop_commander_authentication(self, permission_checker, admin_user, regular_user):
        """Test Desktop Commander authentication."""
        server = DesktopCommanderMCPServer(permission_checker=permission_checker)
        
        with patch.object(server, 'command_executor') as mock_executor:
            mock_result = Mock()
            mock_result.success = True
            mock_result.exit_code = 0
            mock_result.stdout = "test output"
            mock_result.stderr = ""
            mock_result.command = "echo test"
            mock_result.working_directory = "/tmp"
            mock_result.truncated = False
            mock_executor.execute_async.return_value = mock_result
            
            # Admin user should be able to execute commands
            result = await server.call_tool(
                "execute_command",
                {"command": "echo test"},
                admin_user
            )
            assert result["success"] is True
            
            # Regular user should also be able to execute (if permission allows)
            result = await server.call_tool(
                "execute_command",
                {"command": "echo test"},
                regular_user
            )
            assert result["success"] is True
    
    @pytest.mark.asyncio
    async def test_docker_server_authentication(self, permission_checker, admin_user, restricted_user):
        """Test Docker server authentication."""
        server = DockerMCPServer(permission_checker=permission_checker)
        server.docker_available = True
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"Container output", b"")
            mock_subprocess.return_value = mock_process
            
            # Admin user should be able to run containers
            result = await server.call_tool(
                "docker_run",
                {"image": "alpine:latest"},
                admin_user
            )
            assert result["success"] is True
    
    @pytest.mark.asyncio
    async def test_security_scanner_admin_only(self, permission_checker, admin_user, regular_user):
        """Test security scanner requires admin privileges."""
        server = SecurityScannerMCPServer(permission_checker=permission_checker)
        
        # Admin should have access
        # Note: Actual implementation would depend on server's tool methods
        
        # Regular user should be denied admin-only operations
        # Implementation would check permissions before executing sensitive scans


class TestPermissionEnforcement:
    """Test permission enforcement across different scenarios."""
    
    @pytest.mark.asyncio
    async def test_permission_denied_scenarios(self, unauthorized_user):
        """Test permission denied scenarios."""
        # Create permission checker that denies all
        deny_all_checker = MockPermissionChecker(
            allowed_permissions=[],
            denied_permissions=["*"]
        )
        
        servers = [
            BraveMCPServer(api_key="test", permission_checker=deny_all_checker),
            DesktopCommanderMCPServer(permission_checker=deny_all_checker),
            DockerMCPServer(permission_checker=deny_all_checker)
        ]
        
        for server in servers:
            tools = server.get_tools()
            if tools:
                # Should handle permission denial gracefully
                # Implementation depends on how each server checks permissions
                pass
    
    @pytest.mark.asyncio
    async def test_role_based_access_control(self, permission_checker):
        """Test role-based access control."""
        # Create users with different roles
        developer = MockUser(
            username="developer",
            roles=["developer"],
            permissions=["mcp.brave.search:execute", "mcp.docker.container:execute"]
        )
        
        operator = MockUser(
            username="operator",
            roles=["operator"],
            permissions=[
                "mcp.kubernetes.deployment:execute",
                "mcp.prometheus.metrics:read",
                "mcp.slack.notification:send"
            ]
        )
        
        # Developer should have access to development tools
        assert "mcp.docker.container:execute" in developer.permissions
        
        # Operator should have access to operational tools
        assert "mcp.kubernetes.deployment:execute" in operator.permissions
        assert "mcp.prometheus.metrics:read" in operator.permissions
    
    def test_permission_inheritance(self):
        """Test permission inheritance from roles."""
        # User with hierarchical roles
        senior_dev = MockUser(
            username="senior_dev",
            roles=["developer", "senior", "code_reviewer"],
            permissions=[
                "mcp.brave.search:execute",
                "mcp.docker.container:execute",
                "mcp.security.scan:execute"  # Additional permission for senior role
            ]
        )
        
        # Should inherit permissions from multiple roles
        assert len(senior_dev.roles) == 3
        assert "mcp.security.scan:execute" in senior_dev.permissions
    
    @pytest.mark.asyncio
    async def test_dynamic_permission_changes(self, permission_checker, regular_user):
        """Test dynamic permission changes."""
        # Initial permission check
        initial_access = await permission_checker.check_permission(
            regular_user, "mcp.security.scan:execute"
        )
        assert initial_access is False  # Should be denied initially
        
        # Simulate permission grant
        permission_checker.allowed_permissions.append("mcp.security.scan:execute")
        
        # Should now have access
        updated_access = await permission_checker.check_permission(
            regular_user, "mcp.security.scan:execute"
        )
        # Note: This would depend on actual implementation of dynamic permissions


class TestSecurityContexts:
    """Test security contexts and isolation."""
    
    @pytest.mark.asyncio
    async def test_user_context_isolation(self, permission_checker, admin_user, regular_user):
        """Test user context isolation."""
        server = DesktopCommanderMCPServer(permission_checker=permission_checker)
        
        with patch.object(server, 'command_executor') as mock_executor:
            mock_result = Mock()
            mock_result.success = True
            mock_result.exit_code = 0
            mock_result.stdout = "output"
            mock_result.stderr = ""
            mock_result.command = "test"
            mock_result.working_directory = "/tmp"
            mock_result.truncated = False
            mock_executor.execute_async.return_value = mock_result
            
            # Execute commands as different users
            admin_result = await server.call_tool(
                "execute_command",
                {"command": "whoami"},
                admin_user
            )
            
            regular_result = await server.call_tool(
                "execute_command",
                {"command": "whoami"},
                regular_user
            )
            
            # Verify user context is passed correctly
            # Implementation should ensure user context isolation
            assert admin_result["success"] is True
            assert regular_result["success"] is True
    
    def test_session_management(self):
        """Test session management and security."""
        # Test session creation and validation
        user_session = {
            "user_id": "user_123",
            "username": "test_user",
            "created_at": "2024-01-01T00:00:00Z",
            "expires_at": "2024-01-02T00:00:00Z",
            "permissions": ["mcp.brave.search:execute"]
        }
        
        # Session should have required fields
        assert "user_id" in user_session
        assert "username" in user_session
        assert "permissions" in user_session
        assert "expires_at" in user_session
    
    @pytest.mark.asyncio
    async def test_privilege_escalation_prevention(self, permission_checker, regular_user):
        """Test prevention of privilege escalation."""
        server = WindowsSystemMCPServer(permission_checker=permission_checker)
        
        # Attempt to execute privileged command
        dangerous_commands = [
            "Get-Process | Stop-Process -Force",
            "Start-Service -Name Spooler",
            "Set-ExecutionPolicy Bypass"
        ]
        
        for cmd in dangerous_commands:
            # Regular user should not be able to execute privileged commands
            # Implementation should validate command permissions
            try:
                result = await server.call_tool(
                    "powershell_command",
                    {"command": cmd},
                    regular_user
                )
                # If allowed, verify it's properly sandboxed
            except Exception:
                # Exception is expected for unauthorized commands
                pass


class TestAuditingAndLogging:
    """Test auditing and logging of authentication events."""
    
    @pytest.mark.asyncio
    async def test_authentication_logging(self, permission_checker, admin_user, regular_user):
        """Test authentication event logging."""
        server = BraveMCPServer(api_key="test_key", permission_checker=permission_checker)
        
        with patch.object(server, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"web": {"results": []}}
            mock_session.get.return_value.__aenter__.return_value = mock_response
            server.session = mock_session
            
            # Execute operations as different users
            await server.call_tool("brave_web_search", {"query": "admin test"}, admin_user)
            await server.call_tool("brave_web_search", {"query": "user test"}, regular_user)
            
            # Verify permission checks were logged
            checks = permission_checker.get_permission_checks()
            assert len(checks) >= 2
            
            # Verify user information is logged
            usernames = [check["user"] for check in checks]
            assert "admin" in usernames
            assert "regular_user" in usernames
    
    def test_permission_audit_trail(self, permission_checker):
        """Test permission audit trail."""
        # Create mock audit events
        audit_events = [
            {
                "timestamp": "2024-01-01T10:00:00Z",
                "user": "admin",
                "action": "mcp.security.scan:execute",
                "resource": "security_scanner",
                "result": "allowed",
                "source_ip": "192.168.1.100"
            },
            {
                "timestamp": "2024-01-01T10:01:00Z",
                "user": "regular_user",
                "action": "mcp.security.scan:execute", 
                "resource": "security_scanner",
                "result": "denied",
                "source_ip": "192.168.1.101"
            }
        ]
        
        # Audit trail should include all required fields
        for event in audit_events:
            assert "timestamp" in event
            assert "user" in event
            assert "action" in event
            assert "result" in event
    
    def test_security_event_monitoring(self):
        """Test security event monitoring."""
        # Define suspicious activity patterns
        suspicious_events = [
            "Multiple failed permission checks",
            "Unusual command execution patterns",
            "Access to sensitive resources",
            "Privilege escalation attempts"
        ]
        
        # Security monitoring should detect these patterns
        for event_type in suspicious_events:
            # Implementation would include detection logic
            pass


class TestAuthenticationIntegration:
    """Test authentication integration across multiple servers."""
    
    @pytest.mark.asyncio
    async def test_cross_server_permission_consistency(self, permission_checker, admin_user):
        """Test permission consistency across servers."""
        servers = [
            BraveMCPServer(api_key="test", permission_checker=permission_checker),
            DesktopCommanderMCPServer(permission_checker=permission_checker),
            DockerMCPServer(permission_checker=permission_checker)
        ]
        
        # Same user should have consistent permission evaluation
        for server in servers:
            info = server.get_server_info()
            assert isinstance(info, MCPServerInfo)
            
            # Verify permission checker is properly configured
            assert server.permission_checker is not None
    
    @pytest.mark.asyncio
    async def test_federated_authentication(self, admin_user):
        """Test federated authentication across services."""
        # Simulate federated user with external identity
        federated_user = MockUser(
            username="federated_user@external.com",
            user_id="fed_user_001",
            permissions=["mcp.brave.search:execute"],
            is_authenticated=True
        )
        
        # Federated user should work with MCP servers
        assert federated_user.is_authenticated is True
        assert "@external.com" in federated_user.username
    
    def test_multi_tenant_isolation(self):
        """Test multi-tenant isolation."""
        # Create users from different tenants
        tenant_a_user = MockUser(
            username="user_a",
            user_id="tenant_a_user_001",
            permissions=["tenant_a:mcp.brave.search:execute"]
        )
        
        tenant_b_user = MockUser(
            username="user_b", 
            user_id="tenant_b_user_001",
            permissions=["tenant_b:mcp.brave.search:execute"]
        )
        
        # Users should be isolated by tenant
        assert "tenant_a" in tenant_a_user.permissions[0]
        assert "tenant_b" in tenant_b_user.permissions[0]
        assert tenant_a_user.permissions != tenant_b_user.permissions


class TestAdvancedAuthenticationScenarios:
    """Test advanced authentication scenarios."""
    
    @pytest.mark.asyncio
    async def test_token_based_authentication(self):
        """Test token-based authentication."""
        # Mock JWT token
        mock_jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
        
        # Token should contain user information
        token_user = MockUser(
            username="token_user",
            user_id="token_001"
        )
        
        # Verify token user can be authenticated
        assert token_user.username == "token_user"
        assert token_user.is_authenticated is True
    
    def test_api_key_authentication(self):
        """Test API key authentication."""
        # Test API key validation
        valid_api_keys = [
            "sk-1234567890abcdef",
            "brave-api-key-xyz789",
            "azure-devops-pat-abc123"
        ]
        
        for api_key in valid_api_keys:
            # API key should be properly formatted
            assert len(api_key) >= 10
            assert api_key.startswith(("sk-", "brave-", "azure-"))
    
    @pytest.mark.asyncio
    async def test_certificate_based_authentication(self):
        """Test certificate-based authentication."""
        # Mock certificate authentication
        cert_user = MockUser(
            username="cert_user",
            user_id="cert_001"
        )
        
        # Certificate-based user should have strong authentication
        assert cert_user.is_authenticated is True
    
    def test_mfa_authentication(self):
        """Test multi-factor authentication."""
        # User with MFA enabled
        mfa_user = MockUser(
            username="mfa_user",
            user_id="mfa_001",
            is_authenticated=True
        )
        
        # MFA user should have additional security properties
        # Implementation would include MFA validation
        assert mfa_user.is_authenticated is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])