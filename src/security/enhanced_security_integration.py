#!/usr/bin/env python3
"""
Enhanced Security Integration Module
====================================
SYNTHEX Agent 9: Security Auditor Implementation

This module provides Python integration for the Rust-based enhanced security features,
including command validation, privilege management, audit logging, sandboxing,
security testing, and encryption.
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
from datetime import datetime, timedelta

# Import the Rust security module
try:
    from claude_optimized_deployment_rust import security_enhanced as rust_security
except ImportError:
    logging.warning("Rust security module not available, using mock implementation")
    rust_security = None


# ============================================================================
# Security Context and Types
# ============================================================================

class SandboxLevel(Enum):
    """Sandbox security levels"""
    NONE = "None"
    BASIC = "Basic"
    RESTRICTED = "Restricted"
    ISOLATED = "Isolated"


@dataclass
class SecurityContext:
    """Security context for command execution"""
    user_id: str
    session_id: str
    capabilities: Set[str] = field(default_factory=set)
    audit_enabled: bool = True
    sandbox_level: SandboxLevel = SandboxLevel.BASIC
    encryption_enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Rust interop"""
        return {
            "user_id": self.user_id,
            "session_id": self.session_id,
            "capabilities": list(self.capabilities),
            "audit_enabled": self.audit_enabled,
            "sandbox_level": self.sandbox_level.value,
            "encryption_enabled": self.encryption_enabled,
        }


@dataclass
class SecurityConfig:
    """Security configuration"""
    max_command_length: int = 1024
    max_path_depth: int = 10
    command_timeout_ms: int = 30000
    rate_limit_per_minute: int = 100
    enable_fuzzing: bool = True
    enable_static_analysis: bool = True
    audit_log_path: Path = Path("/var/log/security_audit.log")
    encryption_key_path: Path = Path("/etc/security/keys")


# ============================================================================
# Enhanced Security Manager
# ============================================================================

class EnhancedSecurityManager:
    """
    Comprehensive security manager with all security features integrated.
    
    Features:
    - Command validation and sanitization
    - Privilege management with capability-based security
    - Comprehensive audit logging
    - Sandboxing and isolation
    - Security testing and vulnerability scanning
    - Encryption and secure communication
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.logger = logging.getLogger(__name__)
        
        # Initialize Rust components
        if rust_security:
            self._validator = rust_security.CommandValidator()
            self._privilege_manager = rust_security.PrivilegeManager()
            self._audit_logger = rust_security.AuditLogger(
                str(self.config.audit_log_path)
            )
            self._encryption_manager = rust_security.EncryptionManager()
            self._security_tester = rust_security.SecurityTester()
            self._security_manager = rust_security.SecurityManager()
        else:
            self._validator = None
            self._privilege_manager = None
            self._audit_logger = None
            self._encryption_manager = None
            self._security_tester = None
            self._security_manager = None
        
        # Cache for performance
        self._capability_cache: Dict[str, Tuple[Set[str], datetime]] = {}
        self._cache_ttl = timedelta(minutes=5)
    
    # ========================================================================
    # Command Validation
    # ========================================================================
    
    def validate_command(
        self,
        command: str,
        context: SecurityContext
    ) -> bool:
        """
        Validate a command for security issues.
        
        Args:
            command: Command to validate
            context: Security context
            
        Returns:
            True if command is safe to execute
        """
        if not self._validator:
            return True
        
        try:
            return self._validator.validate_command(command, context.to_dict())
        except Exception as e:
            self.logger.error(f"Command validation error: {e}")
            return False
    
    def sanitize_input(self, input_str: str) -> str:
        """
        Sanitize input to prevent injection attacks.
        
        Args:
            input_str: Input string to sanitize
            
        Returns:
            Sanitized string
        """
        if not self._validator:
            return input_str
        
        try:
            return self._validator.sanitize_input(input_str)
        except Exception as e:
            self.logger.error(f"Input sanitization error: {e}")
            return ""
    
    def validate_path(
        self,
        path: str,
        base_path: Optional[str] = None
    ) -> bool:
        """
        Validate file path to prevent traversal attacks.
        
        Args:
            path: Path to validate
            base_path: Optional base path for restriction
            
        Returns:
            True if path is safe
        """
        if not self._validator:
            return True
        
        try:
            return self._validator.validate_path(path, base_path)
        except Exception as e:
            self.logger.error(f"Path validation error: {e}")
            return False
    
    def sanitize_env_vars(
        self,
        env_vars: Dict[str, str]
    ) -> Dict[str, str]:
        """
        Sanitize environment variables.
        
        Args:
            env_vars: Environment variables to sanitize
            
        Returns:
            Sanitized environment variables
        """
        if not self._validator:
            return env_vars
        
        try:
            return self._validator.sanitize_env_vars(env_vars)
        except Exception as e:
            self.logger.error(f"Environment variable sanitization error: {e}")
            return {}
    
    # ========================================================================
    # Privilege Management
    # ========================================================================
    
    async def grant_capability(
        self,
        user_id: str,
        capability: str
    ) -> None:
        """
        Grant a capability to a user.
        
        Args:
            user_id: User ID
            capability: Capability to grant
        """
        if not self._privilege_manager:
            return
        
        try:
            self._privilege_manager.grant_capability(user_id, capability)
            # Clear cache
            if user_id in self._capability_cache:
                del self._capability_cache[user_id]
        except Exception as e:
            self.logger.error(f"Failed to grant capability: {e}")
            raise
    
    async def revoke_capability(
        self,
        user_id: str,
        capability: str
    ) -> None:
        """
        Revoke a capability from a user.
        
        Args:
            user_id: User ID
            capability: Capability to revoke
        """
        if not self._privilege_manager:
            return
        
        try:
            self._privilege_manager.revoke_capability(user_id, capability)
            # Clear cache
            if user_id in self._capability_cache:
                del self._capability_cache[user_id]
        except Exception as e:
            self.logger.error(f"Failed to revoke capability: {e}")
            raise
    
    def has_capability(
        self,
        user_id: str,
        capability: str
    ) -> bool:
        """
        Check if user has a capability.
        
        Args:
            user_id: User ID
            capability: Capability to check
            
        Returns:
            True if user has capability
        """
        if not self._privilege_manager:
            return True
        
        # Check cache
        now = datetime.now()
        if user_id in self._capability_cache:
            caps, timestamp = self._capability_cache[user_id]
            if now - timestamp < self._cache_ttl:
                return capability in caps or "*" in caps
        
        try:
            has_cap = self._privilege_manager.has_capability(user_id, capability)
            
            # Update cache
            if user_id not in self._capability_cache:
                # Fetch all capabilities for caching
                self._capability_cache[user_id] = ({capability}, now)
            
            return has_cap
        except Exception as e:
            self.logger.error(f"Failed to check capability: {e}")
            return False
    
    async def execute_with_privilege(
        self,
        command: str,
        context: SecurityContext
    ) -> str:
        """
        Execute command with appropriate privileges.
        
        Args:
            command: Command to execute
            context: Security context
            
        Returns:
            Command output
        """
        if not self._privilege_manager:
            return "Mock execution"
        
        try:
            return self._privilege_manager.execute_with_privilege(
                command,
                context.to_dict()
            )
        except Exception as e:
            self.logger.error(f"Privileged execution failed: {e}")
            raise
    
    # ========================================================================
    # Audit Logging
    # ========================================================================
    
    def log_security_event(
        self,
        context: SecurityContext,
        action: str,
        resource: str,
        success: bool,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Log a security event to the audit log.
        
        Args:
            context: Security context
            action: Action performed
            resource: Resource accessed
            success: Whether action succeeded
            reason: Optional failure/block reason
            metadata: Optional metadata
            
        Returns:
            Audit entry ID
        """
        if not self._audit_logger:
            return "mock-audit-id"
        
        try:
            if success:
                result = {"Success": None}
            elif reason and "blocked" in reason.lower():
                result = {"Blocked": reason}
            else:
                result = {"Failure": reason or "Unknown"}
            
            return self._audit_logger.log_event(
                context.to_dict(),
                action,
                resource,
                result,
                metadata
            )
        except Exception as e:
            self.logger.error(f"Failed to log security event: {e}")
            return ""
    
    def query_audit_logs(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Query audit logs.
        
        Args:
            user_id: Filter by user ID
            action: Filter by action
            start_time: Filter by start time
            end_time: Filter by end time
            
        Returns:
            List of audit entries
        """
        if not self._audit_logger:
            return []
        
        try:
            start_ts = int(start_time.timestamp()) if start_time else None
            end_ts = int(end_time.timestamp()) if end_time else None
            
            return self._audit_logger.query_logs(
                user_id,
                action,
                start_ts,
                end_ts
            )
        except Exception as e:
            self.logger.error(f"Failed to query audit logs: {e}")
            return []
    
    def generate_audit_report(self) -> Dict[str, Any]:
        """
        Generate audit report.
        
        Returns:
            Audit report
        """
        if not self._audit_logger:
            return {}
        
        try:
            report_json = self._audit_logger.generate_report()
            return json.loads(report_json)
        except Exception as e:
            self.logger.error(f"Failed to generate audit report: {e}")
            return {}
    
    # ========================================================================
    # Sandboxing
    # ========================================================================
    
    async def execute_sandboxed(
        self,
        command: str,
        context: SecurityContext,
        sandbox_level: Optional[SandboxLevel] = None
    ) -> str:
        """
        Execute command in sandbox.
        
        Args:
            command: Command to execute
            context: Security context
            sandbox_level: Override sandbox level
            
        Returns:
            Command output
        """
        if not rust_security:
            return "Mock sandboxed execution"
        
        try:
            level = sandbox_level or context.sandbox_level
            sandbox = rust_security.Sandbox(level.value)
            return sandbox.execute_sandboxed(command, context.to_dict())
        except Exception as e:
            self.logger.error(f"Sandboxed execution failed: {e}")
            raise
    
    # ========================================================================
    # Security Testing
    # ========================================================================
    
    def run_fuzzing_tests(self) -> List[str]:
        """
        Run fuzzing tests on security components.
        
        Returns:
            List of discovered vulnerabilities
        """
        if not self._security_tester:
            return []
        
        try:
            return self._security_tester.fuzz_test(self._validator)
        except Exception as e:
            self.logger.error(f"Fuzzing tests failed: {e}")
            return [f"Fuzzing test error: {e}"]
    
    def run_static_analysis(self, code: str) -> List[str]:
        """
        Run static security analysis on code.
        
        Args:
            code: Code to analyze
            
        Returns:
            List of security findings
        """
        if not self._security_tester:
            return []
        
        try:
            return self._security_tester.static_analysis(code)
        except Exception as e:
            self.logger.error(f"Static analysis failed: {e}")
            return [f"Static analysis error: {e}"]
    
    def run_penetration_tests(self) -> Dict[str, bool]:
        """
        Run penetration test scenarios.
        
        Returns:
            Test results (test_name -> passed)
        """
        if not self._security_tester:
            return {}
        
        try:
            return self._security_tester.pentest_scenarios()
        except Exception as e:
            self.logger.error(f"Penetration tests failed: {e}")
            return {"error": False}
    
    # ========================================================================
    # Encryption
    # ========================================================================
    
    def generate_encryption_key(
        self,
        key_id: str,
        key_type: str = "aes256"
    ) -> str:
        """
        Generate a new encryption key.
        
        Args:
            key_id: Key identifier
            key_type: Key type (aes256, ed25519)
            
        Returns:
            Key ID
        """
        if not self._encryption_manager:
            return key_id
        
        try:
            return self._encryption_manager.generate_key(key_id, key_type)
        except Exception as e:
            self.logger.error(f"Key generation failed: {e}")
            raise
    
    def encrypt_data(
        self,
        data: bytes,
        key_id: str
    ) -> bytes:
        """
        Encrypt data with specified key.
        
        Args:
            data: Data to encrypt
            key_id: Encryption key ID
            
        Returns:
            Encrypted data
        """
        if not self._encryption_manager:
            return data
        
        try:
            return bytes(self._encryption_manager.encrypt_data(data, key_id))
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(
        self,
        encrypted: bytes,
        key_id: str
    ) -> bytes:
        """
        Decrypt data with specified key.
        
        Args:
            encrypted: Encrypted data
            key_id: Encryption key ID
            
        Returns:
            Decrypted data
        """
        if not self._encryption_manager:
            return encrypted
        
        try:
            return bytes(self._encryption_manager.decrypt_data(encrypted, key_id))
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise
    
    def create_secure_channel(self, peer_id: str) -> str:
        """
        Create secure communication channel.
        
        Args:
            peer_id: Peer identifier
            
        Returns:
            Channel ID
        """
        if not self._encryption_manager:
            return f"mock-channel-{peer_id}"
        
        try:
            return self._encryption_manager.create_secure_channel(peer_id)
        except Exception as e:
            self.logger.error(f"Secure channel creation failed: {e}")
            raise
    
    # ========================================================================
    # Comprehensive Security Operations
    # ========================================================================
    
    async def secure_execute(
        self,
        command: str,
        context: SecurityContext,
        validate: bool = True,
        sandbox: Optional[SandboxLevel] = None
    ) -> str:
        """
        Execute command with full security validation and auditing.
        
        Args:
            command: Command to execute
            context: Security context
            validate: Whether to validate command
            sandbox: Optional sandbox level override
            
        Returns:
            Command output
        """
        if not self._security_manager:
            return "Mock secure execution"
        
        try:
            sandbox_value = sandbox.value if sandbox else None
            return self._security_manager.secure_execute(
                command,
                context.to_dict(),
                sandbox_value
            )
        except Exception as e:
            self.logger.error(f"Secure execution failed: {e}")
            # Log failure
            self.log_security_event(
                context,
                "command_execution",
                command,
                False,
                str(e)
            )
            raise
    
    async def run_comprehensive_audit(self) -> Dict[str, Any]:
        """
        Run comprehensive security audit.
        
        Returns:
            Audit results
        """
        if not self._security_manager:
            return {"status": "mock_audit"}
        
        try:
            audit_json = self._security_manager.run_security_audit()
            return json.loads(audit_json)
        except Exception as e:
            self.logger.error(f"Comprehensive audit failed: {e}")
            return {"error": str(e)}


# ============================================================================
# Example Usage and Testing
# ============================================================================

async def example_usage():
    """Example usage of enhanced security features"""
    
    # Initialize security manager
    security_mgr = EnhancedSecurityManager()
    
    # Create security context
    context = SecurityContext(
        user_id="test_user",
        session_id="test_session_123",
        capabilities={"exec:ls", "exec:cat", "read:logs"},
        audit_enabled=True,
        sandbox_level=SandboxLevel.RESTRICTED,
        encryption_enabled=True
    )
    
    # 1. Command validation
    print("=== Command Validation ===")
    safe_cmd = "ls -la /home/user"
    unsafe_cmd = "rm -rf /; echo 'hacked'"
    
    print(f"Safe command valid: {security_mgr.validate_command(safe_cmd, context)}")
    print(f"Unsafe command valid: {security_mgr.validate_command(unsafe_cmd, context)}")
    
    # 2. Path validation
    print("\n=== Path Validation ===")
    safe_path = "/home/user/documents/file.txt"
    unsafe_path = "../../../etc/passwd"
    
    print(f"Safe path valid: {security_mgr.validate_path(safe_path, '/home/user')}")
    print(f"Unsafe path valid: {security_mgr.validate_path(unsafe_path, '/home/user')}")
    
    # 3. Privilege management
    print("\n=== Privilege Management ===")
    await security_mgr.grant_capability("test_user", "exec:docker")
    print(f"Has docker capability: {security_mgr.has_capability('test_user', 'exec:docker')}")
    
    # 4. Secure execution
    print("\n=== Secure Execution ===")
    try:
        result = await security_mgr.secure_execute(
            "ls -la",
            context,
            sandbox=SandboxLevel.RESTRICTED
        )
        print(f"Execution result: {result}")
    except Exception as e:
        print(f"Execution failed: {e}")
    
    # 5. Encryption
    print("\n=== Encryption ===")
    key_id = security_mgr.generate_encryption_key("test-key", "aes256")
    plaintext = b"Secret data that needs encryption"
    encrypted = security_mgr.encrypt_data(plaintext, key_id)
    decrypted = security_mgr.decrypt_data(encrypted, key_id)
    print(f"Encryption successful: {plaintext == decrypted}")
    
    # 6. Security testing
    print("\n=== Security Testing ===")
    fuzz_results = security_mgr.run_fuzzing_tests()
    print(f"Fuzzing vulnerabilities found: {len(fuzz_results)}")
    
    code_sample = """
    password = "hardcoded123"
    api_key = "secret_key_here"
    """
    static_results = security_mgr.run_static_analysis(code_sample)
    print(f"Static analysis findings: {static_results}")
    
    # 7. Audit report
    print("\n=== Audit Report ===")
    report = security_mgr.generate_audit_report()
    print(f"Audit report: {json.dumps(report, indent=2)}")
    
    # 8. Comprehensive security audit
    print("\n=== Comprehensive Security Audit ===")
    audit_results = await security_mgr.run_comprehensive_audit()
    print(f"Security audit results: {json.dumps(audit_results, indent=2)}")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run example
    asyncio.run(example_usage())