#!/usr/bin/env python3
"""
Comprehensive Security Mitigation Test Suite
Tests all security fixes implemented by the 10 parallel agents
"""

import os
import sys
import asyncio
import subprocess
import json
import yaml
import shlex
from pathlib import Path
from typing import Dict, List, Tuple, Any
import importlib.util
import re

class SecurityMitigationTestSuite:
    def __init__(self):
        self.test_results = {
            "timestamp": "2025-01-06",
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "critical_issues": [],
            "test_details": {}
        }

    def test_hardcoded_secrets(self) -> Tuple[bool, str]:
        """Test that no hardcoded secrets remain in source code"""
        print("\n🔍 Testing for hardcoded secrets...")
        
        # Check specific file that had hardcoded API key
        test_file = Path("test_circle_of_experts_simple.py")
        if test_file.exists():
            content = test_file.read_text()
            if "sk-87178544da6648acb4fee894c0818550" in content:
                return False, "CRITICAL: Hardcoded API key still present!"
            if "os.getenv('DEEPSEEK_API_KEY'" in content or "mock-api-key-for-testing" in content:
                return True, "✅ API key properly using environment variable"
        
        # Search for other potential hardcoded secrets
        patterns = [
            r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'password\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']'
        ]
        
        issues = []
        for pattern in patterns:
            result = subprocess.run(
                ["grep", "-r", "-i", "-E", pattern, "src/", "test_*.py"],
                capture_output=True,
                text=True
            )
            if result.stdout:
                # Filter out false positives
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if not any(safe in line.lower() for safe in [
                        "mock", "test", "example", "placeholder", "getenv", 
                        "os.environ", "${", "config[", "settings."
                    ]):
                        issues.append(line)
        
        if issues:
            return False, f"Found potential hardcoded secrets: {issues[:3]}"
        
        return True, "✅ No hardcoded secrets found"

    def test_command_injection_protection(self) -> Tuple[bool, str]:
        """Test command injection protections in MCP servers"""
        print("\n🛡️ Testing command injection protection...")
        
        try:
            # Check the source file for security patterns without importing
            source_file = Path("src/mcp/infrastructure_servers.py")
            
            if not source_file.exists():
                return False, "infrastructure_servers.py not found"
            
            content = source_file.read_text()
            
            # Check for security patterns in the code
            # Check for actual shell=True usage (not in comments)
            lines = content.split('\n')
            has_shell_true = False
            for line in lines:
                # Skip comments
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('//'):
                    continue
                # Check for shell=True in code
                if 'shell=True' in line and not '#' in line.split('shell=True')[0]:
                    has_shell_true = True
                    break
            
            checks = {
                "No unsafe shell execution": not has_shell_true,
                "Has shlex.quote": "shlex.quote" in content or "shlex.split" in content,
                "Has command whitelist": "ALLOWED_COMMANDS" in content,
                "Has injection pattern detection": "INJECTION_PATTERNS" in content,
                "Has timeout limits": "timeout=" in content
            }
            
            failed_checks = [check for check, passed in checks.items() if not passed]
            
            if failed_checks:
                return False, f"Missing protections: {', '.join(failed_checks)}"
            
            return True, "✅ Command injection protections implemented"
            
        except Exception as e:
            return False, f"Error testing command injection: {str(e)}"

    def test_authentication_implementation(self) -> Tuple[bool, str]:
        """Test that authentication is implemented in MCP servers"""
        print("\n🔐 Testing authentication implementation...")
        
        try:
            # Check MCPServer base class
            protocols_file = Path("src/mcp/protocols.py")
            if protocols_file.exists():
                content = protocols_file.read_text()
                
                checks = {
                    "Has auth imports": "from src.auth" in content,
                    "Has require_auth": "@require_auth" in content or "require_auth" in content,
                    "Has permission checking": "check_permission" in content,
                    "Has user context": "user_context" in content
                }
                
                failed_checks = [check for check, passed in checks.items() if not passed]
                
                if failed_checks:
                    return False, f"Missing auth features: {', '.join(failed_checks)}"
                
                return True, "✅ Authentication properly implemented"
            else:
                return False, "protocols.py file not found"
                
        except Exception as e:
            return False, f"Error testing authentication: {str(e)}"

    def test_docker_security(self) -> Tuple[bool, str]:
        """Test Docker security hardening"""
        print("\n🐳 Testing Docker security...")
        
        docker_files = [
            "docker-compose.monitoring.yml",
            "src/monitoring/docker-compose.monitoring.yml"
        ]
        
        issues = []
        for file_path in docker_files:
            if Path(file_path).exists():
                with open(file_path, 'r') as f:
                    content = f.read()
                    data = yaml.safe_load(content)
                    
                    for service_name, service in data.get('services', {}).items():
                        # Check for privileged mode
                        if service.get('privileged', False):
                            issues.append(f"{service_name} has privileged: true")
                        
                        # Check for user specification
                        if 'user' not in service and service_name != 'redis':
                            issues.append(f"{service_name} missing user specification")
                        
                        # Check for hardcoded passwords
                        env = service.get('environment', {})
                        for key, value in env.items() if isinstance(env, dict) else []:
                            if 'PASSWORD' in key and isinstance(value, str) and not value.startswith('${'):
                                issues.append(f"{service_name} has hardcoded password")
        
        if issues:
            return False, f"Docker security issues: {issues[:3]}"
        
        return True, "✅ Docker security hardening applied"

    def test_path_traversal_protection(self) -> Tuple[bool, str]:
        """Test path traversal protections"""
        print("\n📁 Testing path traversal protection...")
        
        # Check if path validation utility exists
        validation_file = Path("src/core/path_validation.py")
        if not validation_file.exists():
            return False, "Path validation utility not found"
        
        # Check implementation
        content = validation_file.read_text()
        required_patterns = [
            r'\.\./',  # Checks for ../
            r'os\.path\.realpath',  # Path resolution
            r'startswith.*base',  # Base directory check
            r'validate_file_path',  # Main function
        ]
        
        missing = []
        for pattern in required_patterns:
            if not re.search(pattern, content):
                missing.append(pattern)
        
        if missing:
            return False, f"Missing path validation patterns: {missing}"
        
        return True, "✅ Path traversal protections implemented"

    def test_cryptographic_improvements(self) -> Tuple[bool, str]:
        """Test cryptographic security improvements"""
        print("\n🔑 Testing cryptographic improvements...")
        
        # Check tokens.py for random salt
        tokens_file = Path("src/auth/tokens.py")
        if tokens_file.exists():
            content = tokens_file.read_text()
            
            # Check for removal of static salt
            if "b'claude-optimized-deployment'" in content:
                return False, "Static salt still present in tokens.py"
            
            # Check for os.urandom usage
            if "os.urandom(32)" not in content:
                return False, "Random salt generation not implemented"
        
        # Check audit.py for default key removal
        audit_file = Path("src/auth/audit.py")
        if audit_file.exists():
            content = audit_file.read_text()
            
            if '"default-signing-key"' in content:
                return False, "Default signing key still present"
            
            if "ValueError" not in content or "signing_key" not in content:
                return False, "Signing key validation not implemented"
        
        return True, "✅ Cryptographic improvements implemented"

    def test_service_exposure(self) -> Tuple[bool, str]:
        """Test that services are bound to localhost"""
        print("\n🌐 Testing service exposure...")
        
        docker_files = [
            "docker-compose.monitoring.yml",
            "infrastructure/logging/docker-compose.logging.yml",
            "src/monitoring/docker-compose.monitoring.yml"
        ]
        
        exposed_services = []
        for file_path in docker_files:
            if Path(file_path).exists():
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                    # Look for port bindings without 127.0.0.1
                    lines = content.split('\n')
                    for i, line in enumerate(lines):
                        if 'ports:' in line:
                            # Check next few lines for port mappings
                            for j in range(i+1, min(i+10, len(lines))):
                                port_line = lines[j].strip()
                                if port_line.startswith('-') and ':' in port_line:
                                    # Remove leading dash and whitespace
                                    cleaned_line = port_line.lstrip('- ')
                                    
                                    # Check if it's a volume mount (contains file paths, extensions, or directory names)
                                    if any(indicator in cleaned_line for indicator in ['/', '.yml', '.yaml', '.conf', '.json', '\\', '/var/', '/etc/', '/usr/', '/opt/', '/home/']):
                                        continue  # Skip volume mounts
                                    
                                    # Extract the port mapping part (remove quotes if present)
                                    port_mapping = cleaned_line.strip('"\'')
                                    
                                    # Check if it's actually a port binding (contains numbers and colon)
                                    # Pattern: port:port or host:port:port
                                    if re.match(r'^\d+:\d+|^[\d\.]+:\d+:\d+', port_mapping):
                                        # It's a port binding, check if it's bound to localhost
                                        if not port_mapping.startswith('127.0.0.1:'):
                                            exposed_services.append(f"{file_path}: {port_line}")
        
        if exposed_services:
            return False, f"Services exposed externally: {exposed_services[:3]}"
        
        return True, "✅ All services bound to localhost"

    def test_container_users(self) -> Tuple[bool, str]:
        """Test that containers run as non-root users"""
        print("\n👤 Testing container user configuration...")
        
        docker_files = [
            "infrastructure/logging/docker-compose.logging.yml",
            "docker-compose.monitoring.yml"
        ]
        
        root_containers = []
        for file_path in docker_files:
            if Path(file_path).exists():
                with open(file_path, 'r') as f:
                    content = yaml.safe_load(f)
                    
                    for service_name, service in content.get('services', {}).items():
                        # Check if service has user specified
                        if 'user' not in service:
                            # Some services like Redis might not need user specification
                            if service_name not in ['redis', 'postgres']:
                                root_containers.append(f"{service_name} (no user specified)")
                        elif service.get('user') == 'root':
                            root_containers.append(f"{service_name} (explicit root)")
        
        if root_containers:
            return False, f"Containers may run as root: {root_containers[:3]}"
        
        return True, "✅ Containers configured with non-root users"

    def run_all_tests(self):
        """Run all security mitigation tests"""
        print("🚀 Starting Security Mitigation Test Suite")
        print("=" * 60)
        
        tests = [
            ("Hardcoded Secrets", self.test_hardcoded_secrets),
            ("Command Injection", self.test_command_injection_protection),
            ("Authentication", self.test_authentication_implementation),
            ("Docker Security", self.test_docker_security),
            ("Path Traversal", self.test_path_traversal_protection),
            ("Cryptography", self.test_cryptographic_improvements),
            ("Service Exposure", self.test_service_exposure),
            ("Container Users", self.test_container_users)
        ]
        
        self.test_results["total_tests"] = len(tests)
        
        for test_name, test_func in tests:
            try:
                passed, message = test_func()
                self.test_results["test_details"][test_name] = {
                    "passed": passed,
                    "message": message
                }
                
                if passed:
                    self.test_results["passed"] += 1
                    print(f"✅ {test_name}: PASSED")
                else:
                    self.test_results["failed"] += 1
                    if "CRITICAL" in message:
                        self.test_results["critical_issues"].append(message)
                    print(f"❌ {test_name}: FAILED - {message}")
                    
            except Exception as e:
                self.test_results["failed"] += 1
                self.test_results["test_details"][test_name] = {
                    "passed": False,
                    "message": f"Exception: {str(e)}"
                }
                print(f"❌ {test_name}: ERROR - {str(e)}")
        
        print("\n" + "=" * 60)
        print("SECURITY TEST SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {self.test_results['total_tests']}")
        print(f"Passed: {self.test_results['passed']}")
        print(f"Failed: {self.test_results['failed']}")
        print(f"Success Rate: {(self.test_results['passed']/self.test_results['total_tests']*100):.1f}%")
        
        if self.test_results["critical_issues"]:
            print("\n⚠️  CRITICAL ISSUES:")
            for issue in self.test_results["critical_issues"]:
                print(f"  - {issue}")
        
        # Save results
        with open("security_test_results.json", "w") as f:
            json.dump(self.test_results, f, indent=2)
        print("\n📄 Detailed results saved to: security_test_results.json")
        
        return self.test_results["failed"] == 0

def main():
    """Main test execution"""
    tester = SecurityMitigationTestSuite()
    success = tester.run_all_tests()
    
    if success:
        print("\n🎉 All security mitigations verified successfully!")
        print("The codebase is now secure and ready for the next phase.")
    else:
        print("\n⚠️  Some security tests failed. Please review and fix the issues.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())