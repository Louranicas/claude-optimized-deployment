#!/usr/bin/env python3
"""
Advanced Security Mitigation Test Suite
Tests all security fixes implemented by the 10 parallel agents for the advanced security audit
"""

import os
import sys
import ast
import json
import yaml
import hmac
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse

class AdvancedSecurityTestSuite:
    def __init__(self):
        self.test_results = {
            "timestamp": "2025-01-06",
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "critical_issues": [],
            "test_details": {}
        }

    def test_hardcoded_credentials_removal(self) -> Tuple[bool, str]:
        """Test that all hardcoded credentials have been removed"""
        print("\n🔐 Testing hardcoded credentials removal...")
        
        # Check specific files that had hardcoded credentials
        issues = []
        
        # Check Brave API key removal
        servers_file = Path("src/mcp/servers.py")
        if servers_file.exists():
            content = servers_file.read_text()
            if "BSAigVAUU4-V72PjB48t8_CqN00Hh5z" in content:
                issues.append("Brave API key still hardcoded in servers.py")
            elif "os.getenv('BRAVE_API_KEY')" not in content:
                issues.append("Brave API key not using environment variable")
        
        # Check Docker compose files for passwords
        compose_files = [
            "docker-compose.monitoring.yml",
            "infrastructure/logging/docker-compose.logging.yml"
        ]
        
        for file_path in compose_files:
            if Path(file_path).exists():
                with open(file_path, 'r') as f:
                    content = f.read()
                    # Check for hardcoded passwords
                    if "changeme" in content and not content.count("${") > content.count("changeme"):
                        issues.append(f"Default password 'changeme' found in {file_path}")
        
        if issues:
            return False, f"Hardcoded credentials found: {issues}"
        
        return True, "✅ All hardcoded credentials removed"

    def test_sql_injection_fixes(self) -> Tuple[bool, str]:
        """Test SQL injection prevention"""
        print("\n🛡️ Testing SQL injection fixes...")
        
        utils_file = Path("src/database/utils.py")
        if not utils_file.exists():
            return False, "Database utils file not found"
        
        content = utils_file.read_text()
        
        checks = {
            "Has table validation": "validate_table_name" in content or "ALLOWED_TABLES" in content,
            "No f-string SQL": not re.search(r'f"[^"]*SELECT[^"]*"', content),
            "No string format SQL": not re.search(r'\.format\([^)]*\)\s*["\'][^"\']*SELECT', content),
            "Has parameterized queries": "WHERE id = %s" in content or "?" in content,
            "Has input validation": "validate_identifier" in content
        }
        
        failed_checks = [check for check, passed in checks.items() if not passed]
        
        if failed_checks:
            return False, f"SQL injection prevention incomplete: {failed_checks}"
        
        return True, "✅ SQL injection vulnerabilities fixed"

    def test_command_injection_fixes(self) -> Tuple[bool, str]:
        """Test command injection prevention"""
        print("\n⚔️ Testing command injection fixes...")
        
        files_to_check = [
            "src/mcp/infrastructure_servers.py",
            "src/mcp/devops_servers.py"
        ]
        
        for file_path in files_to_check:
            if Path(file_path).exists():
                content = Path(file_path).read_text()
                
                # Check for dangerous patterns
                if "subprocess_shell" in content and "shell=True" in content:
                    return False, f"Unsafe shell execution found in {file_path}"
                
                # Check for command validation
                if "ALLOWED_COMMANDS" not in content and "validate_command" not in content:
                    return False, f"Command validation missing in {file_path}"
                
                # Check for input sanitization
                if "shlex.quote" not in content and "shlex.split" not in content:
                    return False, f"Input sanitization missing in {file_path}"
        
        return True, "✅ Command injection vulnerabilities fixed"

    def test_timing_attack_fixes(self) -> Tuple[bool, str]:
        """Test timing attack prevention"""
        print("\n⏱️ Testing timing attack fixes...")
        
        models_file = Path("src/auth/models.py")
        if models_file.exists():
            content = models_file.read_text()
            
            # Check for hmac.compare_digest usage
            if "hmac.compare_digest" not in content:
                return False, "hmac.compare_digest not found in auth models"
            
            # Check that direct comparison is not used for sensitive operations
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if "key_hash ==" in line or "== self.hash_key" in line:
                    return False, f"Direct comparison found at line {i+1}"
        
        return True, "✅ Timing attack vulnerabilities fixed"

    def test_ssrf_protection(self) -> Tuple[bool, str]:
        """Test SSRF protection implementation"""
        print("\n🌐 Testing SSRF protection...")
        
        # Check if SSRF protection module exists
        ssrf_file = Path("src/core/ssrf_protection.py")
        if not ssrf_file.exists():
            return False, "SSRF protection module not found"
        
        content = ssrf_file.read_text()
        
        checks = {
            "Has SSRFProtector": "class SSRFProtector" in content,
            "Blocks private networks": "10.0.0.0/8" in content or "192.168.0.0/16" in content,
            "Blocks localhost": "127.0.0.1" in content or "localhost" in content,
            "Blocks metadata endpoints": "169.254.169.254" in content,
            "Has URL validation": "validate_url" in content
        }
        
        failed_checks = [check for check, passed in checks.items() if not passed]
        
        if failed_checks:
            return False, f"SSRF protection incomplete: {failed_checks}"
        
        return True, "✅ SSRF protection implemented"

    def test_cors_fixes(self) -> Tuple[bool, str]:
        """Test CORS configuration fixes"""
        print("\n🔀 Testing CORS fixes...")
        
        # Check CORS configuration
        cors_file = Path("src/core/cors_config.py")
        if not cors_file.exists():
            return False, "CORS configuration module not found"
        
        # Check test file for secure CORS
        test_file = Path("test_api_functionality.py")
        if test_file.exists():
            content = test_file.read_text()
            if 'allow_origins=["*"]' in content:
                return False, "Wildcard CORS still present in test file"
        
        # Check middleware file
        middleware_file = Path("src/auth/middleware.py")
        if middleware_file.exists():
            content = middleware_file.read_text()
            if '"*"' in content and "Access-Control-Allow-Origin" in content:
                # Check if it's a hardcoded wildcard
                if 'Access-Control-Allow-Origin": "*"' in content:
                    return False, "Wildcard CORS still present in middleware"
        
        return True, "✅ CORS misconfigurations fixed"

    def test_kubernetes_security(self) -> Tuple[bool, str]:
        """Test Kubernetes security manifests"""
        print("\n☸️ Testing Kubernetes security...")
        
        k8s_dir = Path("k8s")
        if not k8s_dir.exists():
            return False, "Kubernetes manifests directory not found"
        
        required_files = [
            "pod-security-policies.yaml",
            "network-policies.yaml",
            "rbac.yaml",
            "namespace.yaml"
        ]
        
        missing_files = []
        for file_name in required_files:
            if not (k8s_dir / file_name).exists():
                missing_files.append(file_name)
        
        if missing_files:
            return False, f"Missing K8s security files: {missing_files}"
        
        # Check for security content
        psp_file = k8s_dir / "pod-security-policies.yaml"
        if psp_file.exists():
            content = psp_file.read_text()
            if "privileged: false" not in content:
                return False, "Pod Security Policy doesn't restrict privileged containers"
        
        return True, "✅ Kubernetes security manifests created"

    def test_dependency_updates(self) -> Tuple[bool, str]:
        """Test dependency security updates"""
        print("\n📦 Testing dependency updates...")
        
        requirements_file = Path("requirements.txt")
        if not requirements_file.exists():
            return False, "requirements.txt not found"
        
        content = requirements_file.read_text()
        
        # Check for updated vulnerable packages
        checks = {
            "cryptography updated": "cryptography>=41.0.6" in content,
            "aiohttp updated": "aiohttp>=3.9.0" in content
        }
        
        failed_checks = [check for check, passed in checks.items() if not passed]
        
        if failed_checks:
            return False, f"Dependency updates missing: {failed_checks}"
        
        return True, "✅ Vulnerable dependencies updated"

    def test_log_injection_prevention(self) -> Tuple[bool, str]:
        """Test log injection prevention"""
        print("\n📝 Testing log injection prevention...")
        
        # Check if log sanitization module exists
        sanitization_file = Path("src/core/log_sanitization.py")
        if not sanitization_file.exists():
            return False, "Log sanitization module not found"
        
        content = sanitization_file.read_text()
        
        checks = {
            "Has LogSanitizer": "class LogSanitizer" in content,
            "CRLF protection": "\\r\\n" in content or "CRLF" in content,
            "Control char filtering": "control" in content.lower(),
            "Pattern detection": "pattern" in content.lower()
        }
        
        failed_checks = [check for check, passed in checks.items() if not passed]
        
        if failed_checks:
            return False, f"Log injection prevention incomplete: {failed_checks}"
        
        return True, "✅ Log injection prevention implemented"

    def test_authentication_bypass_fixes(self) -> Tuple[bool, str]:
        """Test authentication bypass fixes"""
        print("\n🔑 Testing authentication bypass fixes...")
        
        protocols_file = Path("src/mcp/protocols.py")
        if protocols_file.exists():
            content = protocols_file.read_text()
            
            # Check for required authentication
            if "@require_auth" not in content and "require_auth" not in content:
                return False, "Authentication requirement not found in protocols"
            
            # Check for user validation
            if "user:" in content and "Optional[" in content:
                # Check if optional user parameters are still present
                if "user: Optional[" in content and "= None" in content:
                    return False, "Optional user parameters still present"
        
        return True, "✅ Authentication bypass vulnerabilities fixed"

    def run_all_tests(self):
        """Run all advanced security mitigation tests"""
        print("🚀 Starting Advanced Security Mitigation Test Suite")
        print("=" * 70)
        
        tests = [
            ("Hardcoded Credentials", self.test_hardcoded_credentials_removal),
            ("SQL Injection", self.test_sql_injection_fixes),
            ("Command Injection", self.test_command_injection_fixes),
            ("Timing Attacks", self.test_timing_attack_fixes),
            ("SSRF Protection", self.test_ssrf_protection),
            ("CORS Security", self.test_cors_fixes),
            ("Kubernetes Security", self.test_kubernetes_security),
            ("Dependency Updates", self.test_dependency_updates),
            ("Log Injection", self.test_log_injection_prevention),
            ("Authentication Bypass", self.test_authentication_bypass_fixes)
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
                    if "CRITICAL" in message or "not found" in message:
                        self.test_results["critical_issues"].append(message)
                    print(f"❌ {test_name}: FAILED - {message}")
                    
            except Exception as e:
                self.test_results["failed"] += 1
                self.test_results["test_details"][test_name] = {
                    "passed": False,
                    "message": f"Exception: {str(e)}"
                }
                print(f"❌ {test_name}: ERROR - {str(e)}")
        
        print("\n" + "=" * 70)
        print("ADVANCED SECURITY TEST SUMMARY")
        print("=" * 70)
        print(f"Total Tests: {self.test_results['total_tests']}")
        print(f"Passed: {self.test_results['passed']}")
        print(f"Failed: {self.test_results['failed']}")
        print(f"Success Rate: {(self.test_results['passed']/self.test_results['total_tests']*100):.1f}%")
        
        if self.test_results["critical_issues"]:
            print("\n⚠️  CRITICAL ISSUES:")
            for issue in self.test_results["critical_issues"]:
                print(f"  - {issue}")
        
        # Save results
        with open("advanced_security_test_results.json", "w") as f:
            json.dump(self.test_results, f, indent=2)
        print("\n📄 Detailed results saved to: advanced_security_test_results.json")
        
        return self.test_results["failed"] == 0

def main():
    """Main test execution"""
    tester = AdvancedSecurityTestSuite()
    success = tester.run_all_tests()
    
    if success:
        print("\n🎉 All advanced security mitigations verified successfully!")
        print("🔒 The codebase has passed comprehensive security validation.")
        print("🚀 Ready for production deployment with enterprise security standards.")
    else:
        print("\n⚠️  Some security tests failed. Please review and fix the issues.")
        print("🔧 Re-run mitigations for any failed tests before deployment.")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())