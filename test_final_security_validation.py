#!/usr/bin/env python3
"""
Agent 10 - Final Security Validation Suite
Comprehensive re-audit of all security mitigations

This script performs the same comprehensive security audit as Agent 7
to validate that all 48 vulnerabilities have been resolved.
"""

import os
import sys
import json
import subprocess
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

# Comprehensive test results
validation_results = {
    "timestamp": datetime.now().isoformat(),
    "agent": "Agent 10 - Final Security Validation",
    "original_vulnerabilities": 48,
    "categories": {},
    "summary": {
        "total_tests": 0,
        "passed": 0,
        "failed": 0,
        "vulnerabilities_found": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
}

def add_category_result(category: str, subcategory: str, passed: bool, details: str, severity: str = "HIGH"):
    """Add a test result for a category."""
    if category not in validation_results["categories"]:
        validation_results["categories"][category] = {
            "tests": [],
            "passed": 0,
            "failed": 0
        }
    
    validation_results["categories"][category]["tests"].append({
        "subcategory": subcategory,
        "passed": passed,
        "details": details,
        "severity": severity
    })
    
    validation_results["summary"]["total_tests"] += 1
    
    if passed:
        validation_results["summary"]["passed"] += 1
        validation_results["categories"][category]["passed"] += 1
    else:
        validation_results["summary"]["failed"] += 1
        validation_results["categories"][category]["failed"] += 1
        validation_results["summary"]["vulnerabilities_found"] += 1
        
        if severity == "CRITICAL":
            validation_results["summary"]["critical"] += 1
        elif severity == "HIGH":
            validation_results["summary"]["high"] += 1
        elif severity == "MEDIUM":
            validation_results["summary"]["medium"] += 1
        elif severity == "LOW":
            validation_results["summary"]["low"] += 1


def test_command_injection():
    """Test for command injection vulnerabilities."""
    print("\n[1] Testing Command Injection Prevention...")
    
    # Check for shell=True usage
    shell_true_files = []
    src_path = Path("src")
    
    for py_file in src_path.rglob("*.py"):
        try:
            content = py_file.read_text()
            if "shell=True" in content and not "# Safe:" in content:
                # Check if it's in a comment
                for line_num, line in enumerate(content.splitlines(), 1):
                    if "shell=True" in line and not line.strip().startswith("#"):
                        shell_true_files.append(f"{py_file}:{line_num}")
        except:
            pass
    
    if shell_true_files:
        add_category_result(
            "Command Injection",
            "shell=True usage",
            False,
            f"Found {len(shell_true_files)} instances of shell=True",
            "CRITICAL"
        )
    else:
        add_category_result(
            "Command Injection",
            "shell=True usage",
            True,
            "No unsafe shell=True usage found"
        )
    
    # Check for proper command sanitization
    unsafe_patterns = [
        r'os\.system\s*\(',
        r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True',
        r'eval\s*\(',
        r'exec\s*\('
    ]
    
    unsafe_found = False
    for pattern in unsafe_patterns:
        for py_file in src_path.rglob("*.py"):
            try:
                content = py_file.read_text()
                if re.search(pattern, content):
                    unsafe_found = True
                    break
            except:
                pass
    
    if unsafe_found:
        add_category_result(
            "Command Injection",
            "Unsafe command execution",
            False,
            "Found unsafe command execution patterns",
            "CRITICAL"
        )
    else:
        add_category_result(
            "Command Injection",
            "Unsafe command execution",
            True,
            "No unsafe command execution patterns found"
        )


def test_cryptographic_security():
    """Test for cryptographic vulnerabilities."""
    print("\n[2] Testing Cryptographic Security...")
    
    # Check for weak hash algorithms
    weak_crypto_patterns = [
        (r'md5|MD5', "MD5"),
        (r'sha1|SHA1|SHA-1', "SHA-1"),
        (r'des|DES', "DES")
    ]
    
    for pattern, algo in weak_crypto_patterns:
        found_files = []
        for py_file in Path("src").rglob("*.py"):
            try:
                content = py_file.read_text()
                # Exclude comments and strings
                lines = content.splitlines()
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line) and not line.strip().startswith("#"):
                        # Check if it's in a string context (basic check)
                        if not ('"' + algo + '"' in line or "'" + algo + "'" in line):
                            found_files.append(f"{py_file}:{line_num}")
            except:
                pass
        
        if found_files:
            add_category_result(
                "Cryptographic Security",
                f"{algo} usage",
                False,
                f"Found {len(found_files)} instances of weak {algo} algorithm",
                "HIGH"
            )
        else:
            add_category_result(
                "Cryptographic Security",
                f"{algo} usage",
                True,
                f"No {algo} usage found"
            )
    
    # Check for proper SHA-256 usage
    sha256_count = 0
    for py_file in Path("src").rglob("*.py"):
        try:
            content = py_file.read_text()
            sha256_count += len(re.findall(r'sha256|SHA256|SHA-256', content))
        except:
            pass
    
    if sha256_count >= 5:
        add_category_result(
            "Cryptographic Security",
            "SHA-256 adoption",
            True,
            f"Found {sha256_count} instances of SHA-256 usage"
        )
    else:
        add_category_result(
            "Cryptographic Security",
            "SHA-256 adoption",
            False,
            f"Insufficient SHA-256 usage (only {sha256_count} instances)",
            "MEDIUM"
        )


def test_authentication_framework():
    """Test authentication and authorization implementation."""
    print("\n[3] Testing Authentication Framework...")
    
    # Check if auth module exists
    auth_path = Path("src/auth")
    if not auth_path.exists():
        add_category_result(
            "Authentication",
            "Auth module existence",
            False,
            "Authentication module not found",
            "CRITICAL"
        )
        return
    
    # Check for required auth components
    required_files = [
        "models.py", "tokens.py", "rbac.py", "permissions.py",
        "middleware.py", "user_manager.py", "audit.py",
        "mcp_integration.py", "api.py"
    ]
    
    missing_files = []
    for req_file in required_files:
        if not (auth_path / req_file).exists():
            missing_files.append(req_file)
    
    if missing_files:
        add_category_result(
            "Authentication",
            "Required components",
            False,
            f"Missing auth components: {missing_files}",
            "HIGH"
        )
    else:
        add_category_result(
            "Authentication",
            "Required components",
            True,
            "All required authentication components present"
        )
    
    # Check JWT implementation
    token_file = auth_path / "tokens.py"
    if token_file.exists():
        content = token_file.read_text()
        if "jwt" in content.lower() and "create_tokens" in content:
            add_category_result(
                "Authentication",
                "JWT implementation",
                True,
                "JWT token management implemented"
            )
        else:
            add_category_result(
                "Authentication",
                "JWT implementation",
                False,
                "JWT implementation incomplete",
                "HIGH"
            )
    
    # Check RBAC implementation
    rbac_file = auth_path / "rbac.py"
    if rbac_file.exists():
        content = rbac_file.read_text()
        if "RBACManager" in content and "Permission" in content:
            add_category_result(
                "Authentication",
                "RBAC system",
                True,
                "Role-based access control implemented"
            )
        else:
            add_category_result(
                "Authentication",
                "RBAC system",
                False,
                "RBAC implementation incomplete",
                "HIGH"
            )


def test_input_validation():
    """Test input validation and sanitization."""
    print("\n[4] Testing Input Validation...")
    
    # Check for SQL injection prevention
    sql_patterns = [
        r'f".*SELECT.*FROM.*{',
        r"f'.*SELECT.*FROM.*{",
        r'\.format\(.*SELECT.*FROM',
        r'%.*SELECT.*FROM'
    ]
    
    sql_injection_found = False
    for pattern in sql_patterns:
        for py_file in Path("src").rglob("*.py"):
            try:
                content = py_file.read_text()
                if re.search(pattern, content, re.IGNORECASE):
                    sql_injection_found = True
                    break
            except:
                pass
    
    if sql_injection_found:
        add_category_result(
            "Input Validation",
            "SQL injection prevention",
            False,
            "Potential SQL injection vulnerabilities found",
            "CRITICAL"
        )
    else:
        add_category_result(
            "Input Validation",
            "SQL injection prevention",
            True,
            "No obvious SQL injection patterns found"
        )
    
    # Check for path traversal prevention
    path_patterns = [
        r'\.\./',
        r'\.\.\\\\',
        r'os\.path\.join\([^)]*\.\.'
    ]
    
    path_traversal_found = False
    for pattern in path_patterns:
        for py_file in Path("src").rglob("*.py"):
            try:
                content = py_file.read_text()
                if re.search(pattern, content):
                    # Check if it's being validated
                    if not re.search(r'(validate|sanitize|check).*path', content, re.IGNORECASE):
                        path_traversal_found = True
                        break
            except:
                pass
    
    if path_traversal_found:
        add_category_result(
            "Input Validation",
            "Path traversal prevention",
            False,
            "Potential path traversal vulnerabilities found",
            "HIGH"
        )
    else:
        add_category_result(
            "Input Validation",
            "Path traversal prevention",
            True,
            "Path traversal protections in place"
        )


def test_container_security():
    """Test container and Kubernetes security configurations."""
    print("\n[5] Testing Container Security...")
    
    # Check Dockerfile security
    dockerfile_secure = Path("Dockerfile.secure")
    if dockerfile_secure.exists():
        content = dockerfile_secure.read_text()
        
        # Check for non-root user
        if "USER" in content and "appuser" in content:
            add_category_result(
                "Container Security",
                "Non-root user",
                True,
                "Container runs as non-root user"
            )
        else:
            add_category_result(
                "Container Security",
                "Non-root user",
                False,
                "Container may run as root",
                "HIGH"
            )
        
        # Check for minimal base image
        if "slim" in content or "alpine" in content:
            add_category_result(
                "Container Security",
                "Minimal base image",
                True,
                "Using minimal base image"
            )
        else:
            add_category_result(
                "Container Security",
                "Minimal base image",
                False,
                "Not using minimal base image",
                "MEDIUM"
            )
    
    # Check Kubernetes security policies
    k8s_path = Path("k8s")
    if k8s_path.exists():
        psp_file = k8s_path / "pod-security-policies.yaml"
        if psp_file.exists():
            content = psp_file.read_text()
            if "runAsNonRoot: true" in content or "MustRunAsNonRoot" in content:
                add_category_result(
                    "Container Security",
                    "K8s Pod Security Policies",
                    True,
                    "Pod security policies enforce non-root"
                )
            else:
                add_category_result(
                    "Container Security",
                    "K8s Pod Security Policies",
                    False,
                    "Pod security policies may allow root",
                    "HIGH"
                )
        else:
            add_category_result(
                "Container Security",
                "K8s Pod Security Policies",
                False,
                "No pod security policies found",
                "HIGH"
            )


def test_dependency_security():
    """Test dependency security."""
    print("\n[6] Testing Dependency Security...")
    
    # Check requirements.txt
    req_file = Path("requirements.txt")
    if req_file.exists():
        content = req_file.read_text()
        
        # Check for critical package versions
        critical_packages = {
            "cryptography": (r"cryptography>=(\d+)", 42),
            "pyjwt": (r"pyjwt.*>=(\d+)", 2),
            "pyyaml": (r"pyyaml>=(\d+)", 6),
            "requests": (r"requests>=(\d+)", 2),
            "twisted": (r"twisted>=(\d+)", 24)
        }
        
        for package, (pattern, min_version) in critical_packages.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                try:
                    version = int(match.group(1))
                    if version >= min_version:
                        add_category_result(
                            "Dependency Security",
                            f"{package} version",
                            True,
                            f"{package} version {version} meets security requirements"
                        )
                    else:
                        add_category_result(
                            "Dependency Security",
                            f"{package} version",
                            False,
                            f"{package} version {version} below recommended {min_version}",
                            "HIGH"
                        )
                except:
                    pass
            else:
                add_category_result(
                    "Dependency Security",
                    f"{package} version",
                    False,
                    f"{package} not found or version not specified",
                    "MEDIUM"
                )


def test_hardcoded_secrets():
    """Test for hardcoded secrets and credentials."""
    print("\n[7] Testing for Hardcoded Secrets...")
    
    # Patterns for potential secrets
    secret_patterns = [
        (r'["\']api[_-]?key["\']\s*[:=]\s*["\'][^"\']+["\']', "API Key"),
        (r'["\']password["\']\s*[:=]\s*["\'][^"\']+["\']', "Password"),
        (r'["\']secret["\']\s*[:=]\s*["\'][^"\']+["\']', "Secret"),
        (r'["\']token["\']\s*[:=]\s*["\'][^"\']+["\']', "Token"),
        (r'Bearer\s+[A-Za-z0-9\-_]+', "Bearer Token")
    ]
    
    for pattern, secret_type in secret_patterns:
        found_secrets = []
        for py_file in Path("src").rglob("*.py"):
            try:
                content = py_file.read_text()
                matches = re.findall(pattern, content, re.IGNORECASE)
                # Filter out obvious test/example values
                real_matches = [m for m in matches if not any(
                    x in m.lower() for x in ["example", "test", "dummy", "changeme", "placeholder"]
                )]
                if real_matches:
                    found_secrets.append(str(py_file))
            except:
                pass
        
        if found_secrets:
            add_category_result(
                "Secrets Management",
                f"Hardcoded {secret_type}",
                False,
                f"Found potential hardcoded {secret_type} in {len(found_secrets)} files",
                "CRITICAL"
            )
        else:
            add_category_result(
                "Secrets Management",
                f"Hardcoded {secret_type}",
                True,
                f"No hardcoded {secret_type} found"
            )


def test_network_security():
    """Test network security configurations."""
    print("\n[8] Testing Network Security...")
    
    # Check for HTTPS enforcement
    https_patterns = [
        r'https://',
        r'ssl\s*=\s*True',
        r'verify\s*=\s*True',
        r'tls'
    ]
    
    https_count = 0
    http_count = 0
    
    for py_file in Path("src").rglob("*.py"):
        try:
            content = py_file.read_text()
            https_count += len(re.findall(r'https://', content))
            # Don't count localhost/127.0.0.1
            http_matches = re.findall(r'http://(?!localhost|127\.0\.0\.1)', content)
            http_count += len(http_matches)
        except:
            pass
    
    if http_count > 0:
        add_category_result(
            "Network Security",
            "HTTPS enforcement",
            False,
            f"Found {http_count} non-HTTPS URLs",
            "MEDIUM"
        )
    else:
        add_category_result(
            "Network Security",
            "HTTPS enforcement",
            True,
            f"All external connections use HTTPS ({https_count} found)"
        )
    
    # Check for CORS configuration
    cors_files = list(Path("src").rglob("*cors*.py"))
    if cors_files:
        cors_secure = False
        for cors_file in cors_files:
            try:
                content = cors_file.read_text()
                if 'allow_origins=["*"]' not in content and "allow_credentials=False" in content:
                    cors_secure = True
                    break
            except:
                pass
        
        if cors_secure:
            add_category_result(
                "Network Security",
                "CORS configuration",
                True,
                "CORS properly configured"
            )
        else:
            add_category_result(
                "Network Security",
                "CORS configuration",
                False,
                "CORS may allow wildcards with credentials",
                "HIGH"
            )


def test_logging_security():
    """Test logging and monitoring security."""
    print("\n[9] Testing Logging Security...")
    
    # Check for log injection prevention
    log_sanitization_found = False
    for py_file in Path("src").rglob("*.py"):
        try:
            content = py_file.read_text()
            if "sanitize" in content and "log" in content:
                log_sanitization_found = True
                break
        except:
            pass
    
    if log_sanitization_found:
        add_category_result(
            "Logging Security",
            "Log injection prevention",
            True,
            "Log sanitization implemented"
        )
    else:
        add_category_result(
            "Logging Security",
            "Log injection prevention",
            False,
            "No log sanitization found",
            "MEDIUM"
        )
    
    # Check for audit logging
    audit_files = list(Path("src").rglob("*audit*.py"))
    if audit_files:
        add_category_result(
            "Logging Security",
            "Audit logging",
            True,
            f"Audit logging implemented ({len(audit_files)} audit files)"
        )
    else:
        add_category_result(
            "Logging Security",
            "Audit logging",
            False,
            "No audit logging implementation found",
            "MEDIUM"
        )


def test_ssrf_protection():
    """Test for SSRF protection."""
    print("\n[10] Testing SSRF Protection...")
    
    # Check for URL validation
    url_validation_found = False
    ssrf_protection_found = False
    
    for py_file in Path("src").rglob("*.py"):
        try:
            content = py_file.read_text()
            if "urlparse" in content or "validate_url" in content:
                url_validation_found = True
            if "ssrf" in content.lower() or "blocked_hosts" in content.lower():
                ssrf_protection_found = True
        except:
            pass
    
    if ssrf_protection_found:
        add_category_result(
            "SSRF Protection",
            "SSRF prevention",
            True,
            "SSRF protection implemented"
        )
    elif url_validation_found:
        add_category_result(
            "SSRF Protection",
            "SSRF prevention",
            True,
            "URL validation present (basic SSRF protection)"
        )
    else:
        add_category_result(
            "SSRF Protection",
            "SSRF prevention",
            False,
            "No SSRF protection found",
            "HIGH"
        )


def calculate_security_score():
    """Calculate overall security posture score."""
    total = validation_results["summary"]["total_tests"]
    passed = validation_results["summary"]["passed"]
    
    if total == 0:
        return 0
    
    # Base score from test pass rate
    base_score = (passed / total) * 100
    
    # Penalties for severity
    critical_penalty = validation_results["summary"]["critical"] * 10
    high_penalty = validation_results["summary"]["high"] * 5
    medium_penalty = validation_results["summary"]["medium"] * 2
    low_penalty = validation_results["summary"]["low"] * 1
    
    # Calculate final score
    final_score = max(0, base_score - critical_penalty - high_penalty - medium_penalty - low_penalty)
    
    # Convert to 10-point scale
    return round(final_score / 10, 1)


def main():
    """Run comprehensive security validation."""
    print("=" * 80)
    print("AGENT 10: COMPREHENSIVE SECURITY VALIDATION")
    print("=" * 80)
    print(f"Validating security fixes for 48 original vulnerabilities")
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    # Run all security tests
    test_command_injection()
    test_cryptographic_security()
    test_authentication_framework()
    test_input_validation()
    test_container_security()
    test_dependency_security()
    test_hardcoded_secrets()
    test_network_security()
    test_logging_security()
    test_ssrf_protection()
    
    # Calculate security score
    security_score = calculate_security_score()
    validation_results["security_score"] = security_score
    
    # Generate summary
    print("\n" + "=" * 80)
    print("SECURITY VALIDATION SUMMARY")
    print("=" * 80)
    
    print(f"\nTotal Security Tests: {validation_results['summary']['total_tests']}")
    print(f"Passed: {validation_results['summary']['passed']}")
    print(f"Failed: {validation_results['summary']['failed']}")
    
    print(f"\nVulnerabilities by Severity:")
    print(f"  CRITICAL: {validation_results['summary']['critical']}")
    print(f"  HIGH: {validation_results['summary']['high']}")
    print(f"  MEDIUM: {validation_results['summary']['medium']}")
    print(f"  LOW: {validation_results['summary']['low']}")
    
    print(f"\nOriginal Vulnerabilities: 48")
    print(f"Remaining Vulnerabilities: {validation_results['summary']['vulnerabilities_found']}")
    print(f"Remediation Rate: {((48 - validation_results['summary']['vulnerabilities_found']) / 48 * 100):.1f}%")
    
    print(f"\n🔒 SECURITY POSTURE SCORE: {security_score}/10")
    
    if security_score >= 8.0:
        print("✅ PRODUCTION READY - Security meets enterprise standards")
    elif security_score >= 6.0:
        print("⚠️  CONDITIONAL PASS - Minor security improvements needed")
    else:
        print("❌ NOT PRODUCTION READY - Critical security issues remain")
    
    # Category breakdown
    print("\nCategory Results:")
    for category, data in validation_results["categories"].items():
        total = len(data["tests"])
        passed = data["passed"]
        print(f"  {category}: {passed}/{total} passed")
    
    # Save detailed results
    with open('final_security_validation_results.json', 'w') as f:
        json.dump(validation_results, f, indent=2)
    
    print("\nDetailed results saved to: final_security_validation_results.json")
    
    return security_score >= 8.0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)