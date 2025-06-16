#!/usr/bin/env python3
"""
AGENT 9: Simple Phase 1 Security Validation
"""

import os
import sys
import json
import re
from pathlib import Path
from datetime import datetime

def check_dependency_updates():
    """Check if critical dependencies are updated."""
    print("\n🔍 Checking Dependency Updates...")
    
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        return False, "requirements.txt not found"
    
    with open(requirements_file, 'r') as f:
        content = f.read()
    
    checks = {
        "cryptography>=45.0.3": r"cryptography>=45\.0\.3",
        "twisted>=24.11.0": r"twisted>=24\.11\.0", 
        "PyJWT>=2.10.1": r"pyjwt\[crypto\]>=2\.10\.1",
        "PyYAML>=6.0.2": r"pyyaml>=6\.0\.2",
        "requests>=2.32.0": r"requests>=2\.32\.0"
    }
    
    results = []
    for dep, pattern in checks.items():
        found = bool(re.search(pattern, content, re.IGNORECASE))
        results.append((dep, found))
        print(f"  {'✅' if found else '❌'} {dep}")
    
    all_found = all(r[1] for r in results)
    return all_found, results

def check_mcp_auth():
    """Check if MCP authentication is implemented."""
    print("\n🔍 Checking MCP Authentication...")
    
    auth_file = Path("src/mcp/security/auth_middleware.py")
    if not auth_file.exists():
        return False, "auth_middleware.py not found"
    
    with open(auth_file, 'r') as f:
        content = f.read()
    
    required_classes = [
        "MCPAuthMiddleware",
        "UserRole", 
        "Permission",
        "AuthContext"
    ]
    
    results = []
    for cls in required_classes:
        found = f"class {cls}" in content
        results.append((cls, found))
        print(f"  {'✅' if found else '❌'} {cls} class")
    
    # Check for key methods
    required_methods = [
        "generate_token",
        "validate_token",
        "validate_request",
        "check_tool_authorization"
    ]
    
    for method in required_methods:
        found = f"def {method}" in content or f"async def {method}" in content
        results.append((method, found))
        print(f"  {'✅' if found else '❌'} {method} method")
    
    all_found = all(r[1] for r in results)
    return all_found, results

def check_command_injection():
    """Check for command injection prevention."""
    print("\n🔍 Checking Command Injection Prevention...")
    
    # Check commander server
    commander_file = Path("src/mcp/infrastructure/commander_server.py")
    if not commander_file.exists():
        return False, "commander_server.py not found"
    
    with open(commander_file, 'r') as f:
        content = f.read()
    
    checks = []
    
    # Check for shell=True usage
    has_shell_true = "shell=True" in content
    checks.append(("No shell=True", not has_shell_true))
    print(f"  {'✅' if not has_shell_true else '❌'} No shell=True usage")
    
    # Check for shlex usage
    has_shlex = "shlex.split" in content
    checks.append(("Uses shlex.split", has_shlex))
    print(f"  {'✅' if has_shlex else '❌'} Uses shlex.split for parsing")
    
    # Check for command validation
    has_validation = "_validate_command" in content
    checks.append(("Has command validation", has_validation))
    print(f"  {'✅' if has_validation else '❌'} Has command validation")
    
    # Check for whitelist
    has_whitelist = "COMMAND_WHITELIST" in content
    checks.append(("Has command whitelist", has_whitelist))
    print(f"  {'✅' if has_whitelist else '❌'} Has command whitelist")
    
    all_good = all(c[1] for c in checks)
    return all_good, checks

def check_cryptography():
    """Check for secure cryptography usage."""
    print("\n🔍 Checking Cryptographic Security...")
    
    src_dir = Path("src")
    py_files = list(src_dir.rglob("*.py"))
    
    md5_files = []
    sha256_files = []
    
    for py_file in py_files:
        try:
            with open(py_file, 'r') as f:
                content = f.read()
                
            # Skip comments
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if not line.strip().startswith('#'):
                    if re.search(r'\bmd5\b|\bMD5\b', line):
                        md5_files.append((py_file, i+1))
                    if 'sha256' in line.lower():
                        sha256_files.append(py_file)
        except:
            continue
    
    print(f"  {'✅' if not md5_files else '❌'} No MD5 usage found ({len(md5_files)} instances)")
    print(f"  {'✅' if sha256_files else '⚠️'} SHA-256 usage found in {len(set(sha256_files))} files")
    
    return len(md5_files) == 0, {"md5_count": len(md5_files), "sha256_count": len(set(sha256_files))}

def check_docker_security():
    """Check Docker security configurations."""
    print("\n🔍 Checking Docker Security...")
    
    dockerfile = Path("Dockerfile")
    if not dockerfile.exists():
        return False, "Dockerfile not found"
    
    with open(dockerfile, 'r') as f:
        content = f.read()
    
    checks = []
    
    # Check for non-root user
    has_user = bool(re.search(r'USER\s+(?!root)', content))
    checks.append(("Non-root user", has_user))
    print(f"  {'✅' if has_user else '❌'} Uses non-root user")
    
    # Check for user creation
    has_useradd = "useradd" in content or "adduser" in content
    checks.append(("Creates user", has_useradd))
    print(f"  {'✅' if has_useradd else '❌'} Creates application user")
    
    # Check for minimal base image
    uses_slim = "-slim" in content
    checks.append(("Uses slim image", uses_slim))
    print(f"  {'✅' if uses_slim else '❌'} Uses slim base image")
    
    # Check for health check
    has_healthcheck = "HEALTHCHECK" in content
    checks.append(("Has healthcheck", has_healthcheck))
    print(f"  {'✅' if has_healthcheck else '❌'} Has health check")
    
    all_good = all(c[1] for c in checks)
    return all_good, checks

def main():
    """Run all security checks."""
    print("=" * 70)
    print("AGENT 9: PHASE 1 SECURITY VALIDATION")
    print("=" * 70)
    
    results = {}
    
    # Run all checks
    passed, details = check_dependency_updates()
    results["dependency_updates"] = {"passed": passed, "details": details}
    
    passed, details = check_mcp_auth()
    results["mcp_authentication"] = {"passed": passed, "details": details}
    
    passed, details = check_command_injection()
    results["command_injection"] = {"passed": passed, "details": details}
    
    passed, details = check_cryptography()
    results["cryptography"] = {"passed": passed, "details": details}
    
    passed, details = check_docker_security()
    results["docker_security"] = {"passed": passed, "details": details}
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    total_passed = sum(1 for r in results.values() if r["passed"])
    total_checks = len(results)
    
    for check_name, result in results.items():
        status = "✅ PASS" if result["passed"] else "❌ FAIL"
        print(f"{check_name.replace('_', ' ').title()}: {status}")
    
    percentage = (total_passed / total_checks) * 100
    print(f"\nOverall: {total_passed}/{total_checks} checks passed ({percentage:.1f}%)")
    
    # Save results
    output = {
        "timestamp": datetime.now().isoformat(),
        "phase": 1,
        "total_passed": total_passed,
        "total_checks": total_checks,
        "percentage": percentage,
        "results": results
    }
    
    with open("phase1_validation_results.json", 'w') as f:
        json.dump(output, f, indent=2)
    
    if percentage == 100:
        print("\n🎉 ALL PHASE 1 SECURITY CHECKS PASSED!")
    else:
        print(f"\n⚠️  {total_checks - total_passed} checks failed. Review and fix before proceeding.")
    
    return percentage == 100

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)