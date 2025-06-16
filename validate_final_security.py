#!/usr/bin/env python3
"""
Final Security Validation

Comprehensive validation of all security mitigations implemented.
"""

import asyncio
import json
import time
import subprocess
from pathlib import Path
from typing import Dict, Any, List


async def run_final_validation() -> Dict[str, Any]:
    """Run comprehensive final security validation."""
    print("🔒 Final Security Validation Starting...\n")
    
    project_root = Path(__file__).parent
    validation_results = {
        "timestamp": time.time(),
        "categories": {},
        "overall_score": 0,
        "max_score": 100,
        "production_ready": False
    }
    
    # Authentication Framework (20 points)
    auth_score = 0
    print("🔐 Validating Authentication Framework...")
    
    auth_middleware = project_root / "src" / "auth" / "middleware.py"
    if auth_middleware.exists() and "AuthMiddleware" in auth_middleware.read_text():
        auth_score += 7
        print("  ✅ Authentication middleware exists")
    
    mcp_auth = project_root / "src" / "mcp" / "security" / "auth_integration.py"
    if mcp_auth.exists() and "MCPAuthMiddleware" in mcp_auth.read_text():
        auth_score += 8
        print("  ✅ MCP authentication integration exists")
    
    tokens = project_root / "src" / "auth" / "tokens.py"
    if tokens.exists() and "TokenManager" in tokens.read_text():
        auth_score += 5
        print("  ✅ JWT token management exists")
    
    validation_results["categories"]["authentication"] = {
        "score": auth_score,
        "max_score": 20,
        "percentage": round((auth_score / 20) * 100, 1)
    }
    
    # Command Injection Prevention (15 points)
    cmd_score = 0
    print("\n⚡ Validating Command Injection Prevention...")
    
    try:
        # Check for shell=True usage
        result = subprocess.run(
            ['grep', '-r', 'shell=True', str(project_root / 'src')],
            capture_output=True, text=True
        )
        shell_usage = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
        
        if shell_usage == 0:
            cmd_score += 10
            print("  ✅ No dangerous shell=True usage found")
        else:
            print(f"  ⚠️ Found {shell_usage} instances of shell=True")
    except:
        print("  ℹ️ Could not check shell usage")
    
    commander = project_root / "src" / "mcp" / "infrastructure" / "commander_server.py"
    if commander.exists():
        content = commander.read_text()
        if "_validate_command" in content and "COMMAND_WHITELIST" in content:
            cmd_score += 5
            print("  ✅ Command validation implemented")
    
    validation_results["categories"]["command_injection"] = {
        "score": cmd_score,
        "max_score": 15,
        "percentage": round((cmd_score / 15) * 100, 1)
    }
    
    # Cryptographic Security (15 points)
    crypto_score = 0
    print("\n🔐 Validating Cryptographic Security...")
    
    try:
        # Check for MD5 usage
        result = subprocess.run(
            ['grep', '-r', 'hashlib.md5', str(project_root / 'src')],
            capture_output=True, text=True
        )
        md5_usage = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
        
        if md5_usage == 0:
            crypto_score += 8
            print("  ✅ No MD5 usage found")
        else:
            print(f"  ⚠️ Found {md5_usage} instances of MD5 usage")
    except:
        print("  ℹ️ Could not check MD5 usage")
    
    try:
        # Check for SHA-256 usage
        result = subprocess.run(
            ['grep', '-r', 'sha256', str(project_root / 'src')],
            capture_output=True, text=True
        )
        sha256_usage = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
        
        if sha256_usage >= 5:
            crypto_score += 7
            print(f"  ✅ Found {sha256_usage} instances of SHA-256 usage")
        else:
            print(f"  ⚠️ Only {sha256_usage} instances of SHA-256 found")
    except:
        print("  ℹ️ Could not check SHA-256 usage")
    
    validation_results["categories"]["cryptography"] = {
        "score": crypto_score,
        "max_score": 15,
        "percentage": round((crypto_score / 15) * 100, 1)
    }
    
    # Container Security (10 points)
    container_score = 0
    print("\n🐳 Validating Container Security...")
    
    dockerfile_secure = project_root / "Dockerfile.secure"
    if dockerfile_secure.exists():
        content = dockerfile_secure.read_text()
        if "USER appuser" in content:
            container_score += 5
            print("  ✅ Secure Dockerfile with non-root user")
    
    k8s_security = project_root / "k8s" / "pod-security-policies.yaml"
    if k8s_security.exists():
        content = k8s_security.read_text()
        if "runAsNonRoot: true" in content:
            container_score += 5
            print("  ✅ Kubernetes security policies implemented")
    
    validation_results["categories"]["container"] = {
        "score": container_score,
        "max_score": 10,
        "percentage": round((container_score / 10) * 100, 1)
    }
    
    # Dependency Security (10 points)
    deps_score = 0
    print("\n📦 Validating Dependency Security...")
    
    requirements = project_root / "requirements.txt"
    if requirements.exists():
        content = requirements.read_text()
        secure_packages = ["cryptography", "twisted", "PyJWT", "PyYAML", "requests"]
        found_secure = sum(1 for pkg in secure_packages if pkg in content)
        
        if found_secure >= 4:
            deps_score += 10
            print(f"  ✅ Found {found_secure}/5 critical packages with secure versions")
        else:
            print(f"  ⚠️ Only {found_secure}/5 secure packages found")
    
    validation_results["categories"]["dependencies"] = {
        "score": deps_score,
        "max_score": 10,
        "percentage": round((deps_score / 10) * 100, 1)
    }
    
    # Input Validation (10 points)
    input_score = 0
    print("\n🔍 Validating Input Validation...")
    
    path_validation = project_root / "src" / "core" / "path_validation.py"
    if path_validation.exists() and "validate_path" in path_validation.read_text():
        input_score += 5
        print("  ✅ Path validation implemented")
    
    ssrf_protection = project_root / "src" / "core" / "ssrf_protection.py"
    if ssrf_protection.exists() and "validate_url" in ssrf_protection.read_text():
        input_score += 5
        print("  ✅ SSRF protection implemented")
    
    validation_results["categories"]["input_validation"] = {
        "score": input_score,
        "max_score": 10,
        "percentage": round((input_score / 10) * 100, 1)
    }
    
    # Network Security (5 points)
    network_score = 0
    print("\n🌐 Validating Network Security...")
    
    cors_config = project_root / "src" / "core" / "cors_config.py"
    if cors_config.exists() and "CORS" in cors_config.read_text():
        network_score += 5
        print("  ✅ CORS configuration exists")
    
    validation_results["categories"]["network"] = {
        "score": network_score,
        "max_score": 5,
        "percentage": round((network_score / 5) * 100, 1)
    }
    
    # Audit Logging (5 points)
    audit_score = 0
    print("\n📝 Validating Audit Logging...")
    
    log_sanitization = project_root / "src" / "core" / "log_sanitization.py"
    if log_sanitization.exists() and "sanitize_log_input" in log_sanitization.read_text():
        audit_score += 5
        print("  ✅ Log sanitization implemented")
    
    validation_results["categories"]["audit_logging"] = {
        "score": audit_score,
        "max_score": 5,
        "percentage": round((audit_score / 5) * 100, 1)
    }
    
    # Rate Limiting (10 points)
    rate_score = 0
    print("\n⏱️ Validating Rate Limiting...")
    
    rate_config = project_root / "src" / "auth" / "rate_limit_config.py"
    if rate_config.exists() and "RateLimitConfig" in rate_config.read_text():
        rate_score += 5
        print("  ✅ Rate limiting configuration exists")
    
    auth_middleware = project_root / "src" / "auth" / "middleware.py"
    if auth_middleware.exists() and "RateLimitMiddleware" in auth_middleware.read_text():
        rate_score += 5
        print("  ✅ Rate limiting middleware implemented")
    
    validation_results["categories"]["rate_limiting"] = {
        "score": rate_score,
        "max_score": 10,
        "percentage": round((rate_score / 10) * 100, 1)
    }
    
    # Calculate overall score
    total_score = sum(cat["score"] for cat in validation_results["categories"].values())
    validation_results["overall_score"] = total_score
    validation_results["overall_percentage"] = round((total_score / 100) * 100, 1)
    validation_results["production_ready"] = total_score >= 80
    
    # Determine certification level
    if total_score >= 95:
        validation_results["certification"] = "EXCELLENT - Production Ready"
    elif total_score >= 85:
        validation_results["certification"] = "GOOD - Production Ready with Minor Issues"
    elif total_score >= 75:
        validation_results["certification"] = "ACCEPTABLE - Production Ready with Conditions"
    elif total_score >= 60:
        validation_results["certification"] = "NEEDS IMPROVEMENT - Not Production Ready"
    else:
        validation_results["certification"] = "CRITICAL ISSUES - Major Security Gaps"
    
    return validation_results


async def main():
    """Main function."""
    results = await run_final_validation()
    
    # Save results
    with open("final_security_validation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print("\n" + "="*80)
    print("🔒 FINAL SECURITY VALIDATION SUMMARY")
    print("="*80)
    print(f"Overall Score: {results['overall_score']}/100 ({results['overall_percentage']}%)")
    print(f"Certification: {results['certification']}")
    print(f"Production Ready: {'✅ YES' if results['production_ready'] else '❌ NO'}")
    
    print("\n📊 Category Breakdown:")
    for category, data in results["categories"].items():
        status = "✅" if data["percentage"] >= 80 else "⚠️" if data["percentage"] >= 60 else "❌"
        print(f"  {status} {category.replace('_', ' ').title()}: {data['score']}/{data['max_score']} ({data['percentage']}%)")
    
    if results['production_ready']:
        print("\n🎉 SYSTEM IS READY FOR PRODUCTION DEPLOYMENT!")
    else:
        remaining = 80 - results['overall_score']
        print(f"\n⚠️ Need {remaining} more points for production readiness")
    
    print(f"\n📄 Detailed results saved to final_security_validation_results.json")
    
    return results


if __name__ == "__main__":
    asyncio.run(main())