#!/usr/bin/env python3
"""
Verify that all security patterns from the production test are detected correctly
"""

import sys
from pathlib import Path

# Add project path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "mcp_learning_system"))

from bash_god_mcp_server import BashGodSafetyValidator, ExecutionContext, SafetyLevel

def verify_security_fixes():
    """Verify all security fixes are working"""
    print("🔒 Verifying Security Fixes for Bash God MCP Server\n")
    
    validator = BashGodSafetyValidator()
    context = ExecutionContext(
        user="testuser",
        cwd="/tmp",
        environment={},
        system_info={},
        security_level="normal"
    )
    
    # Test cases from the production test suite (test_security_isolation method)
    injection_tests = [
        "ls -la; rm -rf /",
        "ps aux && curl malicious.com", 
        "echo hello | sh",
        "$(rm -rf /tmp)",
        "`whoami && rm file`"
    ]
    
    privilege_tests = [
        "sudo rm -rf /",
        "su root -c 'rm file'",
        "chmod 4755 /bin/sh"
    ]
    
    print("Command Injection Tests:")
    print("-" * 50)
    all_passed = True
    
    for cmd in injection_tests:
        safety_level, warnings = validator.validate_command(cmd, context)
        is_safe = safety_level in [SafetyLevel.SAFE, SafetyLevel.LOW_RISK]
        
        if not is_safe:
            print(f"✅ DETECTED as unsafe: {cmd}")
            print(f"   Safety level: {safety_level.value}")
        else:
            print(f"❌ NOT DETECTED: {cmd}")
            print(f"   Safety level: {safety_level.value}")
            all_passed = False
    
    print("\nPrivilege Escalation Tests:")
    print("-" * 50)
    
    for cmd in privilege_tests:
        safety_level, warnings = validator.validate_command(cmd, context)
        is_high_risk = safety_level in [SafetyLevel.HIGH_RISK, SafetyLevel.CRITICAL_RISK]
        
        if is_high_risk:
            print(f"✅ FLAGGED as high risk: {cmd}")
            print(f"   Safety level: {safety_level.value}")
        else:
            print(f"❌ NOT FLAGGED: {cmd}")
            print(f"   Safety level: {safety_level.value}")
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("✅ All security patterns are properly detected!")
        print("The Bash God MCP Server security validation is working correctly.")
        return True
    else:
        print("❌ Some security patterns were not detected.")
        print("Please review the validation patterns.")
        return False

if __name__ == "__main__":
    success = verify_security_fixes()
    exit(0 if success else 1)