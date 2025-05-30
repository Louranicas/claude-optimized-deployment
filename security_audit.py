#!/usr/bin/env python3
# security_audit.py
import re
import os

def audit_module_security(file_path):
    """Perform security audit on a module."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    issues = []
    
    # Check for hardcoded secrets
    secret_patterns = [
        r'password\s*=\s*["\'][^"\']+["\']',
        r'api_key\s*=\s*["\'][^"\']+["\']',
        r'secret\s*=\s*["\'][^"\']+["\']',
        r'token\s*=\s*["\'][^"\']+["\']'
    ]
    
    for pattern in secret_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            issues.append(f"Potential hardcoded secret: {matches}")
    
    # Check for SQL injection vulnerabilities
    sql_patterns = [
        r'execute\s*\(\s*["\'][^"\']*%s[^"\']*["\']',
        r'query\s*\(\s*["\'][^"\']*\+[^"\']*["\']'
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, content):
            issues.append("Potential SQL injection vulnerability")
    
    # Check for command injection
    if re.search(r'subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True', content):
        # This is actually OK if properly sanitized, but flag for review
        issues.append("Command execution with shell=True (review for injection)")
    
    return issues

def audit_all_modules():
    """Audit all created modules."""
    modules = [
        'src/mcp/monitoring/prometheus_server.py',
        'src/mcp/security/scanner_server.py',
        'src/mcp/infrastructure/commander_server.py',
        'src/mcp/storage/cloud_storage_server.py',
        'src/mcp/communication/slack_server.py'
    ]
    
    total_issues = 0
    for module in modules:
        if os.path.exists(module):
            issues = audit_module_security(module)
            print(f"\n🔍 Security Audit: {module}")
            if issues:
                print(f"❌ {len(issues)} issues found:")
                for issue in issues:
                    print(f"   - {issue}")
                total_issues += len(issues)
            else:
                print("✅ No security issues detected")
        else:
            print(f"⚠️ Module not found: {module}")
    
    print(f"\n📊 Security Audit Complete: {total_issues} total issues across all modules")
    return total_issues

if __name__ == "__main__":
    audit_all_modules()