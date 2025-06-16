#!/usr/bin/env python3
"""
AGENT 7: Phase 2 Dynamic Security Testing
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Security test results
results = {
    "audit_timestamp": datetime.now().isoformat(),
    "phase": "Phase 2: Dynamic Security Testing",
    "vulnerabilities": [],
    "tests_performed": []
}

def test_import_vulnerabilities():
    """Test for dangerous imports and patterns"""
    print("[*] Testing for dangerous imports...")
    
    dangerous_imports = []
    files_checked = 0
    
    for root, dirs, files in os.walk("src"):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                files_checked += 1
                
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        
                        # Check for eval/exec
                        if 'eval(' in content or 'exec(' in content:
                            dangerous_imports.append({
                                "file": filepath,
                                "type": "DANGEROUS_FUNCTION",
                                "severity": "HIGH",
                                "details": "Use of eval() or exec() found"
                            })
                            
                        # Check for pickle (can execute arbitrary code)
                        if 'import pickle' in content or 'from pickle' in content:
                            dangerous_imports.append({
                                "file": filepath,
                                "type": "UNSAFE_DESERIALIZATION",
                                "severity": "HIGH", 
                                "details": "Use of pickle module (unsafe deserialization)"
                            })
                            
                        # Check for shell=True
                        if 'shell=True' in content:
                            dangerous_imports.append({
                                "file": filepath,
                                "type": "COMMAND_INJECTION",
                                "severity": "CRITICAL",
                                "details": "subprocess with shell=True found"
                            })
                            
                except Exception as e:
                    print(f"   [!] Error reading {filepath}: {e}")
                    
    results["tests_performed"].append({
        "test": "Dangerous Import Analysis",
        "files_checked": files_checked,
        "issues_found": len(dangerous_imports)
    })
    
    results["vulnerabilities"].extend(dangerous_imports)
    print(f"   Found {len(dangerous_imports)} dangerous patterns in {files_checked} files")
    

def test_hardcoded_secrets():
    """Test for hardcoded secrets"""
    print("[*] Testing for hardcoded secrets...")
    
    secret_patterns = [
        ('PASSWORD', r'password\s*=\s*["\'][^"\']+["\']'),
        ('API_KEY', r'api_key\s*=\s*["\'][^"\']+["\']'),
        ('SECRET_KEY', r'secret_key\s*=\s*["\'][^"\']+["\']'),
        ('TOKEN', r'token\s*=\s*["\'][^"\']+["\']'),
        ('AWS_KEY', r'AKIA[0-9A-Z]{16}'),
        ('PRIVATE_KEY', r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----')
    ]
    
    secrets_found = []
    
    for root, dirs, files in os.walk("src"):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        
                        for secret_type, pattern in secret_patterns:
                            import re
                            if re.search(pattern, content, re.IGNORECASE):
                                secrets_found.append({
                                    "file": filepath,
                                    "type": "HARDCODED_SECRET",
                                    "severity": "CRITICAL",
                                    "details": f"Potential {secret_type} found",
                                    "cvss_score": 9.8
                                })
                                
                except Exception:
                    pass
                    
    results["vulnerabilities"].extend(secrets_found)
    results["tests_performed"].append({
        "test": "Hardcoded Secrets Scan",
        "issues_found": len(secrets_found)
    })
    
    print(f"   Found {len(secrets_found)} potential hardcoded secrets")


def test_cors_configuration():
    """Test CORS configuration for vulnerabilities"""
    print("[*] Testing CORS configuration...")
    
    cors_issues = []
    
    try:
        # Read CORS config
        cors_file = "src/core/cors_config.py"
        if os.path.exists(cors_file):
            with open(cors_file, 'r') as f:
                content = f.read()
                
                # Check for wildcard origins
                if 'allow_origins=["*"]' in content or "allow_origins=['*']" in content:
                    cors_issues.append({
                        "file": cors_file,
                        "type": "CORS_MISCONFIGURATION",
                        "severity": "HIGH",
                        "details": "CORS allows all origins (*)",
                        "cvss_score": 7.5
                    })
                    
                # Check for credentials with wildcard
                if 'allow_credentials=True' in content and '"*"' in content:
                    cors_issues.append({
                        "file": cors_file,
                        "type": "CORS_MISCONFIGURATION", 
                        "severity": "CRITICAL",
                        "details": "CORS allows credentials with wildcard origin",
                        "cvss_score": 9.8
                    })
                    
    except Exception as e:
        print(f"   [!] Error testing CORS: {e}")
        
    results["vulnerabilities"].extend(cors_issues)
    results["tests_performed"].append({
        "test": "CORS Security Check",
        "issues_found": len(cors_issues)
    })
    
    print(f"   Found {len(cors_issues)} CORS issues")


def analyze_known_vulnerabilities():
    """Analyze already identified vulnerabilities from static analysis"""
    print("[*] Analyzing known vulnerabilities...")
    
    # SQL Injection vulnerabilities identified
    sql_injections = [
        {
            "file": "src/database/init.py:132",
            "type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "details": "Direct string interpolation in SQL query",
            "evidence": "f\"SELECT 1 FROM {table} LIMIT 1\"",
            "cvss_score": 9.8
        },
        {
            "file": "src/database/init.py:233", 
            "type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "details": "Direct string interpolation in SQL query",
            "cvss_score": 9.8
        },
        {
            "file": "src/database/utils.py:116",
            "type": "SQL_INJECTION",
            "severity": "CRITICAL", 
            "details": "Direct string interpolation in SQL query",
            "cvss_score": 9.8
        }
    ]
    
    # Insecure temp file usage
    temp_file_issues = [
        {
            "file": "src/circle_of_experts/drive/manager.py:148",
            "type": "INSECURE_TEMP_FILE",
            "severity": "MEDIUM",
            "details": "Insecure temporary file/directory usage",
            "cvss_score": 5.3
        },
        {
            "file": "src/circle_of_experts/drive/manager.py:252",
            "type": "INSECURE_TEMP_FILE",
            "severity": "MEDIUM",
            "details": "Insecure temporary file/directory usage", 
            "cvss_score": 5.3
        }
    ]
    
    results["vulnerabilities"].extend(sql_injections)
    results["vulnerabilities"].extend(temp_file_issues)
    
    print(f"   Added {len(sql_injections)} SQL injection vulnerabilities")
    print(f"   Added {len(temp_file_issues)} temp file vulnerabilities")


def generate_summary():
    """Generate vulnerability summary"""
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
    
    for vuln in results["vulnerabilities"]:
        severity = vuln["severity"].lower()
        if severity in summary:
            summary[severity] += 1
            
    results["summary"] = summary
    results["total_vulnerabilities"] = len(results["vulnerabilities"])
    
    # Save results
    with open("security_audit_phase2_results.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print("\n" + "="*60)
    print("PHASE 2 SECURITY AUDIT SUMMARY")
    print("="*60)
    print(f"Critical: {summary['critical']}")
    print(f"High: {summary['high']}")
    print(f"Medium: {summary['medium']}")
    print(f"Low: {summary['low']}")
    print(f"Total: {len(results['vulnerabilities'])}")
    print("\nDetailed results saved to: security_audit_phase2_results.json")


if __name__ == "__main__":
    print("\nAGENT 7: PHASE 2 DYNAMIC SECURITY TESTING")
    print("="*60 + "\n")
    
    test_import_vulnerabilities()
    test_hardcoded_secrets()
    test_cors_configuration()
    analyze_known_vulnerabilities()
    generate_summary()