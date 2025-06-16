#!/usr/bin/env python3
"""
Agent 8 - Focused Data Security & Privacy Analysis
Quick analysis of critical security and privacy issues.
"""

import os
import re
import json
from datetime import datetime
from pathlib import Path

def focused_security_analysis(project_root):
    """Quick focused analysis of critical data security issues."""
    results = {
        "timestamp": datetime.now().isoformat(),
        "critical_findings": [],
        "credentials_found": [],
        "privacy_gaps": [],
        "encryption_status": {},
        "compliance_status": {}
    }
    
    # 1. Check for hardcoded credentials (CRITICAL)
    credential_patterns = [
        (r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'api_key'),
        (r'password["\']?\s*[:=]\s*["\']([^"\']{6,})["\']', 'password'),
        (r'secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'secret'),
        (r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_.-]{20,})["\']', 'token'),
    ]
    
    # Scan specific high-risk files
    high_risk_files = [
        "mcp_configs/mcp_master_config_20250607_125216.json",
        "config/security_config.yaml",
        "src/security/mcp_security_core.py"
    ]
    
    for file_rel in high_risk_files:
        file_path = Path(project_root) / file_rel
        if file_path.exists():
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                
                # Check for credentials
                for pattern, cred_type in credential_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        for match in matches:
                            if len(match) > 10:  # Only flag significant credentials
                                results["credentials_found"].append({
                                    "file": str(file_path),
                                    "type": cred_type,
                                    "value_length": len(match),
                                    "risk": "critical"
                                })
                                
            except Exception as e:
                print(f"Could not scan {file_path}: {e}")
    
    # 2. Check encryption implementations
    security_file = Path(project_root) / "src/security/mcp_security_core.py"
    if security_file.exists():
        try:
            content = security_file.read_text()
            
            # Check for strong crypto
            crypto_indicators = {
                "aes_256": "AES-256" in content,
                "bcrypt": "bcrypt" in content,
                "pbkdf2": "PBKDF2" in content,
                "fernet": "Fernet" in content,
                "tls_12_plus": "TLSv1.2" in content,
                "jwt": "jwt" in content.lower()
            }
            
            results["encryption_status"] = crypto_indicators
            
        except Exception as e:
            print(f"Could not analyze encryption: {e}")
    
    # 3. Check privacy compliance indicators
    privacy_keywords = ["gdpr", "ccpa", "privacy", "consent", "erasure", "portability"]
    privacy_found = {}
    
    for keyword in privacy_keywords:
        privacy_found[keyword] = False
        
        # Quick scan of key files
        for py_file in Path(project_root).glob("**/*.py"):
            if py_file.stat().st_size < 1024 * 1024:  # Skip large files
                try:
                    content = py_file.read_text(encoding='utf-8', errors='ignore').lower()
                    if keyword in content:
                        privacy_found[keyword] = True
                        break
                except:
                    continue
    
    results["privacy_compliance"] = privacy_found
    
    # 4. Quick data retention check
    config_file = Path(project_root) / "config/security_config.yaml"
    if config_file.exists():
        try:
            content = config_file.read_text()
            retention_indicators = {
                "has_retention_policy": "retention" in content.lower(),
                "has_data_lifecycle": "lifecycle" in content.lower(),
                "has_cleanup_procedures": "cleanup" in content.lower(),
                "has_backup_retention": "backup" in content.lower()
            }
            results["data_retention"] = retention_indicators
        except:
            results["data_retention"] = {"error": "Could not read config"}
    
    # 5. Generate critical findings summary
    if results["credentials_found"]:
        results["critical_findings"].append({
            "type": "hardcoded_credentials",
            "severity": "critical", 
            "count": len(results["credentials_found"]),
            "description": "Hardcoded credentials found in configuration files"
        })
    
    if not any(results["privacy_compliance"].values()):
        results["critical_findings"].append({
            "type": "no_privacy_controls",
            "severity": "high",
            "description": "No privacy compliance indicators found"
        })
    
    # 6. Compliance assessment
    results["compliance_status"] = {
        "gdpr_ready": results["privacy_compliance"].get("gdpr", False),
        "ccpa_ready": results["privacy_compliance"].get("ccpa", False),
        "encryption_strong": all([
            results["encryption_status"].get("aes_256", False),
            results["encryption_status"].get("bcrypt", False),
            results["encryption_status"].get("tls_12_plus", False)
        ]),
        "credentials_secure": len(results["credentials_found"]) == 0
    }
    
    return results

def main():
    project_root = "."
    results = focused_security_analysis(project_root)
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = f"agent8_focused_security_analysis_{timestamp}.json"
    
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print("=== FOCUSED DATA SECURITY ANALYSIS RESULTS ===")
    print(f"Critical findings: {len(results['critical_findings'])}")
    print(f"Hardcoded credentials: {len(results['credentials_found'])}")
    print(f"Encryption implementations: {sum(results['encryption_status'].values())}/6")
    print(f"Privacy indicators found: {sum(results['privacy_compliance'].values())}/{len(results['privacy_compliance'])}")
    
    print("\nCRITICAL ISSUES:")
    for finding in results['critical_findings']:
        print(f"- {finding['type']}: {finding['description']} (Severity: {finding['severity']})")
    
    print(f"\nDetailed results saved to: {results_file}")
    
    return results

if __name__ == "__main__":
    main()