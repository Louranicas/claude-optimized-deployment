#!/usr/bin/env python3
"""
SYNTHEX Simplified Security Audit
Direct security testing without complex dependencies
"""

import asyncio
import json
import time
import os
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# Basic configuration
AUDIT_ID = f"SYNTHEX-AUDIT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
print(f"\n{'='*80}")
print("SYNTHEX SIMPLIFIED SECURITY AUDIT")
print(f"{'='*80}")
print(f"Audit ID: {AUDIT_ID}")
print(f"Started: {datetime.now().isoformat()}")
print(f"{'='*80}\n")

class SimplifiedSecurityAuditor:
    """Simplified security auditor for SYNTHEX"""
    
    def __init__(self):
        self.audit_results = {
            "audit_id": AUDIT_ID,
            "start_time": datetime.now().isoformat(),
            "phases": {},
            "vulnerabilities": [],
            "summary": {}
        }
    
    async def run_audit(self):
        """Run security audit phases"""
        try:
            # Phase 1: Code Analysis
            await self._phase1_code_analysis()
            
            # Phase 2: Dependency Scan
            await self._phase2_dependency_scan()
            
            # Phase 3: Configuration Check
            await self._phase3_configuration_check()
            
            # Phase 4: Secret Detection
            await self._phase4_secret_detection()
            
            # Phase 5: Vulnerability Patterns
            await self._phase5_vulnerability_patterns()
            
            # Generate final report
            self._generate_final_report()
            
        except Exception as e:
            print(f"ERROR: Audit failed: {e}")
            self.audit_results["error"] = str(e)
    
    async def _phase1_code_analysis(self):
        """Phase 1: Static code analysis"""
        print("\n[PHASE 1] Code Analysis")
        print("-" * 40)
        
        vulnerabilities = []
        
        # Check Python files for security issues
        python_files = list(Path("src/synthex").glob("**/*.py"))
        rust_files = list(Path("rust_core/src/synthex").glob("**/*.rs"))
        
        print(f"Analyzing {len(python_files)} Python files...")
        
        for py_file in python_files:
            try:
                with open(py_file, 'r') as f:
                    content = f.read()
                
                # Check for unsafe patterns
                unsafe_patterns = [
                    (r'eval\s*\(', 'Unsafe eval usage'),
                    (r'exec\s*\(', 'Unsafe exec usage'),
                    (r'pickle\.loads', 'Unsafe pickle deserialization'),
                    (r'shell\s*=\s*True', 'Shell injection risk'),
                    (r'os\.system\s*\(', 'Command injection risk'),
                ]
                
                for pattern, desc in unsafe_patterns:
                    if re.search(pattern, content):
                        vulnerabilities.append({
                            "file": str(py_file),
                            "type": "CODE",
                            "severity": "HIGH",
                            "description": desc
                        })
                        
            except Exception:
                pass
        
        print(f"Analyzing {len(rust_files)} Rust files...")
        
        for rs_file in rust_files:
            try:
                with open(rs_file, 'r') as f:
                    content = f.read()
                
                # Check for unsafe Rust patterns
                if 'unsafe ' in content:
                    vulnerabilities.append({
                        "file": str(rs_file),
                        "type": "CODE",
                        "severity": "MEDIUM",
                        "description": "Unsafe block usage in Rust"
                    })
                    
            except Exception:
                pass
        
        self.audit_results["phases"]["code_analysis"] = {
            "files_analyzed": len(python_files) + len(rust_files),
            "vulnerabilities": len(vulnerabilities)
        }
        self.audit_results["vulnerabilities"].extend(vulnerabilities)
        
        print(f"✓ Code analysis complete: {len(vulnerabilities)} issues found")
    
    async def _phase2_dependency_scan(self):
        """Phase 2: Dependency vulnerability scan"""
        print("\n[PHASE 2] Dependency Scan")
        print("-" * 40)
        
        vulnerabilities = []
        
        # Check requirements.txt
        try:
            with open("requirements.txt", 'r') as f:
                deps = f.read().splitlines()
            
            print(f"Checking {len(deps)} Python dependencies...")
            
            # Basic known vulnerable versions
            vulnerable_deps = {
                "cryptography<41.0.0": "Known security vulnerabilities",
                "pyyaml<5.4": "Unsafe YAML loading vulnerability",
                "requests<2.31.0": "Security vulnerabilities",
            }
            
            for dep in deps:
                for vuln_pattern, desc in vulnerable_deps.items():
                    if vuln_pattern.split('<')[0] in dep.lower():
                        vulnerabilities.append({
                            "dependency": dep,
                            "type": "DEPENDENCY",
                            "severity": "HIGH",
                            "description": desc
                        })
                        
        except Exception as e:
            print(f"Warning: Could not scan dependencies: {e}")
        
        self.audit_results["phases"]["dependency_scan"] = {
            "vulnerabilities": len(vulnerabilities)
        }
        self.audit_results["vulnerabilities"].extend(vulnerabilities)
        
        print(f"✓ Dependency scan complete: {len(vulnerabilities)} issues found")
    
    async def _phase3_configuration_check(self):
        """Phase 3: Configuration security check"""
        print("\n[PHASE 3] Configuration Check")
        print("-" * 40)
        
        issues = []
        
        # Check for debug mode
        if os.getenv("DEBUG", "").lower() in ["true", "1", "yes"]:
            issues.append({
                "type": "CONFIG",
                "severity": "MEDIUM",
                "description": "Debug mode is enabled"
            })
        
        # Check for missing security headers
        config_files = list(Path(".").glob("**/*.yaml")) + list(Path(".").glob("**/*.yml"))
        
        print(f"Checking {len(config_files)} configuration files...")
        
        for config_file in config_files:
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                
                # Check for insecure settings
                if 'allow_all_origins: true' in content:
                    issues.append({
                        "file": str(config_file),
                        "type": "CONFIG",
                        "severity": "HIGH",
                        "description": "CORS allows all origins"
                    })
                    
            except Exception:
                pass
        
        self.audit_results["phases"]["configuration_check"] = {
            "issues": len(issues)
        }
        self.audit_results["vulnerabilities"].extend(issues)
        
        print(f"✓ Configuration check complete: {len(issues)} issues found")
    
    async def _phase4_secret_detection(self):
        """Phase 4: Secret detection"""
        print("\n[PHASE 4] Secret Detection")
        print("-" * 40)
        
        secrets_found = []
        
        # Patterns for detecting secrets
        secret_patterns = [
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']', 'API Key'),
            (r'(?i)(secret|password|passwd|pwd)\s*[:=]\s*["\']([^\'\"]{8,})["\']', 'Password'),
            (r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']([A-Z0-9]{20})["\']', 'AWS Key'),
            (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'Private Key'),
        ]
        
        # Scan source files
        source_files = list(Path("src").glob("**/*.py")) + list(Path("src").glob("**/*.js"))
        
        print(f"Scanning {len(source_files)} source files for secrets...")
        
        for source_file in source_files:
            if 'test' in str(source_file) or 'example' in str(source_file):
                continue
                
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                for pattern, secret_type in secret_patterns:
                    if re.search(pattern, content):
                        # Check if it's a false positive
                        if not any(fp in content for fp in ['os.environ', 'getenv', 'config.']):
                            secrets_found.append({
                                "file": str(source_file),
                                "type": "SECRET",
                                "severity": "CRITICAL",
                                "description": f"{secret_type} exposed"
                            })
                            
            except Exception:
                pass
        
        self.audit_results["phases"]["secret_detection"] = {
            "secrets_found": len(secrets_found)
        }
        self.audit_results["vulnerabilities"].extend(secrets_found)
        
        print(f"✓ Secret detection complete: {len(secrets_found)} secrets found")
    
    async def _phase5_vulnerability_patterns(self):
        """Phase 5: Check for common vulnerability patterns"""
        print("\n[PHASE 5] Vulnerability Pattern Check")
        print("-" * 40)
        
        vulnerabilities = []
        
        # OWASP Top 10 patterns
        patterns = {
            "SQL Injection": [
                (r'execute\s*\(\s*["\'].*["\'].*\+.*\)', 'String concatenation in SQL'),
                (r'f".*{.*}.*".*execute', 'F-string in SQL query'),
            ],
            "XSS": [
                (r'innerHTML\s*=', 'Direct innerHTML usage'),
                (r'document\.write\s*\(', 'Unsafe document.write'),
            ],
            "Path Traversal": [
                (r'open\s*\(\s*request\.|open\s*\([^)]*\+[^)]*request\.', 'User input in file path'),
            ],
            "SSRF": [
                (r'requests\.get\s*\(\s*request\.|urllib.*urlopen\s*\(\s*request\.', 'User input in URL'),
            ]
        }
        
        source_files = list(Path("src/synthex").glob("**/*.py"))
        
        for vuln_type, vuln_patterns in patterns.items():
            print(f"Checking for {vuln_type}...")
            
            for source_file in source_files:
                try:
                    with open(source_file, 'r') as f:
                        content = f.read()
                    
                    for pattern, desc in vuln_patterns:
                        if re.search(pattern, content):
                            vulnerabilities.append({
                                "file": str(source_file),
                                "type": vuln_type.upper(),
                                "severity": "HIGH",
                                "description": desc
                            })
                            
                except Exception:
                    pass
        
        self.audit_results["phases"]["vulnerability_patterns"] = {
            "vulnerabilities": len(vulnerabilities)
        }
        self.audit_results["vulnerabilities"].extend(vulnerabilities)
        
        print(f"✓ Vulnerability pattern check complete: {len(vulnerabilities)} found")
    
    def _generate_final_report(self):
        """Generate final security report"""
        print("\n" + "="*80)
        print("SECURITY AUDIT SUMMARY")
        print("="*80)
        
        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in self.audit_results["vulnerabilities"]:
            severity = vuln.get("severity", "MEDIUM")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        total_issues = len(self.audit_results["vulnerabilities"])
        critical_issues = severity_counts["CRITICAL"]
        
        # Calculate security score
        if critical_issues > 0:
            security_score = 0
            grade = "F"
        elif severity_counts["HIGH"] > 5:
            security_score = 40
            grade = "D"
        elif severity_counts["HIGH"] > 2:
            security_score = 60
            grade = "C"
        elif severity_counts["HIGH"] > 0:
            security_score = 70
            grade = "B"
        elif total_issues > 5:
            security_score = 80
            grade = "B+"
        elif total_issues > 0:
            security_score = 90
            grade = "A"
        else:
            security_score = 100
            grade = "A+"
        
        self.audit_results["summary"] = {
            "security_score": security_score,
            "grade": grade,
            "total_issues": total_issues,
            "critical_issues": critical_issues,
            "audit_passed": critical_issues == 0,
            "severity_breakdown": severity_counts
        }
        
        print(f"\n🔐 Security Score: {security_score}/100 (Grade: {grade})")
        print(f"📊 Total Issues: {total_issues}")
        print(f"   - Critical: {severity_counts['CRITICAL']}")
        print(f"   - High: {severity_counts['HIGH']}")
        print(f"   - Medium: {severity_counts['MEDIUM']}")
        print(f"   - Low: {severity_counts['LOW']}")
        
        if critical_issues > 0:
            print("\n⚠️  AUDIT FAILED - Critical security issues must be resolved!")
            print("\nCritical Issues:")
            for vuln in self.audit_results["vulnerabilities"]:
                if vuln.get("severity") == "CRITICAL":
                    print(f"   - {vuln.get('description', 'Unknown')} in {vuln.get('file', 'Unknown')}")
        else:
            print("\n✅ AUDIT PASSED - No critical security issues found")
        
        # Save report
        self.audit_results["end_time"] = datetime.now().isoformat()
        report_file = f"synthex_security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.audit_results, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        
        # Recommendations
        print("\n📋 Top Recommendations:")
        recommendations = []
        
        if critical_issues > 0:
            recommendations.append("1. Address all CRITICAL vulnerabilities immediately")
        
        if severity_counts["HIGH"] > 0:
            recommendations.append("2. Fix HIGH severity issues before deployment")
        
        if any(v.get("type") == "SECRET" for v in self.audit_results["vulnerabilities"]):
            recommendations.append("3. Remove all hardcoded secrets and use environment variables")
        
        if any(v.get("type") == "DEPENDENCY" for v in self.audit_results["vulnerabilities"]):
            recommendations.append("4. Update vulnerable dependencies")
        
        if not recommendations:
            recommendations.append("1. Continue regular security audits")
            recommendations.append("2. Keep dependencies up to date")
        
        for rec in recommendations[:5]:
            print(f"   {rec}")

async def main():
    """Run simplified security audit"""
    auditor = SimplifiedSecurityAuditor()
    
    try:
        await auditor.run_audit()
        
        # Return exit code based on results
        if auditor.audit_results.get("summary", {}).get("audit_passed", False):
            return 0
        else:
            return 1
            
    except Exception as e:
        print(f"FATAL ERROR: {e}")
        return 2

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)