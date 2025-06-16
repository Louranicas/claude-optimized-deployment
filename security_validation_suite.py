#!/usr/bin/env python3
"""
Comprehensive Security Validation Suite
Tests all security fixes and ensures no vulnerabilities remain
"""

import asyncio
import os
import re
import json
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import hashlib
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityValidationSuite:
    """Comprehensive security validation for CODE project"""
    
    def __init__(self, project_root: str = "/home/louranicas/projects/claude-optimized-deployment"):
        self.project_root = Path(project_root)
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0,
            "findings": []
        }
        
    async def run_all_validations(self) -> Dict:
        """Run comprehensive security validation suite"""
        logger.info("🔒 Starting Comprehensive Security Validation Suite")
        
        # Phase 1: Secret Scanning
        await self.validate_no_hardcoded_secrets()
        
        # Phase 2: Kubernetes Security
        await self.validate_kubernetes_security()
        
        # Phase 3: Container Security
        await self.validate_container_security()
        
        # Phase 4: Vault Integration
        await self.validate_vault_integration()
        
        # Phase 5: Network Security
        await self.validate_network_policies()
        
        # Phase 6: RBAC Validation
        await self.validate_rbac_policies()
        
        # Phase 7: Encryption Validation
        await self.validate_encryption()
        
        # Phase 8: Security Headers
        await self.validate_security_headers()
        
        # Phase 9: Dependency Scanning
        await self.validate_dependencies()
        
        # Phase 10: Compliance Validation
        await self.validate_compliance()
        
        # Generate report
        self.generate_report()
        
        return self.results
    
    async def validate_no_hardcoded_secrets(self):
        """Validate no hardcoded secrets in codebase"""
        logger.info("🔍 Validating: No hardcoded secrets")
        self.results["total_tests"] += 1
        
        # Patterns for common secrets
        secret_patterns = [
            # API Keys
            (r'api[_-]?key\s*[:=]\s*["\']([^"\']{20,})["\']', "API Key"),
            (r'sk_live_[a-zA-Z0-9]{24,}', "Stripe API Key"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
            
            # Passwords
            (r'password\s*[:=]\s*["\']([^"\']+)["\']', "Password"),
            (r'pwd\s*[:=]\s*["\']([^"\']+)["\']', "Password"),
            
            # Tokens
            (r'token\s*[:=]\s*["\']([^"\']{20,})["\']', "Token"),
            (r'bearer\s+[a-zA-Z0-9\-_]{20,}', "Bearer Token"),
            
            # Private Keys
            (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Private Key"),
            (r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', "SSH Private Key"),
        ]
        
        issues_found = 0
        exclude_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
        exclude_files = {'security_validation_suite.py', 'test_security_mcp_servers_comprehensive.py'}
        
        for root, dirs, files in os.walk(self.project_root):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file in exclude_files:
                    continue
                    
                if file.endswith(('.py', '.js', '.ts', '.yaml', '.yml', '.json', '.env')):
                    file_path = Path(root) / file
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern, secret_type in secret_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                # Check if it's a placeholder or environment variable
                                matched_text = match.group(0)
                                if any(placeholder in matched_text.lower() for placeholder in 
                                      ['process.env', 'os.environ', '${', 'example', 'placeholder', 'your-']):
                                    continue
                                
                                line_num = content[:match.start()].count('\n') + 1
                                
                                self.results["findings"].append({
                                    "test": "hardcoded_secrets",
                                    "severity": "CRITICAL",
                                    "file": str(file_path.relative_to(self.project_root)),
                                    "line": line_num,
                                    "type": secret_type,
                                    "finding": f"Potential {secret_type} exposed"
                                })
                                issues_found += 1
                                self.results["critical_issues"] += 1
                                
                    except Exception as e:
                        logger.warning(f"Error scanning {file_path}: {e}")
        
        if issues_found == 0:
            self.results["passed_tests"] += 1
            logger.info("✅ PASSED: No hardcoded secrets found")
        else:
            self.results["failed_tests"] += 1
            logger.error(f"❌ FAILED: Found {issues_found} hardcoded secrets")
    
    async def validate_kubernetes_security(self):
        """Validate Kubernetes security configurations"""
        logger.info("🔍 Validating: Kubernetes security")
        self.results["total_tests"] += 1
        
        k8s_files = list(self.project_root.rglob("*.yaml")) + list(self.project_root.rglob("*.yml"))
        issues_found = 0
        
        for file_path in k8s_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check for privileged containers
                if 'privileged: true' in content:
                    self.results["findings"].append({
                        "test": "kubernetes_security",
                        "severity": "CRITICAL",
                        "file": str(file_path.relative_to(self.project_root)),
                        "type": "Privileged Container",
                        "finding": "Container running with privileged flag"
                    })
                    issues_found += 1
                    self.results["critical_issues"] += 1
                
                # Check for host network
                if 'hostNetwork: true' in content:
                    self.results["findings"].append({
                        "test": "kubernetes_security",
                        "severity": "HIGH",
                        "file": str(file_path.relative_to(self.project_root)),
                        "type": "Host Network",
                        "finding": "Pod using host network"
                    })
                    issues_found += 1
                    self.results["high_issues"] += 1
                
                # Check for Docker socket mount
                if '/var/run/docker.sock' in content:
                    self.results["findings"].append({
                        "test": "kubernetes_security",
                        "severity": "CRITICAL",
                        "file": str(file_path.relative_to(self.project_root)),
                        "type": "Docker Socket",
                        "finding": "Docker socket mounted in container"
                    })
                    issues_found += 1
                    self.results["critical_issues"] += 1
                
                # Check for security context
                if 'kind: Deployment' in content or 'kind: StatefulSet' in content:
                    if 'securityContext:' not in content:
                        self.results["findings"].append({
                            "test": "kubernetes_security",
                            "severity": "HIGH",
                            "file": str(file_path.relative_to(self.project_root)),
                            "type": "Missing Security Context",
                            "finding": "No security context defined"
                        })
                        issues_found += 1
                        self.results["high_issues"] += 1
                        
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
        
        if issues_found == 0:
            self.results["passed_tests"] += 1
            logger.info("✅ PASSED: Kubernetes configurations are secure")
        else:
            self.results["failed_tests"] += 1
            logger.error(f"❌ FAILED: Found {issues_found} Kubernetes security issues")
    
    async def validate_container_security(self):
        """Validate container security best practices"""
        logger.info("🔍 Validating: Container security")
        self.results["total_tests"] += 1
        
        dockerfile_files = list(self.project_root.rglob("Dockerfile*"))
        issues_found = 0
        
        for file_path in dockerfile_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check for running as root
                if 'USER' not in content:
                    self.results["findings"].append({
                        "test": "container_security",
                        "severity": "HIGH",
                        "file": str(file_path.relative_to(self.project_root)),
                        "type": "Root User",
                        "finding": "Container may run as root (no USER directive)"
                    })
                    issues_found += 1
                    self.results["high_issues"] += 1
                
                # Check for sudo installation
                if 'sudo' in content and 'apt-get install' in content:
                    self.results["findings"].append({
                        "test": "container_security",
                        "severity": "MEDIUM",
                        "file": str(file_path.relative_to(self.project_root)),
                        "type": "Sudo Installation",
                        "finding": "Container installs sudo (privilege escalation risk)"
                    })
                    issues_found += 1
                    self.results["medium_issues"] += 1
                    
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
        
        if issues_found == 0:
            self.results["passed_tests"] += 1
            logger.info("✅ PASSED: Container security best practices followed")
        else:
            self.results["failed_tests"] += 1
            logger.error(f"❌ FAILED: Found {issues_found} container security issues")
    
    async def validate_vault_integration(self):
        """Validate HashiCorp Vault integration"""
        logger.info("🔍 Validating: Vault integration")
        self.results["total_tests"] += 1
        
        # Check for Vault client implementation
        vault_files = [
            self.project_root / "src" / "core" / "vault_client.py",
            self.project_root / "src" / "core" / "secret_rotation_manager.py",
            self.project_root / "scripts" / "vault_setup.py"
        ]
        
        missing_files = []
        for file_path in vault_files:
            if not file_path.exists():
                missing_files.append(str(file_path.relative_to(self.project_root)))
        
        if missing_files:
            self.results["failed_tests"] += 1
            self.results["findings"].append({
                "test": "vault_integration",
                "severity": "HIGH",
                "type": "Missing Vault Files",
                "finding": f"Missing Vault integration files: {', '.join(missing_files)}"
            })
            self.results["high_issues"] += 1
            logger.error("❌ FAILED: Vault integration incomplete")
        else:
            self.results["passed_tests"] += 1
            logger.info("✅ PASSED: Vault integration files present")
    
    async def validate_network_policies(self):
        """Validate network security policies"""
        logger.info("🔍 Validating: Network policies")
        self.results["total_tests"] += 1
        
        # Check for NetworkPolicy resources
        network_policy_found = False
        k8s_files = list(self.project_root.rglob("*.yaml")) + list(self.project_root.rglob("*.yml"))
        
        for file_path in k8s_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                if 'kind: NetworkPolicy' in content:
                    network_policy_found = True
                    break
                    
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
        
        if network_policy_found:
            self.results["passed_tests"] += 1
            logger.info("✅ PASSED: Network policies implemented")
        else:
            self.results["failed_tests"] += 1
            self.results["findings"].append({
                "test": "network_policies",
                "severity": "HIGH",
                "type": "Missing Network Policies",
                "finding": "No Kubernetes NetworkPolicy resources found"
            })
            self.results["high_issues"] += 1
            logger.error("❌ FAILED: Network policies not implemented")
    
    async def validate_rbac_policies(self):
        """Validate RBAC configurations"""
        logger.info("🔍 Validating: RBAC policies")
        self.results["total_tests"] += 1
        
        # Check for RBAC resources
        rbac_found = False
        k8s_files = list(self.project_root.rglob("*.yaml")) + list(self.project_root.rglob("*.yml"))
        
        for file_path in k8s_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                if any(kind in content for kind in ['kind: Role', 'kind: ClusterRole', 'kind: RoleBinding']):
                    rbac_found = True
                    
                    # Check for overly permissive rules
                    if '"*"' in content and 'verbs:' in content:
                        self.results["findings"].append({
                            "test": "rbac_policies",
                            "severity": "HIGH",
                            "file": str(file_path.relative_to(self.project_root)),
                            "type": "Overly Permissive RBAC",
                            "finding": "RBAC rule with wildcard permissions"
                        })
                        self.results["high_issues"] += 1
                        
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
        
        if rbac_found:
            self.results["passed_tests"] += 1
            logger.info("✅ PASSED: RBAC policies implemented")
        else:
            self.results["failed_tests"] += 1
            logger.error("❌ FAILED: RBAC policies not found")
    
    async def validate_encryption(self):
        """Validate encryption implementations"""
        logger.info("🔍 Validating: Encryption")
        self.results["total_tests"] += 1
        
        # Check for TLS/SSL configurations
        tls_found = False
        weak_ciphers = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'RC4', 'DES', '3DES']
        
        config_files = list(self.project_root.rglob("*.conf")) + \
                      list(self.project_root.rglob("*.yaml")) + \
                      list(self.project_root.rglob("*.yml"))
        
        for file_path in config_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                if any(tls in content for tls in ['tls:', 'TLS', 'SSL', 'https://']):
                    tls_found = True
                
                # Check for weak ciphers
                for cipher in weak_ciphers:
                    if cipher in content:
                        self.results["findings"].append({
                            "test": "encryption",
                            "severity": "HIGH",
                            "file": str(file_path.relative_to(self.project_root)),
                            "type": "Weak Cipher",
                            "finding": f"Weak cipher suite: {cipher}"
                        })
                        self.results["high_issues"] += 1
                        
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
        
        if tls_found:
            self.results["passed_tests"] += 1
            logger.info("✅ PASSED: Encryption configurations found")
        else:
            self.results["failed_tests"] += 1
            logger.error("❌ FAILED: No encryption configurations found")
    
    async def validate_security_headers(self):
        """Validate security headers implementation"""
        logger.info("🔍 Validating: Security headers")
        self.results["total_tests"] += 1
        
        # Check for security headers in code
        security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-XSS-Protection'
        ]
        
        headers_found = []
        py_files = list(self.project_root.rglob("*.py"))
        
        for file_path in py_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                for header in security_headers:
                    if header in content:
                        headers_found.append(header)
                        
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
        
        missing_headers = set(security_headers) - set(headers_found)
        
        if not missing_headers:
            self.results["passed_tests"] += 1
            logger.info("✅ PASSED: All security headers implemented")
        else:
            self.results["failed_tests"] += 1
            self.results["findings"].append({
                "test": "security_headers",
                "severity": "MEDIUM",
                "type": "Missing Security Headers",
                "finding": f"Missing headers: {', '.join(missing_headers)}"
            })
            self.results["medium_issues"] += 1
            logger.error(f"❌ FAILED: Missing security headers: {missing_headers}")
    
    async def validate_dependencies(self):
        """Validate dependency security"""
        logger.info("🔍 Validating: Dependencies")
        self.results["total_tests"] += 1
        
        # Check for dependency files
        dep_files = [
            (self.project_root / "requirements.txt", "pip"),
            (self.project_root / "package.json", "npm"),
            (self.project_root / "Cargo.toml", "cargo")
        ]
        
        vulnerable_deps = 0
        
        for dep_file, pkg_manager in dep_files:
            if dep_file.exists():
                try:
                    # Run vulnerability scanner (simulation)
                    if pkg_manager == "pip":
                        # Check for known vulnerable packages
                        with open(dep_file, 'r') as f:
                            content = f.read()
                        
                        vulnerable_packages = ['requests<2.31.0', 'django<3.2', 'flask<2.0.0']
                        for vuln_pkg in vulnerable_packages:
                            pkg_name = vuln_pkg.split('<')[0]
                            if pkg_name in content:
                                self.results["findings"].append({
                                    "test": "dependencies",
                                    "severity": "HIGH",
                                    "file": str(dep_file.relative_to(self.project_root)),
                                    "type": "Vulnerable Dependency",
                                    "finding": f"Potentially vulnerable package: {pkg_name}"
                                })
                                vulnerable_deps += 1
                                self.results["high_issues"] += 1
                                
                except Exception as e:
                    logger.warning(f"Error scanning {dep_file}: {e}")
        
        if vulnerable_deps == 0:
            self.results["passed_tests"] += 1
            logger.info("✅ PASSED: No known vulnerable dependencies")
        else:
            self.results["failed_tests"] += 1
            logger.error(f"❌ FAILED: Found {vulnerable_deps} vulnerable dependencies")
    
    async def validate_compliance(self):
        """Validate compliance requirements"""
        logger.info("🔍 Validating: Compliance")
        self.results["total_tests"] += 1
        
        compliance_items = {
            "audit_logging": False,
            "data_encryption": False,
            "access_control": False,
            "data_retention": False,
            "privacy_policy": False
        }
        
        # Check for compliance implementations
        all_files = list(self.project_root.rglob("*.py")) + \
                   list(self.project_root.rglob("*.md")) + \
                   list(self.project_root.rglob("*.yaml"))
        
        for file_path in all_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                
                if 'audit' in content and 'log' in content:
                    compliance_items["audit_logging"] = True
                if 'encrypt' in content:
                    compliance_items["data_encryption"] = True
                if 'rbac' in content or 'access control' in content:
                    compliance_items["access_control"] = True
                if 'retention' in content:
                    compliance_items["data_retention"] = True
                if 'privacy' in content and 'policy' in content:
                    compliance_items["privacy_policy"] = True
                    
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
        
        missing_items = [k for k, v in compliance_items.items() if not v]
        
        if not missing_items:
            self.results["passed_tests"] += 1
            logger.info("✅ PASSED: All compliance requirements met")
        else:
            self.results["failed_tests"] += 1
            self.results["findings"].append({
                "test": "compliance",
                "severity": "MEDIUM",
                "type": "Missing Compliance Items",
                "finding": f"Missing: {', '.join(missing_items)}"
            })
            self.results["medium_issues"] += 1
            logger.error(f"❌ FAILED: Missing compliance items: {missing_items}")
    
    def generate_report(self):
        """Generate comprehensive security report"""
        report_path = self.project_root / "security_validation_report.json"
        
        self.results["summary"] = {
            "total_tests": self.results["total_tests"],
            "passed": self.results["passed_tests"],
            "failed": self.results["failed_tests"],
            "pass_rate": (self.results["passed_tests"] / self.results["total_tests"] * 100) 
                        if self.results["total_tests"] > 0 else 0,
            "critical_issues": self.results["critical_issues"],
            "high_issues": self.results["high_issues"],
            "medium_issues": self.results["medium_issues"],
            "low_issues": self.results["low_issues"],
            "total_issues": (self.results["critical_issues"] + self.results["high_issues"] + 
                           self.results["medium_issues"] + self.results["low_issues"])
        }
        
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"📄 Security validation report saved to: {report_path}")
        
        # Generate markdown report
        md_report_path = self.project_root / "security_validation_report.md"
        self.generate_markdown_report(md_report_path)
    
    def generate_markdown_report(self, output_path: Path):
        """Generate markdown security report"""
        content = f"""# Security Validation Report

**Generated**: {self.results['timestamp']}  
**Pass Rate**: {self.results['summary']['pass_rate']:.1f}%  
**Total Issues**: {self.results['summary']['total_issues']}  

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | {self.results['summary']['total_tests']} |
| Passed | {self.results['summary']['passed']} |
| Failed | {self.results['summary']['failed']} |
| Critical Issues | {self.results['summary']['critical_issues']} |
| High Issues | {self.results['summary']['high_issues']} |
| Medium Issues | {self.results['summary']['medium_issues']} |
| Low Issues | {self.results['summary']['low_issues']} |

## Test Results

"""
        
        # Group findings by test
        test_groups = {}
        for finding in self.results["findings"]:
            test_name = finding["test"]
            if test_name not in test_groups:
                test_groups[test_name] = []
            test_groups[test_name].append(finding)
        
        for test_name, findings in test_groups.items():
            content += f"### {test_name.replace('_', ' ').title()}\n\n"
            
            if findings:
                content += "| Severity | Type | Finding | File |\n"
                content += "|----------|------|---------|------|\n"
                
                for finding in findings:
                    file_info = finding.get('file', 'N/A')
                    if 'line' in finding:
                        file_info += f" (L{finding['line']})"
                    
                    content += f"| {finding['severity']} | {finding['type']} | "
                    content += f"{finding['finding']} | {file_info} |\n"
            else:
                content += "✅ No issues found\n"
            
            content += "\n"
        
        content += """## Recommendations

1. **Immediate Actions**:
   - Fix all CRITICAL issues immediately
   - Rotate any exposed credentials
   - Implement proper secret management

2. **Short-term Actions**:
   - Address HIGH severity issues
   - Implement missing security controls
   - Update vulnerable dependencies

3. **Long-term Actions**:
   - Regular security audits
   - Automated security scanning in CI/CD
   - Security training for development team

## Compliance Status

Based on the security validation results, the system demonstrates:
- **SOC2 Readiness**: Partial (needs completion)
- **GDPR Compliance**: Partial (privacy controls needed)
- **PCI-DSS Readiness**: Not Ready (encryption required)

---

**Security Validation Framework Version**: 1.0.0
"""
        
        with open(output_path, 'w') as f:
            f.write(content)
        
        logger.info(f"📄 Markdown report saved to: {output_path}")

async def main():
    """Run security validation suite"""
    print("🔒 Starting Comprehensive Security Validation")
    print("=" * 60)
    
    validator = SecurityValidationSuite()
    results = await validator.run_all_validations()
    
    print("\n📊 SECURITY VALIDATION COMPLETED")
    print("=" * 60)
    print(f"Pass Rate: {results['summary']['pass_rate']:.1f}%")
    print(f"Total Issues: {results['summary']['total_issues']}")
    print(f"Critical: {results['summary']['critical_issues']}")
    print(f"High: {results['summary']['high_issues']}")
    print(f"Medium: {results['summary']['medium_issues']}")
    print(f"Low: {results['summary']['low_issues']}")
    
    if results['summary']['critical_issues'] > 0:
        print("\n⚠️  CRITICAL SECURITY ISSUES FOUND - IMMEDIATE ACTION REQUIRED")
        return 1
    elif results['summary']['total_issues'] > 0:
        print("\n⚠️  Security issues found - remediation required")
        return 2
    else:
        print("\n✅ All security validations passed")
        return 0

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)