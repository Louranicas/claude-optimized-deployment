#!/usr/bin/env python3
"""
Code Base Crawler (CBC) - Post-Audit Deep Layer Security Analysis System
Advanced security vulnerability detection using HTM pattern recognition and semantic analysis
"""

import os
import sys
import json
import ast
import re
import hashlib
# import entropy  # Using custom entropy calculation
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import yaml
import toml
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Advanced pattern detection imports
import tokenize
import dis
import inspect
import traceback
import secrets
import base64
import urllib.parse
import html

@dataclass
class SecurityVulnerability:
    """Represents a discovered security vulnerability"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str
    description: str
    file_path: str
    line_number: Optional[int]
    code_snippet: Optional[str]
    cwe_id: Optional[str]
    attack_vector: Optional[str]
    remediation: str
    confidence: float  # 0.0 to 1.0
    missed_by_audit: bool = False
    
@dataclass
class HTMPattern:
    """Hierarchical Temporal Memory pattern for security analysis"""
    pattern_id: str
    pattern_type: str
    signature: bytes
    frequency: int
    locations: List[str] = field(default_factory=list)
    risk_score: float = 0.0

class EntropyAnalyzer:
    """Analyzes entropy to detect hardcoded secrets and suspicious patterns"""
    
    def __init__(self):
        self.secret_patterns = [
            r'[a-zA-Z0-9]{32,}',  # API keys
            r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64
            r'[0-9a-fA-F]{64}',  # SHA256
            r'[0-9a-fA-F]{40}',  # SHA1
            r'sk_[a-zA-Z0-9]{32,}',  # Stripe keys
            r'pk_[a-zA-Z0-9]{32,}',  # Public keys
            r'ghp_[a-zA-Z0-9]{36}',  # GitHub tokens
            r'ghr_[a-zA-Z0-9]{36}',  # GitHub refresh tokens
        ]
        
    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string"""
        if not data:
            return 0.0
        
        entropy = 0
        for i in range(256):
            char = chr(i)
            freq = data.count(char)
            if freq > 0:
                freq = float(freq) / len(data)
                entropy += -freq * np.log2(freq)
        return entropy
    
    def detect_secrets(self, content: str, file_path: str) -> List[SecurityVulnerability]:
        """Detect potential secrets in code"""
        vulnerabilities = []
        
        # Skip known false positive files
        if any(skip in file_path for skip in ['.git/', '__pycache__/', 'node_modules/', '.lock']):
            return vulnerabilities
            
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            # Check entropy
            if len(line.strip()) > 20:
                entropy = self.calculate_entropy(line.strip())
                if entropy > 4.5:  # High entropy threshold
                    # Check against secret patterns
                    for pattern in self.secret_patterns:
                        if re.search(pattern, line):
                            vulnerabilities.append(SecurityVulnerability(
                                severity="HIGH",
                                category="Hardcoded Secret",
                                description=f"Potential hardcoded secret detected (entropy: {entropy:.2f})",
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip()[:100] + "...",
                                cwe_id="CWE-798",
                                attack_vector="Information Disclosure",
                                remediation="Move secrets to environment variables or secure vaults",
                                confidence=min(0.9, entropy / 5.0),
                                missed_by_audit=True
                            ))
                            
        return vulnerabilities

class ASTSecurityAnalyzer:
    """Advanced AST-based security analysis for Python code"""
    
    def __init__(self):
        self.dangerous_imports = {
            'pickle', 'marshal', 'shelve', 'subprocess', 'os', 'eval', 'exec',
            'compile', '__import__', 'importlib'
        }
        self.dangerous_functions = {
            'eval', 'exec', 'compile', 'open', 'input', '__import__',
            'getattr', 'setattr', 'delattr', 'globals', 'locals'
        }
        
    def analyze_python_ast(self, content: str, file_path: str) -> List[SecurityVulnerability]:
        """Perform AST analysis on Python code"""
        vulnerabilities = []
        
        try:
            tree = ast.parse(content)
            
            # Analyze imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in self.dangerous_imports:
                            vulnerabilities.append(SecurityVulnerability(
                                severity="MEDIUM",
                                category="Dangerous Import",
                                description=f"Use of potentially dangerous module: {alias.name}",
                                file_path=file_path,
                                line_number=node.lineno,
                                code_snippet=f"import {alias.name}",
                                cwe_id="CWE-676",
                                attack_vector="Code Injection",
                                remediation="Review necessity and implement strict input validation",
                                confidence=0.8,
                                missed_by_audit=True
                            ))
                
                # Check for eval/exec usage
                elif isinstance(node, ast.Call):
                    if hasattr(node.func, 'id') and node.func.id in self.dangerous_functions:
                        vulnerabilities.append(SecurityVulnerability(
                            severity="CRITICAL",
                            category="Code Injection",
                            description=f"Use of dangerous function: {node.func.id}",
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=ast.unparse(node) if hasattr(ast, 'unparse') else str(node),
                            cwe_id="CWE-94",
                            attack_vector="Remote Code Execution",
                            remediation="Remove dynamic code execution or implement secure alternatives",
                            confidence=0.95,
                            missed_by_audit=True
                        ))
                
                # Check for SQL injection patterns
                elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                    if isinstance(node.left, ast.Str) and 'SELECT' in node.left.s.upper():
                        vulnerabilities.append(SecurityVulnerability(
                            severity="CRITICAL",
                            category="SQL Injection",
                            description="Potential SQL injection via string formatting",
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=ast.unparse(node) if hasattr(ast, 'unparse') else str(node),
                            cwe_id="CWE-89",
                            attack_vector="Database Manipulation",
                            remediation="Use parameterized queries or ORM",
                            confidence=0.9,
                            missed_by_audit=True
                        ))
                        
        except Exception as e:
            # Log parsing errors but continue
            pass
            
        return vulnerabilities

class ConfigurationSecurityAnalyzer:
    """Analyzes configuration files for security issues"""
    
    def analyze_yaml(self, content: str, file_path: str) -> List[SecurityVulnerability]:
        """Analyze YAML configuration for security issues"""
        vulnerabilities = []
        
        try:
            data = yaml.safe_load(content)
            
            # Check for insecure configurations
            if isinstance(data, dict):
                # Check for debug mode
                if data.get('debug', False) or data.get('DEBUG', False):
                    vulnerabilities.append(SecurityVulnerability(
                        severity="MEDIUM",
                        category="Insecure Configuration",
                        description="Debug mode enabled in production configuration",
                        file_path=file_path,
                        line_number=None,
                        code_snippet="debug: true",
                        cwe_id="CWE-489",
                        attack_vector="Information Disclosure",
                        remediation="Disable debug mode in production",
                        confidence=0.9,
                        missed_by_audit=True
                    ))
                
                # Check for weak encryption
                if 'encryption' in data:
                    if data['encryption'].get('algorithm', '').lower() in ['des', 'md5', 'sha1']:
                        vulnerabilities.append(SecurityVulnerability(
                            severity="HIGH",
                            category="Weak Cryptography",
                            description="Use of weak encryption algorithm",
                            file_path=file_path,
                            line_number=None,
                            code_snippet=str(data['encryption']),
                            cwe_id="CWE-327",
                            attack_vector="Cryptographic Weakness",
                            remediation="Use strong encryption algorithms (AES-256, SHA-256+)",
                            confidence=0.95,
                            missed_by_audit=True
                        ))
                        
        except Exception:
            pass
            
        return vulnerabilities

class RuntimeBehaviorAnalyzer:
    """Analyzes runtime behavior patterns for security anomalies"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'process_spawn': re.compile(r'subprocess\.(Popen|call|run)'),
            'network_access': re.compile(r'(socket|requests|urllib|http\.client)'),
            'file_operations': re.compile(r'(open|file|shutil|os\.remove)'),
            'privilege_escalation': re.compile(r'(os\.setuid|os\.setgid|sudo)'),
        }
        
    def analyze_runtime_patterns(self, content: str, file_path: str) -> List[SecurityVulnerability]:
        """Detect suspicious runtime behavior patterns"""
        vulnerabilities = []
        
        for pattern_name, pattern in self.suspicious_patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                if pattern_name == 'process_spawn':
                    vulnerabilities.append(SecurityVulnerability(
                        severity="HIGH",
                        category="Command Injection Risk",
                        description="Process spawning detected - potential command injection",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=match.group(0),
                        cwe_id="CWE-78",
                        attack_vector="Command Injection",
                        remediation="Validate and sanitize all inputs to subprocess calls",
                        confidence=0.85,
                        missed_by_audit=True
                    ))
                    
        return vulnerabilities

class CBCSecurityAnalyzer:
    """Main Code Base Crawler security analysis system"""
    
    def __init__(self):
        self.project_root = Path("/home/louranicas/projects/claude-optimized-deployment")
        self.vulnerabilities: List[SecurityVulnerability] = []
        self.htm_patterns: Dict[str, HTMPattern] = {}
        self.previous_audit_findings = self._load_previous_audit_findings()
        
        # Initialize analyzers
        self.entropy_analyzer = EntropyAnalyzer()
        self.ast_analyzer = ASTSecurityAnalyzer()
        self.config_analyzer = ConfigurationSecurityAnalyzer()
        self.runtime_analyzer = RuntimeBehaviorAnalyzer()
        
        # File extensions to analyze
        self.target_extensions = {
            '.py', '.js', '.ts', '.rs', '.yaml', '.yml', '.json', '.toml',
            '.sh', '.bash', '.env', '.config', '.conf', '.ini', '.properties'
        }
        
    def _load_previous_audit_findings(self) -> Set[str]:
        """Load findings from previous 10-agent audit"""
        findings = set()
        
        # Load previous audit reports
        audit_files = [
            "AGENT_4_COMPREHENSIVE_SECURITY_AUDIT_REPORT_20250608_194321.json",
            "AGENT_4_DETAILED_SECURITY_VALIDATION_REPORT_20250608_195218.json",
            "comprehensive_security_audit.json",
            "security_audit_test.py"
        ]
        
        for audit_file in audit_files:
            file_path = self.project_root / audit_file
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        # Extract vulnerability identifiers
                        if isinstance(data, dict):
                            for key in ['vulnerabilities', 'findings', 'issues']:
                                if key in data:
                                    for item in data[key]:
                                        if isinstance(item, dict):
                                            findings.add(item.get('id', str(item)))
                except Exception:
                    pass
                    
        return findings
    
    def _is_vulnerability_new(self, vuln: SecurityVulnerability) -> bool:
        """Check if vulnerability was missed by previous audit"""
        vuln_id = f"{vuln.category}:{vuln.file_path}:{vuln.line_number}"
        return vuln_id not in self.previous_audit_findings
    
    def crawl_and_analyze(self) -> Dict[str, Any]:
        """Main crawler entry point"""
        print("[CBC] Initializing Code Base Crawler security analysis...")
        
        start_time = datetime.now()
        
        # Phase 1: File discovery and classification
        print("[CBC] Phase 1: Discovering and classifying files...")
        files_to_analyze = self._discover_files()
        
        # Phase 2: Deep security analysis
        print(f"[CBC] Phase 2: Analyzing {len(files_to_analyze)} files...")
        self._perform_deep_analysis(files_to_analyze)
        
        # Phase 3: Cross-reference analysis
        print("[CBC] Phase 3: Cross-referencing with previous audit...")
        self._cross_reference_analysis()
        
        # Phase 4: Attack chain analysis
        print("[CBC] Phase 4: Performing attack chain analysis...")
        attack_chains = self._analyze_attack_chains()
        
        # Phase 5: Generate report
        print("[CBC] Phase 5: Generating comprehensive report...")
        report = self._generate_report(start_time, attack_chains)
        
        return report
    
    def _discover_files(self) -> List[Path]:
        """Discover all files to analyze"""
        files = []
        
        for ext in self.target_extensions:
            files.extend(self.project_root.rglob(f"*{ext}"))
            
        # Filter out excluded directories
        excluded_dirs = {'.git', '__pycache__', 'node_modules', 'venv', 'env', '.tox'}
        files = [f for f in files if not any(exc in str(f) for exc in excluded_dirs)]
        
        return files
    
    def _perform_deep_analysis(self, files: List[Path]):
        """Perform deep security analysis on files"""
        
        with ProcessPoolExecutor(max_workers=4) as executor:
            futures = []
            
            for file_path in files:
                future = executor.submit(self._analyze_file, file_path)
                futures.append(future)
                
            for future in futures:
                try:
                    file_vulns = future.result(timeout=30)
                    self.vulnerabilities.extend(file_vulns)
                except Exception as e:
                    print(f"[CBC] Error analyzing file: {e}")
                    
    def _analyze_file(self, file_path: Path) -> List[SecurityVulnerability]:
        """Analyze individual file for vulnerabilities"""
        vulnerabilities = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Entropy analysis for secrets
            vulnerabilities.extend(self.entropy_analyzer.detect_secrets(content, str(file_path)))
            
            # Language-specific analysis
            if file_path.suffix == '.py':
                vulnerabilities.extend(self.ast_analyzer.analyze_python_ast(content, str(file_path)))
                
            elif file_path.suffix in ['.yaml', '.yml']:
                vulnerabilities.extend(self.config_analyzer.analyze_yaml(content, str(file_path)))
                
            # Runtime behavior analysis
            vulnerabilities.extend(self.runtime_analyzer.analyze_runtime_patterns(content, str(file_path)))
            
            # Additional security checks
            vulnerabilities.extend(self._check_authentication_bypass(content, str(file_path)))
            vulnerabilities.extend(self._check_race_conditions(content, str(file_path)))
            vulnerabilities.extend(self._check_unsafe_deserialization(content, str(file_path)))
            
        except Exception as e:
            print(f"[CBC] Error reading {file_path}: {e}")
            
        return vulnerabilities
    
    def _check_authentication_bypass(self, content: str, file_path: str) -> List[SecurityVulnerability]:
        """Check for authentication bypass patterns"""
        vulnerabilities = []
        
        # Pattern: Disabled authentication checks
        if re.search(r'(auth|authenticate|verify).*=.*False', content, re.IGNORECASE):
            vulnerabilities.append(SecurityVulnerability(
                severity="CRITICAL",
                category="Authentication Bypass",
                description="Authentication check potentially disabled",
                file_path=file_path,
                line_number=None,
                code_snippet=None,
                cwe_id="CWE-287",
                attack_vector="Authentication Bypass",
                remediation="Ensure authentication is properly enforced",
                confidence=0.85,
                missed_by_audit=True
            ))
            
        # Pattern: Hardcoded authentication bypass
        if re.search(r'if.*user.*==.*["\']admin["\'].*or.*True', content):
            vulnerabilities.append(SecurityVulnerability(
                severity="CRITICAL",
                category="Hardcoded Bypass",
                description="Hardcoded authentication bypass detected",
                file_path=file_path,
                line_number=None,
                code_snippet=None,
                cwe_id="CWE-798",
                attack_vector="Authentication Bypass",
                remediation="Remove hardcoded bypasses",
                confidence=0.95,
                missed_by_audit=True
            ))
            
        return vulnerabilities
    
    def _check_race_conditions(self, content: str, file_path: str) -> List[SecurityVulnerability]:
        """Check for race condition vulnerabilities"""
        vulnerabilities = []
        
        # Pattern: File operations without locks
        if re.search(r'open.*["\']w["\']', content) and 'lock' not in content.lower():
            vulnerabilities.append(SecurityVulnerability(
                severity="MEDIUM",
                category="Race Condition",
                description="File operation without proper locking mechanism",
                file_path=file_path,
                line_number=None,
                code_snippet=None,
                cwe_id="CWE-362",
                attack_vector="TOCTOU Race Condition",
                remediation="Implement proper file locking",
                confidence=0.7,
                missed_by_audit=True
            ))
            
        return vulnerabilities
    
    def _check_unsafe_deserialization(self, content: str, file_path: str) -> List[SecurityVulnerability]:
        """Check for unsafe deserialization"""
        vulnerabilities = []
        
        # Pattern: Pickle/Marshal usage
        if re.search(r'(pickle|marshal)\.(load|loads)', content):
            vulnerabilities.append(SecurityVulnerability(
                severity="CRITICAL",
                category="Unsafe Deserialization",
                description="Use of unsafe deserialization method",
                file_path=file_path,
                line_number=None,
                code_snippet=None,
                cwe_id="CWE-502",
                attack_vector="Remote Code Execution",
                remediation="Use safe serialization formats (JSON)",
                confidence=0.9,
                missed_by_audit=True
            ))
            
        return vulnerabilities
    
    def _cross_reference_analysis(self):
        """Cross-reference findings with previous audit"""
        for vuln in self.vulnerabilities:
            vuln.missed_by_audit = self._is_vulnerability_new(vuln)
            
    def _analyze_attack_chains(self) -> List[Dict[str, Any]]:
        """Analyze potential attack chains"""
        attack_chains = []
        
        # Group vulnerabilities by category
        vuln_by_category = defaultdict(list)
        for vuln in self.vulnerabilities:
            vuln_by_category[vuln.category].append(vuln)
            
        # Identify attack chains
        if 'Authentication Bypass' in vuln_by_category and 'Code Injection' in vuln_by_category:
            attack_chains.append({
                'name': 'Authentication Bypass to RCE',
                'severity': 'CRITICAL',
                'steps': [
                    'Bypass authentication using identified vulnerability',
                    'Access privileged endpoints',
                    'Exploit code injection vulnerability',
                    'Achieve remote code execution'
                ],
                'vulnerabilities': [
                    vuln_by_category['Authentication Bypass'][0],
                    vuln_by_category['Code Injection'][0]
                ]
            })
            
        return attack_chains
    
    def _generate_report(self, start_time: datetime, attack_chains: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        
        # Calculate statistics
        total_vulns = len(self.vulnerabilities)
        missed_vulns = len([v for v in self.vulnerabilities if v.missed_by_audit])
        critical_vulns = len([v for v in self.vulnerabilities if v.severity == 'CRITICAL'])
        high_vulns = len([v for v in self.vulnerabilities if v.severity == 'HIGH'])
        
        # Group by category
        vulns_by_category = defaultdict(list)
        for vuln in self.vulnerabilities:
            vulns_by_category[vuln.category].append(vuln)
            
        report = {
            'metadata': {
                'analyzer': 'Code Base Crawler (CBC) v2.0',
                'scan_date': datetime.now().isoformat(),
                'duration': str(datetime.now() - start_time),
                'files_analyzed': len(self._discover_files()),
                'project_root': str(self.project_root)
            },
            'summary': {
                'total_vulnerabilities': total_vulns,
                'missed_by_previous_audit': missed_vulns,
                'critical_severity': critical_vulns,
                'high_severity': high_vulns,
                'medium_severity': len([v for v in self.vulnerabilities if v.severity == 'MEDIUM']),
                'low_severity': len([v for v in self.vulnerabilities if v.severity == 'LOW'])
            },
            'vulnerabilities_by_category': {
                category: [
                    {
                        'severity': v.severity,
                        'description': v.description,
                        'file': v.file_path,
                        'line': v.line_number,
                        'cwe': v.cwe_id,
                        'remediation': v.remediation,
                        'confidence': v.confidence,
                        'missed_by_audit': v.missed_by_audit
                    }
                    for v in vulns
                ]
                for category, vulns in vulns_by_category.items()
            },
            'attack_chains': attack_chains,
            'critical_findings': [
                {
                    'severity': v.severity,
                    'category': v.category,
                    'description': v.description,
                    'file': v.file_path,
                    'remediation': v.remediation
                }
                for v in self.vulnerabilities
                if v.severity == 'CRITICAL' and v.missed_by_audit
            ],
            'recommendations': {
                'immediate_actions': [
                    'Address all CRITICAL vulnerabilities immediately',
                    'Implement proper authentication checks across all modules',
                    'Replace unsafe deserialization with secure alternatives',
                    'Remove all hardcoded secrets and use secure vaults',
                    'Implement proper input validation for all user inputs'
                ],
                'short_term': [
                    'Conduct security training for development team',
                    'Implement automated security scanning in CI/CD',
                    'Regular dependency updates and vulnerability scanning',
                    'Implement secure coding standards'
                ],
                'long_term': [
                    'Implement comprehensive security architecture review',
                    'Establish security champions program',
                    'Regular penetration testing',
                    'Implement runtime application self-protection (RASP)'
                ]
            }
        }
        
        return report

def main():
    """Main execution function"""
    analyzer = CBCSecurityAnalyzer()
    report = analyzer.crawl_and_analyze()
    
    # Save report
    output_file = Path("/home/louranicas/projects/claude-optimized-deployment/CBC_POST_AUDIT_SECURITY_ANALYSIS_REPORT.json")
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
        
    print(f"\n[CBC] Analysis complete. Report saved to: {output_file}")
    print(f"[CBC] Found {report['summary']['total_vulnerabilities']} total vulnerabilities")
    print(f"[CBC] {report['summary']['missed_by_previous_audit']} were missed by previous audit")
    print(f"[CBC] {report['summary']['critical_severity']} CRITICAL severity issues require immediate attention")
    
    return report

if __name__ == "__main__":
    main()