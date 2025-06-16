"""
Security validation module for comprehensive security testing and auditing.

This module consolidates functionality from multiple security scripts:
- security_audit.py
- security_audit_pip.json
- security_audit_circle_consultation.py
- test_security_updates.py
- validate_security_updates.py
- security_audit_test.py

Provides a unified interface for security validation, vulnerability scanning,
and compliance checking following enterprise security standards.
"""

import subprocess
import json
import os
import re
import ast
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import hashlib
import yaml

logger = logging.getLogger(__name__)


@dataclass
class SecurityVulnerability:
    """Represents a security vulnerability."""
    severity: str  # critical, high, medium, low, info
    category: str  # injection, auth, crypto, etc.
    description: str
    file_path: Optional[Path] = None
    line_number: Optional[int] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    
    
@dataclass 
class SecurityScanResult:
    """Results from a security scan."""
    scan_type: str
    timestamp: datetime
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    vulnerabilities: List[SecurityVulnerability] = field(default_factory=list)
    scan_duration: float = 0.0
    success: bool = True
    error_message: Optional[str] = None
    
    def add_vulnerability(self, vuln: SecurityVulnerability):
        """Add a vulnerability and update counts."""
        self.vulnerabilities.append(vuln)
        self.total_issues += 1
        
        if vuln.severity == 'critical':
            self.critical_count += 1
        elif vuln.severity == 'high':
            self.high_count += 1
        elif vuln.severity == 'medium':
            self.medium_count += 1
        elif vuln.severity == 'low':
            self.low_count += 1
        elif vuln.severity == 'info':
            self.info_count += 1


@dataclass
class ComplianceCheckResult:
    """Results from compliance checking."""
    framework: str  # OWASP, PCI-DSS, GDPR, etc.
    compliant: bool
    score: float  # 0.0 to 100.0
    passed_checks: int
    total_checks: int
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class SecurityValidator:
    """
    Comprehensive security validation and testing framework.
    
    Consolidates security testing functionality from multiple scripts
    into a unified, production-ready security validation suite.
    """
    
    # OWASP Top 10 2021 categories
    OWASP_TOP_10 = {
        'A01': 'Broken Access Control',
        'A02': 'Cryptographic Failures', 
        'A03': 'Injection',
        'A04': 'Insecure Design',
        'A05': 'Security Misconfiguration',
        'A06': 'Vulnerable and Outdated Components',
        'A07': 'Identification and Authentication Failures',
        'A08': 'Software and Data Integrity Failures',
        'A09': 'Security Logging and Monitoring Failures',
        'A10': 'Server-Side Request Forgery (SSRF)'
    }
    
    # Common security patterns to check
    SECURITY_PATTERNS = {
        'hardcoded_secret': re.compile(r'(password|secret|key|token)\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
        'sql_injection': re.compile(r'(SELECT|INSERT|UPDATE|DELETE).*\+.*%(s|d)', re.IGNORECASE),
        'command_injection': re.compile(r'(subprocess|os\.system|eval|exec)\s*\([^)]*\+[^)]*\)'),
        'path_traversal': re.compile(r'\.\./|\.\.\\'),
        'weak_crypto': re.compile(r'(md5|sha1)\s*\('),
        'insecure_random': re.compile(r'random\.(random|randint|choice)\s*\('),
        'hardcoded_ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        'debug_enabled': re.compile(r'DEBUG\s*=\s*True'),
        'cors_wildcard': re.compile(r'Access-Control-Allow-Origin.*\*'),
        'eval_usage': re.compile(r'\b(eval|exec)\s*\(')
    }
    
    def __init__(self, project_root: Optional[Path] = None):
        """
        Initialize SecurityValidator.
        
        Args:
            project_root: Root directory of the project. Defaults to current directory.
        """
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self._ensure_tools_installed()
        
    def _ensure_tools_installed(self):
        """Ensure required security tools are installed."""
        required_tools = {
            'bandit': 'pip install bandit',
            'safety': 'pip install safety',
            'pip-audit': 'pip install pip-audit',
            'semgrep': 'pip install semgrep'
        }
        
        missing_tools = []
        for tool, install_cmd in required_tools.items():
            if not self._is_tool_available(tool):
                missing_tools.append(f"{tool} ({install_cmd})")
                
        if missing_tools:
            logger.warning(f"Missing security tools: {', '.join(missing_tools)}")
            
    def _is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH."""
        try:
            subprocess.run([tool_name, '--version'], 
                         capture_output=True, 
                         check=False)
            return True
        except FileNotFoundError:
            return False
            
    def run_full_audit(self, 
                      include_patterns: Optional[List[str]] = None,
                      exclude_patterns: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run a comprehensive security audit.
        
        Args:
            include_patterns: File patterns to include
            exclude_patterns: File patterns to exclude
            
        Returns:
            Dictionary with all audit results
        """
        start_time = datetime.now()
        results = {
            'timestamp': start_time.isoformat(),
            'project_root': str(self.project_root),
            'scans': {},
            'compliance': {},
            'summary': {}
        }
        
        # Run various security scans
        logger.info("Running static code analysis...")
        results['scans']['static_analysis'] = self.run_static_analysis(
            include_patterns, exclude_patterns
        )
        
        logger.info("Running dependency vulnerability scan...")
        results['scans']['dependencies'] = self.scan_dependencies()
        
        logger.info("Running secret detection...")
        results['scans']['secrets'] = self.scan_for_secrets()
        
        logger.info("Running SAST analysis...")
        results['scans']['sast'] = self.run_sast_scan()
        
        logger.info("Running container security scan...")
        results['scans']['containers'] = self.scan_containers()
        
        # Check compliance
        logger.info("Checking OWASP Top 10 compliance...")
        results['compliance']['owasp'] = self.check_owasp_compliance(results['scans'])
        
        logger.info("Checking security best practices...")
        results['compliance']['best_practices'] = self.check_security_best_practices()
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        results['summary']['total_duration'] = (datetime.now() - start_time).total_seconds()
        
        return results
        
    def run_static_analysis(self,
                           include_patterns: Optional[List[str]] = None,
                           exclude_patterns: Optional[List[str]] = None) -> SecurityScanResult:
        """
        Run static code analysis for security issues.
        
        Args:
            include_patterns: File patterns to include
            exclude_patterns: File patterns to exclude
            
        Returns:
            SecurityScanResult with findings
        """
        result = SecurityScanResult(
            scan_type='static_analysis',
            timestamp=datetime.now()
        )
        
        start_time = datetime.now()
        
        # Use Bandit for Python security analysis
        if self._is_tool_available('bandit'):
            try:
                cmd = ['bandit', '-r', str(self.project_root), '-f', 'json']
                
                if exclude_patterns:
                    excludes = ','.join(exclude_patterns)
                    cmd.extend(['-x', excludes])
                    
                output = subprocess.run(cmd, capture_output=True, text=True)
                
                if output.stdout:
                    bandit_results = json.loads(output.stdout)
                    
                    for issue in bandit_results.get('results', []):
                        severity = issue['issue_severity'].lower()
                        
                        vuln = SecurityVulnerability(
                            severity=severity,
                            category='static_analysis',
                            description=f"{issue['issue_text']} - {issue['test_name']}",
                            file_path=Path(issue['filename']),
                            line_number=issue['line_number'],
                            remediation=issue.get('more_info', '')
                        )
                        
                        result.add_vulnerability(vuln)
                        
            except Exception as e:
                logger.error(f"Bandit scan failed: {e}")
                result.success = False
                result.error_message = str(e)
                
        # Custom pattern-based analysis
        python_files = list(self.project_root.rglob("*.py"))
        
        if exclude_patterns:
            for pattern in exclude_patterns:
                python_files = [f for f in python_files if pattern not in str(f)]
                
        for file_path in python_files:
            self._analyze_file_patterns(file_path, result)
            
        result.scan_duration = (datetime.now() - start_time).total_seconds()
        return result
        
    def _analyze_file_patterns(self, file_path: Path, result: SecurityScanResult):
        """Analyze a file for security patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            lines = content.split('\n')
            
            for pattern_name, pattern in self.SECURITY_PATTERNS.items():
                for i, line in enumerate(lines, 1):
                    if pattern.search(line):
                        severity = self._get_pattern_severity(pattern_name)
                        
                        vuln = SecurityVulnerability(
                            severity=severity,
                            category=pattern_name,
                            description=f"Potential {pattern_name.replace('_', ' ')} detected",
                            file_path=file_path,
                            line_number=i,
                            remediation=self._get_pattern_remediation(pattern_name)
                        )
                        
                        result.add_vulnerability(vuln)
                        
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            
    def _get_pattern_severity(self, pattern_name: str) -> str:
        """Get severity for a pattern type."""
        severity_map = {
            'hardcoded_secret': 'high',
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'path_traversal': 'high',
            'weak_crypto': 'medium',
            'insecure_random': 'low',
            'hardcoded_ip': 'low',
            'debug_enabled': 'medium',
            'cors_wildcard': 'medium',
            'eval_usage': 'high'
        }
        return severity_map.get(pattern_name, 'medium')
        
    def _get_pattern_remediation(self, pattern_name: str) -> str:
        """Get remediation advice for a pattern."""
        remediation_map = {
            'hardcoded_secret': 'Use environment variables or secure key management',
            'sql_injection': 'Use parameterized queries or ORM',
            'command_injection': 'Sanitize inputs and use safe subprocess methods',
            'path_traversal': 'Validate and sanitize file paths',
            'weak_crypto': 'Use strong cryptographic algorithms (SHA-256+)',
            'insecure_random': 'Use secrets module for security-sensitive randomness',
            'hardcoded_ip': 'Use configuration files or environment variables',
            'debug_enabled': 'Ensure DEBUG is False in production',
            'cors_wildcard': 'Configure specific allowed origins',
            'eval_usage': 'Avoid eval/exec or use safe alternatives'
        }
        return remediation_map.get(pattern_name, 'Review and fix security issue')
        
    def scan_dependencies(self) -> SecurityScanResult:
        """
        Scan project dependencies for known vulnerabilities.
        
        Returns:
            SecurityScanResult with dependency vulnerabilities
        """
        result = SecurityScanResult(
            scan_type='dependencies',
            timestamp=datetime.now()
        )
        
        start_time = datetime.now()
        
        # Use pip-audit for Python dependencies
        if self._is_tool_available('pip-audit'):
            try:
                cmd = ['pip-audit', '--format', 'json']
                
                # Check if requirements.txt exists
                req_file = self.project_root / 'requirements.txt'
                if req_file.exists():
                    cmd.extend(['-r', str(req_file)])
                    
                output = subprocess.run(cmd, capture_output=True, text=True)
                
                if output.stdout:
                    audit_results = json.loads(output.stdout)
                    
                    for vuln in audit_results.get('vulnerabilities', []):
                        severity = self._map_cvss_to_severity(vuln.get('cvss', 0))
                        
                        vulnerability = SecurityVulnerability(
                            severity=severity,
                            category='dependency',
                            description=f"{vuln['name']} {vuln['version']} - {vuln['description']}",
                            cve_id=vuln.get('id'),
                            cvss_score=vuln.get('cvss'),
                            remediation=f"Upgrade to {vuln.get('fix_versions', ['latest'])[0]}"
                        )
                        
                        result.add_vulnerability(vulnerability)
                        
            except Exception as e:
                logger.error(f"pip-audit scan failed: {e}")
                result.success = False
                result.error_message = str(e)
                
        # Use safety for additional checks
        if self._is_tool_available('safety') and result.success:
            try:
                cmd = ['safety', 'check', '--json']
                output = subprocess.run(cmd, capture_output=True, text=True)
                
                if output.stdout:
                    safety_results = json.loads(output.stdout)
                    
                    for vuln in safety_results:
                        severity = self._map_cvss_to_severity(vuln.get('cvss', 0))
                        
                        vulnerability = SecurityVulnerability(
                            severity=severity,
                            category='dependency',
                            description=f"{vuln['package']} - {vuln['advisory']}",
                            cve_id=vuln.get('cve'),
                            cvss_score=vuln.get('cvss'),
                            remediation=f"Upgrade {vuln['package']} to safe version"
                        )
                        
                        # Avoid duplicates
                        if not any(v.cve_id == vulnerability.cve_id 
                                 for v in result.vulnerabilities 
                                 if v.cve_id):
                            result.add_vulnerability(vulnerability)
                            
            except Exception as e:
                logger.error(f"Safety scan failed: {e}")
                
        result.scan_duration = (datetime.now() - start_time).total_seconds()
        return result
        
    def _map_cvss_to_severity(self, cvss_score: float) -> str:
        """Map CVSS score to severity level."""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score > 0:
            return 'low'
        else:
            return 'info'
            
    def scan_for_secrets(self) -> SecurityScanResult:
        """
        Scan for hardcoded secrets and sensitive data.
        
        Returns:
            SecurityScanResult with secret findings
        """
        result = SecurityScanResult(
            scan_type='secrets',
            timestamp=datetime.now()
        )
        
        start_time = datetime.now()
        
        # Common secret patterns
        secret_patterns = {
            'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
            'github_token': re.compile(r'ghp_[0-9a-zA-Z]{36}'),
            'private_key': re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
            'api_key': re.compile(r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][0-9a-zA-Z\-_]{20,}["\']', re.IGNORECASE),
            'jwt_token': re.compile(r'eyJ[0-9a-zA-Z\-_]+\.eyJ[0-9a-zA-Z\-_]+\.[0-9a-zA-Z\-_]+'),
            'basic_auth': re.compile(r'basic\s+[0-9a-zA-Z\+/=]{20,}', re.IGNORECASE),
            'slack_token': re.compile(r'xox[baprs]-[0-9a-zA-Z\-]+'),
            'google_api': re.compile(r'AIza[0-9A-Za-z\-_]{35}')
        }
        
        # Files to check
        text_extensions = {'.py', '.js', '.yml', '.yaml', '.json', '.env', '.conf', '.cfg', '.ini', '.sh'}
        
        for file_path in self.project_root.rglob("*"):
            if file_path.is_file() and file_path.suffix in text_extensions:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    lines = content.split('
')
                    
                    for pattern_name, pattern in secret_patterns.items():
                        for i, line in enumerate(lines, 1):
                            if pattern.search(line):
                                vuln = SecurityVulnerability(
                                    severity='critical',
                                    category='secret',
                                    description=f"Potential {pattern_name.replace('_', ' ')} exposed",
                                    file_path=file_path,
                                    line_number=i,
                                    remediation='Remove secret and use secure secret management'
                                )
                                
                                result.add_vulnerability(vuln)
                                
                except Exception as e:
                    logger.error(f"Error scanning {file_path}: {e}")
                    
        result.scan_duration = (datetime.now() - start_time).total_seconds()
        return result
        
    def run_sast_scan(self) -> SecurityScanResult:
        """
        Run Static Application Security Testing (SAST).
        
        Returns:
            SecurityScanResult with SAST findings
        """
        result = SecurityScanResult(
            scan_type='sast',
            timestamp=datetime.now()
        )
        
        start_time = datetime.now()
        
        # Use Semgrep for advanced SAST
        if self._is_tool_available('semgrep'):
            try:
                cmd = ['semgrep', '--config=auto', '--json', str(self.project_root)]
                output = subprocess.run(cmd, capture_output=True, text=True)
                
                if output.stdout:
                    semgrep_results = json.loads(output.stdout)
                    
                    for finding in semgrep_results.get('results', []):
                        severity = finding.get('extra', {}).get('severity', 'medium').lower()
                        
                        vuln = SecurityVulnerability(
                            severity=severity,
                            category='sast',
                            description=finding.get('extra', {}).get('message', 'Security issue detected'),
                            file_path=Path(finding['path']),
                            line_number=finding['start']['line'],
                            remediation=finding.get('extra', {}).get('fix', '')
                        )
                        
                        result.add_vulnerability(vuln)
                        
            except Exception as e:
                logger.error(f"Semgrep scan failed: {e}")
                result.success = False
                result.error_message = str(e)
                
        # Additional SAST checks
        self._check_authentication_issues(result)
        self._check_authorization_issues(result)
        self._check_input_validation(result)
        
        result.scan_duration = (datetime.now() - start_time).total_seconds()
        return result
        
    def _check_authentication_issues(self, result: SecurityScanResult):
        """Check for authentication-related issues."""
        auth_files = list(self.project_root.rglob("*auth*.py"))
        
        for file_path in auth_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Check for weak password requirements
                if re.search(r'min[_-]?length\s*=\s*[0-7]\b', content, re.IGNORECASE):
                    vuln = SecurityVulnerability(
                        severity='medium',
                        category='authentication',
                        description='Weak password length requirement',
                        file_path=file_path,
                        remediation='Require minimum 8 characters for passwords'
                    )
                    result.add_vulnerability(vuln)
                    
                # Check for missing rate limiting
                if 'login' in content.lower() and 'rate' not in content.lower():
                    vuln = SecurityVulnerability(
                        severity='medium',
                        category='authentication',
                        description='Missing rate limiting on authentication',
                        file_path=file_path,
                        remediation='Implement rate limiting to prevent brute force attacks'
                    )
                    result.add_vulnerability(vuln)
                    
            except Exception as e:
                logger.error(f"Error checking auth in {file_path}: {e}")
                
    def _check_authorization_issues(self, result: SecurityScanResult):
        """Check for authorization-related issues."""
        # Look for endpoints without authorization checks
        api_files = list(self.project_root.rglob("*api*.py"))
        api_files.extend(list(self.project_root.rglob("*route*.py")))
        api_files.extend(list(self.project_root.rglob("*view*.py")))
        
        for file_path in api_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Simple check for routes without auth decorators
                route_pattern = re.compile(r'@(app|router)\.(get|post|put|delete|patch)')
                auth_pattern = re.compile(r'@(auth|login|permission|role)_required')
                
                routes = route_pattern.findall(content)
                auth_decorators = auth_pattern.findall(content)
                
                if len(routes) > len(auth_decorators) * 1.5:  # Allow some public routes
                    vuln = SecurityVulnerability(
                        severity='high',
                        category='authorization',
                        description='Multiple endpoints without authorization checks',
                        file_path=file_path,
                        remediation='Add authorization decorators to all sensitive endpoints'
                    )
                    result.add_vulnerability(vuln)
                    
            except Exception as e:
                logger.error(f"Error checking authz in {file_path}: {e}")
                
    def _check_input_validation(self, result: SecurityScanResult):
        """Check for input validation issues."""
        # Look for request handling without validation
        for file_path in self.project_root.rglob("*.py"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Check for direct request data usage
                if 'request.' in content and 'validate' not in content.lower():
                    if re.search(r'request\.(form|json|args|data)\[', content):
                        vuln = SecurityVulnerability(
                            severity='medium',
                            category='input_validation',
                            description='Request data used without validation',
                            file_path=file_path,
                            remediation='Validate all user inputs before processing'
                        )
                        result.add_vulnerability(vuln)
                        
            except Exception as e:
                logger.error(f"Error checking validation in {file_path}: {e}")
                
    def scan_containers(self) -> SecurityScanResult:
        """
        Scan container configurations and images for security issues.
        
        Returns:
            SecurityScanResult with container findings
        """
        result = SecurityScanResult(
            scan_type='containers',
            timestamp=datetime.now()
        )
        
        start_time = datetime.now()
        
        # Check Dockerfiles
        dockerfiles = list(self.project_root.rglob("Dockerfile*"))
        
        for dockerfile in dockerfiles:
            self._analyze_dockerfile(dockerfile, result)
            
        # Check docker-compose files
        compose_files = list(self.project_root.rglob("docker-compose*.yml"))
        compose_files.extend(list(self.project_root.rglob("docker-compose*.yaml")))
        
        for compose_file in compose_files:
            self._analyze_compose_file(compose_file, result)
            
        # Check Kubernetes manifests
        k8s_files = []
        k8s_dir = self.project_root / 'k8s'
        if k8s_dir.exists():
            k8s_files.extend(k8s_dir.rglob("*.yml"))
            k8s_files.extend(k8s_dir.rglob("*.yaml"))
            
        for k8s_file in k8s_files:
            self._analyze_k8s_manifest(k8s_file, result)
            
        result.scan_duration = (datetime.now() - start_time).total_seconds()
        return result
        
    def _analyze_dockerfile(self, dockerfile: Path, result: SecurityScanResult):
        """Analyze a Dockerfile for security issues."""
        try:
            with open(dockerfile, 'r') as f:
                content = f.read()
                
            lines = content.split('
')
            
            for i, line in enumerate(lines, 1):
                line = line.strip()
                
                # Check for running as root
                if line.startswith('USER') and 'root' in line:
                    vuln = SecurityVulnerability(
                        severity='high',
                        category='container',
                        description='Container running as root user',
                        file_path=dockerfile,
                        line_number=i,
                        remediation='Use a non-root user for running containers'
                    )
                    result.add_vulnerability(vuln)
                    
                # Check for sudo installation
                if 'sudo' in line and ('apt-get install' in line or 'yum install' in line):
                    vuln = SecurityVulnerability(
                        severity='medium',
                        category='container',
                        description='sudo installed in container',
                        file_path=dockerfile,
                        line_number=i,
                        remediation='Avoid installing sudo in containers'
                    )
                    result.add_vulnerability(vuln)
                    
                # Check for ADD instead of COPY
                if line.startswith('ADD') and not line.endswith('.tar'):
                    vuln = SecurityVulnerability(
                        severity='low',
                        category='container',
                        description='ADD used instead of COPY',
                        file_path=dockerfile,
                        line_number=i,
                        remediation='Use COPY instead of ADD for better security'
                    )
                    result.add_vulnerability(vuln)
                    
                # Check for latest tags
                if ':latest' in line or (line.startswith('FROM') and ':' not in line.split()[1]):
                    vuln = SecurityVulnerability(
                        severity='medium',
                        category='container',
                        description='Using latest or untagged base image',
                        file_path=dockerfile,
                        line_number=i,
                        remediation='Pin base image to specific version'
                    )
                    result.add_vulnerability(vuln)
                    
        except Exception as e:
            logger.error(f"Error analyzing {dockerfile}: {e}")
            
    def _analyze_compose_file(self, compose_file: Path, result: SecurityScanResult):
        """Analyze docker-compose file for security issues."""
        try:
            with open(compose_file, 'r') as f:
                compose_data = yaml.safe_load(f)
                
            if 'services' in compose_data:
                for service_name, service_config in compose_data['services'].items():
                    # Check for privileged mode
                    if service_config.get('privileged', False):
                        vuln = SecurityVulnerability(
                            severity='high',
                            category='container',
                            description=f'Service {service_name} running in privileged mode',
                            file_path=compose_file,
                            remediation='Avoid using privileged mode'
                        )
                        result.add_vulnerability(vuln)
                        
                    # Check for host network mode
                    if service_config.get('network_mode') == 'host':
                        vuln = SecurityVulnerability(
                            severity='medium',
                            category='container',
                            description=f'Service {service_name} using host network',
                            file_path=compose_file,
                            remediation='Use bridge networking instead of host'
                        )
                        result.add_vulnerability(vuln)
                        
                    # Check for exposed sensitive ports
                    ports = service_config.get('ports', [])
                    for port in ports:
                        if isinstance(port, str) and port.startswith('0.0.0.0:'):
                            vuln = SecurityVulnerability(
                                severity='medium',
                                category='container',
                                description=f'Service {service_name} binding to all interfaces',
                                file_path=compose_file,
                                remediation='Bind to specific interface or use 127.0.0.1'
                            )
                            result.add_vulnerability(vuln)
                            break
                            
        except Exception as e:
            logger.error(f"Error analyzing {compose_file}: {e}")
            
    def _analyze_k8s_manifest(self, k8s_file: Path, result: SecurityScanResult):
        """Analyze Kubernetes manifest for security issues."""
        try:
            with open(k8s_file, 'r') as f:
                k8s_data = yaml.safe_load(f)
                
            if not k8s_data:
                return
                
            kind = k8s_data.get('kind', '')
            
            # Check pod security
            if kind in ['Pod', 'Deployment', 'DaemonSet', 'StatefulSet']:
                spec = k8s_data.get('spec', {})
                
                if kind != 'Pod':
                    spec = spec.get('template', {}).get('spec', {})
                    
                # Check for security context
                if 'securityContext' not in spec:
                    vuln = SecurityVulnerability(
                        severity='medium',
                        category='kubernetes',
                        description='Missing pod security context',
                        file_path=k8s_file,
                        remediation='Add securityContext with appropriate settings'
                    )
                    result.add_vulnerability(vuln)
                    
                # Check containers
                for container in spec.get('containers', []):
                    # Check for privileged containers
                    if container.get('securityContext', {}).get('privileged', False):
                        vuln = SecurityVulnerability(
                            severity='high',
                            category='kubernetes',
                            description=f"Container {container['name']} running privileged",
                            file_path=k8s_file,
                            remediation='Avoid running privileged containers'
                        )
                        result.add_vulnerability(vuln)
                        
                    # Check for root user
                    if container.get('securityContext', {}).get('runAsUser') == 0:
                        vuln = SecurityVulnerability(
                            severity='high',
                            category='kubernetes',
                            description=f"Container {container['name']} running as root",
                            file_path=k8s_file,
                            remediation='Use non-root user (runAsUser > 0)'
                        )
                        result.add_vulnerability(vuln)
                        
        except Exception as e:
            logger.error(f"Error analyzing {k8s_file}: {e}")
            
    def check_owasp_compliance(self, scan_results: Dict[str, SecurityScanResult]) -> ComplianceCheckResult:
        """
        Check compliance with OWASP Top 10.
        
        Args:
            scan_results: Results from security scans
            
        Returns:
            ComplianceCheckResult for OWASP
        """
        owasp_checks = {
            'A01': self._check_access_control,
            'A02': self._check_crypto_failures,
            'A03': self._check_injection,
            'A04': self._check_insecure_design,
            'A05': self._check_security_misconfig,
            'A06': self._check_vulnerable_components,
            'A07': self._check_auth_failures,
            'A08': self._check_data_integrity,
            'A09': self._check_logging_monitoring,
            'A10': self._check_ssrf
        }
        
        passed_checks = 0
        total_checks = len(owasp_checks)
        findings = []
        recommendations = []
        
        for owasp_id, check_func in owasp_checks.items():
            check_passed, finding, recommendation = check_func(scan_results)
            
            if check_passed:
                passed_checks += 1
            else:
                findings.append(f"{owasp_id} - {self.OWASP_TOP_10[owasp_id]}: {finding}")
                recommendations.append(f"{owasp_id}: {recommendation}")
                
        score = (passed_checks / total_checks) * 100
        compliant = score >= 80  # 80% threshold for compliance
        
        return ComplianceCheckResult(
            framework='OWASP Top 10 2021',
            compliant=compliant,
            score=score,
            passed_checks=passed_checks,
            total_checks=total_checks,
            findings=findings,
            recommendations=recommendations
        )
        
    def _check_access_control(self, scan_results: Dict[str, SecurityScanResult]) -> Tuple[bool, str, str]:
        """Check for broken access control issues."""
        auth_issues = 0
        
        for scan_type, result in scan_results.items():
            for vuln in result.vulnerabilities:
                if vuln.category in ['authorization', 'authentication']:
                    auth_issues += 1
                    
        if auth_issues > 0:
            return False, f"Found {auth_issues} access control issues", \
                   "Implement proper authentication and authorization checks"
        return True, "No access control issues found", ""
        
    def _check_crypto_failures(self, scan_results: Dict[str, SecurityScanResult]) -> Tuple[bool, str, str]:
        """Check for cryptographic failures."""
        crypto_issues = 0
        
        for scan_type, result in scan_results.items():
            for vuln in result.vulnerabilities:
                if vuln.category == 'weak_crypto' or 'crypto' in vuln.description.lower():
                    crypto_issues += 1
                    
        if crypto_issues > 0:
            return False, f"Found {crypto_issues} cryptographic issues", \
                   "Use strong encryption algorithms and proper key management"
        return True, "No cryptographic failures found", ""
        
    def _check_injection(self, scan_results: Dict[str, SecurityScanResult]) -> Tuple[bool, str, str]:
        """Check for injection vulnerabilities."""
        injection_issues = 0
        
        for scan_type, result in scan_results.items():
            for vuln in result.vulnerabilities:
                if 'injection' in vuln.category or 'injection' in vuln.description.lower():
                    injection_issues += 1
                    
        if injection_issues > 0:
            return False, f"Found {injection_issues} injection vulnerabilities", \
                   "Use parameterized queries and input validation"
        return True, "No injection vulnerabilities found", ""
        
    def _check_insecure_design(self, scan_results: Dict[str, SecurityScanResult]) -> Tuple[bool, str, str]:
        """Check for insecure design patterns."""
        design_issues = 0
        
        for scan_type, result in scan_results.items():
            for vuln in result.vulnerabilities:
                if vuln.severity in ['critical', 'high'] and vuln.category == 'sast':
                    design_issues += 1
                    
        if design_issues > 0:
            return False, f"Found {design_issues} design issues", \
                   "Implement secure design patterns and threat modeling"
        return True, "No major design issues found", ""
        
    def _check_security_misconfig(self, scan_results: Dict[str, SecurityScanResult]) -> Tuple[bool, str, str]:
        """Check for security misconfiguration."""
        config_issues = 0
        
        for scan_type, result in scan_results.items():
            for vuln in result.vulnerabilities:
                if vuln.category in ['debug_enabled', 'cors_wildcard'] or \
                   'config' in vuln.description.lower():
                    config_issues += 1
                    
        if config_issues > 0:
            return False, f"Found {config_issues} configuration issues", \
                   "Review and harden security configurations"
        return True, "No security misconfiguration found", ""
        
    def _check_vulnerable_components(self, scan_results: Dict[str, SecurityScanResult]) -> Tuple[bool, str, str]:
        """Check for vulnerable components."""
        dep_result = scan_results.get('dependencies', SecurityScanResult('', datetime.now()))
        
        if dep_result.critical_count > 0 or dep_result.high_count > 0:
            total_issues = dep_result.critical_count + dep_result.high_count
            return False, f"Found {total_issues} high/critical dependency vulnerabilities", \
                   "Update vulnerable dependencies to secure versions"
        return True, "No critical dependency vulnerabilities", ""
        
    def _check_auth_failures(self, scan_results: Dict[str, SecurityScanResult]) -> Tuple[bool, str, str]:
        """Check for authentication failures."""
        auth_issues = 0
        
        for scan_type, result in scan_results.items():
            for vuln in result.vulnerabilities:
                if vuln.category == 'authentication' or \
                   'password' in vuln.description.lower() or \
                   'session' in vuln.description.lower():
                    auth_issues += 1
                    
        if auth_issues > 0:
            return False, f"Found {auth_issues} authentication issues", \
                   "Implement strong authentication with MFA"
        return True, "No authentication failures found", ""
        
    def _check_data_integrity(self, scan_results: Dict[str, SecurityScanResult]) -> Tuple[bool, str, str]:
        """Check for data integrity issues."""
        integrity_issues = 0
        
        for scan_type, result in scan_results.items():
            for vuln in result.vulnerabilities:
                if 'integrity' in vuln.description.lower() or \
                   'signature' in vuln.description.lower():
                    integrity_issues += 1
                    
        if integrity_issues > 0:
            return False, f"Found {integrity_issues} data integrity issues", \
                   "Implement integrity checks and digital signatures"
        return True, "No data integrity issues found", ""
        
    def _check_logging_monitoring(self, scan_results: Dict[str, SecurityScanResult]) -> Tuple[bool, str, str]:
        """Check for logging and monitoring issues."""
        # Simple check - in real implementation would analyze actual logging
        log_files = list(self.project_root.rglob("*log*.py"))
        
        if len(log_files) < 3:  # Arbitrary threshold
            return False, "Insufficient logging implementation detected", \
                   "Implement comprehensive security logging and monitoring"
        return True, "Logging appears to be implemented", ""
        
    def _check_ssrf(self, scan_results: Dict[str, SecurityScanResult]) -> Tuple[bool, str, str]:
        """Check for SSRF vulnerabilities."""
        ssrf_issues = 0
        
        for scan_type, result in scan_results.items():
            for vuln in result.vulnerabilities:
                if 'ssrf' in vuln.description.lower() or \
                   'request' in vuln.description.lower():
                    ssrf_issues += 1
                    
        if ssrf_issues > 0:
            return False, f"Found {ssrf_issues} potential SSRF issues", \
                   "Implement URL validation and whitelisting"
        return True, "No SSRF vulnerabilities found", ""
        
    def check_security_best_practices(self) -> ComplianceCheckResult:
        """
        Check compliance with general security best practices.
        
        Returns:
            ComplianceCheckResult for best practices
        """
        checks = {
            'Security headers configured': self._check_security_headers(),
            'HTTPS enforced': self._check_https_enforcement(),
            'Input validation implemented': self._check_input_validation_practices(),
            'Error handling secure': self._check_error_handling(),
            'Secrets managed properly': self._check_secrets_management(),
            'Dependencies up to date': self._check_dependency_updates(),
            'Security testing in CI/CD': self._check_security_testing(),
            'Least privilege principle': self._check_least_privilege()
        }
        
        passed_checks = sum(1 for passed in checks.values() if passed)
        total_checks = len(checks)
        score = (passed_checks / total_checks) * 100
        
        findings = [check for check, passed in checks.items() if not passed]
        recommendations = []
        
        if not checks['Security headers configured']:
            recommendations.append("Implement security headers (CSP, HSTS, etc.)")
        if not checks['HTTPS enforced']:
            recommendations.append("Enforce HTTPS for all communications")
        if not checks['Input validation implemented']:
            recommendations.append("Implement comprehensive input validation")
            
        return ComplianceCheckResult(
            framework='Security Best Practices',
            compliant=score >= 75,
            score=score,
            passed_checks=passed_checks,
            total_checks=total_checks,
            findings=findings,
            recommendations=recommendations
        )
        
    def _check_security_headers(self) -> bool:
        """Check if security headers are configured."""
        # Look for security header configuration
        header_patterns = ['Content-Security-Policy', 'X-Frame-Options', 
                         'X-Content-Type-Options', 'Strict-Transport-Security']
        
        config_files = list(self.project_root.rglob("*.py"))
        
        for file_path in config_files:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                if any(header in content for header in header_patterns):
                    return True
                    
            except:
                continue
                
        return False
        
    def _check_https_enforcement(self) -> bool:
        """Check if HTTPS is enforced."""
        # Look for HTTPS enforcement patterns
        https_patterns = ['force_https', 'require_https', 'ssl_required', 'secure=True']
        
        for file_path in self.project_root.rglob("*.py"):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                if any(pattern in content.lower() for pattern in https_patterns):
                    return True
                    
            except:
                continue
                
        return False
        
    def _check_input_validation_practices(self) -> bool:
        """Check if input validation is properly implemented."""
        validation_files = 0
        
        for file_path in self.project_root.rglob("*validat*.py"):
            validation_files += 1
            
        return validation_files >= 3  # Arbitrary threshold
        
    def _check_error_handling(self) -> bool:
        """Check if error handling is secure."""
        # Look for generic error responses
        for file_path in self.project_root.rglob("*.py"):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                # Check for stack trace exposure
                if 'traceback.print_exc()' in content or \
                   'debug=True' in content.lower():
                    return False
                    
            except:
                continue
                
        return True
        
    def _check_secrets_management(self) -> bool:
        """Check if secrets are managed properly."""
        # Look for environment variable usage for secrets
        env_patterns = ['os.environ', 'getenv', 'config.get']
        
        secret_files = 0
        
        for file_path in self.project_root.rglob("*.py"):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                if any(pattern in content for pattern in env_patterns):
                    secret_files += 1
                    
            except:
                continue
                
        return secret_files >= 5  # Using env vars for secrets
        
    def _check_dependency_updates(self) -> bool:
        """Check if dependencies are kept up to date."""
        # Check for dependency update automation
        update_files = ['.github/workflows/dependabot.yml', 
                       '.github/dependabot.yml',
                       'renovate.json']
        
        for update_file in update_files:
            if (self.project_root / update_file).exists():
                return True
                
        return False
        
    def _check_security_testing(self) -> bool:
        """Check if security testing is in CI/CD."""
        # Look for security testing in CI/CD files
        ci_patterns = ['bandit', 'safety', 'security', 'snyk', 'trivy']
        
        ci_files = list(self.project_root.glob('.github/workflows/*.yml'))
        ci_files.extend(list(self.project_root.glob('.gitlab-ci.yml')))
        
        for ci_file in ci_files:
            try:
                with open(ci_file, 'r') as f:
                    content = f.read()
                    
                if any(pattern in content.lower() for pattern in ci_patterns):
                    return True
                    
            except:
                continue
                
        return False
        
    def _check_least_privilege(self) -> bool:
        """Check if least privilege principle is followed."""
        # Look for proper permission checks
        permission_patterns = ['permission', 'role', 'rbac', 'can_', 'is_allowed']
        
        permission_files = 0
        
        for file_path in self.project_root.rglob("*.py"):
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                    
                if any(pattern in content.lower() for pattern in permission_patterns):
                    permission_files += 1
                    
            except:
                continue
                
        return permission_files >= 5  # Arbitrary threshold
        
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of all security findings."""
        summary = {
            'total_vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'scans_completed': 0,
            'scans_failed': 0,
            'compliance_scores': {},
            'top_issues': [],
            'recommendations': []
        }
        
        # Aggregate vulnerability counts
        for scan_type, scan_result in results['scans'].items():
            if isinstance(scan_result, SecurityScanResult):
                if scan_result.success:
                    summary['scans_completed'] += 1
                    summary['total_vulnerabilities'] += scan_result.total_issues
                    summary['critical'] += scan_result.critical_count
                    summary['high'] += scan_result.high_count
                    summary['medium'] += scan_result.medium_count
                    summary['low'] += scan_result.low_count
                    summary['info'] += scan_result.info_count
                else:
                    summary['scans_failed'] += 1
                    
        # Get compliance scores
        for framework, compliance in results['compliance'].items():
            if isinstance(compliance, ComplianceCheckResult):
                summary['compliance_scores'][framework] = compliance.score
                
        # Identify top issues
        all_vulns = []
        for scan_result in results['scans'].values():
            if isinstance(scan_result, SecurityScanResult):
                all_vulns.extend(scan_result.vulnerabilities)
                
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        all_vulns.sort(key=lambda v: severity_order.get(v.severity, 5))
        
        # Get top 5 issues
        for vuln in all_vulns[:5]:
            summary['top_issues'].append({
                'severity': vuln.severity,
                'category': vuln.category,
                'description': vuln.description,
                'file': str(vuln.file_path) if vuln.file_path else 'N/A'
            })
            
        # Generate recommendations
        if summary['critical'] > 0:
            summary['recommendations'].append(
                f"URGENT: Fix {summary['critical']} critical vulnerabilities immediately"
            )
            
        if summary['high'] > 0:
            summary['recommendations'].append(
                f"HIGH PRIORITY: Address {summary['high']} high severity issues"
            )
            
        for framework, score in summary['compliance_scores'].items():
            if score < 80:
                summary['recommendations'].append(
                    f"Improve {framework} compliance (current score: {score:.1f}%)"
                )
                
        return summary
        
    def generate_report(self, audit_results: Dict[str, Any], 
                       output_file: Optional[Path] = None) -> str:
        """
        Generate a comprehensive security audit report.
        
        Args:
            audit_results: Results from run_full_audit()
            output_file: Optional file to save report to
            
        Returns:
            Report content as string
        """
        report_lines = [
            "# Security Audit Report",
            f"\n**Generated**: {audit_results['timestamp']}",\n            f"**Project**: {audit_results['project_root']}",\n            "\n## Executive Summary",\n            f"\n- **Total Vulnerabilities**: {audit_results['summary']['total_vulnerabilities']}",\n            f"- **Critical**: {audit_results['summary']['critical']}",\n            f"- **High**: {audit_results['summary']['high']}",\n            f"- **Medium**: {audit_results['summary']['medium']}",\n            f"- **Low**: {audit_results['summary']['low']}",\n            f"- **Info**: {audit_results['summary']['info']}",\n            "\n### Compliance Scores"\n        ]\n\n        for framework, score in audit_results['summary']['compliance_scores'].items():\n            status = "✅ PASS" if score >= 80 else "❌ FAIL"\n            report_lines.append(f"- **{framework}**: {score:.1f}% {status}")\n\n        report_lines.extend([\n            "\n## Top Security Issues",\n            ""\n        ])\n\n        for i, issue in enumerate(audit_results['summary']['top_issues'], 1):\n            report_lines.append(\n                f"{i}. **[{issue['severity'].upper()}]** {issue['category']}: "\n                f"{issue['description']} ({issue['file']})"\n            )\n\n        report_lines.extend([\n            "\n## Recommendations",\n            ""\n        ])\n\n        for rec in audit_results['summary']['recommendations']:\n            report_lines.append(f"- {rec}")\n\n        # Detailed findings by scan type\n        report_lines.extend([\n            "\n## Detailed Findings",\n            ""\n        ])\n\n        for scan_type, scan_result in audit_results['scans'].items():\n            if isinstance(scan_result, SecurityScanResult):\n                report_lines.extend([\n                    f"\n### {scan_type.replace('_', ' ').title()}",\n                    f"- **Status**: {'✅ Success' if scan_result.success else '❌ Failed'}",\n                    f"- **Duration**: {scan_result.scan_duration:.2f}s",\n                    f"- **Issues Found**: {scan_result.total_issues}",\n                    ""\n                ])\n\n                if scan_result.vulnerabilities and scan_result.total_issues <= 20:\n                    report_lines.append("**Vulnerabilities:**")\n                    for vuln in scan_result.vulnerabilities[:10]:  # Limit to 10\n                        location = f"{vuln.file_path}:{vuln.line_number}" if vuln.file_path else "N/A"\n                        report_lines.append(\n                            f"- [{vuln.severity.upper()}] {vuln.description} - {location}"\n                        )\n\n        # Compliance details\n        report_lines.extend([\n            "\n## Compliance Details",\n            ""\n        ])\n\n        for framework, compliance in audit_results['compliance'].items():\n            if isinstance(compliance, ComplianceCheckResult):\n                report_lines.extend([\n                    f"\n### {compliance.framework}",\n                    f"- **Status**: {'✅ Compliant' if compliance.compliant else '❌ Non-Compliant'}",\n                    f"- **Score**: {compliance.score:.1f}%",\n                    f"- **Passed Checks**: {compliance.passed_checks}/{compliance.total_checks}",\n                    ""\n                ])\n\n                if compliance.findings:\n                    report_lines.append("**Findings:**")\n                    for finding in compliance.findings[:5]:  # Limit to 5\n                        report_lines.append(f"- {finding}")\n\n        report_content = '\n'.join(report_lines)\n\n        if output_file:\n            with open(output_file, 'w') as f:\n                f.write(report_content)\n\n        return report_content\n\n\n# CLI interface for backward compatibility\ndef main():\n    """Command-line interface for security validation."""\n    import argparse\n\n    parser = argparse.ArgumentParser(description="Security validation and audit tool")\n\n    subparsers = parser.add_subparsers(dest='command', help='Command to run')\n\n    # Full audit command\n    audit_parser = subparsers.add_parser('audit', help='Run full security audit')\n    audit_parser.add_argument('--output', '-o', help='Output report file')\n    audit_parser.add_argument('--include', nargs='+', help='Include patterns')\n    audit_parser.add_argument('--exclude', nargs='+', help='Exclude patterns')\n\n    # Specific scan commands\n    scan_parser = subparsers.add_parser('scan', help='Run specific security scan')\n    scan_parser.add_argument('scan_type',\n                           choices=['static', 'dependencies', 'secrets', 'sast', 'containers'],\n                           help='Type of scan to run')\n\n    # Compliance check command\n    compliance_parser = subparsers.add_parser('compliance',\n                                            help='Check compliance with frameworks')\n    compliance_parser.add_argument('framework',\n                                 choices=['owasp', 'best-practices'],\n                                 help='Compliance framework to check')\n\n    args = parser.parse_args()\n\n    # Configure logging\n    logging.basicConfig(level=logging.INFO,\n                       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')\n\n    validator = SecurityValidator()\n\n    if args.command == 'audit':\n        print("🔍 Running comprehensive security audit...")\n\n        results = validator.run_full_audit(\n            include_patterns=args.include,\n            exclude_patterns=args.exclude\n        )\n\n        # Generate report\n        report = validator.generate_report(results, args.output)\n\n        print("\n" + report)\n\n        if args.output:\n            print(f"\n✅ Report saved to: {args.output}")\n\n        # Exit with error code if critical issues found\n        if results['summary']['critical'] > 0:\n            return 1\n\n    elif args.command == 'scan':\n        print(f"🔍 Running {args.scan_type} security scan...")\n\n        if args.scan_type == 'static':\n            result = validator.run_static_analysis()\n        elif args.scan_type == 'dependencies':\n            result = validator.scan_dependencies()\n        elif args.scan_type == 'secrets':\n            result = validator.scan_for_secrets()\n        elif args.scan_type == 'sast':\n            result = validator.run_sast_scan()\n        elif args.scan_type == 'containers':\n            result = validator.scan_containers()\n\n        print(f"\n{'✅' if result.success else '❌'} Scan completed")\n        print(f"Total issues: {result.total_issues}")\n        print(f"Critical: {result.critical_count}")\n        print(f"High: {result.high_count}")\n        print(f"Medium: {result.medium_count}")\n        print(f"Low: {result.low_count}")\n\n        if result.vulnerabilities and result.total_issues <= 10:\n            print("\nTop vulnerabilities:")\n            for vuln in result.vulnerabilities[:5]:\n                print(f"- [{vuln.severity.upper()}] {vuln.description}")\n\n    elif args.command == 'compliance':\n        print(f"🔍 Checking {args.framework} compliance...")\n\n        # Run necessary scans first\n        scan_results = {\n            'static_analysis': validator.run_static_analysis(),\n            'dependencies': validator.scan_dependencies()\n        }\n\n        if args.framework == 'owasp':\n            result = validator.check_owasp_compliance(scan_results)\n        else:\n            result = validator.check_security_best_practices()\n\n        print(f"\n{'✅' if result.compliant else '❌'} {result.framework}")\n        print(f"Score: {result.score:.1f}%")\n        print(f"Passed: {result.passed_checks}/{result.total_checks}")\n\n        if result.findings:\n            print("\nFindings:")\n            for finding in result.findings:\n                print(f"- {finding}")\n\n        if result.recommendations:\n            print("\nRecommendations:")\n            for rec in result.recommendations:\n                print(f"- {rec}")\n\n    else:\n        parser.print_help()\n\n\nif __name__ == "__main__":\n    main()