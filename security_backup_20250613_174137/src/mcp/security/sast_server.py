
from __future__ import annotations

"""SAST (Static Application Security Testing) MCP Server."""

__all__ = [
    "SASTMCPServer"
]
import os
import re
import asyncio
import json
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
import logging
from asyncio import Semaphore
import tempfile
import ast

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.mcp.servers import MCPServer

from src.core.error_handler import (
    handle_errors,\n    async_handle_errors,\n    log_error,\n    ServiceUnavailableError,\n    ExternalServiceError,\n    ValidationError,\n    ConfigurationError
)

logger = logging.getLogger(__name__)

# Security patterns for various languages
INJECTION_PATTERNS = {
    "sql_injection": {
        "python": [
            r"\.execute\s*\(\s*[\"'].*%[s|d].*[\"']\s*%",
            r"\.execute\s*\(\s*f[\"'].*{.*}.*[\"']",
            r"\.execute\s*\(\s*[\"'].*\+.*[\"']"
        ],
        "javascript": [
            r"\.query\s*\(\s*[`\"'].*\$\{.*\}.*[`\"']",
            r"\.query\s*\(\s*[\"'].*\+.*[\"']"
        ],
        "java": [
            r"createQuery\s*\(\s*[\"'].*\+.*[\"']",
            r"prepareStatement\s*\(\s*[\"'].*\+.*[\"']"
        ]
    },
    "command_injection": {
        "python": [
            r"os\.system\s*\(",
            r"subprocess\.call\s*\(\s*[^[]",
            r"eval\s*\(",
            r"exec\s*\("
        ],
        "javascript": [
            r"eval\s*\(",
            r"child_process\.exec\s*\(",
            r"\.execSync\s*\("
        ]
    },
    "path_traversal": {
        "all": [
            r"\.\.\/",
            r"\.\.\\\\",
            r"%2e%2e%2f",
            r"%252e%252e%252f"
        ]
    }
}

# CWE mappings
CWE_MAPPINGS = {
    "sql_injection": "CWE-89",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "xss": "CWE-79",
    "xxe": "CWE-611",
    "insecure_deserialization": "CWE-502",
    "weak_crypto": "CWE-327",
    "hardcoded_secrets": "CWE-798"
}


class SASTMCPServer(MCPServer):
    """Static Application Security Testing MCP Server."""
    
    def __init__(self, permission_checker: Optional[Any] = None):
        """Initialize SAST server."""
        super().__init__(name="sast-scanner", version="1.0.0", permission_checker=permission_checker)
        self.scan_history: List[Dict[str, Any]] = []
        self.scan_semaphore = Semaphore(3)
        self._scan_cache: Dict[str, Tuple[datetime, Any]] = {}
        self._cache_ttl = 600  # 10 minutes
    
    def get_server_info(self) -> MCPServerInfo:
        """Get SAST server information."""
        return MCPServerInfo(
            name="sast-scanner",
            version="1.0.0",
            description="Static Application Security Testing with multiple scanners",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "multi_language_support": True,
                    "cwe_mapping": True,
                    "semgrep_integration": True,
                    "codeql_support": True,
                    "sonarqube_integration": True,
                    "custom_rules": True,
                    "incremental_scanning": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available SAST tools."""
        return [
            MCPTool(
                name="run_semgrep_scan",
                description="Run Semgrep static analysis for security vulnerabilities",
                parameters=[
                    MCPToolParameter(name="target_path", type="string", 
                                   description="Path to scan", required=True),
                    MCPToolParameter(name="config", type="string",
                                   description="Semgrep config to use", required=False,
                                   enum=["auto", "security", "owasp", "cwe-top25"], default="auto"),
                    MCPToolParameter(name="severity_filter", type="string",
                                   description="Minimum severity level", required=False,
                                   enum=["INFO", "WARNING", "ERROR"], default="WARNING")
                ]
            ),
            MCPTool(
                name="analyze_code_patterns",
                description="Analyze code for dangerous patterns and anti-patterns",
                parameters=[
                    MCPToolParameter(name="target_path", type="string",
                                   description="Path to analyze", required=True),
                    MCPToolParameter(name="language", type="string",
                                   description="Programming language", required=False,
                                   enum=["python", "javascript", "java", "go", "auto"], default="auto"),
                    MCPToolParameter(name="pattern_types", type="string",
                                   description="Pattern types to check (comma-separated)", required=False,
                                   default="injection,crypto,auth,data_validation")
                ]
            ),
            MCPTool(
                name="run_bandit_scan",
                description="Python-specific security analysis with Bandit",
                parameters=[
                    MCPToolParameter(name="target_path", type="string",
                                   description="Python code path to scan", required=True),
                    MCPToolParameter(name="severity_level", type="string",
                                   description="Minimum severity level", required=False,
                                   enum=["LOW", "MEDIUM", "HIGH"], default="LOW"),
                    MCPToolParameter(name="confidence_level", type="string",
                                   description="Minimum confidence level", required=False,
                                   enum=["LOW", "MEDIUM", "HIGH"], default="LOW")
                ]
            ),
            MCPTool(
                name="detect_hardcoded_secrets",
                description="Advanced detection of hardcoded secrets and credentials",
                parameters=[
                    MCPToolParameter(name="target_path", type="string",
                                   description="Path to scan for secrets", required=True),
                    MCPToolParameter(name="custom_patterns", type="string",
                                   description="Additional regex patterns (JSON array)", required=False, default="[]"),
                    MCPToolParameter(name="exclude_patterns", type="string",
                                   description="Paths to exclude (comma-separated)", required=False, default="")
                ]
            ),
            MCPTool(
                name="analyze_dependencies",
                description="Analyze code dependencies for security issues",
                parameters=[
                    MCPToolParameter(name="project_path", type="string",
                                   description="Project root path", required=True),
                    MCPToolParameter(name="check_licenses", type="boolean",
                                   description="Check for license issues", required=False, default=True),
                    MCPToolParameter(name="check_outdated", type="boolean",
                                   description="Check for outdated packages", required=False, default=True)
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute SAST tool."""
        async with self.scan_semaphore:
            tool_map = {
                "run_semgrep_scan": self._run_semgrep_scan,
                "analyze_code_patterns": self._analyze_code_patterns,
                "run_bandit_scan": self._run_bandit_scan,
                "detect_hardcoded_secrets": self._detect_hardcoded_secrets,
                "analyze_dependencies": self._analyze_dependencies
            }
            
            if tool_name not in tool_map:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
            
            return await tool_map[tool_name](**arguments)
    
    async def _run_semgrep_scan(self, target_path: str, config: str = "auto",
                                severity_filter: str = "WARNING") -> Dict[str, Any]:
        """Run Semgrep security scan."""
        path = Path(target_path)
        if not path.exists():
            raise MCPError(-32000, f"Target path not found: {target_path}")
        
        result = {
            "scan_type": "semgrep",
            "timestamp": datetime.now().isoformat(),
            "target_path": target_path,
            "config": config,
            "findings": [],
            "stats": {"total": 0, "by_severity": {}, "by_rule": {}}
        }
        
        # Build Semgrep command
        cmd = ["semgrep", "--json"]
        
        if config == "auto":
            cmd.extend(["--config=auto"])
        elif config == "security":
            cmd.extend(["--config=p/security-audit"])
        elif config == "owasp":
            cmd.extend(["--config=p/owasp-top-ten"])
        elif config == "cwe-top25":
            cmd.extend(["--config=p/cwe-top-25"])
        
        cmd.append(str(path))
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if stdout:
                semgrep_results = json.loads(stdout.decode())
                
                for finding in semgrep_results.get("results", []):
                    severity = finding.get("extra", {}).get("severity", "INFO")
                    
                    # Apply severity filter
                    severity_levels = {"INFO": 0, "WARNING": 1, "ERROR": 2}
                    if severity_levels.get(severity, 0) >= severity_levels.get(severity_filter, 0):
                        result["findings"].append({
                            "rule_id": finding.get("check_id"),
                            "message": finding.get("extra", {}).get("message"),
                            "severity": severity,
                            "file": finding.get("path"),
                            "line": finding.get("start", {}).get("line"),
                            "code": finding.get("extra", {}).get("lines"),
                            "cwe": self._extract_cwe(finding.get("check_id", "")),
                            "owasp": finding.get("extra", {}).get("metadata", {}).get("owasp")
                        })
                        
                        # Update stats
                        result["stats"]["total"] += 1
                        result["stats"]["by_severity"][severity] = result["stats"]["by_severity"].get(severity, 0) + 1
                        result["stats"]["by_rule"][finding.get("check_id")] = result["stats"]["by_rule"].get(finding.get("check_id"), 0) + 1
                
        except Exception as e:
            result["error"] = str(e)
        
        self.scan_history.append(result)
        return result
    
    async def _analyze_code_patterns(self, target_path: str, language: str = "auto",
                                   pattern_types: str = "injection,crypto,auth,data_validation") -> Dict[str, Any]:
        """Analyze code for security patterns."""
        path = Path(target_path)
        if not path.exists():
            raise MCPError(-32000, f"Target path not found: {target_path}")
        
        result = {
            "scan_type": "pattern_analysis",
            "timestamp": datetime.now().isoformat(),
            "target_path": target_path,
            "language": language,
            "findings": []
        }
        
        pattern_list = pattern_types.split(",")
        files_to_scan = [path] if path.is_file() else list(path.rglob("*"))
        
        for file_path in files_to_scan:
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.java', '.go', '.php', '.rb']:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    file_language = self._detect_language(file_path) if language == "auto" else language
                    
                    # Check injection patterns
                    if "injection" in pattern_list:
                        for injection_type, patterns in INJECTION_PATTERNS.items():
                            lang_patterns = patterns.get(file_language, patterns.get("all", []))
                            for pattern in lang_patterns:
                                matches = re.finditer(pattern, content, re.MULTILINE)
                                for match in matches:
                                    line_num = content[:match.start()].count('\n') + 1
                                    result["findings"].append({
                                        "type": injection_type,
                                        "file": str(file_path),
                                        "line": line_num,
                                        "severity": "HIGH",
                                        "cwe": CWE_MAPPINGS.get(injection_type),
                                        "code_snippet": match.group(0),
                                        "recommendation": f"Review and fix potential {injection_type.replace('_', ' ')}"
                                    })
                    
                    # Check crypto patterns
                    if "crypto" in pattern_list:
                        weak_crypto_patterns = [
                            (r"MD5|md5", "Weak hash algorithm MD5", "CWE-327"),
                            (r"SHA1|sha1", "Weak hash algorithm SHA1", "CWE-327"),
                            (r"DES|des", "Weak encryption algorithm DES", "CWE-327"),
                            (r"Random\(\)|Math\.random", "Insecure random number generator", "CWE-330")
                        ]
                        
                        for pattern, message, cwe in weak_crypto_patterns:
                            if re.search(pattern, content):
                                result["findings"].append({
                                    "type": "weak_crypto",
                                    "file": str(file_path),
                                    "severity": "MEDIUM",
                                    "cwe": cwe,
                                    "message": message,
                                    "recommendation": "Use stronger cryptographic algorithms"
                                })
                    
                except Exception as e:
                    logger.warning(f"Error analyzing {file_path}: {e}")
        
        result["stats"] = {
            "total_findings": len(result["findings"]),
            "by_type": {}
        }
        
        for finding in result["findings"]:
            finding_type = finding.get("type")
            result["stats"]["by_type"][finding_type] = result["stats"]["by_type"].get(finding_type, 0) + 1
        
        self.scan_history.append(result)
        return result
    
    async def _run_bandit_scan(self, target_path: str, severity_level: str = "LOW",
                              confidence_level: str = "LOW") -> Dict[str, Any]:
        """Run Bandit Python security scanner."""
        path = Path(target_path)
        if not path.exists():
            raise MCPError(-32000, f"Target path not found: {target_path}")
        
        result = {
            "scan_type": "bandit",
            "timestamp": datetime.now().isoformat(),
            "target_path": target_path,
            "findings": [],
            "metrics": {}
        }
        
        # Build Bandit command
        cmd = [
            "bandit", "-r", str(path), "-f", "json",
            "-l", "-i",  # Show low severity and confidence by default
            "--severity-level", severity_level.lower(),
            "--confidence-level", confidence_level.lower()
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if stdout:
                bandit_results = json.loads(stdout.decode())
                
                result["metrics"] = bandit_results.get("metrics", {})
                
                for issue in bandit_results.get("results", []):
                    result["findings"].append({
                        "test_id": issue.get("test_id"),
                        "test_name": issue.get("test_name"),
                        "severity": issue.get("issue_severity"),
                        "confidence": issue.get("issue_confidence"),
                        "file": issue.get("filename"),
                        "line": issue.get("line_number"),
                        "code": issue.get("code"),
                        "message": issue.get("issue_text"),
                        "cwe": issue.get("issue_cwe", {}).get("id")
                    })
                
        except Exception as e:
            result["error"] = str(e)
        
        result["stats"] = {
            "total_findings": len(result["findings"]),
            "by_severity": {},
            "by_confidence": {}
        }
        
        for finding in result["findings"]:
            severity = finding.get("severity")
            confidence = finding.get("confidence")
            result["stats"]["by_severity"][severity] = result["stats"]["by_severity"].get(severity, 0) + 1
            result["stats"]["by_confidence"][confidence] = result["stats"]["by_confidence"].get(confidence, 0) + 1
        
        self.scan_history.append(result)
        return result
    
    async def _detect_hardcoded_secrets(self, target_path: str, custom_patterns: str = "[]",
                                      exclude_patterns: str = "") -> Dict[str, Any]:
        """Detect hardcoded secrets in code."""
        path = Path(target_path)
        if not path.exists():
            raise MCPError(-32000, f"Target path not found: {target_path}")
        
        result = {
            "scan_type": "secret_detection",
            "timestamp": datetime.now().isoformat(),
            "target_path": target_path,
            "findings": []
        }
        
        # Use multiple secret detection tools
        tools_results = []
        
        # 1. Trufflehog
        try:
            cmd = ["trufflehog", "filesystem", str(path), "--json"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if stdout:
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        finding = json.loads(line)
                        tools_results.append({
                            "tool": "trufflehog",
                            "type": finding.get("detectorName"),
                            "file": finding.get("sourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file"),
                            "verified": finding.get("verified", False),
                            "raw": finding.get("raw")
                        })
        except Exception as e:
            logger.warning(f"Trufflehog scan failed: {e}")
        
        # 2. Gitleaks
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as report_file:
                cmd = ["gitleaks", "detect", "--source", str(path), "--report-format", "json", "--report-path", report_file.name]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                
                if os.path.exists(report_file.name):
                    with open(report_file.name, 'r') as f:
                        gitleaks_results = json.load(f)
                        for finding in gitleaks_results:
                            tools_results.append({
                                "tool": "gitleaks",
                                "type": finding.get("rule"),
                                "file": finding.get("file"),
                                "line": finding.get("startLine"),
                                "commit": finding.get("commit"),
                                "secret": finding.get("secret")[:20] + "***" if finding.get("secret") else None
                            })
                    os.unlink(report_file.name)
        except Exception as e:
            logger.warning(f"Gitleaks scan failed: {e}")
        
        # Aggregate and deduplicate findings
        seen = set()
        for finding in tools_results:
            key = (finding.get("file"), finding.get("type"))
            if key not in seen:
                seen.add(key)
                result["findings"].append({
                    "type": finding.get("type"),
                    "file": finding.get("file"),
                    "line": finding.get("line"),
                    "tool": finding.get("tool"),
                    "severity": "CRITICAL",
                    "cwe": "CWE-798",
                    "recommendation": "Remove hardcoded secret and use secure secret management"
                })
        
        result["stats"] = {
            "total_findings": len(result["findings"]),
            "by_tool": {},
            "by_type": {}
        }
        
        for finding in result["findings"]:
            tool = finding.get("tool")
            secret_type = finding.get("type")
            result["stats"]["by_tool"][tool] = result["stats"]["by_tool"].get(tool, 0) + 1
            result["stats"]["by_type"][secret_type] = result["stats"]["by_type"].get(secret_type, 0) + 1
        
        self.scan_history.append(result)
        return result
    
    async def _analyze_dependencies(self, project_path: str, check_licenses: bool = True,
                                  check_outdated: bool = True) -> Dict[str, Any]:
        """Analyze project dependencies for security issues."""
        path = Path(project_path)
        if not path.exists():
            raise MCPError(-32000, f"Project path not found: {project_path}")
        
        result = {
            "scan_type": "dependency_analysis",
            "timestamp": datetime.now().isoformat(),
            "project_path": project_path,
            "findings": {
                "vulnerabilities": [],
                "license_issues": [],
                "outdated_packages": []
            }
        }
        
        # Detect project type and analyze accordingly
        if (path / "package.json").exists():
            # Node.js project
            await self._analyze_npm_dependencies(path, result, check_licenses, check_outdated)
        
        if (path / "requirements.txt").exists() or (path / "setup.py").exists() or (path / "pyproject.toml").exists():
            # Python project
            await self._analyze_python_dependencies(path, result, check_licenses, check_outdated)
        
        if (path / "pom.xml").exists():
            # Java Maven project
            await self._analyze_maven_dependencies(path, result, check_licenses, check_outdated)
        
        if (path / "go.mod").exists():
            # Go project
            await self._analyze_go_dependencies(path, result, check_licenses, check_outdated)
        
        # Calculate risk score
        total_issues = (len(result["findings"]["vulnerabilities"]) + 
                       len(result["findings"]["license_issues"]) + 
                       len(result["findings"]["outdated_packages"]))
        
        result["risk_assessment"] = {
            "total_issues": total_issues,
            "risk_level": "CRITICAL" if total_issues > 20 else "HIGH" if total_issues > 10 else "MEDIUM" if total_issues > 5 else "LOW",
            "recommendations": self._generate_dependency_recommendations(result["findings"])
        }
        
        self.scan_history.append(result)
        return result
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension."""
        ext_to_lang = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'javascript',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c'
        }
        return ext_to_lang.get(file_path.suffix, 'unknown')
    
    def _extract_cwe(self, rule_id: str) -> Optional[str]:
        """Extract CWE ID from rule ID if present."""
        cwe_match = re.search(r'CWE-(\d+)', rule_id, re.IGNORECASE)
        return f"CWE-{cwe_match.group(1)}" if cwe_match else None
    
    async def _analyze_npm_dependencies(self, path: Path, result: Dict, check_licenses: bool, check_outdated: bool):
        """Analyze npm dependencies."""
        # Run npm audit
        try:
            cmd = ["npm", "audit", "--json"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if stdout:
                audit_data = json.loads(stdout.decode())
                for advisory_id, advisory in audit_data.get("advisories", {}).items():
                    result["findings"]["vulnerabilities"].append({
                        "type": "npm",
                        "package": advisory.get("module_name"),
                        "severity": advisory.get("severity"),
                        "title": advisory.get("title"),
                        "cve": advisory.get("cves", []),
                        "recommendation": advisory.get("recommendation")
                    })
        except Exception as e:
            logger.warning(f"npm audit failed: {e}")
        
        # Check licenses
        if check_licenses:
            try:
                cmd = ["license-checker", "--json", "--production"]
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=str(path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                
                if stdout:
                    licenses = json.loads(stdout.decode())
                    problematic = ["GPL", "AGPL", "LGPL", "SSPL"]
                    for pkg, info in licenses.items():
                        license_type = info.get("licenses", "")
                        if any(prob in license_type for prob in problematic):
                            result["findings"]["license_issues"].append({
                                "package": pkg,
                                "license": license_type,
                                "issue": "Potentially restrictive license"
                            })
            except Exception as e:
                logger.warning(f"License check failed: {e}")
    
    async def _analyze_python_dependencies(self, path: Path, result: Dict, check_licenses: bool, check_outdated: bool):
        """Analyze Python dependencies."""
        # Run safety check
        try:
            cmd = ["safety", "check", "--json"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if stdout:
                vulnerabilities = json.loads(stdout.decode())
                for vuln in vulnerabilities:
                    result["findings"]["vulnerabilities"].append({
                        "type": "python",
                        "package": vuln.get("package"),
                        "installed_version": vuln.get("installed_version"),
                        "vulnerability": vuln.get("vulnerability"),
                        "description": vuln.get("description"),
                        "cve": vuln.get("cve")
                    })
        except Exception as e:
            logger.warning(f"Safety check failed: {e}")
        
        # Check with pip-audit
        try:
            cmd = ["pip-audit", "--format", "json"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if stdout:
                audit_results = json.loads(stdout.decode())
                for vuln in audit_results:
                    result["findings"]["vulnerabilities"].append({
                        "type": "python",
                        "package": vuln.get("name"),
                        "version": vuln.get("version"),
                        "vulnerability": vuln.get("vulns", [])
                    })
        except Exception as e:
            logger.warning(f"pip-audit failed: {e}")
    
    def _generate_dependency_recommendations(self, findings: Dict) -> List[str]:
        """Generate recommendations based on dependency findings."""
        recommendations = []
        
        if findings["vulnerabilities"]:
            recommendations.append("Update vulnerable dependencies to patched versions")
            critical_vulns = [v for v in findings["vulnerabilities"] if v.get("severity") in ["CRITICAL", "HIGH"]]
            if critical_vulns:
                recommendations.append(f"Address {len(critical_vulns)} critical/high severity vulnerabilities immediately")
        
        if findings["license_issues"]:
            recommendations.append("Review license compliance for restrictive licenses")
        
        if findings["outdated_packages"]:
            recommendations.append("Update outdated packages to maintain security patches")
        
        return recommendations