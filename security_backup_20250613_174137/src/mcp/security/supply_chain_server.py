
from __future__ import annotations

"""Supply Chain Security MCP Server."""

__all__ = [
    "SupplyChainSecurityMCPServer"
]
import os
import json
import asyncio
import hashlib
import subprocess
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from datetime import datetime
import logging
from asyncio import Semaphore
import tempfile
import re
from urllib.parse import urlparse

from src.mcp.protocols import MCPTool, MCPToolParameter, MCPServerInfo, MCPCapabilities, MCPError
from src.mcp.servers import MCPServer

logger = logging.getLogger(__name__)

# Known malicious packages database (simplified version)
KNOWN_MALICIOUS_PACKAGES = {
    "python": [
        "colourama",  # Typosquatting colorama
        "python-binance",  # Known malicious
        "djanggo",  # Typosquatting django
        "reqeusts",  # Typosquatting requests
    ],
    "npm": [
        "crossenv",  # Known malicious
        "event-stream",  # Compromised package
        "eslint-scope",  # Compromised package
        "bootstrap-sass",  # Known vulnerability
    ]
}

# Suspicious patterns in package names
TYPOSQUATTING_PATTERNS = [
    (r"djang[^o]", "django"),
    (r"reque[^s]ts", "requests"),
    (r"nump[^y]", "numpy"),
    (r"panda[^s]", "pandas"),
    (r"expres[^s]", "express"),
    (r"reac[^t]", "react"),
]


class SupplyChainSecurityMCPServer(MCPServer):
    """Supply Chain Security MCP Server for comprehensive dependency analysis."""
    
    def __init__(self, permission_checker: Optional[Any] = None):
        """Initialize Supply Chain Security server."""
        super().__init__(name="supply-chain-security", version="1.0.0", permission_checker=permission_checker)
        self.scan_history: List[Dict[str, Any]] = []
        self.scan_semaphore = Semaphore(3)
        self._sbom_cache: Dict[str, Any] = {}
        self._vulnerability_db: Dict[str, List[Dict]] = {}
        self._initialize_vulnerability_db()
    
    def _initialize_vulnerability_db(self):
        """Initialize local vulnerability database."""
        # In production, this would connect to real vulnerability databases
        self._vulnerability_db = {
            "log4j": [{"cve": "CVE-2021-44228", "severity": "CRITICAL", "versions": ["2.0-2.14.1"]}],
            "spring-core": [{"cve": "CVE-2022-22965", "severity": "CRITICAL", "versions": ["<5.3.18"]}],
            "jackson-databind": [{"cve": "CVE-2020-36518", "severity": "HIGH", "versions": ["<2.13.2"]}]
        }
    
    def get_server_info(self) -> MCPServerInfo:
        """Get Supply Chain Security server information."""
        return MCPServerInfo(
            name="supply-chain-security",
            version="1.0.0",
            description="Supply chain security analysis and SBOM management",
            capabilities=MCPCapabilities(
                tools=True,
                resources=False,
                prompts=False,
                experimental={
                    "sbom_generation": True,
                    "dependency_confusion_detection": True,
                    "license_compliance": True,
                    "vulnerability_correlation": True,
                    "package_integrity_verification": True,
                    "transitive_dependency_analysis": True,
                    "risk_scoring": True
                }
            )
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get available Supply Chain Security tools."""
        return [
            MCPTool(
                name="generate_sbom",
                description="Generate Software Bill of Materials (SBOM)",
                parameters=[
                    MCPToolParameter(name="project_path", type="string",
                                   description="Project root path", required=True),
                    MCPToolParameter(name="format", type="string",
                                   description="SBOM format", required=False,
                                   enum=["cyclonedx", "spdx", "json"], default="cyclonedx"),
                    MCPToolParameter(name="include_dev_deps", type="boolean",
                                   description="Include development dependencies", required=False, default=False)
                ]
            ),
            MCPTool(
                name="detect_dependency_confusion",
                description="Detect dependency confusion and typosquatting attacks",
                parameters=[
                    MCPToolParameter(name="project_path", type="string",
                                   description="Project path to analyze", required=True),
                    MCPToolParameter(name="check_internal_packages", type="boolean",
                                   description="Check for internal package conflicts", required=False, default=True),
                    MCPToolParameter(name="custom_registry", type="string",
                                   description="Custom package registry URL", required=False, default="")
                ]
            ),
            MCPTool(
                name="analyze_license_compliance",
                description="Analyze license compliance across dependencies",
                parameters=[
                    MCPToolParameter(name="project_path", type="string",
                                   description="Project path", required=True),
                    MCPToolParameter(name="allowed_licenses", type="string",
                                   description="Comma-separated list of allowed licenses", required=False,
                                   default="MIT,Apache-2.0,BSD-3-Clause,BSD-2-Clause,ISC"),
                    MCPToolParameter(name="fail_on_violation", type="boolean",
                                   description="Fail if license violations found", required=False, default=False)
                ]
            ),
            MCPTool(
                name="verify_package_integrity",
                description="Verify package integrity and signatures",
                parameters=[
                    MCPToolParameter(name="project_path", type="string",
                                   description="Project path", required=True),
                    MCPToolParameter(name="verify_signatures", type="boolean",
                                   description="Verify package signatures", required=False, default=True),
                    MCPToolParameter(name="check_checksums", type="boolean",
                                   description="Verify package checksums", required=False, default=True)
                ]
            ),
            MCPTool(
                name="analyze_transitive_dependencies",
                description="Deep analysis of transitive dependencies",
                parameters=[
                    MCPToolParameter(name="project_path", type="string",
                                   description="Project path", required=True),
                    MCPToolParameter(name="max_depth", type="integer",
                                   description="Maximum dependency depth to analyze", required=False, default=5),
                    MCPToolParameter(name="include_optional", type="boolean",
                                   description="Include optional dependencies", required=False, default=False)
                ]
            ),
            MCPTool(
                name="assess_supply_chain_risk",
                description="Comprehensive supply chain risk assessment",
                parameters=[
                    MCPToolParameter(name="project_path", type="string",
                                   description="Project path", required=True),
                    MCPToolParameter(name="risk_factors", type="string",
                                   description="Risk factors to evaluate (comma-separated)", required=False,
                                   default="age,popularity,maintenance,vulnerabilities,licenses")
                ]
            )
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute Supply Chain Security tool."""
        async with self.scan_semaphore:
            tool_map = {
                "generate_sbom": self._generate_sbom,
                "detect_dependency_confusion": self._detect_dependency_confusion,
                "analyze_license_compliance": self._analyze_license_compliance,
                "verify_package_integrity": self._verify_package_integrity,
                "analyze_transitive_dependencies": self._analyze_transitive_dependencies,
                "assess_supply_chain_risk": self._assess_supply_chain_risk
            }
            
            if tool_name not in tool_map:
                raise MCPError(-32601, f"Unknown tool: {tool_name}")
            
            return await tool_map[tool_name](**arguments)
    
    async def _generate_sbom(self, project_path: str, format: str = "cyclonedx",
                           include_dev_deps: bool = False) -> Dict[str, Any]:
        """Generate Software Bill of Materials."""
        path = Path(project_path)
        if not path.exists():
            raise MCPError(-32000, f"Project path not found: {project_path}")
        
        result = {
            "scan_type": "sbom_generation",
            "timestamp": datetime.now().isoformat(),
            "project_path": project_path,
            "format": format,
            "sbom": None,
            "stats": {
                "total_packages": 0,
                "direct_dependencies": 0,
                "transitive_dependencies": 0,
                "unique_licenses": set(),
                "package_managers": []
            }
        }
        
        sbom_components = []
        
        # Detect and analyze different package managers
        if (path / "package.json").exists():
            npm_components = await self._analyze_npm_sbom(path, include_dev_deps)
            sbom_components.extend(npm_components)
            result["stats"]["package_managers"].append("npm")
        
        if (path / "requirements.txt").exists() or (path / "pyproject.toml").exists():
            python_components = await self._analyze_python_sbom(path, include_dev_deps)
            sbom_components.extend(python_components)
            result["stats"]["package_managers"].append("python")
        
        if (path / "go.mod").exists():
            go_components = await self._analyze_go_sbom(path, include_dev_deps)
            sbom_components.extend(go_components)
            result["stats"]["package_managers"].append("go")
        
        # Generate SBOM in requested format
        if format == "cyclonedx":
            result["sbom"] = self._generate_cyclonedx_sbom(sbom_components, project_path)
        elif format == "spdx":
            result["sbom"] = self._generate_spdx_sbom(sbom_components, project_path)
        else:  # json
            result["sbom"] = {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "tool": "supply-chain-security-mcp",
                    "project": project_path
                },
                "components": sbom_components
            }
        
        # Update statistics
        result["stats"]["total_packages"] = len(sbom_components)
        result["stats"]["unique_licenses"] = list({comp.get("license", "Unknown") for comp in sbom_components})
        
        # Cache SBOM for future use
        self._sbom_cache[project_path] = result["sbom"]
        
        self.scan_history.append(result)
        return result
    
    async def _detect_dependency_confusion(self, project_path: str, check_internal_packages: bool = True,
                                         custom_registry: str = "") -> Dict[str, Any]:
        """Detect dependency confusion attacks."""
        path = Path(project_path)
        if not path.exists():
            raise MCPError(-32000, f"Project path not found: {project_path}")
        
        result = {
            "scan_type": "dependency_confusion",
            "timestamp": datetime.now().isoformat(),
            "project_path": project_path,
            "findings": {
                "typosquatting": [],
                "namespace_confusion": [],
                "malicious_packages": [],
                "suspicious_packages": []
            }
        }
        
        # Get all dependencies
        all_dependencies = await self._get_all_dependencies(path)
        
        for dep_type, dependencies in all_dependencies.items():
            for dep in dependencies:
                package_name = dep.get("name", "").lower()
                
                # Check against known malicious packages
                if package_name in KNOWN_MALICIOUS_PACKAGES.get(dep_type, []):
                    result["findings"]["malicious_packages"].append({
                        "package": package_name,
                        "type": dep_type,
                        "severity": "CRITICAL",
                        "reason": "Known malicious package"
                    })
                
                # Check for typosquatting
                for pattern, legitimate in TYPOSQUATTING_PATTERNS:
                    if re.match(pattern, package_name) and package_name != legitimate:
                        result["findings"]["typosquatting"].append({
                            "package": package_name,
                            "type": dep_type,
                            "severity": "HIGH",
                            "similar_to": legitimate,
                            "recommendation": f"Did you mean '{legitimate}'?"
                        })
                
                # Check for namespace confusion
                if check_internal_packages and custom_registry:
                    is_internal = await self._check_internal_package(package_name, custom_registry)
                    is_public = await self._check_public_package(package_name, dep_type)
                    
                    if is_internal and is_public:
                        result["findings"]["namespace_confusion"].append({
                            "package": package_name,
                            "type": dep_type,
                            "severity": "HIGH",
                            "reason": "Package exists in both internal and public registries"
                        })
                
                # Check for suspicious patterns
                suspicious_patterns = [
                    (r"test|demo|example", "Development/test package in production"),
                    (r"[0-9]{6,}", "Suspicious version number pattern"),
                    (r"[^a-z0-9\-_]", "Unusual characters in package name")
                ]
                
                for pattern, reason in suspicious_patterns:
                    if re.search(pattern, package_name):
                        result["findings"]["suspicious_packages"].append({
                            "package": package_name,
                            "type": dep_type,
                            "severity": "MEDIUM",
                            "reason": reason
                        })
        
        # Calculate risk score
        total_issues = sum(len(findings) for findings in result["findings"].values())
        result["risk_assessment"] = {
            "total_issues": total_issues,
            "risk_level": "CRITICAL" if result["findings"]["malicious_packages"] else 
                         "HIGH" if result["findings"]["namespace_confusion"] or result["findings"]["typosquatting"] else
                         "MEDIUM" if result["findings"]["suspicious_packages"] else "LOW",
            "recommendations": self._generate_confusion_recommendations(result["findings"])
        }
        
        self.scan_history.append(result)
        return result
    
    async def _analyze_license_compliance(self, project_path: str, 
                                        allowed_licenses: str = "MIT,Apache-2.0,BSD-3-Clause,BSD-2-Clause,ISC",
                                        fail_on_violation: bool = False) -> Dict[str, Any]:
        """Analyze license compliance."""
        path = Path(project_path)
        if not path.exists():
            raise MCPError(-32000, f"Project path not found: {project_path}")
        
        result = {
            "scan_type": "license_compliance",
            "timestamp": datetime.now().isoformat(),
            "project_path": project_path,
            "allowed_licenses": allowed_licenses.split(","),
            "findings": {
                "violations": [],
                "unknown_licenses": [],
                "license_summary": {}
            }
        }
        
        allowed_set = set(lic.strip() for lic in allowed_licenses.split(","))
        
        # Get SBOM if cached, otherwise generate
        if project_path not in self._sbom_cache:
            sbom_result = await self._generate_sbom(project_path, format="json", include_dev_deps=False)
            sbom = sbom_result.get("sbom", {})
        else:
            sbom = self._sbom_cache[project_path]
        
        # Analyze licenses
        for component in sbom.get("components", []):
            license_id = component.get("license", "Unknown")
            package_name = component.get("name")
            
            # Track license usage
            result["findings"]["license_summary"][license_id] = result["findings"]["license_summary"].get(license_id, 0) + 1
            
            if license_id == "Unknown":
                result["findings"]["unknown_licenses"].append({
                    "package": package_name,
                    "version": component.get("version"),
                    "severity": "MEDIUM",
                    "recommendation": "Investigate and document license"
                })
            elif license_id not in allowed_set:
                result["findings"]["violations"].append({
                    "package": package_name,
                    "version": component.get("version"),
                    "license": license_id,
                    "severity": "HIGH" if license_id in ["GPL", "AGPL", "LGPL"] else "MEDIUM",
                    "recommendation": f"Review licensing requirements for {license_id}"
                })
        
        # Risk assessment
        result["compliance_status"] = {
            "compliant": len(result["findings"]["violations"]) == 0,
            "total_packages": len(sbom.get("components", [])),
            "violations_count": len(result["findings"]["violations"]),
            "unknown_count": len(result["findings"]["unknown_licenses"]),
            "risk_level": "HIGH" if result["findings"]["violations"] else "MEDIUM" if result["findings"]["unknown_licenses"] else "LOW"
        }
        
        if fail_on_violation and result["findings"]["violations"]:
            raise MCPError(-32000, f"License compliance check failed: {len(result['findings']['violations'])} violations found")
        
        self.scan_history.append(result)
        return result
    
    async def _verify_package_integrity(self, project_path: str, verify_signatures: bool = True,
                                      check_checksums: bool = True) -> Dict[str, Any]:
        """Verify package integrity and signatures."""
        path = Path(project_path)
        if not path.exists():
            raise MCPError(-32000, f"Project path not found: {project_path}")
        
        result = {
            "scan_type": "package_integrity",
            "timestamp": datetime.now().isoformat(),
            "project_path": project_path,
            "findings": {
                "signature_failures": [],
                "checksum_mismatches": [],
                "missing_integrity": [],
                "verified_packages": []
            }
        }
        
        # NPM integrity check
        if (path / "package-lock.json").exists():
            npm_integrity = await self._verify_npm_integrity(path, verify_signatures, check_checksums)
            result["findings"]["signature_failures"].extend(npm_integrity.get("signature_failures", []))
            result["findings"]["checksum_mismatches"].extend(npm_integrity.get("checksum_mismatches", []))
            result["findings"]["verified_packages"].extend(npm_integrity.get("verified", []))
        
        # Python integrity check
        if (path / "requirements.txt").exists():
            python_integrity = await self._verify_python_integrity(path, check_checksums)
            result["findings"]["checksum_mismatches"].extend(python_integrity.get("checksum_mismatches", []))
            result["findings"]["verified_packages"].extend(python_integrity.get("verified", []))
        
        # Calculate integrity score
        total_packages = len(result["findings"]["verified_packages"]) + len(result["findings"]["signature_failures"]) + len(result["findings"]["checksum_mismatches"])
        integrity_score = (len(result["findings"]["verified_packages"]) / total_packages * 100) if total_packages > 0 else 100
        
        result["integrity_assessment"] = {
            "integrity_score": round(integrity_score, 2),
            "total_packages": total_packages,
            "verified_count": len(result["findings"]["verified_packages"]),
            "failure_count": len(result["findings"]["signature_failures"]) + len(result["findings"]["checksum_mismatches"]),
            "risk_level": "CRITICAL" if integrity_score < 50 else "HIGH" if integrity_score < 80 else "MEDIUM" if integrity_score < 95 else "LOW"
        }
        
        self.scan_history.append(result)
        return result
    
    async def _analyze_transitive_dependencies(self, project_path: str, max_depth: int = 5,
                                             include_optional: bool = False) -> Dict[str, Any]:
        """Analyze transitive dependencies."""
        path = Path(project_path)
        if not path.exists():
            raise MCPError(-32000, f"Project path not found: {project_path}")
        
        result = {
            "scan_type": "transitive_dependencies",
            "timestamp": datetime.now().isoformat(),
            "project_path": project_path,
            "max_depth": max_depth,
            "dependency_tree": {},
            "findings": {
                "deep_dependencies": [],
                "circular_dependencies": [],
                "version_conflicts": [],
                "vulnerability_chains": []
            }
        }
        
        # Build dependency tree
        dependency_tree = await self._build_dependency_tree(path, max_depth, include_optional)
        result["dependency_tree"] = dependency_tree
        
        # Analyze the tree
        visited = set()
        path_stack = []
        
        def analyze_tree(node: Dict, depth: int = 0, parent_path: List[str] = []):
            """Recursively analyze dependency tree."""
            package_name = node.get("name")
            current_path = parent_path + [package_name]
            
            # Check for circular dependencies
            if package_name in parent_path:
                result["findings"]["circular_dependencies"].append({
                    "package": package_name,
                    "cycle": " -> ".join(current_path),
                    "severity": "HIGH"
                })
                return
            
            # Check for deep dependencies
            if depth >= 4:
                result["findings"]["deep_dependencies"].append({
                    "package": package_name,
                    "depth": depth,
                    "path": " -> ".join(current_path),
                    "severity": "MEDIUM",
                    "recommendation": "Consider flattening dependency tree"
                })
            
            # Check for vulnerabilities in chain
            if package_name in self._vulnerability_db:
                result["findings"]["vulnerability_chains"].append({
                    "package": package_name,
                    "vulnerabilities": self._vulnerability_db[package_name],
                    "path": " -> ".join(current_path),
                    "severity": "HIGH"
                })
            
            # Recurse to dependencies
            for dep in node.get("dependencies", []):
                analyze_tree(dep, depth + 1, current_path)
        
        # Start analysis from root dependencies
        for root_dep in dependency_tree.get("dependencies", []):
            analyze_tree(root_dep)
        
        # Check for version conflicts
        version_map = {}
        self._collect_versions(dependency_tree, version_map)
        
        for package, versions in version_map.items():
            if len(versions) > 1:
                result["findings"]["version_conflicts"].append({
                    "package": package,
                    "versions": list(versions),
                    "severity": "MEDIUM",
                    "recommendation": "Resolve version conflicts to ensure consistency"
                })
        
        # Risk assessment
        total_issues = sum(len(findings) for findings in result["findings"].values())
        result["risk_assessment"] = {
            "total_issues": total_issues,
            "max_depth_found": self._get_max_depth(dependency_tree),
            "total_packages": self._count_packages(dependency_tree),
            "risk_level": "HIGH" if result["findings"]["circular_dependencies"] or result["findings"]["vulnerability_chains"] else "MEDIUM" if total_issues > 10 else "LOW"
        }
        
        self.scan_history.append(result)
        return result
    
    async def _assess_supply_chain_risk(self, project_path: str,
                                      risk_factors: str = "age,popularity,maintenance,vulnerabilities,licenses") -> Dict[str, Any]:
        """Comprehensive supply chain risk assessment."""
        path = Path(project_path)
        if not path.exists():
            raise MCPError(-32000, f"Project path not found: {project_path}")
        
        result = {
            "scan_type": "supply_chain_risk_assessment",
            "timestamp": datetime.now().isoformat(),
            "project_path": project_path,
            "risk_factors": risk_factors.split(","),
            "package_risks": [],
            "overall_risk": {
                "score": 0,
                "level": "LOW",
                "critical_risks": [],
                "recommendations": []
            }
        }
        
        # Get all dependencies
        all_dependencies = await self._get_all_dependencies(path)
        risk_scores = []
        
        for dep_type, dependencies in all_dependencies.items():
            for dep in dependencies:
                package_risk = await self._assess_package_risk(dep, dep_type, risk_factors.split(","))
                result["package_risks"].append(package_risk)
                risk_scores.append(package_risk["risk_score"])
                
                if package_risk["risk_level"] == "CRITICAL":
                    result["overall_risk"]["critical_risks"].append({
                        "package": package_risk["package"],
                        "reasons": package_risk["risk_factors"]
                    })
        
        # Calculate overall risk
        if risk_scores:
            avg_risk_score = sum(risk_scores) / len(risk_scores)
            result["overall_risk"]["score"] = round(avg_risk_score, 2)
            result["overall_risk"]["level"] = (
                "CRITICAL" if avg_risk_score >= 80 or result["overall_risk"]["critical_risks"] else
                "HIGH" if avg_risk_score >= 60 else
                "MEDIUM" if avg_risk_score >= 40 else
                "LOW"
            )
        
        # Generate recommendations
        result["overall_risk"]["recommendations"] = self._generate_risk_recommendations(result)
        
        self.scan_history.append(result)
        return result
    
    # Helper methods
    
    async def _analyze_npm_sbom(self, path: Path, include_dev: bool) -> List[Dict]:
        """Analyze npm packages for SBOM."""
        components = []
        
        try:
            cmd = ["npm", "list", "--json", "--all"]
            if not include_dev:
                cmd.append("--production")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            
            if stdout:
                npm_tree = json.loads(stdout.decode())
                self._extract_npm_components(npm_tree.get("dependencies", {}), components)
        except Exception as e:
            logger.warning(f"npm SBOM analysis failed: {e}")
        
        return components
    
    async def _analyze_python_sbom(self, path: Path, include_dev: bool) -> List[Dict]:
        """Analyze Python packages for SBOM."""
        components = []
        
        try:
            cmd = ["pip", "list", "--format=json"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            
            if stdout:
                packages = json.loads(stdout.decode())
                for pkg in packages:
                    components.append({
                        "name": pkg.get("name"),
                        "version": pkg.get("version"),
                        "type": "python",
                        "license": await self._get_python_license(pkg.get("name"))
                    })
        except Exception as e:
            logger.warning(f"Python SBOM analysis failed: {e}")
        
        return components
    
    def _extract_npm_components(self, deps: Dict, components: List[Dict], seen: Set[str] = None):
        """Extract components from npm dependency tree."""
        if seen is None:
            seen = set()
        
        for name, info in deps.items():
            key = f"{name}@{info.get('version')}"
            if key not in seen:
                seen.add(key)
                components.append({
                    "name": name,
                    "version": info.get("version"),
                    "type": "npm",
                    "license": info.get("license", "Unknown"),
                    "resolved": info.get("resolved"),
                    "integrity": info.get("integrity")
                })
                
                if "dependencies" in info:
                    self._extract_npm_components(info["dependencies"], components, seen)
    
    async def _get_python_license(self, package_name: str) -> str:
        """Get license for Python package."""
        try:
            cmd = ["pip", "show", package_name]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            
            if stdout:
                for line in stdout.decode().split('\n'):
                    if line.startswith("License:"):
                        return line.split(":", 1)[1].strip()
        except (asyncio.TimeoutError, subprocess.SubprocessError, OSError) as e:
            logger.debug(f"Failed to get Python package license for {package_name}: {e}")
        
        return "Unknown"
    
    def _generate_cyclonedx_sbom(self, components: List[Dict], project_path: str) -> Dict:
        """Generate CycloneDX format SBOM."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{hashlib.sha256(project_path.encode()).hexdigest()[:8]}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [{"name": "supply-chain-security-mcp", "version": "1.0.0"}]
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": f"{comp['name']}@{comp['version']}",
                    "name": comp["name"],
                    "version": comp["version"],
                    "licenses": [{"license": {"name": comp.get("license", "Unknown")}}]
                }
                for comp in components
            ]
        }
    
    async def _get_all_dependencies(self, path: Path) -> Dict[str, List[Dict]]:
        """Get all dependencies from project."""
        dependencies = {}
        
        # NPM dependencies
        if (path / "package.json").exists():
            with open(path / "package.json", "r") as f:
                package_json = json.load(f)
                npm_deps = []
                for name, version in package_json.get("dependencies", {}).items():
                    npm_deps.append({"name": name, "version": version})
                dependencies["npm"] = npm_deps
        
        # Python dependencies
        if (path / "requirements.txt").exists():
            python_deps = []
            with open(path / "requirements.txt", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = re.split(r'[=<>~!]', line)
                        if parts:
                            python_deps.append({"name": parts[0].strip(), "version": line})
            dependencies["python"] = python_deps
        
        return dependencies
    
    async def _check_internal_package(self, package_name: str, registry_url: str) -> bool:
        """Check if package exists in internal registry."""
        # Simplified check - in production would make actual API calls
        return package_name.startswith("internal-") or package_name.startswith("company-")
    
    async def _check_public_package(self, package_name: str, package_type: str) -> bool:
        """Check if package exists in public registry."""
        # Simplified check - in production would query npm, PyPI, etc.
        return True  # Assume all packages are public for this example
    
    def _generate_confusion_recommendations(self, findings: Dict) -> List[str]:
        """Generate recommendations for dependency confusion findings."""
        recommendations = []
        
        if findings["malicious_packages"]:
            recommendations.append("CRITICAL: Remove malicious packages immediately and scan for compromise")
        
        if findings["typosquatting"]:
            recommendations.append("Review and correct typosquatted package names")
        
        if findings["namespace_confusion"]:
            recommendations.append("Use scoped packages or private registry for internal packages")
        
        if findings["suspicious_packages"]:
            recommendations.append("Investigate suspicious packages and verify their legitimacy")
        
        return recommendations
    
    async def _verify_npm_integrity(self, path: Path, verify_signatures: bool, check_checksums: bool) -> Dict:
        """Verify NPM package integrity."""
        result = {"signature_failures": [], "checksum_mismatches": [], "verified": []}
        
        try:
            with open(path / "package-lock.json", "r") as f:
                lock_data = json.load(f)
                
                for name, package_data in lock_data.get("packages", {}).items():
                    if name and "integrity" in package_data:
                        # In production, would verify actual package integrity
                        result["verified"].append({
                            "package": name,
                            "integrity": package_data["integrity"]
                        })
        except Exception as e:
            logger.warning(f"NPM integrity check failed: {e}")
        
        return result
    
    async def _build_dependency_tree(self, path: Path, max_depth: int, include_optional: bool) -> Dict:
        """Build dependency tree."""
        tree = {"name": "root", "dependencies": []}
        
        # Simplified tree building - in production would use proper dependency resolution
        all_deps = await self._get_all_dependencies(path)
        
        for dep_type, deps in all_deps.items():
            for dep in deps:
                tree["dependencies"].append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "type": dep_type,
                    "dependencies": []  # Would recursively fetch in production
                })
        
        return tree
    
    def _collect_versions(self, node: Dict, version_map: Dict[str, Set[str]]):
        """Collect all versions of packages in dependency tree."""
        name = node.get("name")
        version = node.get("version")
        
        if name and version:
            if name not in version_map:
                version_map[name] = set()
            version_map[name].add(version)
        
        for dep in node.get("dependencies", []):
            self._collect_versions(dep, version_map)
    
    def _get_max_depth(self, node: Dict, current_depth: int = 0) -> int:
        """Get maximum depth of dependency tree."""
        if not node.get("dependencies"):
            return current_depth
        
        return max(self._get_max_depth(dep, current_depth + 1) for dep in node["dependencies"])
    
    def _count_packages(self, node: Dict) -> int:
        """Count total packages in dependency tree."""
        count = 1 if node.get("name") != "root" else 0
        
        for dep in node.get("dependencies", []):
            count += self._count_packages(dep)
        
        return count
    
    async def _assess_package_risk(self, package: Dict, package_type: str, risk_factors: List[str]) -> Dict:
        """Assess risk for individual package."""
        risk_score = 0
        risk_details = []
        
        package_name = package.get("name")
        
        # Age factor (simplified - in production would check actual package age)
        if "age" in risk_factors:
            # Assume new packages (< 6 months) are riskier
            risk_score += 20
            risk_details.append("Package age unknown")
        
        # Popularity factor (simplified)
        if "popularity" in risk_factors:
            # In production, would check download counts
            risk_score += 10
            risk_details.append("Popularity metrics unavailable")
        
        # Maintenance factor
        if "maintenance" in risk_factors:
            # In production, would check last update date
            risk_score += 15
            risk_details.append("Maintenance status unknown")
        
        # Vulnerability factor
        if "vulnerabilities" in risk_factors:
            if package_name in self._vulnerability_db:
                risk_score += 40
                risk_details.append(f"Known vulnerabilities: {len(self._vulnerability_db[package_name])}")
        
        # License factor
        if "licenses" in risk_factors:
            # Simplified license risk
            risky_licenses = ["GPL", "AGPL", "LGPL", "SSPL"]
            risk_score += 20
            risk_details.append("License risk assessment pending")
        
        return {
            "package": package_name,
            "type": package_type,
            "risk_score": min(risk_score, 100),
            "risk_level": "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW",
            "risk_factors": risk_details
        }
    
    def _generate_risk_recommendations(self, assessment: Dict) -> List[str]:
        """Generate recommendations based on risk assessment."""
        recommendations = []
        
        risk_level = assessment["overall_risk"]["level"]
        
        if risk_level in ["CRITICAL", "HIGH"]:
            recommendations.append("Conduct immediate security review of high-risk dependencies")
            recommendations.append("Consider replacing critical packages with more secure alternatives")
        
        if assessment["overall_risk"]["critical_risks"]:
            recommendations.append("Address critical package risks before deployment")
        
        recommendations.append("Implement continuous dependency monitoring")
        recommendations.append("Establish dependency update policies and procedures")
        
        # Specific recommendations based on risk factors
        high_risk_packages = [p for p in assessment["package_risks"] if p["risk_level"] in ["CRITICAL", "HIGH"]]
        if high_risk_packages:
            recommendations.append(f"Review and remediate {len(high_risk_packages)} high-risk packages")
        
        return recommendations