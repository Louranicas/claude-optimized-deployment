#!/usr/bin/env python3
"""
AGENT 7: Phase 4 Supply Chain and Dependency Security Audit
Tests all dependencies for vulnerabilities, malicious packages, and supply chain risks
"""

import os
import sys
import json
import subprocess
from datetime import datetime
from pathlib import Path

results = {
    "audit_timestamp": datetime.now().isoformat(),
    "phase": "Phase 4: Supply Chain Security Assessment",
    "vulnerabilities": [],
    "tests_performed": [],
    "dependency_analysis": {}
}

def analyze_python_dependencies():
    """Analyze Python dependencies for vulnerabilities"""
    print("[*] Analyzing Python dependencies...")
    
    python_vulns = []
    
    # Run pip-audit for comprehensive analysis
    try:
        print("   Running pip-audit...")
        audit_result = subprocess.run(
            ["./venv_bulletproof/bin/pip-audit", "--format", "json"],
            capture_output=True,
            text=True
        )
        
        if audit_result.stdout:
            audit_data = json.loads(audit_result.stdout)
            
            for vuln in audit_data.get('vulnerabilities', []):
                python_vulns.append({
                    "package": vuln.get('name'),
                    "version": vuln.get('version'),
                    "vulnerability_id": vuln.get('id'),
                    "type": "DEPENDENCY_VULNERABILITY",
                    "severity": "HIGH",  # pip-audit doesn't provide severity
                    "details": vuln.get('description', 'No description'),
                    "fix_version": vuln.get('fix_versions', [None])[0]
                })
                
    except Exception as e:
        print(f"   [!] Error running pip-audit: {e}")
        
    # Check for typosquatting
    print("   Checking for typosquatting...")
    typo_patterns = [
        ("request", "requests"),  # Common typo
        ("numpy", "nunpy"),
        ("pandas", "pndas"),
        ("django", "djngo"),
        ("flask", "flsk")
    ]
    
    installed_packages = set()
    try:
        pip_list = subprocess.run(
            ["./venv_bulletproof/bin/pip", "list", "--format=json"],
            capture_output=True,
            text=True
        )
        if pip_list.stdout:
            packages = json.loads(pip_list.stdout)
            installed_packages = {p['name'].lower() for p in packages}
    except Exception:
        pass
        
    for correct, typo in typo_patterns:
        if typo in installed_packages:
            python_vulns.append({
                "package": typo,
                "type": "TYPOSQUATTING",
                "severity": "CRITICAL",
                "details": f"Possible typosquatting package. Did you mean '{correct}'?",
                "cvss_score": 9.8
            })
            
    # Check for outdated packages
    print("   Checking for outdated packages...")
    try:
        outdated = subprocess.run(
            ["./venv_bulletproof/bin/pip", "list", "--outdated", "--format=json"],
            capture_output=True,
            text=True
        )
        if outdated.stdout:
            outdated_pkgs = json.loads(outdated.stdout)
            
            # Count severely outdated (major version behind)
            for pkg in outdated_pkgs[:5]:  # Top 5 most outdated
                current = pkg.get('version', '0.0.0')
                latest = pkg.get('latest_version', '0.0.0')
                
                current_major = int(current.split('.')[0])
                latest_major = int(latest.split('.')[0])
                
                if latest_major - current_major >= 2:
                    python_vulns.append({
                        "package": pkg['name'],
                        "current_version": current,
                        "latest_version": latest,
                        "type": "SEVERELY_OUTDATED",
                        "severity": "MEDIUM",
                        "details": f"Package is {latest_major - current_major} major versions behind",
                        "cvss_score": 5.3
                    })
                    
    except Exception as e:
        print(f"   [!] Error checking outdated packages: {e}")
        
    results["vulnerabilities"].extend(python_vulns)
    results["tests_performed"].append({
        "test": "Python Dependency Analysis",
        "packages_analyzed": len(installed_packages),
        "issues_found": len(python_vulns)
    })
    
    print(f"   Found {len(python_vulns)} Python dependency issues")
    

def analyze_rust_dependencies():
    """Analyze Rust dependencies for vulnerabilities"""
    print("[*] Analyzing Rust dependencies...")
    
    rust_vulns = []
    
    # Check if cargo-audit is available
    cargo_audit_path = None
    for path in ["/usr/local/bin/cargo-audit", "/home/louranicas/.cargo/bin/cargo-audit"]:
        if os.path.exists(path):
            cargo_audit_path = path
            break
            
    if cargo_audit_path:
        try:
            print("   Running cargo-audit...")
            audit_result = subprocess.run(
                [cargo_audit_path, "audit", "--json"],
                cwd="rust_core",
                capture_output=True,
                text=True
            )
            
            if audit_result.stdout:
                # Parse cargo-audit output
                for line in audit_result.stdout.split('\n'):
                    if line and line.startswith('{'):
                        try:
                            vuln_data = json.loads(line)
                            if vuln_data.get('type') == 'vulnerability':
                                rust_vulns.append({
                                    "package": vuln_data.get('package', {}).get('name'),
                                    "version": vuln_data.get('package', {}).get('version'),
                                    "vulnerability_id": vuln_data.get('advisory', {}).get('id'),
                                    "type": "RUST_DEPENDENCY_VULNERABILITY",
                                    "severity": vuln_data.get('advisory', {}).get('severity', 'UNKNOWN').upper(),
                                    "details": vuln_data.get('advisory', {}).get('title', 'No description'),
                                    "cvss_score": vuln_data.get('advisory', {}).get('cvss')
                                })
                        except json.JSONDecodeError:
                            pass
                            
        except Exception as e:
            print(f"   [!] Error running cargo-audit: {e}")
    else:
        print("   [!] cargo-audit not found, skipping Rust dependency audit")
        
    # Check Cargo.lock for git dependencies (supply chain risk)
    cargo_lock = "rust_core/Cargo.lock"
    if os.path.exists(cargo_lock):
        try:
            with open(cargo_lock, 'r') as f:
                content = f.read()
                
                if 'git+' in content:
                    rust_vulns.append({
                        "file": cargo_lock,
                        "type": "GIT_DEPENDENCY",
                        "severity": "MEDIUM",
                        "details": "Git dependencies found in Cargo.lock (supply chain risk)",
                        "cvss_score": 5.3
                    })
                    
        except Exception as e:
            print(f"   [!] Error reading Cargo.lock: {e}")
            
    results["vulnerabilities"].extend(rust_vulns)
    results["tests_performed"].append({
        "test": "Rust Dependency Analysis",
        "issues_found": len(rust_vulns)
    })
    
    print(f"   Found {len(rust_vulns)} Rust dependency issues")


def analyze_npm_dependencies():
    """Analyze NPM dependencies if present"""
    print("[*] Analyzing NPM dependencies...")
    
    npm_vulns = []
    
    if os.path.exists("package.json"):
        try:
            # Run npm audit
            print("   Running npm audit...")
            audit_result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True
            )
            
            if audit_result.stdout:
                audit_data = json.loads(audit_result.stdout)
                
                for vuln_id, vuln_info in audit_data.get('vulnerabilities', {}).items():
                    npm_vulns.append({
                        "package": vuln_info.get('name'),
                        "vulnerability_id": vuln_id,
                        "type": "NPM_VULNERABILITY",
                        "severity": vuln_info.get('severity', 'unknown').upper(),
                        "details": vuln_info.get('title', 'No description'),
                        "cvss_score": vuln_info.get('cvss', {}).get('score')
                    })
                    
        except Exception as e:
            print(f"   [!] Error running npm audit: {e}")
            
    else:
        print("   No package.json found, skipping NPM audit")
        
    results["vulnerabilities"].extend(npm_vulns)
    results["tests_performed"].append({
        "test": "NPM Dependency Analysis",
        "issues_found": len(npm_vulns)
    })
    
    print(f"   Found {len(npm_vulns)} NPM dependency issues")


def check_dependency_confusion():
    """Check for dependency confusion attacks"""
    print("[*] Checking for dependency confusion risks...")
    
    confusion_risks = []
    
    # Check for internal package names that might be hijacked
    internal_prefixes = ["claude", "code", "mcp", "circle_of_experts"]
    
    requirements_files = ["requirements.txt", "requirements-dev.txt", "requirements-fixed.txt"]
    
    for req_file in requirements_files:
        if os.path.exists(req_file):
            try:
                with open(req_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            pkg_name = line.split('==')[0].split('>=')[0].split('<')[0].strip()
                            
                            # Check if it looks like an internal package
                            for prefix in internal_prefixes:
                                if pkg_name.startswith(prefix):
                                    confusion_risks.append({
                                        "package": pkg_name,
                                        "file": req_file,
                                        "type": "DEPENDENCY_CONFUSION_RISK",
                                        "severity": "HIGH",
                                        "details": f"Internal-looking package name could be hijacked on PyPI",
                                        "cvss_score": 7.5
                                    })
                                    
            except Exception as e:
                print(f"   [!] Error reading {req_file}: {e}")
                
    results["vulnerabilities"].extend(confusion_risks)
    results["tests_performed"].append({
        "test": "Dependency Confusion Check",
        "issues_found": len(confusion_risks)
    })
    
    print(f"   Found {len(confusion_risks)} dependency confusion risks")


def analyze_supply_chain_integrity():
    """Analyze overall supply chain integrity"""
    print("[*] Analyzing supply chain integrity...")
    
    integrity_issues = []
    
    # Check for package pinning
    requirements_files = ["requirements.txt", "requirements-dev.txt"]
    unpinned_packages = 0
    
    for req_file in requirements_files:
        if os.path.exists(req_file):
            try:
                with open(req_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Check if version is pinned
                            if '==' not in line and '>=' in line or '<' in line:
                                unpinned_packages += 1
                                
            except Exception:
                pass
                
    if unpinned_packages > 5:
        integrity_issues.append({
            "type": "UNPINNED_DEPENDENCIES",
            "severity": "MEDIUM",
            "details": f"{unpinned_packages} packages not pinned to specific versions",
            "cvss_score": 5.3
        })
        
    # Check for suspicious package sources
    if os.path.exists("requirements.txt"):
        try:
            with open("requirements.txt", 'r') as f:
                content = f.read()
                
                # Check for non-PyPI sources
                if 'git+' in content or 'http://' in content:
                    integrity_issues.append({
                        "file": "requirements.txt",
                        "type": "NON_PYPI_SOURCE",
                        "severity": "HIGH",
                        "details": "Dependencies from non-PyPI sources detected",
                        "cvss_score": 7.5
                    })
                    
        except Exception:
            pass
            
    # Check for package verification
    pip_conf_exists = os.path.exists(os.path.expanduser("~/.pip/pip.conf"))
    if not pip_conf_exists:
        integrity_issues.append({
            "type": "MISSING_PACKAGE_VERIFICATION",
            "severity": "MEDIUM",
            "details": "No pip configuration for package verification found",
            "cvss_score": 5.3
        })
        
    results["vulnerabilities"].extend(integrity_issues)
    results["tests_performed"].append({
        "test": "Supply Chain Integrity Analysis",
        "issues_found": len(integrity_issues)
    })
    
    print(f"   Found {len(integrity_issues)} supply chain integrity issues")


def generate_supply_chain_summary():
    """Generate supply chain security summary"""
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
    
    for vuln in results["vulnerabilities"]:
        severity = vuln.get("severity", "unknown").lower()
        if severity in summary:
            summary[severity] += 1
            
    results["summary"] = summary
    results["total_vulnerabilities"] = len(results["vulnerabilities"])
    
    # Save results
    with open("security_audit_phase4_results.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print("\n" + "="*60)
    print("PHASE 4 SUPPLY CHAIN SECURITY SUMMARY")
    print("="*60)
    print(f"Critical: {summary['critical']}")
    print(f"High: {summary['high']}")
    print(f"Medium: {summary['medium']}")
    print(f"Low: {summary['low']}")
    print(f"Total: {len(results['vulnerabilities'])}")
    print("\nDetailed results saved to: security_audit_phase4_results.json")


if __name__ == "__main__":
    print("\nAGENT 7: PHASE 4 SUPPLY CHAIN SECURITY ASSESSMENT")
    print("="*60 + "\n")
    
    analyze_python_dependencies()
    analyze_rust_dependencies()
    analyze_npm_dependencies()
    check_dependency_confusion()
    analyze_supply_chain_integrity()
    generate_supply_chain_summary()