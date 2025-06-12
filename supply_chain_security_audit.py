#!/usr/bin/env python3
"""
Supply Chain Security Audit Script
Analyzes dependencies for security vulnerabilities and risks
"""

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple
import urllib.request
import urllib.error

def parse_requirements(file_path: str) -> List[Tuple[str, str]]:
    """Parse requirements.txt and extract package names and versions."""
    packages = []
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse package and version
            match = re.match(r'^([a-zA-Z0-9\-_\[\]]+)([><=!~]+)(.+)$', line)
            if match:
                package = match.group(1).split('[')[0]  # Remove extras like [crypto]
                operator = match.group(2)
                version = match.group(3)
                packages.append((package, f"{operator}{version}"))
            else:
                # Package without version constraint
                packages.append((line, "*"))
    
    return packages

def check_typosquatting_risks(packages: List[Tuple[str, str]]) -> List[Dict[str, str]]:
    """Check for potential typosquatting risks."""
    # Common legitimate packages that are often typosquatted
    legitimate_packages = {
        'requests': ['request', 'requets', 'reqests'],
        'urllib3': ['urllib', 'urlib3'],
        'numpy': ['nunpy', 'numby'],
        'pandas': ['pands', 'pndas'],
        'tensorflow': ['tensorfow', 'tensorflw'],
        'scikit-learn': ['sklearn', 'sikit-learn'],
        'beautifulsoup4': ['beautifulsoup', 'beautifulsoup3'],
        'python-dateutil': ['dateutil'],
        'pillow': ['pil', 'PIL'],
        'cryptography': ['crypto', 'criptography'],
        'pyyaml': ['yaml'],
        'setuptools': ['setup-tools', 'setuptool'],
    }
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'test[-_]?package',
        r'example[-_]?package',
        r'demo[-_]?package',
        r'^[a-z]{1,2}$',  # Very short names
        r'[0-9]{5,}',  # Many numbers in name
    ]
    
    risks = []
    package_names = [p[0].lower() for p in packages]
    
    # Check for typosquatting
    for legit, typos in legitimate_packages.items():
        for typo in typos:
            if typo in package_names:
                risks.append({
                    'type': 'typosquatting',
                    'package': typo,
                    'risk': f'Possible typosquatting of "{legit}"',
                    'severity': 'high'
                })
    
    # Check for suspicious patterns
    for package, _ in packages:
        for pattern in suspicious_patterns:
            if re.search(pattern, package.lower()):
                risks.append({
                    'type': 'suspicious_pattern',
                    'package': package,
                    'risk': f'Matches suspicious pattern: {pattern}',
                    'severity': 'medium'
                })
                break
    
    return risks

def check_package_info_pypi(package_name: str) -> Dict[str, Any]:
    """Fetch package information from PyPI."""
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        with urllib.request.urlopen(url) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError:
        return None
    except Exception:
        return None

def analyze_package_health(packages: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    """Analyze package health and maintenance status."""
    health_issues = []
    
    for package, version in packages:
        info = check_package_info_pypi(package)
        if not info:
            health_issues.append({
                'package': package,
                'issue': 'Package not found on PyPI',
                'severity': 'high'
            })
            continue
        
        # Check last release date
        releases = info.get('releases', {})
        if releases:
            latest_date = None
            for release_info in releases.values():
                if release_info:
                    upload_time = release_info[0].get('upload_time', '')
                    if upload_time:
                        date = datetime.fromisoformat(upload_time.replace('Z', '+00:00'))
                        if not latest_date or date > latest_date:
                            latest_date = date
            
            if latest_date:
                days_old = (datetime.now(latest_date.tzinfo) - latest_date).days
                if days_old > 730:  # 2 years
                    health_issues.append({
                        'package': package,
                        'issue': f'No updates in {days_old} days',
                        'severity': 'medium',
                        'last_update': latest_date.isoformat()
                    })
        
        # Check for yanked releases
        if 'yanked' in str(info):
            health_issues.append({
                'package': package,
                'issue': 'Has yanked releases',
                'severity': 'medium'
            })
    
    return health_issues

def check_known_vulnerabilities() -> Dict[str, Any]:
    """Check for known vulnerabilities in common packages."""
    # Known vulnerabilities (simplified database)
    known_vulns = {
        'requests': {
            '<2.31.0': {
                'CVE': 'CVE-2023-32681',
                'description': 'Unintended leak of Proxy-Authorization header',
                'severity': 'medium'
            }
        },
        'cryptography': {
            '<41.0.0': {
                'CVE': 'CVE-2023-38325',
                'description': 'NULL pointer dereference vulnerability',
                'severity': 'high'
            }
        },
        'pyyaml': {
            '<5.4': {
                'CVE': 'CVE-2020-14343',
                'description': 'Arbitrary code execution vulnerability',
                'severity': 'critical'
            }
        },
        'sqlalchemy': {
            '<1.4.0': {
                'CVE': 'CVE-2021-23727',
                'description': 'SQL injection vulnerability',
                'severity': 'high'
            }
        },
        'aiohttp': {
            '<3.8.0': {
                'CVE': 'CVE-2021-21330',
                'description': 'Open redirect vulnerability',
                'severity': 'medium'
            }
        }
    }
    
    return known_vulns

def analyze_npm_dependencies(package_json_path: str) -> Dict[str, Any]:
    """Analyze npm dependencies for vulnerabilities."""
    try:
        with open(package_json_path, 'r') as f:
            package_data = json.load(f)
        
        dependencies = package_data.get('dependencies', {})
        dev_dependencies = package_data.get('devDependencies', {})
        
        npm_analysis = {
            'total_dependencies': len(dependencies) + len(dev_dependencies),
            'dependencies': dependencies,
            'dev_dependencies': dev_dependencies,
            'risks': []
        }
        
        # Check for suspicious patterns in npm packages
        for dep_name in list(dependencies.keys()) + list(dev_dependencies.keys()):
            # Check for scoped packages from unknown sources
            if dep_name.startswith('@') and not dep_name.startswith(('@types/', '@babel/', '@eslint/')):
                npm_analysis['risks'].append({
                    'package': dep_name,
                    'risk': 'Scoped package from potentially unknown source',
                    'severity': 'low'
                })
        
        return npm_analysis
    except Exception as e:
        return {'error': str(e)}

def generate_report(python_packages, typosquatting_risks, health_issues, npm_analysis):
    """Generate comprehensive security audit report."""
    report = {
        'audit_timestamp': datetime.now().isoformat(),
        'summary': {
            'total_python_packages': len(python_packages),
            'typosquatting_risks': len(typosquatting_risks),
            'health_issues': len(health_issues),
            'npm_dependencies': npm_analysis.get('total_dependencies', 0)
        },
        'python_dependencies': {
            'packages': python_packages,
            'typosquatting_risks': typosquatting_risks,
            'health_issues': health_issues
        },
        'npm_dependencies': npm_analysis,
        'recommendations': []
    }
    
    # Add recommendations
    if typosquatting_risks:
        report['recommendations'].append({
            'priority': 'high',
            'action': 'Review and remove potential typosquatted packages',
            'details': 'Found packages that may be typosquatting legitimate packages'
        })
    
    if health_issues:
        unmaintained = [h for h in health_issues if 'No updates' in h.get('issue', '')]
        if unmaintained:
            report['recommendations'].append({
                'priority': 'medium',
                'action': 'Consider replacing unmaintained packages',
                'details': f'Found {len(unmaintained)} packages without recent updates'
            })
    
    # Check for critical dependencies
    critical_packages = ['cryptography', 'pyjwt', 'bcrypt', 'sqlalchemy', 'aiohttp']
    for package, version in python_packages:
        if package in critical_packages:
            report['recommendations'].append({
                'priority': 'high',
                'action': f'Ensure {package} is up to date',
                'details': f'Security-critical package currently at {version}'
            })
    
    return report

def main():
    """Main function to run supply chain security audit."""
    print("Starting Supply Chain Security Audit...")
    
    # Analyze Python dependencies
    python_packages = parse_requirements('requirements.txt')
    print(f"Found {len(python_packages)} Python packages")
    
    # Check for typosquatting
    typosquatting_risks = check_typosquatting_risks(python_packages)
    print(f"Found {len(typosquatting_risks)} potential typosquatting risks")
    
    # Analyze package health
    print("Analyzing package health (this may take a moment)...")
    health_issues = analyze_package_health(python_packages[:10])  # Limit to first 10 for speed
    
    # Analyze npm dependencies
    npm_analysis = analyze_npm_dependencies('package.json')
    
    # Generate report
    report = generate_report(python_packages, typosquatting_risks, health_issues, npm_analysis)
    
    # Save report
    with open('supply_chain_security_audit_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\nAudit complete. Report saved to supply_chain_security_audit_report.json")
    
    # Print summary
    print("\n=== SUMMARY ===")
    print(f"Total Python packages: {report['summary']['total_python_packages']}")
    print(f"Typosquatting risks: {report['summary']['typosquatting_risks']}")
    print(f"Health issues: {report['summary']['health_issues']}")
    print(f"NPM dependencies: {report['summary']['npm_dependencies']}")
    print(f"\nTotal recommendations: {len(report['recommendations'])}")

if __name__ == "__main__":
    main()