#!/usr/bin/env python3
"""
AGENT 7: Phase 3 Infrastructure Security Assessment
Tests container security, secrets management, logging, and deployment configurations
"""

import os
import sys
import json
import yaml
from datetime import datetime
from pathlib import Path

results = {
    "audit_timestamp": datetime.now().isoformat(),
    "phase": "Phase 3: Infrastructure Security Assessment",
    "vulnerabilities": [],
    "tests_performed": []
}

def test_docker_security():
    """Test Docker configuration security"""
    print("[*] Testing Docker security...")
    
    docker_issues = []
    
    # Check Dockerfiles
    dockerfiles = []
    for root, dirs, files in os.walk("."):
        for file in files:
            if file == "Dockerfile" or file.endswith(".dockerfile"):
                dockerfiles.append(os.path.join(root, file))
                
    for dockerfile in dockerfiles:
        try:
            with open(dockerfile, 'r') as f:
                content = f.read()
                
                # Check for running as root
                if 'USER root' in content or not 'USER ' in content:
                    docker_issues.append({
                        "file": dockerfile,
                        "type": "DOCKER_ROOT_USER",
                        "severity": "HIGH",
                        "details": "Container runs as root user",
                        "cvss_score": 7.5
                    })
                    
                # Check for hardcoded secrets
                if 'ENV' in content and any(x in content for x in ['password = os.environ.get("PASSWORD", "test-password-placeholder")api_key = os.environ.get("API_KEY", "test-key-placeholder")SECRET=']):
                    docker_issues.append({
                        "file": dockerfile,
                        "type": "DOCKER_HARDCODED_SECRET",
                        "severity": "CRITICAL",
                        "details": "Hardcoded secrets in Dockerfile",
                        "cvss_score": 9.8
                    })
                    
                # Check for --privileged
                if '--privileged' in content:
                    docker_issues.append({
                        "file": dockerfile,
                        "type": "DOCKER_PRIVILEGED",
                        "severity": "CRITICAL",
                        "details": "Container runs in privileged mode",
                        "cvss_score": 9.8
                    })
                    
        except Exception as e:
            print(f"   [!] Error reading {dockerfile}: {e}")
            
    # Check docker-compose files
    compose_files = []
    for root, dirs, files in os.walk("."):
        for file in files:
            if file.startswith("docker-compose") and file.endswith((".yml", ".yaml")):
                compose_files.append(os.path.join(root, file))
                
    for compose_file in compose_files:
        try:
            with open(compose_file, 'r') as f:
                content = yaml.safe_load(f)
                
                if content and 'services' in content:
                    for service, config in content['services'].items():
                        # Check for privileged mode
                        if config.get('privileged', False):
                            docker_issues.append({
                                "file": compose_file,
                                "type": "DOCKER_COMPOSE_PRIVILEGED",
                                "severity": "CRITICAL",
                                "details": f"Service '{service}' runs in privileged mode",
                                "cvss_score": 9.8
                            })
                            
                        # Check for host network mode
                        if config.get('network_mode') == 'host':
                            docker_issues.append({
                                "file": compose_file,
                                "type": "DOCKER_HOST_NETWORK",
                                "severity": "HIGH",
                                "details": f"Service '{service}' uses host network",
                                "cvss_score": 7.5
                            })
                            
                        # Check for exposed secrets
                        if 'environment' in config:
                            for env in config['environment']:
                                if isinstance(env, str) and any(x in env for x in ['password = os.environ.get("PASSWORD", "test-password-placeholder")SECRET=', 'KEY=']):
                                    docker_issues.append({
                                        "file": compose_file,
                                        "type": "DOCKER_COMPOSE_SECRET",
                                        "severity": "CRITICAL",
                                        "details": f"Hardcoded secret in service '{service}'",
                                        "cvss_score": 9.8
                                    })
                                    
        except Exception as e:
            print(f"   [!] Error reading {compose_file}: {e}")
            
    results["vulnerabilities"].extend(docker_issues)
    results["tests_performed"].append({
        "test": "Docker Security Assessment",
        "files_checked": len(dockerfiles) + len(compose_files),
        "issues_found": len(docker_issues)
    })
    
    print(f"   Found {len(docker_issues)} Docker security issues")


def test_kubernetes_security():
    """Test Kubernetes configuration security"""
    print("[*] Testing Kubernetes security...")
    
    k8s_issues = []
    k8s_files = []
    
    # Find Kubernetes YAML files
    k8s_dir = "k8s"
    if os.path.exists(k8s_dir):
        for root, dirs, files in os.walk(k8s_dir):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    k8s_files.append(os.path.join(root, file))
                    
    for k8s_file in k8s_files:
        try:
            with open(k8s_file, 'r') as f:
                content = yaml.safe_load(f)
                
                if not content:
                    continue
                    
                # Check for security contexts
                if 'spec' in content:
                    spec = content['spec']
                    
                    # Check containers
                    containers = []
                    if 'containers' in spec:
                        containers = spec['containers']
                    elif 'template' in spec and 'spec' in spec['template']:
                        containers = spec['template']['spec'].get('containers', [])
                        
                    for container in containers:
                        # Check for privileged containers
                        sec_context = container.get('securityContext', {})
                        if sec_context.get('privileged', False):
                            k8s_issues.append({
                                "file": k8s_file,
                                "type": "K8S_PRIVILEGED_CONTAINER",
                                "severity": "CRITICAL",
                                "details": f"Container runs in privileged mode",
                                "cvss_score": 9.8
                            })
                            
                        # Check for runAsRoot
                        if sec_context.get('runAsUser') == 0:
                            k8s_issues.append({
                                "file": k8s_file,
                                "type": "K8S_RUN_AS_ROOT",
                                "severity": "HIGH",
                                "details": "Container runs as root (UID 0)",
                                "cvss_score": 7.5
                            })
                            
                        # Check for capabilities
                        if 'capabilities' in sec_context:
                            caps = sec_context['capabilities'].get('add', [])
                            if 'ALL' in caps or 'SYS_ADMIN' in caps:
                                k8s_issues.append({
                                    "file": k8s_file,
                                    "type": "K8S_DANGEROUS_CAPABILITIES",
                                    "severity": "HIGH",
                                    "details": f"Dangerous capabilities: {caps}",
                                    "cvss_score": 7.5
                                })
                                
                # Check for exposed secrets
                if content.get('kind') == 'Secret' and content.get('type') != 'Opaque':
                    k8s_issues.append({
                        "file": k8s_file,
                        "type": "K8S_UNENCRYPTED_SECRET",
                        "severity": "HIGH",
                        "details": "Secret not using Opaque type",
                        "cvss_score": 7.5
                    })
                    
        except Exception as e:
            print(f"   [!] Error reading {k8s_file}: {e}")
            
    results["vulnerabilities"].extend(k8s_issues)
    results["tests_performed"].append({
        "test": "Kubernetes Security Assessment",
        "files_checked": len(k8s_files),
        "issues_found": len(k8s_issues)
    })
    
    print(f"   Found {len(k8s_issues)} Kubernetes security issues")


def test_secrets_management():
    """Test secrets management security"""
    print("[*] Testing secrets management...")
    
    secrets_issues = []
    
    # Check for .env files
    env_files = []
    for root, dirs, files in os.walk("."):
        # Skip venv directories
        if 'venv' in root:
            continue
            
        for file in files:
            if file.startswith('.env'):
                env_files.append(os.path.join(root, file))
                
    for env_file in env_files:
        # Check if .env file is in git
        git_check = os.popen(f"git ls-files {env_file} 2>/dev/null").read().strip()
        if git_check:
            secrets_issues.append({
                "file": env_file,
                "type": "SECRETS_IN_GIT",
                "severity": "CRITICAL",
                "details": ".env file tracked in git",
                "cvss_score": 9.8
            })
            
    # Check for exposed API keys patterns
    api_key_patterns = [
        "AKIA[0-9A-Z]{16}",  # AWS
        "AIza[0-9A-Za-z\\-_]{35}",  # Google
        "sk_live_[0-9a-zA-Z]{24}",  # Stripe
        "rk_live_[0-9a-zA-Z]{24}"   # Stripe
    ]
    
    for root, dirs, files in os.walk("src"):
        for file in files:
            if file.endswith((".py", ".yml", ".yaml", ".json")):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        
                        import re
                        for pattern in api_key_patterns:
                            if re.search(pattern, content):
                                secrets_issues.append({
                                    "file": filepath,
                                    "type": "EXPOSED_API_KEY",
                                    "severity": "CRITICAL",
                                    "details": "Potential API key exposed",
                                    "cvss_score": 9.8
                                })
                                break
                                
                except Exception:
                    pass
                    
    results["vulnerabilities"].extend(secrets_issues)
    results["tests_performed"].append({
        "test": "Secrets Management Assessment",
        "issues_found": len(secrets_issues)
    })
    
    print(f"   Found {len(secrets_issues)} secrets management issues")


def test_logging_security():
    """Test logging and monitoring security"""
    print("[*] Testing logging security...")
    
    logging_issues = []
    
    # Check logging configuration
    logging_files = [
        "src/core/logging_config.py",
        "monitoring/prometheus.yml",
        "monitoring/alertmanager.yml"
    ]
    
    for log_file in logging_files:
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    content = f.read()
                    
                    # Check for sensitive data in logs
                    if any(x in content.lower() for x in ['password', 'secret', 'token', 'api_key']):
                        logging_issues.append({
                            "file": log_file,
                            "type": "LOGGING_SENSITIVE_DATA",
                            "severity": "HIGH",
                            "details": "Potential sensitive data logging",
                            "cvss_score": 7.5
                        })
                        
                    # Check for debug mode in production
                    if 'DEBUG' in content and 'True' in content:
                        logging_issues.append({
                            "file": log_file,
                            "type": "DEBUG_MODE_ENABLED",
                            "severity": "MEDIUM",
                            "details": "Debug mode may be enabled",
                            "cvss_score": 5.3
                        })
                        
            except Exception as e:
                print(f"   [!] Error reading {log_file}: {e}")
                
    # Check for log injection prevention
    log_sanitization = "src/core/log_sanitization.py"
    if not os.path.exists(log_sanitization):
        logging_issues.append({
            "file": "src/core/",
            "type": "MISSING_LOG_SANITIZATION",
            "severity": "MEDIUM",
            "details": "Log sanitization module not found",
            "cvss_score": 5.3
        })
        
    results["vulnerabilities"].extend(logging_issues)
    results["tests_performed"].append({
        "test": "Logging Security Assessment",
        "issues_found": len(logging_issues)
    })
    
    print(f"   Found {len(logging_issues)} logging security issues")


def test_api_security():
    """Test API security configurations"""
    print("[*] Testing API security...")
    
    api_issues = []
    
    # Check for rate limiting
    rate_limit_found = False
    for root, dirs, files in os.walk("src"):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r') as f:
                        if 'rate_limit' in f.read() or 'RateLimit' in f.read():
                            rate_limit_found = True
                            break
                except Exception:
                    pass
                    
    if not rate_limit_found:
        api_issues.append({
            "file": "src/api/",
            "type": "MISSING_RATE_LIMITING",
            "severity": "HIGH",
            "details": "No rate limiting implementation found",
            "cvss_score": 7.5
        })
        
    # Check for API versioning
    api_version_found = False
    api_files = ["src/api/", "api_docs/"]
    for api_dir in api_files:
        if os.path.exists(api_dir):
            for file in os.listdir(api_dir):
                if 'v1' in file or 'version' in file:
                    api_version_found = True
                    break
                    
    if not api_version_found:
        api_issues.append({
            "file": "src/api/",
            "type": "MISSING_API_VERSIONING",
            "severity": "MEDIUM",
            "details": "No API versioning implementation found",
            "cvss_score": 5.3
        })
        
    results["vulnerabilities"].extend(api_issues)
    results["tests_performed"].append({
        "test": "API Security Assessment",
        "issues_found": len(api_issues)
    })
    
    print(f"   Found {len(api_issues)} API security issues")


def generate_infrastructure_summary():
    """Generate infrastructure security summary"""
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
    with open("security_audit_phase3_results.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print("\n" + "="*60)
    print("PHASE 3 INFRASTRUCTURE SECURITY SUMMARY")
    print("="*60)
    print(f"Critical: {summary['critical']}")
    print(f"High: {summary['high']}")
    print(f"Medium: {summary['medium']}")
    print(f"Low: {summary['low']}")
    print(f"Total: {len(results['vulnerabilities'])}")
    print("\nDetailed results saved to: security_audit_phase3_results.json")


if __name__ == "__main__":
    print("\nAGENT 7: PHASE 3 INFRASTRUCTURE SECURITY ASSESSMENT")
    print("="*60 + "\n")
    
    test_docker_security()
    test_kubernetes_security()
    test_secrets_management()
    test_logging_security()
    test_api_security()
    generate_infrastructure_summary()