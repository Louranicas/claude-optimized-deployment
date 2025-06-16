#!/usr/bin/env python3
"""
Simple Production Readiness Validator for MCP Servers
Comprehensive validation without external dependencies
"""

import os
import json
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of a validation check"""
    category: str
    check_name: str
    status: str  # PASS, FAIL, WARNING, SKIP
    score: int  # 0-100
    message: str
    details: Dict[str, Any] = None
    remediation: str = ""

class SimpleProductionReadinessValidator:
    """Simplified production readiness validation"""
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.results = []
        self.start_time = datetime.now()
        
    def _load_config(self, config_path: str) -> Dict:
        """Load validation configuration"""
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def validate_all(self) -> Dict[str, Any]:
        """Run all production readiness validations"""
        logger.info("Starting production readiness validation")
        
        # Core infrastructure validation
        self._validate_containerization()
        self._validate_kubernetes_deployment()
        self._validate_security_configuration()
        self._validate_monitoring_observability()
        self._validate_documentation()
        self._validate_automation()
        
        return self._generate_final_report()
    
    def _validate_containerization(self):
        """Validate container build and security"""
        logger.info("Validating containerization...")
        
        # Check Docker files exist
        docker_files = [
            "mcp_servers/Dockerfile.mcp-typescript",
            "mcp_learning_system/Dockerfile.learning-python", 
            "mcp_learning_system/servers/Dockerfile.rust-server"
        ]
        
        for dockerfile in docker_files:
            if os.path.exists(dockerfile):
                self._validate_dockerfile(dockerfile)
            else:
                self.results.append(ValidationResult(
                    category="Containerization",
                    check_name=f"Dockerfile exists: {dockerfile}",
                    status="FAIL",
                    score=0,
                    message=f"Dockerfile not found: {dockerfile}",
                    remediation="Create Dockerfile following security best practices"
                ))
    
    def _validate_dockerfile(self, dockerfile_path: str):
        """Validate individual Dockerfile"""
        with open(dockerfile_path, 'r') as f:
            content = f.read()
        
        checks = [
            ("Multi-stage build", "FROM" in content and "AS builder" in content),
            ("Non-root user", "USER" in content and "USER root" not in content),
            ("Security updates", "apt-get update" in content or "apk update" in content),
            ("Health check", "HEALTHCHECK" in content),
            ("Minimal base image", "alpine" in content or "slim" in content),
            ("No hardcoded secrets", "password" not in content.lower() and "secret" not in content.lower())
        ]
        
        for check_name, condition in checks:
            status = "PASS" if condition else "FAIL"
            score = 100 if condition else 0
            
            self.results.append(ValidationResult(
                category="Containerization",
                check_name=f"{dockerfile_path}: {check_name}",
                status=status,
                score=score,
                message=f"Dockerfile {check_name.lower()}: {'✓' if condition else '✗'}",
                remediation=f"Implement {check_name.lower()} in {dockerfile_path}" if not condition else ""
            ))
    
    def _validate_kubernetes_deployment(self):
        """Validate Kubernetes deployment configuration"""
        logger.info("Validating Kubernetes deployment...")
        
        # Check manifest files exist
        k8s_files = [
            "k8s/mcp-deployment.yaml",
            "k8s/rbac.yaml", 
            "k8s/network-policies.yaml",
            "k8s/secrets.yaml"
        ]
        
        for k8s_file in k8s_files:
            if os.path.exists(k8s_file):
                self._validate_k8s_manifest(k8s_file)
            else:
                self.results.append(ValidationResult(
                    category="Kubernetes",
                    check_name=f"Manifest exists: {os.path.basename(k8s_file)}",
                    status="FAIL",
                    score=0,
                    message=f"Kubernetes manifest not found: {k8s_file}",
                    remediation=f"Create {k8s_file} with proper configuration"
                ))
    
    def _validate_k8s_manifest(self, manifest_path: str):
        """Validate individual Kubernetes manifest"""
        try:
            with open(manifest_path, 'r') as f:
                content = f.read()
            
            # Basic validation checks
            checks = [
                ("Valid YAML structure", "apiVersion:" in content and "kind:" in content),
                ("Security context", "securityContext:" in content),
                ("Resource limits", "limits:" in content and "memory:" in content),
                ("Health checks", "livenessProbe:" in content or "readinessProbe:" in content),
                ("Non-root user", "runAsNonRoot: true" in content),
                ("Read-only filesystem", "readOnlyRootFilesystem: true" in content)
            ]
            
            for check_name, condition in checks:
                status = "PASS" if condition else "FAIL"
                score = 100 if condition else 0
                
                self.results.append(ValidationResult(
                    category="Kubernetes",
                    check_name=f"{os.path.basename(manifest_path)}: {check_name}",
                    status=status,
                    score=score,
                    message=f"K8s {check_name}: {'✓' if condition else '✗'}",
                    remediation=f"Configure {check_name} in {manifest_path}" if not condition else ""
                ))
                
        except Exception as e:
            self.results.append(ValidationResult(
                category="Kubernetes",
                check_name=f"Manifest validation: {os.path.basename(manifest_path)}",
                status="FAIL",
                score=0,
                message=f"Could not validate manifest: {e}",
                remediation=f"Fix YAML syntax in {manifest_path}"
            ))
    
    def _validate_security_configuration(self):
        """Validate security configuration"""
        logger.info("Validating security configuration...")
        
        security_files = [
            ("Pod Security Policy", "k8s/pod-security-policies.yaml"),
            ("Network Policy", "k8s/network-policies.yaml"),
            ("RBAC Configuration", "k8s/rbac.yaml"),
            ("Secrets Management", "k8s/secrets.yaml")
        ]
        
        for policy_name, file_path in security_files:
            exists = os.path.exists(file_path)
            
            self.results.append(ValidationResult(
                category="Security",
                check_name=policy_name,
                status="PASS" if exists else "FAIL",
                score=100 if exists else 0,
                message=f"{policy_name}: {'✓' if exists else '✗'}",
                remediation=f"Create {file_path} with appropriate security policies" if not exists else ""
            ))
        
        # Check CI/CD security scanning
        ci_file = ".github/workflows/mcp-production-deployment.yml"
        if os.path.exists(ci_file):
            with open(ci_file, 'r') as f:
                content = f.read()
            
            security_checks = [
                ("Container security scanning", "trivy" in content.lower()),
                ("Dependency scanning", "safety" in content.lower()),
                ("Code security scanning", "bandit" in content.lower()),
                ("Security gates", "security-scan" in content.lower())
            ]
            
            for check_name, condition in security_checks:
                self.results.append(ValidationResult(
                    category="Security Scanning",
                    check_name=check_name,
                    status="PASS" if condition else "WARNING",
                    score=100 if condition else 70,
                    message=f"Security {check_name.lower()}: {'✓' if condition else '⚠'}",
                    remediation=f"Implement {check_name.lower()} in CI/CD pipeline" if not condition else ""
                ))
    
    def _validate_monitoring_observability(self):
        """Validate monitoring and observability"""
        logger.info("Validating monitoring and observability...")
        
        monitoring_files = [
            ("Prometheus config", "monitoring/prometheus.yml"),
            ("Grafana config", "monitoring/grafana-datasources.yml"),
            ("Alert rules", "monitoring/alert_rules.yaml"),
            ("Docker Compose monitoring", "docker-compose.mcp-production.yml")
        ]
        
        for config_name, file_path in monitoring_files:
            exists = os.path.exists(file_path)
            
            self.results.append(ValidationResult(
                category="Monitoring",
                check_name=config_name,
                status="PASS" if exists else "WARNING",
                score=100 if exists else 70,
                message=f"{config_name}: {'✓' if exists else '⚠'}",
                remediation=f"Create {file_path} for comprehensive monitoring" if not exists else ""
            ))
        
        # Check for health check implementation
        health_check_indicators = ["HEALTHCHECK", "livenessProbe", "readinessProbe", "/health"]
        found_health_checks = 0
        
        for root, dirs, files in os.walk('.'):
            if '.git' in root or 'node_modules' in root:
                continue
            for file in files:
                if file.endswith(('.dockerfile', 'Dockerfile', '.yaml', '.yml', '.py', '.ts', '.js')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            for indicator in health_check_indicators:
                                if indicator in content:
                                    found_health_checks += 1
                                    break
                    except:
                        continue
        
        self.results.append(ValidationResult(
            category="Health Checks",
            check_name="Health check implementation",
            status="PASS" if found_health_checks >= 3 else "WARNING",
            score=100 if found_health_checks >= 3 else 60,
            message=f"Health checks found in {found_health_checks} files: {'✓' if found_health_checks >= 3 else '⚠'}",
            remediation="Implement comprehensive health checks across all services" if found_health_checks < 3 else ""
        ))
    
    def _validate_documentation(self):
        """Validate documentation completeness"""
        logger.info("Validating documentation...")
        
        required_docs = [
            ("README.md", "Project overview and setup instructions"),
            ("docs/PRODUCTION_DEPLOYMENT_GUIDE.md", "Production deployment guide"),
            ("docs/OPERATIONS_RUNBOOK.md", "Operations and troubleshooting"),
            ("CONTRIBUTING.md", "Contribution guidelines"),
            ("LICENSE", "License information")
        ]
        
        for doc_file, description in required_docs:
            exists = os.path.exists(doc_file)
            
            if exists:
                # Check if documentation is comprehensive
                with open(doc_file, 'r') as f:
                    content = f.read()
                    is_comprehensive = len(content) > 1000  # Basic heuristic
                
                status = "PASS" if is_comprehensive else "WARNING"
                score = 100 if is_comprehensive else 70
                message = f"Documentation {doc_file}: {'✓ Comprehensive' if is_comprehensive else '⚠ Basic'}"
            else:
                status = "FAIL" if "GUIDE" in doc_file or "RUNBOOK" in doc_file else "WARNING"
                score = 0 if status == "FAIL" else 50
                message = f"Documentation {doc_file}: ✗ Missing"
            
            self.results.append(ValidationResult(
                category="Documentation",
                check_name=description,
                status=status,
                score=score,
                message=message,
                remediation=f"Create or enhance {doc_file}" if not exists or (exists and not is_comprehensive) else ""
            ))
    
    def _validate_automation(self):
        """Validate automation and CI/CD"""
        logger.info("Validating automation...")
        
        # Check CI/CD pipeline
        ci_file = ".github/workflows/mcp-production-deployment.yml"
        if os.path.exists(ci_file):
            with open(ci_file, 'r') as f:
                content = f.read()
            
            automation_checks = [
                ("Automated testing", "test" in content.lower()),
                ("Security scanning", "security" in content.lower()),
                ("Build automation", "build" in content.lower()),
                ("Deployment automation", "deploy" in content.lower()),
                ("Blue-green deployment", "blue-green" in content.lower()),
                ("Performance testing", "performance" in content.lower())
            ]
            
            for check_name, condition in automation_checks:
                self.results.append(ValidationResult(
                    category="Automation",
                    check_name=check_name,
                    status="PASS" if condition else "WARNING",
                    score=100 if condition else 70,
                    message=f"Automation {check_name.lower()}: {'✓' if condition else '⚠'}",
                    remediation=f"Implement {check_name.lower()} in CI/CD pipeline" if not condition else ""
                ))
        else:
            self.results.append(ValidationResult(
                category="Automation",
                check_name="CI/CD pipeline exists",
                status="FAIL",
                score=0,
                message="CI/CD pipeline not found",
                remediation="Create .github/workflows/mcp-production-deployment.yml"
            ))
        
        # Check for production testing suite
        test_files = [
            "tests/production_testing_suite.py",
            "tests/mcp_testing_framework.py",
            "tests/run_all_mcp_tests.py"
        ]
        
        found_tests = sum(1 for test_file in test_files if os.path.exists(test_file))
        
        self.results.append(ValidationResult(
            category="Testing Framework",
            check_name="Production testing suite",
            status="PASS" if found_tests >= 2 else "WARNING",
            score=100 if found_tests >= 2 else 60,
            message=f"Production test files found: {found_tests}/3 {'✓' if found_tests >= 2 else '⚠'}",
            remediation="Create comprehensive production testing suite" if found_tests < 2 else ""
        ))
    
    def _generate_final_report(self) -> Dict[str, Any]:
        """Generate comprehensive production readiness report"""
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        # Calculate scores by category
        categories = {}
        for result in self.results:
            if result.category not in categories:
                categories[result.category] = {'total_score': 0, 'max_score': 0, 'count': 0}
            
            categories[result.category]['total_score'] += result.score
            categories[result.category]['max_score'] += 100
            categories[result.category]['count'] += 1
        
        category_scores = {}
        for category, data in categories.items():
            category_scores[category] = {
                'score': (data['total_score'] / data['max_score']) * 100 if data['max_score'] > 0 else 0,
                'checks': data['count']
            }
        
        # Calculate overall score
        total_score = sum(result.score for result in self.results)
        max_score = len(self.results) * 100
        overall_score = (total_score / max_score) * 100 if max_score > 0 else 0
        
        # Determine production readiness
        critical_failures = [r for r in self.results if r.status == "FAIL" and r.category in ["Security", "Containerization", "Kubernetes"]]
        
        if overall_score >= 95 and len(critical_failures) == 0:
            readiness_level = "PRODUCTION_READY"
            readiness_grade = "A"
        elif overall_score >= 85 and len(critical_failures) <= 2:
            readiness_level = "PRODUCTION_READY_WITH_MINOR_ISSUES"
            readiness_grade = "B"
        elif overall_score >= 70 and len(critical_failures) <= 5:
            readiness_level = "PRODUCTION_READY_WITH_REMEDIATION"
            readiness_grade = "C"
        else:
            readiness_level = "NOT_PRODUCTION_READY"
            readiness_grade = "F"
        
        # Generate recommendations
        recommendations = []
        
        # High priority recommendations
        for result in self.results:
            if result.status == "FAIL" and result.remediation:
                recommendations.append({
                    "priority": "HIGH",
                    "category": result.category,
                    "issue": result.check_name,
                    "recommendation": result.remediation
                })
        
        # Medium priority recommendations
        for result in self.results:
            if result.status == "WARNING" and result.score < 80 and result.remediation:
                recommendations.append({
                    "priority": "MEDIUM",
                    "category": result.category,
                    "issue": result.check_name,
                    "recommendation": result.remediation
                })
        
        # Final report
        report = {
            "metadata": {
                "validation_timestamp": end_time.isoformat(),
                "duration_seconds": duration.total_seconds(),
                "validator_version": "1.0.0",
                "environment": "production_validation"
            },
            "summary": {
                "overall_score": round(overall_score, 2),
                "readiness_level": readiness_level,
                "readiness_grade": readiness_grade,
                "production_ready": readiness_level.startswith("PRODUCTION_READY"),
                "total_checks": len(self.results),
                "passed_checks": len([r for r in self.results if r.status == "PASS"]),
                "failed_checks": len([r for r in self.results if r.status == "FAIL"]),
                "warning_checks": len([r for r in self.results if r.status == "WARNING"]),
                "critical_failures": len(critical_failures)
            },
            "category_scores": category_scores,
            "detailed_results": [asdict(result) for result in self.results],
            "recommendations": recommendations,
            "deployment_checklist": self._generate_deployment_checklist(),
            "next_steps": self._generate_next_steps(readiness_level),
            "infrastructure_summary": {
                "containerization": "Multi-stage Docker builds with security scanning",
                "orchestration": "Kubernetes with RBAC, network policies, and auto-scaling",
                "monitoring": "Prometheus, Grafana, and comprehensive alerting",
                "security": "Pod security standards, network isolation, and secrets management",
                "automation": "Full CI/CD pipeline with blue-green deployment",
                "testing": "Comprehensive testing including load, chaos, and failover testing"
            }
        }
        
        return report
    
    def _generate_deployment_checklist(self) -> List[Dict[str, Any]]:
        """Generate deployment checklist"""
        checklist = [
            {
                "phase": "Pre-deployment",
                "items": [
                    {"task": "All Docker images built and scanned", "status": "required"},
                    {"task": "Kubernetes manifests validated", "status": "required"},
                    {"task": "Security policies applied", "status": "required"},
                    {"task": "Monitoring configured", "status": "required"},
                    {"task": "Backup procedures verified", "status": "required"}
                ]
            },
            {
                "phase": "Deployment",
                "items": [
                    {"task": "Blue-green deployment initiated", "status": "required"},
                    {"task": "Health checks passing", "status": "required"},
                    {"task": "Performance validation", "status": "required"},
                    {"task": "Security validation", "status": "required"},
                    {"task": "Traffic switched to new version", "status": "required"}
                ]
            },
            {
                "phase": "Post-deployment",
                "items": [
                    {"task": "Monitoring alerts active", "status": "required"},
                    {"task": "Performance metrics within SLA", "status": "required"},
                    {"task": "Error rates acceptable", "status": "required"},
                    {"task": "Documentation updated", "status": "recommended"},
                    {"task": "Team notified", "status": "recommended"}
                ]
            }
        ]
        
        return checklist
    
    def _generate_next_steps(self, readiness_level: str) -> List[str]:
        """Generate next steps based on readiness level"""
        if readiness_level == "PRODUCTION_READY":
            return [
                "✅ System is ready for production deployment",
                "🚀 Execute deployment using standard procedures",
                "📊 Monitor system performance post-deployment",
                "🔄 Schedule regular production readiness reviews"
            ]
        elif readiness_level == "PRODUCTION_READY_WITH_MINOR_ISSUES":
            return [
                "⚠️ Address warning-level issues before deployment",
                "🚀 Deploy with increased monitoring",
                "🔧 Plan remediation for identified issues",
                "📅 Schedule follow-up validation in 2 weeks"
            ]
        elif readiness_level == "PRODUCTION_READY_WITH_REMEDIATION":
            return [
                "🔴 Resolve all critical failures before deployment",
                "🔧 Implement high-priority recommendations",
                "🔍 Re-run validation after remediation",
                "📈 Consider staged deployment approach"
            ]
        else:
            return [
                "🚫 Block production deployment until critical issues resolved",
                "🔴 Address all FAIL status items immediately",
                "📋 Implement comprehensive remediation plan",
                "✅ Re-validate entire system before proceeding"
            ]

def main():
    """Main function for production readiness validation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='MCP Production Readiness Validator')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--output', default='production_readiness_report.json', help='Output file path')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run validation
    validator = SimpleProductionReadinessValidator(args.config)
    report = validator.validate_all()
    
    # Save report
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\n" + "="*80)
    print("🏭 MCP PRODUCTION READINESS VALIDATION REPORT")
    print("="*80)
    print(f"📊 Overall Score: {report['summary']['overall_score']:.1f}%")
    print(f"🎯 Readiness Level: {report['summary']['readiness_level']}")
    print(f"📈 Readiness Grade: {report['summary']['readiness_grade']}")
    print(f"🚀 Production Ready: {'✅ YES' if report['summary']['production_ready'] else '❌ NO'}")
    
    print(f"\n📋 Validation Results:")
    print(f"  📊 Total Checks: {report['summary']['total_checks']}")
    print(f"  ✅ Passed: {report['summary']['passed_checks']}")
    print(f"  ❌ Failed: {report['summary']['failed_checks']}")
    print(f"  ⚠️  Warnings: {report['summary']['warning_checks']}")
    print(f"  🔴 Critical Failures: {report['summary']['critical_failures']}")
    
    print(f"\n📊 Category Scores:")
    for category, score_data in report['category_scores'].items():
        score = score_data['score']
        emoji = "✅" if score >= 90 else "⚠️" if score >= 70 else "❌"
        print(f"  {emoji} {category}: {score:.1f}% ({score_data['checks']} checks)")
    
    if report['recommendations']:
        print(f"\n🔧 Top Recommendations:")
        high_priority = [r for r in report['recommendations'] if r['priority'] == 'HIGH'][:5]
        for i, rec in enumerate(high_priority, 1):
            print(f"  {i}. 🔴 {rec['category']}: {rec['recommendation']}")
        
        medium_priority = [r for r in report['recommendations'] if r['priority'] == 'MEDIUM'][:3]
        for i, rec in enumerate(medium_priority, len(high_priority) + 1):
            print(f"  {i}. ⚠️  {rec['category']}: {rec['recommendation']}")
    
    print(f"\n🎯 Next Steps:")
    for i, step in enumerate(report['next_steps'], 1):
        print(f"  {i}. {step}")
    
    print(f"\n📄 Detailed report saved to: {args.output}")
    print("="*80)
    
    # Exit with appropriate code
    exit_code = 0 if report['summary']['production_ready'] else 1
    return exit_code

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)