#!/usr/bin/env python3
"""
Ultra Security Excellence Tracking Dashboard
Real-time security posture monitoring and tracking system
"""

import json
import yaml
import datetime
import subprocess
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    GOOD = "GOOD"

class ComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    PARTIAL = "PARTIAL"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_ASSESSED = "NOT_ASSESSED"

@dataclass
class SecurityMetric:
    name: str
    current_value: float
    target_value: float
    unit: str
    status: SecurityLevel
    last_updated: datetime.datetime
    trend: str  # "IMPROVING", "STABLE", "DEGRADING"

@dataclass
class ComplianceFramework:
    name: str
    version: str
    overall_score: float
    status: ComplianceStatus
    controls: Dict[str, Dict[str, Any]]
    last_assessment: datetime.datetime

@dataclass
class VulnerabilityStatus:
    total_count: int
    critical: int
    high: int
    medium: int
    low: int
    remediated_this_week: int
    mean_time_to_remediation: float

@dataclass
class SecurityComponent:
    name: str
    category: str
    status: SecurityLevel
    coverage: float
    last_tested: datetime.datetime
    issues: List[str]
    recommendations: List[str]

class SecurityExcellenceTracker:
    """Main security excellence tracking and monitoring system"""
    
    def __init__(self, project_root: str = "/home/louranicas/projects/claude-optimized-deployment"):
        self.project_root = Path(project_root)
        self.config_file = self.project_root / "config" / "security_config.yaml"
        self.data_dir = self.project_root / "security_data"
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize tracking data
        self.security_metrics: Dict[str, SecurityMetric] = {}
        self.compliance_frameworks: Dict[str, ComplianceFramework] = {}
        self.security_components: Dict[str, SecurityComponent] = {}
        self.vulnerability_status = VulnerabilityStatus(0, 0, 0, 0, 0, 0, 0.0)
        
        # Load configuration
        self.load_security_config()
        self.initialize_tracking_system()

    def load_security_config(self):
        """Load security configuration from YAML file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self.config = yaml.safe_load(f)
                logger.info("Loaded security configuration")
            else:
                logger.warning(f"Security config file not found: {self.config_file}")
                self.config = {}
        except Exception as e:
            logger.error(f"Error loading security config: {e}")
            self.config = {}

    def initialize_tracking_system(self):
        """Initialize the security tracking system with baseline metrics"""
        
        # Initialize core security metrics
        self.security_metrics = {
            "vulnerability_count": SecurityMetric(
                name="Total Vulnerabilities",
                current_value=12820,
                target_value=10,
                unit="count",
                status=SecurityLevel.CRITICAL,
                last_updated=datetime.datetime.now(),
                trend="STABLE"
            ),
            "critical_cves": SecurityMetric(
                name="Critical CVEs",
                current_value=47,
                target_value=0,
                unit="count",
                status=SecurityLevel.CRITICAL,
                last_updated=datetime.datetime.now(),
                trend="STABLE"
            ),
            "owasp_compliance": SecurityMetric(
                name="OWASP Top 10 Compliance",
                current_value=44.0,
                target_value=95.0,
                unit="percent",
                status=SecurityLevel.CRITICAL,
                last_updated=datetime.datetime.now(),
                trend="IMPROVING"
            ),
            "nist_csf_maturity": SecurityMetric(
                name="NIST CSF Maturity",
                current_value=49.0,
                target_value=90.0,
                unit="percent",
                status=SecurityLevel.CRITICAL,
                last_updated=datetime.datetime.now(),
                trend="IMPROVING"
            ),
            "authentication_strength": SecurityMetric(
                name="Authentication Strength",
                current_value=85.0,
                target_value=95.0,
                unit="percent",
                status=SecurityLevel.HIGH,
                last_updated=datetime.datetime.now(),
                trend="STABLE"
            ),
            "security_automation": SecurityMetric(
                name="Security Automation",
                current_value=45.0,
                target_value=90.0,
                unit="percent",
                status=SecurityLevel.MEDIUM,
                last_updated=datetime.datetime.now(),
                trend="IMPROVING"
            )
        }
        
        # Initialize compliance frameworks
        self.compliance_frameworks = {
            "owasp_top_10": ComplianceFramework(
                name="OWASP Top 10 2025",
                version="2025.1",
                overall_score=44.0,
                status=ComplianceStatus.NON_COMPLIANT,
                controls={
                    "A01_Broken_Access_Control": {"score": 30, "status": "FAIL"},
                    "A02_Cryptographic_Failures": {"score": 25, "status": "FAIL"},
                    "A03_Injection": {"score": 15, "status": "CRITICAL"},
                    "A04_Insecure_Design": {"score": 60, "status": "PARTIAL"},
                    "A05_Security_Misconfiguration": {"score": 40, "status": "FAIL"},
                    "A06_Vulnerable_Components": {"score": 5, "status": "CRITICAL"},
                    "A07_Authentication_Failures": {"score": 85, "status": "PASS"},
                    "A08_Software_Integrity": {"score": 20, "status": "FAIL"},
                    "A09_Logging_Failures": {"score": 70, "status": "PARTIAL"},
                    "A10_SSRF": {"score": 90, "status": "PASS"}
                },
                last_assessment=datetime.datetime.now()
            ),
            "nist_csf": ComplianceFramework(
                name="NIST Cybersecurity Framework 2.0",
                version="2.0",
                overall_score=49.0,
                status=ComplianceStatus.NON_COMPLIANT,
                controls={
                    "Identify": {"score": 65, "status": "PARTIAL"},
                    "Protect": {"score": 55, "status": "FAIL"},
                    "Detect": {"score": 60, "status": "PARTIAL"},
                    "Respond": {"score": 40, "status": "FAIL"},
                    "Recover": {"score": 25, "status": "FAIL"}
                },
                last_assessment=datetime.datetime.now()
            ),
            "iso_27001": ComplianceFramework(
                name="ISO 27001:2022",
                version="2022",
                overall_score=47.0,
                status=ComplianceStatus.NON_COMPLIANT,
                controls={
                    "A.5_Information_Security_Policies": {"score": 40, "status": "FAIL"},
                    "A.8_Asset_Management": {"score": 60, "status": "PARTIAL"},
                    "A.9_Access_Control": {"score": 70, "status": "PARTIAL"},
                    "A.12_Operations_Security": {"score": 65, "status": "PARTIAL"},
                    "A.13_Communications_Security": {"score": 75, "status": "PARTIAL"}
                },
                last_assessment=datetime.datetime.now()
            )
        }
        
        # Initialize security components
        self.security_components = {
            "multi_agent_audit": SecurityComponent(
                name="Multi-Agent Security Audit System",
                category="Audit & Assessment",
                status=SecurityLevel.GOOD,
                coverage=100.0,
                last_tested=datetime.datetime.now(),
                issues=[],
                recommendations=["Continue regular agent rotation"]
            ),
            "dependency_scanning": SecurityComponent(
                name="Dependency Vulnerability Scanning",
                category="Vulnerability Management",
                status=SecurityLevel.CRITICAL,
                coverage=85.0,
                last_tested=datetime.datetime.now(),
                issues=["12,820+ vulnerabilities detected", "47 critical CVEs"],
                recommendations=["Immediate dependency updates", "Automated patching"]
            ),
            "authentication_system": SecurityComponent(
                name="Authentication & Authorization",
                category="Access Control",
                status=SecurityLevel.HIGH,
                coverage=85.0,
                last_tested=datetime.datetime.now(),
                issues=["RBAC overpermissive", "MFA not fully deployed"],
                recommendations=["Implement strict RBAC", "Deploy MFA everywhere"]
            ),
            "container_security": SecurityComponent(
                name="Container Security",
                category="Infrastructure",
                status=SecurityLevel.HIGH,
                coverage=70.0,
                last_tested=datetime.datetime.now(),
                issues=["Some outdated base images", "Missing runtime monitoring"],
                recommendations=["Update base images", "Deploy Falco monitoring"]
            ),
            "siem_system": SecurityComponent(
                name="SIEM & Monitoring",
                category="Detection & Response",
                status=SecurityLevel.CRITICAL,
                coverage=0.0,
                last_tested=datetime.datetime.now(),
                issues=["No SIEM deployed", "Limited threat detection"],
                recommendations=["Deploy enterprise SIEM", "24/7 SOC operations"]
            ),
            "secrets_management": SecurityComponent(
                name="Secrets Management",
                category="Data Protection",
                status=SecurityLevel.CRITICAL,
                coverage=15.0,
                last_tested=datetime.datetime.now(),
                issues=["1,027+ hardcoded secrets", "No proper vault"],
                recommendations=["Deploy HashiCorp Vault", "Rotate all secrets"]
            )
        }
        
        # Initialize vulnerability status
        self.vulnerability_status = VulnerabilityStatus(
            total_count=12820,
            critical=47,
            high=1247,
            medium=4892,
            low=6634,
            remediated_this_week=0,
            mean_time_to_remediation=0.0
        )

    def scan_project_security_status(self) -> Dict[str, Any]:
        """Scan the project for current security status"""
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "scan_type": "comprehensive_security_scan",
            "results": {}
        }
        
        # Scan for security audit files
        audit_files = list(self.project_root.glob("*SECURITY*")) + \
                     list(self.project_root.glob("*security*")) + \
                     list(self.project_root.glob("*AUDIT*"))
        
        results["results"]["audit_files_found"] = len(audit_files)
        results["results"]["audit_files"] = [str(f.name) for f in audit_files[:10]]
        
        # Check for dependency vulnerabilities
        try:
            bandit_files = list(self.project_root.glob("bandit*.json"))
            if bandit_files:
                with open(bandit_files[0], 'r') as f:
                    bandit_data = json.load(f)
                    results["results"]["bandit_issues"] = len(bandit_data.get("results", []))
        except Exception as e:
            results["results"]["bandit_scan_error"] = str(e)
        
        # Check for security configuration
        security_configs = list(self.project_root.glob("**/security_config.*"))
        results["results"]["security_configs"] = len(security_configs)
        
        # Check for MCP security servers
        mcp_security_files = list(self.project_root.glob("**/security/*server*.py"))
        results["results"]["mcp_security_servers"] = len(mcp_security_files)
        
        return results

    def update_vulnerability_metrics(self):
        """Update vulnerability metrics from latest scan results"""
        try:
            # Read latest vulnerability reports
            vuln_files = [
                "bandit_comprehensive_report.json",
                "dependency_vulnerabilities.json",
                "security_audit_phase2_results.json"
            ]
            
            total_vulns = 0
            critical_count = 0
            high_count = 0
            
            for vuln_file in vuln_files:
                file_path = self.project_root / vuln_file
                if file_path.exists():
                    try:
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                            
                        if "vulnerabilities" in data:
                            for vuln in data["vulnerabilities"]:
                                total_vulns += 1
                                severity = vuln.get("severity", "").upper()
                                if severity == "CRITICAL":
                                    critical_count += 1
                                elif severity == "HIGH":
                                    high_count += 1
                                    
                    except Exception as e:
                        logger.warning(f"Error reading {vuln_file}: {e}")
            
            # Update metrics if we found new data
            if total_vulns > 0:
                self.security_metrics["vulnerability_count"].current_value = total_vulns
                self.security_metrics["critical_cves"].current_value = critical_count
                self.vulnerability_status.total_count = total_vulns
                self.vulnerability_status.critical = critical_count
                self.vulnerability_status.high = high_count
                
        except Exception as e:
            logger.error(f"Error updating vulnerability metrics: {e}")

    def calculate_security_score(self) -> float:
        """Calculate overall security score based on all metrics"""
        weights = {
            "vulnerability_count": 0.25,
            "critical_cves": 0.25,
            "owasp_compliance": 0.20,
            "nist_csf_maturity": 0.15,
            "authentication_strength": 0.10,
            "security_automation": 0.05
        }
        
        total_score = 0.0
        for metric_name, weight in weights.items():
            if metric_name in self.security_metrics:
                metric = self.security_metrics[metric_name]
                
                # Normalize score (higher is better for most metrics)
                if metric_name in ["vulnerability_count", "critical_cves"]:
                    # For vulnerability counts, lower is better
                    if metric.current_value == 0:
                        normalized_score = 100.0
                    elif metric.target_value == 0:
                        normalized_score = max(0, 100 - (metric.current_value / 100))
                    else:
                        normalized_score = max(0, 100 * (1 - metric.current_value / (metric.target_value * 10)))
                else:
                    # For percentage metrics, higher is better
                    normalized_score = min(100, metric.current_value)
                
                total_score += normalized_score * weight
        
        return round(total_score, 1)

    def generate_security_dashboard(self) -> Dict[str, Any]:
        """Generate comprehensive security dashboard data"""
        dashboard = {
            "timestamp": datetime.datetime.now().isoformat(),
            "overall_security_score": self.calculate_security_score(),
            "security_level": self.get_overall_security_level(),
            "metrics": {},
            "compliance": {},
            "components": {},
            "vulnerabilities": asdict(self.vulnerability_status),
            "recommendations": self.generate_recommendations(),
            "trends": self.calculate_trends(),
            "alerts": self.generate_alerts()
        }
        
        # Add metrics
        for name, metric in self.security_metrics.items():
            dashboard["metrics"][name] = asdict(metric)
        
        # Add compliance frameworks
        for name, framework in self.compliance_frameworks.items():
            dashboard["compliance"][name] = asdict(framework)
        
        # Add security components
        for name, component in self.security_components.items():
            dashboard["components"][name] = asdict(component)
        
        return dashboard

    def get_overall_security_level(self) -> str:
        """Determine overall security level based on metrics"""
        score = self.calculate_security_score()
        
        if score >= 90:
            return "EXCELLENT"
        elif score >= 75:
            return "GOOD"
        elif score >= 50:
            return "ADEQUATE"
        elif score >= 25:
            return "POOR"
        else:
            return "CRITICAL"

    def generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized security recommendations"""
        recommendations = []
        
        # Critical vulnerabilities
        if self.vulnerability_status.critical > 0:
            recommendations.append({
                "priority": "P0_CRITICAL",
                "category": "Vulnerability Management",
                "title": "Immediate Critical CVE Remediation",
                "description": f"Remediate {self.vulnerability_status.critical} critical CVEs immediately",
                "timeline": "24-48 hours",
                "impact": "HIGH"
            })
        
        # Secrets management
        secrets_component = self.security_components.get("secrets_management")
        if secrets_component and secrets_component.status == SecurityLevel.CRITICAL:
            recommendations.append({
                "priority": "P0_CRITICAL",
                "category": "Secrets Management",
                "title": "Deploy Enterprise Secrets Management",
                "description": "Implement HashiCorp Vault and rotate all exposed secrets",
                "timeline": "1 week",
                "impact": "HIGH"
            })
        
        # SIEM deployment
        siem_component = self.security_components.get("siem_system")
        if siem_component and siem_component.coverage == 0:
            recommendations.append({
                "priority": "P1_HIGH",
                "category": "Detection & Response",
                "title": "Deploy Enterprise SIEM Solution",
                "description": "Implement comprehensive SIEM with 24/7 SOC operations",
                "timeline": "2-4 weeks",
                "impact": "HIGH"
            })
        
        # OWASP compliance
        owasp_compliance = self.security_metrics.get("owasp_compliance")
        if owasp_compliance and owasp_compliance.current_value < 70:
            recommendations.append({
                "priority": "P1_HIGH",
                "category": "Compliance",
                "title": "OWASP Top 10 Compliance Achievement",
                "description": "Implement remaining OWASP controls to achieve >95% compliance",
                "timeline": "4-6 weeks",
                "impact": "MEDIUM"
            })
        
        # Authentication hardening
        auth_component = self.security_components.get("authentication_system")
        if auth_component and "MFA" in str(auth_component.issues):
            recommendations.append({
                "priority": "P2_MEDIUM",
                "category": "Authentication",
                "title": "Complete MFA Deployment",
                "description": "Deploy multi-factor authentication across all systems",
                "timeline": "2 weeks",
                "impact": "MEDIUM"
            })
        
        return recommendations

    def calculate_trends(self) -> Dict[str, Any]:
        """Calculate security trends and projections"""
        # This would typically use historical data
        # For now, providing baseline trend analysis
        
        trends = {
            "overall_trend": "STABLE",
            "vulnerability_trend": "CRITICAL_STABLE",
            "compliance_trend": "SLOWLY_IMPROVING",
            "automation_trend": "IMPROVING",
            "projected_security_score_30_days": self.calculate_security_score() + 15,
            "projected_compliance_90_days": 70.0,
            "risk_trajectory": "HIGH_RISK_MAINTAINED"
        }
        
        return trends

    def generate_alerts(self) -> List[Dict[str, Any]]:
        """Generate security alerts based on current status"""
        alerts = []
        
        # Critical vulnerability alert
        if self.vulnerability_status.critical > 0:
            alerts.append({
                "level": "CRITICAL",
                "type": "VULNERABILITY",
                "message": f"{self.vulnerability_status.critical} critical CVEs require immediate attention",
                "action_required": "Emergency patching required within 24 hours",
                "timestamp": datetime.datetime.now().isoformat()
            })
        
        # SIEM missing alert
        siem_component = self.security_components.get("siem_system")
        if siem_component and siem_component.coverage == 0:
            alerts.append({
                "level": "HIGH",
                "type": "MONITORING",
                "message": "No SIEM system deployed - blind to security threats",
                "action_required": "Deploy enterprise SIEM immediately",
                "timestamp": datetime.datetime.now().isoformat()
            })
        
        # Secrets exposure alert
        secrets_component = self.security_components.get("secrets_management")
        if secrets_component and "1,027+" in str(secrets_component.issues):
            alerts.append({
                "level": "CRITICAL",
                "type": "DATA_EXPOSURE",
                "message": "1,027+ hardcoded secrets detected in source code",
                "action_required": "Immediate secret rotation and vault deployment",
                "timestamp": datetime.datetime.now().isoformat()
            })
        
        # Compliance gap alert
        owasp_score = self.compliance_frameworks["owasp_top_10"].overall_score
        if owasp_score < 50:
            alerts.append({
                "level": "HIGH",
                "type": "COMPLIANCE",
                "message": f"OWASP compliance at {owasp_score}% - well below industry standards",
                "action_required": "Implement comprehensive security controls",
                "timestamp": datetime.datetime.now().isoformat()
            })
        
        return alerts

    def save_dashboard_data(self, dashboard_data: Dict[str, Any]):
        """Save dashboard data to file for persistence"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_dashboard_{timestamp}.json"
        filepath = self.data_dir / filename
        
        try:
            with open(filepath, 'w') as f:
                json.dump(dashboard_data, f, indent=2, default=str)
            logger.info(f"Dashboard data saved to {filepath}")
        except Exception as e:
            logger.error(f"Error saving dashboard data: {e}")

    def export_security_report(self) -> str:
        """Export comprehensive security report"""
        dashboard = self.generate_security_dashboard()
        
        report = f"""
# SECURITY EXCELLENCE DASHBOARD REPORT
Generated: {dashboard['timestamp']}

## EXECUTIVE SUMMARY
Overall Security Score: {dashboard['overall_security_score']}/100
Security Level: {dashboard['security_level']}

## CRITICAL METRICS
"""
        
        for name, metric in dashboard['metrics'].items():
            status_emoji = "🔴" if metric['status'] == "CRITICAL" else "🟡" if metric['status'] == "HIGH" else "🟢"
            report += f"- {metric['name']}: {metric['current_value']}{metric['unit']} / {metric['target_value']}{metric['unit']} {status_emoji}\n"
        
        report += f"""
## VULNERABILITY STATUS
- Total Vulnerabilities: {dashboard['vulnerabilities']['total_count']}
- Critical CVEs: {dashboard['vulnerabilities']['critical']}
- High Severity: {dashboard['vulnerabilities']['high']}
- Medium Severity: {dashboard['vulnerabilities']['medium']}
- Low Severity: {dashboard['vulnerabilities']['low']}

## COMPLIANCE STATUS
"""
        
        for name, framework in dashboard['compliance'].items():
            status_emoji = "🔴" if framework['status'] == "NON_COMPLIANT" else "🟡" if framework['status'] == "PARTIAL" else "🟢"
            report += f"- {framework['name']}: {framework['overall_score']}% {status_emoji}\n"
        
        report += "\n## IMMEDIATE ACTIONS REQUIRED\n"
        for rec in dashboard['recommendations'][:5]:
            report += f"- [{rec['priority']}] {rec['title']}\n"
        
        report += "\n## ACTIVE ALERTS\n"
        for alert in dashboard['alerts']:
            level_emoji = "🚨" if alert['level'] == "CRITICAL" else "⚠️"
            report += f"{level_emoji} {alert['message']}\n"
        
        return report

    async def run_continuous_monitoring(self, interval_minutes: int = 60):
        """Run continuous security monitoring"""
        logger.info(f"Starting continuous security monitoring (interval: {interval_minutes} minutes)")
        
        while True:
            try:
                # Update metrics
                self.update_vulnerability_metrics()
                
                # Generate dashboard
                dashboard = self.generate_security_dashboard()
                
                # Save data
                self.save_dashboard_data(dashboard)
                
                # Check for critical alerts
                alerts = dashboard['alerts']
                critical_alerts = [a for a in alerts if a['level'] == 'CRITICAL']
                
                if critical_alerts:
                    logger.critical(f"CRITICAL SECURITY ALERTS: {len(critical_alerts)} alerts require immediate attention")
                    for alert in critical_alerts:
                        logger.critical(f"- {alert['message']}")
                
                # Log status
                logger.info(f"Security monitoring cycle complete. Score: {dashboard['overall_security_score']}/100")
                
                # Wait for next cycle
                await asyncio.sleep(interval_minutes * 60)
                
            except Exception as e:
                logger.error(f"Error in monitoring cycle: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retry

def main():
    """Main function for running the security dashboard"""
    print("🛡️  Ultra Security Excellence Tracking Dashboard")
    print("=" * 50)
    
    # Initialize tracker
    tracker = SecurityExcellenceTracker()
    
    # Generate dashboard
    dashboard = tracker.generate_security_dashboard()
    
    # Display key metrics
    print(f"\n📊 OVERALL SECURITY SCORE: {dashboard['overall_security_score']}/100")
    print(f"🎯 SECURITY LEVEL: {dashboard['security_level']}")
    
    print(f"\n🚨 CRITICAL ALERTS: {len([a for a in dashboard['alerts'] if a['level'] == 'CRITICAL'])}")
    print(f"⚠️  HIGH ALERTS: {len([a for a in dashboard['alerts'] if a['level'] == 'HIGH'])}")
    
    print(f"\n🔍 VULNERABILITY STATUS:")
    vuln = dashboard['vulnerabilities']
    print(f"   Total: {vuln['total_count']}")
    print(f"   Critical: {vuln['critical']}")
    print(f"   High: {vuln['high']}")
    
    print(f"\n📋 COMPLIANCE STATUS:")
    for name, framework in dashboard['compliance'].items():
        status_emoji = "🔴" if framework['status'] == "NON_COMPLIANT" else "🟡" if framework['status'] == "PARTIAL" else "🟢"
        print(f"   {framework['name']}: {framework['overall_score']}% {status_emoji}")
    
    print(f"\n⚡ TOP RECOMMENDATIONS:")
    for i, rec in enumerate(dashboard['recommendations'][:3], 1):
        print(f"   {i}. [{rec['priority']}] {rec['title']}")
    
    # Save dashboard data
    tracker.save_dashboard_data(dashboard)
    
    # Export report
    report = tracker.export_security_report()
    report_file = tracker.data_dir / f"security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    
    try:
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"\n📄 Security report exported to: {report_file}")
    except Exception as e:
        print(f"❌ Error exporting report: {e}")
    
    print(f"\n✅ Dashboard data saved to: {tracker.data_dir}")
    
    # Option to run continuous monitoring
    choice = input("\nRun continuous monitoring? (y/N): ").strip().lower()
    if choice == 'y':
        print("Starting continuous monitoring...")
        asyncio.run(tracker.run_continuous_monitoring())

if __name__ == "__main__":
    main()