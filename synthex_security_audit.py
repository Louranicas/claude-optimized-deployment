#!/usr/bin/env python3
"""
SYNTHEX Comprehensive Security Audit
Uses MCP security testing servers to perform thorough security assessment
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.mcp.security.synthex_security_server import SynthexSecurityServer
from src.synthex import SynthexEngine, SynthexConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SynthexSecurityAuditor:
    """
    Comprehensive security auditor for SYNTHEX
    Coordinates multiple security testing approaches
    """
    
    def __init__(self):
        self.security_server = SynthexSecurityServer()
        self.audit_results = {
            "audit_id": f"SYNTHEX-AUDIT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "start_time": datetime.now().isoformat(),
            "phases": {}
        }
    
    async def run_comprehensive_audit(self):
        """Run complete security audit"""
        print("\n" + "="*80)
        print("SYNTHEX COMPREHENSIVE SECURITY AUDIT")
        print("="*80)
        print(f"Audit ID: {self.audit_results['audit_id']}")
        print(f"Started: {self.audit_results['start_time']}")
        print("="*80 + "\n")
        
        try:
            # Start security server
            await self.security_server.start()
            
            # Phase 1: Vulnerability Scanning
            await self._phase1_vulnerability_scan()
            
            # Phase 2: Penetration Testing
            await self._phase2_penetration_testing()
            
            # Phase 3: Secret Detection
            await self._phase3_secret_detection()
            
            # Phase 4: Compliance Validation
            await self._phase4_compliance_check()
            
            # Phase 5: Attack Simulation
            await self._phase5_attack_simulation()
            
            # Phase 6: Configuration Review
            await self._phase6_configuration_review()
            
            # Generate final report
            await self._generate_final_report()
            
        except Exception as e:
            logger.error(f"Audit failed: {e}")
            self.audit_results["error"] = str(e)
        finally:
            await self.security_server.stop()
    
    async def _phase1_vulnerability_scan(self):
        """Phase 1: Comprehensive vulnerability scanning"""
        print("\n[PHASE 1] Vulnerability Scanning")
        print("-" * 40)
        
        # Deep scan
        result = await self.security_server._scan_vulnerabilities({
            "scan_type": "deep",
            "components": ["all"]
        })
        
        self.audit_results["phases"]["vulnerability_scan"] = result
        
        print(f"✓ Total vulnerabilities found: {result['total_vulnerabilities']}")
        print(f"  - Critical: {result['critical']}")
        print(f"  - High: {result['high']}")
        print(f"  - Medium: {result['medium']}")
        print(f"  - Low: {result['low']}")
        
        if result['critical'] > 0:
            print("\n⚠️  CRITICAL vulnerabilities detected!")
            for vuln in result['vulnerabilities']:
                if vuln['severity'] == 'CRITICAL':
                    print(f"   - {vuln['name']}: {vuln['description']}")
    
    async def _phase2_penetration_testing(self):
        """Phase 2: Penetration testing"""
        print("\n[PHASE 2] Penetration Testing")
        print("-" * 40)
        
        result = await self.security_server._run_pen_test({
            "attack_vectors": ["sql_injection", "xss", "api_abuse", "dos"],
            "intensity": "medium"
        })
        
        self.audit_results["phases"]["penetration_test"] = result
        
        print(f"✓ Attack vectors tested: {len(result['attack_vectors'])}")
        print(f"  - Blocked: {result['summary']['blocked']}")
        print(f"  - Vulnerable: {result['summary']['vulnerable']}")
        
        for test in result['results']:
            status_icon = "✓" if test['status'] == "BLOCKED" else "✗"
            print(f"  {status_icon} {test['vector']}: {test['status']}")
    
    async def _phase3_secret_detection(self):
        """Phase 3: Secret detection"""
        print("\n[PHASE 3] Secret Detection")
        print("-" * 40)
        
        result = await self.security_server._detect_secrets({
            "scan_paths": ["src/synthex"],
            "exclude_patterns": ["test_", "_test", "example", "__pycache__"]
        })
        
        self.audit_results["phases"]["secret_detection"] = result
        
        print(f"✓ Total secrets found: {result['total_secrets_found']}")
        for secret_type, count in result['secrets_by_type'].items():
            if count > 0:
                print(f"  - {secret_type}: {count}")
        
        if result['total_secrets_found'] > 0:
            print("\n⚠️  Exposed secrets detected in:")
            for file in result['high_risk_files'][:5]:
                print(f"   - {file}")
    
    async def _phase4_compliance_check(self):
        """Phase 4: Compliance validation"""
        print("\n[PHASE 4] Compliance Validation")
        print("-" * 40)
        
        result = await self.security_server._check_compliance({
            "standards": ["owasp_top10", "soc2", "gdpr"]
        })
        
        self.audit_results["phases"]["compliance"] = result
        
        print(f"✓ Standards checked: {len(result['standards'])}")
        print(f"  Overall compliance: {result['compliance_percentage']:.1f}%")
        
        for standard, compliance in result['compliance_results'].items():
            status = "✓" if compliance.get('compliant', False) else "✗"
            print(f"  {status} {standard.upper()}: {'Compliant' if compliance.get('compliant', False) else 'Non-compliant'}")
            if not compliance.get('compliant', False) and 'failed_checks' in compliance:
                for check in compliance['failed_checks'][:3]:
                    print(f"     - Failed: {check}")
    
    async def _phase5_attack_simulation(self):
        """Phase 5: Attack simulation"""
        print("\n[PHASE 5] Attack Simulation")
        print("-" * 40)
        
        attack_types = ["rate_limit", "malformed_input", "resource_exhaustion"]
        
        for attack_type in attack_types:
            result = await self.security_server._simulate_attack({
                "attack_type": attack_type,
                "duration_seconds": 10,  # Short duration for audit
                "concurrent_attacks": 5
            })
            
            self.audit_results["phases"][f"attack_{attack_type}"] = result
            
            if attack_type == "rate_limit":
                protected = result.get('protection_effective', False)
                print(f"✓ Rate Limiting: {'Protected' if protected else 'Vulnerable'}")
                print(f"  - Block rate: {result.get('block_rate', 0):.1f}%")
            
            elif attack_type == "malformed_input":
                resilient = result.get('resilience', False)
                print(f"✓ Input Validation: {'Resilient' if resilient else 'Vulnerable'}")
                print(f"  - Error handling rate: {result.get('error_rate', 0):.1f}%")
            
            elif attack_type == "resource_exhaustion":
                protected = result.get('resource_protection', False)
                print(f"✓ Resource Protection: {'Protected' if protected else 'Vulnerable'}")
                print(f"  - Memory increase: {result.get('memory_increase_mb', 0):.1f} MB")
    
    async def _phase6_configuration_review(self):
        """Phase 6: Configuration review"""
        print("\n[PHASE 6] Configuration Review")
        print("-" * 40)
        
        config_issues = []
        
        # Check debug mode
        if os.getenv("DEBUG", "").lower() in ["true", "1", "yes"]:
            config_issues.append("Debug mode is enabled")
        
        # Check environment
        if not os.getenv("SYNTHEX_ENV") or os.getenv("SYNTHEX_ENV") != "production":
            config_issues.append("Not running in production mode")
        
        # Check secret configuration
        required_secrets = ["BRAVE_API_KEY", "DATABASE_URL"]
        missing_secrets = [s for s in required_secrets if not os.getenv(s)]
        if missing_secrets:
            config_issues.append(f"Missing required secrets: {', '.join(missing_secrets)}")
        
        self.audit_results["phases"]["configuration"] = {
            "issues": config_issues,
            "secure": len(config_issues) == 0
        }
        
        if config_issues:
            print("✗ Configuration issues found:")
            for issue in config_issues:
                print(f"  - {issue}")
        else:
            print("✓ Configuration is secure")
    
    async def _generate_final_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*80)
        print("SECURITY AUDIT SUMMARY")
        print("="*80)
        
        # Calculate overall score
        total_issues = 0
        critical_issues = 0
        
        # Count vulnerabilities
        vuln_phase = self.audit_results["phases"].get("vulnerability_scan", {})
        total_issues += vuln_phase.get("total_vulnerabilities", 0)
        critical_issues += vuln_phase.get("critical", 0)
        
        # Count pen test failures
        pen_phase = self.audit_results["phases"].get("penetration_test", {})
        if pen_phase.get("summary", {}).get("vulnerable", 0) > 0:
            total_issues += pen_phase["summary"]["vulnerable"]
            critical_issues += 1
        
        # Count secrets
        secret_phase = self.audit_results["phases"].get("secret_detection", {})
        if secret_phase.get("total_secrets_found", 0) > 0:
            total_issues += secret_phase["total_secrets_found"]
            critical_issues += 1
        
        # Calculate score
        if critical_issues > 0:
            security_score = 0
            grade = "F"
        elif total_issues > 10:
            security_score = 60
            grade = "D"
        elif total_issues > 5:
            security_score = 70
            grade = "C"
        elif total_issues > 2:
            security_score = 80
            grade = "B"
        elif total_issues > 0:
            security_score = 90
            grade = "A"
        else:
            security_score = 100
            grade = "A+"
        
        self.audit_results["summary"] = {
            "security_score": security_score,
            "grade": grade,
            "total_issues": total_issues,
            "critical_issues": critical_issues,
            "audit_passed": critical_issues == 0
        }
        
        print(f"\n🔐 Security Score: {security_score}/100 (Grade: {grade})")
        print(f"📊 Total Issues: {total_issues}")
        print(f"🚨 Critical Issues: {critical_issues}")
        
        if critical_issues > 0:
            print("\n⚠️  AUDIT FAILED - Critical security issues must be resolved!")
        else:
            print("\n✅ AUDIT PASSED - No critical security issues found")
        
        # Save detailed report
        self.audit_results["end_time"] = datetime.now().isoformat()
        report_file = f"synthex_security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.audit_results, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        
        # Print recommendations
        print("\n📋 Top Recommendations:")
        recommendations = set()
        
        for phase, result in self.audit_results["phases"].items():
            if isinstance(result, dict) and "recommendations" in result:
                recommendations.update(result["recommendations"])
        
        for i, rec in enumerate(list(recommendations)[:5], 1):
            print(f"   {i}. {rec}")
        
        return self.audit_results


async def main():
    """Run security audit"""
    auditor = SynthexSecurityAuditor()
    
    try:
        results = await auditor.run_comprehensive_audit()
        
        # Exit code based on results
        if results["summary"]["audit_passed"]:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Audit failed with error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    asyncio.run(main())