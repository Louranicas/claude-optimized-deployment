#!/usr/bin/env python3
"""
MCP Testing Framework Master Runner

Comprehensive test execution coordinator for all MCP testing modules.
Agent 5: Complete testing suite orchestrator with detailed reporting and analysis.
"""

import asyncio
import time
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import sys
import subprocess

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import all testing modules
try:
    from mcp_testing_framework import MCPTestFramework
    from mcp_stress_testing import MCPStressTester, STRESS_TEST_CONFIGS
    from mcp_security_testing import MCPSecurityTester
    from mcp_health_monitoring import MCPHealthMonitor, console_alert_handler
except ImportError as e:
    print(f"Error importing testing modules: {e}")
    print("Please ensure all testing modules are in the tests directory")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class TestSuiteResult:
    """Result from a test suite execution."""
    suite_name: str
    status: str
    duration_minutes: float
    total_tests: int
    passed_tests: int
    failed_tests: int
    error_tests: int
    skipped_tests: int
    success_rate: float
    details: Dict[str, Any]
    timestamp: str


class MCPTestOrchestrator:
    """
    Master test orchestrator for comprehensive MCP testing.
    
    Coordinates execution of:
    - Unit and integration tests
    - Performance and stress tests
    - Security and vulnerability assessments
    - Health monitoring and validation
    """
    
    def __init__(self):
        self.session_id = f"mcp_test_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.start_time = None
        self.end_time = None
        self.suite_results: List[TestSuiteResult] = []
        
    async def run_comprehensive_testing(
        self,
        suites: Optional[List[str]] = None,
        include_stress: bool = True,
        include_security: bool = True,
        include_health_monitoring: bool = True,
        monitoring_duration_minutes: int = 2
    ) -> Dict[str, Any]:
        """
        Run comprehensive MCP testing suite.
        
        Args:
            suites: Optional list of specific test suites to run
            include_stress: Whether to include stress testing
            include_security: Whether to include security testing
            include_health_monitoring: Whether to include health monitoring
            monitoring_duration_minutes: Duration for health monitoring
            
        Returns:
            Comprehensive test report
        """
        self.start_time = datetime.now()
        
        print("🚀 MCP Comprehensive Testing Suite")
        print("=" * 80)
        print(f"Session ID: {self.session_id}")
        print(f"Start Time: {self.start_time.isoformat()}")
        print("=" * 80)
        
        # Determine which suites to run
        available_suites = {
            "framework": "Core testing framework (unit, integration, performance)",
            "stress": "Stress and load testing",
            "security": "Security and vulnerability assessment",
            "health": "Health monitoring and validation"
        }
        
        if suites:
            suites_to_run = {k: v for k, v in available_suites.items() if k in suites}
        else:
            suites_to_run = available_suites.copy()
            if not include_stress:
                suites_to_run.pop("stress", None)
            if not include_security:
                suites_to_run.pop("security", None)
            if not include_health_monitoring:
                suites_to_run.pop("health", None)
        
        print(f"📋 Test suites to execute: {len(suites_to_run)}")
        for suite, description in suites_to_run.items():
            print(f"  • {suite}: {description}")
        print()
        
        # Run test suites
        if "framework" in suites_to_run:
            await self._run_framework_tests()
        
        if "stress" in suites_to_run:
            await self._run_stress_tests()
        
        if "security" in suites_to_run:
            await self._run_security_tests()
        
        if "health" in suites_to_run:
            await self._run_health_monitoring(monitoring_duration_minutes)
        
        self.end_time = datetime.now()
        
        # Generate comprehensive report
        report = await self._generate_comprehensive_report()
        
        # Save results
        await self._save_test_results(report)
        
        # Display summary
        self._display_test_summary(report)
        
        return report
    
    async def _run_framework_tests(self):
        """Run core testing framework tests."""
        print("🧪 Running Core Testing Framework...")
        print("-" * 50)
        
        suite_start = time.time()
        
        try:
            framework = MCPTestFramework()
            await framework.initialize()
            
            # Run all framework tests
            report = await framework.run_all_tests()
            
            duration_minutes = (time.time() - suite_start) / 60
            summary = report["summary"]
            
            result = TestSuiteResult(
                suite_name="Core Testing Framework",
                status="PASS" if summary["overall_status"] == "PASS" else "FAIL",
                duration_minutes=duration_minutes,
                total_tests=summary["total_tests"],
                passed_tests=summary["passed_tests"],
                failed_tests=summary["failed_tests"],
                error_tests=summary["error_tests"],
                skipped_tests=summary["skipped_tests"],
                success_rate=summary["success_rate"],
                details=report,
                timestamp=datetime.now().isoformat()
            )
            
            self.suite_results.append(result)
            
            print(f"✅ Core framework tests completed: {summary['success_rate']:.1%} success rate")
            await framework.cleanup()
            
        except Exception as e:
            duration_minutes = (time.time() - suite_start) / 60
            
            result = TestSuiteResult(
                suite_name="Core Testing Framework",
                status="ERROR",
                duration_minutes=duration_minutes,
                total_tests=0,
                passed_tests=0,
                failed_tests=0,
                error_tests=1,
                skipped_tests=0,
                success_rate=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )
            
            self.suite_results.append(result)
            print(f"❌ Core framework tests failed: {e}")
    
    async def _run_stress_tests(self):
        """Run stress and load testing."""
        print("\n🔥 Running Stress and Load Testing...")
        print("-" * 50)
        
        suite_start = time.time()
        
        try:
            tester = MCPStressTester()
            await tester.initialize()
            
            # Run selected stress tests
            stress_configs = [
                ("Light Load", STRESS_TEST_CONFIGS["light_load"]),
                ("Spike Test", STRESS_TEST_CONFIGS["spike_test"]),
                ("Memory Stress", STRESS_TEST_CONFIGS["memory_stress"]),
            ]
            
            stress_results = []
            total_operations = 0
            total_successful = 0
            
            for test_name, config in stress_configs:
                print(f"  🚀 Running {test_name}...")
                metrics = await tester.run_stress_test(config)
                stress_results.append(asdict(metrics))
                
                total_operations += metrics.total_operations
                total_successful += metrics.successful_operations
                
                print(f"    ✓ {test_name}: {metrics.success_rate:.1%} success rate")
                
                # Reset for next test
                tester.results = []
                tester.metrics_history = []
            
            duration_minutes = (time.time() - suite_start) / 60
            overall_success_rate = total_successful / total_operations if total_operations > 0 else 0
            
            result = TestSuiteResult(
                suite_name="Stress and Load Testing",
                status="PASS" if overall_success_rate > 0.8 else "FAIL",
                duration_minutes=duration_minutes,
                total_tests=len(stress_configs),
                passed_tests=len([r for r in stress_results if r["success_rate"] > 0.8]),
                failed_tests=len([r for r in stress_results if r["success_rate"] <= 0.8]),
                error_tests=0,
                skipped_tests=0,
                success_rate=overall_success_rate,
                details={"stress_results": stress_results, "total_operations": total_operations},
                timestamp=datetime.now().isoformat()
            )
            
            self.suite_results.append(result)
            
            print(f"✅ Stress tests completed: {overall_success_rate:.1%} overall success rate")
            await tester.cleanup()
            
        except Exception as e:
            duration_minutes = (time.time() - suite_start) / 60
            
            result = TestSuiteResult(
                suite_name="Stress and Load Testing",
                status="ERROR",
                duration_minutes=duration_minutes,
                total_tests=0,
                passed_tests=0,
                failed_tests=0,
                error_tests=1,
                skipped_tests=0,
                success_rate=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )
            
            self.suite_results.append(result)
            print(f"❌ Stress tests failed: {e}")
    
    async def _run_security_tests(self):
        """Run security and vulnerability assessment."""
        print("\n🔒 Running Security and Vulnerability Assessment...")
        print("-" * 50)
        
        suite_start = time.time()
        
        try:
            tester = MCPSecurityTester()
            await tester.initialize()
            
            # Run comprehensive security assessment
            report = await tester.run_comprehensive_security_assessment()
            
            duration_minutes = (time.time() - suite_start) / 60
            
            # Determine pass/fail based on security score
            status = "PASS" if report.security_score >= 80 else "FAIL"
            if report.critical_vulnerabilities > 0:
                status = "CRITICAL"
            
            result = TestSuiteResult(
                suite_name="Security Assessment",
                status=status,
                duration_minutes=duration_minutes,
                total_tests=report.total_tests,
                passed_tests=report.passed_tests,
                failed_tests=report.failed_tests,
                error_tests=0,
                skipped_tests=report.total_tests - report.passed_tests - report.failed_tests,
                success_rate=report.passed_tests / report.total_tests if report.total_tests > 0 else 0,
                details={
                    "security_score": report.security_score,
                    "vulnerabilities_found": report.vulnerabilities_found,
                    "critical_vulnerabilities": report.critical_vulnerabilities,
                    "high_vulnerabilities": report.high_vulnerabilities,
                    "compliance_status": report.compliance_status,
                    "full_report": asdict(report)
                },
                timestamp=datetime.now().isoformat()
            )
            
            self.suite_results.append(result)
            
            print(f"✅ Security assessment completed:")
            print(f"    Security Score: {report.security_score}/100 ({report.compliance_status})")
            print(f"    Vulnerabilities: {report.vulnerabilities_found} total ({report.critical_vulnerabilities} critical)")
            
            await tester.cleanup()
            
        except Exception as e:
            duration_minutes = (time.time() - suite_start) / 60
            
            result = TestSuiteResult(
                suite_name="Security Assessment",
                status="ERROR",
                duration_minutes=duration_minutes,
                total_tests=0,
                passed_tests=0,
                failed_tests=0,
                error_tests=1,
                skipped_tests=0,
                success_rate=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )
            
            self.suite_results.append(result)
            print(f"❌ Security assessment failed: {e}")
    
    async def _run_health_monitoring(self, duration_minutes: int):
        """Run health monitoring and validation."""
        print(f"\n💓 Running Health Monitoring ({duration_minutes} minutes)...")
        print("-" * 50)
        
        suite_start = time.time()
        
        try:
            monitor = MCPHealthMonitor()
            await monitor.initialize()
            
            # Add console alert handler
            monitor.add_alert_handler(console_alert_handler)
            
            # Start monitoring
            await monitor.start_continuous_monitoring(duration_minutes=duration_minutes)
            
            # Wait for monitoring to complete
            await asyncio.sleep((duration_minutes * 60) + 5)
            
            # Generate health report
            health_report = await monitor.generate_health_report()
            
            duration_minutes_actual = (time.time() - suite_start) / 60
            summary = health_report["summary"]
            
            # Determine status based on health
            status = "PASS"
            if summary["overall_status"] == "critical":
                status = "CRITICAL"
            elif summary["overall_status"] == "warning":
                status = "WARNING"
            
            result = TestSuiteResult(
                suite_name="Health Monitoring",
                status=status,
                duration_minutes=duration_minutes_actual,
                total_tests=summary["total_checks"],
                passed_tests=summary["healthy_checks"],
                failed_tests=summary["critical_checks"],
                error_tests=0,
                skipped_tests=summary["warning_checks"],
                success_rate=summary["healthy_checks"] / summary["total_checks"] if summary["total_checks"] > 0 else 0,
                details={
                    "overall_status": summary["overall_status"],
                    "active_alerts": summary["active_alerts"],
                    "sla_compliance": health_report.get("sla_compliance", {}),
                    "trends": health_report.get("trends", {}),
                    "full_report": health_report
                },
                timestamp=datetime.now().isoformat()
            )
            
            self.suite_results.append(result)
            
            print(f"✅ Health monitoring completed:")
            print(f"    Overall Status: {summary['overall_status'].upper()}")
            print(f"    Health Checks: {summary['healthy_checks']}/{summary['total_checks']} healthy")
            print(f"    Active Alerts: {summary['active_alerts']}")
            
            await monitor.cleanup()
            
        except Exception as e:
            duration_minutes_actual = (time.time() - suite_start) / 60
            
            result = TestSuiteResult(
                suite_name="Health Monitoring",
                status="ERROR",
                duration_minutes=duration_minutes_actual,
                total_tests=0,
                passed_tests=0,
                failed_tests=0,
                error_tests=1,
                skipped_tests=0,
                success_rate=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )
            
            self.suite_results.append(result)
            print(f"❌ Health monitoring failed: {e}")
    
    async def _generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        total_duration = (self.end_time - self.start_time).total_seconds() / 60
        
        # Calculate overall statistics
        total_tests = sum(result.total_tests for result in self.suite_results)
        total_passed = sum(result.passed_tests for result in self.suite_results)
        total_failed = sum(result.failed_tests for result in self.suite_results)
        total_errors = sum(result.error_tests for result in self.suite_results)
        total_skipped = sum(result.skipped_tests for result in self.suite_results)
        
        overall_success_rate = total_passed / total_tests if total_tests > 0 else 0
        
        # Determine overall status
        critical_suites = [r for r in self.suite_results if r.status in ["CRITICAL", "ERROR"]]
        failed_suites = [r for r in self.suite_results if r.status == "FAIL"]
        
        if critical_suites:
            overall_status = "CRITICAL"
        elif failed_suites:
            overall_status = "FAIL"
        elif overall_success_rate >= 0.9:
            overall_status = "EXCELLENT"
        elif overall_success_rate >= 0.8:
            overall_status = "GOOD"
        else:
            overall_status = "NEEDS_IMPROVEMENT"
        
        # Extract key findings
        key_findings = []
        recommendations = []
        
        for result in self.suite_results:
            if result.status in ["CRITICAL", "ERROR"]:
                key_findings.append(f"❌ {result.suite_name}: {result.status}")
            elif result.status == "FAIL":
                key_findings.append(f"⚠️ {result.suite_name}: {result.success_rate:.1%} success rate")
            else:
                key_findings.append(f"✅ {result.suite_name}: {result.success_rate:.1%} success rate")
        
        # Generate recommendations
        if critical_suites:
            recommendations.append("URGENT: Address critical failures before production deployment")
        if failed_suites:
            recommendations.append("Review and fix failed test cases")
        if overall_success_rate < 0.9:
            recommendations.append("Improve overall system reliability")
        
        recommendations.extend([
            "Implement continuous testing in CI/CD pipeline",
            "Set up automated monitoring for production deployment",
            "Conduct regular security assessments",
            "Maintain comprehensive test coverage"
        ])
        
        return {
            "session_info": {
                "session_id": self.session_id,
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat(),
                "total_duration_minutes": total_duration
            },
            "summary": {
                "overall_status": overall_status,
                "total_test_suites": len(self.suite_results),
                "successful_suites": len([r for r in self.suite_results if r.status == "PASS"]),
                "failed_suites": len(failed_suites),
                "critical_suites": len(critical_suites),
                "total_tests": total_tests,
                "total_passed": total_passed,
                "total_failed": total_failed,
                "total_errors": total_errors,
                "total_skipped": total_skipped,
                "overall_success_rate": overall_success_rate
            },
            "suite_results": [asdict(result) for result in self.suite_results],
            "key_findings": key_findings,
            "recommendations": recommendations,
            "detailed_reports": {
                result.suite_name.lower().replace(" ", "_"): result.details
                for result in self.suite_results
            }
        }
    
    async def _save_test_results(self, report: Dict[str, Any]):
        """Save comprehensive test results."""
        try:
            results_dir = Path("comprehensive_test_results")
            results_dir.mkdir(exist_ok=True)
            
            # Save main report
            report_path = results_dir / f"comprehensive_test_report_{self.session_id}.json"
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Save executive summary
            summary_path = results_dir / f"executive_summary_{self.session_id}.md"
            with open(summary_path, 'w') as f:
                f.write(self._generate_executive_summary(report))
            
            # Save detailed results for each suite
            for result in self.suite_results:
                suite_name = result.suite_name.lower().replace(" ", "_")
                suite_path = results_dir / f"{suite_name}_details_{self.session_id}.json"
                with open(suite_path, 'w') as f:
                    json.dump(result.details, f, indent=2, default=str)
            
            logger.info(f"Comprehensive test results saved:")
            logger.info(f"  Main report: {report_path}")
            logger.info(f"  Executive summary: {summary_path}")
            
        except Exception as e:
            logger.error(f"Failed to save test results: {e}")
    
    def _generate_executive_summary(self, report: Dict[str, Any]) -> str:
        """Generate executive summary markdown."""
        summary = report["summary"]
        session = report["session_info"]
        
        md = f"""# MCP Comprehensive Testing Executive Summary

## Test Session Overview
- **Session ID**: {session["session_id"]}
- **Duration**: {session["total_duration_minutes"]:.1f} minutes
- **Date**: {session["start_time"][:10]}

## Overall Assessment: {summary["overall_status"]}

## Summary Statistics
- **Total Test Suites**: {summary["total_test_suites"]}
- **Successful Suites**: {summary["successful_suites"]}
- **Failed Suites**: {summary["failed_suites"]}
- **Critical Issues**: {summary["critical_suites"]}

## Test Results
- **Total Tests**: {summary["total_tests"]}
- **Passed**: {summary["total_passed"]}
- **Failed**: {summary["total_failed"]}
- **Errors**: {summary["total_errors"]}
- **Skipped**: {summary["total_skipped"]}
- **Success Rate**: {summary["overall_success_rate"]:.1%}

## Key Findings
"""
        
        for finding in report["key_findings"]:
            md += f"- {finding}\n"
        
        md += f"""
## Priority Recommendations
"""
        
        for i, rec in enumerate(report["recommendations"][:5], 1):
            md += f"{i}. {rec}\n"
        
        md += f"""
## Detailed Results by Suite

"""
        
        for result in report["suite_results"]:
            status_icon = {"PASS": "✅", "FAIL": "⚠️", "CRITICAL": "❌", "ERROR": "💥"}.get(result["status"], "❓")
            md += f"### {status_icon} {result['suite_name']}\n"
            md += f"- **Status**: {result['status']}\n"
            md += f"- **Success Rate**: {result['success_rate']:.1%}\n"
            md += f"- **Duration**: {result['duration_minutes']:.1f} minutes\n"
            md += f"- **Tests**: {result['passed_tests']}/{result['total_tests']} passed\n\n"
        
        md += f"""
---
*Report generated by MCP Testing Framework on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        return md
    
    def _display_test_summary(self, report: Dict[str, Any]):
        """Display test summary to console."""
        print("\n" + "=" * 80)
        print("🎯 COMPREHENSIVE TESTING COMPLETE")
        print("=" * 80)
        
        summary = report["summary"]
        session = report["session_info"]
        
        print(f"Session: {session['session_id']}")
        print(f"Duration: {session['total_duration_minutes']:.1f} minutes")
        print(f"Overall Status: {summary['overall_status']}")
        print()
        
        print("📊 Results Summary:")
        print(f"  Test Suites: {summary['successful_suites']}/{summary['total_test_suites']} successful")
        print(f"  Individual Tests: {summary['total_passed']}/{summary['total_tests']} passed ({summary['overall_success_rate']:.1%})")
        print(f"  Critical Issues: {summary['critical_suites']}")
        print(f"  Failed Suites: {summary['failed_suites']}")
        print()
        
        print("📈 Suite Breakdown:")
        for result in self.suite_results:
            status_icon = {"PASS": "✅", "FAIL": "⚠️", "CRITICAL": "❌", "ERROR": "💥"}.get(result.status, "❓")
            print(f"  {status_icon} {result.suite_name}: {result.success_rate:.1%} ({result.duration_minutes:.1f}m)")
        print()
        
        if report["key_findings"]:
            print("🔍 Key Findings:")
            for finding in report["key_findings"][:5]:
                print(f"  • {finding}")
            print()
        
        if report["recommendations"]:
            print("💡 Top Recommendations:")
            for i, rec in enumerate(report["recommendations"][:3], 1):
                print(f"  {i}. {rec}")
            print()
        
        print("📁 Results saved to: comprehensive_test_results/")
        print("=" * 80)


def main():
    """Main entry point for comprehensive testing."""
    parser = argparse.ArgumentParser(description="MCP Comprehensive Testing Suite")
    parser.add_argument(
        "--suites",
        nargs="*",
        choices=["framework", "stress", "security", "health"],
        help="Specific test suites to run (default: all)"
    )
    parser.add_argument(
        "--no-stress",
        action="store_true",
        help="Skip stress testing"
    )
    parser.add_argument(
        "--no-security",
        action="store_true",
        help="Skip security testing"
    )
    parser.add_argument(
        "--no-health",
        action="store_true",
        help="Skip health monitoring"
    )
    parser.add_argument(
        "--health-duration",
        type=int,
        default=2,
        help="Health monitoring duration in minutes (default: 2)"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick tests only (framework tests with reduced scope)"
    )
    
    args = parser.parse_args()
    
    async def run_tests():
        orchestrator = MCPTestOrchestrator()
        
        try:
            # Configure test parameters
            include_stress = not args.no_stress and not args.quick
            include_security = not args.no_security and not args.quick
            include_health = not args.no_health
            health_duration = 1 if args.quick else args.health_duration
            
            # Run comprehensive testing
            report = await orchestrator.run_comprehensive_testing(
                suites=args.suites,
                include_stress=include_stress,
                include_security=include_security,
                include_health_monitoring=include_health,
                monitoring_duration_minutes=health_duration
            )
            
            # Return appropriate exit code
            if report["summary"]["overall_status"] in ["CRITICAL", "ERROR"]:
                return 2  # Critical failure
            elif report["summary"]["overall_status"] == "FAIL":
                return 1  # Test failures
            else:
                return 0  # Success
                
        except KeyboardInterrupt:
            print("\n⏹️ Testing interrupted by user")
            return 130
        except Exception as e:
            print(f"\n💥 Testing orchestrator failed: {e}")
            import traceback
            traceback.print_exc()
            return 1
    
    # Run the tests
    exit_code = asyncio.run(run_tests())
    sys.exit(exit_code)


if __name__ == "__main__":
    main()