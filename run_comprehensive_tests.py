#!/usr/bin/env python3
"""
Comprehensive Test Runner for CODE Development

This script orchestrates the complete testing infrastructure including:
- Unit tests (Python and Rust)
- Integration tests (Python-Rust FFI)
- Performance benchmarks
- Security vulnerability scans
- End-to-end testing
- Memory safety validation

Usage:
    python run_comprehensive_tests.py [options]
"""

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Import our testing frameworks
sys.path.insert(0, str(Path(__file__).parent))

from tests.framework.test_orchestrator import TestOrchestrator, TestConfiguration
from tests.framework.ffi_integration_tester import FFIIntegrationTester
from tests.framework.performance_testing import PerformanceTestSuite
from tests.framework.test_automation import TestAutomation, TestJobConfig, TestExecutionMode, TestPriority, TestEnvironment

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'test_execution_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)


class ComprehensiveTestRunner:
    """Main test runner that orchestrates all testing frameworks."""
    
    def __init__(self, args):
        self.args = args
        self.start_time = datetime.now()
        self.results = {}
        
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all test suites comprehensively."""
        logger.info("Starting comprehensive test execution")
        logger.info(f"Test configuration: {vars(self.args)}")
        
        # Test execution plan
        test_plan = []
        
        if self.args.unit_tests:
            test_plan.append(("Unit Tests", self._run_unit_tests))
        
        if self.args.integration_tests:
            test_plan.append(("Integration Tests", self._run_integration_tests))
        
        if self.args.ffi_tests:
            test_plan.append(("FFI Tests", self._run_ffi_tests))
        
        if self.args.performance_tests:
            test_plan.append(("Performance Tests", self._run_performance_tests))
        
        if self.args.security_tests:
            test_plan.append(("Security Tests", self._run_security_tests))
        
        if self.args.e2e_tests:
            test_plan.append(("End-to-End Tests", self._run_e2e_tests))
        
        # Execute test plan
        for test_name, test_func in test_plan:
            logger.info(f"Executing: {test_name}")
            
            try:
                start_time = time.time()
                result = await test_func()
                duration = time.time() - start_time
                
                self.results[test_name] = {
                    'success': True,
                    'duration_seconds': duration,
                    'result': result
                }
                
                logger.info(f"{test_name} completed successfully in {duration:.2f} seconds")
                
                # Stop on first failure if fast-fail is enabled
                if self.args.fast_fail and not result.get('success', True):
                    logger.error(f"Fast-fail enabled, stopping due to {test_name} failure")
                    break
                    
            except Exception as e:
                duration = time.time() - start_time
                self.results[test_name] = {
                    'success': False,
                    'duration_seconds': duration,
                    'error': str(e)
                }
                
                logger.error(f"{test_name} failed after {duration:.2f} seconds: {e}")
                
                if self.args.fast_fail:
                    logger.error("Fast-fail enabled, stopping execution")
                    break
        
        # Generate final report
        return self._generate_final_report()
    
    async def _run_unit_tests(self) -> Dict[str, Any]:
        """Run unit tests for both Python and Rust components."""
        logger.info("Starting unit tests")
        
        # Use test automation framework
        automation = TestAutomation()
        
        job_config = TestJobConfig(
            job_id=f"unit_tests_{int(time.time())}",
            test_types=['rust_unit', 'python_unit'],
            execution_mode=TestExecutionMode.PARALLEL if self.args.parallel else TestExecutionMode.SEQUENTIAL,
            priority=TestPriority.HIGH,
            environment=TestEnvironment.CI if self.args.ci_mode else TestEnvironment.DEVELOPMENT,
            max_workers=self.args.max_workers,
            timeout_minutes=self.args.timeout_minutes
        )
        
        result = await automation.execute_test_job(job_config)
        
        return {
            'success': result.success,
            'test_results': result.test_results,
            'duration_seconds': result.duration_seconds,
            'artifacts': result.artifacts
        }
    
    async def _run_integration_tests(self) -> Dict[str, Any]:
        """Run integration tests."""
        logger.info("Starting integration tests")
        
        config = TestConfiguration(
            max_workers=self.args.max_workers,
            timeout_seconds=self.args.timeout_minutes * 60,
            enable_parallel=self.args.parallel
        )
        
        orchestrator = TestOrchestrator(config)
        report = await orchestrator.run_all_tests()
        
        # Save report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = f"tests/results/integration_test_report_{timestamp}.json"
        orchestrator.save_report(report, report_path)
        
        return {
            'success': report['summary']['status'] == 'PASS',
            'report': report,
            'report_path': report_path
        }
    
    async def _run_ffi_tests(self) -> Dict[str, Any]:
        """Run FFI integration tests."""
        logger.info("Starting FFI integration tests")
        
        tester = FFIIntegrationTester()
        report = await tester.run_comprehensive_test_suite()
        
        # Save report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = f"tests/results/ffi_test_report_{timestamp}.json"
        tester.save_report(report, report_path)
        
        return {
            'success': report['summary']['success_rate'] >= 0.9,
            'report': report,
            'report_path': report_path
        }
    
    async def _run_performance_tests(self) -> Dict[str, Any]:
        """Run performance benchmarks."""
        logger.info("Starting performance tests")
        
        test_suite = PerformanceTestSuite()
        report = await test_suite.run_comprehensive_suite()
        
        # Save report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = f"tests/results/performance_report_{timestamp}.json"
        test_suite.save_report(report, report_path)
        
        return {
            'success': report['summary']['successful'] > 0,
            'report': report,
            'report_path': report_path
        }
    
    async def _run_security_tests(self) -> Dict[str, Any]:
        """Run security vulnerability tests."""
        logger.info("Starting security tests")
        
        automation = TestAutomation()
        
        job_config = TestJobConfig(
            job_id=f"security_tests_{int(time.time())}",
            test_types=['security'],
            execution_mode=TestExecutionMode.SEQUENTIAL,  # Security tests should be sequential
            priority=TestPriority.CRITICAL,
            environment=TestEnvironment.CI if self.args.ci_mode else TestEnvironment.DEVELOPMENT,
            max_workers=1,
            timeout_minutes=self.args.timeout_minutes
        )
        
        result = await automation.execute_test_job(job_config)
        
        return {
            'success': result.success,
            'test_results': result.test_results,
            'duration_seconds': result.duration_seconds,
            'artifacts': result.artifacts
        }
    
    async def _run_e2e_tests(self) -> Dict[str, Any]:
        """Run end-to-end tests."""
        logger.info("Starting end-to-end tests")
        
        automation = TestAutomation()
        
        job_config = TestJobConfig(
            job_id=f"e2e_tests_{int(time.time())}",
            test_types=['e2e'],
            execution_mode=TestExecutionMode.SEQUENTIAL,  # E2E tests should be sequential
            priority=TestPriority.MEDIUM,
            environment=TestEnvironment.CI if self.args.ci_mode else TestEnvironment.DEVELOPMENT,
            max_workers=1,
            timeout_minutes=self.args.timeout_minutes * 2  # E2E tests might take longer
        )
        
        result = await automation.execute_test_job(job_config)
        
        return {
            'success': result.success,
            'test_results': result.test_results,
            'duration_seconds': result.duration_seconds,
            'artifacts': result.artifacts
        }
    
    def _generate_final_report(self) -> Dict[str, Any]:
        """Generate comprehensive final report."""
        end_time = datetime.now()
        total_duration = (end_time - self.start_time).total_seconds()
        
        # Calculate overall statistics
        total_tests = len(self.results)
        successful_tests = len([r for r in self.results.values() if r['success']])
        failed_tests = total_tests - successful_tests
        
        overall_success = failed_tests == 0
        success_rate = successful_tests / total_tests if total_tests > 0 else 0.0
        
        # Resource utilization summary
        import psutil
        system_info = {
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': psutil.virtual_memory().total / (1024 ** 3),
            'disk_usage_percent': psutil.disk_usage('/').percent,
            'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
        }
        
        report = {
            'session_info': {
                'session_id': f"comprehensive_test_{self.start_time.strftime('%Y%m%d_%H%M%S')}",
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'total_duration_seconds': total_duration,
                'test_configuration': vars(self.args),
                'system_info': system_info
            },
            'summary': {
                'overall_success': overall_success,
                'total_test_suites': total_tests,
                'successful_test_suites': successful_tests,
                'failed_test_suites': failed_tests,
                'success_rate': success_rate,
                'total_duration_seconds': total_duration
            },
            'test_suite_results': self.results,
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        # Check for failed test suites
        failed_suites = [name for name, result in self.results.items() if not result['success']]
        
        if failed_suites:
            recommendations.append(f"Address failures in: {', '.join(failed_suites)}")
        
        # Check for slow test suites
        slow_suites = [
            name for name, result in self.results.items() 
            if result.get('duration_seconds', 0) > 300  # 5 minutes
        ]
        
        if slow_suites:
            recommendations.append(f"Consider optimizing slow test suites: {', '.join(slow_suites)}")
        
        # Performance recommendations
        if 'Performance Tests' in self.results:
            perf_result = self.results['Performance Tests']
            if perf_result['success'] and 'report' in perf_result['result']:
                perf_score = perf_result['result']['report']['summary'].get('overall_performance_score', 0)
                if perf_score < 70:
                    recommendations.append("Performance score is below optimal. Consider hardware upgrades or code optimizations.")
        
        # Security recommendations
        if 'Security Tests' in self.results:
            sec_result = self.results['Security Tests']
            if not sec_result['success']:
                recommendations.append("Security vulnerabilities detected. Review and address security issues immediately.")
        
        if not recommendations:
            recommendations.append("All tests passed successfully. System is performing optimally.")
        
        return recommendations
    
    def save_final_report(self, report: Dict[str, Any]):
        """Save the final comprehensive report."""
        timestamp = self.start_time.strftime('%Y%m%d_%H%M%S')
        report_path = Path(f"tests/results/comprehensive_test_report_{timestamp}.json")
        
        # Ensure directory exists
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save JSON report
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Save human-readable summary
        summary_path = report_path.with_suffix('.md')
        with open(summary_path, 'w') as f:
            f.write(self._generate_markdown_summary(report))
        
        logger.info(f"Final report saved to: {report_path}")
        logger.info(f"Summary saved to: {summary_path}")
        
        return str(report_path)
    
    def _generate_markdown_summary(self, report: Dict[str, Any]) -> str:
        """Generate human-readable markdown summary."""
        summary = f"""# Comprehensive Test Report

## Session Information
- **Session ID**: {report['session_info']['session_id']}
- **Start Time**: {report['session_info']['start_time']}
- **Duration**: {report['session_info']['total_duration_seconds']:.2f} seconds
- **Configuration**: {report['session_info']['test_configuration']}

## Summary
- **Overall Success**: {'✅ PASS' if report['summary']['overall_success'] else '❌ FAIL'}
- **Success Rate**: {report['summary']['success_rate']:.1%}
- **Test Suites**: {report['summary']['successful_test_suites']}/{report['summary']['total_test_suites']} passed

## Test Suite Results
"""
        
        for suite_name, result in report['test_suite_results'].items():
            status = "✅ PASS" if result['success'] else "❌ FAIL"
            duration = result['duration_seconds']
            summary += f"- **{suite_name}**: {status} ({duration:.2f}s)\n"
            
            if not result['success'] and 'error' in result:
                summary += f"  - Error: {result['error']}\n"
        
        summary += f"\n## Recommendations\n"
        for recommendation in report['recommendations']:
            summary += f"- {recommendation}\n"
        
        summary += f"\n## System Information\n"
        system_info = report['session_info']['system_info']
        summary += f"- **CPU Cores**: {system_info['cpu_count']}\n"
        summary += f"- **Memory**: {system_info['memory_total_gb']:.1f} GB\n"
        summary += f"- **Disk Usage**: {system_info['disk_usage_percent']:.1f}%\n"
        
        return summary


def create_argument_parser():
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Comprehensive test runner for CODE development",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all tests
  python run_comprehensive_tests.py --all

  # Run only unit and integration tests
  python run_comprehensive_tests.py --unit-tests --integration-tests

  # Run tests in CI mode with parallel execution
  python run_comprehensive_tests.py --all --ci-mode --parallel --max-workers 8

  # Run performance tests only
  python run_comprehensive_tests.py --performance-tests --timeout-minutes 60
        """
    )
    
    # Test selection
    test_group = parser.add_argument_group('Test Selection')
    test_group.add_argument('--all', action='store_true', 
                           help='Run all test suites')
    test_group.add_argument('--unit-tests', action='store_true',
                           help='Run unit tests (Python and Rust)')
    test_group.add_argument('--integration-tests', action='store_true',
                           help='Run integration tests')
    test_group.add_argument('--ffi-tests', action='store_true',
                           help='Run FFI integration tests')
    test_group.add_argument('--performance-tests', action='store_true',
                           help='Run performance benchmarks')
    test_group.add_argument('--security-tests', action='store_true',
                           help='Run security vulnerability tests')
    test_group.add_argument('--e2e-tests', action='store_true',
                           help='Run end-to-end tests')
    
    # Execution options
    exec_group = parser.add_argument_group('Execution Options')
    exec_group.add_argument('--parallel', action='store_true',
                           help='Enable parallel test execution')
    exec_group.add_argument('--max-workers', type=int, default=8,
                           help='Maximum number of parallel workers (default: 8)')
    exec_group.add_argument('--timeout-minutes', type=int, default=30,
                           help='Timeout for individual test suites in minutes (default: 30)')
    exec_group.add_argument('--fast-fail', action='store_true',
                           help='Stop execution on first test failure')
    exec_group.add_argument('--ci-mode', action='store_true',
                           help='Run in CI mode with appropriate settings')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--verbose', '-v', action='store_true',
                             help='Enable verbose output')
    output_group.add_argument('--quiet', '-q', action='store_true',
                             help='Suppress non-essential output')
    output_group.add_argument('--output-dir', default='tests/results',
                             help='Output directory for test reports (default: tests/results)')
    
    return parser


async def main():
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Set up logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Handle --all flag
    if args.all:
        args.unit_tests = True
        args.integration_tests = True
        args.ffi_tests = True
        args.performance_tests = True
        args.security_tests = True
        args.e2e_tests = True
    
    # Validate that at least one test type is selected
    test_types_selected = any([
        args.unit_tests,
        args.integration_tests,
        args.ffi_tests,
        args.performance_tests,
        args.security_tests,
        args.e2e_tests
    ])
    
    if not test_types_selected:
        parser.error("At least one test type must be selected. Use --all to run all tests.")
    
    # Create test runner and execute
    runner = ComprehensiveTestRunner(args)
    
    try:
        logger.info("=" * 80)
        logger.info("COMPREHENSIVE TEST EXECUTION STARTING")
        logger.info("=" * 80)
        
        final_report = await runner.run_all_tests()
        report_path = runner.save_final_report(final_report)
        
        logger.info("=" * 80)
        logger.info("COMPREHENSIVE TEST EXECUTION COMPLETED")
        logger.info("=" * 80)
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"COMPREHENSIVE TEST EXECUTION SUMMARY")
        print(f"{'='*60}")
        print(f"Overall Status: {'✅ PASS' if final_report['summary']['overall_success'] else '❌ FAIL'}")
        print(f"Success Rate: {final_report['summary']['success_rate']:.1%}")
        print(f"Duration: {final_report['summary']['total_duration_seconds']:.2f} seconds")
        print(f"Test Suites: {final_report['summary']['successful_test_suites']}/{final_report['summary']['total_test_suites']} passed")
        print(f"Report: {report_path}")
        
        # Print test suite results
        print(f"\nTest Suite Results:")
        for suite_name, result in final_report['test_suite_results'].items():
            status = "✅ PASS" if result['success'] else "❌ FAIL"
            duration = result['duration_seconds']
            print(f"  {suite_name}: {status} ({duration:.2f}s)")
        
        # Print recommendations
        print(f"\nRecommendations:")
        for recommendation in final_report['recommendations']:
            print(f"  • {recommendation}")
        
        print(f"{'='*60}")
        
        # Exit with appropriate code
        sys.exit(0 if final_report['summary']['overall_success'] else 1)
        
    except KeyboardInterrupt:
        logger.warning("Test execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Test execution failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())