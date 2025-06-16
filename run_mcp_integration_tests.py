#!/usr/bin/env python3
"""
MCP Servers Comprehensive Integration Test Runner

This script runs all comprehensive integration tests for the 11 MCP servers
identified in the CODE project. It provides detailed reporting and can be
used for CI/CD pipelines or manual testing.

Usage:
    python run_mcp_integration_tests.py [options]

Options:
    --test-suite: Specific test suite to run (all, basic, security, failure, performance, auth)
    --servers: Comma-separated list of specific servers to test
    --parallel: Run tests in parallel (default: False)
    --report-format: Output format (console, json, html, junit)
    --output-file: Output file for reports
    --verbose: Verbose output
    --coverage: Generate coverage report
"""

import sys
import os
import argparse
import subprocess
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class MCPTestRunner:
    """Comprehensive test runner for MCP servers."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_directory = self.project_root / "tests" / "integration"
        self.results = {}
        
        # Available test suites
        self.test_suites = {
            "basic": "test_mcp_servers_comprehensive.py",
            "security": "test_mcp_security_scenarios.py", 
            "failure": "test_mcp_failure_scenarios.py",
            "performance": "test_mcp_performance_load.py",
            "auth": "test_mcp_authentication_authorization.py"
        }
        
        # MCP servers
        self.mcp_servers = [
            "BraveMCPServer",
            "DesktopCommanderMCPServer",
            "DockerMCPServer", 
            "KubernetesMCPServer",
            "AzureDevOpsMCPServer",
            "WindowsSystemMCPServer",
            "SlackNotificationMCPServer",
            "PrometheusMonitoringMCP",
            "SecurityScannerMCPServer",
            "S3StorageMCPServer",
            "CloudStorageMCP"
        ]
    
    def validate_environment(self) -> bool:
        """Validate test environment and dependencies."""
        logger.info("Validating test environment...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            logger.error("Python 3.8+ is required")
            return False
        
        # Check if pytest is available
        try:
            import pytest
            logger.info(f"pytest version: {pytest.__version__}")
        except ImportError:
            logger.error("pytest is not installed")
            return False
        
        # Check test directory exists
        if not self.test_directory.exists():
            logger.error(f"Test directory not found: {self.test_directory}")
            return False
        
        # Check test files exist
        missing_files = []
        for suite_name, file_name in self.test_suites.items():
            test_file = self.test_directory / file_name
            if not test_file.exists():
                missing_files.append(file_name)
        
        if missing_files:
            logger.error(f"Missing test files: {missing_files}")
            return False
        
        # Check if project modules can be imported
        try:
            from src.mcp.servers import BraveMCPServer
            from src.mcp.devops_servers import AzureDevOpsMCPServer
            from src.mcp.infrastructure_servers import DesktopCommanderMCPServer
            logger.info("Core MCP modules imported successfully")
        except ImportError as e:
            logger.error(f"Failed to import MCP modules: {e}")
            return False
        
        logger.info("Environment validation successful")
        return True
    
    def run_test_suite(
        self,
        suite_name: str,
        servers: Optional[List[str]] = None,
        parallel: bool = False,
        verbose: bool = False,
        coverage: bool = False
    ) -> Dict[str, Any]:
        """Run a specific test suite."""
        if suite_name not in self.test_suites:
            raise ValueError(f"Unknown test suite: {suite_name}")
        
        test_file = self.test_directory / self.test_suites[suite_name]
        
        logger.info(f"Running test suite: {suite_name}")
        logger.info(f"Test file: {test_file}")
        
        # Build pytest command
        cmd = ["python", "-m", "pytest", str(test_file)]
        
        # Add options
        if verbose:
            cmd.extend(["-v", "-s"])
        else:
            cmd.append("-q")
        
        if parallel:
            cmd.extend(["-n", "auto"])  # Requires pytest-xdist
        
        if coverage:
            cmd.extend([
                "--cov=src.mcp",
                "--cov-report=term-missing",
                "--cov-report=html:htmlcov"
            ])
        
        # Filter by servers if specified
        if servers:
            server_patterns = []
            for server in servers:
                server_patterns.extend(["-k", f"Test{server}"])
            cmd.extend(server_patterns)
        
        # Add JSON report
        json_report = self.project_root / f"test_results_{suite_name}.json"
        cmd.extend(["--json-report", f"--json-report-file={json_report}"])
        
        # Run tests
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minute timeout
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Parse results
            test_result = {
                "suite": suite_name,
                "duration": duration,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }
            
            # Try to load JSON report if available
            if json_report.exists():
                try:
                    with open(json_report) as f:
                        json_data = json.load(f)
                        test_result["detailed_results"] = json_data
                except Exception as e:
                    logger.warning(f"Failed to load JSON report: {e}")
            
            logger.info(f"Test suite {suite_name} completed in {duration:.2f}s")
            if result.returncode == 0:
                logger.info(f"✅ {suite_name} PASSED")
            else:
                logger.error(f"❌ {suite_name} FAILED")
            
            return test_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Test suite {suite_name} timed out")
            return {
                "suite": suite_name,
                "duration": 1800,
                "return_code": -1,
                "stdout": "",
                "stderr": "Test suite timed out",
                "success": False,
                "timeout": True
            }
        except Exception as e:
            logger.error(f"Failed to run test suite {suite_name}: {e}")
            return {
                "suite": suite_name,
                "duration": 0,
                "return_code": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False,
                "error": str(e)
            }
    
    def run_all_tests(
        self,
        suites: List[str] = None,
        servers: Optional[List[str]] = None,
        parallel: bool = False,
        verbose: bool = False,
        coverage: bool = False
    ) -> Dict[str, Any]:
        """Run all or specified test suites."""
        if suites is None:
            suites = list(self.test_suites.keys())
        
        logger.info(f"Running test suites: {suites}")
        if servers:
            logger.info(f"Filtering for servers: {servers}")
        
        overall_start = time.time()
        results = {}
        
        for suite in suites:
            try:
                result = self.run_test_suite(
                    suite, servers, parallel, verbose, coverage
                )
                results[suite] = result
            except Exception as e:
                logger.error(f"Failed to run suite {suite}: {e}")
                results[suite] = {
                    "suite": suite,
                    "success": False,
                    "error": str(e)
                }
        
        overall_end = time.time()
        overall_duration = overall_end - overall_start
        
        # Calculate summary statistics
        total_suites = len(results)
        passed_suites = sum(1 for r in results.values() if r.get("success", False))
        failed_suites = total_suites - passed_suites
        
        summary = {
            "total_duration": overall_duration,
            "total_suites": total_suites,
            "passed_suites": passed_suites,
            "failed_suites": failed_suites,
            "success_rate": passed_suites / total_suites if total_suites > 0 else 0,
            "results": results
        }
        
        logger.info(f"\n{'='*60}")
        logger.info(f"TEST SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Total Duration: {overall_duration:.2f}s")
        logger.info(f"Total Suites: {total_suites}")
        logger.info(f"Passed: {passed_suites}")
        logger.info(f"Failed: {failed_suites}")
        logger.info(f"Success Rate: {summary['success_rate']:.1%}")
        logger.info(f"{'='*60}")
        
        return summary
    
    def generate_report(
        self,
        results: Dict[str, Any],
        format_type: str = "console",
        output_file: Optional[str] = None
    ):
        """Generate test report in specified format."""
        if format_type == "console":
            self._generate_console_report(results)
        elif format_type == "json":
            self._generate_json_report(results, output_file)
        elif format_type == "html":
            self._generate_html_report(results, output_file)
        elif format_type == "junit":
            self._generate_junit_report(results, output_file)
        else:
            raise ValueError(f"Unknown report format: {format_type}")
    
    def _generate_console_report(self, results: Dict[str, Any]):
        """Generate console report."""
        print(f"\n{'='*80}")
        print(f"MCP SERVERS INTEGRATION TEST REPORT")
        print(f"{'='*80}")
        print(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Duration: {results['total_duration']:.2f}s")
        print(f"Success Rate: {results['success_rate']:.1%}")
        print()
        
        for suite_name, suite_result in results['results'].items():
            status = "✅ PASS" if suite_result.get("success", False) else "❌ FAIL"
            duration = suite_result.get("duration", 0)
            print(f"{suite_name:25} {status:10} {duration:8.2f}s")
            
            if not suite_result.get("success", False):
                stderr = suite_result.get("stderr", "")
                if stderr:
                    print(f"  Error: {stderr[:100]}...")
        
        print(f"\n{'='*80}")
    
    def _generate_json_report(self, results: Dict[str, Any], output_file: Optional[str]):
        """Generate JSON report."""
        report_data = {
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "summary": {
                "total_duration": results["total_duration"],
                "total_suites": results["total_suites"],
                "passed_suites": results["passed_suites"],
                "failed_suites": results["failed_suites"],
                "success_rate": results["success_rate"]
            },
            "suites": results["results"]
        }
        
        output_path = output_file or "mcp_test_report.json"
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"JSON report generated: {output_path}")
    
    def _generate_html_report(self, results: Dict[str, Any], output_file: Optional[str]):
        """Generate HTML report."""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>MCP Servers Integration Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .suite {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 3px; }}
        .pass {{ background-color: #d4edda; }}
        .fail {{ background-color: #f8d7da; }}
        .metrics {{ display: inline-block; margin: 0 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>MCP Servers Integration Test Report</h1>
        <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="metrics">
            <strong>Total Duration:</strong> {results['total_duration']:.2f}s
        </div>
        <div class="metrics">
            <strong>Success Rate:</strong> {results['success_rate']:.1%}
        </div>
        <div class="metrics">
            <strong>Passed:</strong> {results['passed_suites']}
        </div>
        <div class="metrics">
            <strong>Failed:</strong> {results['failed_suites']}
        </div>
    </div>
    
    <h2>Test Suites</h2>
"""
        
        for suite_name, suite_result in results['results'].items():
            success = suite_result.get("success", False)
            css_class = "pass" if success else "fail"
            status = "PASS" if success else "FAIL"
            duration = suite_result.get("duration", 0)
            
            html_content += f"""
    <div class="suite {css_class}">
        <h3>{suite_name} - {status} ({duration:.2f}s)</h3>
"""
            
            if not success:
                stderr = suite_result.get("stderr", "")
                html_content += f"<pre>{stderr}</pre>"
            
            html_content += "    </div>\n"
        
        html_content += """
</body>
</html>
"""
        
        output_path = output_file or "mcp_test_report.html"
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path}")
    
    def _generate_junit_report(self, results: Dict[str, Any], output_file: Optional[str]):
        """Generate JUnit XML report."""
        # Simple JUnit XML generation
        junit_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="{results['total_suites']}" failures="{results['failed_suites']}" time="{results['total_duration']:.3f}">
"""
        
        for suite_name, suite_result in results['results'].items():
            success = suite_result.get("success", False)
            duration = suite_result.get("duration", 0)
            
            junit_xml += f'  <testsuite name="{suite_name}" tests="1" failures="{0 if success else 1}" time="{duration:.3f}">\n'
            junit_xml += f'    <testcase name="{suite_name}" time="{duration:.3f}"'
            
            if not success:
                stderr = suite_result.get("stderr", "")
                junit_xml += f'>\n      <failure message="Test suite failed">{stderr}</failure>\n    </testcase>\n'
            else:
                junit_xml += '/>\n'
            
            junit_xml += '  </testsuite>\n'
        
        junit_xml += '</testsuites>\n'
        
        output_path = output_file or "mcp_test_report.xml"
        with open(output_path, 'w') as f:
            f.write(junit_xml)
        
        logger.info(f"JUnit report generated: {output_path}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run comprehensive integration tests for MCP servers"
    )
    
    parser.add_argument(
        "--test-suite",
        choices=["all", "basic", "security", "failure", "performance", "auth"],
        default="all",
        help="Specific test suite to run"
    )
    
    parser.add_argument(
        "--servers",
        help="Comma-separated list of specific servers to test"
    )
    
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run tests in parallel"
    )
    
    parser.add_argument(
        "--report-format",
        choices=["console", "json", "html", "junit"],
        default="console",
        help="Output format for reports"
    )
    
    parser.add_argument(
        "--output-file",
        help="Output file for reports"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Generate coverage report"
    )
    
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate environment, don't run tests"
    )
    
    args = parser.parse_args()
    
    # Create test runner
    runner = MCPTestRunner()
    
    # Validate environment
    if not runner.validate_environment():
        logger.error("Environment validation failed")
        sys.exit(1)
    
    if args.validate_only:
        logger.info("Environment validation successful")
        sys.exit(0)
    
    # Parse servers list
    servers = None
    if args.servers:
        servers = [s.strip() for s in args.servers.split(",")]
        logger.info(f"Testing specific servers: {servers}")
    
    # Determine test suites to run
    suites = None
    if args.test_suite != "all":
        suites = [args.test_suite]
    
    try:
        # Run tests
        results = runner.run_all_tests(
            suites=suites,
            servers=servers,
            parallel=args.parallel,
            verbose=args.verbose,
            coverage=args.coverage
        )
        
        # Generate report
        runner.generate_report(
            results,
            format_type=args.report_format,
            output_file=args.output_file
        )
        
        # Exit with appropriate code
        if results["failed_suites"] > 0:
            logger.error("Some test suites failed")
            sys.exit(1)
        else:
            logger.info("All test suites passed")
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.info("Test run interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Test run failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()