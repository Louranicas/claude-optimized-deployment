#!/usr/bin/env python3
"""
API Contract Test Runner

This script runs comprehensive API contract tests for the Claude-Optimized
Deployment Engine with various configurations and reporting options.
"""

import argparse
import asyncio
import os
import sys
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

def run_command(cmd: List[str], description: str) -> Dict[str, any]:
    """Run a command and capture results."""
    print(f"\n🔄 {description}")
    print(f"Command: {' '.join(cmd)}")
    
    start_time = datetime.now()
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=600  # 10 minute timeout
        )
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        success = result.returncode == 0
        print(f"{'✅' if success else '❌'} {description} ({'PASSED' if success else 'FAILED'}) in {duration:.1f}s")
        
        if not success:
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
        
        return {
            "success": success,
            "duration": duration,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": ' '.join(cmd)
        }
    
    except subprocess.TimeoutExpired:
        print(f"❌ {description} TIMED OUT")
        return {
            "success": False,
            "duration": 600,
            "returncode": -1,
            "stdout": "",
            "stderr": "Test timed out",
            "command": ' '.join(cmd)
        }
    except Exception as e:
        print(f"❌ {description} ERROR: {e}")
        return {
            "success": False,
            "duration": 0,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "command": ' '.join(cmd)
        }


def install_dependencies():
    """Install required dependencies for API testing."""
    print("📦 Installing API testing dependencies...")
    
    # Install main requirements
    result1 = run_command(
        ["pip", "install", "-r", "requirements.txt"],
        "Installing main requirements"
    )
    
    # Install API test specific requirements
    result2 = run_command(
        ["pip", "install", "-r", "requirements-api-tests.txt"],
        "Installing API test requirements"
    )
    
    return result1["success"] and result2["success"]


def run_basic_api_tests() -> Dict[str, any]:
    """Run basic API contract tests."""
    cmd = [
        "python", "-m", "pytest", 
        "tests/api/",
        "-m", "api_contract and not slow",
        "-v",
        "--tb=short",
        "--durations=10"
    ]
    
    return run_command(cmd, "Basic API Contract Tests")


def run_schema_validation_tests() -> Dict[str, any]:
    """Run OpenAPI schema validation tests."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/test_openapi_schema_validation.py",
        "tests/api/test_pydantic_schemas.py",
        "-v",
        "--tb=short"
    ]
    
    return run_command(cmd, "Schema Validation Tests")


def run_authentication_tests() -> Dict[str, any]:
    """Run authentication endpoint tests."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/test_authentication_endpoints.py",
        "-v",
        "--tb=short"
    ]
    
    return run_command(cmd, "Authentication Tests")


def run_error_handling_tests() -> Dict[str, any]:
    """Run error response validation tests."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/test_error_responses.py",
        "-v",
        "--tb=short"
    ]
    
    return run_command(cmd, "Error Handling Tests")


def run_rate_limiting_tests() -> Dict[str, any]:
    """Run rate limiting tests."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/test_rate_limiting.py",
        "-v",
        "--tb=short"
    ]
    
    return run_command(cmd, "Rate Limiting Tests")


def run_cors_tests() -> Dict[str, any]:
    """Run CORS header tests."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/test_cors_headers.py",
        "-v",
        "--tb=short"
    ]
    
    return run_command(cmd, "CORS Tests")


def run_content_type_tests() -> Dict[str, any]:
    """Run content-type handling tests."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/test_content_type_handling.py",
        "-v",
        "--tb=short"
    ]
    
    return run_command(cmd, "Content-Type Tests")


def run_versioning_tests() -> Dict[str, any]:
    """Run API versioning and compatibility tests."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/test_versioning_compatibility.py",
        "-v",
        "--tb=short"
    ]
    
    return run_command(cmd, "Versioning & Compatibility Tests")


def run_property_based_tests() -> Dict[str, any]:
    """Run property-based tests with schemathesis."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/test_schemathesis_integration.py",
        "-v",
        "--tb=short",
        "-m", "not slow"
    ]
    
    return run_command(cmd, "Property-Based Tests (Fast)")


def run_slow_property_based_tests() -> Dict[str, any]:
    """Run slow property-based tests."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/test_schemathesis_integration.py",
        "-v",
        "--tb=short",
        "-m", "slow",
        "--timeout=300"  # 5 minute timeout per test
    ]
    
    return run_command(cmd, "Property-Based Tests (Comprehensive)")


def run_coverage_tests() -> Dict[str, any]:
    """Run tests with coverage reporting."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/",
        "-m", "api_contract and not slow",
        "--cov=src",
        "--cov-report=html:htmlcov/api_tests",
        "--cov-report=json:coverage_api_tests.json",
        "--cov-report=term-missing",
        "-v"
    ]
    
    return run_command(cmd, "API Tests with Coverage")


def run_parallel_tests() -> Dict[str, any]:
    """Run tests in parallel for faster execution."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/",
        "-m", "api_contract and not slow",
        "-n", "auto",  # Use all CPU cores
        "--dist=loadfile",
        "-v"
    ]
    
    return run_command(cmd, "Parallel API Tests")


def generate_html_report() -> Dict[str, any]:
    """Generate HTML test report."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/",
        "-m", "api_contract and not slow",
        "--html=reports/api_contract_tests.html",
        "--self-contained-html",
        "-v"
    ]
    
    return run_command(cmd, "HTML Test Report Generation")


def generate_json_report() -> Dict[str, any]:
    """Generate JSON test report."""
    cmd = [
        "python", "-m", "pytest",
        "tests/api/",
        "-m", "api_contract and not slow",
        "--json-report",
        "--json-report-file=reports/api_contract_tests.json",
        "-v"
    ]
    
    return run_command(cmd, "JSON Test Report Generation")


def validate_openapi_schema() -> Dict[str, any]:
    """Validate the OpenAPI schema independently."""
    cmd = [
        "python", "-c",
        """
import requests
import json
from openapi_spec_validator import validate_spec
try:
    # Get OpenAPI schema
    response = requests.get('http://localhost:8000/docs/openapi.json', timeout=10)
    if response.status_code == 200:
        schema = response.json()
        validate_spec(schema)
        print('✅ OpenAPI schema is valid')
    else:
        print(f'❌ Cannot fetch schema: {response.status_code}')
        exit(1)
except Exception as e:
    print(f'❌ Schema validation failed: {e}')
    exit(1)
"""
    ]
    
    return run_command(cmd, "OpenAPI Schema Validation")


def create_test_summary(results: List[Dict[str, any]]) -> Dict[str, any]:
    """Create a summary of all test results."""
    summary = {
        "total_tests": len(results),
        "passed": sum(1 for r in results if r["success"]),
        "failed": sum(1 for r in results if not r["success"]),
        "total_duration": sum(r["duration"] for r in results),
        "timestamp": datetime.now().isoformat(),
        "results": results
    }
    
    summary["success_rate"] = (summary["passed"] / summary["total_tests"]) * 100
    
    return summary


def save_results(summary: Dict[str, any], output_file: str):
    """Save test results to file."""
    os.makedirs("reports", exist_ok=True)
    
    with open(f"reports/{output_file}", "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"📊 Results saved to reports/{output_file}")


def print_summary(summary: Dict[str, any]):
    """Print test summary."""
    print("\n" + "="*60)
    print("🧪 API CONTRACT TEST SUMMARY")
    print("="*60)
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Passed: {summary['passed']} ✅")
    print(f"Failed: {summary['failed']} ❌")
    print(f"Success Rate: {summary['success_rate']:.1f}%")
    print(f"Total Duration: {summary['total_duration']:.1f}s")
    print("="*60)
    
    if summary['failed'] > 0:
        print("\n❌ FAILED TESTS:")
        for result in summary['results']:
            if not result['success']:
                print(f"  • {result.get('description', 'Unknown test')}")
    
    print()


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description="API Contract Test Runner")
    parser.add_argument("--quick", action="store_true", 
                       help="Run only quick tests")
    parser.add_argument("--full", action="store_true",
                       help="Run all tests including slow ones")
    parser.add_argument("--coverage", action="store_true",
                       help="Run tests with coverage reporting")
    parser.add_argument("--parallel", action="store_true",
                       help="Run tests in parallel")
    parser.add_argument("--install-deps", action="store_true",
                       help="Install dependencies before running tests")
    parser.add_argument("--reports", action="store_true",
                       help="Generate HTML and JSON reports")
    parser.add_argument("--schema-only", action="store_true",
                       help="Run only schema validation tests")
    parser.add_argument("--auth-only", action="store_true",
                       help="Run only authentication tests")
    
    args = parser.parse_args()
    
    print("🚀 API Contract Test Runner")
    print(f"Working directory: {os.getcwd()}")
    print(f"Python version: {sys.version}")
    
    # Install dependencies if requested
    if args.install_deps:
        if not install_dependencies():
            print("❌ Failed to install dependencies")
            sys.exit(1)
    
    results = []
    
    # Run specific test suites based on arguments
    if args.schema_only:
        results.append(run_schema_validation_tests())
    elif args.auth_only:
        results.append(run_authentication_tests())
    elif args.quick:
        results.extend([
            run_basic_api_tests(),
            run_schema_validation_tests(),
            run_error_handling_tests()
        ])
    elif args.full:
        results.extend([
            run_basic_api_tests(),
            run_schema_validation_tests(),
            run_authentication_tests(),
            run_error_handling_tests(),
            run_rate_limiting_tests(),
            run_cors_tests(),
            run_content_type_tests(),
            run_versioning_tests(),
            run_property_based_tests(),
            run_slow_property_based_tests()
        ])
    else:
        # Default test suite
        results.extend([
            run_basic_api_tests(),
            run_schema_validation_tests(),
            run_authentication_tests(),
            run_error_handling_tests(),
            run_rate_limiting_tests(),
            run_cors_tests(),
            run_content_type_tests(),
            run_versioning_tests(),
            run_property_based_tests()
        ])
    
    # Run additional features if requested
    if args.coverage:
        results.append(run_coverage_tests())
    
    if args.parallel:
        results.append(run_parallel_tests())
    
    if args.reports:
        results.extend([
            generate_html_report(),
            generate_json_report()
        ])
    
    # Create and save summary
    summary = create_test_summary(results)
    save_results(summary, "api_contract_test_summary.json")
    print_summary(summary)
    
    # Exit with error code if any tests failed
    if summary['failed'] > 0:
        sys.exit(1)
    else:
        print("🎉 All API contract tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()