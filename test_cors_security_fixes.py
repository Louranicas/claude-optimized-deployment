#!/usr/bin/env python3
"""
CORS Security Fixes Validation Test Suite

This test validates that all CORS misconfigurations have been properly fixed
and that the application now uses secure CORS policies instead of wildcards.
"""

import asyncio
import sys
import json
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import aiohttp
import subprocess

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from src.core.cors_config import (
    SecureCORSConfig, 
    Environment, 
    get_cors_config, 
    get_fastapi_cors_config,
    is_origin_allowed,
    reset_cors_config
)
from src.core.logging_config import setup_logging, get_logger
from src.auth.middleware import AuthMiddleware
from src.auth.tokens import TokenManager
from src.auth.rbac import RBACManager
from src.auth.permissions import PermissionChecker


class CORSSecurityTestSuite:
    """Comprehensive CORS security test suite."""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "test_type": "cors_security_validation",
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "security_issues": [],
            "tests": {}
        }
        
        # Setup logging
        setup_logging(log_level="INFO", enable_console=True, structured=False)
        self.logger = get_logger(__name__)
    
    def test_cors_config_initialization(self) -> Dict[str, Any]:
        """Test CORS configuration initialization for different environments."""
        test_result = {
            "test_name": "cors_config_initialization",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            # Test different environments
            environments = [Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION, Environment.TESTING]
            
            for env in environments:
                reset_cors_config()  # Reset for clean test
                config = SecureCORSConfig(env)
                
                # Check no wildcard origins
                has_wildcard = "*" in config.allowed_origins
                if has_wildcard:
                    test_result["issues"].append(f"Environment {env.value} still uses wildcard origins")
                
                # Check production security
                if env == Environment.PRODUCTION:
                    http_origins = [o for o in config.allowed_origins if o.startswith("http://")]
                    if http_origins:
                        test_result["issues"].append(f"Production environment allows HTTP origins: {http_origins}")
                    
                    localhost_origins = [o for o in config.allowed_origins if "localhost" in o]
                    if localhost_origins:
                        test_result["issues"].append(f"Production environment allows localhost origins: {localhost_origins}")
                
                test_result["details"][env.value] = {
                    "origins_count": len(config.allowed_origins),
                    "has_wildcard": has_wildcard,
                    "sample_origins": config.allowed_origins[:3],
                    "allows_credentials": config.allow_credentials
                }
            
            test_result["status"] = "passed" if not test_result["issues"] else "failed"
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"Configuration initialization failed: {str(e)}")
        
        return test_result
    
    def test_origin_validation(self) -> Dict[str, Any]:
        """Test origin validation logic."""
        test_result = {
            "test_name": "origin_validation",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            # Test various origins
            test_cases = [
                # Valid origins (should be allowed)
                ("http://localhost:3000", Environment.DEVELOPMENT, True),
                ("https://claude-optimized-deployment.com", Environment.PRODUCTION, True),
                ("https://staging.claude-optimized-deployment.com", Environment.STAGING, True),
                
                # Invalid origins (should be rejected)
                ("https://malicious-site.com", Environment.PRODUCTION, False),
                ("http://evil.com", Environment.PRODUCTION, False),
                ("*", Environment.PRODUCTION, False),
                ("null", Environment.PRODUCTION, False),
                
                # Environment-specific cases
                ("http://localhost:3000", Environment.PRODUCTION, False),  # localhost not allowed in prod
                ("https://claude-optimized-deployment.com", Environment.DEVELOPMENT, False),  # prod domain not in dev
            ]
            
            for origin, env, should_be_allowed in test_cases:
                reset_cors_config()
                config = SecureCORSConfig(env)
                is_allowed = config.is_origin_allowed(origin)
                
                if is_allowed != should_be_allowed:
                    test_result["issues"].append(
                        f"Origin '{origin}' in {env.value}: expected {should_be_allowed}, got {is_allowed}"
                    )
                
                test_result["details"][f"{origin}_{env.value}"] = {
                    "expected": should_be_allowed,
                    "actual": is_allowed,
                    "match": is_allowed == should_be_allowed
                }
            
            test_result["status"] = "passed" if not test_result["issues"] else "failed"
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"Origin validation failed: {str(e)}")
        
        return test_result
    
    def test_fastapi_cors_integration(self) -> Dict[str, Any]:
        """Test FastAPI CORS middleware integration."""
        test_result = {
            "test_name": "fastapi_cors_integration",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            # Test FastAPI CORS config generation
            environments = [Environment.DEVELOPMENT, Environment.PRODUCTION, Environment.TESTING]
            
            for env in environments:
                cors_config = get_fastapi_cors_config(env)
                
                # Check required fields
                required_fields = ["allow_origins", "allow_credentials", "allow_methods", "allow_headers"]
                for field in required_fields:
                    if field not in cors_config:
                        test_result["issues"].append(f"Missing required field '{field}' in {env.value} config")
                
                # Check no wildcards
                origins = cors_config.get("allow_origins", [])
                if "*" in origins:
                    test_result["issues"].append(f"Wildcard origins found in {env.value} FastAPI config")
                
                test_result["details"][env.value] = {
                    "origins_count": len(origins),
                    "has_wildcard": "*" in origins,
                    "config_keys": list(cors_config.keys())
                }
            
            test_result["status"] = "passed" if not test_result["issues"] else "failed"
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"FastAPI integration test failed: {str(e)}")
        
        return test_result
    
    def test_auth_middleware_cors(self) -> Dict[str, Any]:
        """Test auth middleware CORS implementation."""
        test_result = {
            "test_name": "auth_middleware_cors",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            # Create auth middleware instance
            token_manager = TokenManager()
            rbac_manager = RBACManager()
            permission_checker = PermissionChecker(rbac_manager)
            
            middleware = AuthMiddleware(
                token_manager=token_manager,
                rbac_manager=rbac_manager,
                permission_checker=permission_checker
            )
            
            # Check that it uses secure CORS config
            if "*" in middleware.allowed_origins:
                test_result["issues"].append("Auth middleware still uses wildcard origins")
            
            # Test CORS header generation
            test_origins = [
                "http://localhost:3000",
                "https://malicious-site.com",
                "https://claude-optimized-deployment.com"
            ]
            
            for origin in test_origins:
                headers = middleware.cors_config.get_manual_cors_headers(origin)
                allowed = middleware.cors_config.is_origin_allowed(origin)
                
                if allowed and not headers:
                    test_result["issues"].append(f"No CORS headers generated for allowed origin: {origin}")
                elif not allowed and headers:
                    test_result["issues"].append(f"CORS headers generated for disallowed origin: {origin}")
                
                test_result["details"][f"origin_{origin}"] = {
                    "allowed": allowed,
                    "headers_count": len(headers),
                    "has_access_control_allow_origin": "Access-Control-Allow-Origin" in headers
                }
            
            test_result["status"] = "passed" if not test_result["issues"] else "failed"
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"Auth middleware test failed: {str(e)}")
        
        return test_result
    
    def test_security_report_generation(self) -> Dict[str, Any]:
        """Test security report generation."""
        test_result = {
            "test_name": "security_report_generation",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            environments = [Environment.DEVELOPMENT, Environment.PRODUCTION, Environment.TESTING]
            
            for env in environments:
                reset_cors_config()
                config = SecureCORSConfig(env)
                report = config.get_security_report()
                
                # Check report structure
                required_fields = ["environment", "total_origins", "security_analysis"]
                for field in required_fields:
                    if field not in report:
                        test_result["issues"].append(f"Missing field '{field}' in {env.value} security report")
                
                # Check security analysis
                security_analysis = report.get("security_analysis", {})
                
                # Should not use wildcards
                if security_analysis.get("uses_wildcard", False):
                    test_result["issues"].append(f"Security report shows wildcard usage in {env.value}")
                
                # Production should not allow HTTP
                if env == Environment.PRODUCTION and security_analysis.get("allows_http_in_production", False):
                    test_result["issues"].append(f"Production environment allows HTTP origins")
                
                test_result["details"][env.value] = report
            
            test_result["status"] = "passed" if not test_result["issues"] else "failed"
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"Security report generation failed: {str(e)}")
        
        return test_result
    
    async def test_runtime_cors_behavior(self) -> Dict[str, Any]:
        """Test runtime CORS behavior with a test FastAPI app."""
        test_result = {
            "test_name": "runtime_cors_behavior",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            # Create test FastAPI app with secure CORS
            app = FastAPI(title="CORS Test App")
            
            # Add CORS middleware with secure config
            cors_config = get_fastapi_cors_config(Environment.TESTING)
            app.add_middleware(CORSMiddleware, **cors_config)
            
            @app.get("/test")
            async def test_endpoint():
                return {"message": "test"}
            
            @app.options("/test")
            async def test_options():
                return {"message": "options"}
            
            # Start test server
            config = uvicorn.Config(app, host="127.0.0.1", port=8001, log_level="error")
            server = uvicorn.Server(config)
            
            # Run server in background
            server_task = asyncio.create_task(server.serve())
            await asyncio.sleep(1)  # Wait for server to start
            
            try:
                # Test different origins
                test_origins = [
                    ("http://localhost:3000", True),   # Should be allowed in testing
                    ("https://malicious-site.com", False),  # Should be rejected
                    ("http://127.0.0.1:8000", True),  # Should be allowed in testing
                ]
                
                async with aiohttp.ClientSession() as session:
                    for origin, should_be_allowed in test_origins:
                        # Test OPTIONS request (preflight)
                        headers = {
                            "Origin": origin,
                            "Access-Control-Request-Method": "GET",
                            "Access-Control-Request-Headers": "Content-Type"
                        }
                        
                        async with session.options(
                            "http://127.0.0.1:8001/test",
                            headers=headers
                        ) as response:
                            cors_origin = response.headers.get("Access-Control-Allow-Origin")
                            
                            if should_be_allowed:
                                if cors_origin != origin:
                                    test_result["issues"].append(
                                        f"Expected origin '{origin}' in CORS header, got '{cors_origin}'"
                                    )
                            else:
                                if cors_origin == origin:
                                    test_result["issues"].append(
                                        f"Disallowed origin '{origin}' was accepted"
                                    )
                            
                            test_result["details"][f"preflight_{origin}"] = {
                                "status_code": response.status,
                                "cors_origin": cors_origin,
                                "expected_allowed": should_be_allowed,
                                "actually_allowed": cors_origin == origin
                            }
                        
                        # Test actual GET request
                        async with session.get(
                            "http://127.0.0.1:8001/test",
                            headers={"Origin": origin}
                        ) as response:
                            cors_origin = response.headers.get("Access-Control-Allow-Origin")
                            
                            test_result["details"][f"request_{origin}"] = {
                                "status_code": response.status,
                                "cors_origin": cors_origin,
                                "expected_allowed": should_be_allowed,
                                "actually_allowed": cors_origin == origin
                            }
            
            finally:
                # Shutdown server
                server.should_exit = True
                await server_task
            
            test_result["status"] = "passed" if not test_result["issues"] else "failed"
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"Runtime CORS test failed: {str(e)}")
        
        return test_result
    
    def scan_codebase_for_cors_wildcards(self) -> Dict[str, Any]:
        """Scan codebase for remaining CORS wildcard usage."""
        test_result = {
            "test_name": "codebase_wildcard_scan",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            # Search for potential CORS wildcard patterns
            search_patterns = [
                r'allow_origins.*\["?\*"?\]',
                r'Access-Control-Allow-Origin.*\*',
                r'origin.*=.*\*',
                r'CORS.*\*'
            ]
            
            project_root = Path(__file__).parent
            python_files = list(project_root.rglob("*.py"))
            
            # Exclude test files and virtual environments
            python_files = [
                f for f in python_files 
                if not any(exclude in str(f) for exclude in ["venv", "__pycache__", ".git", "test_cors_security_fixes.py"])
            ]
            
            wildcard_found = False
            
            for pattern in search_patterns:
                try:
                    result = subprocess.run(
                        ["grep", "-r", "-n", "--include=*.py", pattern, str(project_root)],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        lines = result.stdout.strip().split('\n')
                        filtered_lines = [
                            line for line in lines 
                            if not any(exclude in line for exclude in [
                                "test_cors_security_fixes.py",
                                "venv/", 
                                "__pycache__/",
                                ".git/",
                                "# Allow additional origins"
                            ])
                        ]
                        
                        if filtered_lines:
                            wildcard_found = True
                            test_result["issues"].append(f"Wildcard CORS pattern found: {pattern}")
                            test_result["details"][f"pattern_{pattern}"] = filtered_lines[:5]  # First 5 matches
                
                except subprocess.SubprocessError:
                    # grep might not be available, skip this check
                    continue
            
            test_result["status"] = "failed" if wildcard_found else "passed"
            test_result["details"]["scanned_files"] = len(python_files)
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"Codebase scan failed: {str(e)}")
        
        return test_result
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all CORS security tests."""
        self.logger.info("Starting CORS Security Validation Test Suite")
        
        # List of all test methods
        tests = [
            self.test_cors_config_initialization,
            self.test_origin_validation,
            self.test_fastapi_cors_integration,
            self.test_auth_middleware_cors,
            self.test_security_report_generation,
            self.scan_codebase_for_cors_wildcards,
        ]
        
        # Add async test
        async_tests = [
            self.test_runtime_cors_behavior
        ]
        
        # Run synchronous tests
        for test_method in tests:
            self.results["total_tests"] += 1
            test_result = test_method()
            
            test_name = test_result["test_name"]
            self.results["tests"][test_name] = test_result
            
            if test_result["status"] == "passed":
                self.results["passed_tests"] += 1
                self.logger.info(f"✓ {test_name}: PASSED")
            else:
                self.results["failed_tests"] += 1
                self.logger.error(f"✗ {test_name}: FAILED")
                
                # Add issues to security issues list
                self.results["security_issues"].extend(test_result.get("issues", []))
        
        # Run async tests
        for test_method in async_tests:
            self.results["total_tests"] += 1
            test_result = await test_method()
            
            test_name = test_result["test_name"]
            self.results["tests"][test_name] = test_result
            
            if test_result["status"] == "passed":
                self.results["passed_tests"] += 1
                self.logger.info(f"✓ {test_name}: PASSED")
            else:
                self.results["failed_tests"] += 1
                self.logger.error(f"✗ {test_name}: FAILED")
                
                # Add issues to security issues list
                self.results["security_issues"].extend(test_result.get("issues", []))
        
        # Generate summary
        self.results["summary"] = {
            "all_tests_passed": self.results["failed_tests"] == 0,
            "security_compliant": len(self.results["security_issues"]) == 0,
            "pass_rate": self.results["passed_tests"] / self.results["total_tests"] if self.results["total_tests"] > 0 else 0
        }
        
        return self.results


async def main():
    """Main test runner."""
    print("\n🔒 CORS Security Fixes Validation Test Suite")
    print("=" * 60)
    
    test_suite = CORSSecurityTestSuite()
    
    try:
        results = await test_suite.run_all_tests()
        
        # Print summary
        print(f"\n📊 Test Results Summary:")
        print(f"Total Tests: {results['total_tests']}")
        print(f"Passed: {results['passed_tests']}")
        print(f"Failed: {results['failed_tests']}")
        print(f"Pass Rate: {results['summary']['pass_rate']:.1%}")
        
        if results["security_issues"]:
            print(f"\n🚨 Security Issues Found ({len(results['security_issues'])}):")
            for issue in results["security_issues"]:
                print(f"  - {issue}")
        else:
            print(f"\n✅ No security issues found - CORS is properly configured!")
        
        # Save detailed results
        results_file = Path("cors_security_test_results.json")
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n📄 Detailed results saved to: {results_file}")
        
        # Exit with appropriate code
        if results["summary"]["all_tests_passed"] and results["summary"]["security_compliant"]:
            print("\n🎉 All CORS security tests passed!")
            return 0
        else:
            print("\n❌ Some CORS security tests failed!")
            return 1
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))