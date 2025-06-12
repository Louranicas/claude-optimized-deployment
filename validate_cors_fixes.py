#!/usr/bin/env python3
"""
Simple CORS Security Validation Script

Validates that CORS misconfigurations have been fixed without requiring additional dependencies.
"""

import sys
import json
import re
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from src.core.cors_config import SecureCORSConfig, Environment, get_cors_config, reset_cors_config
    from src.core.logging_config import setup_logging, get_logger
except ImportError as e:
    print(f"❌ Failed to import required modules: {e}")
    sys.exit(1)


class CORSSecurityValidator:
    """Simple CORS security validator."""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "security_issues": [],
            "tests": {}
        }
        
        # Setup basic logging
        try:
            setup_logging(log_level="INFO", enable_console=True, structured=False)
            self.logger = get_logger(__name__)
        except:
            # Fallback to print if logging setup fails
            self.logger = None
    
    def log(self, message: str):
        """Log message with fallback to print."""
        if self.logger:
            self.logger.info(message)
        else:
            print(message)
    
    def test_cors_config_no_wildcards(self) -> Dict[str, Any]:
        """Test that CORS configuration doesn't use wildcards."""
        test_result = {
            "test_name": "cors_config_no_wildcards",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            environments = [Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION, Environment.TESTING]
            
            for env in environments:
                reset_cors_config()
                config = SecureCORSConfig(env)
                
                # Check for wildcards
                has_wildcard = "*" in config.allowed_origins
                if has_wildcard:
                    test_result["issues"].append(f"Environment {env.value} still uses wildcard origins")
                
                test_result["details"][env.value] = {
                    "origins_count": len(config.allowed_origins),
                    "has_wildcard": has_wildcard,
                    "sample_origins": config.allowed_origins[:3]
                }
            
            test_result["status"] = "passed" if not test_result["issues"] else "failed"
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"Configuration test failed: {str(e)}")
        
        return test_result
    
    def test_production_security(self) -> Dict[str, Any]:
        """Test production environment security settings."""
        test_result = {
            "test_name": "production_security",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            reset_cors_config()
            config = SecureCORSConfig(Environment.PRODUCTION)
            
            # Check for HTTP origins in production
            http_origins = [o for o in config.allowed_origins if o.startswith("http://")]
            if http_origins:
                test_result["issues"].append(f"Production allows HTTP origins: {http_origins}")
            
            # Check for localhost in production
            localhost_origins = [o for o in config.allowed_origins if "localhost" in o or "127.0.0.1" in o]
            if localhost_origins:
                test_result["issues"].append(f"Production allows localhost origins: {localhost_origins}")
            
            test_result["details"] = {
                "total_origins": len(config.allowed_origins),
                "http_origins": len(http_origins),
                "localhost_origins": len(localhost_origins),
                "all_https": all(o.startswith("https://") for o in config.allowed_origins)
            }
            
            test_result["status"] = "passed" if not test_result["issues"] else "failed"
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"Production security test failed: {str(e)}")
        
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
            # Test cases: (origin, environment, should_be_allowed)
            test_cases = [
                ("http://localhost:3000", Environment.DEVELOPMENT, True),
                ("https://claude-optimized-deployment.com", Environment.PRODUCTION, True),
                ("https://malicious-site.com", Environment.PRODUCTION, False),
                ("*", Environment.PRODUCTION, False),
                ("http://localhost:3000", Environment.PRODUCTION, False),
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
                    "correct": is_allowed == should_be_allowed
                }
            
            test_result["status"] = "passed" if not test_result["issues"] else "failed"
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"Origin validation test failed: {str(e)}")
        
        return test_result
    
    def scan_for_wildcard_patterns(self) -> Dict[str, Any]:
        """Scan source files for wildcard CORS patterns."""
        test_result = {
            "test_name": "wildcard_pattern_scan",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            project_root = Path(__file__).parent
            
            # Files to check
            target_files = [
                "test_api_functionality.py",
                "src/auth/middleware.py"
            ]
            
            wildcard_patterns = [
                r'allow_origins.*\[.*"\*".*\]',
                r'Access-Control-Allow-Origin.*\*',
                r'allowed_origins.*=.*\[.*"\*".*\]'
            ]
            
            files_with_wildcards = []
            
            for file_path in target_files:
                full_path = project_root / file_path
                if not full_path.exists():
                    continue
                
                try:
                    with open(full_path, 'r') as f:
                        content = f.read()
                    
                    for pattern in wildcard_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            files_with_wildcards.append((str(file_path), pattern, matches))
                            test_result["issues"].append(f"Wildcard pattern found in {file_path}: {pattern}")
                
                except Exception as e:
                    test_result["issues"].append(f"Error reading {file_path}: {str(e)}")
            
            test_result["details"] = {
                "files_checked": len(target_files),
                "wildcards_found": len(files_with_wildcards),
                "wildcard_files": files_with_wildcards
            }
            
            test_result["status"] = "passed" if not files_with_wildcards else "failed"
            
        except Exception as e:
            test_result["status"] = "failed" 
            test_result["error"] = str(e)
            test_result["issues"].append(f"Wildcard scan failed: {str(e)}")
        
        return test_result
    
    def test_fastapi_cors_integration(self) -> Dict[str, Any]:
        """Test FastAPI CORS configuration."""
        test_result = {
            "test_name": "fastapi_cors_integration",
            "status": "running",
            "details": {},
            "issues": []
        }
        
        try:
            from src.core.cors_config import get_fastapi_cors_config
            
            # Test configuration for different environments
            environments = [Environment.DEVELOPMENT, Environment.PRODUCTION, Environment.TESTING]
            
            for env in environments:
                cors_config = get_fastapi_cors_config(env)
                
                # Check required fields
                required_fields = ["allow_origins", "allow_credentials", "allow_methods", "allow_headers"]
                missing_fields = [f for f in required_fields if f not in cors_config]
                
                if missing_fields:
                    test_result["issues"].append(f"Missing fields in {env.value}: {missing_fields}")
                
                # Check for wildcards
                origins = cors_config.get("allow_origins", [])
                if "*" in origins:
                    test_result["issues"].append(f"Wildcard origins in {env.value} FastAPI config")
                
                test_result["details"][env.value] = {
                    "config_fields": list(cors_config.keys()),
                    "origins_count": len(origins),
                    "has_wildcard": "*" in origins,
                    "missing_fields": missing_fields
                }
            
            test_result["status"] = "passed" if not test_result["issues"] else "failed"
            
        except Exception as e:
            test_result["status"] = "failed"
            test_result["error"] = str(e)
            test_result["issues"].append(f"FastAPI integration test failed: {str(e)}")
        
        return test_result
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all validation tests."""
        self.log("🔒 Starting CORS Security Validation")
        
        # List of test methods
        tests = [
            self.test_cors_config_no_wildcards,
            self.test_production_security,
            self.test_origin_validation,
            self.test_fastapi_cors_integration,
            self.scan_for_wildcard_patterns,
        ]
        
        # Run tests
        for test_method in tests:
            self.results["total_tests"] += 1
            test_result = test_method()
            
            test_name = test_result["test_name"]
            self.results["tests"][test_name] = test_result
            
            if test_result["status"] == "passed":
                self.results["passed_tests"] += 1
                self.log(f"✓ {test_name}: PASSED")
            else:
                self.results["failed_tests"] += 1
                self.log(f"✗ {test_name}: FAILED")
                
                # Add issues to security issues list
                self.results["security_issues"].extend(test_result.get("issues", []))
        
        # Generate summary
        self.results["summary"] = {
            "all_tests_passed": self.results["failed_tests"] == 0,
            "security_compliant": len(self.results["security_issues"]) == 0,
            "pass_rate": self.results["passed_tests"] / self.results["total_tests"] if self.results["total_tests"] > 0 else 0
        }
        
        return self.results


def main():
    """Main validation runner."""
    print("\n🔒 CORS Security Validation")
    print("=" * 50)
    
    validator = CORSSecurityValidator()
    
    try:
        results = validator.run_all_tests()
        
        # Print summary
        print(f"\n📊 Validation Results:")
        print(f"Total Tests: {results['total_tests']}")
        print(f"Passed: {results['passed_tests']}")
        print(f"Failed: {results['failed_tests']}")
        print(f"Pass Rate: {results['summary']['pass_rate']:.1%}")
        
        if results["security_issues"]:
            print(f"\n🚨 Security Issues ({len(results['security_issues'])}):")
            for issue in results["security_issues"]:
                print(f"  - {issue}")
        else:
            print(f"\n✅ No security issues found!")
        
        # Save results
        results_file = Path("cors_validation_results.json")
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n📄 Results saved to: {results_file}")
        
        # Print test details
        print(f"\n📋 Test Details:")
        for test_name, test_result in results["tests"].items():
            status_icon = "✅" if test_result["status"] == "passed" else "❌"
            print(f"{status_icon} {test_name}")
            
            if test_result.get("issues"):
                for issue in test_result["issues"]:
                    print(f"    ⚠️ {issue}")
        
        # Return appropriate exit code
        if results["summary"]["all_tests_passed"] and results["summary"]["security_compliant"]:
            print(f"\n🎉 CORS security validation completed successfully!")
            return 0
        else:
            print(f"\n❌ CORS security validation found issues!")
            return 1
            
    except KeyboardInterrupt:
        print("\n\n⚠️ Validation interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Validation failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())