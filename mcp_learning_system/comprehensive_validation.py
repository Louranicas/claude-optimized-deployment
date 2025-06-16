#!/usr/bin/env python3
"""
Comprehensive validation of all error fixes implemented
"""

import os
import sys
import json
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict

@dataclass
class ValidationResult:
    """Result of a validation test"""
    test_name: str
    status: str  # PASS, FAIL, WARNING, SKIP
    details: str
    execution_time: float
    errors: List[str]
    warnings: List[str]

class ComprehensiveValidator:
    """Comprehensive validation of all implemented fixes"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.results: List[ValidationResult] = []
        
    def run_all_validations(self) -> Dict[str, Any]:
        """Run all validation tests"""
        print("Starting Comprehensive Error Fix Validation")
        print("=" * 80)
        
        validation_tests = [
            ("Python Dependencies", self.validate_python_dependencies),
            ("Rust Compilation", self.validate_rust_compilation),
            ("Security Framework", self.validate_security_framework),
            ("Input Validation", self.validate_input_validation),
            ("FFI Integration", self.validate_ffi_integration),
            ("System Integration", self.validate_system_integration),
        ]
        
        for test_name, test_func in validation_tests:
            print(f"\n--- Running {test_name} Validation ---")
            start_time = time.time()
            
            try:
                result = test_func()
                result.execution_time = time.time() - start_time
                self.results.append(result)
                
                status_icon = {
                    "PASS": "✅",
                    "FAIL": "❌", 
                    "WARNING": "⚠️",
                    "SKIP": "⏭️"
                }.get(result.status, "❓")
                
                print(f"{status_icon} {result.test_name}: {result.status}")
                print(f"   Details: {result.details}")
                
                if result.warnings:
                    for warning in result.warnings:
                        print(f"   Warning: {warning}")
                        
                if result.errors:
                    for error in result.errors:
                        print(f"   Error: {error}")
                        
            except Exception as e:
                result = ValidationResult(
                    test_name=test_name,
                    status="FAIL",
                    details=f"Test execution failed: {str(e)}",
                    execution_time=time.time() - start_time,
                    errors=[str(e)],
                    warnings=[]
                )
                self.results.append(result)
                print(f"❌ {test_name}: FAIL - {str(e)}")
        
        return self.generate_summary()
    
    def validate_python_dependencies(self) -> ValidationResult:
        """Validate Python ML dependencies are properly configured"""
        errors = []
        warnings = []
        
        # Check if requirements.txt exists and has proper versions
        req_file = self.project_root / "python_learning" / "requirements.txt"
        if not req_file.exists():
            errors.append("requirements.txt not found")
        else:
            content = req_file.read_text()
            required_packages = [
                "numpy>=1.24.0",
                "scikit-learn>=1.3.0", 
                "torch>=2.0.0",
                "pandas>=2.0.0",
                "transformers>=4.30.0"
            ]
            
            for package in required_packages:
                if package.split(">=")[0] not in content:
                    errors.append(f"Missing dependency: {package}")
                elif package not in content:
                    warnings.append(f"Dependency version may be outdated: {package}")
        
        # Test basic Python import capability
        try:
            result = subprocess.run([
                sys.executable, "-c", 
                "import numpy; print(f'numpy: {numpy.__version__}')"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                details = f"Python dependencies validation passed. {result.stdout.strip()}"
            else:
                errors.append(f"Failed to import numpy: {result.stderr}")
                details = "Python dependencies validation failed"
                
        except subprocess.TimeoutExpired:
            errors.append("Python dependency test timed out")
            details = "Python dependencies validation timed out"
        except Exception as e:
            errors.append(f"Python dependency test error: {e}")
            details = "Python dependencies validation error"
        
        status = "FAIL" if errors else ("WARNING" if warnings else "PASS")
        if not errors and not warnings:
            details = "All Python ML dependencies properly configured"
            
        return ValidationResult(
            test_name="Python Dependencies",
            status=status,
            details=details,
            execution_time=0.0,
            errors=errors,
            warnings=warnings
        )
    
    def validate_rust_compilation(self) -> ValidationResult:
        """Validate Rust core compiles successfully"""
        errors = []
        warnings = []
        
        rust_dir = self.project_root / "rust_core"
        if not rust_dir.exists():
            return ValidationResult(
                test_name="Rust Compilation",
                status="SKIP",
                details="Rust core directory not found",
                execution_time=0.0,
                errors=[],
                warnings=[]
            )
        
        try:
            # Test Rust compilation
            result = subprocess.run([
                "cargo", "check", "--quiet"
            ], cwd=rust_dir, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                details = "Rust core compilation successful"
                
                # Check for warnings in stderr
                if result.stderr and "warning:" in result.stderr:
                    warning_count = result.stderr.count("warning:")
                    warnings.append(f"Rust compilation has {warning_count} warnings")
                    
            else:
                errors.append(f"Rust compilation failed: {result.stderr}")
                details = "Rust core compilation failed"
                
        except subprocess.TimeoutExpired:
            errors.append("Rust compilation timed out")
            details = "Rust compilation validation timed out"
        except FileNotFoundError:
            errors.append("Cargo not found - Rust toolchain not installed")
            details = "Rust toolchain not available"
        except Exception as e:
            errors.append(f"Rust compilation test error: {e}")
            details = "Rust compilation validation error"
        
        status = "FAIL" if errors else ("WARNING" if warnings else "PASS")
        
        return ValidationResult(
            test_name="Rust Compilation",
            status=status,
            details=details,
            execution_time=0.0,
            errors=errors,
            warnings=warnings
        )
    
    def validate_security_framework(self) -> ValidationResult:
        """Validate security fixes are in place"""
        errors = []
        warnings = []
        
        # Check if input validation framework exists
        input_validator = self.project_root / "security" / "input_validator.py"
        if not input_validator.exists():
            errors.append("Input validation framework not found")
        else:
            # Test basic functionality
            try:
                result = subprocess.run([
                    sys.executable, "-c",
                    "import sys; sys.path.insert(0, '.'); "
                    "from security.input_validator import InputValidator; "
                    "v = InputValidator(); "
                    "r = v.validate_string('test'); "
                    "print(f'Validator working: {r.is_valid}')"
                ], cwd=self.project_root, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and "True" in result.stdout:
                    details = "Security input validation framework operational"
                else:
                    errors.append(f"Input validator test failed: {result.stderr}")
                    
            except Exception as e:
                errors.append(f"Security framework test error: {e}")
        
        # Check for externalized secrets (no hardcoded passwords/keys)
        config_files = list(self.project_root.rglob("*.yaml")) + list(self.project_root.rglob("*.toml"))
        secret_patterns = ["password", "secret", "key", "token"]
        
        for config_file in config_files:
            try:
                content = config_file.read_text().lower()
                for pattern in secret_patterns:
                    if f'{pattern}=' in content or f'{pattern}:' in content:
                        # Check if it's externalized (contains env var reference)
                        if "os.getenv" not in content and "env." not in content:
                            warnings.append(f"Potential hardcoded secret in {config_file.name}")
            except Exception:
                continue
        
        status = "FAIL" if errors else ("WARNING" if warnings else "PASS")
        if not errors and not warnings:
            details = "Security framework validation passed"
        elif not errors:
            details = "Security framework operational with minor issues"
        else:
            details = "Security framework validation failed"
            
        return ValidationResult(
            test_name="Security Framework",
            status=status,
            details=details,
            execution_time=0.0,
            errors=errors,
            warnings=warnings
        )
    
    def validate_input_validation(self) -> ValidationResult:
        """Validate input validation framework functionality"""
        errors = []
        warnings = []
        
        try:
            # Run the input validation test suite
            test_script = self.project_root / "test_input_validation.py"
            if not test_script.exists():
                errors.append("Input validation test script not found")
                details = "Input validation tests missing"
            else:
                result = subprocess.run([
                    sys.executable, str(test_script)
                ], cwd=self.project_root, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    details = "Input validation framework tests passed"
                    # Count passed tests from output
                    if "test suites passed" in result.stderr:
                        details += f" - {result.stderr.split('test suites passed')[0].split()[-1]} suites passed"
                else:
                    errors.append("Input validation tests failed")
                    details = "Input validation framework tests failed"
                    if result.stderr:
                        errors.append(result.stderr[-500:])  # Last 500 chars of error
                        
        except subprocess.TimeoutExpired:
            errors.append("Input validation tests timed out")
            details = "Input validation tests timed out"
        except Exception as e:
            errors.append(f"Input validation test error: {e}")
            details = "Input validation test execution error"
        
        status = "FAIL" if errors else ("WARNING" if warnings else "PASS")
        
        return ValidationResult(
            test_name="Input Validation",
            status=status,
            details=details,
            execution_time=0.0,
            errors=errors,
            warnings=warnings
        )
    
    def validate_ffi_integration(self) -> ValidationResult:
        """Validate FFI integration between Rust and Python"""
        errors = []
        warnings = []
        
        # Check if setup.py is properly configured
        setup_py = self.project_root / "python_learning" / "setup.py"
        if not setup_py.exists():
            errors.append("setup.py not found")
        else:
            content = setup_py.read_text()
            if "rust_extensions" not in content:
                warnings.append("setup.py may not be configured for Rust extensions")
            elif "setuptools_rust" not in content:
                warnings.append("setup.py missing setuptools_rust import")
        
        # Check if Cargo.toml has PyO3 dependencies
        cargo_toml = self.project_root / "rust_core" / "Cargo.toml"
        if cargo_toml.exists():
            content = cargo_toml.read_text()
            if "pyo3" not in content:
                warnings.append("Cargo.toml missing PyO3 dependencies")
            if "cdylib" not in content:
                warnings.append("Cargo.toml missing cdylib crate type for Python bindings")
        
        # Check if FFI module exists
        ffi_module = self.project_root / "rust_core" / "src" / "ffi.rs"
        if not ffi_module.exists():
            warnings.append("FFI module (ffi.rs) not found")
        else:
            content = ffi_module.read_text()
            if "#[pymodule]" not in content:
                warnings.append("FFI module missing PyO3 module definition")
        
        status = "FAIL" if errors else ("WARNING" if warnings else "PASS")
        
        if not errors and not warnings:
            details = "FFI integration configuration appears correct"
        elif not errors:
            details = "FFI integration configured with minor issues"
        else:
            details = "FFI integration configuration has errors"
            
        return ValidationResult(
            test_name="FFI Integration",
            status=status,
            details=details,
            execution_time=0.0,
            errors=errors,
            warnings=warnings
        )
    
    def validate_system_integration(self) -> ValidationResult:
        """Validate overall system integration"""
        errors = []
        warnings = []
        
        # Check if key system files exist
        key_files = [
            ("README.md", "Project documentation"),
            ("python_learning/requirements.txt", "Python dependencies"),
            ("rust_core/Cargo.toml", "Rust dependencies"),
            ("security/input_validator.py", "Security framework"),
        ]
        
        missing_files = []
        for file_path, description in key_files:
            if not (self.project_root / file_path).exists():
                missing_files.append(f"{description} ({file_path})")
        
        if missing_files:
            errors.extend(missing_files)
        
        # Check if project structure is intact
        expected_dirs = ["python_learning", "rust_core", "security", "servers"]
        missing_dirs = []
        for dir_name in expected_dirs:
            if not (self.project_root / dir_name).exists():
                missing_dirs.append(dir_name)
        
        if missing_dirs:
            warnings.extend([f"Directory missing: {d}" for d in missing_dirs])
        
        # Test if we can run basic validation
        try:
            # Simple test that our security framework can be imported
            result = subprocess.run([
                sys.executable, "-c",
                "import sys; sys.path.insert(0, '.'); "
                "from security.input_validator import validate_input; "
                "print('System integration test passed')"
            ], cwd=self.project_root, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                warnings.append("System integration test failed")
                
        except Exception as e:
            warnings.append(f"System integration test error: {e}")
        
        status = "FAIL" if errors else ("WARNING" if warnings else "PASS")
        
        if not errors and not warnings:
            details = "System integration validation passed"
        elif not errors:
            details = "System integration mostly complete with minor issues"
        else:
            details = "System integration validation failed"
            
        return ValidationResult(
            test_name="System Integration",
            status=status,
            details=details,
            execution_time=0.0,
            errors=errors,
            warnings=warnings
        )
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate comprehensive validation summary"""
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.status == "PASS")
        failed_tests = sum(1 for r in self.results if r.status == "FAIL")
        warning_tests = sum(1 for r in self.results if r.status == "WARNING")
        skipped_tests = sum(1 for r in self.results if r.status == "SKIP")
        
        total_execution_time = sum(r.execution_time for r in self.results)
        
        summary = {
            "validation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "warning_tests": warning_tests,
            "skipped_tests": skipped_tests,
            "total_execution_time": round(total_execution_time, 2),
            "overall_status": "PASS" if failed_tests == 0 else "FAIL",
            "results": [asdict(r) for r in self.results]
        }
        
        print("\n" + "=" * 80)
        print("COMPREHENSIVE VALIDATION SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"⚠️  Warnings: {warning_tests}")
        print(f"⏭️  Skipped: {skipped_tests}")
        print(f"Total Execution Time: {total_execution_time:.2f} seconds")
        print(f"Overall Status: {'✅ PASS' if summary['overall_status'] == 'PASS' else '❌ FAIL'}")
        
        return summary

def main():
    """Main validation function"""
    validator = ComprehensiveValidator()
    summary = validator.run_all_validations()
    
    # Save results to file
    results_file = Path(__file__).parent / "comprehensive_validation_results.json"
    with open(results_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\nDetailed results saved to: {results_file}")
    
    # Return success if no failures
    return summary['overall_status'] == 'PASS'

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)