#!/usr/bin/env python3
"""
AGENT 1: Comprehensive Module Testing and Error Identification
Complete test suite for mcp_learning_system
"""

import os
import sys
import subprocess
import json
import traceback
from datetime import datetime
from pathlib import Path

class ComprehensiveTestSuite:
    def __init__(self):
        self.base_path = Path(__file__).parent
        self.errors = []
        self.warnings = []
        self.successes = []
        self.test_results = {
            "timestamp": datetime.now().isoformat(),
            "test_summary": {
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "warnings": 0
            },
            "errors": [],
            "warnings": [],
            "successes": []
        }
    
    def log_error(self, category, test_name, error_type, message, severity="HIGH"):
        """Log an error with categorization"""
        error_entry = {
            "category": category,
            "test_name": test_name,
            "error_type": error_type,
            "message": str(message),
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }
        self.errors.append(error_entry)
        self.test_results["errors"].append(error_entry)
        print(f"❌ [{severity}] {category}/{test_name}: {error_type} - {message}")
    
    def log_warning(self, category, test_name, message):
        """Log a warning"""
        warning_entry = {
            "category": category,
            "test_name": test_name,
            "message": str(message),
            "timestamp": datetime.now().isoformat()
        }
        self.warnings.append(warning_entry)
        self.test_results["warnings"].append(warning_entry)
        print(f"⚠️  {category}/{test_name}: {message}")
    
    def log_success(self, category, test_name, message):
        """Log a success"""
        success_entry = {
            "category": category,
            "test_name": test_name,
            "message": str(message),
            "timestamp": datetime.now().isoformat()
        }
        self.successes.append(success_entry)
        self.test_results["successes"].append(success_entry)
        print(f"✅ {category}/{test_name}: {message}")
    
    def test_rust_compilation(self):
        """Test Rust compilation and build process"""
        print("\n=== RUST COMPILATION TESTING ===")
        
        # Test main rust_core
        rust_core_path = self.base_path / "rust_core"
        if rust_core_path.exists():
            try:
                os.chdir(rust_core_path)
                result = subprocess.run(
                    ["cargo", "check"], 
                    capture_output=True, 
                    text=True, 
                    timeout=60
                )
                if result.returncode == 0:
                    self.log_success("rust_compilation", "rust_core", "Compilation successful")
                else:
                    self.log_error(
                        "rust_compilation", 
                        "rust_core", 
                        "COMPILATION_ERROR", 
                        result.stderr,
                        "CRITICAL"
                    )
            except subprocess.TimeoutExpired:
                self.log_error("rust_compilation", "rust_core", "TIMEOUT", "Compilation timeout", "HIGH")
            except Exception as e:
                self.log_error("rust_compilation", "rust_core", "EXCEPTION", str(e), "CRITICAL")
        else:
            self.log_error("rust_compilation", "rust_core", "MISSING_DIRECTORY", "rust_core directory not found", "CRITICAL")
        
        # Test server rust components
        servers_path = self.base_path / "servers"
        if servers_path.exists():
            for server_dir in servers_path.iterdir():
                if server_dir.is_dir():
                    rust_src_path = server_dir / "rust_src"
                    if rust_src_path.exists():
                        try:
                            os.chdir(rust_src_path)
                            result = subprocess.run(
                                ["cargo", "check"], 
                                capture_output=True, 
                                text=True, 
                                timeout=30
                            )
                            if result.returncode == 0:
                                self.log_success("rust_compilation", f"server_{server_dir.name}", "Compilation successful")
                            else:
                                self.log_error(
                                    "rust_compilation", 
                                    f"server_{server_dir.name}", 
                                    "COMPILATION_ERROR", 
                                    result.stderr,
                                    "HIGH"
                                )
                        except subprocess.TimeoutExpired:
                            self.log_error("rust_compilation", f"server_{server_dir.name}", "TIMEOUT", "Compilation timeout", "MEDIUM")
                        except Exception as e:
                            self.log_error("rust_compilation", f"server_{server_dir.name}", "EXCEPTION", str(e), "HIGH")
    
    def test_python_imports(self):
        """Test Python imports and dependencies"""
        print("\n=== PYTHON IMPORT TESTING ===")
        
        # Test python_learning module
        python_learning_path = self.base_path / "python_learning"
        if python_learning_path.exists():
            sys.path.insert(0, str(python_learning_path))
            
            # Test basic structure
            init_file = python_learning_path / "mcp_learning" / "__init__.py"
            if init_file.exists():
                self.log_success("python_imports", "mcp_learning_structure", "Module structure exists")
            else:
                self.log_error("python_imports", "mcp_learning_structure", "MISSING_INIT", "Missing __init__.py", "HIGH")
            
            # Test individual modules
            mcp_learning_modules = [
                "core", "algorithms", "orchestrator", "shared_memory", 
                "patterns", "metrics", "learning", "utils"
            ]
            
            for module_name in mcp_learning_modules:
                try:
                    module_path = python_learning_path / "mcp_learning" / f"{module_name}.py"
                    if module_path.exists():
                        # Try basic syntax checking
                        with open(module_path, 'r') as f:
                            compile(f.read(), str(module_path), 'exec')
                        self.log_success("python_imports", f"mcp_learning.{module_name}", "Module syntax valid")
                    else:
                        self.log_warning("python_imports", f"mcp_learning.{module_name}", "Module file not found")
                except SyntaxError as e:
                    self.log_error("python_imports", f"mcp_learning.{module_name}", "SYNTAX_ERROR", str(e), "HIGH")
                except Exception as e:
                    self.log_error("python_imports", f"mcp_learning.{module_name}", "IMPORT_ERROR", str(e), "MEDIUM")
        
        # Test server Python modules
        servers_path = self.base_path / "servers"
        if servers_path.exists():
            for server_dir in servers_path.iterdir():
                if server_dir.is_dir():
                    python_src_path = server_dir / "python_src"
                    if python_src_path.exists():
                        sys.path.insert(0, str(python_src_path))
                        
                        for py_file in python_src_path.glob("*.py"):
                            try:
                                with open(py_file, 'r') as f:
                                    compile(f.read(), str(py_file), 'exec')
                                self.log_success("python_imports", f"server_{server_dir.name}_{py_file.stem}", "Syntax valid")
                            except SyntaxError as e:
                                self.log_error("python_imports", f"server_{server_dir.name}_{py_file.stem}", "SYNTAX_ERROR", str(e), "HIGH")
                            except Exception as e:
                                self.log_error("python_imports", f"server_{server_dir.name}_{py_file.stem}", "ERROR", str(e), "MEDIUM")
    
    def test_configuration_parsing(self):
        """Test configuration file parsing"""
        print("\n=== CONFIGURATION TESTING ===")
        
        config_path = self.base_path / "config"
        if config_path.exists():
            # Test YAML config
            yaml_config = config_path / "config.yaml"
            if yaml_config.exists():
                try:
                    import yaml
                    with open(yaml_config, 'r') as f:
                        config = yaml.safe_load(f)
                    if config:
                        self.log_success("configuration", "yaml_parsing", "YAML config parsed successfully")
                    else:
                        self.log_warning("configuration", "yaml_parsing", "YAML config is empty")
                except ImportError:
                    self.log_error("configuration", "yaml_parsing", "MISSING_DEPENDENCY", "yaml module not available", "MEDIUM")
                except Exception as e:
                    self.log_error("configuration", "yaml_parsing", "PARSING_ERROR", str(e), "HIGH")
            
            # Test TOML config
            toml_config = config_path / "config.toml"
            if toml_config.exists():
                try:
                    import toml
                    with open(toml_config, 'r') as f:
                        config = toml.load(f)
                    self.log_success("configuration", "toml_parsing", "TOML config parsed successfully")
                except ImportError:
                    self.log_error("configuration", "toml_parsing", "MISSING_DEPENDENCY", "toml module not available", "MEDIUM")
                except Exception as e:
                    self.log_error("configuration", "toml_parsing", "PARSING_ERROR", str(e), "HIGH")
    
    def test_stress_testing_framework(self):
        """Test stress testing framework"""
        print("\n=== STRESS TESTING FRAMEWORK ===")
        
        stress_path = self.base_path / "stress_testing"
        if stress_path.exists():
            sys.path.insert(0, str(stress_path))
            
            # Test framework modules
            framework_modules = ["integration", "scenarios", "benchmarks", "monitoring", "validators"]
            for module_dir in framework_modules:
                module_path = stress_path / module_dir
                if module_path.exists() and module_path.is_dir():
                    # Check for __init__.py
                    init_file = module_path / "__init__.py"
                    if init_file.exists():
                        self.log_success("stress_testing", f"{module_dir}_structure", "Module structure exists")
                    else:
                        self.log_warning("stress_testing", f"{module_dir}_structure", "__init__.py missing")
                else:
                    self.log_warning("stress_testing", f"{module_dir}_structure", "Module directory missing")
    
    def test_learning_core(self):
        """Test learning core functionality"""
        print("\n=== LEARNING CORE TESTING ===")
        
        learning_core_path = self.base_path / "learning_core"
        if learning_core_path.exists():
            sys.path.insert(0, str(learning_core_path))
            
            # Test core modules
            core_modules = ["adaptive_learning", "cross_instance", "learning_core", "models", 
                          "optimization", "pattern_recognition", "persistence", "prediction_engine"]
            
            for module_name in core_modules:
                module_file = learning_core_path / f"{module_name}.py"
                if module_file.exists():
                    try:
                        with open(module_file, 'r') as f:
                            compile(f.read(), str(module_file), 'exec')
                        self.log_success("learning_core", module_name, "Module syntax valid")
                    except SyntaxError as e:
                        self.log_error("learning_core", module_name, "SYNTAX_ERROR", str(e), "HIGH")
                    except Exception as e:
                        self.log_error("learning_core", module_name, "ERROR", str(e), "MEDIUM")
                else:
                    self.log_warning("learning_core", module_name, "Module file not found")
    
    def test_dependency_availability(self):
        """Test critical dependency availability"""
        print("\n=== DEPENDENCY TESTING ===")
        
        critical_deps = [
            ("yaml", "MEDIUM"), ("json", "LOW"), ("os", "LOW"), ("sys", "LOW"),
            ("pathlib", "LOW"), ("asyncio", "HIGH"), ("subprocess", "MEDIUM")
        ]
        
        optional_deps = [
            ("numpy", "HIGH"), ("sklearn", "HIGH"), ("torch", "HIGH"), 
            ("pandas", "MEDIUM"), ("redis", "MEDIUM"), ("prometheus_client", "MEDIUM"),
            ("toml", "MEDIUM")
        ]
        
        for dep, severity in critical_deps:
            try:
                __import__(dep)
                self.log_success("dependencies", f"critical_{dep}", "Available")
            except ImportError:
                self.log_error("dependencies", f"critical_{dep}", "MISSING_DEPENDENCY", f"{dep} not available", severity)
        
        for dep, severity in optional_deps:
            try:
                __import__(dep)
                self.log_success("dependencies", f"optional_{dep}", "Available")
            except ImportError:
                self.log_warning("dependencies", f"optional_{dep}", f"{dep} not available (optional)")
    
    def test_file_structure_integrity(self):
        """Test file structure integrity"""
        print("\n=== FILE STRUCTURE TESTING ===")
        
        expected_dirs = [
            "rust_core", "python_learning", "servers", "stress_testing",
            "learning_core", "config", "monitoring"
        ]
        
        for dir_name in expected_dirs:
            dir_path = self.base_path / dir_name
            if dir_path.exists() and dir_path.is_dir():
                self.log_success("file_structure", f"directory_{dir_name}", "Directory exists")
            else:
                self.log_error("file_structure", f"directory_{dir_name}", "MISSING_DIRECTORY", f"{dir_name} directory not found", "HIGH")
        
        # Check for critical files
        critical_files = [
            "rust_core/Cargo.toml",
            "python_learning/requirements.txt",
            "config/config.yaml",
            "README.md"
        ]
        
        for file_path in critical_files:
            full_path = self.base_path / file_path
            if full_path.exists():
                self.log_success("file_structure", f"file_{file_path.replace('/', '_')}", "File exists")
            else:
                self.log_error("file_structure", f"file_{file_path.replace('/', '_')}", "MISSING_FILE", f"{file_path} not found", "MEDIUM")
    
    def run_all_tests(self):
        """Run all tests and generate comprehensive report"""
        print("🚀 Starting Comprehensive MCP Learning System Testing")
        print("=" * 60)
        
        # Change to base directory
        os.chdir(self.base_path)
        
        # Run all test categories
        self.test_file_structure_integrity()
        self.test_dependency_availability()
        self.test_configuration_parsing()
        self.test_python_imports()
        self.test_learning_core()
        self.test_stress_testing_framework()
        self.test_rust_compilation()
        
        # Calculate summary
        total_tests = len(self.errors) + len(self.warnings) + len(self.successes)
        self.test_results["test_summary"] = {
            "total_tests": total_tests,
            "passed": len(self.successes),
            "failed": len(self.errors),
            "warnings": len(self.warnings)
        }
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE TEST REPORT")
        print("=" * 60)
        
        summary = self.test_results["test_summary"]
        print(f"Total Tests: {summary['total_tests']}")
        print(f"✅ Passed: {summary['passed']}")
        print(f"❌ Failed: {summary['failed']}")
        print(f"⚠️  Warnings: {summary['warnings']}")
        
        if summary['failed'] > 0:
            print(f"\n🔥 CRITICAL ISSUES (Total: {summary['failed']})")
            print("-" * 40)
            
            # Group errors by severity
            critical_errors = [e for e in self.errors if e['severity'] == 'CRITICAL']
            high_errors = [e for e in self.errors if e['severity'] == 'HIGH']
            medium_errors = [e for e in self.errors if e['severity'] == 'MEDIUM']
            
            if critical_errors:
                print(f"\n🚨 CRITICAL ERRORS ({len(critical_errors)}):")
                for error in critical_errors:
                    print(f"  • {error['category']}/{error['test_name']}: {error['error_type']}")
                    print(f"    {error['message'][:100]}...")
            
            if high_errors:
                print(f"\n🔴 HIGH PRIORITY ERRORS ({len(high_errors)}):")
                for error in high_errors:
                    print(f"  • {error['category']}/{error['test_name']}: {error['error_type']}")
            
            if medium_errors:
                print(f"\n🟡 MEDIUM PRIORITY ERRORS ({len(medium_errors)}):")
                for error in medium_errors:
                    print(f"  • {error['category']}/{error['test_name']}: {error['error_type']}")
        
        # Save detailed report
        report_file = self.base_path / "comprehensive_test_results.json"
        with open(report_file, 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        
        # System Assessment
        print(f"\n🎯 SYSTEM READINESS ASSESSMENT")
        print("-" * 40)
        
        critical_count = len([e for e in self.errors if e['severity'] == 'CRITICAL'])
        high_count = len([e for e in self.errors if e['severity'] == 'HIGH'])
        
        if critical_count == 0 and high_count == 0:
            print("🟢 READY FOR PRODUCTION")
        elif critical_count == 0 and high_count <= 2:
            print("🟡 READY FOR TESTING (minor issues)")
        elif critical_count <= 1 and high_count <= 5:
            print("🟠 NEEDS ATTENTION (moderate issues)")
        else:
            print("🔴 NOT READY (significant issues)")

if __name__ == "__main__":
    test_suite = ComprehensiveTestSuite()
    test_suite.run_all_tests()