#!/usr/bin/env python3
"""
Testing Infrastructure Validation Script

Validates that the comprehensive testing infrastructure is properly configured
and all components are working correctly.
"""

import subprocess
import sys
from pathlib import Path
import json
import configparser
from typing import List, Dict, Any
import importlib.util


class TestingInfrastructureValidator:
    """Validate the testing infrastructure setup."""
    
    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path.cwd()
        self.errors = []
        self.warnings = []
        self.passed_checks = []
    
    def validate_all(self) -> bool:
        """Run all validation checks."""
        print("🧪 Validating Testing Infrastructure...")
        print("=" * 50)
        
        checks = [
            self.check_pytest_config,
            self.check_coverage_config,
            self.check_mutation_config,
            self.check_hypothesis_config,
            self.check_test_dependencies,
            self.check_test_structure,
            self.check_conftest_files,
            self.check_makefile,
            self.check_ci_workflow,
            self.check_report_generation,
            self.check_fixtures,
            self.validate_sample_test_execution
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                self.errors.append(f"Error in {check.__name__}: {e}")
        
        self.print_summary()
        return len(self.errors) == 0
    
    def check_pytest_config(self):
        """Validate pytest.ini configuration."""
        pytest_ini = self.project_root / "pytest.ini"
        
        if not pytest_ini.exists():
            self.errors.append("pytest.ini not found")
            return
        
        config = configparser.ConfigParser()
        config.read(pytest_ini)
        
        # Check essential sections
        if not config.has_section('tool:pytest'):
            self.errors.append("pytest.ini missing [tool:pytest] section")
            return
        
        pytest_section = config['tool:pytest']
        
        # Check essential settings
        required_settings = {
            'testpaths': 'tests',
            'minversion': '7.0',
            'addopts': lambda v: '--cov=src' in v and '--cov-fail-under=80' in v
        }
        
        for setting, expected in required_settings.items():
            if setting not in pytest_section:
                self.errors.append(f"pytest.ini missing required setting: {setting}")
            elif callable(expected):
                if not expected(pytest_section[setting]):
                    self.errors.append(f"pytest.ini {setting} missing required values")
            elif pytest_section[setting] != expected:
                self.warnings.append(f"pytest.ini {setting} has unexpected value")
        
        # Check markers
        if 'markers' in pytest_section:
            markers = pytest_section['markers']
            required_markers = ['unit', 'integration', 'performance', 'security', 'property']
            for marker in required_markers:
                if marker not in markers:
                    self.warnings.append(f"pytest.ini missing recommended marker: {marker}")
        
        self.passed_checks.append("pytest.ini configuration")
    
    def check_coverage_config(self):
        """Validate coverage configuration."""
        pytest_ini = self.project_root / "pytest.ini"
        
        if not pytest_ini.exists():
            return  # Already reported in pytest check
        
        config = configparser.ConfigParser()
        config.read(pytest_ini)
        
        # Check coverage sections
        coverage_sections = ['coverage:run', 'coverage:report', 'coverage:html', 'coverage:xml']
        for section in coverage_sections:
            if not config.has_section(section):
                self.warnings.append(f"pytest.ini missing coverage section: {section}")
        
        # Check coverage settings
        if config.has_section('coverage:run'):
            run_section = config['coverage:run']
            if 'source' not in run_section or 'src' not in run_section['source']:
                self.errors.append("Coverage source not properly configured")
            
            if 'branch' not in run_section or run_section['branch'] != 'true':
                self.warnings.append("Branch coverage not enabled")
        
        if config.has_section('coverage:report'):
            report_section = config['coverage:report']
            if 'fail_under' not in report_section:
                self.warnings.append("Coverage fail_under threshold not set")
            elif int(report_section['fail_under']) < 80:
                self.warnings.append("Coverage threshold below recommended 80%")
        
        self.passed_checks.append("Coverage configuration")
    
    def check_mutation_config(self):
        """Validate mutation testing configuration."""
        mutmut_ini = self.project_root / ".mutmut.ini"
        
        if not mutmut_ini.exists():
            self.warnings.append(".mutmut.ini not found - mutation testing not configured")
            return
        
        config = configparser.ConfigParser()
        config.read(mutmut_ini)
        
        if not config.has_section('mutmut'):
            self.errors.append(".mutmut.ini missing [mutmut] section")
            return
        
        mutmut_section = config['mutmut']
        
        # Check essential settings
        required_settings = ['paths_to_mutate', 'runner']
        for setting in required_settings:
            if setting not in mutmut_section:
                self.errors.append(f".mutmut.ini missing required setting: {setting}")
        
        if 'paths_to_mutate' in mutmut_section and 'src/' not in mutmut_section['paths_to_mutate']:
            self.warnings.append("Mutation testing not targeting src/ directory")
        
        self.passed_checks.append("Mutation testing configuration")
    
    def check_hypothesis_config(self):
        """Validate Hypothesis configuration."""
        hypothesis_ini = self.project_root / "hypothesis.ini"
        
        if not hypothesis_ini.exists():
            self.warnings.append("hypothesis.ini not found - property-based testing config missing")
            return
        
        config = configparser.ConfigParser()
        config.read(hypothesis_ini)
        
        if not config.has_section('hypothesis'):
            self.errors.append("hypothesis.ini missing [hypothesis] section")
            return
        
        # Check for profiles
        profiles = ['hypothesis:dev', 'hypothesis:ci', 'hypothesis:debug']
        for profile in profiles:
            if not config.has_section(profile):
                self.warnings.append(f"hypothesis.ini missing recommended profile: {profile}")
        
        self.passed_checks.append("Hypothesis configuration")
    
    def check_test_dependencies(self):
        """Validate test dependencies are properly defined."""
        requirements_files = [
            self.project_root / "requirements-testing.txt",
            self.project_root / "requirements-dev.txt"
        ]
        
        testing_requirements = None
        for req_file in requirements_files:
            if req_file.exists():
                testing_requirements = req_file
                break
        
        if not testing_requirements:
            self.warnings.append("No testing requirements file found")
            return
        
        with open(testing_requirements, 'r') as f:
            content = f.read()
        
        essential_packages = [
            'pytest>=7',
            'pytest-cov',
            'pytest-asyncio',
            'pytest-xdist',
            'pytest-html',
            'hypothesis',
            'mutmut'
        ]
        
        for package in essential_packages:
            package_name = package.split('>=')[0].split('==')[0]
            if package_name not in content:
                self.warnings.append(f"Testing dependency missing: {package_name}")
        
        self.passed_checks.append("Test dependencies")
    
    def check_test_structure(self):
        """Validate test directory structure."""
        tests_dir = self.project_root / "tests"
        
        if not tests_dir.exists():
            self.errors.append("tests/ directory not found")
            return
        
        required_dirs = [
            "unit",
            "integration", 
            "security",
            "performance"
        ]
        
        for dir_name in required_dirs:
            test_subdir = tests_dir / dir_name
            if not test_subdir.exists():
                self.warnings.append(f"tests/{dir_name}/ directory not found")
        
        # Check for __init__.py files
        for dir_path in tests_dir.rglob("*/"):
            if dir_path.is_dir() and not (dir_path / "__init__.py").exists():
                init_file = dir_path / "__init__.py"
                if not init_file.exists():
                    self.warnings.append(f"Missing __init__.py in {dir_path.relative_to(self.project_root)}")
        
        self.passed_checks.append("Test directory structure")
    
    def check_conftest_files(self):
        """Validate conftest.py files exist and are properly structured."""
        tests_dir = self.project_root / "tests"
        
        if not tests_dir.exists():
            return  # Already reported
        
        # Check main conftest.py
        main_conftest = tests_dir / "conftest.py"
        if not main_conftest.exists():
            self.errors.append("tests/conftest.py not found")
        else:
            self._validate_conftest_content(main_conftest, "main")
        
        # Check subdirectory conftest files
        subdirs = ["integration", "security", "performance"]
        for subdir in subdirs:
            conftest_path = tests_dir / subdir / "conftest.py"
            if conftest_path.exists():
                self._validate_conftest_content(conftest_path, subdir)
                self.passed_checks.append(f"{subdir} conftest.py")
            else:
                self.warnings.append(f"tests/{subdir}/conftest.py not found")
    
    def _validate_conftest_content(self, conftest_path: Path, context: str):
        """Validate conftest.py content."""
        try:
            with open(conftest_path, 'r') as f:
                content = f.read()
            
            # Check for pytest import
            if 'import pytest' not in content:
                self.warnings.append(f"{conftest_path.name} missing pytest import")
            
            # Check for fixture definitions
            if '@pytest.fixture' not in content:
                self.warnings.append(f"{conftest_path.name} contains no fixtures")
            
            # Context-specific checks
            if context == "security" and 'security' not in content.lower():
                self.warnings.append(f"Security conftest.py may not contain security-specific fixtures")
            
            if context == "performance" and 'performance' not in content.lower():
                self.warnings.append(f"Performance conftest.py may not contain performance-specific fixtures")
                
        except Exception as e:
            self.errors.append(f"Error reading {conftest_path}: {e}")
    
    def check_makefile(self):
        """Validate Makefile.testing exists and has required targets."""
        makefile = self.project_root / "Makefile.testing"
        
        if not makefile.exists():
            self.warnings.append("Makefile.testing not found")
            return
        
        with open(makefile, 'r') as f:
            content = f.read()
        
        required_targets = [
            'test-setup',
            'test',
            'test-unit',
            'test-integration',
            'test-security',
            'test-performance',
            'test-coverage',
            'test-mutation',
            'test-clean'
        ]
        
        for target in required_targets:
            if f"{target}:" not in content:
                self.warnings.append(f"Makefile.testing missing target: {target}")
        
        self.passed_checks.append("Makefile.testing")
    
    def check_ci_workflow(self):
        """Validate CI/CD workflow configuration."""
        workflow_file = self.project_root / ".github" / "workflows" / "comprehensive-testing.yml"
        
        if not workflow_file.exists():
            self.warnings.append("GitHub Actions comprehensive testing workflow not found")
            return
        
        with open(workflow_file, 'r') as f:
            content = f.read()
        
        required_elements = [
            'pytest',
            'coverage',
            'security',
            'performance',
            'quality-gates'
        ]
        
        for element in required_elements:
            if element not in content.lower():
                self.warnings.append(f"CI workflow missing: {element}")
        
        self.passed_checks.append("CI/CD workflow")
    
    def check_report_generation(self):
        """Validate test report generation script."""
        script_path = self.project_root / "scripts" / "generate_test_reports.py"
        
        if not script_path.exists():
            self.warnings.append("Test report generation script not found")
            return
        
        # Check if script is executable
        if not script_path.stat().st_mode & 0o111:
            self.warnings.append("Test report script not executable")
        
        self.passed_checks.append("Report generation script")
    
    def check_fixtures(self):
        """Validate test fixtures are properly organized."""
        fixtures_dir = self.project_root / "tests" / "fixtures"
        
        if fixtures_dir.exists():
            fixture_files = list(fixtures_dir.glob("*.py"))
            if fixture_files:
                self.passed_checks.append("Test fixtures directory")
            else:
                self.warnings.append("Test fixtures directory empty")
        else:
            self.warnings.append("Test fixtures directory not found")
    
    def validate_sample_test_execution(self):
        """Validate that pytest can run successfully."""
        try:
            # Try to run pytest with --collect-only to validate configuration
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "--collect-only", "-q"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                self.passed_checks.append("Pytest configuration validation")
            else:
                self.errors.append(f"Pytest configuration error: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.warnings.append("Pytest validation timed out")
        except Exception as e:
            self.warnings.append(f"Could not validate pytest execution: {e}")
    
    def print_summary(self):
        """Print validation summary."""
        print("\n" + "=" * 50)
        print("📋 VALIDATION SUMMARY")
        print("=" * 50)
        
        if self.passed_checks:
            print(f"\n✅ PASSED CHECKS ({len(self.passed_checks)}):")
            for check in self.passed_checks:
                print(f"   ✓ {check}")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   ⚠️  {warning}")
        
        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"   ❌ {error}")
        
        print(f"\n📊 RESULTS:")
        print(f"   Passed: {len(self.passed_checks)}")
        print(f"   Warnings: {len(self.warnings)}")
        print(f"   Errors: {len(self.errors)}")
        
        if len(self.errors) == 0:
            print(f"\n🎉 Testing infrastructure validation PASSED!")
            if len(self.warnings) > 0:
                print(f"   Consider addressing {len(self.warnings)} warnings for optimal setup.")
        else:
            print(f"\n💥 Testing infrastructure validation FAILED!")
            print(f"   Please fix {len(self.errors)} errors before proceeding.")
        
        return len(self.errors) == 0


def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate testing infrastructure")
    parser.add_argument("--project-root", help="Project root directory", default=".")
    
    args = parser.parse_args()
    
    validator = TestingInfrastructureValidator(Path(args.project_root))
    success = validator.validate_all()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()