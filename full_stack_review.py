#!/usr/bin/env python3
"""
Comprehensive Full Stack Review for Claude-Optimized Deployment Engine
This script performs an end-to-end review of all stack components
"""

import os
import sys
import json
import subprocess
import importlib
import asyncio
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
from datetime import datetime

class FullStackReview:
    def __init__(self):
        self.review_results = {
            "timestamp": datetime.now().isoformat(),
            "stack_components": {},
            "missing_dependencies": [],
            "configuration_issues": [],
            "runtime_issues": [],
            "security_findings": [],
            "recommendations": []
        }
        
    def check_system_requirements(self) -> Dict[str, Any]:
        """Check system-level requirements"""
        print("\n🔍 Checking System Requirements...")
        results = {}
        
        # Check Python version
        python_version = sys.version.split()[0]
        results['python_version'] = {
            'version': python_version,
            'status': 'pass' if python_version.startswith('3.12') else 'warning',
            'message': f'Python {python_version} detected'
        }
        
        # Check system commands
        commands = ['docker', 'kubectl', 'git', 'make', 'cargo', 'rustc']
        for cmd in commands:
            try:
                result = subprocess.run(['which', cmd], capture_output=True, text=True)
                results[cmd] = {
                    'installed': result.returncode == 0,
                    'path': result.stdout.strip() if result.returncode == 0 else None
                }
            except:
                results[cmd] = {'installed': False, 'path': None}
        
        return results
    
    def review_python_stack(self) -> Dict[str, Any]:
        """Review Python dependencies and modules"""
        print("\n🐍 Reviewing Python Stack...")
        results = {
            'core_packages': {},
            'optional_packages': {},
            'dev_packages': {}
        }
        
        # Core packages that must be installed
        core_packages = [
            'pydantic', 'aiohttp', 'aiofiles', 'fastapi', 'uvicorn',
            'sqlalchemy', 'tortoise', 'asyncpg', 'aiomysql', 'alembic',
            'jwt', 'bcrypt', 'cryptography', 'email_validator',
            'boto3', 'kubernetes', 'google.auth', 'openai', 'anthropic',
            'prometheus_client', 'opentelemetry', 'structlog', 'click', 'rich'
        ]
        
        # Optional but recommended packages
        optional_packages = [
            'redis', 'celery', 'flower', 'sentry_sdk', 'datadog',
            'numpy', 'pandas', 'matplotlib', 'seaborn', 'plotly'
        ]
        
        # Development packages
        dev_packages = [
            'pytest', 'pytest_asyncio', 'pytest_cov', 'pytest_benchmark',
            'black', 'ruff', 'mypy', 'bandit', 'safety',
            'sphinx', 'mkdocs', 'pre_commit'
        ]
        
        # Check each package group
        for package in core_packages:
            try:
                if package == 'google.auth':
                    importlib.import_module('google.auth')
                else:
                    importlib.import_module(package)
                results['core_packages'][package] = 'installed'
            except ImportError:
                results['core_packages'][package] = 'missing'
                self.review_results['missing_dependencies'].append(package)
        
        for package in optional_packages:
            try:
                importlib.import_module(package)
                results['optional_packages'][package] = 'installed'
            except ImportError:
                results['optional_packages'][package] = 'not installed'
        
        for package in dev_packages:
            try:
                importlib.import_module(package.replace('-', '_'))
                results['dev_packages'][package] = 'installed'
            except ImportError:
                results['dev_packages'][package] = 'not installed'
        
        return results
    
    def review_infrastructure_stack(self) -> Dict[str, Any]:
        """Review infrastructure components"""
        print("\n🏗️ Reviewing Infrastructure Stack...")
        results = {}
        
        # Check Docker
        try:
            docker_result = subprocess.run(['docker', 'version'], capture_output=True, text=True)
            results['docker'] = {
                'installed': docker_result.returncode == 0,
                'running': 'Server' in docker_result.stdout if docker_result.returncode == 0 else False
            }
        except:
            results['docker'] = {'installed': False, 'running': False}
        
        # Check Kubernetes
        try:
            kubectl_result = subprocess.run(['kubectl', 'version', '--client'], capture_output=True, text=True)
            results['kubernetes'] = {
                'kubectl_installed': kubectl_result.returncode == 0,
                'version': kubectl_result.stdout.strip() if kubectl_result.returncode == 0 else None
            }
        except:
            results['kubernetes'] = {'kubectl_installed': False, 'version': None}
        
        # Check cloud CLI tools
        cloud_tools = ['aws', 'gcloud', 'az']
        for tool in cloud_tools:
            try:
                result = subprocess.run([tool, '--version'], capture_output=True, text=True)
                results[f'{tool}_cli'] = result.returncode == 0
            except:
                results[f'{tool}_cli'] = False
        
        return results
    
    def review_database_stack(self) -> Dict[str, Any]:
        """Review database components and connections"""
        print("\n💾 Reviewing Database Stack...")
        results = {}
        
        # Check for database drivers
        db_drivers = {
            'postgresql': 'asyncpg',
            'mysql': 'aiomysql',
            'sqlite': 'aiosqlite',
            'redis': 'redis',
            'mongodb': 'motor'
        }
        
        for db, driver in db_drivers.items():
            try:
                importlib.import_module(driver)
                results[db] = {'driver': driver, 'installed': True}
            except ImportError:
                results[db] = {'driver': driver, 'installed': False}
        
        # Check ORM support
        try:
            import tortoise
            results['tortoise_orm'] = True
        except:
            results['tortoise_orm'] = False
            
        try:
            import sqlalchemy
            results['sqlalchemy'] = True
        except:
            results['sqlalchemy'] = False
        
        return results
    
    def review_ai_ml_stack(self) -> Dict[str, Any]:
        """Review AI/ML components"""
        print("\n🤖 Reviewing AI/ML Stack...")
        results = {}
        
        # Check AI providers
        ai_providers = {
            'anthropic': 'anthropic',
            'openai': 'openai',
            'google_generativeai': 'google.generativeai',
            'huggingface': 'transformers',
            'langchain': 'langchain',
            'llamaindex': 'llama_index'
        }
        
        for provider, module in ai_providers.items():
            try:
                if '.' in module:
                    parts = module.split('.')
                    importlib.import_module(parts[0])
                else:
                    importlib.import_module(module)
                results[provider] = 'installed'
            except ImportError:
                results[provider] = 'not installed'
        
        # Check for local model support
        try:
            ollama_check = subprocess.run(['ollama', '--version'], capture_output=True, text=True)
            results['ollama'] = ollama_check.returncode == 0
        except:
            results['ollama'] = False
        
        return results
    
    def review_monitoring_stack(self) -> Dict[str, Any]:
        """Review monitoring and observability components"""
        print("\n📊 Reviewing Monitoring Stack...")
        results = {}
        
        # Check monitoring packages
        monitoring_packages = [
            'prometheus_client',
            'opentelemetry.api',
            'opentelemetry.sdk',
            'opentelemetry.instrumentation',
            'opentelemetry.exporter.otlp',
            'opentelemetry.exporter.jaeger',
            'datadog',
            'sentry_sdk',
            'structlog',
            'loguru'
        ]
        
        for package in monitoring_packages:
            try:
                if '.' in package:
                    parts = package.split('.')
                    mod = importlib.import_module(parts[0])
                    for part in parts[1:]:
                        mod = getattr(mod, part)
                else:
                    importlib.import_module(package)
                results[package] = 'installed'
            except (ImportError, AttributeError):
                results[package] = 'not installed'
        
        return results
    
    def review_security_stack(self) -> Dict[str, Any]:
        """Review security components"""
        print("\n🔐 Reviewing Security Stack...")
        results = {}
        
        # Security packages
        security_packages = [
            'cryptography',
            'jwt',
            'bcrypt',
            'passlib',
            'python_jose',
            'authlib',
            'pyotp',
            'qrcode',
            'bandit',
            'safety'
        ]
        
        for package in security_packages:
            try:
                importlib.import_module(package.replace('-', '_'))
                results[package] = 'installed'
            except ImportError:
                results[package] = 'not installed'
        
        # Check for SSL/TLS support
        try:
            import ssl
            results['ssl_support'] = {
                'available': True,
                'version': ssl.OPENSSL_VERSION
            }
        except:
            results['ssl_support'] = {'available': False}
        
        return results
    
    def review_web_framework_stack(self) -> Dict[str, Any]:
        """Review web framework components"""
        print("\n🌐 Reviewing Web Framework Stack...")
        results = {}
        
        # Web frameworks and servers
        web_components = {
            'fastapi': 'fastapi',
            'uvicorn': 'uvicorn',
            'gunicorn': 'gunicorn',
            'starlette': 'starlette',
            'pydantic': 'pydantic',
            'httpx': 'httpx',
            'requests': 'requests',
            'aiohttp': 'aiohttp',
            'websockets': 'websockets',
            'socketio': 'socketio'
        }
        
        for component, module in web_components.items():
            try:
                importlib.import_module(module)
                results[component] = 'installed'
            except ImportError:
                results[component] = 'not installed'
        
        return results
    
    def review_testing_stack(self) -> Dict[str, Any]:
        """Review testing framework components"""
        print("\n🧪 Reviewing Testing Stack...")
        results = {}
        
        # Testing frameworks
        testing_packages = [
            'pytest',
            'pytest_asyncio',
            'pytest_cov',
            'pytest_benchmark',
            'pytest_mock',
            'pytest_timeout',
            'hypothesis',
            'faker',
            'factory_boy',
            'responses',
            'vcr'
        ]
        
        for package in testing_packages:
            try:
                importlib.import_module(package.replace('-', '_'))
                results[package] = 'installed'
            except ImportError:
                results[package] = 'not installed'
        
        return results
    
    def check_environment_variables(self) -> Dict[str, Any]:
        """Check required environment variables"""
        print("\n🔧 Checking Environment Variables...")
        results = {}
        
        # Required variables
        required_vars = [
            'DATABASE_URL',
            'JWT_SECRET_KEY',
            'ENVIRONMENT'
        ]
        
        # AI provider keys (at least one required)
        ai_keys = [
            'ANTHROPIC_API_KEY',
            'OPENAI_API_KEY',
            'GOOGLE_GEMINI_API_KEY',
            'DEEPSEEK_API_KEY'
        ]
        
        # Optional but recommended
        optional_vars = [
            'REDIS_URL',
            'PROMETHEUS_URL',
            'SLACK_WEBHOOK_URL',
            'SENTRY_DSN',
            'AWS_ACCESS_KEY_ID',
            'AWS_SECRET_ACCESS_KEY',
            'AZURE_TENANT_ID',
            'GCP_PROJECT_ID'
        ]
        
        # Check required
        for var in required_vars:
            results[var] = {
                'set': var in os.environ,
                'value': '***' if var in os.environ else None,
                'required': True
            }
        
        # Check AI keys (at least one required)
        ai_key_found = False
        for var in ai_keys:
            is_set = var in os.environ
            if is_set:
                ai_key_found = True
            results[var] = {
                'set': is_set,
                'value': '***' if is_set else None,
                'required': 'at_least_one'
            }
        
        if not ai_key_found:
            self.review_results['configuration_issues'].append(
                "No AI provider API key found. At least one is required."
            )
        
        # Check optional
        for var in optional_vars:
            results[var] = {
                'set': var in os.environ,
                'value': '***' if var in os.environ else None,
                'required': False
            }
        
        return results
    
    def check_file_structure(self) -> Dict[str, Any]:
        """Check project file structure"""
        print("\n📁 Checking File Structure...")
        results = {}
        
        # Essential directories
        essential_dirs = [
            'src',
            'tests',
            'docs',
            'scripts',
            'examples',
            'rust_core'
        ]
        
        # Essential files
        essential_files = [
            'requirements.txt',
            'requirements-dev.txt',
            'pyproject.toml',
            'Makefile',
            'README.md',
            '.env.example'
        ]
        
        # Check directories
        for dir_name in essential_dirs:
            path = Path(dir_name)
            results[f'dir_{dir_name}'] = {
                'exists': path.exists(),
                'is_directory': path.is_dir() if path.exists() else None
            }
        
        # Check files
        for file_name in essential_files:
            path = Path(file_name)
            results[f'file_{file_name}'] = {
                'exists': path.exists(),
                'is_file': path.is_file() if path.exists() else None
            }
        
        return results
    
    def test_imports(self) -> Dict[str, Any]:
        """Test critical imports"""
        print("\n🧩 Testing Critical Imports...")
        results = {}
        
        critical_imports = [
            ('Circle of Experts', 'from src.circle_of_experts import EnhancedExpertManager'),
            ('MCP Manager', 'from src.mcp.manager import get_mcp_manager'),
            ('Core Exceptions', 'from src.core.exceptions import BaseDeploymentError'),
            ('Auth RBAC', 'from src.auth.rbac import RBACManager'),
            ('Database Models', 'from src.database.models import User'),
            ('Monitoring Metrics', 'from src.monitoring.metrics import MetricsCollector'),
            ('API Circuit Breaker', 'from src.api.circuit_breaker_api import CircuitBreakerAPI')
        ]
        
        for name, import_stmt in critical_imports:
            try:
                exec(import_stmt)
                results[name] = 'success'
            except Exception as e:
                results[name] = f'failed: {str(e)}'
                self.review_results['runtime_issues'].append(f"{name}: {str(e)}")
        
        return results
    
    def generate_report(self) -> str:
        """Generate comprehensive review report"""
        report = []
        report.append("=" * 80)
        report.append("FULL STACK REVIEW REPORT")
        report.append("=" * 80)
        report.append(f"Timestamp: {self.review_results['timestamp']}")
        report.append("")
        
        # Summary of findings
        report.append("SUMMARY OF FINDINGS:")
        report.append("-" * 40)
        report.append(f"Missing Dependencies: {len(self.review_results['missing_dependencies'])}")
        report.append(f"Configuration Issues: {len(self.review_results['configuration_issues'])}")
        report.append(f"Runtime Issues: {len(self.review_results['runtime_issues'])}")
        report.append(f"Security Findings: {len(self.review_results['security_findings'])}")
        
        # Detailed findings
        if self.review_results['missing_dependencies']:
            report.append("\nMISSING DEPENDENCIES:")
            report.append("-" * 40)
            for dep in self.review_results['missing_dependencies']:
                report.append(f"  - {dep}")
        
        if self.review_results['configuration_issues']:
            report.append("\nCONFIGURATION ISSUES:")
            report.append("-" * 40)
            for issue in self.review_results['configuration_issues']:
                report.append(f"  - {issue}")
        
        if self.review_results['runtime_issues']:
            report.append("\nRUNTIME ISSUES:")
            report.append("-" * 40)
            for issue in self.review_results['runtime_issues']:
                report.append(f"  - {issue}")
        
        # Stack component summary
        report.append("\nSTACK COMPONENTS:")
        report.append("-" * 40)
        for component, data in self.review_results['stack_components'].items():
            report.append(f"\n{component.upper()}:")
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        report.append(f"  {key}:")
                        for k, v in value.items():
                            report.append(f"    {k}: {v}")
                    else:
                        report.append(f"  {key}: {value}")
        
        return "\n".join(report)
    
    def run_full_review(self):
        """Run the complete full stack review"""
        print("🚀 Starting Full Stack Review...")
        
        # Run all reviews
        self.review_results['stack_components']['system'] = self.check_system_requirements()
        self.review_results['stack_components']['python'] = self.review_python_stack()
        self.review_results['stack_components']['infrastructure'] = self.review_infrastructure_stack()
        self.review_results['stack_components']['database'] = self.review_database_stack()
        self.review_results['stack_components']['ai_ml'] = self.review_ai_ml_stack()
        self.review_results['stack_components']['monitoring'] = self.review_monitoring_stack()
        self.review_results['stack_components']['security'] = self.review_security_stack()
        self.review_results['stack_components']['web_framework'] = self.review_web_framework_stack()
        self.review_results['stack_components']['testing'] = self.review_testing_stack()
        self.review_results['stack_components']['environment'] = self.check_environment_variables()
        self.review_results['stack_components']['file_structure'] = self.check_file_structure()
        self.review_results['stack_components']['imports'] = self.test_imports()
        
        # Generate and print report
        report = self.generate_report()
        print("\n" + report)
        
        # Save detailed results
        with open('full_stack_review_results.json', 'w') as f:
            json.dump(self.review_results, f, indent=2)
        print(f"\n📄 Detailed results saved to: full_stack_review_results.json")
        
        # Generate installation script if needed
        if self.review_results['missing_dependencies']:
            self.generate_installation_script()
    
    def generate_installation_script(self):
        """Generate script to install missing dependencies"""
        script_content = """#!/bin/bash
# Auto-generated installation script for missing dependencies

echo "Installing missing dependencies..."

# Activate virtual environment
source venv_bulletproof/bin/activate

# Install missing Python packages
"""
        
        for dep in self.review_results['missing_dependencies']:
            # Map import names to package names
            package_map = {
                'google.auth': 'google-auth',
                'jwt': 'PyJWT',
                'yaml': 'PyYAML',
                'cv2': 'opencv-python',
                'sklearn': 'scikit-learn',
                'skimage': 'scikit-image'
            }
            package_name = package_map.get(dep, dep)
            script_content += f"pip install {package_name}\n"
        
        script_content += """
echo "Installation complete!"
"""
        
        with open('install_missing_dependencies.sh', 'w') as f:
            f.write(script_content)
        os.chmod('install_missing_dependencies.sh', 0o755)
        print("\n📝 Installation script generated: install_missing_dependencies.sh")

if __name__ == "__main__":
    reviewer = FullStackReview()
    reviewer.run_full_review()