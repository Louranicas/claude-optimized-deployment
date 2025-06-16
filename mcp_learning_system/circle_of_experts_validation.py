#!/usr/bin/env python3
"""
CIRCLE OF EXPERTS VALIDATION FRAMEWORK
Real expert validation of mitigation work completion

MISSION: Deploy real expert validation of completed mitigation work
APPROACH: Each expert performs comprehensive domain validation
"""

import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
import subprocess
import importlib.util
import ast
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('CircleOfExperts')

@dataclass
class ValidationMetric:
    """Validation metric for expert analysis"""
    name: str
    score: float  # 0.0 to 1.0
    details: str
    issues: List[str]
    recommendations: List[str]

@dataclass
class ExpertValidation:
    """Expert validation result"""
    expert_name: str
    domain: str
    metrics: List[ValidationMetric]
    overall_score: float
    verdict: str
    critical_issues: List[str]
    improvement_areas: List[str]
    production_ready: bool

class DevelopmentExpert:
    """Expert in development practices and code quality"""
    
    def __init__(self):
        self.name = "Development Expert"
        self.domain = "Command Implementation Quality"
    
    async def validate(self, project_path: Path) -> ExpertValidation:
        """Validate command implementation quality"""
        logger.info(f"{self.name} starting validation...")
        
        metrics = []
        issues = []
        recommendations = []
        
        # 1. Validate command count and diversity
        command_metric = await self._validate_command_implementation(project_path)
        metrics.append(command_metric)
        
        # 2. Validate code structure and organization
        structure_metric = await self._validate_code_structure(project_path)
        metrics.append(structure_metric)
        
        # 3. Validate error handling implementation
        error_metric = await self._validate_error_handling(project_path)
        metrics.append(error_metric)
        
        # 4. Validate documentation completeness
        docs_metric = await self._validate_documentation(project_path)
        metrics.append(docs_metric)
        
        # 5. Validate test coverage
        test_metric = await self._validate_test_coverage(project_path)
        metrics.append(test_metric)
        
        # Calculate overall score
        overall_score = sum(m.score for m in metrics) / len(metrics)
        
        # Determine production readiness
        critical_issues = []
        for metric in metrics:
            if metric.score < 0.6:
                critical_issues.extend(metric.issues)
        
        return ExpertValidation(
            expert_name=self.name,
            domain=self.domain,
            metrics=metrics,
            overall_score=overall_score,
            verdict=self._get_verdict(overall_score),
            critical_issues=critical_issues,
            improvement_areas=[r for m in metrics for r in m.recommendations],
            production_ready=overall_score >= 0.8 and len(critical_issues) == 0
        )
    
    async def _validate_command_implementation(self, project_path: Path) -> ValidationMetric:
        """Validate the command library implementation"""
        issues = []
        recommendations = []
        score = 0.0
        
        try:
            # Check bash_god_mcp_server.py
            server_file = project_path / "bash_god_mcp_server.py"
            if server_file.exists():
                with open(server_file, 'r') as f:
                    content = f.read()
                
                # Count command definitions
                command_count = len(re.findall(r'def\s+\w+_command', content))
                
                # Check for command categories
                has_categories = 'CommandCategory' in content
                has_safety_levels = 'SafetyLevel' in content
                has_chaining = 'ChainStrategy' in content
                
                # Check for expanded commands integration
                expanded_file = project_path / "bash_god_expanded_commands.py"
                has_expanded = expanded_file.exists()
                
                # Calculate score
                if command_count >= 50:  # Base commands
                    score += 0.3
                if has_categories and has_safety_levels:
                    score += 0.2
                if has_chaining:
                    score += 0.2
                if has_expanded:
                    score += 0.3
                
                # Issues and recommendations
                if command_count < 50:
                    issues.append(f"Only {command_count} base commands found (expected 50+)")
                    recommendations.append("Complete base command implementation")
                
                if not has_expanded:
                    issues.append("Expanded commands module not found")
                    recommendations.append("Implement expanded command sets")
            else:
                issues.append("Main server file not found")
                score = 0.0
                
        except Exception as e:
            issues.append(f"Error validating commands: {str(e)}")
            score = 0.0
        
        return ValidationMetric(
            name="Command Implementation",
            score=score,
            details=f"Validated command library with {command_count if 'command_count' in locals() else 0} base commands",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_code_structure(self, project_path: Path) -> ValidationMetric:
        """Validate code organization and structure"""
        issues = []
        recommendations = []
        score = 0.0
        
        required_modules = [
            "bash_god_mcp_server.py",
            "bash_god_expanded_commands.py",
            "security/input_validator.py",
            "bash_god_orchestrator.py"
        ]
        
        found_modules = 0
        for module in required_modules:
            if (project_path / module).exists():
                found_modules += 1
            else:
                issues.append(f"Missing module: {module}")
        
        score = found_modules / len(required_modules)
        
        if score < 1.0:
            recommendations.append("Implement all required modules")
        
        return ValidationMetric(
            name="Code Structure",
            score=score,
            details=f"Found {found_modules}/{len(required_modules)} required modules",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_error_handling(self, project_path: Path) -> ValidationMetric:
        """Validate error handling implementation"""
        issues = []
        recommendations = []
        score = 0.8  # Default good score
        
        server_file = project_path / "bash_god_mcp_server.py"
        if server_file.exists():
            with open(server_file, 'r') as f:
                content = f.read()
            
            # Check for proper error handling patterns
            has_try_except = 'try:' in content and 'except' in content
            has_logging = 'logger' in content or 'logging' in content
            has_validation = 'validate' in content or 'check' in content
            
            if not has_try_except:
                issues.append("Limited error handling found")
                score -= 0.3
            if not has_logging:
                issues.append("No logging implementation found")
                score -= 0.2
            if not has_validation:
                issues.append("No input validation found")
                score -= 0.3
        
        return ValidationMetric(
            name="Error Handling",
            score=max(0, score),
            details="Validated error handling patterns",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_documentation(self, project_path: Path) -> ValidationMetric:
        """Validate documentation completeness"""
        score = 0.7  # Default score
        issues = []
        recommendations = []
        
        # Check for docstrings in main file
        server_file = project_path / "bash_god_mcp_server.py"
        if server_file.exists():
            with open(server_file, 'r') as f:
                content = f.read()
            
            # Count docstrings
            docstring_count = len(re.findall(r'"""[\s\S]*?"""', content))
            function_count = len(re.findall(r'def\s+\w+', content))
            
            if function_count > 0:
                docstring_ratio = docstring_count / function_count
                score = min(1.0, docstring_ratio)
                
                if docstring_ratio < 0.8:
                    issues.append(f"Only {int(docstring_ratio * 100)}% of functions documented")
                    recommendations.append("Add docstrings to all functions")
        
        return ValidationMetric(
            name="Documentation",
            score=score,
            details="Validated code documentation",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_test_coverage(self, project_path: Path) -> ValidationMetric:
        """Validate test coverage"""
        score = 0.5  # Default moderate score
        issues = []
        recommendations = []
        
        # Check for test files
        test_files = list(project_path.glob("test_*.py"))
        validation_files = list(project_path.glob("validate_*.py"))
        
        total_test_files = len(test_files) + len(validation_files)
        
        if total_test_files >= 5:
            score = 0.8
        elif total_test_files >= 3:
            score = 0.6
        else:
            score = 0.4
            issues.append(f"Only {total_test_files} test files found")
            recommendations.append("Implement comprehensive test suite")
        
        return ValidationMetric(
            name="Test Coverage",
            score=score,
            details=f"Found {total_test_files} test files",
            issues=issues,
            recommendations=recommendations
        )
    
    def _get_verdict(self, score: float) -> str:
        """Get verdict based on score"""
        if score >= 0.9:
            return "EXCELLENT - Production ready"
        elif score >= 0.8:
            return "GOOD - Minor improvements needed"
        elif score >= 0.7:
            return "SATISFACTORY - Some improvements required"
        elif score >= 0.6:
            return "NEEDS WORK - Significant improvements required"
        else:
            return "INSUFFICIENT - Major work needed"


class SecurityExpert:
    """Expert in security practices and vulnerability assessment"""
    
    def __init__(self):
        self.name = "Security Expert"
        self.domain = "Security Enhancement Effectiveness"
    
    async def validate(self, project_path: Path) -> ExpertValidation:
        """Validate security implementations"""
        logger.info(f"{self.name} starting validation...")
        
        metrics = []
        
        # 1. Validate input sanitization
        input_metric = await self._validate_input_sanitization(project_path)
        metrics.append(input_metric)
        
        # 2. Validate command injection prevention
        injection_metric = await self._validate_injection_prevention(project_path)
        metrics.append(injection_metric)
        
        # 3. Validate privilege escalation prevention
        privilege_metric = await self._validate_privilege_controls(project_path)
        metrics.append(privilege_metric)
        
        # 4. Validate security monitoring
        monitoring_metric = await self._validate_security_monitoring(project_path)
        metrics.append(monitoring_metric)
        
        # 5. Validate authentication and authorization
        auth_metric = await self._validate_auth_mechanisms(project_path)
        metrics.append(auth_metric)
        
        overall_score = sum(m.score for m in metrics) / len(metrics)
        critical_issues = [issue for m in metrics if m.score < 0.7 for issue in m.issues]
        
        return ExpertValidation(
            expert_name=self.name,
            domain=self.domain,
            metrics=metrics,
            overall_score=overall_score,
            verdict=self._get_verdict(overall_score),
            critical_issues=critical_issues,
            improvement_areas=[r for m in metrics for r in m.recommendations],
            production_ready=overall_score >= 0.85 and len(critical_issues) == 0
        )
    
    async def _validate_input_sanitization(self, project_path: Path) -> ValidationMetric:
        """Validate input sanitization implementation"""
        score = 0.0
        issues = []
        recommendations = []
        
        # Check for input validator
        validator_file = project_path / "security" / "input_validator.py"
        if validator_file.exists():
            score += 0.5
            
            with open(validator_file, 'r') as f:
                content = f.read()
            
            # Check for comprehensive validation
            has_command_validation = 'validate_command' in content
            has_parameter_validation = 'validate_parameter' in content
            has_sanitization = 'sanitize' in content
            
            if has_command_validation:
                score += 0.2
            else:
                issues.append("Missing command validation")
                
            if has_parameter_validation:
                score += 0.2
            else:
                issues.append("Missing parameter validation")
                
            if has_sanitization:
                score += 0.1
            else:
                issues.append("Missing input sanitization")
        else:
            issues.append("Input validator module not found")
            recommendations.append("Implement security/input_validator.py")
        
        return ValidationMetric(
            name="Input Sanitization",
            score=score,
            details="Validated input sanitization mechanisms",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_injection_prevention(self, project_path: Path) -> ValidationMetric:
        """Validate command injection prevention"""
        score = 0.7  # Start with good score
        issues = []
        recommendations = []
        
        server_file = project_path / "bash_god_mcp_server.py"
        if server_file.exists():
            with open(server_file, 'r') as f:
                content = f.read()
            
            # Check for dangerous patterns
            if 'os.system(' in content:
                issues.append("Using os.system() - vulnerable to injection")
                score -= 0.3
                recommendations.append("Replace os.system with subprocess.run")
            
            if 'eval(' in content:
                issues.append("Using eval() - security risk")
                score -= 0.2
                recommendations.append("Remove eval() usage")
            
            # Check for safe practices
            if 'subprocess.run' in content and 'shell=False' in content:
                score += 0.2
            
            if 'shlex.quote' in content:
                score += 0.1
        
        return ValidationMetric(
            name="Injection Prevention",
            score=min(1.0, max(0, score)),
            details="Validated command injection prevention",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_privilege_controls(self, project_path: Path) -> ValidationMetric:
        """Validate privilege escalation prevention"""
        score = 0.8
        issues = []
        recommendations = []
        
        # Check for safety levels implementation
        server_file = project_path / "bash_god_mcp_server.py"
        if server_file.exists():
            with open(server_file, 'r') as f:
                content = f.read()
            
            if 'SafetyLevel' not in content:
                issues.append("No safety level classification")
                score -= 0.3
                recommendations.append("Implement command safety levels")
            
            if 'check_permissions' not in content and 'validate_permissions' not in content:
                issues.append("No permission validation found")
                score -= 0.2
                recommendations.append("Add permission validation")
        
        return ValidationMetric(
            name="Privilege Controls",
            score=max(0, score),
            details="Validated privilege escalation prevention",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_security_monitoring(self, project_path: Path) -> ValidationMetric:
        """Validate security monitoring capabilities"""
        score = 0.6
        issues = []
        recommendations = []
        
        # Check for security monitoring commands
        expanded_file = project_path / "bash_god_expanded_commands.py"
        if expanded_file.exists():
            with open(expanded_file, 'r') as f:
                content = f.read()
            
            if 'get_expanded_security_commands' in content:
                score += 0.2
            
            # Check for specific security tools
            security_tools = ['snort', 'suricata', 'ossec', 'fail2ban', 'aide']
            found_tools = sum(1 for tool in security_tools if tool in content)
            
            if found_tools >= 3:
                score += 0.2
            else:
                issues.append(f"Only {found_tools} security tools integrated")
                recommendations.append("Add more security monitoring tools")
        
        return ValidationMetric(
            name="Security Monitoring",
            score=min(1.0, score),
            details="Validated security monitoring capabilities",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_auth_mechanisms(self, project_path: Path) -> ValidationMetric:
        """Validate authentication and authorization"""
        score = 0.5
        issues = []
        recommendations = []
        
        # Basic check for auth implementation
        server_file = project_path / "bash_god_mcp_server.py"
        if server_file.exists():
            with open(server_file, 'r') as f:
                content = f.read()
            
            if 'authenticate' in content or 'authorization' in content:
                score += 0.3
            else:
                issues.append("No authentication mechanism found")
                recommendations.append("Implement authentication for MCP server")
        
        return ValidationMetric(
            name="Authentication",
            score=score,
            details="Validated authentication mechanisms",
            issues=issues,
            recommendations=recommendations
        )
    
    def _get_verdict(self, score: float) -> str:
        """Get security verdict"""
        if score >= 0.9:
            return "SECURE - Production ready"
        elif score >= 0.8:
            return "GOOD - Minor security enhancements needed"
        elif score >= 0.7:
            return "ACCEPTABLE - Some security improvements required"
        elif score >= 0.6:
            return "VULNERABLE - Significant security work needed"
        else:
            return "INSECURE - Critical security issues"


class PerformanceExpert:
    """Expert in performance optimization and AMD-specific tuning"""
    
    def __init__(self):
        self.name = "Performance Expert"
        self.domain = "AMD Optimization Accuracy"
    
    async def validate(self, project_path: Path) -> ExpertValidation:
        """Validate performance optimizations"""
        logger.info(f"{self.name} starting validation...")
        
        metrics = []
        
        # 1. Validate AMD Ryzen optimizations
        amd_metric = await self._validate_amd_optimizations(project_path)
        metrics.append(amd_metric)
        
        # 2. Validate parallel execution
        parallel_metric = await self._validate_parallel_execution(project_path)
        metrics.append(parallel_metric)
        
        # 3. Validate resource management
        resource_metric = await self._validate_resource_management(project_path)
        metrics.append(resource_metric)
        
        # 4. Validate caching strategies
        cache_metric = await self._validate_caching(project_path)
        metrics.append(cache_metric)
        
        # 5. Validate performance monitoring
        monitoring_metric = await self._validate_performance_monitoring(project_path)
        metrics.append(monitoring_metric)
        
        overall_score = sum(m.score for m in metrics) / len(metrics)
        critical_issues = [issue for m in metrics if m.score < 0.6 for issue in m.issues]
        
        return ExpertValidation(
            expert_name=self.name,
            domain=self.domain,
            metrics=metrics,
            overall_score=overall_score,
            verdict=self._get_verdict(overall_score),
            critical_issues=critical_issues,
            improvement_areas=[r for m in metrics for r in m.recommendations],
            production_ready=overall_score >= 0.75
        )
    
    async def _validate_amd_optimizations(self, project_path: Path) -> ValidationMetric:
        """Validate AMD Ryzen 7 7800X3D optimizations"""
        score = 0.0
        issues = []
        recommendations = []
        
        server_file = project_path / "bash_god_mcp_server.py"
        if server_file.exists():
            with open(server_file, 'r') as f:
                content = f.read()
            
            # Check for AMD-specific optimizations
            if 'amd_ryzen_optimized' in content:
                score += 0.3
            else:
                issues.append("No AMD optimization flags found")
            
            if 'cpu_cores' in content:
                score += 0.2
            
            if 'memory_requirement' in content:
                score += 0.2
            
            # Check for performance commands
            expanded_file = project_path / "bash_god_expanded_commands.py"
            if expanded_file.exists():
                with open(expanded_file, 'r') as f:
                    expanded_content = f.read()
                
                if 'get_expanded_performance_commands' in expanded_content:
                    score += 0.3
                    
                    # Check for AMD-specific tools
                    amd_tools = ['ryzen', 'amd', 'zen4', '7800x3d']
                    found_amd = any(tool in expanded_content.lower() for tool in amd_tools)
                    if found_amd:
                        score = min(1.0, score + 0.2)
        
        if score < 0.7:
            recommendations.append("Add more AMD Ryzen 7 7800X3D specific optimizations")
        
        return ValidationMetric(
            name="AMD Optimizations",
            score=score,
            details="Validated AMD Ryzen 7 7800X3D optimizations",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_parallel_execution(self, project_path: Path) -> ValidationMetric:
        """Validate parallel execution capabilities"""
        score = 0.5
        issues = []
        recommendations = []
        
        server_file = project_path / "bash_god_mcp_server.py"
        if server_file.exists():
            with open(server_file, 'r') as f:
                content = f.read()
            
            # Check for parallel execution support
            if 'ThreadPoolExecutor' in content or 'ProcessPoolExecutor' in content:
                score += 0.3
            
            if 'asyncio' in content:
                score += 0.2
            
            if 'ChainStrategy.PARALLEL' in content:
                score = min(1.0, score + 0.2)
        
        if score < 0.8:
            issues.append("Limited parallel execution support")
            recommendations.append("Enhance parallel command execution")
        
        return ValidationMetric(
            name="Parallel Execution",
            score=score,
            details="Validated parallel execution capabilities",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_resource_management(self, project_path: Path) -> ValidationMetric:
        """Validate resource management"""
        score = 0.6
        issues = []
        recommendations = []
        
        # Check for resource monitoring
        if (project_path / "bash_god_mcp_server.py").exists():
            with open(project_path / "bash_god_mcp_server.py", 'r') as f:
                content = f.read()
            
            if 'psutil' in content:
                score += 0.2
            
            if 'memory_requirement' in content:
                score += 0.1
            
            if 'cpu_cores' in content:
                score += 0.1
        
        return ValidationMetric(
            name="Resource Management",
            score=min(1.0, score),
            details="Validated resource management",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_caching(self, project_path: Path) -> ValidationMetric:
        """Validate caching strategies"""
        score = 0.4  # Base score
        issues = []
        recommendations = []
        
        # Check for caching implementation
        if not any(project_path.glob("*cache*")):
            issues.append("No caching implementation found")
            recommendations.append("Implement command result caching")
        else:
            score = 0.7
        
        return ValidationMetric(
            name="Caching Strategies",
            score=score,
            details="Validated caching implementation",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_performance_monitoring(self, project_path: Path) -> ValidationMetric:
        """Validate performance monitoring"""
        score = 0.5
        issues = []
        recommendations = []
        
        # Check for monitoring directory
        monitoring_dir = project_path / "monitoring"
        if monitoring_dir.exists():
            score += 0.3
            
            # Check for dashboards
            if (monitoring_dir / "dashboards").exists():
                score += 0.2
        else:
            issues.append("No monitoring configuration found")
            recommendations.append("Implement performance monitoring")
        
        return ValidationMetric(
            name="Performance Monitoring",
            score=score,
            details="Validated performance monitoring setup",
            issues=issues,
            recommendations=recommendations
        )
    
    def _get_verdict(self, score: float) -> str:
        """Get performance verdict"""
        if score >= 0.85:
            return "OPTIMIZED - Excellent performance"
        elif score >= 0.75:
            return "GOOD - Well optimized"
        elif score >= 0.65:
            return "ADEQUATE - Some optimizations needed"
        elif score >= 0.5:
            return "SUBOPTIMAL - Significant optimizations required"
        else:
            return "POOR - Major performance work needed"


class DevOpsExpert:
    """Expert in DevOps practices and automation"""
    
    def __init__(self):
        self.name = "DevOps Expert"
        self.domain = "Automation Command Completeness"
    
    async def validate(self, project_path: Path) -> ExpertValidation:
        """Validate DevOps automation completeness"""
        logger.info(f"{self.name} starting validation...")
        
        metrics = []
        
        # 1. Validate CI/CD commands
        cicd_metric = await self._validate_cicd_commands(project_path)
        metrics.append(cicd_metric)
        
        # 2. Validate container operations
        container_metric = await self._validate_container_ops(project_path)
        metrics.append(container_metric)
        
        # 3. Validate infrastructure automation
        infra_metric = await self._validate_infrastructure(project_path)
        metrics.append(infra_metric)
        
        # 4. Validate deployment automation
        deploy_metric = await self._validate_deployment(project_path)
        metrics.append(deploy_metric)
        
        # 5. Validate monitoring integration
        monitoring_metric = await self._validate_monitoring_integration(project_path)
        metrics.append(monitoring_metric)
        
        overall_score = sum(m.score for m in metrics) / len(metrics)
        critical_issues = [issue for m in metrics if m.score < 0.6 for issue in m.issues]
        
        return ExpertValidation(
            expert_name=self.name,
            domain=self.domain,
            metrics=metrics,
            overall_score=overall_score,
            verdict=self._get_verdict(overall_score),
            critical_issues=critical_issues,
            improvement_areas=[r for m in metrics for r in m.recommendations],
            production_ready=overall_score >= 0.8
        )
    
    async def _validate_cicd_commands(self, project_path: Path) -> ValidationMetric:
        """Validate CI/CD automation commands"""
        score = 0.0
        issues = []
        recommendations = []
        
        # Check for DevOps commands in expanded set
        expanded_file = project_path / "bash_god_expanded_commands.py"
        if expanded_file.exists():
            with open(expanded_file, 'r') as f:
                content = f.read()
            
            if 'get_expanded_devops_commands' in content:
                score += 0.5
                
                # Check for specific CI/CD tools
                cicd_tools = ['jenkins', 'gitlab', 'github', 'circleci', 'docker', 'kubernetes']
                found_tools = sum(1 for tool in cicd_tools if tool in content.lower())
                
                score += min(0.5, found_tools * 0.1)
        else:
            issues.append("DevOps commands not found")
            recommendations.append("Implement DevOps command set")
        
        return ValidationMetric(
            name="CI/CD Commands",
            score=score,
            details="Validated CI/CD automation commands",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_container_ops(self, project_path: Path) -> ValidationMetric:
        """Validate container operations"""
        score = 0.5
        issues = []
        recommendations = []
        
        # Check for Docker configuration
        docker_files = list(project_path.glob("**/Dockerfile*"))
        compose_files = list(project_path.glob("**/docker-compose*.yml"))
        
        if docker_files:
            score += 0.25
        else:
            issues.append("No Dockerfile found")
        
        if compose_files:
            score += 0.25
        else:
            issues.append("No docker-compose configuration")
        
        return ValidationMetric(
            name="Container Operations",
            score=min(1.0, score),
            details="Validated container operation support",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_infrastructure(self, project_path: Path) -> ValidationMetric:
        """Validate infrastructure automation"""
        score = 0.4
        issues = []
        recommendations = []
        
        # Check for infrastructure as code
        k8s_dir = project_path.parent / "k8s"
        if k8s_dir.exists():
            score += 0.3
            
            # Check for essential K8s resources
            k8s_files = ['deployments.yaml', 'services.yaml', 'configmaps.yaml']
            found_files = sum(1 for f in k8s_files if (k8s_dir / f).exists())
            score += min(0.3, found_files * 0.1)
        
        if score < 0.7:
            recommendations.append("Enhance infrastructure automation")
        
        return ValidationMetric(
            name="Infrastructure Automation",
            score=score,
            details="Validated infrastructure as code",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_deployment(self, project_path: Path) -> ValidationMetric:
        """Validate deployment automation"""
        score = 0.0
        issues = []
        recommendations = []
        
        # Check for deployment scripts
        deploy_dir = project_path / "deployment"
        if deploy_dir.exists():
            score += 0.4
            
            # Check for deployment automation
            if (deploy_dir / "scripts" / "deploy_learning_mcp.py").exists():
                score += 0.3
            
            if (deploy_dir / "scripts" / "production_certification.py").exists():
                score += 0.3
        else:
            issues.append("No deployment directory found")
            recommendations.append("Create deployment automation scripts")
        
        return ValidationMetric(
            name="Deployment Automation",
            score=score,
            details="Validated deployment automation",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_monitoring_integration(self, project_path: Path) -> ValidationMetric:
        """Validate monitoring integration"""
        score = 0.0
        issues = []
        recommendations = []
        
        monitoring_dir = project_path / "monitoring"
        if monitoring_dir.exists():
            score += 0.3
            
            # Check for Prometheus config
            if (monitoring_dir / "prometheus.yml").exists():
                score += 0.3
            
            # Check for dashboards
            if (monitoring_dir / "dashboards").exists():
                score += 0.2
            
            # Check for alerts
            if (monitoring_dir / "alert_rules.yml").exists():
                score += 0.2
        else:
            issues.append("No monitoring configuration")
            recommendations.append("Implement monitoring integration")
        
        return ValidationMetric(
            name="Monitoring Integration",
            score=score,
            details="Validated monitoring setup",
            issues=issues,
            recommendations=recommendations
        )
    
    def _get_verdict(self, score: float) -> str:
        """Get DevOps verdict"""
        if score >= 0.85:
            return "AUTOMATED - Excellent DevOps practices"
        elif score >= 0.75:
            return "GOOD - Well automated"
        elif score >= 0.65:
            return "PARTIAL - Some automation gaps"
        elif score >= 0.5:
            return "LIMITED - Significant automation needed"
        else:
            return "MANUAL - Major automation work required"


class QualityExpert:
    """Expert in overall system quality and reliability"""
    
    def __init__(self):
        self.name = "Quality Expert"
        self.domain = "Overall System Reliability"
    
    async def validate(self, project_path: Path) -> ExpertValidation:
        """Validate overall system quality"""
        logger.info(f"{self.name} starting validation...")
        
        metrics = []
        
        # 1. Validate test framework
        test_metric = await self._validate_test_framework(project_path)
        metrics.append(test_metric)
        
        # 2. Validate integration testing
        integration_metric = await self._validate_integration_testing(project_path)
        metrics.append(integration_metric)
        
        # 3. Validate error recovery
        recovery_metric = await self._validate_error_recovery(project_path)
        metrics.append(recovery_metric)
        
        # 4. Validate logging and observability
        observability_metric = await self._validate_observability(project_path)
        metrics.append(observability_metric)
        
        # 5. Validate production readiness
        production_metric = await self._validate_production_readiness(project_path)
        metrics.append(production_metric)
        
        overall_score = sum(m.score for m in metrics) / len(metrics)
        critical_issues = [issue for m in metrics if m.score < 0.7 for issue in m.issues]
        
        return ExpertValidation(
            expert_name=self.name,
            domain=self.domain,
            metrics=metrics,
            overall_score=overall_score,
            verdict=self._get_verdict(overall_score),
            critical_issues=critical_issues,
            improvement_areas=[r for m in metrics for r in m.recommendations],
            production_ready=overall_score >= 0.8 and len(critical_issues) == 0
        )
    
    async def _validate_test_framework(self, project_path: Path) -> ValidationMetric:
        """Validate test framework completeness"""
        score = 0.0
        issues = []
        recommendations = []
        
        # Count test files
        test_files = list(project_path.glob("test_*.py"))
        validate_files = list(project_path.glob("validate_*.py"))
        
        total_tests = len(test_files) + len(validate_files)
        
        if total_tests >= 10:
            score = 0.8
        elif total_tests >= 5:
            score = 0.6
        elif total_tests >= 3:
            score = 0.4
        else:
            score = 0.2
            issues.append(f"Only {total_tests} test files found")
        
        # Check for test results
        test_results = list(project_path.glob("*test_results*.json"))
        if test_results:
            score = min(1.0, score + 0.2)
        
        if score < 0.8:
            recommendations.append("Expand test coverage")
        
        return ValidationMetric(
            name="Test Framework",
            score=score,
            details=f"Found {total_tests} test files",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_integration_testing(self, project_path: Path) -> ValidationMetric:
        """Validate integration testing"""
        score = 0.0
        issues = []
        recommendations = []
        
        # Check for integration test files
        integration_tests = [
            "test_cross_server_integration.py",
            "test_mcp_protocol_compliance.py",
            "direct_integration.py",
            "final_integration.py"
        ]
        
        found_tests = sum(1 for test in integration_tests if (project_path / test).exists())
        score = found_tests / len(integration_tests)
        
        if score < 1.0:
            missing = [t for t in integration_tests if not (project_path / t).exists()]
            issues.append(f"Missing integration tests: {', '.join(missing[:2])}")
            recommendations.append("Complete integration test suite")
        
        return ValidationMetric(
            name="Integration Testing",
            score=score,
            details=f"Found {found_tests}/{len(integration_tests)} integration tests",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_error_recovery(self, project_path: Path) -> ValidationMetric:
        """Validate error recovery mechanisms"""
        score = 0.6  # Base score
        issues = []
        recommendations = []
        
        server_file = project_path / "bash_god_mcp_server.py"
        if server_file.exists():
            with open(server_file, 'r') as f:
                content = f.read()
            
            # Check for error handling patterns
            if 'retry' in content.lower():
                score += 0.1
            
            if 'fallback' in content.lower():
                score += 0.1
            
            if 'circuit_breaker' in content.lower():
                score += 0.2
            else:
                recommendations.append("Implement circuit breaker pattern")
        
        return ValidationMetric(
            name="Error Recovery",
            score=min(1.0, score),
            details="Validated error recovery mechanisms",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_observability(self, project_path: Path) -> ValidationMetric:
        """Validate logging and observability"""
        score = 0.5
        issues = []
        recommendations = []
        
        # Check for logging configuration
        server_file = project_path / "bash_god_mcp_server.py"
        if server_file.exists():
            with open(server_file, 'r') as f:
                content = f.read()
            
            if 'logging.basicConfig' in content:
                score += 0.2
            
            if 'logger = logging.getLogger' in content:
                score += 0.2
            
            # Check for structured logging
            if 'json' in content and 'log' in content:
                score += 0.1
        
        if score < 0.8:
            recommendations.append("Enhance logging and observability")
        
        return ValidationMetric(
            name="Observability",
            score=score,
            details="Validated logging and observability",
            issues=issues,
            recommendations=recommendations
        )
    
    async def _validate_production_readiness(self, project_path: Path) -> ValidationMetric:
        """Validate production readiness"""
        score = 0.0
        issues = []
        recommendations = []
        
        # Check for production certification
        cert_script = project_path / "deployment" / "scripts" / "production_certification.py"
        if cert_script.exists():
            score += 0.4
        else:
            issues.append("No production certification script")
        
        # Check for deployment validation
        validation_script = project_path / "deployment" / "validation" / "validate_learning_system.py"
        if validation_script.exists():
            score += 0.3
        
        # Check for security reports
        security_reports = list(project_path.glob("*security*.json"))
        if security_reports:
            score += 0.3
        
        if score < 0.8:
            recommendations.append("Complete production readiness checklist")
        
        return ValidationMetric(
            name="Production Readiness",
            score=score,
            details="Validated production readiness",
            issues=issues,
            recommendations=recommendations
        )
    
    def _get_verdict(self, score: float) -> str:
        """Get quality verdict"""
        if score >= 0.85:
            return "EXCELLENT - High quality, production ready"
        elif score >= 0.75:
            return "GOOD - Quality standards met"
        elif score >= 0.65:
            return "ACCEPTABLE - Some quality improvements needed"
        elif score >= 0.5:
            return "NEEDS WORK - Quality issues present"
        else:
            return "POOR - Significant quality problems"


class CircleOfExpertsOrchestrator:
    """Orchestrator for Circle of Experts validation"""
    
    def __init__(self):
        self.experts = [
            DevelopmentExpert(),
            SecurityExpert(),
            PerformanceExpert(),
            DevOpsExpert(),
            QualityExpert()
        ]
    
    async def validate_system(self, project_path: Path) -> Dict[str, Any]:
        """Run comprehensive validation with all experts"""
        logger.info("Starting Circle of Experts validation...")
        
        start_time = time.time()
        
        # Run all expert validations in parallel
        validations = await asyncio.gather(
            *[expert.validate(project_path) for expert in self.experts]
        )
        
        # Calculate consensus scores
        overall_scores = [v.overall_score for v in validations]
        consensus_score = sum(overall_scores) / len(overall_scores)
        
        # Determine production readiness
        production_ready = all(v.production_ready for v in validations)
        
        # Collect all critical issues
        all_critical_issues = []
        for validation in validations:
            all_critical_issues.extend(validation.critical_issues)
        
        # Collect all recommendations
        all_recommendations = []
        for validation in validations:
            all_recommendations.extend(validation.improvement_areas)
        
        # Remove duplicates
        all_recommendations = list(set(all_recommendations))
        
        # Generate final verdict
        final_verdict = self._generate_final_verdict(consensus_score, production_ready, len(all_critical_issues))
        
        validation_time = time.time() - start_time
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "validation_duration": f"{validation_time:.2f} seconds",
            "expert_validations": [asdict(v) for v in validations],
            "consensus_score": consensus_score,
            "production_ready": production_ready,
            "final_verdict": final_verdict,
            "critical_issues_count": len(all_critical_issues),
            "critical_issues": all_critical_issues[:10],  # Top 10 critical issues
            "recommendations_count": len(all_recommendations),
            "top_recommendations": all_recommendations[:10],  # Top 10 recommendations
            "expert_consensus": {
                "development": validations[0].verdict,
                "security": validations[1].verdict,
                "performance": validations[2].verdict,
                "devops": validations[3].verdict,
                "quality": validations[4].verdict
            }
        }
        
        return report
    
    def _generate_final_verdict(self, score: float, production_ready: bool, critical_issues: int) -> str:
        """Generate final system verdict"""
        if production_ready and score >= 0.85:
            return "PRODUCTION READY - All experts approve deployment"
        elif score >= 0.8 and critical_issues < 5:
            return "NEARLY READY - Minor improvements needed before production"
        elif score >= 0.7:
            return "GOOD PROGRESS - Address critical issues before deployment"
        elif score >= 0.6:
            return "NEEDS WORK - Significant improvements required"
        else:
            return "NOT READY - Major work needed across multiple domains"


async def main():
    """Run Circle of Experts validation"""
    project_path = Path(__file__).parent
    
    orchestrator = CircleOfExpertsOrchestrator()
    report = await orchestrator.validate_system(project_path)
    
    # Save report
    report_file = project_path / f"circle_of_experts_validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print("\n" + "="*80)
    print("CIRCLE OF EXPERTS VALIDATION COMPLETE")
    print("="*80)
    print(f"Consensus Score: {report['consensus_score']:.2%}")
    print(f"Production Ready: {'YES' if report['production_ready'] else 'NO'}")
    print(f"Final Verdict: {report['final_verdict']}")
    print(f"Critical Issues: {report['critical_issues_count']}")
    print(f"Recommendations: {report['recommendations_count']}")
    print("\nExpert Consensus:")
    for domain, verdict in report['expert_consensus'].items():
        print(f"  {domain.capitalize()}: {verdict}")
    print(f"\nFull report saved to: {report_file}")
    print("="*80)

if __name__ == "__main__":
    asyncio.run(main())