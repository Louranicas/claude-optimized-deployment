#!/usr/bin/env python3
"""
Quality Gate Validator for MCP Server Testing
Enforces quality standards including coverage, performance, security, and code quality metrics
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import subprocess
import re
import sys


@dataclass
class QualityMetrics:
    """Quality metrics data structure"""
    test_coverage: float = 0.0
    line_coverage: float = 0.0
    branch_coverage: float = 0.0
    function_coverage: float = 0.0
    
    test_success_rate: float = 0.0
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    
    performance_score: float = 0.0
    avg_response_time: float = 0.0
    max_response_time: float = 0.0
    throughput: float = 0.0
    
    security_score: float = 0.0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    
    code_quality_score: float = 0.0
    complexity_score: float = 0.0
    maintainability_index: float = 0.0
    
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class QualityGate:
    """Quality gate configuration"""
    name: str
    description: str
    category: str
    threshold: float
    operator: str = "gte"  # gte, gt, lte, lt, eq
    severity: str = "error"  # error, warning, info
    enabled: bool = True


@dataclass
class QualityResult:
    """Quality gate result"""
    gate: QualityGate
    actual_value: float
    passed: bool
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class QualityGateValidator:
    """Validates quality gates for MCP server testing"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path) if config_path else Path(__file__).parent / "quality_gates.json"
        self.gates = self._load_quality_gates()
        self.results: List[QualityResult] = []
    
    def _load_quality_gates(self) -> List[QualityGate]:
        """Load quality gate configurations"""
        default_gates = [
            # Coverage Gates
            QualityGate(
                name="minimum_test_coverage",
                description="Minimum test coverage percentage",
                category="coverage",
                threshold=80.0,
                operator="gte",
                severity="error"
            ),
            QualityGate(
                name="minimum_line_coverage",
                description="Minimum line coverage percentage",
                category="coverage",
                threshold=80.0,
                operator="gte",
                severity="error"
            ),
            QualityGate(
                name="minimum_branch_coverage",
                description="Minimum branch coverage percentage",
                category="coverage",
                threshold=75.0,
                operator="gte",
                severity="warning"
            ),
            QualityGate(
                name="minimum_function_coverage",
                description="Minimum function coverage percentage",
                category="coverage",
                threshold=85.0,
                operator="gte",
                severity="error"
            ),
            
            # Test Quality Gates
            QualityGate(
                name="minimum_test_success_rate",
                description="Minimum test success rate percentage",
                category="testing",
                threshold=95.0,
                operator="gte",
                severity="error"
            ),
            QualityGate(
                name="maximum_failed_tests",
                description="Maximum number of failed tests",
                category="testing",
                threshold=5.0,
                operator="lte",
                severity="warning"
            ),
            
            # Performance Gates
            QualityGate(
                name="maximum_avg_response_time",
                description="Maximum average response time in seconds",
                category="performance",
                threshold=2.0,
                operator="lte",
                severity="error"
            ),
            QualityGate(
                name="maximum_response_time",
                description="Maximum response time in seconds",
                category="performance",
                threshold=10.0,
                operator="lte",
                severity="error"
            ),
            QualityGate(
                name="minimum_throughput",
                description="Minimum throughput (requests per second)",
                category="performance",
                threshold=50.0,
                operator="gte",
                severity="warning"
            ),
            
            # Security Gates
            QualityGate(
                name="no_critical_vulnerabilities",
                description="No critical security vulnerabilities allowed",
                category="security",
                threshold=0.0,
                operator="eq",
                severity="error"
            ),
            QualityGate(
                name="maximum_high_vulnerabilities",
                description="Maximum high-severity vulnerabilities",
                category="security",
                threshold=2.0,
                operator="lte",
                severity="error"
            ),
            QualityGate(
                name="maximum_medium_vulnerabilities",
                description="Maximum medium-severity vulnerabilities",
                category="security",
                threshold=10.0,
                operator="lte",
                severity="warning"
            ),
            
            # Code Quality Gates
            QualityGate(
                name="minimum_code_quality_score",
                description="Minimum code quality score",
                category="quality",
                threshold=7.0,
                operator="gte",
                severity="warning"
            ),
            QualityGate(
                name="maximum_complexity_score",
                description="Maximum complexity score",
                category="quality",
                threshold=10.0,
                operator="lte",
                severity="warning"
            ),
            QualityGate(
                name="minimum_maintainability_index",
                description="Minimum maintainability index",
                category="quality",
                threshold=60.0,
                operator="gte",
                severity="info"
            )
        ]
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                
                gates = []
                for gate_data in config_data.get("quality_gates", []):
                    gate = QualityGate(**gate_data)
                    gates.append(gate)
                
                return gates
            except Exception as e:
                print(f"Warning: Could not load quality gates config: {e}")
                print("Using default quality gates")
        
        return default_gates
    
    def save_quality_gates(self):
        """Save quality gates configuration to file"""
        config_data = {
            "quality_gates": [
                {
                    "name": gate.name,
                    "description": gate.description,
                    "category": gate.category,
                    "threshold": gate.threshold,
                    "operator": gate.operator,
                    "severity": gate.severity,
                    "enabled": gate.enabled
                }
                for gate in self.gates
            ]
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(config_data, f, indent=2)
    
    def collect_metrics(self, test_results_path: str) -> QualityMetrics:
        """Collect quality metrics from test results"""
        metrics = QualityMetrics()
        results_path = Path(test_results_path)
        
        # Collect coverage metrics
        coverage_metrics = self._collect_coverage_metrics(results_path)
        metrics.test_coverage = coverage_metrics.get("coverage", 0.0)
        metrics.line_coverage = coverage_metrics.get("line_coverage", 0.0)
        metrics.branch_coverage = coverage_metrics.get("branch_coverage", 0.0)
        metrics.function_coverage = coverage_metrics.get("function_coverage", 0.0)
        
        # Collect test metrics
        test_metrics = self._collect_test_metrics(results_path)
        metrics.total_tests = test_metrics.get("total", 0)
        metrics.passed_tests = test_metrics.get("passed", 0)
        metrics.failed_tests = test_metrics.get("failed", 0)
        metrics.skipped_tests = test_metrics.get("skipped", 0)
        
        if metrics.total_tests > 0:
            metrics.test_success_rate = (metrics.passed_tests / metrics.total_tests) * 100
        
        # Collect performance metrics
        performance_metrics = self._collect_performance_metrics(results_path)
        metrics.avg_response_time = performance_metrics.get("avg_response_time", 0.0)
        metrics.max_response_time = performance_metrics.get("max_response_time", 0.0)
        metrics.throughput = performance_metrics.get("throughput", 0.0)
        metrics.performance_score = self._calculate_performance_score(performance_metrics)
        
        # Collect security metrics
        security_metrics = self._collect_security_metrics(results_path)
        metrics.critical_vulnerabilities = security_metrics.get("critical", 0)
        metrics.high_vulnerabilities = security_metrics.get("high", 0)
        metrics.medium_vulnerabilities = security_metrics.get("medium", 0)
        metrics.low_vulnerabilities = security_metrics.get("low", 0)
        metrics.security_score = self._calculate_security_score(security_metrics)
        
        # Collect code quality metrics
        quality_metrics = self._collect_code_quality_metrics(results_path)
        metrics.code_quality_score = quality_metrics.get("quality_score", 0.0)
        metrics.complexity_score = quality_metrics.get("complexity", 0.0)
        metrics.maintainability_index = quality_metrics.get("maintainability", 0.0)
        
        return metrics
    
    def _collect_coverage_metrics(self, results_path: Path) -> Dict[str, float]:
        """Collect test coverage metrics"""
        metrics = {}
        
        # Try to parse coverage.xml
        coverage_xml = results_path / "coverage" / "coverage.xml"
        if coverage_xml.exists():
            try:
                tree = ET.parse(coverage_xml)
                root = tree.getroot()
                
                coverage_elem = root.find(".//coverage")
                if coverage_elem is not None:
                    metrics["line_coverage"] = float(coverage_elem.get("line-rate", 0)) * 100
                    metrics["branch_coverage"] = float(coverage_elem.get("branch-rate", 0)) * 100
                    metrics["coverage"] = metrics["line_coverage"]
                
                # Calculate function coverage from classes/methods
                methods_total = 0
                methods_hit = 0
                for method in root.findall(".//method"):
                    methods_total += 1
                    if int(method.get("hits", 0)) > 0:
                        methods_hit += 1
                
                if methods_total > 0:
                    metrics["function_coverage"] = (methods_hit / methods_total) * 100
                
            except Exception as e:
                print(f"Warning: Could not parse coverage XML: {e}")
        
        # Try to parse Jest coverage report
        jest_coverage = results_path / "coverage" / "coverage-summary.json"
        if jest_coverage.exists():
            try:
                with open(jest_coverage, 'r') as f:
                    coverage_data = json.load(f)
                
                total = coverage_data.get("total", {})
                metrics["line_coverage"] = total.get("lines", {}).get("pct", 0)
                metrics["branch_coverage"] = total.get("branches", {}).get("pct", 0)
                metrics["function_coverage"] = total.get("functions", {}).get("pct", 0)
                metrics["coverage"] = total.get("statements", {}).get("pct", 0)
                
            except Exception as e:
                print(f"Warning: Could not parse Jest coverage: {e}")
        
        return metrics
    
    def _collect_test_metrics(self, results_path: Path) -> Dict[str, int]:
        """Collect test execution metrics"""
        metrics = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
        
        # Parse JUnit XML files
        for xml_file in results_path.glob("**/*.xml"):
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                if root.tag == "testsuite":
                    metrics["total"] += int(root.get("tests", 0))
                    metrics["failed"] += int(root.get("failures", 0)) + int(root.get("errors", 0))
                    metrics["skipped"] += int(root.get("skipped", 0))
                
                elif root.tag == "testsuites":
                    for suite in root.findall("testsuite"):
                        metrics["total"] += int(suite.get("tests", 0))
                        metrics["failed"] += int(suite.get("failures", 0)) + int(suite.get("errors", 0))
                        metrics["skipped"] += int(suite.get("skipped", 0))
                        
            except Exception as e:
                print(f"Warning: Could not parse test XML {xml_file}: {e}")
        
        metrics["passed"] = metrics["total"] - metrics["failed"] - metrics["skipped"]
        return metrics
    
    def _collect_performance_metrics(self, results_path: Path) -> Dict[str, float]:
        """Collect performance metrics"""
        metrics = {}
        
        # Parse benchmark results
        benchmark_files = list(results_path.glob("**/benchmark*.json"))
        for benchmark_file in benchmark_files:
            try:
                with open(benchmark_file, 'r') as f:
                    benchmark_data = json.load(f)
                
                if "benchmarks" in benchmark_data:
                    # pytest-benchmark format
                    response_times = []
                    for benchmark in benchmark_data["benchmarks"]:
                        stats = benchmark.get("stats", {})
                        mean_time = stats.get("mean", 0)
                        response_times.append(mean_time)
                    
                    if response_times:
                        metrics["avg_response_time"] = sum(response_times) / len(response_times)
                        metrics["max_response_time"] = max(response_times)
                        metrics["throughput"] = 1.0 / metrics["avg_response_time"] if metrics["avg_response_time"] > 0 else 0
                
            except Exception as e:
                print(f"Warning: Could not parse benchmark file {benchmark_file}: {e}")
        
        return metrics
    
    def _collect_security_metrics(self, results_path: Path) -> Dict[str, int]:
        """Collect security scan metrics"""
        metrics = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        # Parse security scan results
        security_files = [
            "safety-report.json",
            "bandit-report.json",
            "semgrep-report.json",
            "grype-report.json"
        ]
        
        for security_file in security_files:
            file_path = results_path / security_file
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        security_data = json.load(f)
                    
                    # Parse different security tool formats
                    if "vulnerabilities" in security_data:
                        for vuln in security_data["vulnerabilities"]:
                            severity = vuln.get("severity", "").lower()
                            if severity in metrics:
                                metrics[severity] += 1
                    
                    elif "results" in security_data:
                        for result in security_data["results"]:
                            severity = result.get("severity", "").lower()
                            if severity in metrics:
                                metrics[severity] += 1
                    
                except Exception as e:
                    print(f"Warning: Could not parse security file {security_file}: {e}")
        
        return metrics
    
    def _collect_code_quality_metrics(self, results_path: Path) -> Dict[str, float]:
        """Collect code quality metrics"""
        metrics = {}
        
        # Try to run code quality tools if not already run
        try:
            # Run radon for complexity metrics
            radon_result = subprocess.run(
                ["radon", "cc", "src/", "--json"], 
                capture_output=True, 
                text=True,
                timeout=30
            )
            
            if radon_result.returncode == 0:
                radon_data = json.loads(radon_result.stdout)
                complexities = []
                
                for file_data in radon_data.values():
                    for item in file_data:
                        complexities.append(item.get("complexity", 0))
                
                if complexities:
                    metrics["complexity"] = sum(complexities) / len(complexities)
                
        except Exception as e:
            print(f"Warning: Could not run radon: {e}")
        
        # Calculate synthetic quality score based on other metrics
        # This is a simplified version - in practice, you'd use tools like SonarQube
        base_score = 8.0  # Start with good score
        
        # Adjust based on complexity
        if metrics.get("complexity", 0) > 10:
            base_score -= 2.0
        elif metrics.get("complexity", 0) > 7:
            base_score -= 1.0
        
        metrics["quality_score"] = max(0.0, min(10.0, base_score))
        metrics["maintainability"] = metrics["quality_score"] * 10  # Scale to 0-100
        
        return metrics
    
    def _calculate_performance_score(self, performance_metrics: Dict[str, float]) -> float:
        """Calculate overall performance score"""
        score = 100.0
        
        avg_time = performance_metrics.get("avg_response_time", 0)
        max_time = performance_metrics.get("max_response_time", 0)
        throughput = performance_metrics.get("throughput", 0)
        
        # Penalize high response times
        if avg_time > 2.0:
            score -= min(50, (avg_time - 2.0) * 25)  # -25 points per second over 2s
        
        if max_time > 10.0:
            score -= min(30, (max_time - 10.0) * 5)  # -5 points per second over 10s
        
        # Reward high throughput
        if throughput > 100:
            score += min(20, (throughput - 100) / 10)  # +1 point per 10 rps over 100
        
        return max(0.0, min(100.0, score))
    
    def _calculate_security_score(self, security_metrics: Dict[str, int]) -> float:
        """Calculate overall security score"""
        score = 100.0
        
        # Heavy penalties for vulnerabilities
        score -= security_metrics.get("critical", 0) * 50  # -50 per critical
        score -= security_metrics.get("high", 0) * 20     # -20 per high
        score -= security_metrics.get("medium", 0) * 5    # -5 per medium
        score -= security_metrics.get("low", 0) * 1       # -1 per low
        
        return max(0.0, min(100.0, score))
    
    def validate_quality_gates(self, metrics: QualityMetrics) -> List[QualityResult]:
        """Validate all quality gates against metrics"""
        results = []
        
        # Mapping of gate names to metric values
        metric_values = {
            "minimum_test_coverage": metrics.test_coverage,
            "minimum_line_coverage": metrics.line_coverage,
            "minimum_branch_coverage": metrics.branch_coverage,
            "minimum_function_coverage": metrics.function_coverage,
            "minimum_test_success_rate": metrics.test_success_rate,
            "maximum_failed_tests": float(metrics.failed_tests),
            "maximum_avg_response_time": metrics.avg_response_time,
            "maximum_response_time": metrics.max_response_time,
            "minimum_throughput": metrics.throughput,
            "no_critical_vulnerabilities": float(metrics.critical_vulnerabilities),
            "maximum_high_vulnerabilities": float(metrics.high_vulnerabilities),
            "maximum_medium_vulnerabilities": float(metrics.medium_vulnerabilities),
            "minimum_code_quality_score": metrics.code_quality_score,
            "maximum_complexity_score": metrics.complexity_score,
            "minimum_maintainability_index": metrics.maintainability_index
        }
        
        for gate in self.gates:
            if not gate.enabled:
                continue
            
            actual_value = metric_values.get(gate.name, 0.0)
            passed = self._evaluate_gate(actual_value, gate.threshold, gate.operator)
            
            message = self._generate_gate_message(gate, actual_value, passed)
            
            result = QualityResult(
                gate=gate,
                actual_value=actual_value,
                passed=passed,
                message=message
            )
            
            results.append(result)
        
        self.results = results
        return results
    
    def _evaluate_gate(self, actual: float, threshold: float, operator: str) -> bool:
        """Evaluate if a value passes the gate"""
        if operator == "gte":
            return actual >= threshold
        elif operator == "gt":
            return actual > threshold
        elif operator == "lte":
            return actual <= threshold
        elif operator == "lt":
            return actual < threshold
        elif operator == "eq":
            return actual == threshold
        else:
            raise ValueError(f"Unknown operator: {operator}")
    
    def _generate_gate_message(self, gate: QualityGate, actual_value: float, passed: bool) -> str:
        """Generate a descriptive message for the gate result"""
        status = "PASS" if passed else "FAIL"
        op_text = {
            "gte": ">=",
            "gt": ">",
            "lte": "<=",
            "lt": "<",
            "eq": "=="
        }.get(gate.operator, gate.operator)
        
        return f"{status}: {gate.description} - {actual_value:.2f} {op_text} {gate.threshold:.2f}"
    
    def generate_report(self, metrics: QualityMetrics, results: List[QualityResult]) -> Dict[str, Any]:
        """Generate comprehensive quality report"""
        total_gates = len(results)
        passed_gates = sum(1 for r in results if r.passed)
        failed_gates = total_gates - passed_gates
        
        # Categorize results by severity and category
        results_by_severity = {}
        results_by_category = {}
        
        for result in results:
            severity = result.gate.severity
            category = result.gate.category
            
            if severity not in results_by_severity:
                results_by_severity[severity] = []
            results_by_severity[severity].append(result)
            
            if category not in results_by_category:
                results_by_category[category] = []
            results_by_category[category].append(result)
        
        # Determine overall status
        has_error_failures = any(
            not r.passed and r.gate.severity == "error"
            for r in results
        )
        
        overall_status = "FAIL" if has_error_failures else "PASS"
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": overall_status,
            "summary": {
                "total_gates": total_gates,
                "passed_gates": passed_gates,
                "failed_gates": failed_gates,
                "success_rate": (passed_gates / total_gates * 100) if total_gates > 0 else 0
            },
            "metrics": {
                "coverage": {
                    "test_coverage": metrics.test_coverage,
                    "line_coverage": metrics.line_coverage,
                    "branch_coverage": metrics.branch_coverage,
                    "function_coverage": metrics.function_coverage
                },
                "testing": {
                    "success_rate": metrics.test_success_rate,
                    "total_tests": metrics.total_tests,
                    "passed_tests": metrics.passed_tests,
                    "failed_tests": metrics.failed_tests,
                    "skipped_tests": metrics.skipped_tests
                },
                "performance": {
                    "score": metrics.performance_score,
                    "avg_response_time": metrics.avg_response_time,
                    "max_response_time": metrics.max_response_time,
                    "throughput": metrics.throughput
                },
                "security": {
                    "score": metrics.security_score,
                    "critical_vulnerabilities": metrics.critical_vulnerabilities,
                    "high_vulnerabilities": metrics.high_vulnerabilities,
                    "medium_vulnerabilities": metrics.medium_vulnerabilities,
                    "low_vulnerabilities": metrics.low_vulnerabilities
                },
                "quality": {
                    "code_quality_score": metrics.code_quality_score,
                    "complexity_score": metrics.complexity_score,
                    "maintainability_index": metrics.maintainability_index
                }
            },
            "gate_results": [
                {
                    "name": r.gate.name,
                    "description": r.gate.description,
                    "category": r.gate.category,
                    "severity": r.gate.severity,
                    "threshold": r.gate.threshold,
                    "actual_value": r.actual_value,
                    "passed": r.passed,
                    "message": r.message
                }
                for r in results
            ],
            "results_by_category": {
                category: {
                    "total": len(category_results),
                    "passed": sum(1 for r in category_results if r.passed),
                    "failed": sum(1 for r in category_results if not r.passed),
                    "results": [
                        {
                            "name": r.gate.name,
                            "passed": r.passed,
                            "message": r.message
                        }
                        for r in category_results
                    ]
                }
                for category, category_results in results_by_category.items()
            },
            "recommendations": self._generate_recommendations(metrics, results)
        }
        
        return report
    
    def _generate_recommendations(self, metrics: QualityMetrics, results: List[QualityResult]) -> List[str]:
        """Generate recommendations based on quality gate results"""
        recommendations = []
        
        # Coverage recommendations
        if metrics.test_coverage < 80:
            recommendations.append(
                f"Increase test coverage from {metrics.test_coverage:.1f}% to at least 80%. "
                "Focus on testing critical business logic and edge cases."
            )
        
        if metrics.branch_coverage < 75:
            recommendations.append(
                f"Improve branch coverage from {metrics.branch_coverage:.1f}% to at least 75%. "
                "Add tests for conditional logic and error handling paths."
            )
        
        # Performance recommendations
        if metrics.avg_response_time > 2.0:
            recommendations.append(
                f"Optimize performance: average response time is {metrics.avg_response_time:.2f}s. "
                "Consider caching, database optimization, or algorithmic improvements."
            )
        
        if metrics.throughput < 50:
            recommendations.append(
                f"Improve throughput from {metrics.throughput:.1f} to at least 50 requests/second. "
                "Consider connection pooling, async processing, or horizontal scaling."
            )
        
        # Security recommendations
        if metrics.critical_vulnerabilities > 0:
            recommendations.append(
                f"Address {metrics.critical_vulnerabilities} critical security vulnerabilities immediately. "
                "Review security scan reports and update dependencies."
            )
        
        if metrics.high_vulnerabilities > 2:
            recommendations.append(
                f"Address {metrics.high_vulnerabilities} high-severity vulnerabilities. "
                "Prioritize security updates and consider security-focused code review."
            )
        
        # Code quality recommendations
        if metrics.complexity_score > 10:
            recommendations.append(
                f"Reduce code complexity (current: {metrics.complexity_score:.1f}). "
                "Refactor complex functions and consider breaking down large modules."
            )
        
        if metrics.maintainability_index < 60:
            recommendations.append(
                f"Improve maintainability index from {metrics.maintainability_index:.1f} to at least 60. "
                "Focus on code documentation, naming conventions, and modular design."
            )
        
        # Test quality recommendations
        if metrics.test_success_rate < 95:
            recommendations.append(
                f"Improve test success rate from {metrics.test_success_rate:.1f}% to at least 95%. "
                "Fix failing tests and improve test reliability."
            )
        
        if not recommendations:
            recommendations.append("All quality gates passed! Maintain current quality standards.")
        
        return recommendations
    
    def save_report(self, report: Dict[str, Any], output_path: str):
        """Save quality report to file"""
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
    
    def print_summary(self, report: Dict[str, Any]):
        """Print quality gate summary to console"""
        print("\n" + "="*60)
        print("🔍 QUALITY GATE VALIDATION REPORT")
        print("="*60)
        
        summary = report["summary"]
        print(f"Overall Status: {report['overall_status']}")
        print(f"Gates Passed: {summary['passed_gates']}/{summary['total_gates']} ({summary['success_rate']:.1f}%)")
        
        print("\n📊 METRICS SUMMARY")
        print("-"*30)
        metrics = report["metrics"]
        print(f"Test Coverage: {metrics['coverage']['test_coverage']:.1f}%")
        print(f"Test Success Rate: {metrics['testing']['success_rate']:.1f}%")
        print(f"Performance Score: {metrics['performance']['score']:.1f}/100")
        print(f"Security Score: {metrics['security']['score']:.1f}/100")
        print(f"Code Quality Score: {metrics['quality']['code_quality_score']:.1f}/10")
        
        # Print failed gates
        failed_results = [r for r in self.results if not r.passed]
        if failed_results:
            print("\n❌ FAILED QUALITY GATES")
            print("-"*30)
            for result in failed_results:
                severity_icon = {"error": "🚨", "warning": "⚠️", "info": "ℹ️"}.get(result.gate.severity, "❓")
                print(f"{severity_icon} {result.message}")
        
        # Print recommendations
        recommendations = report["recommendations"]
        if recommendations:
            print("\n💡 RECOMMENDATIONS")
            print("-"*30)
            for i, rec in enumerate(recommendations[:5], 1):  # Show top 5
                print(f"{i}. {rec}")
        
        print("\n" + "="*60)


def main():
    """Main entry point for quality gate validation"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate MCP quality gates")
    parser.add_argument("--results-path", required=True, help="Path to test results directory")
    parser.add_argument("--config", help="Path to quality gates configuration")
    parser.add_argument("--output", help="Output path for quality report")
    parser.add_argument("--fail-on-error", action="store_true", help="Exit with code 1 if any error-level gates fail")
    
    args = parser.parse_args()
    
    # Initialize validator
    validator = QualityGateValidator(args.config)
    
    # Collect metrics
    print("🔍 Collecting quality metrics...")
    metrics = validator.collect_metrics(args.results_path)
    
    # Validate gates
    print("🚪 Validating quality gates...")
    results = validator.validate_quality_gates(metrics)
    
    # Generate report
    print("📊 Generating quality report...")
    report = validator.generate_report(metrics, results)
    
    # Save report if output specified
    if args.output:
        validator.save_report(report, args.output)
        print(f"📄 Quality report saved to: {args.output}")
    
    # Print summary
    validator.print_summary(report)
    
    # Exit with appropriate code
    if args.fail_on_error and report["overall_status"] == "FAIL":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()