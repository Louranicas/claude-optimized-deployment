#!/usr/bin/env python3
"""
Quality Excellence Tracking System
ULTRA THINK MODE: Development Standards Quality Excellence Tracker

This system provides comprehensive quality assurance monitoring and automation
for the CODE platform, implementing meta tree mind map quality standards.
"""

import json
import asyncio
import logging
import statistics
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from pathlib import Path
import subprocess
import ast
import re
import tempfile
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class QualityCategory(Enum):
    """Quality assessment categories."""
    CODE_QUALITY = "code_quality"
    TESTING = "testing"
    SECURITY = "security"
    DOCUMENTATION = "documentation"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"
    TYPE_SAFETY = "type_safety"


class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComparisonOperator(Enum):
    """Comparison operators for quality gates."""
    EQUALS = "equals"
    GREATER = "greater"
    GREATER_EQUAL = "greater_equal"
    LESS = "less"
    LESS_EQUAL = "less_equal"
    NOT_EQUALS = "not_equals"

    def compare(self, value: float, threshold: float) -> bool:
        """Compare value against threshold using this operator."""
        if self == self.EQUALS:
            return abs(value - threshold) < 0.001
        elif self == self.GREATER:
            return value > threshold
        elif self == self.GREATER_EQUAL:
            return value >= threshold
        elif self == self.LESS:
            return value < threshold
        elif self == self.LESS_EQUAL:
            return value <= threshold
        elif self == self.NOT_EQUALS:
            return abs(value - threshold) >= 0.001


@dataclass
class QualityMetric:
    """Quality metric measurement."""
    name: str
    value: float
    target: float
    category: QualityCategory
    timestamp: datetime
    unit: str = ""
    trend: str = "stable"  # increasing, decreasing, stable


@dataclass
class QualityGate:
    """Quality gate definition."""
    name: str
    description: str
    category: QualityCategory
    threshold: float
    operator: ComparisonOperator
    severity: Severity
    blocking: bool = True
    enabled: bool = True


@dataclass
class GateResult:
    """Quality gate validation result."""
    gate: QualityGate
    measurement: Optional[float]
    passed: bool
    severity: Severity
    message: str = ""
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class QualityReport:
    """Comprehensive quality assessment report."""
    results: List[GateResult]
    overall_score: float
    grade: str
    timestamp: datetime
    blocking_issues: List[GateResult]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'overall_score': self.overall_score,
            'grade': self.grade,
            'timestamp': self.timestamp.isoformat(),
            'total_gates': len(self.results),
            'passed_gates': len([r for r in self.results if r.passed]),
            'failed_gates': len([r for r in self.results if not r.passed]),
            'blocking_issues': len(self.blocking_issues),
            'recommendations': self.recommendations,
            'gate_results': [
                {
                    'name': r.gate.name,
                    'category': r.gate.category.value,
                    'passed': r.passed,
                    'measurement': r.measurement,
                    'threshold': r.gate.threshold,
                    'severity': r.severity.value,
                    'message': r.message
                }
                for r in self.results
            ]
        }


class CodeQualityAnalyzer:
    """Analyze code quality metrics."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.src_path = self.project_root / "src"

    def analyze_syntax_errors(self) -> QualityMetric:
        """Analyze syntax error rate."""
        python_files = list(self.src_path.rglob("*.py"))
        error_count = 0
        
        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                ast.parse(content)
            except SyntaxError:
                error_count += 1
            except Exception:
                error_count += 1
        
        error_rate = (error_count / len(python_files)) * 100 if python_files else 0
        
        return QualityMetric(
            name="syntax_error_rate",
            value=error_rate,
            target=0.0,
            category=QualityCategory.CODE_QUALITY,
            timestamp=datetime.now(),
            unit="%"
        )

    def analyze_complexity(self) -> QualityMetric:
        """Analyze cyclomatic complexity."""
        python_files = list(self.src_path.rglob("*.py"))
        complexities = []
        
        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        complexity = self._calculate_complexity(node)
                        complexities.append(complexity)
            except Exception as e:
                logger.warning(f"Error analyzing {file_path}: {e}")
        
        avg_complexity = statistics.mean(complexities) if complexities else 0
        
        return QualityMetric(
            name="average_complexity",
            value=avg_complexity,
            target=5.0,
            category=QualityCategory.MAINTAINABILITY,
            timestamp=datetime.now(),
            unit=""
        )

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity for a function."""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, (ast.And, ast.Or)):
                complexity += 1
        
        return complexity

    def analyze_type_hints(self) -> QualityMetric:
        """Analyze type hint coverage."""
        python_files = list(self.src_path.rglob("*.py"))
        total_functions = 0
        typed_functions = 0
        
        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if not node.name.startswith('_'):  # Only public functions
                            total_functions += 1
                            
                            # Check for return type hint
                            has_return_hint = node.returns is not None
                            
                            # Check for parameter type hints
                            param_hints = sum(1 for arg in node.args.args if arg.annotation)
                            total_params = len(node.args.args)
                            
                            # Function is considered typed if it has return hint and all params are typed
                            if has_return_hint and (total_params == 0 or param_hints == total_params):
                                typed_functions += 1
                                
            except Exception as e:
                logger.warning(f"Error analyzing type hints in {file_path}: {e}")
        
        coverage = (typed_functions / total_functions) * 100 if total_functions > 0 else 0
        
        return QualityMetric(
            name="type_hint_coverage",
            value=coverage,
            target=80.0,
            category=QualityCategory.TYPE_SAFETY,
            timestamp=datetime.now(),
            unit="%"
        )

    def analyze_docstring_coverage(self) -> QualityMetric:
        """Analyze docstring coverage."""
        python_files = list(self.src_path.rglob("*.py"))
        total_items = 0
        documented_items = 0
        
        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        total_items += 1
                        if ast.get_docstring(node):
                            documented_items += 1
                    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if not node.name.startswith('_'):  # Only public functions
                            total_items += 1
                            if ast.get_docstring(node):
                                documented_items += 1
                                
            except Exception as e:
                logger.warning(f"Error analyzing docstrings in {file_path}: {e}")
        
        coverage = (documented_items / total_items) * 100 if total_items > 0 else 0
        
        return QualityMetric(
            name="docstring_coverage",
            value=coverage,
            target=85.0,
            category=QualityCategory.DOCUMENTATION,
            timestamp=datetime.now(),
            unit="%"
        )


class SecurityAnalyzer:
    """Analyze security metrics."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)

    def run_security_scan(self) -> List[QualityMetric]:
        """Run comprehensive security analysis."""
        metrics = []
        
        # Bandit security scan
        bandit_results = self._run_bandit()
        if bandit_results:
            metrics.extend(bandit_results)
        
        # Safety dependency scan
        safety_results = self._run_safety()
        if safety_results:
            metrics.extend(safety_results)
        
        return metrics

    def _run_bandit(self) -> List[QualityMetric]:
        """Run Bandit security scanner."""
        try:
            cmd = ["bandit", "-r", str(self.project_root / "src"), "-f", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                data = json.loads(result.stdout)
                metrics = data.get("metrics", {}).get("_totals", {})
                
                return [
                    QualityMetric(
                        name="critical_vulnerabilities",
                        value=metrics.get("SEVERITY.HIGH", 0),
                        target=0.0,
                        category=QualityCategory.SECURITY,
                        timestamp=datetime.now(),
                        unit="count"
                    ),
                    QualityMetric(
                        name="medium_vulnerabilities",
                        value=metrics.get("SEVERITY.MEDIUM", 0),
                        target=5.0,
                        category=QualityCategory.SECURITY,
                        timestamp=datetime.now(),
                        unit="count"
                    )
                ]
        except Exception as e:
            logger.warning(f"Bandit scan failed: {e}")
            return []

    def _run_safety(self) -> List[QualityMetric]:
        """Run Safety dependency scanner."""
        try:
            cmd = ["safety", "check", "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                data = json.loads(result.stdout)
                vulnerability_count = len(data) if isinstance(data, list) else 0
                
                return [
                    QualityMetric(
                        name="dependency_vulnerabilities",
                        value=vulnerability_count,
                        target=0.0,
                        category=QualityCategory.SECURITY,
                        timestamp=datetime.now(),
                        unit="count"
                    )
                ]
        except Exception as e:
            logger.warning(f"Safety scan failed: {e}")
            return []


class TestCoverageAnalyzer:
    """Analyze test coverage metrics."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)

    def analyze_coverage(self) -> List[QualityMetric]:
        """Analyze test coverage."""
        try:
            # Run pytest with coverage
            cmd = [
                "python", "-m", "pytest",
                "--cov=src",
                "--cov-report=json:coverage.json",
                "--tb=no",
                "-q"
            ]
            
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            coverage_file = self.project_root / "coverage.json"
            if coverage_file.exists():
                with open(coverage_file) as f:
                    data = json.load(f)
                
                totals = data.get("totals", {})
                line_coverage = totals.get("percent_covered", 0)
                
                return [
                    QualityMetric(
                        name="line_coverage",
                        value=line_coverage,
                        target=85.0,
                        category=QualityCategory.TESTING,
                        timestamp=datetime.now(),
                        unit="%"
                    )
                ]
        except Exception as e:
            logger.warning(f"Coverage analysis failed: {e}")
            return []


class QualityGateValidator:
    """Validate quality gates against measurements."""
    
    def __init__(self):
        self.gates = self._define_quality_gates()
        self.measurements = {}

    def _define_quality_gates(self) -> List[QualityGate]:
        """Define comprehensive quality gates."""
        return [
            # Code Quality Gates
            QualityGate(
                name="syntax_error_rate",
                description="Code must be syntactically valid",
                category=QualityCategory.CODE_QUALITY,
                threshold=0.0,
                operator=ComparisonOperator.EQUALS,
                severity=Severity.CRITICAL,
                blocking=True
            ),
            
            QualityGate(
                name="average_complexity",
                description="Average function complexity should be reasonable",
                category=QualityCategory.MAINTAINABILITY,
                threshold=5.0,
                operator=ComparisonOperator.LESS_EQUAL,
                severity=Severity.MEDIUM,
                blocking=False
            ),
            
            QualityGate(
                name="type_hint_coverage",
                description="Type hint coverage for public APIs",
                category=QualityCategory.TYPE_SAFETY,
                threshold=80.0,
                operator=ComparisonOperator.GREATER_EQUAL,
                severity=Severity.HIGH,
                blocking=False
            ),
            
            QualityGate(
                name="docstring_coverage",
                description="Documentation coverage for public APIs",
                category=QualityCategory.DOCUMENTATION,
                threshold=85.0,
                operator=ComparisonOperator.GREATER_EQUAL,
                severity=Severity.MEDIUM,
                blocking=False
            ),
            
            # Testing Gates
            QualityGate(
                name="line_coverage",
                description="Test line coverage percentage",
                category=QualityCategory.TESTING,
                threshold=85.0,
                operator=ComparisonOperator.GREATER_EQUAL,
                severity=Severity.HIGH,
                blocking=True
            ),
            
            # Security Gates
            QualityGate(
                name="critical_vulnerabilities",
                description="Critical security vulnerabilities",
                category=QualityCategory.SECURITY,
                threshold=0,
                operator=ComparisonOperator.EQUALS,
                severity=Severity.CRITICAL,
                blocking=True
            ),
            
            QualityGate(
                name="medium_vulnerabilities",
                description="Medium severity security vulnerabilities",
                category=QualityCategory.SECURITY,
                threshold=5,
                operator=ComparisonOperator.LESS_EQUAL,
                severity=Severity.MEDIUM,
                blocking=False
            ),
            
            QualityGate(
                name="dependency_vulnerabilities",
                description="Dependency security vulnerabilities",
                category=QualityCategory.SECURITY,
                threshold=0,
                operator=ComparisonOperator.EQUALS,
                severity=Severity.HIGH,
                blocking=True
            )
        ]

    def add_measurement(self, name: str, value: float):
        """Add a measurement for gate validation."""
        self.measurements[name] = value

    def validate_all(self) -> QualityReport:
        """Validate all gates and generate report."""
        results = []
        
        for gate in self.gates:
            if not gate.enabled:
                continue
                
            if gate.name in self.measurements:
                measurement = self.measurements[gate.name]
                passed = gate.operator.compare(measurement, gate.threshold)
                
                result = GateResult(
                    gate=gate,
                    measurement=measurement,
                    passed=passed,
                    severity=gate.severity if not passed else Severity.INFO,
                    message=self._generate_gate_message(gate, measurement, passed)
                )
            else:
                result = GateResult(
                    gate=gate,
                    measurement=None,
                    passed=False,
                    severity=Severity.HIGH,
                    message=f"Measurement not available for {gate.name}"
                )
            
            results.append(result)

        blocking_issues = [r for r in results if not r.passed and r.gate.blocking]
        overall_score = self._calculate_overall_score(results)
        grade = self._calculate_grade(overall_score)
        recommendations = self._generate_recommendations(results)

        return QualityReport(
            results=results,
            overall_score=overall_score,
            grade=grade,
            timestamp=datetime.now(),
            blocking_issues=blocking_issues,
            recommendations=recommendations
        )

    def _generate_gate_message(self, gate: QualityGate, measurement: float, passed: bool) -> str:
        """Generate descriptive message for gate result."""
        if passed:
            return f"✅ {gate.description}: {measurement} meets threshold {gate.threshold}"
        else:
            return f"❌ {gate.description}: {measurement} fails threshold {gate.threshold}"

    def _calculate_overall_score(self, results: List[GateResult]) -> float:
        """Calculate overall quality score."""
        if not results:
            return 0.0
        
        passed_count = sum(1 for r in results if r.passed)
        return (passed_count / len(results)) * 100

    def _calculate_grade(self, score: float) -> str:
        """Convert numeric score to letter grade."""
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "A-"
        elif score >= 80:
            return "B+"
        elif score >= 75:
            return "B"
        elif score >= 70:
            return "B-"
        elif score >= 65:
            return "C+"
        elif score >= 60:
            return "C"
        else:
            return "F"

    def _generate_recommendations(self, results: List[GateResult]) -> List[str]:
        """Generate improvement recommendations."""
        recommendations = []
        
        failed_results = [r for r in results if not r.passed]
        
        # Priority recommendations based on severity
        critical_failures = [r for r in failed_results if r.severity == Severity.CRITICAL]
        if critical_failures:
            recommendations.append("🚨 CRITICAL: Fix syntax errors and security vulnerabilities immediately")
        
        high_failures = [r for r in failed_results if r.severity == Severity.HIGH]
        if high_failures:
            recommendations.append("⚠️ HIGH: Improve test coverage and address dependency vulnerabilities")
        
        medium_failures = [r for r in failed_results if r.severity == Severity.MEDIUM]
        if medium_failures:
            recommendations.append("📝 MEDIUM: Enhance documentation and reduce code complexity")
        
        # Specific recommendations
        for result in failed_results:
            if result.gate.name == "type_hint_coverage":
                recommendations.append("Add type hints to improve code safety and IDE support")
            elif result.gate.name == "line_coverage":
                recommendations.append("Write additional tests to improve coverage")
            elif result.gate.name == "average_complexity":
                recommendations.append("Refactor complex functions into smaller, focused functions")
        
        return recommendations


class QualityExcellenceTracker:
    """Main quality excellence tracking system."""
    
    def __init__(self, project_root: str):
        self.project_root = project_root
        self.code_analyzer = CodeQualityAnalyzer(project_root)
        self.security_analyzer = SecurityAnalyzer(project_root)
        self.coverage_analyzer = TestCoverageAnalyzer(project_root)
        self.gate_validator = QualityGateValidator()
        self.history = []

    async def run_comprehensive_analysis(self) -> QualityReport:
        """Run comprehensive quality analysis."""
        logger.info("Starting comprehensive quality analysis...")
        
        # Collect all metrics
        metrics = []
        
        # Code quality metrics
        logger.info("Analyzing code quality...")
        metrics.append(self.code_analyzer.analyze_syntax_errors())
        metrics.append(self.code_analyzer.analyze_complexity())
        metrics.append(self.code_analyzer.analyze_type_hints())
        metrics.append(self.code_analyzer.analyze_docstring_coverage())
        
        # Security metrics
        logger.info("Analyzing security...")
        security_metrics = self.security_analyzer.run_security_scan()
        metrics.extend(security_metrics)
        
        # Test coverage metrics
        logger.info("Analyzing test coverage...")
        coverage_metrics = self.coverage_analyzer.analyze_coverage()
        metrics.extend(coverage_metrics)
        
        # Add measurements to validator
        for metric in metrics:
            self.gate_validator.add_measurement(metric.name, metric.value)
        
        # Validate quality gates
        logger.info("Validating quality gates...")
        report = self.gate_validator.validate_all()
        
        # Store historical data
        self.history.append(report)
        
        logger.info(f"Quality analysis complete. Overall score: {report.overall_score:.1f} ({report.grade})")
        return report

    def save_report(self, report: QualityReport, output_path: str = None):
        """Save quality report to file."""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"quality_report_{timestamp}.json"
        
        with open(output_path, 'w') as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        
        logger.info(f"Quality report saved to {output_path}")

    def generate_dashboard_data(self) -> Dict[str, Any]:
        """Generate dashboard data for quality monitoring."""
        if not self.history:
            return {"error": "No quality data available"}
        
        latest_report = self.history[-1]
        
        # Calculate trends if we have historical data
        trends = {}
        if len(self.history) > 1:
            prev_report = self.history[-2]
            score_change = latest_report.overall_score - prev_report.overall_score
            trends['score_trend'] = 'improving' if score_change > 0 else 'declining' if score_change < 0 else 'stable'
        
        return {
            'overview': {
                'overall_score': latest_report.overall_score,
                'grade': latest_report.grade,
                'total_gates': len(latest_report.results),
                'passed_gates': len([r for r in latest_report.results if r.passed]),
                'failed_gates': len([r for r in latest_report.results if not r.passed]),
                'blocking_issues': len(latest_report.blocking_issues),
                'last_updated': latest_report.timestamp.isoformat()
            },
            'trends': trends,
            'gates_by_category': self._group_gates_by_category(latest_report),
            'blocking_issues': [
                {
                    'name': issue.gate.name,
                    'category': issue.gate.category.value,
                    'severity': issue.severity.value,
                    'message': issue.message
                }
                for issue in latest_report.blocking_issues
            ],
            'recommendations': latest_report.recommendations
        }

    def _group_gates_by_category(self, report: QualityReport) -> Dict[str, Any]:
        """Group gate results by category."""
        categories = {}
        
        for result in report.results:
            category = result.gate.category.value
            if category not in categories:
                categories[category] = {
                    'total': 0,
                    'passed': 0,
                    'failed': 0,
                    'score': 0
                }
            
            categories[category]['total'] += 1
            if result.passed:
                categories[category]['passed'] += 1
            else:
                categories[category]['failed'] += 1
        
        # Calculate category scores
        for category_data in categories.values():
            if category_data['total'] > 0:
                category_data['score'] = (category_data['passed'] / category_data['total']) * 100
        
        return categories


async def main():
    """Main entry point for quality excellence tracker."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Quality Excellence Tracker")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    parser.add_argument("--output", help="Output file path for report")
    parser.add_argument("--dashboard", action="store_true", help="Generate dashboard data")
    parser.add_argument("--continuous", action="store_true", help="Run continuous monitoring")
    
    args = parser.parse_args()
    
    tracker = QualityExcellenceTracker(args.project_root)
    
    if args.continuous:
        logger.info("Starting continuous quality monitoring...")
        while True:
            try:
                report = await tracker.run_comprehensive_analysis()
                tracker.save_report(report)
                
                if report.blocking_issues:
                    logger.error(f"⚠️ {len(report.blocking_issues)} blocking quality issues found!")
                    for issue in report.blocking_issues:
                        logger.error(f"  - {issue.message}")
                
                # Wait 1 hour before next analysis
                await asyncio.sleep(3600)
                
            except KeyboardInterrupt:
                logger.info("Continuous monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error
    else:
        # Single analysis run
        report = await tracker.run_comprehensive_analysis()
        
        if args.output:
            tracker.save_report(report, args.output)
        else:
            tracker.save_report(report)
        
        if args.dashboard:
            dashboard_data = tracker.generate_dashboard_data()
            dashboard_file = "quality_dashboard.json"
            with open(dashboard_file, 'w') as f:
                json.dump(dashboard_data, f, indent=2, default=str)
            logger.info(f"Dashboard data saved to {dashboard_file}")
        
        # Print summary
        print("\n" + "="*80)
        print("🎯 QUALITY EXCELLENCE TRACKING SUMMARY")
        print("="*80)
        print(f"Overall Quality Score: {report.overall_score:.1f} (Grade: {report.grade})")
        print(f"Total Quality Gates: {len(report.results)}")
        print(f"Passed: {len([r for r in report.results if r.passed])}")
        print(f"Failed: {len([r for r in report.results if not r.passed])}")
        print(f"Blocking Issues: {len(report.blocking_issues)}")
        
        if report.blocking_issues:
            print("\n🚨 BLOCKING ISSUES:")
            for issue in report.blocking_issues:
                print(f"  - {issue.message}")
        
        if report.recommendations:
            print("\n💡 RECOMMENDATIONS:")
            for rec in report.recommendations:
                print(f"  - {rec}")
        
        print("="*80)


if __name__ == "__main__":
    asyncio.run(main())