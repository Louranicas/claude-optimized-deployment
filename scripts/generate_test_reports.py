#!/usr/bin/env python3
"""
Test Report Generation Script

Generates comprehensive test reports, badges, and documentation
for the Claude Optimized Deployment testing infrastructure.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional
import subprocess
import sys
import tempfile
from datetime import datetime
import argparse


class TestReportGenerator:
    """Generate comprehensive test reports and badges."""
    
    def __init__(self, report_dir: Path = Path("test-results")):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(exist_ok=True)
        
    def generate_coverage_badge(self, coverage_file: Path = Path("coverage/coverage.json")) -> str:
        """Generate coverage badge SVG."""
        try:
            with open(coverage_file, 'r') as f:
                coverage_data = json.load(f)
            
            coverage_percent = coverage_data.get('totals', {}).get('percent_covered', 0)
            
            # Determine badge color based on coverage
            if coverage_percent >= 90:
                color = "brightgreen"
            elif coverage_percent >= 80:
                color = "green"
            elif coverage_percent >= 70:
                color = "yellow"
            elif coverage_percent >= 60:
                color = "orange"
            else:
                color = "red"
            
            # Generate badge using shields.io format
            badge_svg = self._create_badge_svg("coverage", f"{coverage_percent:.1f}%", color)
            
            badge_path = self.report_dir / "coverage-badge.svg"
            with open(badge_path, 'w') as f:
                f.write(badge_svg)
            
            return str(badge_path)
            
        except Exception as e:
            print(f"Error generating coverage badge: {e}")
            return self._create_badge_svg("coverage", "unknown", "lightgrey")
    
    def generate_test_status_badge(self, junit_files: List[Path]) -> str:
        """Generate test status badge from JUnit XML files."""
        total_tests = 0
        failed_tests = 0
        
        for junit_file in junit_files:
            if junit_file.exists():
                try:
                    tree = ET.parse(junit_file)
                    root = tree.getroot()
                    
                    # Handle both testsuite and testsuites root elements
                    if root.tag == 'testsuites':
                        for testsuite in root.findall('testsuite'):
                            total_tests += int(testsuite.get('tests', 0))
                            failed_tests += int(testsuite.get('failures', 0))
                            failed_tests += int(testsuite.get('errors', 0))
                    elif root.tag == 'testsuite':
                        total_tests += int(root.get('tests', 0))
                        failed_tests += int(root.get('failures', 0))
                        failed_tests += int(root.get('errors', 0))
                        
                except ET.ParseError as e:
                    print(f"Error parsing {junit_file}: {e}")
        
        if total_tests == 0:
            status = "no tests"
            color = "lightgrey"
        elif failed_tests == 0:
            status = f"{total_tests} passing"
            color = "brightgreen"
        else:
            status = f"{failed_tests}/{total_tests} failing"
            color = "red"
        
        badge_svg = self._create_badge_svg("tests", status, color)
        badge_path = self.report_dir / "test-status-badge.svg"
        
        with open(badge_path, 'w') as f:
            f.write(badge_svg)
        
        return str(badge_path)
    
    def generate_performance_badge(self, benchmark_file: Path = Path("test-results/benchmark-results.json")) -> str:
        """Generate performance badge from benchmark results."""
        try:
            with open(benchmark_file, 'r') as f:
                benchmark_data = json.load(f)
            
            # Extract performance metrics
            benchmarks = benchmark_data.get('benchmarks', [])
            if not benchmarks:
                return self._create_badge_svg("performance", "no data", "lightgrey")
            
            # Calculate average performance score
            total_time = sum(b.get('stats', {}).get('mean', 0) for b in benchmarks)
            avg_time = total_time / len(benchmarks)
            
            # Determine status based on average time
            if avg_time < 0.1:  # < 100ms
                status = "excellent"
                color = "brightgreen"
            elif avg_time < 0.5:  # < 500ms
                status = "good"
                color = "green"
            elif avg_time < 1.0:  # < 1s
                status = "fair"
                color = "yellow"
            else:
                status = "poor"
                color = "red"
            
            badge_svg = self._create_badge_svg("performance", status, color)
            badge_path = self.report_dir / "performance-badge.svg"
            
            with open(badge_path, 'w') as f:
                f.write(badge_svg)
            
            return str(badge_path)
            
        except Exception as e:
            print(f"Error generating performance badge: {e}")
            return self._create_badge_svg("performance", "unknown", "lightgrey")
    
    def generate_security_badge(self, security_reports: List[Path]) -> str:
        """Generate security badge from security scan results."""
        high_issues = 0
        medium_issues = 0
        low_issues = 0
        
        for report_file in security_reports:
            if not report_file.exists():
                continue
                
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)
                
                # Handle different security tool formats
                if 'results' in data:  # Bandit format
                    for result in data['results']:
                        severity = result.get('issue_severity', 'LOW').upper()
                        if severity == 'HIGH':
                            high_issues += 1
                        elif severity == 'MEDIUM':
                            medium_issues += 1
                        else:
                            low_issues += 1
                            
                elif 'vulnerabilities' in data:  # Safety format
                    for vuln in data['vulnerabilities']:
                        # Safety doesn't always have severity, assume medium
                        medium_issues += 1
                        
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Error parsing security report {report_file}: {e}")
        
        # Determine badge status
        if high_issues > 0:
            status = f"{high_issues} high issues"
            color = "red"
        elif medium_issues > 0:
            status = f"{medium_issues} medium issues"
            color = "orange"
        elif low_issues > 0:
            status = f"{low_issues} low issues"
            color = "yellow"
        else:
            status = "no issues"
            color = "brightgreen"
        
        badge_svg = self._create_badge_svg("security", status, color)
        badge_path = self.report_dir / "security-badge.svg"
        
        with open(badge_path, 'w') as f:
            f.write(badge_svg)
        
        return str(badge_path)
    
    def generate_comprehensive_report(self) -> str:
        """Generate a comprehensive HTML test report."""
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "coverage": self._get_coverage_data(),
            "test_results": self._get_test_results(),
            "performance": self._get_performance_data(),
            "security": self._get_security_data()
        }
        
        html_content = self._generate_html_report(report_data)
        report_path = self.report_dir / "comprehensive-report.html"
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        return str(report_path)
    
    def generate_json_summary(self) -> str:
        """Generate JSON summary of all test results."""
        summary = {
            "generated_at": datetime.now().isoformat(),
            "coverage": self._get_coverage_summary(),
            "tests": self._get_test_summary(),
            "performance": self._get_performance_summary(),
            "security": self._get_security_summary(),
            "quality_score": self._calculate_quality_score()
        }
        
        summary_path = self.report_dir / "test-summary.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return str(summary_path)
    
    def _create_badge_svg(self, label: str, message: str, color: str) -> str:
        """Create SVG badge content."""
        # Simple SVG badge template
        return f'''<svg xmlns="http://www.w3.org/2000/svg" width="104" height="20">
    <linearGradient id="b" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <mask id="a">
        <rect width="104" height="20" rx="3" fill="#fff"/>
    </mask>
    <g mask="url(#a)">
        <path fill="#555" d="M0 0h63v20H0z"/>
        <path fill="{self._get_color_hex(color)}" d="M63 0h41v20H63z"/>
        <path fill="url(#b)" d="M0 0h104v20H0z"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
        <text x="31.5" y="15" fill="#010101" fill-opacity=".3">{label}</text>
        <text x="31.5" y="14">{label}</text>
        <text x="82.5" y="15" fill="#010101" fill-opacity=".3">{message}</text>
        <text x="82.5" y="14">{message}</text>
    </g>
</svg>'''
    
    def _get_color_hex(self, color: str) -> str:
        """Convert color name to hex value."""
        color_map = {
            "brightgreen": "#4c1",
            "green": "#97CA00",
            "yellow": "#dfb317",
            "orange": "#fe7d37",
            "red": "#e05d44",
            "lightgrey": "#9f9f9f"
        }
        return color_map.get(color, "#9f9f9f")
    
    def _get_coverage_data(self) -> Dict[str, Any]:
        """Extract coverage data from coverage reports."""
        coverage_file = Path("coverage/coverage.json")
        if coverage_file.exists():
            try:
                with open(coverage_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def _get_test_results(self) -> List[Dict[str, Any]]:
        """Extract test results from JUnit XML files."""
        results = []
        junit_files = list(self.report_dir.glob("*.xml"))
        
        for junit_file in junit_files:
            try:
                tree = ET.parse(junit_file)
                root = tree.getroot()
                
                if root.tag == 'testsuite':
                    results.append({
                        "name": root.get('name', str(junit_file.name)),
                        "tests": int(root.get('tests', 0)),
                        "failures": int(root.get('failures', 0)),
                        "errors": int(root.get('errors', 0)),
                        "time": float(root.get('time', 0))
                    })
                    
            except Exception as e:
                print(f"Error parsing {junit_file}: {e}")
        
        return results
    
    def _get_performance_data(self) -> Dict[str, Any]:
        """Extract performance data from benchmark results."""
        benchmark_file = self.report_dir / "benchmark-results.json"
        if benchmark_file.exists():
            try:
                with open(benchmark_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def _get_security_data(self) -> List[Dict[str, Any]]:
        """Extract security data from security reports."""
        security_data = []
        security_files = [
            self.report_dir / "bandit-report.json",
            self.report_dir / "safety-report.json",
            self.report_dir / "semgrep-report.json"
        ]
        
        for security_file in security_files:
            if security_file.exists():
                try:
                    with open(security_file, 'r') as f:
                        data = json.load(f)
                        security_data.append({
                            "tool": security_file.stem.replace("-report", ""),
                            "data": data
                        })
                except Exception:
                    pass
        
        return security_data
    
    def _get_coverage_summary(self) -> Dict[str, Any]:
        """Get coverage summary."""
        coverage_data = self._get_coverage_data()
        totals = coverage_data.get('totals', {})
        return {
            "percent_covered": totals.get('percent_covered', 0),
            "num_statements": totals.get('num_statements', 0),
            "missing_lines": totals.get('missing_lines', 0)
        }
    
    def _get_test_summary(self) -> Dict[str, Any]:
        """Get test summary."""
        test_results = self._get_test_results()
        total_tests = sum(r['tests'] for r in test_results)
        total_failures = sum(r['failures'] + r['errors'] for r in test_results)
        
        return {
            "total_tests": total_tests,
            "total_failures": total_failures,
            "success_rate": (total_tests - total_failures) / total_tests * 100 if total_tests > 0 else 0,
            "test_suites": len(test_results)
        }
    
    def _get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        perf_data = self._get_performance_data()
        benchmarks = perf_data.get('benchmarks', [])
        
        if benchmarks:
            avg_time = sum(b.get('stats', {}).get('mean', 0) for b in benchmarks) / len(benchmarks)
            return {
                "benchmark_count": len(benchmarks),
                "average_time": avg_time,
                "status": "good" if avg_time < 0.5 else "needs_improvement"
            }
        
        return {"benchmark_count": 0, "average_time": 0, "status": "no_data"}
    
    def _get_security_summary(self) -> Dict[str, Any]:
        """Get security summary."""
        security_data = self._get_security_data()
        total_issues = 0
        
        for tool_data in security_data:
            data = tool_data['data']
            if 'results' in data:  # Bandit
                total_issues += len(data['results'])
            elif 'vulnerabilities' in data:  # Safety
                total_issues += len(data['vulnerabilities'])
        
        return {
            "total_issues": total_issues,
            "tools_run": len(security_data),
            "status": "secure" if total_issues == 0 else "issues_found"
        }
    
    def _calculate_quality_score(self) -> float:
        """Calculate overall quality score (0-100)."""
        coverage_score = self._get_coverage_summary()['percent_covered']
        test_score = self._get_test_summary()['success_rate']
        
        # Security penalty
        security_issues = self._get_security_summary()['total_issues']
        security_score = max(0, 100 - (security_issues * 10))
        
        # Performance score (simplified)
        perf_summary = self._get_performance_summary()
        perf_score = 100 if perf_summary['status'] == 'good' else 70 if perf_summary['status'] == 'needs_improvement' else 50
        
        # Weighted average
        return (coverage_score * 0.3 + test_score * 0.4 + security_score * 0.2 + perf_score * 0.1)
    
    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report content."""
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Claude Optimized Deployment - Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 10px; background: #f9f9f9; border-radius: 3px; }}
        .success {{ color: green; }}
        .warning {{ color: orange; }}
        .error {{ color: red; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Claude Optimized Deployment - Test Report</h1>
        <p>Generated: {data['timestamp']}</p>
        <p>Quality Score: {self._calculate_quality_score():.1f}/100</p>
    </div>
    
    <div class="section">
        <h2>Coverage Summary</h2>
        <div class="metric">Coverage: {self._get_coverage_summary()['percent_covered']:.1f}%</div>
        <div class="metric">Statements: {self._get_coverage_summary()['num_statements']}</div>
    </div>
    
    <div class="section">
        <h2>Test Results</h2>
        <div class="metric">Total Tests: {self._get_test_summary()['total_tests']}</div>
        <div class="metric">Failures: {self._get_test_summary()['total_failures']}</div>
        <div class="metric">Success Rate: {self._get_test_summary()['success_rate']:.1f}%</div>
    </div>
    
    <div class="section">
        <h2>Security Summary</h2>
        <div class="metric">Issues Found: {self._get_security_summary()['total_issues']}</div>
        <div class="metric">Tools Run: {self._get_security_summary()['tools_run']}</div>
    </div>
    
    <div class="section">
        <h2>Performance Summary</h2>
        <div class="metric">Benchmarks: {self._get_performance_summary()['benchmark_count']}</div>
        <div class="metric">Avg Time: {self._get_performance_summary()['average_time']:.3f}s</div>
    </div>
</body>
</html>'''


def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(description="Generate test reports and badges")
    parser.add_argument("--report-dir", default="test-results", help="Test results directory")
    parser.add_argument("--generate-badges", action="store_true", help="Generate badges")
    parser.add_argument("--generate-report", action="store_true", help="Generate HTML report")
    parser.add_argument("--generate-summary", action="store_true", help="Generate JSON summary")
    parser.add_argument("--all", action="store_true", help="Generate all reports and badges")
    
    args = parser.parse_args()
    
    generator = TestReportGenerator(Path(args.report_dir))
    
    if args.all or args.generate_badges:
        print("Generating badges...")
        generator.generate_coverage_badge()
        generator.generate_test_status_badge(list(Path(args.report_dir).glob("*.xml")))
        generator.generate_performance_badge()
        generator.generate_security_badge([
            Path(args.report_dir) / "bandit-report.json",
            Path(args.report_dir) / "safety-report.json"
        ])
        print("Badges generated!")
    
    if args.all or args.generate_report:
        print("Generating HTML report...")
        report_path = generator.generate_comprehensive_report()
        print(f"HTML report generated: {report_path}")
    
    if args.all or args.generate_summary:
        print("Generating JSON summary...")
        summary_path = generator.generate_json_summary()
        print(f"JSON summary generated: {summary_path}")


if __name__ == "__main__":
    main()