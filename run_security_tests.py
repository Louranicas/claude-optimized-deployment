#!/usr/bin/env python3
"""
Security Test Suite Runner

Runs comprehensive security tests and generates reports.
"""

import subprocess
import sys
import json
import os
from datetime import datetime
from pathlib import Path


class SecurityTestRunner:
    """Run security tests and generate comprehensive reports."""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "test_categories": {},
            "vulnerabilities": [],
            "recommendations": []
        }
        self.report_dir = Path("security_reports")
        self.report_dir.mkdir(exist_ok=True)
    
    def run_all_tests(self):
        """Run all security test categories."""
        print("🔒 Running Comprehensive Security Test Suite")
        print("=" * 60)
        
        test_categories = [
            ("Authentication Bypass", "tests/security/test_authentication_bypass.py"),
            ("Command Injection", "tests/security/test_command_injection.py"),
            ("SQL Injection", "tests/security/test_sql_injection.py"),
            ("CSRF Protection", "tests/security/test_csrf_protection.py"),
            ("Rate Limiting", "tests/security/test_rate_limiting.py"),
            ("Security Regression", "tests/security/test_security_regression.py")
        ]
        
        total_passed = 0
        total_failed = 0
        
        for category_name, test_file in test_categories:
            print(f"\n📋 Testing: {category_name}")
            print("-" * 40)
            
            passed, failed = self.run_category_tests(category_name, test_file)
            total_passed += passed
            total_failed += failed
        
        # Generate final report
        self.generate_final_report(total_passed, total_failed)
        
        # Return exit code
        return 0 if total_failed == 0 else 1
    
    def run_category_tests(self, category_name: str, test_file: str):
        """Run tests for a specific category."""
        cmd = [
            sys.executable, "-m", "pytest",
            test_file,
            "-v",
            "--tb=short",
            "--json-report",
            f"--json-report-file={self.report_dir}/{category_name.lower().replace(' ', '_')}.json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Parse results
        passed = 0
        failed = 0
        
        if "passed" in result.stdout:
            # Extract test counts from pytest output
            import re
            match = re.search(r'(\d+) passed', result.stdout)
            if match:
                passed = int(match.group(1))
            
            match = re.search(r'(\d+) failed', result.stdout)
            if match:
                failed = int(match.group(1))
        
        # Store results
        self.results["test_categories"][category_name] = {
            "passed": passed,
            "failed": failed,
            "total": passed + failed,
            "status": "PASS" if failed == 0 else "FAIL"
        }
        
        # Check for vulnerabilities
        if failed > 0:
            self.analyze_failures(category_name, result.stdout)
        
        print(f"✅ Passed: {passed}")
        if failed > 0:
            print(f"❌ Failed: {failed}")
        
        return passed, failed
    
    def analyze_failures(self, category: str, output: str):
        """Analyze test failures for vulnerabilities."""
        vulnerability_patterns = {
            "authentication": ["bypass", "privilege", "escalation"],
            "injection": ["sql", "command", "code", "script"],
            "csrf": ["forgery", "token", "missing"],
            "rate": ["limit", "ddos", "brute force"]
        }
        
        for vuln_type, patterns in vulnerability_patterns.items():
            for pattern in patterns:
                if pattern.lower() in output.lower():
                    self.results["vulnerabilities"].append({
                        "category": category,
                        "type": vuln_type,
                        "severity": self.determine_severity(vuln_type),
                        "description": f"Potential {vuln_type} vulnerability detected"
                    })
                    break
    
    def determine_severity(self, vuln_type: str) -> str:
        """Determine vulnerability severity."""
        critical_types = ["authentication", "injection", "privilege"]
        high_types = ["csrf", "session", "encryption"]
        
        if any(crit in vuln_type for crit in critical_types):
            return "CRITICAL"
        elif any(high in vuln_type for high in high_types):
            return "HIGH"
        else:
            return "MEDIUM"
    
    def generate_final_report(self, total_passed: int, total_failed: int):
        """Generate comprehensive security test report."""
        print("\n" + "=" * 60)
        print("📊 Security Test Summary")
        print("=" * 60)
        
        # Calculate metrics
        total_tests = total_passed + total_failed
        pass_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
        
        # Summary
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {total_passed}")
        print(f"Failed: {total_failed}")
        print(f"Pass Rate: {pass_rate:.2f}%")
        
        # Vulnerability summary
        if self.results["vulnerabilities"]:
            print(f"\n⚠️  Vulnerabilities Found: {len(self.results['vulnerabilities'])}")
            
            by_severity = {}
            for vuln in self.results["vulnerabilities"]:
                severity = vuln["severity"]
                by_severity[severity] = by_severity.get(severity, 0) + 1
            
            for severity, count in sorted(by_severity.items()):
                print(f"  - {severity}: {count}")
        else:
            print("\n✅ No vulnerabilities detected!")
        
        # Recommendations
        self.generate_recommendations()
        
        if self.results["recommendations"]:
            print("\n📋 Recommendations:")
            for i, rec in enumerate(self.results["recommendations"], 1):
                print(f"  {i}. {rec}")
        
        # Save detailed report
        report_path = self.report_dir / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_path}")
        
        # Generate HTML report
        self.generate_html_report(report_path)
    
    def generate_recommendations(self):
        """Generate security recommendations based on results."""
        if any(cat["failed"] > 0 for cat in self.results["test_categories"].values()):
            self.results["recommendations"].append(
                "Review and fix all failing security tests before deployment"
            )
        
        if any(v["severity"] == "CRITICAL" for v in self.results["vulnerabilities"]):
            self.results["recommendations"].append(
                "Address all CRITICAL vulnerabilities immediately"
            )
        
        # Category-specific recommendations
        for category, results in self.results["test_categories"].items():
            if results["failed"] > 0:
                if "Authentication" in category:
                    self.results["recommendations"].append(
                        "Strengthen authentication mechanisms and implement MFA"
                    )
                elif "Injection" in category:
                    self.results["recommendations"].append(
                        "Implement proper input validation and parameterized queries"
                    )
                elif "CSRF" in category:
                    self.results["recommendations"].append(
                        "Ensure CSRF tokens are properly implemented on all state-changing operations"
                    )
                elif "Rate" in category:
                    self.results["recommendations"].append(
                        "Configure appropriate rate limiting for all endpoints"
                    )
    
    def generate_html_report(self, json_report_path: Path):
        """Generate HTML report from JSON results."""
        html_path = json_report_path.with_suffix(".html")
        
        html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; }
        .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; }
        .category { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .pass { color: #27ae60; }
        .fail { color: #e74c3c; }
        .critical { background-color: #e74c3c; color: white; padding: 5px; }
        .high { background-color: #f39c12; color: white; padding: 5px; }
        .medium { background-color: #3498db; color: white; padding: 5px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Test Report</h1>
        <p>Generated: {timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Tests: {total_tests}</p>
        <p>Pass Rate: {pass_rate:.2f}%</p>
        <p>Vulnerabilities: {vuln_count}</p>
    </div>
    
    <h2>Test Results by Category</h2>
    {category_results}
    
    <h2>Vulnerabilities</h2>
    {vulnerability_table}
    
    <h2>Recommendations</h2>
    <ul>
        {recommendations}
    </ul>
</body>
</html>
"""
        
        # Calculate values
        total_tests = sum(cat["total"] for cat in self.results["test_categories"].values())
        total_passed = sum(cat["passed"] for cat in self.results["test_categories"].values())
        pass_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
        
        # Generate category results
        category_html = ""
        for category, results in self.results["test_categories"].items():
            status_class = "pass" if results["status"] == "PASS" else "fail"
            category_html += f"""
            <div class="category">
                <h3>{category}</h3>
                <p>Status: <span class="{status_class}">{results["status"]}</span></p>
                <p>Passed: {results["passed"]} | Failed: {results["failed"]}</p>
            </div>
            """
        
        # Generate vulnerability table
        vuln_html = "<table><tr><th>Category</th><th>Type</th><th>Severity</th><th>Description</th></tr>"
        for vuln in self.results["vulnerabilities"]:
            severity_class = vuln["severity"].lower()
            vuln_html += f"""
            <tr>
                <td>{vuln["category"]}</td>
                <td>{vuln["type"]}</td>
                <td><span class="{severity_class}">{vuln["severity"]}</span></td>
                <td>{vuln["description"]}</td>
            </tr>
            """
        vuln_html += "</table>"
        
        # Generate recommendations
        rec_html = "".join(f"<li>{rec}</li>" for rec in self.results["recommendations"])
        
        # Fill template
        html_content = html_content.format(
            timestamp=self.results["timestamp"],
            total_tests=total_tests,
            pass_rate=pass_rate,
            vuln_count=len(self.results["vulnerabilities"]),
            category_results=category_html,
            vulnerability_table=vuln_html if self.results["vulnerabilities"] else "<p>No vulnerabilities found.</p>",
            recommendations=rec_html if self.results["recommendations"] else "<li>All security tests passed!</li>"
        )
        
        with open(html_path, "w") as f:
            f.write(html_content)
        
        print(f"📄 HTML report saved to: {html_path}")


if __name__ == "__main__":
    runner = SecurityTestRunner()
    exit_code = runner.run_all_tests()
    sys.exit(exit_code)