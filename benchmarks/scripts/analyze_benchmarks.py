#!/usr/bin/env python3
"""
Benchmark Analysis and Regression Detection
Compares current benchmark results with baseline and detects regressions
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import statistics
from dataclasses import dataclass, asdict
from enum import Enum


class Severity(Enum):
    """Regression severity levels"""
    CRITICAL = "critical"
    WARNING = "warning"
    NOTICE = "notice"
    NONE = "none"


@dataclass
class Regression:
    """Represents a performance regression"""
    metric: str
    component: str
    baseline_value: float
    current_value: float
    change_percent: float
    severity: Severity
    threshold: float
    description: str


class BenchmarkAnalyzer:
    """Analyzes benchmark results and detects regressions"""
    
    def __init__(self, thresholds_config: Optional[Dict] = None):
        self.thresholds = thresholds_config or self._default_thresholds()
        self.regressions: List[Regression] = []
        
    def _default_thresholds(self) -> Dict:
        """Default regression thresholds"""
        return {
            "critical": {
                "response_time_increase": 0.20,  # 20%
                "throughput_decrease": 0.15,      # 15%
                "error_rate_increase": 1.00,      # 100%
                "memory_leak": 50,                # MB/hour
                "cpu_increase": 0.25              # 25%
            },
            "warning": {
                "response_time_increase": 0.10,  # 10%
                "throughput_decrease": 0.05,      # 5%
                "error_rate_increase": 0.50,      # 50%
                "memory_leak": 20,                # MB/hour
                "cpu_increase": 0.10              # 10%
            },
            "notice": {
                "response_time_increase": 0.05,  # 5%
                "throughput_decrease": 0.02,      # 2%
                "error_rate_increase": 0.20,      # 20%
                "memory_leak": 10,                # MB/hour
                "cpu_increase": 0.05              # 5%
            }
        }
    
    def analyze(self, current: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze benchmark results and detect regressions"""
        self.regressions = []
        
        # Analyze different benchmark categories
        if "micro" in current.get("benchmarks", {}) and "micro" in baseline.get("benchmarks", {}):
            self._analyze_micro_benchmarks(
                current["benchmarks"]["micro"],
                baseline["benchmarks"]["micro"]
            )
        
        if "integration" in current.get("benchmarks", {}) and "integration" in baseline.get("benchmarks", {}):
            self._analyze_integration_benchmarks(
                current["benchmarks"]["integration"],
                baseline["benchmarks"]["integration"]
            )
        
        if "load" in current.get("benchmarks", {}) and "load" in baseline.get("benchmarks", {}):
            self._analyze_load_tests(
                current["benchmarks"]["load"],
                baseline["benchmarks"]["load"]
            )
        
        # Generate analysis report
        return self._generate_analysis_report(current, baseline)
    
    def _analyze_micro_benchmarks(self, current: Dict, baseline: Dict):
        """Analyze micro benchmark results"""
        # Function performance
        if "functions" in current and "functions" in baseline:
            for func_name in current["functions"]:
                if func_name in baseline["functions"]:
                    current_ops = current["functions"][func_name]["ops_per_second"]
                    baseline_ops = baseline["functions"][func_name]["ops_per_second"]
                    
                    self._check_metric_change(
                        metric=f"function_{func_name}_ops_per_second",
                        component="micro_benchmarks",
                        current_value=current_ops,
                        baseline_value=baseline_ops,
                        decrease_is_regression=True,
                        metric_type="throughput"
                    )
        
        # Database operations
        if "database" in current and "database" in baseline:
            for operation in current["database"]:
                if operation in baseline["database"]:
                    for size in current["database"][operation]:
                        if size in baseline["database"][operation]:
                            current_time = current["database"][operation][size]["execution_time"]
                            baseline_time = baseline["database"][operation][size]["execution_time"]
                            
                            self._check_metric_change(
                                metric=f"database_{operation}_{size}",
                                component="database",
                                current_value=current_time,
                                baseline_value=baseline_time,
                                decrease_is_regression=False,
                                metric_type="response_time"
                            )
    
    def _analyze_integration_benchmarks(self, current: Dict, baseline: Dict):
        """Analyze integration benchmark results"""
        if "modules" in current and "modules" in baseline:
            for module_name in current["modules"]:
                if module_name in baseline["modules"]:
                    current_results = current["modules"][module_name]
                    baseline_results = baseline["modules"][module_name]
                    
                    # Match tools by name
                    for current_tool in current_results:
                        baseline_tool = self._find_matching_tool(
                            current_tool, baseline_results
                        )
                        
                        if baseline_tool:
                            # Response time metrics
                            for percentile in ["p50", "p95", "p99"]:
                                self._check_metric_change(
                                    metric=f"{module_name}.{current_tool['tool_name']}_{percentile}",
                                    component=module_name,
                                    current_value=current_tool[f"{percentile}_execution_time"],
                                    baseline_value=baseline_tool[f"{percentile}_execution_time"],
                                    decrease_is_regression=False,
                                    metric_type="response_time"
                                )
                            
                            # Memory usage
                            self._check_metric_change(
                                metric=f"{module_name}.{current_tool['tool_name']}_memory",
                                component=module_name,
                                current_value=current_tool["avg_memory_delta"],
                                baseline_value=baseline_tool["avg_memory_delta"],
                                decrease_is_regression=False,
                                metric_type="memory"
                            )
    
    def _analyze_load_tests(self, current: Dict, baseline: Dict):
        """Analyze load test results"""
        # Steady state analysis
        if "steady_state" in current and "steady_state" in baseline:
            self._check_metric_change(
                metric="steady_state_response_time",
                component="load_test",
                current_value=current["steady_state"]["avg_response_time"],
                baseline_value=baseline["steady_state"]["avg_response_time"],
                decrease_is_regression=False,
                metric_type="response_time"
            )
            
            self._check_metric_change(
                metric="steady_state_error_rate",
                component="load_test",
                current_value=current["steady_state"]["error_rate"],
                baseline_value=baseline["steady_state"]["error_rate"],
                decrease_is_regression=False,
                metric_type="error_rate"
            )
        
        # Stress test breaking point
        if "stress_test" in current and "stress_test" in baseline:
            self._check_metric_change(
                metric="breaking_point_rps",
                component="stress_test",
                current_value=current["stress_test"]["breaking_point"],
                baseline_value=baseline["stress_test"]["breaking_point"],
                decrease_is_regression=True,
                metric_type="throughput"
            )
    
    def _find_matching_tool(self, tool: Dict, baseline_results: List[Dict]) -> Optional[Dict]:
        """Find matching tool in baseline results"""
        for baseline_tool in baseline_results:
            if baseline_tool["tool_name"] == tool["tool_name"]:
                return baseline_tool
        return None
    
    def _check_metric_change(self, metric: str, component: str, 
                           current_value: float, baseline_value: float,
                           decrease_is_regression: bool, metric_type: str):
        """Check if metric change constitutes a regression"""
        if baseline_value == 0:
            return  # Can't calculate percentage change
        
        change_percent = (current_value - baseline_value) / baseline_value
        
        # Determine if this is a regression
        is_regression = (change_percent > 0 and not decrease_is_regression) or \
                       (change_percent < 0 and decrease_is_regression)
        
        if not is_regression:
            return
        
        abs_change_percent = abs(change_percent)
        
        # Determine severity based on metric type
        severity = self._get_severity(metric_type, abs_change_percent)
        
        if severity != Severity.NONE:
            regression = Regression(
                metric=metric,
                component=component,
                baseline_value=baseline_value,
                current_value=current_value,
                change_percent=change_percent * 100,  # Convert to percentage
                severity=severity,
                threshold=self._get_threshold(metric_type, severity),
                description=self._generate_description(
                    metric, current_value, baseline_value, change_percent
                )
            )
            self.regressions.append(regression)
    
    def _get_severity(self, metric_type: str, change_percent: float) -> Severity:
        """Determine regression severity"""
        # Map metric types to threshold keys
        threshold_key_map = {
            "response_time": "response_time_increase",
            "throughput": "throughput_decrease",
            "error_rate": "error_rate_increase",
            "memory": "memory_leak",
            "cpu": "cpu_increase"
        }
        
        threshold_key = threshold_key_map.get(metric_type, "response_time_increase")
        
        if change_percent >= self.thresholds["critical"][threshold_key]:
            return Severity.CRITICAL
        elif change_percent >= self.thresholds["warning"][threshold_key]:
            return Severity.WARNING
        elif change_percent >= self.thresholds["notice"][threshold_key]:
            return Severity.NOTICE
        else:
            return Severity.NONE
    
    def _get_threshold(self, metric_type: str, severity: Severity) -> float:
        """Get threshold value for metric type and severity"""
        threshold_key_map = {
            "response_time": "response_time_increase",
            "throughput": "throughput_decrease",
            "error_rate": "error_rate_increase",
            "memory": "memory_leak",
            "cpu": "cpu_increase"
        }
        
        threshold_key = threshold_key_map.get(metric_type, "response_time_increase")
        return self.thresholds[severity.value][threshold_key] * 100  # Convert to percentage
    
    def _generate_description(self, metric: str, current: float, 
                            baseline: float, change_percent: float) -> str:
        """Generate human-readable description of regression"""
        direction = "increased" if change_percent > 0 else "decreased"
        return (f"{metric} {direction} by {abs(change_percent)*100:.1f}% "
                f"(from {baseline:.3f} to {current:.3f})")
    
    def _generate_analysis_report(self, current: Dict, baseline: Dict) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        # Group regressions by severity
        critical_regressions = [r for r in self.regressions if r.severity == Severity.CRITICAL]
        warning_regressions = [r for r in self.regressions if r.severity == Severity.WARNING]
        notice_regressions = [r for r in self.regressions if r.severity == Severity.NOTICE]
        
        # Calculate summary statistics
        total_metrics_analyzed = self._count_total_metrics(current)
        
        # Generate summary
        summary = self._generate_summary(
            len(critical_regressions),
            len(warning_regressions),
            len(notice_regressions),
            total_metrics_analyzed
        )
        
        # Performance comparison
        performance_comparison = self._generate_performance_comparison(current, baseline)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "regression": len(critical_regressions) > 0,
            "summary": summary,
            "statistics": {
                "total_metrics_analyzed": total_metrics_analyzed,
                "total_regressions": len(self.regressions),
                "critical_regressions": len(critical_regressions),
                "warning_regressions": len(warning_regressions),
                "notice_regressions": len(notice_regressions)
            },
            "regressions": {
                "critical": [asdict(r) for r in critical_regressions],
                "warning": [asdict(r) for r in warning_regressions],
                "notice": [asdict(r) for r in notice_regressions]
            },
            "performance_comparison": performance_comparison,
            "recommendations": self._generate_recommendations(critical_regressions, warning_regressions)
        }
    
    def _count_total_metrics(self, results: Dict) -> int:
        """Count total number of metrics analyzed"""
        count = 0
        
        if "benchmarks" in results:
            # Count micro benchmarks
            if "micro" in results["benchmarks"]:
                micro = results["benchmarks"]["micro"]
                if "functions" in micro:
                    count += len(micro["functions"])
                if "database" in micro:
                    for op in micro["database"].values():
                        count += len(op)
            
            # Count integration benchmarks
            if "integration" in results["benchmarks"]:
                if "modules" in results["benchmarks"]["integration"]:
                    for module_results in results["benchmarks"]["integration"]["modules"].values():
                        count += len(module_results) * 3  # p50, p95, p99
            
            # Count load test metrics
            if "load" in results["benchmarks"]:
                count += 5  # Approximate metrics from load tests
        
        return count
    
    def _generate_summary(self, critical: int, warning: int, 
                         notice: int, total: int) -> str:
        """Generate executive summary"""
        if critical > 0:
            return (f"⚠️ **CRITICAL**: {critical} critical performance regressions detected! "
                   f"Deployment should be blocked until these are resolved.")
        elif warning > 0:
            return (f"⚠️ **WARNING**: {warning} performance regressions detected. "
                   f"Review required before deployment.")
        elif notice > 0:
            return (f"ℹ️ **NOTICE**: {notice} minor performance changes detected. "
                   f"No action required, but worth monitoring.")
        else:
            return f"✅ **PASS**: No performance regressions detected across {total} metrics."
    
    def _generate_performance_comparison(self, current: Dict, baseline: Dict) -> Dict[str, Any]:
        """Generate overall performance comparison"""
        comparison = {}
        
        # Extract key metrics for comparison
        if "benchmarks" in current and "benchmarks" in baseline:
            # Response time comparison
            if "integration" in current["benchmarks"] and "integration" in baseline["benchmarks"]:
                current_p95_times = []
                baseline_p95_times = []
                
                for module in current["benchmarks"]["integration"].get("modules", {}).values():
                    for tool in module:
                        current_p95_times.append(tool["p95_execution_time"])
                
                for module in baseline["benchmarks"]["integration"].get("modules", {}).values():
                    for tool in module:
                        baseline_p95_times.append(tool["p95_execution_time"])
                
                if current_p95_times and baseline_p95_times:
                    comparison["response_time_p95"] = {
                        "current": statistics.mean(current_p95_times),
                        "baseline": statistics.mean(baseline_p95_times),
                        "change": self._calculate_change_string(
                            statistics.mean(current_p95_times),
                            statistics.mean(baseline_p95_times)
                        )
                    }
            
            # Throughput comparison
            if "load" in current["benchmarks"] and "load" in baseline["benchmarks"]:
                if "steady_state" in current["benchmarks"]["load"] and \
                   "steady_state" in baseline["benchmarks"]["load"]:
                    current_rps = current["benchmarks"]["load"]["steady_state"]["actual_rps"]
                    baseline_rps = baseline["benchmarks"]["load"]["steady_state"]["actual_rps"]
                    
                    comparison["throughput"] = {
                        "current": current_rps,
                        "baseline": baseline_rps,
                        "change": self._calculate_change_string(current_rps, baseline_rps)
                    }
        
        return comparison
    
    def _calculate_change_string(self, current: float, baseline: float) -> str:
        """Calculate and format change percentage"""
        if baseline == 0:
            return "N/A"
        
        change = ((current - baseline) / baseline) * 100
        sign = "+" if change > 0 else ""
        return f"{sign}{change:.1f}%"
    
    def _generate_recommendations(self, critical: List[Regression], 
                                warning: List[Regression]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Analyze regression patterns
        components_affected = set()
        metric_types_affected = set()
        
        for regression in critical + warning:
            components_affected.add(regression.component)
            
            # Categorize metric types
            if "response_time" in regression.metric or "p95" in regression.metric or "p99" in regression.metric:
                metric_types_affected.add("response_time")
            elif "throughput" in regression.metric or "ops_per_second" in regression.metric or "rps" in regression.metric:
                metric_types_affected.add("throughput")
            elif "memory" in regression.metric:
                metric_types_affected.add("memory")
            elif "error" in regression.metric:
                metric_types_affected.add("error_rate")
        
        # Generate specific recommendations
        if "response_time" in metric_types_affected:
            recommendations.append(
                "🔍 **Response Time**: Profile the affected components to identify "
                "performance bottlenecks. Consider implementing caching or optimizing "
                "database queries."
            )
        
        if "throughput" in metric_types_affected:
            recommendations.append(
                "📊 **Throughput**: Review recent changes for inefficient algorithms "
                "or blocking operations. Consider parallel processing or async operations."
            )
        
        if "memory" in metric_types_affected:
            recommendations.append(
                "💾 **Memory**: Check for memory leaks or inefficient data structures. "
                "Run memory profiling and implement proper cleanup."
            )
        
        if "error_rate" in metric_types_affected:
            recommendations.append(
                "❌ **Error Rate**: Investigate error logs and implement better error "
                "handling. Check for resource exhaustion or timeout issues."
            )
        
        # Component-specific recommendations
        if len(components_affected) > 3:
            recommendations.append(
                "⚠️ **Widespread Impact**: Multiple components affected. Consider "
                "reverting recent infrastructure or dependency changes."
            )
        
        return recommendations


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze benchmark results")
    parser.add_argument("--current", required=True, help="Current benchmark results file")
    parser.add_argument("--baseline", required=True, help="Baseline benchmark results file")
    parser.add_argument("--output", required=True, help="Output analysis file")
    parser.add_argument("--thresholds", help="Custom thresholds configuration file")
    parser.add_argument("--generate-report", action="store_true", 
                       help="Generate markdown report")
    
    args = parser.parse_args()
    
    # Load benchmark results
    with open(args.current, 'r') as f:
        current_results = json.load(f)
    
    with open(args.baseline, 'r') as f:
        baseline_results = json.load(f)
    
    # Load custom thresholds if provided
    thresholds = None
    if args.thresholds:
        with open(args.thresholds, 'r') as f:
            thresholds = json.load(f)
    
    # Analyze results
    analyzer = BenchmarkAnalyzer(thresholds)
    analysis = analyzer.analyze(current_results, baseline_results)
    
    # Save analysis
    with open(args.output, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    # Generate markdown report if requested
    if args.generate_report:
        report_path = Path(args.output).with_suffix('.md')
        report = generate_markdown_report(analysis, analyzer.regressions)
        report_path.write_text(report)
        print(f"📄 Report generated: {report_path}")
    
    # Print summary
    print(f"\n{analysis['summary']}")
    
    if analysis['regression']:
        print(f"\n❌ Found {len(analyzer.regressions)} regressions")
        sys.exit(1)
    else:
        print("\n✅ No regressions detected")
        sys.exit(0)


def generate_markdown_report(analysis: Dict[str, Any], 
                           regressions: List[Regression]) -> str:
    """Generate markdown report from analysis"""
    report = []
    report.append("# Performance Regression Analysis Report")
    report.append(f"Generated: {analysis['timestamp']}")
    report.append(f"\n## Summary\n\n{analysis['summary']}")
    
    # Statistics
    report.append("\n## Statistics")
    stats = analysis['statistics']
    report.append(f"- **Total Metrics Analyzed**: {stats['total_metrics_analyzed']}")
    report.append(f"- **Total Regressions**: {stats['total_regressions']}")
    report.append(f"- **Critical**: {stats['critical_regressions']}")
    report.append(f"- **Warning**: {stats['warning_regressions']}")
    report.append(f"- **Notice**: {stats['notice_regressions']}")
    
    # Performance comparison
    if analysis['performance_comparison']:
        report.append("\n## Performance Comparison")
        for metric, data in analysis['performance_comparison'].items():
            report.append(f"\n### {metric.replace('_', ' ').title()}")
            report.append(f"- **Current**: {data['current']:.3f}")
            report.append(f"- **Baseline**: {data['baseline']:.3f}")
            report.append(f"- **Change**: {data['change']}")
    
    # Regressions by severity
    if analysis['regressions']['critical']:
        report.append("\n## 🚨 Critical Regressions")
        for reg in analysis['regressions']['critical']:
            report.append(f"\n### {reg['metric']}")
            report.append(f"- **Component**: {reg['component']}")
            report.append(f"- **Change**: {reg['change_percent']:.1f}%")
            report.append(f"- **Description**: {reg['description']}")
            report.append(f"- **Threshold**: {reg['threshold']:.0f}%")
    
    if analysis['regressions']['warning']:
        report.append("\n## ⚠️ Warning Regressions")
        for reg in analysis['regressions']['warning']:
            report.append(f"\n### {reg['metric']}")
            report.append(f"- **Component**: {reg['component']}")
            report.append(f"- **Change**: {reg['change_percent']:.1f}%")
            report.append(f"- **Description**: {reg['description']}")
    
    # Recommendations
    if analysis['recommendations']:
        report.append("\n## 📋 Recommendations")
        for rec in analysis['recommendations']:
            report.append(f"\n{rec}")
    
    return "\n".join(report)


if __name__ == "__main__":
    main()