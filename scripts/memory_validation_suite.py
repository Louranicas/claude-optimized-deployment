#!/usr/bin/env python3
"""
Memory Validation Suite
Comprehensive memory testing automation and orchestration.
"""

import argparse
import asyncio
import os
import sys
import json
import yaml
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

# Import test utilities
from tests.utils.memory_test_utils import MemoryMonitor, get_memory_info
from tests.utils.memory_profiler import AdvancedMemoryProfiler
from tests.utils.statistical_analyzer import MemoryStatisticalAnalyzer

# Import test suites
from tests.memory.test_memory_leaks import TestMemoryLeaks
from tests.memory.test_memory_performance_regression import TestMemoryPerformanceRegression
from tests.memory.test_memory_stress import MemoryStressTester
from tests.memory.test_gc_performance import TestGCPerformance


class MemoryValidationSuite:
    """Orchestrates comprehensive memory validation testing"""
    
    def __init__(self, config_path: str = "memory_validation_config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.results = {}
        self.start_time = None
        self.end_time = None
        self.logger = self._setup_logging()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load memory validation configuration"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for validation suite"""
        logger = logging.getLogger("memory_validation")
        logger.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        return logger
    
    async def run_validation(
        self, 
        level: str = "comprehensive",
        output_dir: str = "reports/memory_validation"
    ) -> Dict[str, Any]:
        """Run memory validation suite"""
        
        self.logger.info(f"Starting memory validation - Level: {level}")
        self.start_time = time.time()
        
        # Get level configuration
        level_config = self.config['validation_levels'].get(level)
        if not level_config:
            raise ValueError(f"Unknown validation level: {level}")
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize results
        self.results = {
            'validation_level': level,
            'start_time': datetime.now().isoformat(),
            'config': level_config,
            'environment': self._get_environment_info(),
            'test_results': {},
            'overall_status': 'RUNNING',
            'overall_score': 0.0,
            'summary': {},
            'recommendations': []
        }
        
        try:
            # Run test suites based on configuration
            if level_config.get('leak_detection', {}).get('enabled', False):
                await self._run_leak_detection(level_config['leak_detection'])
            
            if level_config.get('regression_testing', {}).get('enabled', False):
                await self._run_regression_testing(level_config['regression_testing'])
            
            if level_config.get('stress_testing', {}).get('enabled', False):
                await self._run_stress_testing(level_config['stress_testing'])
            
            if level_config.get('gc_performance', {}).get('enabled', False):
                await self._run_gc_performance(level_config['gc_performance'])
            
            # Calculate overall results
            self._calculate_overall_results()
            
            # Generate reports
            await self._generate_reports(output_path)
            
            self.logger.info(f"Memory validation completed - Status: {self.results['overall_status']}")
            
        except Exception as e:
            self.logger.error(f"Memory validation failed: {e}")
            self.results['overall_status'] = 'ERROR'
            self.results['error'] = str(e)
            raise
        
        finally:
            self.end_time = time.time()
            self.results['end_time'] = datetime.now().isoformat()
            self.results['duration_seconds'] = self.end_time - self.start_time
        
        return self.results
    
    async def _run_leak_detection(self, config: Dict[str, Any]):
        """Run memory leak detection tests"""
        self.logger.info("Running memory leak detection tests...")
        
        test_suite = TestMemoryLeaks()
        components = config.get('components', ['ExpertManager'])
        results = []
        
        for component in components:
            try:
                self.logger.info(f"Testing {component} for memory leaks...")
                
                if component == 'ExpertManager':
                    result = await test_suite.test_expert_manager_leaks()
                elif component == 'RustModules':
                    result = await test_suite.test_rust_modules_leaks()
                elif component == 'MCPTools':
                    result = await test_suite.test_mcp_manager_leaks()
                elif component == 'ResponseAggregation':
                    result = await test_suite.test_response_aggregation_leaks()
                else:
                    self.logger.warning(f"Unknown component for leak testing: {component}")
                    continue
                
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Leak detection failed for {component}: {e}")
                results.append({
                    'component_name': component,
                    'leak_detected': True,
                    'leak_severity': 'error',
                    'error': str(e)
                })
        
        # Run comprehensive test if configured
        if len(components) > 1:
            try:
                comprehensive_results = await test_suite.test_comprehensive_leak_detection()
                results.extend(comprehensive_results)
            except Exception as e:
                self.logger.error(f"Comprehensive leak detection failed: {e}")
        
        self.results['test_results']['leak_detection'] = {
            'status': 'COMPLETED',
            'components_tested': len(components),
            'leaks_detected': sum(1 for r in results if getattr(r, 'leak_detected', False)),
            'critical_leaks': sum(1 for r in results if getattr(r, 'leak_severity', 'none') == 'critical'),
            'results': [r.__dict__ if hasattr(r, '__dict__') else r for r in results]
        }
    
    async def _run_regression_testing(self, config: Dict[str, Any]):
        """Run performance regression tests"""
        self.logger.info("Running performance regression tests...")
        
        test_suite = TestMemoryPerformanceRegression()
        components = config.get('components', ['ExpertManager'])
        results = []
        
        for component in components:
            try:
                self.logger.info(f"Testing {component} for performance regression...")
                
                if component == 'ExpertManager':
                    result = await test_suite.test_expert_manager_performance_regression()
                elif component == 'RustModules':
                    result = await test_suite.test_rust_modules_performance_regression()
                elif component == 'MCPTools':
                    result = await test_suite.test_mcp_tools_performance_regression()
                else:
                    self.logger.warning(f"Unknown component for regression testing: {component}")
                    continue
                
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Regression testing failed for {component}: {e}")
                results.append({
                    'component_name': component,
                    'test_name': f'{component}_regression_test',
                    'regression_detected': True,
                    'regression_severity': 'error',
                    'error': str(e)
                })
        
        # Run comprehensive test if configured
        if len(components) > 1:
            try:
                comprehensive_results = await test_suite.test_comprehensive_performance_regression()
                results.extend(comprehensive_results)
            except Exception as e:
                self.logger.error(f"Comprehensive regression testing failed: {e}")
        
        self.results['test_results']['regression_testing'] = {
            'status': 'COMPLETED',
            'components_tested': len(components),
            'regressions_detected': sum(1 for r in results if getattr(r, 'regression_detected', False)),
            'improvements_detected': sum(1 for r in results if getattr(r, 'improvement_detected', False)),
            'results': [r.__dict__ if hasattr(r, '__dict__') else r for r in results]
        }
    
    async def _run_stress_testing(self, config: Dict[str, Any]):
        """Run memory stress tests"""
        self.logger.info("Running memory stress tests...")
        
        test_suite = MemoryStressTester()
        results = []
        
        if config.get('memory_pressure', False):
            try:
                result = await test_suite.test_memory_pressure_scenarios()
                results.append(result)
            except Exception as e:
                self.logger.error(f"Memory pressure testing failed: {e}")
        
        if config.get('concurrent_operations', False):
            try:
                result = await test_suite.test_concurrent_memory_operations()
                results.append(result)
            except Exception as e:
                self.logger.error(f"Concurrent operations testing failed: {e}")
        
        if config.get('fragmentation_testing', False):
            try:
                result = await test_suite.test_memory_fragmentation_stress()
                results.append(result)
            except Exception as e:
                self.logger.error(f"Fragmentation testing failed: {e}")
        
        if config.get('recovery_testing', False):
            try:
                result = await test_suite.test_memory_recovery_patterns()
                results.append(result)
            except Exception as e:
                self.logger.error(f"Recovery testing failed: {e}")
        
        # Run comprehensive test if multiple tests are configured
        if sum([
            config.get('memory_pressure', False),
            config.get('concurrent_operations', False),
            config.get('fragmentation_testing', False),
            config.get('recovery_testing', False)
        ]) > 1:
            try:
                comprehensive_results = await test_suite.test_comprehensive_memory_stress()
                results.extend(comprehensive_results)
            except Exception as e:
                self.logger.error(f"Comprehensive stress testing failed: {e}")
        
        self.results['test_results']['stress_testing'] = {
            'status': 'COMPLETED',
            'tests_run': len(results),
            'breaking_points_reached': sum(1 for r in results if getattr(r, 'breaking_point_reached', False)),
            'avg_stability_score': sum(getattr(r, 'stability_score', 0) for r in results) / len(results) if results else 0,
            'results': [r.__dict__ if hasattr(r, '__dict__') else r for r in results]
        }
    
    async def _run_gc_performance(self, config: Dict[str, Any]):
        """Run GC performance tests"""
        self.logger.info("Running GC performance tests...")
        
        test_suite = TestGCPerformance()
        components = config.get('components', ['ExpertManager'])
        results = []
        
        for component in components:
            try:
                self.logger.info(f"Testing {component} GC performance...")
                
                if component == 'ExpertManager':
                    result = await test_suite.test_expert_manager_gc_performance()
                elif component == 'RustModules':
                    result = await test_suite.test_rust_modules_gc_performance()
                elif component == 'MCPTools':
                    result = await test_suite.test_mcp_tools_gc_performance()
                elif component == 'ResponseAggregation':
                    result = await test_suite.test_response_aggregation_gc_performance()
                else:
                    self.logger.warning(f"Unknown component for GC testing: {component}")
                    continue
                
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"GC performance testing failed for {component}: {e}")
                results.append({
                    'component_name': component,
                    'test_name': f'{component}_gc_performance',
                    'gc_efficiency_score': 0.0,
                    'error': str(e)
                })
        
        # Run comprehensive test if configured
        if len(components) > 1:
            try:
                comprehensive_results = await test_suite.test_comprehensive_gc_performance()
                results.extend(comprehensive_results)
            except Exception as e:
                self.logger.error(f"Comprehensive GC testing failed: {e}")
        
        self.results['test_results']['gc_performance'] = {
            'status': 'COMPLETED',
            'components_tested': len(components),
            'avg_efficiency_score': sum(getattr(r, 'gc_efficiency_score', 0) for r in results) / len(results) if results else 0,
            'efficient_components': sum(1 for r in results if getattr(r, 'gc_efficiency_score', 0) >= 0.7),
            'results': [r.__dict__ if hasattr(r, '__dict__') else r for r in results]
        }
    
    def _get_environment_info(self) -> Dict[str, Any]:
        """Get environment information"""
        return {
            'python_version': sys.version,
            'platform': sys.platform,
            'memory_info': get_memory_info(),
            'timestamp': datetime.now().isoformat(),
            'config_version': self.config.get('metadata', {}).get('config_version', 'unknown')
        }
    
    def _calculate_overall_results(self):
        """Calculate overall validation results"""
        test_results = self.results['test_results']
        
        # Count critical issues
        critical_issues = 0
        major_issues = 0
        total_score = 0
        score_count = 0
        
        # Analyze leak detection results
        if 'leak_detection' in test_results:
            leak_results = test_results['leak_detection']
            critical_issues += leak_results.get('critical_leaks', 0)
            
            # Score based on leak severity
            if leak_results.get('critical_leaks', 0) > 0:
                total_score += 0  # 0 points for critical leaks
            elif leak_results.get('leaks_detected', 0) > 0:
                total_score += 50  # 50 points for non-critical leaks
            else:
                total_score += 100  # 100 points for no leaks
            score_count += 1
        
        # Analyze regression testing results
        if 'regression_testing' in test_results:
            regression_results = test_results['regression_testing']
            critical_regressions = sum(
                1 for r in regression_results.get('results', [])
                if r.get('regression_severity') == 'critical'
            )
            major_regressions = sum(
                1 for r in regression_results.get('results', [])
                if r.get('regression_severity') == 'major'
            )
            
            critical_issues += critical_regressions
            major_issues += major_regressions
            
            # Score based on regressions
            if critical_regressions > 0:
                total_score += 0
            elif major_regressions > 0:
                total_score += 50
            elif regression_results.get('improvements_detected', 0) > 0:
                total_score += 120  # Bonus for improvements
            else:
                total_score += 100
            score_count += 1
        
        # Analyze stress testing results
        if 'stress_testing' in test_results:
            stress_results = test_results['stress_testing']
            avg_stability = stress_results.get('avg_stability_score', 0)
            breaking_points = stress_results.get('breaking_points_reached', 0)
            
            if breaking_points > stress_results.get('tests_run', 1) * 0.5:
                major_issues += 1
                total_score += 30
            elif avg_stability < 0.5:
                major_issues += 1
                total_score += 50
            else:
                total_score += 100
            score_count += 1
        
        # Analyze GC performance results
        if 'gc_performance' in test_results:
            gc_results = test_results['gc_performance']
            avg_efficiency = gc_results.get('avg_efficiency_score', 0)
            
            if avg_efficiency < 0.5:
                major_issues += 1
                total_score += 30
            elif avg_efficiency < 0.7:
                total_score += 70
            else:
                total_score += 100
            score_count += 1
        
        # Calculate overall score
        overall_score = total_score / score_count if score_count > 0 else 0
        
        # Determine overall status
        if critical_issues > 0:
            overall_status = 'FAIL'
        elif major_issues > 2:
            overall_status = 'FAIL'
        elif major_issues > 0:
            overall_status = 'WARNING'
        else:
            overall_status = 'PASS'
        
        # Generate recommendations
        recommendations = []
        if critical_issues > 0:
            recommendations.append(f"CRITICAL: {critical_issues} critical issues detected - immediate action required")
        if major_issues > 0:
            recommendations.append(f"WARNING: {major_issues} major issues detected - review recommended")
        if overall_score >= 90:
            recommendations.append("EXCELLENT: Memory performance is highly optimized")
        elif overall_score >= 70:
            recommendations.append("GOOD: Memory performance is acceptable")
        else:
            recommendations.append("NEEDS IMPROVEMENT: Memory optimization required")
        
        # Update results
        self.results.update({
            'overall_status': overall_status,
            'overall_score': round(overall_score, 1),
            'summary': {
                'critical_issues': critical_issues,
                'major_issues': major_issues,
                'total_tests': score_count,
                'avg_score': round(overall_score, 1)
            },
            'recommendations': recommendations
        })
    
    async def _generate_reports(self, output_path: Path):
        """Generate validation reports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        level = self.results['validation_level']
        
        # Generate JSON report
        json_path = output_path / f"memory_validation_{level}_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Generate Markdown summary
        md_path = output_path / f"memory_validation_summary_{timestamp}.md"
        await self._generate_markdown_report(md_path)
        
        # Generate HTML report (if configured)
        if 'html' in self.config.get('reporting', {}).get('output_formats', []):
            html_path = output_path / f"memory_validation_{level}_{timestamp}.html"
            await self._generate_html_report(html_path)
        
        self.logger.info(f"Reports generated:")
        self.logger.info(f"  JSON: {json_path}")
        self.logger.info(f"  Markdown: {md_path}")
    
    async def _generate_markdown_report(self, output_path: Path):
        """Generate Markdown summary report"""
        report = []
        
        # Header
        report.append(f"# Memory Validation Report")
        report.append(f"**Level:** {self.results['validation_level']}")
        report.append(f"**Status:** {self.results['overall_status']}")
        report.append(f"**Overall Score:** {self.results['overall_score']}")
        report.append(f"**Generated:** {self.results.get('end_time', 'In Progress')}")
        report.append("")
        
        # Summary
        summary = self.results.get('summary', {})
        report.append("## Summary")
        report.append(f"- **Critical Issues:** {summary.get('critical_issues', 0)}")
        report.append(f"- **Major Issues:** {summary.get('major_issues', 0)}")
        report.append(f"- **Total Tests:** {summary.get('total_tests', 0)}")
        report.append(f"- **Duration:** {self.results.get('duration_seconds', 0):.1f} seconds")
        report.append("")
        
        # Test Results Summary
        test_results = self.results.get('test_results', {})
        
        if 'leak_detection' in test_results:
            leak_data = test_results['leak_detection']
            report.append("### Memory Leak Detection")
            report.append(f"- **Components Tested:** {leak_data.get('components_tested', 0)}")
            report.append(f"- **Leaks Detected:** {leak_data.get('leaks_detected', 0)}")
            report.append(f"- **Critical Leaks:** {leak_data.get('critical_leaks', 0)}")
            report.append("")
        
        if 'regression_testing' in test_results:
            regression_data = test_results['regression_testing']
            report.append("### Performance Regression Testing")
            report.append(f"- **Components Tested:** {regression_data.get('components_tested', 0)}")
            report.append(f"- **Regressions Detected:** {regression_data.get('regressions_detected', 0)}")
            report.append(f"- **Improvements Detected:** {regression_data.get('improvements_detected', 0)}")
            report.append("")
        
        if 'stress_testing' in test_results:
            stress_data = test_results['stress_testing']
            report.append("### Memory Stress Testing")
            report.append(f"- **Tests Run:** {stress_data.get('tests_run', 0)}")
            report.append(f"- **Breaking Points:** {stress_data.get('breaking_points_reached', 0)}")
            report.append(f"- **Avg Stability:** {stress_data.get('avg_stability_score', 0):.2f}")
            report.append("")
        
        if 'gc_performance' in test_results:
            gc_data = test_results['gc_performance']
            report.append("### GC Performance Testing")
            report.append(f"- **Components Tested:** {gc_data.get('components_tested', 0)}")
            report.append(f"- **Avg Efficiency:** {gc_data.get('avg_efficiency_score', 0):.2f}")
            report.append(f"- **Efficient Components:** {gc_data.get('efficient_components', 0)}")
            report.append("")
        
        # Recommendations
        recommendations = self.results.get('recommendations', [])
        if recommendations:
            report.append("## Recommendations")
            for rec in recommendations:
                report.append(f"- {rec}")
            report.append("")
        
        # Environment Info
        env_info = self.results.get('environment', {})
        report.append("## Environment")
        report.append(f"- **Python Version:** {env_info.get('python_version', 'Unknown')}")
        report.append(f"- **Platform:** {env_info.get('platform', 'Unknown')}")
        memory_info = env_info.get('memory_info', {})
        if memory_info:
            report.append(f"- **System Memory:** {memory_info.get('rss_mb', 0):.1f} MB RSS")
        
        # Write report
        with open(output_path, 'w') as f:
            f.write('\n'.join(report))
    
    async def _generate_html_report(self, output_path: Path):
        """Generate HTML report (placeholder)"""
        # This would generate a more detailed HTML report
        # For now, just create a simple HTML wrapper around the markdown
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Memory Validation Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .status-pass {{ color: green; }}
                .status-warning {{ color: orange; }}
                .status-fail {{ color: red; }}
            </style>
        </head>
        <body>
            <h1>Memory Validation Report</h1>
            <p><strong>Status:</strong> <span class="status-{self.results['overall_status'].lower()}">{self.results['overall_status']}</span></p>
            <p><strong>Score:</strong> {self.results['overall_score']}</p>
            <p><em>Detailed JSON report available in artifacts.</em></p>
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)


def main():
    """Main entry point for memory validation suite"""
    parser = argparse.ArgumentParser(description="Memory Validation Suite")
    parser.add_argument(
        '--level',
        choices=['quick', 'comprehensive', 'nightly'],
        default='comprehensive',
        help='Validation level'
    )
    parser.add_argument(
        '--output-dir',
        default='reports/memory_validation',
        help='Output directory for reports'
    )
    parser.add_argument(
        '--config',
        default='memory_validation_config.yaml',
        help='Configuration file path'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run validation suite
    suite = MemoryValidationSuite(args.config)
    
    try:
        results = asyncio.run(suite.run_validation(args.level, args.output_dir))
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"Memory Validation Complete")
        print(f"{'='*60}")
        print(f"Level: {results['validation_level']}")
        print(f"Status: {results['overall_status']}")
        print(f"Score: {results['overall_score']}")
        print(f"Duration: {results.get('duration_seconds', 0):.1f} seconds")
        
        # Print recommendations
        if results.get('recommendations'):
            print(f"\nRecommendations:")
            for rec in results['recommendations']:
                print(f"  - {rec}")
        
        # Exit with appropriate code
        if results['overall_status'] == 'FAIL':
            sys.exit(1)
        elif results['overall_status'] == 'WARNING':
            sys.exit(2)
        else:
            sys.exit(0)
    
    except Exception as e:
        print(f"Memory validation failed: {e}")
        sys.exit(3)


if __name__ == "__main__":
    main()