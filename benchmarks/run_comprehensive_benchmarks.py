#!/usr/bin/env python3
"""
Master Comprehensive Benchmarking Suite Executor
Orchestrates all benchmark components for complete performance analysis
"""

import asyncio
import sys
import os
import time
import argparse
from datetime import datetime
from pathlib import Path

# Add benchmarks directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Import all benchmark components
from performance_suite import BenchmarkSuite
from automation_controller import AutomationController
from quick_benchmark import QuickBenchmarks
from load_testing_suite import LoadTestSuite
from optimization_engine import (
    PerformanceDatabase, PerformanceAnalyzer, BottleneckDetector,
    OptimizationRecommendationEngine, OptimizationReportGenerator
)
from dashboard_server import run_dashboard_server

class MasterBenchmarkOrchestrator:
    """Orchestrates all benchmarking components"""
    
    def __init__(self):
        self.benchmark_suite = BenchmarkSuite()
        self.automation_controller = AutomationController()
        self.quick_benchmarks = QuickBenchmarks()
        self.load_test_suite = LoadTestSuite()
        
        # Optimization components
        self.db = PerformanceDatabase()
        self.analyzer = PerformanceAnalyzer(self.db)
        self.bottleneck_detector = BottleneckDetector(self.analyzer)
        self.optimization_engine = OptimizationRecommendationEngine(
            self.analyzer, self.bottleneck_detector
        )
        self.report_generator = OptimizationReportGenerator(self.optimization_engine)
        
        self.results_summary = {}
    
    def run_quick_benchmark(self):
        """Run quick benchmark suite"""
        print("\n🚀 === QUICK BENCHMARK SUITE ===")
        print("Running lightweight benchmarks for rapid feedback...")
        
        start_time = time.time()
        
        try:
            # Run quick tests
            results = self.quick_benchmarks.run_all_quick_tests()
            report = self.quick_benchmarks.generate_quick_report(results)
            self.quick_benchmarks.save_results(results, report)
            
            duration = time.time() - start_time
            
            self.results_summary['quick_benchmark'] = {
                'status': 'success',
                'duration': duration,
                'tests_completed': len(results),
                'successful_tests': len([r for r in results if 'error' not in r.get('metadata', {})]),
                'results_files': [
                    'quick_benchmark_results_*.json',
                    'quick_benchmark_report_*.md'
                ]
            }
            
            print(f"✅ Quick benchmark completed in {duration:.1f}s")
            
        except Exception as e:
            print(f"❌ Quick benchmark failed: {e}")
            self.results_summary['quick_benchmark'] = {
                'status': 'failed',
                'error': str(e)
            }
    
    def run_hardware_benchmark(self):
        """Run hardware-specific benchmarks"""
        print("\n🖥️  === HARDWARE BENCHMARK SUITE ===")
        print("Running comprehensive hardware performance tests...")
        
        start_time = time.time()
        
        try:
            # Run hardware benchmarks
            hardware_results = self.benchmark_suite.run_hardware_benchmarks()
            
            duration = time.time() - start_time
            
            self.results_summary['hardware_benchmark'] = {
                'status': 'success',
                'duration': duration,
                'tests_completed': len(hardware_results),
                'successful_tests': len([r for r in hardware_results if not r.metadata or 'error' not in r.metadata]),
                'avg_throughput': sum(r.throughput for r in hardware_results if r.throughput) / len(hardware_results),
                'results_files': []
            }
            
            print(f"✅ Hardware benchmark completed in {duration:.1f}s")
            
        except Exception as e:
            print(f"❌ Hardware benchmark failed: {e}")
            self.results_summary['hardware_benchmark'] = {
                'status': 'failed',
                'error': str(e)
            }
    
    def run_code_benchmark(self):
        """Run CODE-specific benchmarks"""
        print("\n🚀 === CODE PROJECT BENCHMARK SUITE ===")
        print("Running CODE-specific performance tests...")
        
        start_time = time.time()
        
        try:
            # Run CODE benchmarks
            code_results = self.benchmark_suite.run_code_benchmarks()
            
            duration = time.time() - start_time
            
            self.results_summary['code_benchmark'] = {
                'status': 'success',
                'duration': duration,
                'tests_completed': len(code_results),
                'successful_tests': len([r for r in code_results if not r.metadata or 'error' not in r.metadata]),
                'rust_compilation_success': any('rust_compilation' in str(r.test_name) for r in code_results),
                'results_files': []
            }
            
            print(f"✅ CODE benchmark completed in {duration:.1f}s")
            
        except Exception as e:
            print(f"❌ CODE benchmark failed: {e}")
            self.results_summary['code_benchmark'] = {
                'status': 'failed',
                'error': str(e)
            }
    
    async def run_load_testing(self):
        """Run comprehensive load testing"""
        print("\n📈 === LOAD TESTING SUITE ===")
        print("Running comprehensive load and stress tests...")
        
        start_time = time.time()
        
        try:
            # Run load tests
            load_results = await self.load_test_suite.run_comprehensive_load_tests()
            report = self.load_test_suite.generate_load_test_report(load_results)
            self.load_test_suite.save_load_test_results(load_results, report)
            
            duration = time.time() - start_time
            
            self.results_summary['load_testing'] = {
                'status': 'success',
                'duration': duration,
                'scenarios_completed': len(load_results),
                'total_operations': sum(r.total_operations for r in load_results),
                'avg_error_rate': sum(r.error_rate for r in load_results) / len(load_results) if load_results else 0,
                'results_files': [
                    'load_test_results_*.json',
                    'load_test_report_*.md'
                ]
            }
            
            print(f"✅ Load testing completed in {duration:.1f}s")
            
        except Exception as e:
            print(f"❌ Load testing failed: {e}")
            self.results_summary['load_testing'] = {
                'status': 'failed',
                'error': str(e)
            }
    
    def run_optimization_analysis(self):
        """Run optimization analysis and recommendations"""
        print("\n🎯 === OPTIMIZATION ANALYSIS ===")
        print("Analyzing performance data and generating recommendations...")
        
        start_time = time.time()
        
        try:
            # Generate recommendations
            recommendations = self.optimization_engine.generate_recommendations(30)
            report = self.report_generator.generate_optimization_report(30)
            self.report_generator.save_optimization_report(report, recommendations)
            
            duration = time.time() - start_time
            
            critical_recommendations = len([r for r in recommendations if r.priority == 'critical'])
            high_recommendations = len([r for r in recommendations if r.priority == 'high'])
            
            self.results_summary['optimization_analysis'] = {
                'status': 'success',
                'duration': duration,
                'total_recommendations': len(recommendations),
                'critical_recommendations': critical_recommendations,
                'high_recommendations': high_recommendations,
                'estimated_improvement': sum(r.estimated_improvement_percent for r in recommendations[:5]),
                'results_files': [
                    'optimization_report_*.md',
                    'optimization_recommendations_*.json'
                ]
            }
            
            print(f"✅ Optimization analysis completed in {duration:.1f}s")
            print(f"   Generated {len(recommendations)} recommendations")
            print(f"   Critical: {critical_recommendations}, High: {high_recommendations}")
            
        except Exception as e:
            print(f"❌ Optimization analysis failed: {e}")
            self.results_summary['optimization_analysis'] = {
                'status': 'failed',
                'error': str(e)
            }
    
    def run_comprehensive_benchmark(self):
        """Run complete comprehensive benchmark suite"""
        print("\n🏆 === COMPREHENSIVE BENCHMARK SUITE ===")
        print("Running complete performance analysis...")
        
        start_time = time.time()
        
        try:
            # Run comprehensive benchmarks
            self.benchmark_suite.run_comprehensive_benchmark()
            
            duration = time.time() - start_time
            
            self.results_summary['comprehensive_benchmark'] = {
                'status': 'success',
                'duration': duration,
                'results_files': [
                    'comprehensive_benchmark_results_*.json',
                    'comprehensive_benchmark_report_*.md'
                ]
            }
            
            print(f"✅ Comprehensive benchmark completed in {duration:.1f}s")
            
        except Exception as e:
            print(f"❌ Comprehensive benchmark failed: {e}")
            self.results_summary['comprehensive_benchmark'] = {
                'status': 'failed',
                'error': str(e)
            }
    
    async def run_full_suite(self, include_load_testing=True):
        """Run the complete benchmarking suite"""
        print("🚀 STARTING COMPREHENSIVE BENCHMARKING SUITE")
        print("=" * 80)
        print(f"Started at: {datetime.now().isoformat()}")
        print(f"System: AMD Ryzen 7 7800X3D | 32GB DDR5 6000MHz | NVMe 2TB")
        print("")
        
        total_start_time = time.time()
        
        # 1. Quick benchmark for immediate feedback
        self.run_quick_benchmark()
        
        # 2. Hardware-specific benchmarks
        self.run_hardware_benchmark()
        
        # 3. CODE-specific benchmarks
        self.run_code_benchmark()
        
        # 4. Load testing (optional, time-consuming)
        if include_load_testing:
            await self.run_load_testing()
        
        # 5. Comprehensive benchmark suite
        self.run_comprehensive_benchmark()
        
        # 6. Optimization analysis and recommendations
        self.run_optimization_analysis()
        
        total_duration = time.time() - total_start_time
        
        # Generate final summary
        self.generate_final_summary(total_duration)
    
    def generate_final_summary(self, total_duration: float):
        """Generate final benchmarking summary"""
        print("\n" + "=" * 80)
        print("🎯 COMPREHENSIVE BENCHMARKING SUITE COMPLETED")
        print("=" * 80)
        
        print(f"\n📊 EXECUTION SUMMARY")
        print(f"Total execution time: {total_duration:.1f}s ({total_duration/60:.1f} minutes)")
        print(f"Completed at: {datetime.now().isoformat()}")
        print("")
        
        # Summary by component
        print("📈 COMPONENT RESULTS")
        for component, results in self.results_summary.items():
            status_emoji = "✅" if results['status'] == 'success' else "❌"
            component_name = component.replace('_', ' ').title()
            
            print(f"{status_emoji} {component_name}")
            
            if results['status'] == 'success':
                duration = results.get('duration', 0)
                print(f"   Duration: {duration:.1f}s")
                
                if 'tests_completed' in results:
                    print(f"   Tests completed: {results['tests_completed']}")
                if 'successful_tests' in results:
                    print(f"   Successful tests: {results['successful_tests']}")
                if 'total_recommendations' in results:
                    print(f"   Recommendations: {results['total_recommendations']}")
                    print(f"   Critical: {results.get('critical_recommendations', 0)}")
                if 'avg_throughput' in results:
                    print(f"   Avg throughput: {results['avg_throughput']:.1f} ops/s")
                if 'estimated_improvement' in results:
                    print(f"   Est. improvement: {results['estimated_improvement']:.1f}%")
            else:
                print(f"   Error: {results.get('error', 'Unknown error')}")
        
        print("")
        
        # Performance highlights
        successful_components = [c for c, r in self.results_summary.items() if r['status'] == 'success']
        
        print("🏆 PERFORMANCE HIGHLIGHTS")
        
        if 'optimization_analysis' in successful_components:
            opt_results = self.results_summary['optimization_analysis']
            print(f"• {opt_results['total_recommendations']} optimization opportunities identified")
            print(f"• {opt_results['critical_recommendations']} critical issues require immediate attention")
            print(f"• Estimated {opt_results['estimated_improvement']:.1f}% performance improvement potential")
        
        if 'load_testing' in successful_components:
            load_results = self.results_summary['load_testing']
            print(f"• {load_results['total_operations']:,} total operations executed in load testing")
            print(f"• {load_results['avg_error_rate']:.2f}% average error rate under load")
        
        if 'hardware_benchmark' in successful_components:
            hw_results = self.results_summary['hardware_benchmark']
            print(f"• Hardware benchmark average throughput: {hw_results.get('avg_throughput', 0):.1f} ops/s")
        
        print("")
        
        # Generated files
        print("📁 GENERATED FILES")
        benchmarks_dir = Path("/home/louranicas/projects/claude-optimized-deployment/benchmarks")
        
        all_files = []
        for component, results in self.results_summary.items():
            if results['status'] == 'success' and 'results_files' in results:
                all_files.extend(results['results_files'])
        
        if all_files:
            print(f"All results saved in: {benchmarks_dir}")
            print("Key files generated:")
            for file_pattern in set(all_files):
                print(f"• {file_pattern}")
        
        print("")
        
        # Next steps
        print("🎯 RECOMMENDED NEXT STEPS")
        
        if 'optimization_analysis' in successful_components:
            opt_results = self.results_summary['optimization_analysis']
            if opt_results['critical_recommendations'] > 0:
                print("1. 🔴 Address critical optimization recommendations immediately")
            if opt_results['high_recommendations'] > 0:
                print("2. 🟠 Plan implementation of high-priority optimizations")
            print("3. 📊 Review detailed optimization report for specific actions")
        
        if 'load_testing' in successful_components:
            load_results = self.results_summary['load_testing']
            if load_results['avg_error_rate'] > 5:
                print("4. ⚠️ Investigate high error rate in load testing")
        
        print("5. 🔄 Set up automated benchmarking schedule")
        print("6. 📈 Start performance dashboard for ongoing monitoring")
        print("7. 🚀 Begin implementing optimization recommendations")
        
        print("")
        print("✅ Comprehensive benchmarking suite completed successfully!")
        print("   Review the generated reports for detailed analysis and recommendations.")
    
    def start_dashboard(self, host='localhost', port=5000):
        """Start the performance dashboard"""
        print(f"\n🌐 Starting Performance Dashboard")
        print(f"Dashboard URL: http://{host}:{port}")
        
        try:
            run_dashboard_server(host=host, port=port, debug=False)
        except KeyboardInterrupt:
            print("\nDashboard stopped by user")
        except Exception as e:
            print(f"Dashboard failed to start: {e}")

def main():
    """Main entry point with command line arguments"""
    parser = argparse.ArgumentParser(description='Comprehensive Performance Benchmarking Suite')
    parser.add_argument('--mode', choices=['quick', 'hardware', 'code', 'load', 'optimization', 'comprehensive', 'full', 'dashboard'], 
                       default='full', help='Benchmark mode to run')
    parser.add_argument('--no-load-testing', action='store_true', 
                       help='Skip load testing (saves time)')
    parser.add_argument('--dashboard-host', default='localhost', 
                       help='Dashboard host (default: localhost)')
    parser.add_argument('--dashboard-port', type=int, default=5000, 
                       help='Dashboard port (default: 5000)')
    
    args = parser.parse_args()
    
    orchestrator = MasterBenchmarkOrchestrator()
    
    if args.mode == 'quick':
        orchestrator.run_quick_benchmark()
    elif args.mode == 'hardware':
        orchestrator.run_hardware_benchmark()
    elif args.mode == 'code':
        orchestrator.run_code_benchmark()
    elif args.mode == 'load':
        asyncio.run(orchestrator.run_load_testing())
    elif args.mode == 'optimization':
        orchestrator.run_optimization_analysis()
    elif args.mode == 'comprehensive':
        orchestrator.run_comprehensive_benchmark()
    elif args.mode == 'dashboard':
        orchestrator.start_dashboard(args.dashboard_host, args.dashboard_port)
    elif args.mode == 'full':
        include_load = not args.no_load_testing
        asyncio.run(orchestrator.run_full_suite(include_load_testing=include_load))
    
    # Print final instructions
    if args.mode != 'dashboard':
        print(f"\n💡 TIP: Start the dashboard to monitor results in real-time:")
        print(f"   python3 {__file__} --mode dashboard")

if __name__ == "__main__":
    main()