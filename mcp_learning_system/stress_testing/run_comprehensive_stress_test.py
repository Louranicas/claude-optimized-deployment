#!/usr/bin/env python3
"""
Comprehensive MCP Learning System Stress Testing Suite

This script runs the complete stress testing framework including:
- 7-phase stress testing
- Performance benchmarking  
- Chaos engineering
- Memory efficiency testing
- Cross-instance stress testing
- Validation and reporting

Usage:
    python run_comprehensive_stress_test.py [--duration SECONDS] [--report-only]
"""

import asyncio
import argparse
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

# Import stress testing components
from integration import MCPLearningStressTest
from benchmarks import LearningBenchmark, MemoryBenchmark, CrossInstanceBenchmark
from scenarios import (
    LearningUnderLoadScenario,
    MemoryEfficiencyScenario, 
    CrossInstanceStressScenario,
    ChaosRecoveryScenario
)
from validators import PerformanceValidator
from reports.performance_optimization_report import PerformanceOptimizationReportGenerator

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'stress_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)

logger = logging.getLogger(__name__)


class ComprehensiveStressTestSuite:
    """Complete stress testing suite for MCP Learning System."""
    
    def __init__(self, duration_per_test: int = 300):
        """Initialize stress test suite.
        
        Args:
            duration_per_test: Duration for each test category in seconds
        """
        self.duration_per_test = duration_per_test
        self.results = {}
        
    async def run_complete_test_suite(self) -> Dict[str, Any]:
        """Run the complete stress testing suite."""
        logger.info("=" * 80)
        logger.info("STARTING COMPREHENSIVE MCP LEARNING SYSTEM STRESS TEST SUITE")
        logger.info("=" * 80)
        
        start_time = time.time()
        
        try:
            # Phase 1: Core Stress Testing (7-phase framework)
            logger.info("\n🔄 PHASE 1: Core Stress Testing")
            self.results['core_stress_test'] = await self._run_core_stress_test()
            
            # Phase 2: Performance Benchmarking
            logger.info("\n📊 PHASE 2: Performance Benchmarking")
            self.results['benchmarks'] = await self._run_performance_benchmarks()
            
            # Phase 3: Scenario-Based Testing
            logger.info("\n🎯 PHASE 3: Scenario-Based Testing")
            self.results['scenarios'] = await self._run_scenario_tests()
            
            # Phase 4: Chaos Engineering
            logger.info("\n💥 PHASE 4: Chaos Engineering")
            self.results['chaos_testing'] = await self._run_chaos_tests()
            
            # Phase 5: Validation and Analysis
            logger.info("\n✅ PHASE 5: Validation and Analysis")
            self.results['validation'] = await self._run_validation()
            
            # Phase 6: Report Generation
            logger.info("\n📋 PHASE 6: Report Generation")
            self.results['optimization_report'] = await self._generate_optimization_report()
            
            total_time = time.time() - start_time
            logger.info(f"\n🎉 STRESS TEST SUITE COMPLETED in {total_time:.1f} seconds")
            
            # Print summary
            self._print_test_summary()
            
            return self.results
            
        except Exception as e:
            logger.error(f"❌ STRESS TEST SUITE FAILED: {e}")
            raise
    
    async def _run_core_stress_test(self) -> Dict[str, Any]:
        """Run 7-phase core stress testing."""
        logger.info("Running 7-phase stress testing framework...")
        
        stress_tester = MCPLearningStressTest()
        
        try:
            results = await stress_tester.run_comprehensive_stress_test()
            
            logger.info("✅ Core stress testing completed successfully")
            logger.info(f"   - Phases completed: {len(results.get('results', {}))}")
            logger.info(f"   - Overall success: {results.get('summary', {}).get('overall_success', False)}")
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Core stress testing failed: {e}")
            return {'error': str(e)}
    
    async def _run_performance_benchmarks(self) -> Dict[str, Any]:
        """Run performance benchmarking suite."""
        logger.info("Running performance benchmarks...")
        
        benchmark_results = {}
        
        try:
            # Learning benchmarks
            logger.info("  📈 Learning performance benchmarks...")
            learning_benchmark = LearningBenchmark()
            benchmark_results['learning'] = await learning_benchmark.run_all_benchmarks()
            
            # Memory benchmarks
            logger.info("  🧠 Memory efficiency benchmarks...")
            memory_benchmark = MemoryBenchmark()
            benchmark_results['memory'] = await memory_benchmark.run_memory_benchmarks()
            
            # Cross-instance benchmarks
            logger.info("  🌐 Cross-instance communication benchmarks...")
            cross_instance_benchmark = CrossInstanceBenchmark()
            benchmark_results['cross_instance'] = await cross_instance_benchmark.run_cross_instance_benchmarks()
            
            logger.info("✅ Performance benchmarking completed successfully")
            
            return benchmark_results
            
        except Exception as e:
            logger.error(f"❌ Performance benchmarking failed: {e}")
            return {'error': str(e)}
    
    async def _run_scenario_tests(self) -> Dict[str, Any]:
        """Run scenario-based stress testing."""
        logger.info("Running scenario-based stress tests...")
        
        scenario_results = {}
        
        try:
            # Learning under load scenarios
            logger.info("  🏋️ Learning under load scenarios...")
            learning_scenario = LearningUnderLoadScenario()
            scenario_results['learning_under_load'] = await learning_scenario.run_scenario(
                duration=self.duration_per_test
            )
            
            # Memory efficiency scenarios
            logger.info("  💾 Memory efficiency scenarios...")
            memory_scenario = MemoryEfficiencyScenario()
            scenario_results['memory_efficiency'] = await memory_scenario.run_scenario(
                duration=self.duration_per_test
            )
            
            # Cross-instance stress scenarios
            logger.info("  🔗 Cross-instance stress scenarios...")
            cross_instance_scenario = CrossInstanceStressScenario()
            scenario_results['cross_instance_stress'] = await cross_instance_scenario.run_scenario(
                duration=self.duration_per_test
            )
            
            logger.info("✅ Scenario-based testing completed successfully")
            
            return scenario_results
            
        except Exception as e:
            logger.error(f"❌ Scenario-based testing failed: {e}")
            return {'error': str(e)}
    
    async def _run_chaos_tests(self) -> Dict[str, Any]:
        """Run chaos engineering tests."""
        logger.info("Running chaos engineering tests...")
        
        try:
            chaos_scenario = ChaosRecoveryScenario()
            chaos_results = await chaos_scenario.run_scenario(duration=self.duration_per_test)
            
            logger.info("✅ Chaos engineering completed successfully")
            
            # Log chaos summary
            total_events = sum(
                result.total_chaos_events for result in chaos_results.values()
                if hasattr(result, 'total_chaos_events')
            )
            logger.info(f"   - Total chaos events: {total_events}")
            
            return chaos_results
            
        except Exception as e:
            logger.error(f"❌ Chaos engineering failed: {e}")
            return {'error': str(e)}
    
    async def _run_validation(self) -> Dict[str, Any]:
        """Run validation of all test results."""
        logger.info("Running validation and analysis...")
        
        try:
            validator = PerformanceValidator()
            validation_results = {}
            
            # Validate benchmark results
            if 'benchmarks' in self.results:
                logger.info("  🔍 Validating benchmark results...")
                benchmark_validations = validator.validate_benchmark_results(
                    self.results['benchmarks']
                )
                validation_results['benchmark_validations'] = benchmark_validations
            
            # Validate stress test results
            if 'core_stress_test' in self.results:
                logger.info("  🔍 Validating stress test results...")
                stress_validations = validator.validate_stress_test_results(
                    self.results['core_stress_test']
                )
                validation_results['stress_validations'] = stress_validations
            
            # Validate scenario results
            if 'scenarios' in self.results:
                logger.info("  🔍 Validating scenario results...")
                scenario_validations = validator.validate_load_scenario_results(
                    self.results['scenarios']
                )
                validation_results['scenario_validations'] = scenario_validations
            
            # Generate validation report
            all_validations = []
            for validation_list in validation_results.values():
                if isinstance(validation_list, list):
                    all_validations.extend(validation_list)
            
            validation_report = validator.generate_performance_report(all_validations)
            validation_results['summary'] = validation_report
            
            logger.info("✅ Validation completed successfully")
            logger.info(f"   - Total validations: {validation_report.get('total_validations', 0)}")
            logger.info(f"   - Passed: {validation_report.get('passed_validations', 0)}")
            logger.info(f"   - Failed: {validation_report.get('failed_validations', 0)}")
            logger.info(f"   - Performance score: {validation_report.get('performance_score', 0):.1f}")
            
            return validation_results
            
        except Exception as e:
            logger.error(f"❌ Validation failed: {e}")
            return {'error': str(e)}
    
    async def _generate_optimization_report(self) -> Dict[str, Any]:
        """Generate comprehensive optimization report."""
        logger.info("Generating optimization report...")
        
        try:
            report_generator = PerformanceOptimizationReportGenerator()
            
            # Extract required data
            stress_results = self.results.get('core_stress_test', {})
            benchmark_results = self.results.get('benchmarks', {})
            validation_results = self.results.get('validation', {})
            
            # Generate comprehensive report
            optimization_report = report_generator.generate_comprehensive_report(
                stress_results, benchmark_results, validation_results
            )
            
            logger.info("✅ Optimization report generated successfully")
            
            # Log key findings
            executive_summary = optimization_report.get('executive_summary', {})
            overall_assessment = executive_summary.get('overall_assessment', {})
            
            logger.info(f"   - Performance score: {overall_assessment.get('performance_score', 0):.1f}")
            logger.info(f"   - Score rating: {overall_assessment.get('score_rating', 'Unknown')}")
            
            recommendations_summary = executive_summary.get('recommendations_summary', {})
            logger.info(f"   - Total recommendations: {recommendations_summary.get('total_recommendations', 0)}")
            
            return optimization_report
            
        except Exception as e:
            logger.error(f"❌ Optimization report generation failed: {e}")
            return {'error': str(e)}
    
    def _print_test_summary(self):
        """Print comprehensive test summary."""
        logger.info("\n" + "=" * 80)
        logger.info("COMPREHENSIVE STRESS TEST SUMMARY")
        logger.info("=" * 80)
        
        # Core stress test summary
        if 'core_stress_test' in self.results:
            core_results = self.results['core_stress_test']
            if 'summary' in core_results:
                summary = core_results['summary']
                logger.info(f"🔄 Core Stress Test:")
                logger.info(f"   - Overall Success: {summary.get('overall_success', False)}")
                logger.info(f"   - Phases Passed: {summary.get('phases_passed', 0)}")
                logger.info(f"   - Total Errors: {summary.get('total_errors', 0)}")
        
        # Benchmark summary
        if 'benchmarks' in self.results:
            logger.info(f"📊 Performance Benchmarks: Completed")
            benchmark_results = self.results['benchmarks']
            for category, results in benchmark_results.items():
                if isinstance(results, dict) and 'summary' in results:
                    logger.info(f"   - {category.title()}: {len(results)} tests")
        
        # Scenario summary
        if 'scenarios' in self.results:
            logger.info(f"🎯 Scenario Tests: Completed")
            scenario_results = self.results['scenarios']
            for scenario_name in scenario_results.keys():
                logger.info(f"   - {scenario_name.replace('_', ' ').title()}: ✅")
        
        # Chaos testing summary
        if 'chaos_testing' in self.results:
            logger.info(f"💥 Chaos Engineering: Completed")
            chaos_results = self.results['chaos_testing']
            if 'summary' in chaos_results:
                chaos_summary = chaos_results['summary']
                logger.info(f"   - Resilience Score: {chaos_summary.get('system_resilience_score', 0):.2f}")
                logger.info(f"   - Recovery Rate: {chaos_summary.get('successful_recoveries', 0)}/{chaos_summary.get('total_chaos_events', 0)}")
        
        # Validation summary
        if 'validation' in self.results:
            validation_results = self.results['validation']
            if 'summary' in validation_results:
                validation_summary = validation_results['summary']
                logger.info(f"✅ Validation:")
                logger.info(f"   - Performance Score: {validation_summary.get('performance_score', 0):.1f}/100")
                logger.info(f"   - Critical Issues: {validation_summary.get('by_severity', {}).get('critical', 0)}")
        
        # Optimization report summary
        if 'optimization_report' in self.results:
            opt_report = self.results['optimization_report']
            if 'executive_summary' in opt_report:
                exec_summary = opt_report['executive_summary']
                recommendations = exec_summary.get('recommendations_summary', {})
                logger.info(f"📋 Optimization Report:")
                logger.info(f"   - Total Recommendations: {recommendations.get('total_recommendations', 0)}")
                logger.info(f"   - Critical/High Priority: {recommendations.get('by_priority', {}).get('critical', 0) + recommendations.get('by_priority', {}).get('high', 0)}")
        
        logger.info("\n🎯 NEXT STEPS:")
        logger.info("   1. Review the detailed optimization report")
        logger.info("   2. Address critical and high-priority recommendations")
        logger.info("   3. Implement monitoring for continuous performance tracking")
        logger.info("   4. Schedule regular stress testing")
        
        logger.info("\n📁 Report files saved to: mcp_learning_system/stress_testing/reports/")
        logger.info("=" * 80)


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Comprehensive MCP Learning System Stress Testing Suite"
    )
    parser.add_argument(
        '--duration',
        type=int,
        default=300,
        help='Duration for each test category in seconds (default: 300)'
    )
    parser.add_argument(
        '--report-only',
        action='store_true',
        help='Generate report from existing results only'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        if args.report_only:
            logger.info("Report-only mode: Generating reports from existing data")
            # TODO: Implement report-only mode
            logger.warning("Report-only mode not yet implemented")
            return
        
        # Run comprehensive stress test suite
        logger.info(f"Starting comprehensive stress test suite (duration per test: {args.duration}s)")
        
        test_suite = ComprehensiveStressTestSuite(duration_per_test=args.duration)
        results = await test_suite.run_complete_test_suite()
        
        logger.info("✅ All tests completed successfully!")
        
        # Save final results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = Path(f"mcp_learning_system/stress_testing/reports/comprehensive_results_{timestamp}.json")
        
        # Ensure directory exists
        results_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Save results (with proper JSON serialization)
        import json
        
        def serialize_results(obj):
            """Custom serializer for complex objects."""
            if hasattr(obj, 'to_dict'):
                return obj.to_dict()
            elif isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, Exception):
                return str(obj)
            else:
                return str(obj)
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=serialize_results)
        
        logger.info(f"📁 Complete results saved to: {results_file}")
        
    except KeyboardInterrupt:
        logger.warning("⚠️ Test suite interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Test suite failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Run the comprehensive stress test suite
    asyncio.run(main())