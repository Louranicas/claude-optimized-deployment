#!/usr/bin/env python3
"""
Comprehensive Example Usage of the Stress Testing Framework

This example demonstrates all major features of the stress testing framework
including cycle management, safety controls, adaptive ramping, and real-time monitoring.
"""

import asyncio
import logging
import time
import json
from typing import Dict, Any

# Import the stress testing framework
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.cycle_manager import StressCycleManager, StressPhase
from core.safety_manager import SafetyManager, SafetyViolation
from core.metrics_collector import MetricsCollector, SystemSnapshot
from core.adaptive_ramping import AdaptiveRampingEngine, RampingProfile, RampingStrategy
from interfaces.control_api import StressTestingControlAPI
from . import StressTestingFramework, run_stress_test, quick_stress_test


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('stress_test.log')
    ]
)

logger = logging.getLogger(__name__)


class StressTestingDemo:
    """
    Comprehensive demonstration of the stress testing framework
    """
    
    def __init__(self):
        self.framework = None
        self.results = {}
    
    async def run_all_examples(self):
        """Run all demonstration examples"""
        logger.info("Starting comprehensive stress testing framework demonstration")
        
        try:
            # Example 1: Basic cycle execution
            await self.example_basic_cycle()
            
            # Example 2: Custom phase selection
            await self.example_custom_phases()
            
            # Example 3: Safety system demonstration
            await self.example_safety_system()
            
            # Example 4: Adaptive ramping demonstration
            await self.example_adaptive_ramping()
            
            # Example 5: Real-time control
            await self.example_real_time_control()
            
            # Example 6: Metrics collection and analysis
            await self.example_metrics_analysis()
            
            # Example 7: Quick stress test
            await self.example_quick_test()
            
            # Generate summary report
            await self.generate_summary_report()
            
        except Exception as e:
            logger.error(f"Demo execution failed: {e}")
        
        logger.info("Stress testing framework demonstration completed")
    
    async def example_basic_cycle(self):
        """Example 1: Basic full cycle execution"""
        logger.info("=== Example 1: Basic Full Cycle Execution ===")
        
        try:
            # Initialize framework
            self.framework = StressTestingFramework()
            
            # Set up event callbacks
            self.framework.cycle_manager.register_phase_change_callback(self._on_phase_change)
            self.framework.cycle_manager.register_safety_callback(self._on_safety_event)
            
            # Start the full 7-phase cycle
            logger.info("Starting complete 7-phase stress testing cycle")
            success = await self.framework.cycle_manager.start_cycle()
            
            if success:
                # Monitor progress
                while self.framework.cycle_manager.is_running():
                    status = self.framework.cycle_manager.get_status()
                    logger.info(f"Phase: {status.current_phase.name if status.current_phase else 'None'}, "
                              f"Load: {status.current_load_percent:.1f}%, "
                              f"State: {status.state.value}")
                    await asyncio.sleep(5)  # Check every 5 seconds
                
                # Get final results
                history = self.framework.cycle_manager.get_cycle_history()
                self.results['basic_cycle'] = history[-1] if history else None
                
                logger.info("Basic cycle completed successfully")
            else:
                logger.error("Failed to start basic cycle")
                
        except Exception as e:
            logger.error(f"Basic cycle example failed: {e}")
        
        finally:
            if self.framework:
                await self.framework.stop()
    
    async def example_custom_phases(self):
        """Example 2: Custom phase selection"""
        logger.info("=== Example 2: Custom Phase Selection ===")
        
        try:
            self.framework = StressTestingFramework()
            
            # Run only specific phases
            selected_phases = [StressPhase.LIGHT, StressPhase.MEDIUM, StressPhase.HEAVY]
            
            logger.info(f"Running selected phases: {[p.name for p in selected_phases]}")
            success = await self.framework.cycle_manager.start_cycle(selected_phases)
            
            if success:
                # Monitor with detailed logging
                while self.framework.cycle_manager.is_running():
                    status = self.framework.cycle_manager.get_status()
                    logger.info(f"Custom phases - Phase: {status.current_phase.name if status.current_phase else 'None'}, "
                              f"Load: {status.current_load_percent:.1f}%")
                    await asyncio.sleep(3)
                
                history = self.framework.cycle_manager.get_cycle_history()
                self.results['custom_phases'] = history[-1] if history else None
                
                logger.info("Custom phases completed successfully")
            
        except Exception as e:
            logger.error(f"Custom phases example failed: {e}")
        
        finally:
            if self.framework:
                await self.framework.stop()
    
    async def example_safety_system(self):
        """Example 3: Safety system demonstration"""
        logger.info("=== Example 3: Safety System Demonstration ===")
        
        try:
            self.framework = StressTestingFramework()
            
            # Set up safety violation callback
            safety_events = []
            
            async def safety_callback(violation):
                safety_events.append(violation)
                logger.warning(f"Safety violation: {violation.message}")
            
            # Register safety callback
            # Note: This would require access to the safety manager
            # self.framework.cycle_manager.safety_manager.register_violation_callback(safety_callback)
            
            # Simulate a test that might trigger safety mechanisms
            # Run only the EXTREME phase to test safety limits
            logger.info("Running EXTREME phase to test safety mechanisms")
            success = await self.framework.cycle_manager.start_cycle([StressPhase.EXTREME])
            
            if success:
                while self.framework.cycle_manager.is_running():
                    status = self.framework.cycle_manager.get_status()
                    logger.info(f"Safety test - Load: {status.current_load_percent:.1f}%, "
                              f"Safety triggered: {status.safety_triggered}")
                    await asyncio.sleep(2)
                
                self.results['safety_system'] = {
                    'safety_events': len(safety_events),
                    'safety_triggered': status.safety_triggered
                }
                
                logger.info("Safety system demonstration completed")
            
        except Exception as e:
            logger.error(f"Safety system example failed: {e}")
        
        finally:
            if self.framework:
                await self.framework.stop()
    
    async def example_adaptive_ramping(self):
        """Example 4: Adaptive ramping demonstration"""
        logger.info("=== Example 4: Adaptive Ramping Demonstration ===")
        
        try:
            # Create adaptive ramping engine with custom profile
            ramping_profile = RampingProfile(
                strategy=RampingStrategy.ADAPTIVE,
                aggressiveness=0.7,  # More aggressive
                stability_threshold=0.15,
                degradation_threshold=0.25,
                adaptation_rate=0.2
            )
            
            adaptive_engine = AdaptiveRampingEngine(ramping_profile)
            await adaptive_engine.initialize()
            
            # Simulate adaptive ramping decisions
            logger.info("Demonstrating adaptive ramping decisions")
            
            # Mock phase configuration
            class MockPhaseConfig:
                min_load_percent = 0.0
                max_load_percent = 75.0
                adaptive_enabled = True
            
            phase_config = MockPhaseConfig()
            
            # Simulate ramping through different progress levels
            decisions = []
            for progress in [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]:
                target_load = await adaptive_engine.calculate_target_load(phase_config, progress)
                decisions.append({
                    'progress': progress,
                    'target_load': target_load
                })
                logger.info(f"Progress: {progress:.1f}, Target Load: {target_load:.1f}%")
                await asyncio.sleep(0.5)
            
            # Get analysis summary
            analysis = adaptive_engine.get_analysis_summary()
            
            self.results['adaptive_ramping'] = {
                'decisions': decisions,
                'analysis': analysis
            }
            
            logger.info("Adaptive ramping demonstration completed")
            
        except Exception as e:
            logger.error(f"Adaptive ramping example failed: {e}")
    
    async def example_real_time_control(self):
        """Example 5: Real-time control demonstration"""
        logger.info("=== Example 5: Real-time Control Demonstration ===")
        
        try:
            # Start control API in background
            self.framework = StressTestingFramework()
            
            # Simulate real-time control operations
            logger.info("Demonstrating real-time control operations")
            
            # Start a cycle
            await self.framework.cycle_manager.start_cycle([StressPhase.LIGHT, StressPhase.MEDIUM])
            
            # Wait a bit, then pause
            await asyncio.sleep(10)
            logger.info("Pausing cycle for demonstration")
            await self.framework.cycle_manager.pause_cycle()
            
            await asyncio.sleep(5)
            logger.info("Resuming cycle")
            await self.framework.cycle_manager.resume_cycle()
            
            # Wait for completion
            while self.framework.cycle_manager.is_running():
                await asyncio.sleep(2)
            
            self.results['real_time_control'] = {
                'operations': ['start', 'pause', 'resume', 'complete']
            }
            
            logger.info("Real-time control demonstration completed")
            
        except Exception as e:
            logger.error(f"Real-time control example failed: {e}")
        
        finally:
            if self.framework:
                await self.framework.stop()
    
    async def example_metrics_analysis(self):
        """Example 6: Metrics collection and analysis"""
        logger.info("=== Example 6: Metrics Collection and Analysis ===")
        
        try:
            # Initialize metrics collector
            metrics_collector = MetricsCollector(collection_interval=0.5)
            
            # Start collection
            await metrics_collector.start_collection()
            
            # Collect baseline
            baseline = await metrics_collector.collect_baseline()
            logger.info(f"Baseline CPU: {baseline.cpu_usage:.1f}%, Memory: {baseline.memory_usage:.1f}%")
            
            # Create a profiler
            profiler = metrics_collector.create_profiler("demo_operation")
            profiler.start()
            
            # Simulate some work with metrics collection
            logger.info("Collecting metrics during simulated work")
            for i in range(20):
                profiler.checkpoint(f"step_{i}")
                await asyncio.sleep(0.5)
                
                if i % 5 == 0:
                    current_metrics = await metrics_collector.collect_metrics()
                    logger.info(f"Step {i}: CPU {current_metrics.get('current_snapshot', {}).get('cpu_usage', 0):.1f}%")
            
            profiler.end()
            
            # Get final metrics
            final_metrics = await metrics_collector.collect_final_metrics()
            
            # Stop collection
            await metrics_collector.stop_collection()
            
            # Export metrics
            metrics_file = "demo_metrics.json"
            metrics_collector.export_metrics_json(metrics_file)
            
            self.results['metrics_analysis'] = {
                'baseline': baseline.cpu_usage,
                'profiler_duration': profiler.get_duration(),
                'snapshots_collected': len(metrics_collector.snapshots),
                'metrics_exported': metrics_file
            }
            
            logger.info("Metrics analysis demonstration completed")
            
        except Exception as e:
            logger.error(f"Metrics analysis example failed: {e}")
    
    async def example_quick_test(self):
        """Example 7: Quick stress test"""
        logger.info("=== Example 7: Quick Stress Test ===")
        
        try:
            # Use the convenience function for a quick test
            logger.info("Running quick stress test with 60% load for 30 seconds")
            result = await quick_stress_test(target_load=60, duration=30)
            
            if result['success']:
                logger.info(f"Quick test completed: {result}")
                self.results['quick_test'] = result
            else:
                logger.error(f"Quick test failed: {result['error']}")
            
        except Exception as e:
            logger.error(f"Quick test example failed: {e}")
    
    async def generate_summary_report(self):
        """Generate comprehensive summary report"""
        logger.info("=== Generating Summary Report ===")
        
        try:
            report = {
                'timestamp': time.time(),
                'demo_results': self.results,
                'framework_info': {
                    'version': '1.0.0',
                    'components_tested': [
                        'cycle_manager',
                        'safety_system',
                        'adaptive_ramping',
                        'metrics_collection',
                        'real_time_control'
                    ]
                }
            }
            
            # Save report
            report_file = f"stress_test_demo_report_{int(time.time())}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Summary report saved to: {report_file}")
            
            # Print summary
            print("\n" + "="*60)
            print("STRESS TESTING FRAMEWORK DEMONSTRATION SUMMARY")
            print("="*60)
            print(f"Report saved to: {report_file}")
            print(f"Total examples executed: {len(self.results)}")
            print("\nExample Results:")
            for example, result in self.results.items():
                print(f"  {example}: {'SUCCESS' if result else 'FAILED'}")
            print("="*60 + "\n")
            
        except Exception as e:
            logger.error(f"Failed to generate summary report: {e}")
    
    # Event callback methods
    async def _on_phase_change(self, phase, event, status):
        """Handle phase change events"""
        logger.info(f"Phase Change: {phase.name} - {event}")
    
    async def _on_safety_event(self, event, status):
        """Handle safety events"""
        logger.warning(f"Safety Event: {event}")


# Standalone examples
async def simple_example():
    """Simple standalone example"""
    print("Running simple stress test example...")
    
    # Quick test
    result = await quick_stress_test(target_load=30, duration=15)
    print(f"Quick test result: {result}")
    
    # Full cycle test with selected phases
    result = await run_stress_test(['idle', 'light', 'medium'])
    print(f"Full cycle result: {result}")


async def advanced_example():
    """Advanced standalone example with detailed control"""
    print("Running advanced stress test example...")
    
    framework = StressTestingFramework()
    
    try:
        # Start a controlled test
        cycle_manager = framework.get_cycle_manager()
        
        # Register callbacks for monitoring
        events = []
        
        async def phase_callback(phase, event, status):
            events.append(f"Phase {phase.name}: {event}")
        
        cycle_manager.register_phase_change_callback(phase_callback)
        
        # Run specific phases with monitoring
        success = await cycle_manager.start_cycle([StressPhase.MEDIUM, StressPhase.HEAVY])
        
        if success:
            while cycle_manager.is_running():
                status = cycle_manager.get_status()
                print(f"Status: {status.state.value}, Load: {status.current_load_percent:.1f}%")
                await asyncio.sleep(3)
            
            print(f"Test completed. Events: {len(events)}")
            for event in events:
                print(f"  {event}")
        
    finally:
        await framework.stop()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Stress Testing Framework Examples")
    parser.add_argument("--mode", choices=['simple', 'advanced', 'demo'], 
                       default='demo', help="Example mode to run")
    
    args = parser.parse_args()
    
    if args.mode == 'simple':
        asyncio.run(simple_example())
    elif args.mode == 'advanced':
        asyncio.run(advanced_example())
    else:  # demo
        demo = StressTestingDemo()
        asyncio.run(demo.run_all_examples())