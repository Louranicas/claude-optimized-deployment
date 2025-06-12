#!/usr/bin/env python3
"""
Test Script for Stress Testing Framework

Validates the core functionality of the stress testing framework components.
"""

import asyncio
import logging
import sys
import os
import tempfile
import time

# Add the stress testing framework to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.cycle_manager import StressCycleManager, StressPhase, CycleState
from core.load_controller import LoadController, LoadConfiguration
from core.safety_manager import SafetyManager, SafetyLevel, ThresholdType
from core.metrics_collector import MetricsCollector, SystemSnapshot
from core.adaptive_ramping import AdaptiveRampingEngine, RampingStrategy, RampingProfile

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FrameworkTester:
    """Test suite for the stress testing framework"""
    
    def __init__(self):
        self.test_results = {}
        self.temp_dir = tempfile.mkdtemp(prefix="stress_test_")
    
    async def run_all_tests(self):
        """Run all component tests"""
        logger.info("Starting stress testing framework validation")
        
        test_methods = [
            self.test_load_controller,
            self.test_safety_manager,
            self.test_metrics_collector,
            self.test_adaptive_ramping,
            self.test_cycle_manager,
            self.test_integration
        ]
        
        for test_method in test_methods:
            try:
                logger.info(f"Running {test_method.__name__}")
                await test_method()
                self.test_results[test_method.__name__] = "PASSED"
                logger.info(f"{test_method.__name__} PASSED")
            except Exception as e:
                logger.error(f"{test_method.__name__} FAILED: {e}")
                self.test_results[test_method.__name__] = f"FAILED: {e}"
        
        self.print_summary()
    
    async def test_load_controller(self):
        """Test load controller functionality"""
        logger.info("Testing load controller...")
        
        # Create load controller with small limits for testing
        config = LoadConfiguration(
            cpu_cores=2,
            memory_limit_gb=0.1,  # Very small for testing
            io_operations_per_second=10,
            network_bandwidth_mbps=1.0
        )
        
        controller = LoadController(config)
        
        try:
            # Initialize
            await controller.initialize()
            assert controller.is_initialized(), "Controller should be initialized"
            
            # Test load setting
            await controller.set_cpu_load(25.0)
            await controller.set_memory_load(10.0)
            
            loads = controller.get_current_loads()
            assert loads['cpu'] == 25.0, f"CPU load should be 25%, got {loads['cpu']}"
            assert loads['memory'] == 10.0, f"Memory load should be 10%, got {loads['memory']}"
            
            # Test stop
            await controller.stop_all_loads()
            loads = controller.get_current_loads()
            assert all(load == 0.0 for load in loads.values()), "All loads should be 0 after stop"
            
        finally:
            await controller.cleanup()
    
    async def test_safety_manager(self):
        """Test safety manager functionality"""
        logger.info("Testing safety manager...")
        
        safety_manager = SafetyManager()
        
        try:
            # Initialize
            await safety_manager.initialize()
            assert safety_manager.initialized, "Safety manager should be initialized"
            
            # Test threshold setting
            thresholds = {"cpu_usage": 80.0, "memory_usage": 85.0}
            await safety_manager.set_thresholds(thresholds)
            
            # Test circuit breaker
            assert await safety_manager.check_circuit_breaker("cpu_protection"), "Circuit breaker should be closed initially"
            
            # Test emergency conditions (should be false initially)
            emergency = await safety_manager.check_emergency_conditions()
            assert not emergency, "Emergency conditions should be false initially"
            
            # Get status
            status = safety_manager.get_current_status()
            assert status['initialized'], "Status should show initialized"
            assert not status['emergency_triggered'], "Emergency should not be triggered"
            
        finally:
            await safety_manager.shutdown()
    
    async def test_metrics_collector(self):
        """Test metrics collector functionality"""
        logger.info("Testing metrics collector...")
        
        collector = MetricsCollector(collection_interval=0.1)
        
        try:
            # Start collection
            await collector.start_collection()
            assert collector.collecting, "Collector should be collecting"
            
            # Collect baseline
            baseline = await collector.collect_baseline()
            assert isinstance(baseline, SystemSnapshot), "Baseline should be SystemSnapshot"
            assert baseline.cpu_usage >= 0, "CPU usage should be non-negative"
            
            # Wait for some collection
            await asyncio.sleep(1.0)
            
            # Get current metrics
            metrics = await collector.collect_metrics()
            assert 'current_snapshot' in metrics, "Metrics should contain current snapshot"
            
            # Test profiler
            profiler = collector.create_profiler("test_operation")
            profiler.start()
            profiler.checkpoint("middle")
            await asyncio.sleep(0.1)
            profiler.end()
            
            assert profiler.get_duration() > 0, "Profiler should have positive duration"
            
            # Export metrics
            metrics_file = os.path.join(self.temp_dir, "test_metrics.json")
            collector.export_metrics_json(metrics_file)
            assert os.path.exists(metrics_file), "Metrics file should be created"
            
        finally:
            await collector.stop_collection()
    
    async def test_adaptive_ramping(self):
        """Test adaptive ramping engine"""
        logger.info("Testing adaptive ramping engine...")
        
        # Create custom profile
        profile = RampingProfile(
            strategy=RampingStrategy.ADAPTIVE,
            aggressiveness=0.5,
            stability_threshold=0.1
        )
        
        ramping_engine = AdaptiveRampingEngine(profile)
        
        try:
            # Initialize
            await ramping_engine.initialize()
            assert ramping_engine.initialized, "Ramping engine should be initialized"
            
            # Mock phase configuration
            class MockPhaseConfig:
                min_load_percent = 0.0
                max_load_percent = 50.0
                adaptive_enabled = True
            
            phase_config = MockPhaseConfig()
            
            # Test target load calculation
            target_load = await ramping_engine.calculate_target_load(phase_config, 0.5)
            assert 0 <= target_load <= 50, f"Target load should be between 0-50%, got {target_load}"
            
            # Test steady state adjustment
            adjusted_load = await ramping_engine.adjust_steady_state_load(phase_config, 25.0)
            assert isinstance(adjusted_load, float), "Adjusted load should be float"
            
            # Get analysis summary
            summary = ramping_engine.get_analysis_summary()
            assert 'current_load' in summary, "Summary should contain current load"
            assert 'ramping_profile' in summary, "Summary should contain ramping profile"
            
        except Exception as e:
            logger.error(f"Adaptive ramping test failed: {e}")
            raise
    
    async def test_cycle_manager(self):
        """Test cycle manager functionality"""
        logger.info("Testing cycle manager...")
        
        # Create config file
        config_file = os.path.join(self.temp_dir, "test_config.yaml")
        with open(config_file, 'w') as f:
            f.write("""
phases:
  - phase: 0
    min_load_percent: 0.0
    max_load_percent: 5.0
    duration_seconds: 2
    ramp_up_seconds: 1
    ramp_down_seconds: 1
    cpu_weight: 0.5
    memory_weight: 0.3
    io_weight: 0.2
    network_weight: 0.1
    safety_thresholds:
      cpu_usage: 50.0
      memory_usage: 60.0
    adaptive_enabled: true
""")
        
        cycle_manager = StressCycleManager(config_file)
        
        try:
            # Test status
            status = cycle_manager.get_status()
            assert status.state == CycleState.STOPPED, "Initial state should be STOPPED"
            
            # Test starting with specific phases
            phases = [StressPhase.IDLE]
            success = await cycle_manager.start_cycle(phases)
            assert success, "Cycle should start successfully"
            
            # Wait for completion (short test cycle)
            timeout = 30  # 30 second timeout
            start_time = time.time()
            
            while cycle_manager.is_running() and (time.time() - start_time) < timeout:
                await asyncio.sleep(0.5)
            
            if cycle_manager.is_running():
                await cycle_manager.stop_cycle()
            
            # Check history
            history = cycle_manager.get_cycle_history()
            assert len(history) > 0, "Should have cycle history"
            
        except Exception as e:
            logger.error(f"Cycle manager test failed: {e}")
            # Ensure cleanup
            if cycle_manager.is_running():
                await cycle_manager.stop_cycle(emergency=True)
            raise
    
    async def test_integration(self):
        """Test integration between components"""
        logger.info("Testing component integration...")
        
        # Create minimal integration test
        config = LoadConfiguration(
            cpu_cores=1,
            memory_limit_gb=0.05,
            io_operations_per_second=5,
            network_bandwidth_mbps=0.5
        )
        
        load_controller = LoadController(config)
        safety_manager = SafetyManager()
        metrics_collector = MetricsCollector(collection_interval=0.2)
        
        try:
            # Initialize all components
            await load_controller.initialize()
            await safety_manager.initialize()
            await metrics_collector.start_collection()
            
            # Test coordinated operation
            await load_controller.set_cpu_load(10.0)
            
            # Let it run briefly
            await asyncio.sleep(2.0)
            
            # Check that everything is working
            loads = load_controller.get_current_loads()
            safety_status = safety_manager.get_current_status()
            metrics = await metrics_collector.collect_metrics()
            
            assert loads['cpu'] == 10.0, "Load should be set"
            assert safety_status['initialized'], "Safety should be initialized"
            assert 'current_snapshot' in metrics, "Metrics should be collected"
            
            # Clean shutdown
            await load_controller.stop_all_loads()
            
        finally:
            await load_controller.cleanup()
            await safety_manager.shutdown()
            await metrics_collector.stop_collection()
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*60)
        print("STRESS TESTING FRAMEWORK TEST RESULTS")
        print("="*60)
        
        passed = sum(1 for result in self.test_results.values() if result == "PASSED")
        total = len(self.test_results)
        
        print(f"Tests Passed: {passed}/{total}")
        print()
        
        for test_name, result in self.test_results.items():
            status = "✓" if result == "PASSED" else "✗"
            print(f"{status} {test_name}: {result}")
        
        print("="*60)
        
        if passed == total:
            print("🎉 ALL TESTS PASSED! Framework is ready for use.")
        else:
            print("❌ Some tests failed. Please check the logs above.")
        
        print("="*60 + "\n")


async def main():
    """Main test function"""
    tester = FrameworkTester()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())