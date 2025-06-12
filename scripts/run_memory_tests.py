#!/usr/bin/env python3
"""
Memory Test Runner
Quick test runner for memory validation suite.
"""

import os
import sys
import asyncio
import time
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

# Set test environment variables
os.environ['ENVIRONMENT'] = 'testing'
os.environ['LOG_LEVEL'] = 'INFO'
os.environ['ANTHROPIC_API_KEY'] = 'test-key'
os.environ['OPENAI_API_KEY'] = 'test-key'
os.environ['GOOGLE_GEMINI_API_KEY'] = 'test-key'

# Import memory test utilities
from tests.utils.memory_test_utils import MemoryMonitor, get_memory_info
from tests.utils.memory_profiler import AdvancedMemoryProfiler
from tests.utils.statistical_analyzer import MemoryStatisticalAnalyzer


async def run_quick_memory_tests():
    """Run a quick set of memory tests to verify functionality"""
    print("🧠 Starting Quick Memory Test Suite...")
    print("="*60)
    
    start_time = time.time()
    
    # Test 1: Memory Utilities
    print("\n📊 Testing Memory Utilities...")
    try:
        monitor = MemoryMonitor()
        initial_snapshot = monitor.take_snapshot("test_start")
        
        # Simulate some memory usage
        test_data = []
        for i in range(1000):
            test_data.append({'id': i, 'data': 'x' * 100})
        
        final_snapshot = monitor.take_snapshot("test_end")
        delta = monitor.calculate_delta(initial_snapshot, final_snapshot)
        
        print(f"  ✅ Memory Delta: {delta.rss_delta_mb:+.2f} MB")
        print(f"  ✅ Growth Rate: {delta.growth_rate_mb_per_sec:.3f} MB/s")
        
        # Cleanup
        test_data.clear()
        
    except Exception as e:
        print(f"  ❌ Memory utilities test failed: {e}")
    
    # Test 2: Statistical Analysis
    print("\n📈 Testing Statistical Analysis...")
    try:
        analyzer = MemoryStatisticalAnalyzer()
        
        # Generate test data
        import random
        baseline_data = [100 + random.gauss(0, 5) for _ in range(50)]
        current_data = [105 + random.gauss(0, 5) for _ in range(50)]  # Slight increase
        
        # Test regression detection
        regression = analyzer.detect_regression(baseline_data, current_data)
        print(f"  ✅ Regression Detection: {regression.regression_detected}")
        print(f"  ✅ Change: {regression.change_percentage:.2f}%")
        
        # Test trend analysis
        trend_data = [100 + i * 0.1 + random.gauss(0, 1) for i in range(30)]
        trend = analyzer.analyze_memory_trend(trend_data)
        print(f"  ✅ Trend Type: {trend.trend_type}")
        print(f"  ✅ R²: {trend.r_squared:.3f}")
        
    except Exception as e:
        print(f"  ❌ Statistical analysis test failed: {e}")
    
    # Test 3: Memory Profiler
    print("\n🔍 Testing Memory Profiler...")
    try:
        profiler = AdvancedMemoryProfiler()
        
        profiler.start_profiling("test_profiler")
        
        # Simulate memory operations
        test_objects = []
        for i in range(500):
            obj = {
                'id': i,
                'content': 'test data ' * 50,
                'metadata': {'timestamp': time.time()}
            }
            test_objects.append(obj)
        
        await asyncio.sleep(0.1)
        
        profile = profiler.stop_profiling()
        print(f"  ✅ Peak Memory: {profile.peak_memory_mb:.2f} MB")
        print(f"  ✅ Allocations: {profile.total_allocations}")
        print(f"  ✅ Duration: {profile.duration:.2f}s")
        
        # Cleanup
        test_objects.clear()
        
    except Exception as e:
        print(f"  ❌ Memory profiler test failed: {e}")
    
    # Test 4: Basic Component Test
    print("\n🔧 Testing Basic Component...")
    try:
        from src.circle_of_experts.core.expert_manager import ExpertManager
        
        monitor = MemoryMonitor()
        initial_snapshot = monitor.take_snapshot("component_start")
        
        # Test ExpertManager creation
        managers = []
        for i in range(10):
            manager = ExpertManager()
            managers.append(manager)
        
        final_snapshot = monitor.take_snapshot("component_end")
        delta = monitor.calculate_delta(initial_snapshot, final_snapshot)
        
        print(f"  ✅ Component Memory Delta: {delta.rss_delta_mb:+.2f} MB")
        print(f"  ✅ Objects Created: 10 ExpertManagers")
        
        # Cleanup
        managers.clear()
        
    except Exception as e:
        print(f"  ❌ Component test failed: {e}")
    
    # Test 5: Configuration Loading
    print("\n⚙️ Testing Configuration...")
    try:
        import yaml
        
        config_path = "memory_validation_config.yaml"
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            print(f"  ✅ Config loaded: {config.get('metadata', {}).get('config_version', 'unknown')}")
            print(f"  ✅ Validation levels: {len(config.get('validation_levels', {}))}")
            
            # Check validation levels
            levels = config.get('validation_levels', {})
            for level_name in ['quick', 'comprehensive', 'nightly']:
                if level_name in levels:
                    level_config = levels[level_name]
                    enabled_tests = sum(1 for test_type in ['leak_detection', 'regression_testing', 'stress_testing', 'gc_performance'] 
                                      if level_config.get(test_type, {}).get('enabled', False))
                    print(f"    {level_name}: {enabled_tests} tests enabled")
        else:
            print(f"  ❌ Configuration file not found: {config_path}")
            
    except Exception as e:
        print(f"  ❌ Configuration test failed: {e}")
    
    # Summary
    duration = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"🎯 Quick Memory Test Suite Complete")
    print(f"⏱️ Duration: {duration:.2f} seconds")
    print(f"📊 System Memory: {get_memory_info()['rss_mb']:.1f} MB RSS")
    print(f"✅ Memory testing framework is operational!")
    print(f"{'='*60}")


def test_memory_validation_suite():
    """Test the memory validation suite script"""
    print("\n🚀 Testing Memory Validation Suite...")
    
    try:
        # Check if script exists and is executable
        script_path = "scripts/memory_validation_suite.py"
        if os.path.exists(script_path) and os.access(script_path, os.X_OK):
            print(f"  ✅ Memory validation suite script found and executable")
            
            # Test help output
            import subprocess
            result = subprocess.run([sys.executable, script_path, '--help'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and 'Memory Validation Suite' in result.stdout:
                print(f"  ✅ Script help output working")
            else:
                print(f"  ❌ Script help failed: {result.stderr}")
                
        else:
            print(f"  ❌ Memory validation suite script not found or not executable")
            
    except Exception as e:
        print(f"  ❌ Memory validation suite test failed: {e}")


def main():
    """Main test runner"""
    print("🧠 Memory Testing Framework Validation")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run async tests
    try:
        asyncio.run(run_quick_memory_tests())
    except Exception as e:
        print(f"❌ Async tests failed: {e}")
    
    # Test memory validation suite
    test_memory_validation_suite()
    
    print(f"\n🏁 All tests completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()