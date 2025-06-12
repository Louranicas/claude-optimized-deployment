"""
Garbage Collection Performance Validation
Ensures GC behavior doesn't regress with optimizations.
"""

import pytest
import asyncio
import gc
import time
import statistics
import json
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Callable, Optional, Tuple
from pathlib import Path
import sys
import os
import weakref
from collections import defaultdict
import threading

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.circle_of_experts.core.expert_manager import ExpertManager
from src.circle_of_experts.models.query import ExpertQuery, QueryType, QueryPriority
from src.circle_of_experts.models.response import ExpertResponse
from src.mcp.manager import get_mcp_manager
from src.circle_of_experts.core.rust_accelerated import (
    ExpertAnalyzer,
    ConsensusEngine,
    ResponseAggregator
)


@dataclass
class GCPerformanceMetrics:
    """Garbage collection performance metrics"""
    test_name: str
    component_name: str
    total_operations: int
    test_duration_seconds: float
    gc_metrics: Dict[str, Any]
    gc_pause_times: List[float]
    generation_promotions: Dict[int, int]
    object_lifecycle_stats: Dict[str, int]
    memory_reclaimed_mb: float
    gc_efficiency_score: float
    recommendations: List[str]


@dataclass
class GCEvent:
    """Single garbage collection event"""
    timestamp: float
    generation: int
    objects_before: int
    objects_after: int
    objects_collected: int
    pause_time_ms: float


class GCPerformanceValidator:
    """Validate garbage collection performance"""
    
    def __init__(self):
        self.gc_thresholds = {
            'gen0_collections_per_100_ops': 50,
            'gen1_collections_per_1000_ops': 10,
            'gen2_collections_per_10000_ops': 2,
            'max_gc_pause_ms': 100,
            'min_efficiency_score': 0.7
        }
        self.gc_events = []
        self.object_refs = []
        self.monitoring_active = False
        
    def start_gc_monitoring(self):
        """Start monitoring garbage collection events"""
        self.gc_events = []
        self.object_refs = []
        self.monitoring_active = True
        
        # Enable detailed GC stats
        gc.set_debug(gc.DEBUG_STATS)
        
    def stop_gc_monitoring(self):
        """Stop monitoring garbage collection events"""
        self.monitoring_active = False
        gc.set_debug(0)
        
    def capture_gc_event(self, generation: int = -1) -> GCEvent:
        """Capture a garbage collection event"""
        timestamp = time.time()
        
        # Get object counts before GC
        objects_before = len(gc.get_objects())
        
        # Measure GC pause time
        start_time = time.perf_counter()
        
        if generation >= 0:
            # Force collection of specific generation
            collected = gc.collect(generation)
        else:
            # Full collection
            collected = gc.collect()
            
        pause_time = (time.perf_counter() - start_time) * 1000  # Convert to ms
        
        # Get object counts after GC
        objects_after = len(gc.get_objects())
        
        event = GCEvent(
            timestamp=timestamp,
            generation=generation if generation >= 0 else 2,  # Assume full collection
            objects_before=objects_before,
            objects_after=objects_after,
            objects_collected=collected,
            pause_time_ms=pause_time
        )
        
        if self.monitoring_active:
            self.gc_events.append(event)
            
        return event
    
    async def test_gc_frequency(
        self, 
        operation_func: Callable,
        iterations: int = 1000,
        component_name: str = "unknown"
    ) -> GCPerformanceMetrics:
        """Test garbage collection frequency during operations"""
        
        print(f"\n🗑️ Testing GC Frequency for {component_name}...")
        
        self.start_gc_monitoring()
        
        # Initial state
        initial_gc_counts = list(gc.get_count())
        start_time = time.time()
        
        # Run operations and monitor GC
        pause_times = []
        
        for i in range(iterations):
            # Execute operation
            if asyncio.iscoroutinefunction(operation_func):
                await operation_func()
            else:
                operation_func()
            
            # Periodic GC monitoring
            if i % 100 == 0:
                event = self.capture_gc_event()
                pause_times.append(event.pause_time_ms)
                
                print(f"  Iteration {i}: GC pause {event.pause_time_ms:.2f}ms, "
                      f"objects collected: {event.objects_collected}")
        
        # Final measurements
        final_gc_counts = list(gc.get_count())
        test_duration = time.time() - start_time
        
        self.stop_gc_monitoring()
        
        # Calculate metrics
        gc_deltas = [
            final_gc_counts[i] - initial_gc_counts[i] 
            for i in range(len(initial_gc_counts))
        ]
        
        # Analyze generation promotions
        generation_promotions = self._analyze_generation_promotions()
        
        # Calculate efficiency score
        efficiency_score = self._calculate_gc_efficiency(pause_times, gc_deltas, iterations)
        
        # Object lifecycle analysis
        object_lifecycle_stats = self._analyze_object_lifecycle()
        
        # Memory reclamation estimation
        memory_reclaimed = sum(event.objects_collected for event in self.gc_events) * 0.001  # Rough estimate
        
        # Generate recommendations
        recommendations = self._generate_gc_recommendations(
            pause_times, gc_deltas, efficiency_score, iterations
        )
        
        metrics = GCPerformanceMetrics(
            test_name=f"gc_frequency_{component_name}",
            component_name=component_name,
            total_operations=iterations,
            test_duration_seconds=test_duration,
            gc_metrics={
                'initial_counts': initial_gc_counts,
                'final_counts': final_gc_counts,
                'deltas': gc_deltas,
                'total_collections': sum(gc_deltas),
                'collections_per_100_ops': [
                    (delta / iterations) * 100 for delta in gc_deltas
                ]
            },
            gc_pause_times=pause_times,
            generation_promotions=generation_promotions,
            object_lifecycle_stats=object_lifecycle_stats,
            memory_reclaimed_mb=memory_reclaimed,
            gc_efficiency_score=efficiency_score,
            recommendations=recommendations
        )
        
        self._print_gc_metrics(metrics)
        return metrics
    
    async def test_gc_pause_times(
        self, 
        operation_func: Callable,
        component_name: str = "unknown"
    ) -> GCPerformanceMetrics:
        """Measure GC pause times during operations"""
        
        print(f"\n⏱️ Testing GC Pause Times for {component_name}...")
        
        self.start_gc_monitoring()
        start_time = time.time()
        
        # Create memory pressure to trigger GC
        memory_objects = []
        pause_times = []
        
        try:
            for i in range(100):
                # Create objects to trigger GC
                large_object = {
                    'id': i,
                    'data': 'x' * 10000,  # 10KB
                    'nested': [{'item': j} for j in range(100)]
                }
                memory_objects.append(large_object)
                
                # Execute operation
                if asyncio.iscoroutinefunction(operation_func):
                    await operation_func()
                else:
                    operation_func()
                
                # Trigger and measure GC pause
                if i % 10 == 0:
                    for generation in range(3):
                        event = self.capture_gc_event(generation)
                        pause_times.append(event.pause_time_ms)
                        
                        print(f"  Gen {generation} GC: {event.pause_time_ms:.2f}ms, "
                              f"collected: {event.objects_collected}")
        
        finally:
            # Cleanup
            memory_objects.clear()
            test_duration = time.time() - start_time
            self.stop_gc_monitoring()
        
        # Calculate metrics
        efficiency_score = self._calculate_pause_efficiency(pause_times)
        
        metrics = GCPerformanceMetrics(
            test_name=f"gc_pause_times_{component_name}",
            component_name=component_name,
            total_operations=100,
            test_duration_seconds=test_duration,
            gc_metrics={
                'avg_pause_time_ms': statistics.mean(pause_times) if pause_times else 0,
                'max_pause_time_ms': max(pause_times) if pause_times else 0,
                'min_pause_time_ms': min(pause_times) if pause_times else 0,
                'p95_pause_time_ms': sorted(pause_times)[int(len(pause_times) * 0.95)] if pause_times else 0,
                'total_pause_time_ms': sum(pause_times)
            },
            gc_pause_times=pause_times,
            generation_promotions=self._analyze_generation_promotions(),
            object_lifecycle_stats=self._analyze_object_lifecycle(),
            memory_reclaimed_mb=0,  # Not measured in this test
            gc_efficiency_score=efficiency_score,
            recommendations=self._generate_pause_recommendations(pause_times)
        )
        
        self._print_gc_metrics(metrics)
        return metrics
    
    def validate_gc_efficiency(self, gc_metrics: GCPerformanceMetrics) -> bool:
        """Validate GC efficiency against thresholds"""
        
        print(f"\n✅ Validating GC Efficiency for {gc_metrics.component_name}...")
        
        validation_results = {}
        all_passed = True
        
        # Check collection frequency
        if gc_metrics.total_operations >= 100:
            gen0_rate = (gc_metrics.gc_metrics.get('deltas', [0])[0] / gc_metrics.total_operations) * 100
            validation_results['gen0_frequency'] = gen0_rate <= self.gc_thresholds['gen0_collections_per_100_ops']
            
            if not validation_results['gen0_frequency']:
                all_passed = False
                print(f"  ❌ Gen0 GC frequency too high: {gen0_rate:.1f} (threshold: {self.gc_thresholds['gen0_collections_per_100_ops']})")
        
        # Check pause times
        if gc_metrics.gc_pause_times:
            max_pause = max(gc_metrics.gc_pause_times)
            validation_results['max_pause_time'] = max_pause <= self.gc_thresholds['max_gc_pause_ms']
            
            if not validation_results['max_pause_time']:
                all_passed = False
                print(f"  ❌ GC pause time too high: {max_pause:.2f}ms (threshold: {self.gc_thresholds['max_gc_pause_ms']}ms)")
        
        # Check efficiency score
        validation_results['efficiency_score'] = gc_metrics.gc_efficiency_score >= self.gc_thresholds['min_efficiency_score']
        
        if not validation_results['efficiency_score']:
            all_passed = False
            print(f"  ❌ GC efficiency too low: {gc_metrics.gc_efficiency_score:.2f} (threshold: {self.gc_thresholds['min_efficiency_score']})")
        
        if all_passed:
            print("  ✅ All GC efficiency checks passed")
        
        return all_passed
    
    # Helper methods
    
    def _analyze_generation_promotions(self) -> Dict[int, int]:
        """Analyze object promotions between GC generations"""
        promotions = defaultdict(int)
        
        # Simplified promotion analysis based on GC events
        for event in self.gc_events:
            if event.generation < 2:  # Objects promoted to next generation
                promotions[event.generation] += max(0, event.objects_before - event.objects_after - event.objects_collected)
        
        return dict(promotions)
    
    def _analyze_object_lifecycle(self) -> Dict[str, int]:
        """Analyze object lifecycle statistics"""
        return {
            'total_objects_created': sum(event.objects_before for event in self.gc_events),
            'total_objects_collected': sum(event.objects_collected for event in self.gc_events),
            'peak_objects': max((event.objects_before for event in self.gc_events), default=0),
            'avg_objects': int(statistics.mean([event.objects_after for event in self.gc_events])) if self.gc_events else 0
        }
    
    def _calculate_gc_efficiency(
        self, 
        pause_times: List[float], 
        gc_deltas: List[int], 
        operations: int
    ) -> float:
        """Calculate GC efficiency score (0-1, higher is better)"""
        
        # Frequency efficiency (fewer collections is better)
        total_collections = sum(gc_deltas)
        if operations > 0:
            frequency_score = max(0, 1 - (total_collections / operations))
        else:
            frequency_score = 1.0
        
        # Pause time efficiency (shorter pauses are better)
        if pause_times:
            avg_pause = statistics.mean(pause_times)
            pause_score = max(0, 1 - (avg_pause / self.gc_thresholds['max_gc_pause_ms']))
        else:
            pause_score = 1.0
        
        # Combined score
        return (frequency_score + pause_score) / 2
    
    def _calculate_pause_efficiency(self, pause_times: List[float]) -> float:
        """Calculate pause time efficiency"""
        if not pause_times:
            return 1.0
        
        avg_pause = statistics.mean(pause_times)
        max_pause = max(pause_times)
        
        # Efficiency based on average and max pause times
        avg_efficiency = max(0, 1 - (avg_pause / self.gc_thresholds['max_gc_pause_ms']))
        max_efficiency = max(0, 1 - (max_pause / (self.gc_thresholds['max_gc_pause_ms'] * 2)))
        
        return (avg_efficiency + max_efficiency) / 2
    
    def _generate_gc_recommendations(
        self, 
        pause_times: List[float], 
        gc_deltas: List[int], 
        efficiency_score: float,
        iterations: int
    ) -> List[str]:
        """Generate GC performance recommendations"""
        recommendations = []
        
        # Frequency recommendations
        if iterations > 0:
            gen0_rate = (gc_deltas[0] / iterations) * 100 if gc_deltas else 0
            
            if gen0_rate > self.gc_thresholds['gen0_collections_per_100_ops']:
                recommendations.append(f"High Gen0 GC frequency ({gen0_rate:.1f}/100 ops) - consider object pooling")
        
        # Pause time recommendations
        if pause_times:
            avg_pause = statistics.mean(pause_times)
            max_pause = max(pause_times)
            
            if max_pause > self.gc_thresholds['max_gc_pause_ms']:
                recommendations.append(f"Long GC pauses detected ({max_pause:.2f}ms) - consider incremental GC tuning")
            
            if avg_pause > self.gc_thresholds['max_gc_pause_ms'] * 0.5:
                recommendations.append("Consistent GC pauses - review object allocation patterns")
        
        # Efficiency recommendations
        if efficiency_score < self.gc_thresholds['min_efficiency_score']:
            recommendations.append("Low GC efficiency - consider memory usage optimization")
        
        if not recommendations:
            recommendations.append("GC performance is within acceptable thresholds")
        
        return recommendations
    
    def _generate_pause_recommendations(self, pause_times: List[float]) -> List[str]:
        """Generate pause time specific recommendations"""
        recommendations = []
        
        if not pause_times:
            return ["No GC pause data available"]
        
        avg_pause = statistics.mean(pause_times)
        max_pause = max(pause_times)
        
        if max_pause > 100:  # >100ms
            recommendations.append("Very long GC pauses detected - consider concurrent GC settings")
        elif max_pause > 50:  # >50ms
            recommendations.append("Long GC pauses detected - review large object allocation")
        
        if avg_pause > 20:  # >20ms average
            recommendations.append("High average GC pause time - optimize object lifecycle")
        
        # Check for variance in pause times
        if len(pause_times) > 1:
            stdev = statistics.stdev(pause_times)
            if stdev > avg_pause * 0.5:  # High variance
                recommendations.append("High variance in GC pause times - investigate allocation patterns")
        
        if not recommendations:
            recommendations.append("GC pause times are well optimized")
        
        return recommendations
    
    def _print_gc_metrics(self, metrics: GCPerformanceMetrics):
        """Print GC metrics summary"""
        print(f"\n📊 GC Performance Metrics for {metrics.component_name}:")
        print(f"   Test: {metrics.test_name}")
        print(f"   Operations: {metrics.total_operations}")
        print(f"   Duration: {metrics.test_duration_seconds:.2f}s")
        print(f"   Efficiency Score: {metrics.gc_efficiency_score:.2f}")
        
        if metrics.gc_pause_times:
            print(f"   Avg Pause Time: {statistics.mean(metrics.gc_pause_times):.2f}ms")
            print(f"   Max Pause Time: {max(metrics.gc_pause_times):.2f}ms")
        
        if 'total_collections' in metrics.gc_metrics:
            print(f"   Total GC Collections: {metrics.gc_metrics['total_collections']}")
        
        print("   Recommendations:")
        for rec in metrics.recommendations:
            print(f"     - {rec}")


# Test implementations
class TestGCPerformance:
    """GC performance test suite"""
    
    def __init__(self):
        self.gc_validator = GCPerformanceValidator()
    
    @pytest.mark.memory_gc
    async def test_expert_manager_gc_performance(self):
        """Test ExpertManager GC performance"""
        
        async def expert_manager_operation():
            manager = ExpertManager()
            
            # Create query objects
            query = ExpertQuery(
                title="GC test query",
                content="Testing garbage collection performance",
                query_type=QueryType.TECHNICAL,
                priority=QueryPriority.MEDIUM,
                requester="gc_test@test.com"
            )
            
            # Simulate processing
            await asyncio.sleep(0.001)
        
        # Test GC frequency
        metrics = await self.gc_validator.test_gc_frequency(
            expert_manager_operation,
            iterations=500,
            component_name="ExpertManager"
        )
        
        # Validate efficiency
        is_efficient = self.gc_validator.validate_gc_efficiency(metrics)
        
        # Assertions
        assert is_efficient, f"ExpertManager GC efficiency below threshold: {metrics.recommendations}"
        assert metrics.gc_efficiency_score >= 0.6, f"Low GC efficiency: {metrics.gc_efficiency_score}"
        
        return metrics
    
    @pytest.mark.memory_gc
    async def test_rust_modules_gc_performance(self):
        """Test Rust modules GC performance"""
        
        def rust_operation():
            # Rust modules should have minimal GC impact
            analyzer = ExpertAnalyzer()
            
            responses = []
            for i in range(20):
                response = ExpertResponse(
                    expert_type=f"expert_{i}",
                    content="GC test content",
                    confidence=0.9,
                    response_time=1.0,
                    model_used="gc_test",
                    cost_estimate=0.001
                )
                responses.append(response)
            
            analyzer.analyze_responses(responses)
        
        # Test GC frequency
        metrics = await self.gc_validator.test_gc_frequency(
            rust_operation,
            iterations=200,
            component_name="RustModules"
        )
        
        # Rust modules should have excellent GC performance
        is_efficient = self.gc_validator.validate_gc_efficiency(metrics)
        
        # Assertions
        assert is_efficient, f"Rust modules GC efficiency below threshold: {metrics.recommendations}"
        assert metrics.gc_efficiency_score >= 0.8, f"Rust modules should have high GC efficiency: {metrics.gc_efficiency_score}"
        
        return metrics
    
    @pytest.mark.memory_gc
    async def test_mcp_tools_gc_performance(self):
        """Test MCP tools GC performance"""
        
        async def mcp_operation():
            manager = get_mcp_manager()
            
            try:
                await manager.call_tool("desktop.execute_command", {"command": "echo 'gc test'"})
            except:
                pass  # Ignore errors for GC testing
        
        # Test GC pause times (fewer iterations for network operations)
        metrics = await self.gc_validator.test_gc_pause_times(
            mcp_operation,
            component_name="MCPTools"
        )
        
        # Validate efficiency
        is_efficient = self.gc_validator.validate_gc_efficiency(metrics)
        
        # MCP tools may have variable GC performance due to I/O
        assert metrics.gc_efficiency_score >= 0.5, f"MCP tools GC efficiency too low: {metrics.gc_efficiency_score}"
        
        return metrics
    
    @pytest.mark.memory_gc
    async def test_response_aggregation_gc_performance(self):
        """Test response aggregation GC performance"""
        
        def aggregation_operation():
            aggregator = ResponseAggregator()
            
            # Create many response objects
            responses = []
            for i in range(100):
                response = ExpertResponse(
                    expert_type=f"expert_{i % 10}",
                    content=f"Aggregation test content {i}",
                    confidence=0.8,
                    response_time=1.0,
                    model_used="gc_test",
                    cost_estimate=0.001
                )
                responses.append(response)
            
            aggregator.aggregate_responses(responses)
        
        # Test GC frequency
        metrics = await self.gc_validator.test_gc_frequency(
            aggregation_operation,
            iterations=100,
            component_name="ResponseAggregation"
        )
        
        # Validate efficiency
        is_efficient = self.gc_validator.validate_gc_efficiency(metrics)
        
        # Assertions
        assert metrics.gc_efficiency_score >= 0.6, f"Response aggregation GC efficiency too low: {metrics.gc_efficiency_score}"
        
        return metrics
    
    @pytest.mark.memory_gc_comprehensive
    async def test_comprehensive_gc_performance(self):
        """Run comprehensive GC performance testing"""
        
        print("\n🗑️ Running Comprehensive GC Performance Testing...")
        
        # Test all components
        results = []
        
        results.append(await self.test_expert_manager_gc_performance())
        results.append(await self.test_rust_modules_gc_performance())
        results.append(await self.test_mcp_tools_gc_performance())
        results.append(await self.test_response_aggregation_gc_performance())
        
        # Generate comprehensive report
        report = self._generate_gc_report(results)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"tests/memory/gc_performance_report_{timestamp}.md"
        
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, 'w') as f:
            f.write(report)
        
        # Save detailed results
        results_data = [asdict(r) for r in results]
        results_path = f"tests/memory/gc_performance_results_{timestamp}.json"
        with open(results_path, 'w') as f:
            json.dump(results_data, f, indent=2, default=str)
        
        print(f"\n✅ Comprehensive GC performance testing complete!")
        print(f"📄 Report: {report_path}")
        print(f"📊 Results: {results_path}")
        
        # Overall assertions
        avg_efficiency = sum(r.gc_efficiency_score for r in results) / len(results)
        assert avg_efficiency >= 0.6, f"Overall GC efficiency too low: {avg_efficiency:.2f}"
        
        return results
    
    def _generate_gc_report(self, results: List[GCPerformanceMetrics]) -> str:
        """Generate comprehensive GC performance report"""
        report = []
        report.append("# Garbage Collection Performance Report")
        report.append(f"Generated: {datetime.now().isoformat()}")
        
        # Summary
        report.append("\n## Executive Summary")
        total_tests = len(results)
        avg_efficiency = sum(r.gc_efficiency_score for r in results) / len(results)
        efficient_components = sum(1 for r in results if r.gc_efficiency_score >= 0.7)
        
        report.append(f"- **Total Components Tested**: {total_tests}")
        report.append(f"- **Average GC Efficiency**: {avg_efficiency:.2f}")
        report.append(f"- **Efficient Components**: {efficient_components}/{total_tests}")
        
        if avg_efficiency >= 0.8:
            report.append("\n✅ **EXCELLENT**: GC performance is highly optimized")
        elif avg_efficiency >= 0.6:
            report.append("\n✅ **GOOD**: GC performance is acceptable")
        else:
            report.append("\n⚠️ **NEEDS IMPROVEMENT**: GC performance optimization required")
        
        # Detailed results
        report.append("\n## Component Analysis")
        
        for result in sorted(results, key=lambda x: x.gc_efficiency_score, reverse=True):
            report.append(f"\n### {result.component_name}")
            report.append(f"- **Efficiency Score**: {result.gc_efficiency_score:.2f}")
            report.append(f"- **Total Operations**: {result.total_operations}")
            report.append(f"- **Test Duration**: {result.test_duration_seconds:.2f}s")
            
            if result.gc_pause_times:
                avg_pause = statistics.mean(result.gc_pause_times)
                max_pause = max(result.gc_pause_times)
                report.append(f"- **Average GC Pause**: {avg_pause:.2f}ms")
                report.append(f"- **Maximum GC Pause**: {max_pause:.2f}ms")
            
            if 'total_collections' in result.gc_metrics:
                total_collections = result.gc_metrics['total_collections']
                collections_per_op = total_collections / result.total_operations if result.total_operations > 0 else 0
                report.append(f"- **Total GC Collections**: {total_collections}")
                report.append(f"- **Collections per Operation**: {collections_per_op:.3f}")
            
            report.append("- **Recommendations**:")
            for rec in result.recommendations:
                report.append(f"  - {rec}")
        
        # Best practices
        report.append("\n## GC Optimization Best Practices")
        report.append("1. **Object Pooling**: Reuse objects instead of frequent allocation/deallocation")
        report.append("2. **Lazy Initialization**: Create objects only when needed")
        report.append("3. **Weak References**: Use weak references for caches and observers")
        report.append("4. **Batch Processing**: Process data in batches to reduce GC pressure")
        report.append("5. **Memory Profiling**: Regular profiling to identify allocation hotspots")
        
        return "\n".join(report)


async def run_gc_performance_testing():
    """Run GC performance testing suite"""
    tester = TestGCPerformance()
    return await tester.test_comprehensive_gc_performance()


if __name__ == "__main__":
    # Run GC performance testing
    asyncio.run(run_gc_performance_testing())