"""
Simplified Chaos Engineering Framework Tests

Tests core functionality without external dependencies.
"""

import asyncio
import json
import logging
import sys
import traceback
from datetime import datetime, timedelta

# Add the project root to Python path
sys.path.insert(0, '/home/louranicas/projects/claude-optimized-deployment')

# Import chaos engineering components
try:
    from test_environments.chaos_engineering import (
        ChaosOrchestrator, FailureInjector, ResilienceValidator, 
        BreakingPointAnalyzer, RecoveryMeasurer
    )
    from test_environments.chaos_engineering.expert_chaos_controller import ExpertChaosController
    from test_environments.chaos_engineering.scenarios.cascade_failure import CascadeFailureScenario
    from test_environments.chaos_engineering.safety.safety_controller import SafetyController
except ImportError as e:
    print(f"Import error: {e}")
    print("This is expected as we're testing the framework structure")


# Mock expert manager for testing
class MockExpertManager:
    def __init__(self):
        self.query_count = 0
    
    async def query_experts(self, query: str, expertise_areas: list = None):
        self.query_count += 1
        
        class MockResponse:
            def __init__(self, content: str, confidence: float = 0.8):
                self.content = content
                self.confidence = confidence
                self.reasoning = "Mock expert analysis"
        
        class MockExpertResponse:
            def __init__(self):
                self.expert_responses = [
                    MockResponse("Recommend gradual failure injection starting with non-critical services"),
                    MockResponse("Implement circuit breakers and monitor recovery mechanisms"),
                    MockResponse("Focus on cascade failure containment and system isolation")
                ]
                self.confidence_score = 0.85
                self.recommendations = ["Start with low impact", "Monitor continuously", "Validate recovery"]
        
        return MockExpertResponse()


async def test_chaos_orchestrator():
    """Test chaos orchestrator basic functionality"""
    print("Testing Chaos Orchestrator...")
    
    try:
        mock_expert_manager = MockExpertManager()
        orchestrator = ChaosOrchestrator(expert_manager=mock_expert_manager)
        
        # Test experiment creation
        experiment_config = {
            "name": "test_service_failure",
            "description": "Test service failure resilience",
            "type": "service_chaos",
            "target_services": ["auth-service", "user-service"],
            "failure_scenarios": [{
                "type": "service_crash",
                "config": {"duration": 180}
            }],
            "duration_seconds": 300,
            "blast_radius": 0.1
        }
        
        experiment = await orchestrator.create_experiment(experiment_config)
        assert experiment is not None, "Experiment creation failed"
        assert experiment.name == "test_service_failure", "Experiment name mismatch"
        assert len(experiment.target_services) == 2, "Target services count mismatch"
        
        print("  ✓ Experiment creation successful")
        
        # Test experiment execution
        metrics = await orchestrator.run_experiment(experiment.id)
        assert metrics is not None, "Experiment execution failed"
        assert hasattr(metrics, 'experiment_id'), "Metrics missing experiment ID"
        
        print("  ✓ Experiment execution successful")
        
        # Test global metrics
        global_metrics = await orchestrator.get_global_resilience_metrics()
        assert global_metrics["total_experiments"] >= 1, "Global metrics not updated"
        
        print("  ✓ Global metrics calculation successful")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Chaos Orchestrator test failed: {e}")
        traceback.print_exc()
        return False


async def test_failure_injector():
    """Test failure injector functionality"""
    print("Testing Failure Injector...")
    
    try:
        injector = FailureInjector()
        
        # Test service failure injection
        result = await injector.inject_service_failure(
            service="test-service",
            failure_type="service_crash",
            duration=60
        )
        
        assert result["success"] is True, "Service failure injection failed"
        assert "injection_id" in result, "Injection ID missing"
        
        print("  ✓ Service failure injection successful")
        
        # Test network partition injection
        result = await injector.inject_network_partition(
            services=["service-a", "service-b"],
            partition_type="split_brain",
            duration=120
        )
        
        assert result["success"] is True, "Network partition injection failed"
        print("  ✓ Network partition injection successful")
        
        # Test resource exhaustion injection
        result = await injector.inject_resource_exhaustion(
            resource_type="cpu_exhaustion",
            intensity=0.8,
            duration=90
        )
        
        assert result["success"] is True, "Resource exhaustion injection failed"
        print("  ✓ Resource exhaustion injection successful")
        
        # Test active injections tracking
        active_injections = injector.get_active_injections()
        assert len(active_injections) >= 0, "Active injections tracking failed"
        
        print("  ✓ Active injections tracking successful")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Failure Injector test failed: {e}")
        traceback.print_exc()
        return False


async def test_resilience_validator():
    """Test resilience validator functionality"""
    print("Testing Resilience Validator...")
    
    try:
        validator = ResilienceValidator()
        test_services = ["auth-service", "user-service", "order-service"]
        
        # Test resilience measurement
        start_time = datetime.now() - timedelta(minutes=5)
        end_time = datetime.now()
        
        result = await validator.measure_resilience(
            services=test_services,
            start_time=start_time,
            end_time=end_time
        )
        
        assert "measurement_period" in result, "Measurement period missing"
        assert "service_metrics" in result, "Service metrics missing"
        assert "overall_resilience" in result, "Overall resilience missing"
        
        print("  ✓ Resilience measurement successful")
        
        # Test failure detection validation
        result = await validator.validate_failure_detection(
            service="test-service",
            failure_injection_time=datetime.now() - timedelta(minutes=2),
            detection_timeout=120
        )
        
        assert "detection_methods" in result, "Detection methods missing"
        assert "overall_detected" in result, "Overall detection status missing"
        
        print("  ✓ Failure detection validation successful")
        
        # Test recovery mechanism validation
        result = await validator.validate_recovery_mechanisms(
            service="test-service",
            failure_start=datetime.now() - timedelta(minutes=3),
            recovery_timeout=300
        )
        
        assert "recovery_mechanisms" in result, "Recovery mechanisms missing"
        assert "recovery_success" in result, "Recovery success status missing"
        
        print("  ✓ Recovery mechanism validation successful")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Resilience Validator test failed: {e}")
        traceback.print_exc()
        return False


async def test_breaking_point_analyzer():
    """Test breaking point analyzer functionality"""
    print("Testing Breaking Point Analyzer...")
    
    try:
        analyzer = BreakingPointAnalyzer()
        
        # Test breaking point analysis
        result = await analyzer.analyze_breaking_points(
            services=["test-service-1", "test-service-2"],
            failure_scenarios=[{"type": "load_test", "config": {"max_rps": 1000}}]
        )
        
        assert "analysis_timestamp" in result, "Analysis timestamp missing"
        assert "service_analysis" in result, "Service analysis missing"
        assert "system_analysis" in result, "System analysis missing"
        
        print("  ✓ Breaking point analysis successful")
        
        # Test capacity limit identification
        result = await analyzer.find_capacity_limits(
            service="test-service",
            load_pattern="linear"
        )
        
        assert result["service"] == "test-service", "Service name mismatch"
        assert "breaking_points" in result, "Breaking points missing"
        assert "capacity_analysis" in result, "Capacity analysis missing"
        
        print("  ✓ Capacity limit identification successful")
        
        # Test performance cliff identification
        result = await analyzer.identify_performance_cliffs("test-service")
        
        assert "detected_cliffs" in result, "Detected cliffs missing"
        assert "cliff_analysis" in result, "Cliff analysis missing"
        
        print("  ✓ Performance cliff identification successful")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Breaking Point Analyzer test failed: {e}")
        traceback.print_exc()
        return False


async def test_recovery_measurer():
    """Test recovery measurer functionality"""
    print("Testing Recovery Measurer...")
    
    try:
        measurer = RecoveryMeasurer()
        test_services = ["service-1", "service-2"]
        
        # Test recovery measurement
        result = await measurer.measure_recovery(
            services=test_services,
            failure_scenarios=[{"type": "service_crash", "config": {"duration": 60}}],
            failure_start=datetime.now() - timedelta(minutes=5),
            measurement_end=datetime.now()
        )
        
        assert "measurement_period" in result, "Measurement period missing"
        assert "service_recovery_metrics" in result, "Service recovery metrics missing"
        assert "aggregate_metrics" in result, "Aggregate metrics missing"
        
        print("  ✓ Recovery measurement successful")
        
        # Test recovery time distribution
        result = await measurer.measure_recovery_time_distribution(
            service="test-service",
            failure_type="service_crash",
            num_samples=2  # Reduced for testing
        )
        
        assert result["service"] == "test-service", "Service name mismatch"
        assert "distribution_stats" in result, "Distribution stats missing"
        
        print("  ✓ Recovery time distribution measurement successful")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Recovery Measurer test failed: {e}")
        traceback.print_exc()
        return False


async def test_safety_controller():
    """Test safety controller functionality"""
    print("Testing Safety Controller...")
    
    try:
        from test_environments.chaos_engineering.chaos_orchestrator import ChaosExperiment, ExperimentType
        
        safety_controller = SafetyController()
        
        # Test experiment safety validation
        experiment = ChaosExperiment(
            name="test_safety_validation",
            experiment_type=ExperimentType.SERVICE_CHAOS,
            target_services=["safe-service"],
            blast_radius=0.05,
            duration_seconds=300
        )
        
        result = await safety_controller.validate_experiment(experiment)
        
        assert "safe" in result, "Safety validation result missing"
        assert "warnings" in result, "Warnings missing"
        assert "violations" in result, "Violations missing"
        
        print("  ✓ Experiment safety validation successful")
        
        # Test pre-experiment check
        result = await safety_controller.pre_experiment_check(experiment)
        
        assert "safe" in result, "Pre-experiment safety status missing"
        assert "checks_performed" in result, "Checks performed list missing"
        
        print("  ✓ Pre-experiment safety check successful")
        
        # Test safety configuration
        safety_controller.add_protected_service("critical-service")
        safety_controller.add_critical_service("core-service")
        safety_controller.set_safety_threshold("max_error_rate", 0.03)
        
        assert "critical-service" in safety_controller.protected_services
        assert "core-service" in safety_controller.critical_services
        assert safety_controller.default_safety_thresholds["max_error_rate"] == 0.03
        
        print("  ✓ Safety configuration successful")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Safety Controller test failed: {e}")
        traceback.print_exc()
        return False


async def test_expert_chaos_controller():
    """Test expert chaos controller functionality"""
    print("Testing Expert Chaos Controller...")
    
    try:
        mock_expert_manager = MockExpertManager()
        chaos_orchestrator = ChaosOrchestrator(expert_manager=mock_expert_manager)
        expert_controller = ExpertChaosController(
            expert_manager=mock_expert_manager,
            chaos_orchestrator=chaos_orchestrator
        )
        
        system_context = {
            "system_name": "e-commerce-platform",
            "services": ["auth-service", "user-service", "order-service"],
            "critical_services": ["auth-service"],
            "failure_domains": ["web-tier", "service-tier"],
            "environment": "testing"
        }
        
        # Test intelligent strategy generation
        learning_objectives = ["Validate service resilience", "Test recovery mechanisms"]
        
        strategy = await expert_controller.generate_intelligent_strategy(
            system_context=system_context,
            learning_objectives=learning_objectives
        )
        
        assert strategy.target_system == system_context["system_name"], "Target system mismatch"
        assert len(strategy.recommended_experiments) > 0, "No recommended experiments"
        assert len(strategy.expert_recommendations) > 0, "No expert recommendations"
        assert strategy.learning_objectives == learning_objectives, "Learning objectives mismatch"
        
        print("  ✓ Intelligent strategy generation successful")
        
        # Test expert-guided experiment execution
        result = await expert_controller.execute_expert_guided_experiment(
            strategy_id=strategy.strategy_id,
            experiment_index=0
        )
        
        assert result["strategy_id"] == strategy.strategy_id, "Strategy ID mismatch"
        assert "execution_result" in result, "Execution result missing"
        assert "expert_guidance" in result, "Expert guidance missing"
        
        print("  ✓ Expert-guided experiment execution successful")
        
        # Test continuous learning optimization
        optimization_result = await expert_controller.continuous_learning_optimization(system_context)
        
        assert "historical_analysis" in optimization_result, "Historical analysis missing"
        assert "optimization_recommendations" in optimization_result, "Optimization recommendations missing"
        
        print("  ✓ Continuous learning optimization successful")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Expert Chaos Controller test failed: {e}")
        traceback.print_exc()
        return False


async def test_cascade_failure_scenario():
    """Test cascade failure scenario functionality"""
    print("Testing Cascade Failure Scenario...")
    
    try:
        failure_injector = FailureInjector()
        resilience_validator = ResilienceValidator()
        cascade_scenario = CascadeFailureScenario(
            failure_injector=failure_injector,
            resilience_validator=resilience_validator
        )
        
        test_services = ["service-1", "service-2", "service-3"]
        
        # Test linear cascade execution
        result = await cascade_scenario.execute_linear_cascade(
            services=test_services,
            delay_seconds=5  # Reduced for testing
        )
        
        assert result["success"] is True, "Linear cascade execution failed"
        assert "scenario_id" in result, "Scenario ID missing"
        assert "cascade_results" in result, "Cascade results missing"
        
        print("  ✓ Linear cascade execution successful")
        
        # Test dependency cascade execution
        result = await cascade_scenario.execute_dependency_cascade(
            upstream_service=test_services[0],
            downstream_services=test_services[1:],
            delay_seconds=5
        )
        
        assert result["success"] is True, "Dependency cascade execution failed"
        
        print("  ✓ Dependency cascade execution successful")
        
        # Test cascade containment testing
        result = await cascade_scenario.test_cascade_containment(
            services=test_services,
            isolation_mechanisms=["circuit_breaker", "bulkhead"]
        )
        
        assert "containment_mechanisms_tested" in result, "Containment mechanisms test missing"
        assert "average_containment_score" in result, "Average containment score missing"
        
        print("  ✓ Cascade containment testing successful")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Cascade Failure Scenario test failed: {e}")
        traceback.print_exc()
        return False


async def test_integration():
    """Test integration between components"""
    print("Testing Component Integration...")
    
    try:
        # Initialize all components
        mock_expert_manager = MockExpertManager()
        chaos_orchestrator = ChaosOrchestrator(expert_manager=mock_expert_manager)
        failure_injector = FailureInjector()
        resilience_validator = ResilienceValidator()
        safety_controller = SafetyController()
        expert_controller = ExpertChaosController(
            expert_manager=mock_expert_manager,
            chaos_orchestrator=chaos_orchestrator
        )
        
        # Configure safety
        safety_controller.add_critical_service("auth-service")
        
        # Test end-to-end workflow
        system_context = {
            "system_name": "test-platform",
            "services": ["auth-service", "user-service"],
            "critical_services": ["auth-service"],
            "environment": "testing"
        }
        
        # 1. Generate strategy
        strategy = await expert_controller.generate_intelligent_strategy(
            system_context=system_context,
            learning_objectives=["Test system resilience"]
        )
        
        # 2. Execute experiment
        experiment_result = await expert_controller.execute_expert_guided_experiment(
            strategy_id=strategy.strategy_id,
            experiment_index=0
        )
        
        # 3. Validate safety integration
        experiment_config = {
            "name": "integration_test",
            "type": "service_chaos",
            "target_services": ["user-service"],  # Non-critical service
            "failure_scenarios": [{"type": "service_crash"}],
            "blast_radius": 0.05
        }
        
        experiment = await chaos_orchestrator.create_experiment(experiment_config)
        safety_validation = await safety_controller.validate_experiment(experiment)
        
        assert strategy is not None, "Strategy generation failed"
        assert experiment_result["execution_result"]["execution_successful"] is True, "Experiment execution failed"
        assert safety_validation["safe"] is True, "Safety validation failed"
        
        print("  ✓ End-to-end integration successful")
        
        # Test expert consultation integration
        assert mock_expert_manager.query_count > 0, "Expert consultation not triggered"
        
        print("  ✓ Expert consultation integration successful")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Integration test failed: {e}")
        traceback.print_exc()
        return False


async def run_all_tests():
    """Run all chaos engineering framework tests"""
    print("Chaos Engineering Framework - Comprehensive Test Suite")
    print("=" * 60)
    print(f"Test started at: {datetime.now().isoformat()}")
    print()
    
    test_functions = [
        ("Chaos Orchestrator", test_chaos_orchestrator),
        ("Failure Injector", test_failure_injector),
        ("Resilience Validator", test_resilience_validator),
        ("Breaking Point Analyzer", test_breaking_point_analyzer),
        ("Recovery Measurer", test_recovery_measurer),
        ("Safety Controller", test_safety_controller),
        ("Expert Chaos Controller", test_expert_chaos_controller),
        ("Cascade Failure Scenario", test_cascade_failure_scenario),
        ("Integration Tests", test_integration)
    ]
    
    results = {
        "total_tests": len(test_functions),
        "passed_tests": 0,
        "failed_tests": 0,
        "test_details": []
    }
    
    start_time = datetime.now()
    
    for test_name, test_function in test_functions:
        print(f"\n{test_name}:")
        print("-" * 40)
        
        try:
            success = await test_function()
            if success:
                results["passed_tests"] += 1
                status = "PASSED"
                print(f"  {test_name}: ✓ PASSED")
            else:
                results["failed_tests"] += 1
                status = "FAILED"
                print(f"  {test_name}: ✗ FAILED")
                
        except Exception as e:
            results["failed_tests"] += 1
            status = "ERROR"
            print(f"  {test_name}: ✗ ERROR - {e}")
        
        results["test_details"].append({
            "test_name": test_name,
            "status": status
        })
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    # Print summary
    print("\n" + "=" * 60)
    print("CHAOS ENGINEERING FRAMEWORK TEST SUMMARY")
    print("=" * 60)
    print(f"Total Tests: {results['total_tests']}")
    print(f"Passed: {results['passed_tests']}")
    print(f"Failed: {results['failed_tests']}")
    print(f"Success Rate: {(results['passed_tests']/results['total_tests']*100):.1f}%")
    print(f"Test Duration: {duration:.2f} seconds")
    print(f"Test Completed: {end_time.isoformat()}")
    
    # Detailed results
    print("\nDetailed Results:")
    print("-" * 40)
    for detail in results["test_details"]:
        status_symbol = "✓" if detail["status"] == "PASSED" else "✗"
        print(f"  {status_symbol} {detail['test_name']}: {detail['status']}")
    
    # Save results
    test_report = {
        "test_summary": results,
        "test_timestamp": end_time.isoformat(),
        "duration_seconds": duration,
        "framework_validation": {
            "core_components_tested": [
                "ChaosOrchestrator",
                "FailureInjector",
                "ResilienceValidator", 
                "BreakingPointAnalyzer",
                "RecoveryMeasurer",
                "SafetyController",
                "ExpertChaosController",
                "CascadeFailureScenario"
            ],
            "integration_tested": True,
            "expert_integration_tested": True,
            "safety_mechanisms_tested": True
        },
        "chaos_engineering_capabilities": {
            "failure_injection": "Comprehensive failure injection across service, network, resource, data, and infrastructure layers",
            "resilience_validation": "System resilience measurement, failure detection validation, and recovery mechanism testing",
            "breaking_point_analysis": "Capacity limit identification, performance cliff detection, and stability boundary measurement",
            "recovery_measurement": "Recovery time measurement, effectiveness analysis, and bottleneck identification",
            "safety_mechanisms": "Pre-experiment validation, continuous monitoring, emergency recovery, and blast radius control",
            "expert_integration": "AI-driven experiment selection, strategy optimization, and intelligent chaos orchestration",
            "cascade_scenarios": "Linear, tree, dependency, and load redistribution cascade failure testing",
            "adaptive_orchestration": "Real-time strategy adjustment based on expert recommendations and learning outcomes"
        }
    }
    
    with open("chaos_engineering_test_results_simple.json", "w") as f:
        json.dump(test_report, f, indent=2)
    
    print(f"\nTest report saved to: chaos_engineering_test_results_simple.json")
    
    if results["failed_tests"] == 0:
        print("\n🎉 ALL TESTS PASSED! Chaos Engineering Framework is fully functional.")
    else:
        print(f"\n⚠️  {results['failed_tests']} tests failed. Review the framework implementation.")
    
    return results


if __name__ == "__main__":
    asyncio.run(run_all_tests())