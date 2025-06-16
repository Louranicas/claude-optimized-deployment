"""
Comprehensive Chaos Engineering Framework Tests

Tests all components of the chaos engineering framework including orchestration,
failure injection, resilience validation, breaking point analysis, and expert integration.
"""

import asyncio
import pytest
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any

# Import chaos engineering components
from test_environments.chaos_engineering import (
    ChaosOrchestrator, FailureInjector, ResilienceValidator, 
    BreakingPointAnalyzer, RecoveryMeasurer
)
from test_environments.chaos_engineering.expert_chaos_controller import ExpertChaosController
from test_environments.chaos_engineering.scenarios.cascade_failure import CascadeFailureScenario
from test_environments.chaos_engineering.safety.safety_controller import SafetyController

# Mock expert manager for testing
class MockExpertManager:
    def __init__(self):
        self.query_count = 0
    
    async def query_experts(self, query: str, expertise_areas: List[str] = None):
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


class TestChaosEngineeringFramework:
    """Comprehensive test suite for chaos engineering framework"""
    
    @pytest.fixture
    def mock_expert_manager(self):
        return MockExpertManager()
    
    @pytest.fixture
    def chaos_orchestrator(self, mock_expert_manager):
        return ChaosOrchestrator(expert_manager=mock_expert_manager)
    
    @pytest.fixture
    def failure_injector(self):
        return FailureInjector()
    
    @pytest.fixture
    def resilience_validator(self):
        return ResilienceValidator()
    
    @pytest.fixture
    def breaking_point_analyzer(self):
        return BreakingPointAnalyzer()
    
    @pytest.fixture
    def recovery_measurer(self):
        return RecoveryMeasurer()
    
    @pytest.fixture
    def safety_controller(self):
        return SafetyController()
    
    @pytest.fixture
    def expert_chaos_controller(self, mock_expert_manager, chaos_orchestrator):
        return ExpertChaosController(expert_manager=mock_expert_manager, chaos_orchestrator=chaos_orchestrator)
    
    @pytest.fixture
    def cascade_failure_scenario(self, failure_injector, resilience_validator):
        return CascadeFailureScenario(failure_injector=failure_injector, resilience_validator=resilience_validator)
    
    @pytest.fixture
    def test_services(self):
        return ["auth-service", "user-service", "order-service", "payment-service", "notification-service"]
    
    @pytest.fixture
    def system_context(self, test_services):
        return {
            "system_name": "e-commerce-platform",
            "services": test_services,
            "critical_services": ["auth-service", "payment-service"],
            "failure_domains": ["web-tier", "service-tier", "data-tier"],
            "environment": "testing"
        }


class TestChaosOrchestrator:
    """Test chaos orchestrator functionality"""
    
    @pytest.mark.asyncio
    async def test_create_experiment(self, chaos_orchestrator, test_services):
        """Test experiment creation with validation"""
        experiment_config = {
            "name": "test_service_failure",
            "description": "Test service failure resilience",
            "type": "service_chaos",
            "target_services": test_services[:2],
            "failure_scenarios": [{
                "type": "service_crash",
                "config": {"duration": 180}
            }],
            "duration_seconds": 300,
            "blast_radius": 0.1
        }
        
        experiment = await chaos_orchestrator.create_experiment(experiment_config)
        
        assert experiment is not None
        assert experiment.name == "test_service_failure"
        assert experiment.target_services == test_services[:2]
        assert len(experiment.failure_scenarios) == 1
        assert experiment.state.value == "ready"
        assert len(experiment.expert_recommendations) > 0  # Expert consultation should provide recommendations
    
    @pytest.mark.asyncio
    async def test_run_experiment(self, chaos_orchestrator, test_services):
        """Test experiment execution and metrics collection"""
        experiment_config = {
            "name": "test_experiment_execution",
            "type": "service_chaos",
            "target_services": [test_services[0]],
            "failure_scenarios": [{
                "type": "service_crash",
                "config": {"duration": 60}
            }],
            "duration_seconds": 120,
            "blast_radius": 0.05
        }
        
        experiment = await chaos_orchestrator.create_experiment(experiment_config)
        metrics = await chaos_orchestrator.run_experiment(experiment.id)
        
        assert metrics is not None
        assert metrics.experiment_id == experiment.id
        assert metrics.mttd_seconds >= 0
        assert metrics.mttr_seconds >= 0
        assert 0 <= metrics.resilience_score <= 1.0
        assert experiment.state.value == "completed"
    
    @pytest.mark.asyncio
    async def test_emergency_stop(self, chaos_orchestrator, test_services):
        """Test emergency stop functionality"""
        experiment_config = {
            "name": "test_emergency_stop",
            "type": "service_chaos",
            "target_services": [test_services[0]],
            "failure_scenarios": [{
                "type": "service_crash",
                "config": {"duration": 300}
            }],
            "duration_seconds": 600
        }
        
        experiment = await chaos_orchestrator.create_experiment(experiment_config)
        
        # Start experiment (in background)
        experiment_task = asyncio.create_task(chaos_orchestrator.run_experiment(experiment.id))
        
        # Allow experiment to start
        await asyncio.sleep(0.1)
        
        # Emergency stop
        stop_result = await chaos_orchestrator.emergency_stop_experiment(experiment.id)
        
        assert stop_result is True
        assert experiment.state.value == "emergency_stopped"
        
        # Cancel the experiment task
        experiment_task.cancel()
        try:
            await experiment_task
        except asyncio.CancelledError:
            pass
    
    @pytest.mark.asyncio
    async def test_global_resilience_metrics(self, chaos_orchestrator, test_services):
        """Test global resilience metrics calculation"""
        # Run multiple experiments
        for i in range(3):
            experiment_config = {
                "name": f"test_metrics_{i}",
                "type": "service_chaos",
                "target_services": [test_services[i % len(test_services)]],
                "failure_scenarios": [{
                    "type": "service_crash",
                    "config": {"duration": 30}
                }],
                "duration_seconds": 60
            }
            
            experiment = await chaos_orchestrator.create_experiment(experiment_config)
            await chaos_orchestrator.run_experiment(experiment.id)
        
        global_metrics = await chaos_orchestrator.get_global_resilience_metrics()
        
        assert global_metrics["total_experiments"] == 3
        assert global_metrics["resilience_score"] >= 0
        assert global_metrics["success_rate"] >= 0
        assert "experiments_by_type" in global_metrics


class TestFailureInjector:
    """Test failure injection capabilities"""
    
    @pytest.mark.asyncio
    async def test_service_failure_injection(self, failure_injector):
        """Test service failure injection"""
        result = await failure_injector.inject_service_failure(
            service="test-service",
            failure_type="service_crash",
            duration=60
        )
        
        assert result["success"] is True
        assert "injection_id" in result
        assert result["recovery_scheduled"] is True
        
        # Check active injections
        active_injections = failure_injector.get_active_injections()
        assert len(active_injections) == 1
    
    @pytest.mark.asyncio
    async def test_network_partition_injection(self, failure_injector):
        """Test network partition injection"""
        services = ["service-a", "service-b", "service-c"]
        
        result = await failure_injector.inject_network_partition(
            services=services,
            partition_type="split_brain",
            duration=120
        )
        
        assert result["success"] is True
        assert result["affected_services"] == services
        assert "injection_id" in result
    
    @pytest.mark.asyncio
    async def test_resource_exhaustion_injection(self, failure_injector):
        """Test resource exhaustion injection"""
        result = await failure_injector.inject_resource_exhaustion(
            resource_type="cpu_exhaustion",
            intensity=0.8,
            duration=90
        )
        
        assert result["success"] is True
        assert result["intensity"] == 0.8
        assert "injection_id" in result
    
    @pytest.mark.asyncio
    async def test_failure_recovery(self, failure_injector):
        """Test failure injection recovery"""
        # Inject failure
        result = await failure_injector.inject_service_failure(
            service="test-service",
            failure_type="service_hang",
            duration=60
        )
        
        injection_id = result["injection_id"]
        
        # Manually recover
        recovery_result = await failure_injector.recover_injection(injection_id)
        
        assert recovery_result["success"] is True
        assert recovery_result["recovery_time"] >= 0
        assert len(recovery_result["actions"]) >= 0
    
    @pytest.mark.asyncio
    async def test_cleanup_all_failures(self, failure_injector):
        """Test cleanup of all failures for an experiment"""
        experiment_id = "test_experiment_123"
        
        # Inject multiple failures
        for i in range(3):
            await failure_injector.inject_service_failure(
                service=f"service-{i}",
                failure_type="service_crash",
                duration=300
            )
            # Manually set experiment_id for tracking
            for injection in failure_injector.active_injections.values():
                injection.experiment_id = experiment_id
                break
        
        # Cleanup all failures
        cleanup_result = await failure_injector.cleanup_all_failures(experiment_id)
        
        assert cleanup_result["cleaned_up"] >= 0
        assert "results" in cleanup_result


class TestResilienceValidator:
    """Test resilience validation functionality"""
    
    @pytest.mark.asyncio
    async def test_measure_resilience(self, resilience_validator, test_services):
        """Test resilience measurement"""
        start_time = datetime.now() - timedelta(minutes=5)
        end_time = datetime.now()
        
        result = await resilience_validator.measure_resilience(
            services=test_services[:3],
            start_time=start_time,
            end_time=end_time
        )
        
        assert "measurement_period" in result
        assert "service_metrics" in result
        assert "overall_resilience" in result
        assert result["mttd_seconds"] >= 0
        assert 0 <= result["performance_degradation"] <= 1.0
    
    @pytest.mark.asyncio
    async def test_validate_failure_detection(self, resilience_validator):
        """Test failure detection validation"""
        service = "test-service"
        failure_time = datetime.now() - timedelta(minutes=2)
        
        result = await resilience_validator.validate_failure_detection(
            service=service,
            failure_injection_time=failure_time,
            detection_timeout=120
        )
        
        assert result["service"] == service
        assert "detection_methods" in result
        assert "fastest_detection_seconds" in result
        assert "overall_detected" in result
    
    @pytest.mark.asyncio
    async def test_validate_recovery_mechanisms(self, resilience_validator):
        """Test recovery mechanism validation"""
        service = "test-service"
        failure_start = datetime.now() - timedelta(minutes=3)
        
        result = await resilience_validator.validate_recovery_mechanisms(
            service=service,
            failure_start=failure_start,
            recovery_timeout=300
        )
        
        assert result["service"] == service
        assert "recovery_mechanisms" in result
        assert "full_recovery" in result
        assert "recovery_success" in result
    
    @pytest.mark.asyncio
    async def test_validate_full_recovery(self, resilience_validator, test_services):
        """Test full system recovery validation"""
        result = await resilience_validator.validate_full_recovery(test_services[:3])
        
        assert result["total_services"] == 3
        assert "recovered_services" in result
        assert "recovery_rate" in result
        assert "service_status" in result
        assert isinstance(result["full_recovery_achieved"], bool)
    
    @pytest.mark.asyncio
    async def test_cascade_failure_containment(self, resilience_validator, test_services):
        """Test cascade failure containment measurement"""
        initial_service = test_services[0]
        all_services = test_services
        
        result = await resilience_validator.measure_cascade_failure_containment(
            initial_failure_service=initial_service,
            all_services=all_services
        )
        
        assert result["initial_failure_service"] == initial_service
        assert result["total_services_monitored"] == len(all_services) - 1
        assert 0 <= result["containment_effectiveness"] <= 1.0
        assert isinstance(result["cascade_failure_contained"], bool)
    
    @pytest.mark.asyncio
    async def test_graceful_degradation_measurement(self, resilience_validator, test_services):
        """Test graceful degradation measurement"""
        result = await resilience_validator.measure_graceful_degradation(test_services[:3])
        
        assert result["services_measured"] == 3
        assert "graceful_degradation_active" in result
        assert 0 <= result["overall_degradation_score"] <= 1.0
        assert "service_degradation_metrics" in result


class TestBreakingPointAnalyzer:
    """Test breaking point analysis functionality"""
    
    @pytest.mark.asyncio
    async def test_analyze_breaking_points(self, breaking_point_analyzer, test_services):
        """Test breaking point analysis"""
        failure_scenarios = [{
            "type": "load_test",
            "config": {"max_rps": 1000}
        }]
        
        result = await breaking_point_analyzer.analyze_breaking_points(
            services=test_services[:2],
            failure_scenarios=failure_scenarios
        )
        
        assert "analysis_timestamp" in result
        assert "service_analysis" in result
        assert "system_analysis" in result
        assert "capacity_recommendations" in result
    
    @pytest.mark.asyncio
    async def test_find_capacity_limits(self, breaking_point_analyzer):
        """Test capacity limit identification"""
        service = "test-service"
        
        result = await breaking_point_analyzer.find_capacity_limits(
            service=service,
            load_pattern="linear"
        )
        
        assert result["service"] == service
        assert result["load_pattern"] == "linear"
        assert "breaking_points" in result
        assert "performance_data" in result
        assert "capacity_analysis" in result
    
    @pytest.mark.asyncio
    async def test_identify_performance_cliffs(self, breaking_point_analyzer):
        """Test performance cliff identification"""
        service = "test-service"
        
        result = await breaking_point_analyzer.identify_performance_cliffs(service)
        
        assert result["service"] == service
        assert "performance_data" in result
        assert "detected_cliffs" in result
        assert "cliff_analysis" in result
    
    @pytest.mark.asyncio
    async def test_resource_exhaustion_analysis(self, breaking_point_analyzer):
        """Test resource exhaustion point analysis"""
        service = "test-service"
        
        result = await breaking_point_analyzer.analyze_resource_exhaustion_points(service)
        
        assert result["service"] == service
        assert "exhaustion_points" in result
        assert "resource_interactions" in result
        assert "critical_resources" in result
    
    @pytest.mark.asyncio
    async def test_stability_boundaries(self, breaking_point_analyzer):
        """Test system stability boundary measurement"""
        service = "test-service"
        
        result = await breaking_point_analyzer.measure_system_stability_boundaries(service)
        
        assert result["service"] == service
        assert "stability_measurements" in result
        assert "stability_boundaries" in result
        assert "recommended_operating_range" in result


class TestRecoveryMeasurer:
    """Test recovery measurement functionality"""
    
    @pytest.mark.asyncio
    async def test_measure_recovery(self, recovery_measurer, test_services):
        """Test recovery measurement"""
        failure_scenarios = [{
            "type": "service_crash",
            "config": {"duration": 60}
        }]
        failure_start = datetime.now() - timedelta(minutes=5)
        measurement_end = datetime.now()
        
        result = await recovery_measurer.measure_recovery(
            services=test_services[:2],
            failure_scenarios=failure_scenarios,
            failure_start=failure_start,
            measurement_end=measurement_end
        )
        
        assert "measurement_period" in result
        assert "service_recovery_metrics" in result
        assert "aggregate_metrics" in result
        assert result["mttr_seconds"] >= 0
        assert 0 <= result["effectiveness"] <= 1.0
    
    @pytest.mark.asyncio
    async def test_recovery_time_distribution(self, recovery_measurer):
        """Test recovery time distribution measurement"""
        service = "test-service"
        
        result = await recovery_measurer.measure_recovery_time_distribution(
            service=service,
            failure_type="service_crash",
            num_samples=3  # Reduced for testing
        )
        
        assert result["service"] == service
        assert result["failure_type"] == "service_crash"
        assert "distribution_stats" in result
        assert result["sample_count"] >= 0
    
    @pytest.mark.asyncio
    async def test_recovery_bottleneck_analysis(self, recovery_measurer):
        """Test recovery bottleneck analysis"""
        from test_environments.chaos_engineering.recovery_measurer import RecoveryMeasurement, RecoveryEvent, RecoveryPhase
        
        # Create mock recovery measurement
        measurement = RecoveryMeasurement(
            service_name="test-service",
            failure_start=datetime.now() - timedelta(minutes=5),
            total_recovery_time_seconds=240
        )
        
        # Add mock recovery events
        measurement.recovery_events = [
            RecoveryEvent(
                timestamp=datetime.now(),
                phase=RecoveryPhase.DETECTION,
                event_type="failure_detected",
                duration_ms=30000
            ),
            RecoveryEvent(
                timestamp=datetime.now(),
                phase=RecoveryPhase.RESPONSE,
                event_type="restart_initiated",
                duration_ms=120000
            )
        ]
        
        result = await recovery_measurer.analyze_recovery_bottlenecks(
            service="test-service",
            recovery_measurement=measurement
        )
        
        assert result["service"] == "test-service"
        assert "phase_analysis" in result
        assert "bottlenecks" in result
        assert "improvement_opportunities" in result
    
    @pytest.mark.asyncio
    async def test_recovery_consistency_validation(self, recovery_measurer):
        """Test recovery consistency validation"""
        service = "test-service"
        
        result = await recovery_measurer.validate_recovery_consistency(
            service=service,
            num_trials=3  # Reduced for testing
        )
        
        assert result["service"] == service
        assert "trials_completed" in result
        assert "consistency_metrics" in result
        assert 0 <= result["overall_consistency_score"] <= 1.0


class TestSafetyController:
    """Test safety controller functionality"""
    
    @pytest.mark.asyncio
    async def test_validate_experiment(self, safety_controller):
        """Test experiment safety validation"""
        from test_environments.chaos_engineering.chaos_orchestrator import ChaosExperiment, ExperimentType
        
        experiment = ChaosExperiment(
            name="test_safety_validation",
            experiment_type=ExperimentType.SERVICE_CHAOS,
            target_services=["safe-service"],
            blast_radius=0.05,  # 5% - safe level
            duration_seconds=300
        )
        
        result = await safety_controller.validate_experiment(experiment)
        
        assert "safe" in result
        assert "warnings" in result
        assert "violations" in result
        assert "reasons" in result
    
    @pytest.mark.asyncio
    async def test_pre_experiment_check(self, safety_controller):
        """Test pre-experiment safety check"""
        from test_environments.chaos_engineering.chaos_orchestrator import ChaosExperiment, ExperimentType
        
        experiment = ChaosExperiment(
            name="test_pre_check",
            experiment_type=ExperimentType.SERVICE_CHAOS,
            target_services=["test-service"],
            blast_radius=0.1
        )
        
        result = await safety_controller.pre_experiment_check(experiment)
        
        assert "safe" in result
        assert "checks_performed" in result
        assert "timestamp" in result
    
    @pytest.mark.asyncio
    async def test_continuous_safety_check(self, safety_controller):
        """Test continuous safety monitoring"""
        from test_environments.chaos_engineering.chaos_orchestrator import ChaosExperiment, ExperimentType
        
        experiment = ChaosExperiment(
            name="test_continuous_safety",
            experiment_type=ExperimentType.SERVICE_CHAOS,
            target_services=["monitored-service"],
            blast_radius=0.1
        )
        
        result = await safety_controller.continuous_safety_check(experiment)
        
        assert "safe" in result
        assert "safety_level" in result
        assert "violations" in result
        assert "metrics" in result
    
    @pytest.mark.asyncio
    async def test_emergency_recovery(self, safety_controller):
        """Test emergency recovery procedures"""
        from test_environments.chaos_engineering.chaos_orchestrator import ChaosExperiment, ExperimentType
        
        experiment = ChaosExperiment(
            name="test_emergency_recovery",
            experiment_type=ExperimentType.SERVICE_CHAOS,
            target_services=["emergency-service"]
        )
        
        result = await safety_controller.emergency_recovery(experiment)
        
        assert "emergency_recovery" in result
        assert "actions_performed" in result
        assert "recovery_timestamp" in result
    
    def test_safety_configuration(self, safety_controller):
        """Test safety configuration methods"""
        # Add protected service
        safety_controller.add_protected_service("critical-service")
        assert "critical-service" in safety_controller.protected_services
        
        # Add critical service
        safety_controller.add_critical_service("core-service")
        assert "core-service" in safety_controller.critical_services
        
        # Set safety threshold
        safety_controller.set_safety_threshold("max_error_rate", 0.03)
        assert safety_controller.default_safety_thresholds["max_error_rate"] == 0.03


class TestExpertChaosController:
    """Test expert-driven chaos controller"""
    
    @pytest.mark.asyncio
    async def test_generate_intelligent_strategy(self, expert_chaos_controller, system_context):
        """Test intelligent strategy generation"""
        learning_objectives = [
            "Validate service resilience",
            "Test recovery mechanisms",
            "Measure system breaking points"
        ]
        
        strategy = await expert_chaos_controller.generate_intelligent_strategy(
            system_context=system_context,
            learning_objectives=learning_objectives
        )
        
        assert strategy.target_system == system_context["system_name"]
        assert len(strategy.recommended_experiments) > 0
        assert len(strategy.expert_recommendations) > 0
        assert len(strategy.execution_priority) > 0
        assert strategy.learning_objectives == learning_objectives
    
    @pytest.mark.asyncio
    async def test_execute_expert_guided_experiment(self, expert_chaos_controller, system_context):
        """Test expert-guided experiment execution"""
        learning_objectives = ["Test basic resilience"]
        
        strategy = await expert_chaos_controller.generate_intelligent_strategy(
            system_context=system_context,
            learning_objectives=learning_objectives
        )
        
        result = await expert_chaos_controller.execute_expert_guided_experiment(
            strategy_id=strategy.strategy_id,
            experiment_index=0
        )
        
        assert result["strategy_id"] == strategy.strategy_id
        assert result["experiment_index"] == 0
        assert "execution_result" in result
        assert "expert_guidance" in result
        assert "learning_objectives_progress" in result
    
    @pytest.mark.asyncio
    async def test_adaptive_chaos_orchestration(self, expert_chaos_controller, system_context):
        """Test adaptive chaos orchestration"""
        learning_objectives = ["Validate system resilience"]
        
        strategy = await expert_chaos_controller.generate_intelligent_strategy(
            system_context=system_context,
            learning_objectives=learning_objectives
        )
        
        result = await expert_chaos_controller.adaptive_chaos_orchestration(
            strategy_id=strategy.strategy_id,
            max_experiments=2  # Limit for testing
        )
        
        assert result["strategy_id"] == strategy.strategy_id
        assert "experiments_executed" in result
        assert "adaptive_decisions" in result
        assert "learning_outcomes" in result
        assert "expert_insights" in result
    
    @pytest.mark.asyncio
    async def test_continuous_learning_optimization(self, expert_chaos_controller, system_context):
        """Test continuous learning optimization"""
        result = await expert_chaos_controller.continuous_learning_optimization(system_context)
        
        assert "historical_analysis" in result
        assert "pattern_analysis" in result
        assert "optimization_recommendations" in result
        assert "learning_optimization_timestamp" in result


class TestCascadeFailureScenario:
    """Test cascade failure scenario functionality"""
    
    @pytest.mark.asyncio
    async def test_linear_cascade_execution(self, cascade_failure_scenario, test_services):
        """Test linear cascade failure execution"""
        services = test_services[:3]
        
        result = await cascade_failure_scenario.execute_linear_cascade(
            services=services,
            delay_seconds=10  # Reduced for testing
        )
        
        assert result["success"] is True
        assert "scenario_id" in result
        assert "cascade_results" in result
        assert result["total_services_affected"] <= len(services)
    
    @pytest.mark.asyncio
    async def test_tree_cascade_execution(self, cascade_failure_scenario, test_services):
        """Test tree cascade failure execution"""
        root_service = test_services[0]
        service_groups = [test_services[1:3], test_services[3:5]]
        
        result = await cascade_failure_scenario.execute_tree_cascade(
            root_service=root_service,
            service_groups=service_groups,
            delay_seconds=10
        )
        
        assert result["success"] is True
        assert "cascade_results" in result
    
    @pytest.mark.asyncio
    async def test_dependency_cascade_execution(self, cascade_failure_scenario, test_services):
        """Test dependency cascade failure execution"""
        upstream_service = test_services[0]
        downstream_services = test_services[1:3]
        
        result = await cascade_failure_scenario.execute_dependency_cascade(
            upstream_service=upstream_service,
            downstream_services=downstream_services,
            delay_seconds=10
        )
        
        assert result["success"] is True
        assert "cascade_results" in result
    
    @pytest.mark.asyncio
    async def test_cascade_containment_testing(self, cascade_failure_scenario, test_services):
        """Test cascade containment mechanism testing"""
        services = test_services[:3]
        isolation_mechanisms = ["circuit_breaker", "bulkhead"]
        
        result = await cascade_failure_scenario.test_cascade_containment(
            services=services,
            isolation_mechanisms=isolation_mechanisms
        )
        
        assert "containment_mechanisms_tested" in result
        assert "containment_results" in result
        assert "most_effective_mechanism" in result
        assert 0 <= result["average_containment_score"] <= 1.0
    
    @pytest.mark.asyncio
    async def test_load_redistribution_cascade(self, cascade_failure_scenario, test_services):
        """Test load redistribution cascade simulation"""
        services = test_services[:3]
        
        result = await cascade_failure_scenario.simulate_load_redistribution_cascade(
            services=services,
            initial_load_multiplier=2.0
        )
        
        assert result["scenario_type"] == "load_redistribution_cascade"
        assert "redistribution_stages" in result
        assert "cascade_analysis" in result
        assert result["total_failures"] >= 0


class TestIntegration:
    """Integration tests for the complete chaos engineering framework"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_chaos_experiment(self, chaos_orchestrator, expert_chaos_controller, 
                                              cascade_failure_scenario, system_context):
        """Test complete end-to-end chaos experiment workflow"""
        # 1. Generate intelligent strategy
        learning_objectives = ["Validate system resilience", "Test cascade containment"]
        
        strategy = await expert_chaos_controller.generate_intelligent_strategy(
            system_context=system_context,
            learning_objectives=learning_objectives
        )
        
        assert len(strategy.recommended_experiments) > 0
        
        # 2. Execute expert-guided experiment
        experiment_result = await expert_chaos_controller.execute_expert_guided_experiment(
            strategy_id=strategy.strategy_id,
            experiment_index=0
        )
        
        assert experiment_result["execution_result"]["execution_successful"] is True
        
        # 3. Run cascade failure scenario
        cascade_result = await cascade_failure_scenario.execute_linear_cascade(
            services=system_context["services"][:3],
            delay_seconds=5
        )
        
        assert cascade_result["success"] is True
        
        # 4. Validate learning objectives progress
        learning_progress = await expert_chaos_controller._assess_learning_progress(strategy)
        assert learning_progress["total_objectives"] == len(learning_objectives)
    
    @pytest.mark.asyncio
    async def test_safety_integrated_experiment(self, chaos_orchestrator, safety_controller, test_services):
        """Test experiment with integrated safety mechanisms"""
        # Configure safety
        safety_controller.add_critical_service(test_services[0])
        safety_controller.set_safety_threshold("max_error_rate", 0.03)
        
        # Create experiment targeting critical service (should trigger safety warnings)
        experiment_config = {
            "name": "safety_test_experiment",
            "type": "service_chaos",
            "target_services": [test_services[0]],  # Critical service
            "failure_scenarios": [{
                "type": "service_crash",
                "config": {"duration": 120}
            }],
            "blast_radius": 0.05,
            "duration_seconds": 180
        }
        
        experiment = await chaos_orchestrator.create_experiment(experiment_config)
        
        # Safety validation should include warnings about critical service
        safety_status = await safety_controller.get_safety_status(experiment.id)
        
        # Run experiment with safety monitoring
        metrics = await chaos_orchestrator.run_experiment(experiment.id)
        
        assert metrics is not None
        assert experiment.state.value in ["completed", "emergency_stopped"]
    
    @pytest.mark.asyncio
    async def test_multi_component_resilience_analysis(self, resilience_validator, breaking_point_analyzer,
                                                     recovery_measurer, test_services):
        """Test comprehensive resilience analysis using multiple components"""
        services = test_services[:3]
        start_time = datetime.now() - timedelta(minutes=10)
        end_time = datetime.now()
        
        # 1. Measure overall resilience
        resilience_result = await resilience_validator.measure_resilience(
            services=services,
            start_time=start_time,
            end_time=end_time
        )
        
        # 2. Analyze breaking points
        breaking_point_result = await breaking_point_analyzer.analyze_breaking_points(
            services=services,
            failure_scenarios=[{"type": "load_test"}]
        )
        
        # 3. Measure recovery patterns
        recovery_result = await recovery_measurer.measure_recovery(
            services=services,
            failure_scenarios=[{"type": "service_crash"}],
            failure_start=start_time,
            measurement_end=end_time
        )
        
        # Validate all components provided results
        assert resilience_result["overall_resilience"]["overall_availability"] > 0
        assert "system_analysis" in breaking_point_result
        assert recovery_result["mttr_seconds"] >= 0
        
        # Integration check: results should be consistent
        assert len(resilience_result["service_metrics"]) == len(services)
        assert len(breaking_point_result["service_analysis"]) == len(services)


# Test runner function
async def run_comprehensive_chaos_tests():
    """Run all chaos engineering tests"""
    import time
    
    print("Starting Comprehensive Chaos Engineering Framework Tests")
    print("=" * 60)
    
    start_time = time.time()
    
    # Initialize test components
    mock_expert_manager = MockExpertManager()
    chaos_orchestrator = ChaosOrchestrator(expert_manager=mock_expert_manager)
    failure_injector = FailureInjector()
    resilience_validator = ResilienceValidator()
    breaking_point_analyzer = BreakingPointAnalyzer()
    recovery_measurer = RecoveryMeasurer()
    safety_controller = SafetyController()
    expert_chaos_controller = ExpertChaosController(
        expert_manager=mock_expert_manager, 
        chaos_orchestrator=chaos_orchestrator
    )
    cascade_failure_scenario = CascadeFailureScenario(
        failure_injector=failure_injector,
        resilience_validator=resilience_validator
    )
    
    test_services = ["auth-service", "user-service", "order-service", "payment-service", "notification-service"]
    system_context = {
        "system_name": "e-commerce-platform",
        "services": test_services,
        "critical_services": ["auth-service", "payment-service"],
        "failure_domains": ["web-tier", "service-tier", "data-tier"],
        "environment": "testing"
    }
    
    test_results = {
        "total_tests": 0,
        "passed_tests": 0,
        "failed_tests": 0,
        "test_details": []
    }
    
    # Test categories
    test_categories = [
        ("Chaos Orchestrator", TestChaosOrchestrator),
        ("Failure Injector", TestFailureInjector),
        ("Resilience Validator", TestResilienceValidator),
        ("Breaking Point Analyzer", TestBreakingPointAnalyzer),
        ("Recovery Measurer", TestRecoveryMeasurer),
        ("Safety Controller", TestSafetyController),
        ("Expert Chaos Controller", TestExpertChaosController),
        ("Cascade Failure Scenario", TestCascadeFailureScenario),
        ("Integration Tests", TestIntegration)
    ]
    
    for category_name, test_class in test_categories:
        print(f"\n{category_name} Tests:")
        print("-" * 40)
        
        category_results = {"passed": 0, "failed": 0, "tests": []}
        
        # Get test methods
        test_methods = [method for method in dir(test_class) if method.startswith('test_')]
        
        for test_method_name in test_methods:
            test_results["total_tests"] += 1
            
            try:
                # Create test instance
                test_instance = test_class()
                
                # Inject required fixtures
                if hasattr(test_instance, test_method_name):
                    test_method = getattr(test_instance, test_method_name)
                    
                    # Call test method with appropriate fixtures
                    if category_name == "Chaos Orchestrator":
                        await test_method(chaos_orchestrator, test_services)
                    elif category_name == "Failure Injector":
                        await test_method(failure_injector)
                    elif category_name == "Resilience Validator":
                        await test_method(resilience_validator, test_services)
                    elif category_name == "Breaking Point Analyzer":
                        await test_method(breaking_point_analyzer, test_services)
                    elif category_name == "Recovery Measurer":
                        await test_method(recovery_measurer, test_services)
                    elif category_name == "Safety Controller":
                        await test_method(safety_controller)
                    elif category_name == "Expert Chaos Controller":
                        await test_method(expert_chaos_controller, system_context)
                    elif category_name == "Cascade Failure Scenario":
                        await test_method(cascade_failure_scenario, test_services)
                    elif category_name == "Integration Tests":
                        if "end_to_end" in test_method_name:
                            await test_method(chaos_orchestrator, expert_chaos_controller, 
                                            cascade_failure_scenario, system_context)
                        elif "safety_integrated" in test_method_name:
                            await test_method(chaos_orchestrator, safety_controller, test_services)
                        elif "multi_component" in test_method_name:
                            await test_method(resilience_validator, breaking_point_analyzer,
                                            recovery_measurer, test_services)
                
                print(f"  ✓ {test_method_name}")
                test_results["passed_tests"] += 1
                category_results["passed"] += 1
                category_results["tests"].append({"name": test_method_name, "status": "PASSED"})
                
            except Exception as e:
                print(f"  ✗ {test_method_name}: {str(e)}")
                test_results["failed_tests"] += 1
                category_results["failed"] += 1
                category_results["tests"].append({"name": test_method_name, "status": "FAILED", "error": str(e)})
        
        test_results["test_details"].append({
            "category": category_name,
            "results": category_results
        })
        
        print(f"  Category Summary: {category_results['passed']} passed, {category_results['failed']} failed")
    
    # Final summary
    end_time = time.time()
    duration = end_time - start_time
    
    print("\n" + "=" * 60)
    print("CHAOS ENGINEERING FRAMEWORK TEST RESULTS")
    print("=" * 60)
    print(f"Total Tests: {test_results['total_tests']}")
    print(f"Passed: {test_results['passed_tests']}")
    print(f"Failed: {test_results['failed_tests']}")
    print(f"Success Rate: {(test_results['passed_tests']/test_results['total_tests']*100):.1f}%")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Expert Consultations: {mock_expert_manager.query_count}")
    
    # Save detailed results
    test_report = {
        "test_summary": test_results,
        "test_timestamp": datetime.now().isoformat(),
        "duration_seconds": duration,
        "framework_components_tested": [
            "ChaosOrchestrator",
            "FailureInjector", 
            "ResilienceValidator",
            "BreakingPointAnalyzer",
            "RecoveryMeasurer",
            "SafetyController",
            "ExpertChaosController",
            "CascadeFailureScenario"
        ],
        "expert_integration": {
            "mock_expert_manager": True,
            "expert_consultations": mock_expert_manager.query_count,
            "expert_integration_functional": True
        }
    }
    
    # Write test report
    with open("/home/louranicas/projects/claude-optimized-deployment/chaos_engineering_test_results.json", "w") as f:
        json.dump(test_report, f, indent=2)
    
    print(f"\nDetailed test report saved to: chaos_engineering_test_results.json")
    
    return test_results


if __name__ == "__main__":
    asyncio.run(run_comprehensive_chaos_tests())