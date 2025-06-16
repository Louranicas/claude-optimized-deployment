"""
Simple Test for Dynamic Environment Scaling and Resource Management

This test validates the core dynamic scaling functionality without external dependencies.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import scaling components
from test_environments.scaling import (
    ScalingOrchestrator,
    ResourceManager, 
    CostOptimizer,
    CapacityPlanner,
    Autoscaler
)
from test_environments.scaling.scaling_orchestrator import ScalingMetrics
from test_environments.scaling.types import ScalingAction, ScalingStrategy
from test_environments.scaling.resource_manager import ResourceType, ResourceRequirement, AllocationStrategy
from test_environments.scaling.cost_optimizer import CostOptimizationStrategy, BudgetConstraint
from test_environments.scaling.capacity_planner import CapacityMetric, ForecastMethod
from test_environments.scaling.autoscaler import ScalingRule, ScalingPolicy, ScalingTrigger, ScalingDirection

# Import provider integrations
from test_environments.scaling.providers import AWSScaler, KubernetesScaler


async def test_scaling_orchestrator():
    """Test basic scaling orchestrator operation"""
    logger.info("Testing Scaling Orchestrator")
    
    orchestrator = ScalingOrchestrator()
    
    # Create test metrics
    metrics = ScalingMetrics(
        cpu_utilization=85.0,
        memory_utilization=75.0,
        network_io=50.0,
        disk_io=40.0,
        active_connections=150,
        queue_depth=10,
        response_time=2.5,
        error_rate=2.0,
        cost_per_hour=50.0
    )
    
    # Test scaling decision
    decision = await orchestrator.orchestrate_scaling(metrics)
    
    assert decision is not None
    assert decision.action in [action for action in ScalingAction]
    assert decision.strategy in [strategy for strategy in ScalingStrategy]
    assert 0.0 <= decision.confidence <= 1.0
    assert decision.estimated_cost >= 0.0
    
    logger.info(f"✓ Scaling decision: {decision.action.value} with confidence {decision.confidence}")
    return True


async def test_resource_manager():
    """Test resource manager allocation"""
    logger.info("Testing Resource Manager")
    
    resource_manager = ResourceManager()
    
    # Add test resource pools
    await resource_manager.add_resource_pool(
        pool_id="test_cpu_pool",
        resource_type=ResourceType.CPU,
        capacity=100.0,
        cost_per_unit=0.10
    )
    
    await resource_manager.add_resource_pool(
        pool_id="test_memory_pool",
        resource_type=ResourceType.MEMORY,
        capacity=200.0,
        cost_per_unit=0.05
    )
    
    # Create resource requirements
    requirements = [
        ResourceRequirement(
            resource_type=ResourceType.CPU,
            min_amount=10.0,
            max_amount=50.0,
            preferred_amount=25.0,
            priority=1
        )
    ]
    
    # Test allocation
    allocations = await resource_manager.allocate_resources(
        requirements,
        AllocationStrategy.BALANCED
    )
    
    assert len(allocations) > 0
    for allocation in allocations:
        assert allocation.allocated_amount > 0
        assert allocation.cost_per_hour >= 0
    
    logger.info(f"✓ Allocated {len(allocations)} resources successfully")
    return True


async def test_cost_optimizer():
    """Test cost optimizer functionality"""
    logger.info("Testing Cost Optimizer")
    
    cost_optimizer = CostOptimizer()
    
    # Test cost estimation
    resources = {
        'instance_count': 3,
        'cpu_cores': 4,
        'memory_gb': 8,
        'storage_gb': 100,
        'instance_type': 'on_demand'
    }
    
    estimated_cost = await cost_optimizer.estimate_cost(resources, timedelta(hours=24))
    assert estimated_cost > 0
    
    logger.info(f"✓ Estimated cost for 24 hours: ${estimated_cost:.2f}")
    
    # Test cost optimization
    current_metrics = {
        'cpu_utilization': 45.0,
        'memory_utilization': 60.0,
        'response_time': 1.2,
        'error_rate': 1.0
    }
    
    optimization_result = await cost_optimizer.optimize_resources(
        resources, current_metrics, CostOptimizationStrategy.COST_PERFORMANCE_BALANCED
    )
    
    assert optimization_result.original_cost >= 0
    assert optimization_result.optimized_cost >= 0
    assert optimization_result.savings_percentage >= 0
    
    logger.info(f"✓ Cost optimization: {optimization_result.savings_percentage:.2f}% savings")
    return True


async def test_capacity_planner():
    """Test capacity planner forecasting"""
    logger.info("Testing Capacity Planner")
    
    capacity_planner = CapacityPlanner()
    
    # Simulate current metrics
    current_metrics = {
        'cpu_utilization': 70.0,
        'memory_utilization': 65.0,
        'request_rate': 1000.0,
        'response_time': 1.5,
        'active_users': 500
    }
    
    # Test forecast generation
    forecast = await capacity_planner.generate_forecast(
        current_metrics=current_metrics,
        horizon_hours=24,
        method=ForecastMethod.MACHINE_LEARNING
    )
    
    assert 'forecasts' in forecast
    assert 'predicted_load_change' in forecast
    assert 'confidence' in forecast
    assert 0.0 <= forecast['confidence'] <= 1.0
    
    logger.info(f"✓ Forecast confidence: {forecast['confidence']:.2f}")
    return True


async def test_autoscaler():
    """Test autoscaler rules and policies"""
    logger.info("Testing Autoscaler")
    
    autoscaler = Autoscaler()
    
    # Test metrics update
    test_metrics = {
        'cpu_utilization': 85.0,
        'memory_utilization': 70.0,
        'response_time': 2.0
    }
    
    await autoscaler.update_metrics(test_metrics)
    
    # Test autoscaler status
    status = await autoscaler.get_autoscaler_status()
    assert 'enabled' in status
    assert 'active_policies' in status
    
    logger.info(f"✓ Autoscaler managing {status['active_policies']} policies")
    return True


async def test_aws_scaler():
    """Test AWS scaler simulation"""
    logger.info("Testing AWS Scaler")
    
    aws_scaler = AWSScaler(region_name='us-east-1')
    
    # Test EC2 scaling simulation
    ec2_result = await aws_scaler.scale_ec2_instances(
        auto_scaling_group_name="test-asg",
        desired_capacity=5,
        wait_for_completion=False
    )
    
    assert ec2_result['success']
    assert 'operation_id' in ec2_result
    assert ec2_result['new_capacity'] == 5
    
    logger.info(f"✓ {ec2_result['message']}")
    return True


async def test_kubernetes_scaler():
    """Test Kubernetes scaler simulation"""
    logger.info("Testing Kubernetes Scaler")
    
    k8s_scaler = KubernetesScaler()
    
    # Test deployment scaling simulation
    deployment_result = await k8s_scaler.scale_deployment(
        name="test-deployment",
        namespace="default",
        replicas=5,
        wait_for_completion=False
    )
    
    assert deployment_result['success']
    assert deployment_result['new_replicas'] == 5
    
    logger.info(f"✓ {deployment_result['message']}")
    return True


async def run_all_tests():
    """Run all dynamic scaling tests"""
    logger.info("🚀 Starting Dynamic Scaling System Tests")
    
    test_results = {}
    
    try:
        # Run individual tests
        test_results['scaling_orchestrator'] = await test_scaling_orchestrator()
        test_results['resource_manager'] = await test_resource_manager()
        test_results['cost_optimizer'] = await test_cost_optimizer()
        test_results['capacity_planner'] = await test_capacity_planner()
        test_results['autoscaler'] = await test_autoscaler()
        test_results['aws_scaler'] = await test_aws_scaler()
        test_results['kubernetes_scaler'] = await test_kubernetes_scaler()
        
        # Count results
        passed_tests = sum(1 for result in test_results.values() if result)
        total_tests = len(test_results)
        
        logger.info(f"✅ All Dynamic Scaling Tests Completed: {passed_tests}/{total_tests} passed")
        
        # Generate test report
        test_report = {
            'test_suite': 'Dynamic Scaling System Tests',
            'timestamp': datetime.now().isoformat(),
            'tests_completed': total_tests,
            'tests_passed': passed_tests,
            'tests_failed': total_tests - passed_tests,
            'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            'components_tested': [
                'Scaling Orchestrator',
                'Resource Manager',
                'Cost Optimizer',
                'Capacity Planner',
                'Autoscaler',
                'AWS Scaler (Simulated)',
                'Kubernetes Scaler (Simulated)'
            ],
            'test_results': test_results,
            'system_capabilities': {
                'dynamic_scaling': 'Operational',
                'resource_management': 'Operational',
                'cost_optimization': 'Operational',
                'capacity_planning': 'Operational',
                'autoscaling': 'Operational',
                'cloud_provider_integration': 'Simulated',
                'expert_integration': 'Available (not tested)'
            }
        }
        
        return test_report
        
    except Exception as e:
        logger.error(f"❌ Dynamic Scaling Tests Failed: {e}")
        return {
            'test_suite': 'Dynamic Scaling System Tests',
            'timestamp': datetime.now().isoformat(),
            'error': str(e),
            'status': 'failed'
        }


if __name__ == "__main__":
    # Run the tests
    test_report = asyncio.run(run_all_tests())
    
    # Save test report
    with open('dynamic_scaling_test_report.json', 'w') as f:
        json.dump(test_report, f, indent=2)
    
    print("\n" + "="*80)
    print("DYNAMIC ENVIRONMENT SCALING TEST REPORT")
    print("="*80)
    print(json.dumps(test_report, indent=2))
    print("="*80)