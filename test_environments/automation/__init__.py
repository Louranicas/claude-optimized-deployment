"""
Test Automation Framework - Comprehensive automated test execution pipeline.

This module provides a complete test automation framework with intelligent scheduling,
real-time reporting, CI/CD integration, and advanced analytics.
"""

from .test_orchestrator import (
    TestOrchestrator,
    TestSuite,
    TestExecution,
    TestStatus,
    TestPriority
)

from .scheduler import (
    TestScheduler,
    ScheduleStrategy,
    ScheduledTest,
    ResourceRequirement
)

from .execution_engine import (
    ExecutionEngine,
    TestExecutor,
    TestResult,
    TestType,
    ExecutionStatus
)

from .result_processor import (
    ResultProcessor,
    ProcessedResults,
    TestMetric,
    Anomaly,
    TrendAnalysis,
    PerformanceBaseline
)

from .report_generator import (
    ReportGenerator,
    ReportFormat,
    ChartType
)

# Pipeline imports
from .pipelines.stress_test_pipeline import (
    StressTestPipeline,
    StressTestConfig,
    StressTestResult,
    StressTestType,
    LoadPattern
)

from .pipelines.chaos_test_pipeline import (
    ChaosTestPipeline,
    ChaosExperimentConfig,
    ChaosExperimentResult,
    ChaosExperimentType,
    ImpactLevel
)

# CI/CD integration imports
from .ci_cd.github_actions import (
    GitHubActionsIntegration,
    GitHubActionsConfig,
    WorkflowRun,
    TestExecutionRequest,
    WorkflowEvent
)

__version__ = "1.0.0"
__author__ = "Claude Test Automation Team"

__all__ = [
    # Core components
    "TestOrchestrator",
    "TestSuite", 
    "TestExecution",
    "TestStatus",
    "TestPriority",
    
    # Scheduler
    "TestScheduler",
    "ScheduleStrategy", 
    "ScheduledTest",
    "ResourceRequirement",
    
    # Execution Engine
    "ExecutionEngine",
    "TestExecutor",
    "TestResult", 
    "TestType",
    "ExecutionStatus",
    
    # Result Processing
    "ResultProcessor",
    "ProcessedResults",
    "TestMetric",
    "Anomaly", 
    "TrendAnalysis",
    "PerformanceBaseline",
    
    # Report Generation
    "ReportGenerator",
    "ReportFormat",
    "ChartType",
    
    # Pipeline Implementations
    "StressTestPipeline",
    "StressTestConfig",
    "StressTestResult", 
    "StressTestType",
    "LoadPattern",
    
    "ChaosTestPipeline",
    "ChaosExperimentConfig",
    "ChaosExperimentResult",
    "ChaosExperimentType", 
    "ImpactLevel",
    
    # CI/CD Integration
    "GitHubActionsIntegration",
    "GitHubActionsConfig",
    "WorkflowRun",
    "TestExecutionRequest",
    "WorkflowEvent"
]


# Framework configuration
DEFAULT_CONFIG = {
    "orchestrator": {
        "max_workers": 10,
        "max_processes": 4,
        "execution_timeout": 7200,
        "resource_limits": {
            "cpu_percent": 80,
            "memory_percent": 75,
            "disk_percent": 90
        }
    },
    "scheduler": {
        "strategy": "intelligent",
        "max_concurrent_tests": 16,
        "analysis_period_days": 30
    },
    "result_processor": {
        "anomaly_thresholds": {
            "performance": 0.20,
            "memory": 0.25,
            "cpu": 0.30,
            "duration": 0.15
        },
        "baseline_file": "test_baselines.json"
    },
    "report_generator": {
        "formats": ["html", "json", "pdf"],
        "template_dir": "templates",
        "output_dir": "reports"
    }
}


def create_automation_framework(config=None):
    """
    Create a complete test automation framework instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured TestOrchestrator instance
    """
    framework_config = DEFAULT_CONFIG.copy()
    if config:
        framework_config.update(config)
        
    return TestOrchestrator(framework_config)


def create_stress_test_suite():
    """
    Create a comprehensive stress test suite.
    
    Returns:
        List of StressTestConfig instances
    """
    pipeline = StressTestPipeline()
    return pipeline.create_comprehensive_stress_suite()


def create_chaos_experiment_suite():
    """
    Create a comprehensive chaos experiment suite.
    
    Returns:
        List of ChaosExperimentConfig instances
    """
    pipeline = ChaosTestPipeline()
    return pipeline.create_chaos_experiment_suite()


# Quick start example
async def quick_start_example():
    """
    Quick start example demonstrating the automation framework.
    """
    import asyncio
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create automation framework
    orchestrator = create_automation_framework()
    
    # Create a sample test suite
    test_suite = TestSuite(
        id="quick-start-001",
        name="Quick Start Test Suite",
        tests=[
            "test_basic_functionality",
            "test_performance_baseline",
            "test_error_handling"
        ],
        priority=TestPriority.HIGH,
        timeout=300,
        parallel=True,
        max_parallel=2
    )
    
    # Register and execute
    orchestrator.register_suite(test_suite)
    execution_id = orchestrator.schedule_suite("quick-start-001", immediate=True)
    
    # Monitor execution
    while True:
        status = orchestrator.get_execution_status(execution_id)
        if status:
            print(f"Status: {status['status']}, Progress: {status['progress']}")
            if status['status'] in ['completed', 'failed', 'cancelled']:
                break
        await asyncio.sleep(5)
        
    print("Quick start example completed!")
    orchestrator.shutdown()