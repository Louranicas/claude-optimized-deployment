"""
Automated SLA validation test suite.

Provides:
- Comprehensive SLA testing framework
- Real-time validation tests
- Performance regression detection
- Automated compliance checks
"""

import asyncio
import pytest
import json
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
import statistics
import logging

from .sla import SLATracker, SLAObjective, SLAType, get_sla_tracker
from .sla_alerting import SLAAlertManager, get_sla_alert_manager
from .sla_history import SLAHistoryTracker, get_sla_history_tracker
from .sla_dashboard import SLADashboardAPI, get_sla_dashboard_api
from .prometheus_client import get_prometheus_client

__all__ = [
    "SLATestResult",
    "SLATestSuite",
    "SLAValidator",
    "run_sla_validation"
]

logger = logging.getLogger(__name__)


@dataclass
class SLATestResult:
    """Result of an SLA test."""
    test_name: str
    objective_name: str
    passed: bool
    message: str
    actual_value: Optional[float] = None
    expected_value: Optional[float] = None
    metadata: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_name": self.test_name,
            "objective_name": self.objective_name,
            "passed": self.passed,
            "message": self.message,
            "actual_value": self.actual_value,
            "expected_value": self.expected_value,
            "metadata": self.metadata or {}
        }


class SLAValidator:
    """Validates SLA implementations and calculations."""
    
    def __init__(self):
        self.sla_tracker = get_sla_tracker()
        self.alert_manager = get_sla_alert_manager()
        self.history_tracker = get_sla_history_tracker()
        self.dashboard_api = get_sla_dashboard_api()
        self.prometheus_client = get_prometheus_client()
    
    async def validate_sla_calculation(self, objective_name: str) -> SLATestResult:
        \"\"\"Validate that SLA calculation matches expected logic.\"\"\"
        if objective_name not in self.sla_tracker.objectives:
            return SLATestResult(
                test_name=\"sla_calculation_validation\",
                objective_name=objective_name,
                passed=False,
                message=f\"Objective {objective_name} not found\"
            )
        
        objective = self.sla_tracker.objectives[objective_name]
        
        try:
            # Get current report
            report = await self.sla_tracker.check_objective(objective)
            
            # Validate basic constraints
            if not (0 <= report.compliance_percent <= 100):
                return SLATestResult(
                    test_name=\"sla_calculation_validation\",
                    objective_name=objective_name,
                    passed=False,
                    message=f\"Compliance percent out of range: {report.compliance_percent}\",
                    actual_value=report.compliance_percent
                )
            
            if not (0 <= report.error_budget_remaining <= 100):
                return SLATestResult(
                    test_name=\"sla_calculation_validation\",
                    objective_name=objective_name,
                    passed=False,
                    message=f\"Error budget out of range: {report.error_budget_remaining}\",
                    actual_value=report.error_budget_remaining
                )
            
            # Validate error budget calculation
            expected_budget = self.sla_tracker.calculate_error_budget(
                objective, report.compliance_percent
            )
            
            if abs(report.error_budget_remaining - expected_budget) > 0.01:
                return SLATestResult(
                    test_name=\"sla_calculation_validation\",
                    objective_name=objective_name,
                    passed=False,
                    message=\"Error budget calculation mismatch\",
                    actual_value=report.error_budget_remaining,
                    expected_value=expected_budget
                )
            
            return SLATestResult(
                test_name=\"sla_calculation_validation\",
                objective_name=objective_name,
                passed=True,
                message=\"SLA calculation validation passed\",
                actual_value=report.compliance_percent
            )
            
        except Exception as e:
            return SLATestResult(
                test_name=\"sla_calculation_validation\",
                objective_name=objective_name,
                passed=False,
                message=f\"Validation failed with error: {e}\"
            )
    
    async def validate_prometheus_connectivity(self) -> SLATestResult:
        \"\"\"Validate Prometheus connectivity and data availability.\"\"\"
        try:
            # Test basic connectivity
            metrics = await self.prometheus_client.query(\"up\")
            
            if not metrics:
                return SLATestResult(
                    test_name=\"prometheus_connectivity\",
                    objective_name=\"system\",
                    passed=False,
                    message=\"No metrics returned from Prometheus\"
                )
            
            # Check for required metrics
            required_metrics = [
                \"http_requests_total\",
                \"http_request_duration_seconds\",
                \"up\"
            ]
            
            missing_metrics = []
            for metric in required_metrics:
                try:
                    result = await self.prometheus_client.query(metric)
                    if not result:
                        missing_metrics.append(metric)
                except Exception:
                    missing_metrics.append(metric)
            
            if missing_metrics:
                return SLATestResult(
                    test_name=\"prometheus_connectivity\",
                    objective_name=\"system\",
                    passed=False,
                    message=f\"Missing required metrics: {missing_metrics}\",
                    metadata={\"missing_metrics\": missing_metrics}
                )
            
            return SLATestResult(
                test_name=\"prometheus_connectivity\",
                objective_name=\"system\",
                passed=True,
                message=\"Prometheus connectivity validated\",
                actual_value=len(metrics)
            )
            
        except Exception as e:
            return SLATestResult(
                test_name=\"prometheus_connectivity\",
                objective_name=\"system\",
                passed=False,
                message=f\"Prometheus connectivity failed: {e}\"
            )
    
    async def validate_alerting_thresholds(self, objective_name: str) -> SLATestResult:
        \"\"\"Validate alerting threshold configuration.\"\"\"
        if objective_name not in self.alert_manager.alerting_rules:
            return SLATestResult(
                test_name=\"alerting_thresholds\",
                objective_name=objective_name,
                passed=False,
                message=f\"No alerting rule found for {objective_name}\"
            )
        
        rule = self.alert_manager.alerting_rules[objective_name]
        objective = self.sla_tracker.objectives[objective_name]
        
        # Validate threshold ordering
        thresholds = [
            rule.critical_threshold,
            rule.high_threshold,
            rule.medium_threshold
        ]
        
        if not all(thresholds[i] <= thresholds[i+1] for i in range(len(thresholds)-1)):
            return SLATestResult(
                test_name=\"alerting_thresholds\",
                objective_name=objective_name,
                passed=False,
                message=\"Alert thresholds not properly ordered\",
                metadata={\"thresholds\": thresholds}
            )
        
        # Validate thresholds are below SLA target
        if rule.medium_threshold >= objective.target:
            return SLATestResult(
                test_name=\"alerting_thresholds\",
                objective_name=objective_name,
                passed=False,
                message=\"Medium threshold should be below SLA target\",
                actual_value=rule.medium_threshold,
                expected_value=objective.target
            )
        
        return SLATestResult(
            test_name=\"alerting_thresholds\",
            objective_name=objective_name,
            passed=True,
            message=\"Alerting thresholds validated\"
        )
    
    async def validate_historical_data_consistency(self, objective_name: str) -> SLATestResult:
        \"\"\"Validate consistency of historical SLA data.\"\"\"
        try:
            # Get recent history
            history = await self.history_tracker.get_history(
                objective_name,
                start_time=datetime.now() - timedelta(hours=24),
                limit=100
            )
            
            if len(history) < 5:
                return SLATestResult(
                    test_name=\"historical_data_consistency\",
                    objective_name=objective_name,
                    passed=False,
                    message=f\"Insufficient historical data: {len(history)} points\"
                )
            
            # Check for data anomalies
            compliance_values = [point.compliance_percent for point in history]
            
            # Check for impossible values
            invalid_values = [v for v in compliance_values if not (0 <= v <= 100)]
            if invalid_values:
                return SLATestResult(
                    test_name=\"historical_data_consistency\",
                    objective_name=objective_name,
                    passed=False,
                    message=f\"Invalid compliance values found: {invalid_values}\"
                )
            
            # Check for excessive volatility (may indicate calculation issues)
            if len(compliance_values) > 1:
                std_dev = statistics.stdev(compliance_values)
                if std_dev > 20:  # More than 20% standard deviation seems suspicious
                    return SLATestResult(
                        test_name=\"historical_data_consistency\",
                        objective_name=objective_name,
                        passed=False,
                        message=f\"Excessive volatility detected: {std_dev:.2f}% std dev\",
                        actual_value=std_dev
                    )
            
            # Check timestamp ordering
            timestamps = [point.timestamp for point in history]
            if timestamps != sorted(timestamps):
                return SLATestResult(
                    test_name=\"historical_data_consistency\",
                    objective_name=objective_name,
                    passed=False,
                    message=\"Historical data timestamps not properly ordered\"
                )
            
            return SLATestResult(
                test_name=\"historical_data_consistency\",
                objective_name=objective_name,
                passed=True,
                message=\"Historical data consistency validated\",
                actual_value=len(history)
            )
            
        except Exception as e:
            return SLATestResult(
                test_name=\"historical_data_consistency\",
                objective_name=objective_name,
                passed=False,
                message=f\"Historical data validation failed: {e}\"
            )
    
    async def validate_dashboard_data_integrity(self) -> SLATestResult:
        \"\"\"Validate dashboard data integrity and consistency.\"\"\"
        try:
            dashboard_data = await self.dashboard_api.get_dashboard_data()
            
            # Validate overall health score
            if not (0 <= dashboard_data.overall_score <= 100):
                return SLATestResult(
                    test_name=\"dashboard_data_integrity\",
                    objective_name=\"dashboard\",
                    passed=False,
                    message=f\"Invalid overall score: {dashboard_data.overall_score}\"
                )
            
            # Validate objectives data structure
            if not dashboard_data.objectives:
                return SLATestResult(
                    test_name=\"dashboard_data_integrity\",
                    objective_name=\"dashboard\",
                    passed=False,
                    message=\"No objectives data in dashboard\"
                )
            
            # Check each objective has required fields
            required_fields = [
                \"compliance_percent\", \"current_value\", \"target\",
                \"error_budget_remaining\", \"is_compliant\"
            ]
            
            for obj_name, obj_data in dashboard_data.objectives.items():
                missing_fields = [field for field in required_fields if field not in obj_data]
                if missing_fields:
                    return SLATestResult(
                        test_name=\"dashboard_data_integrity\",
                        objective_name=\"dashboard\",
                        passed=False,
                        message=f\"Missing fields in {obj_name}: {missing_fields}\"
                    )
            
            return SLATestResult(
                test_name=\"dashboard_data_integrity\",
                objective_name=\"dashboard\",
                passed=True,
                message=\"Dashboard data integrity validated\"
            )
            
        except Exception as e:
            return SLATestResult(
                test_name=\"dashboard_data_integrity\",
                objective_name=\"dashboard\",
                passed=False,
                message=f\"Dashboard validation failed: {e}\"
            )
    
    async def validate_error_budget_burn_rate(self, objective_name: str) -> SLATestResult:
        \"\"\"Validate error budget burn rate calculations.\"\"\"
        try:
            burn_rate = await self.sla_tracker.get_error_budget_burn_rate(objective_name)
            
            # Burn rate should be positive
            if burn_rate < 0:
                return SLATestResult(
                    test_name=\"error_budget_burn_rate\",
                    objective_name=objective_name,
                    passed=False,
                    message=f\"Invalid burn rate: {burn_rate}\",
                    actual_value=burn_rate
                )
            
            # Extremely high burn rates may indicate calculation issues
            if burn_rate > 100:  # 100x normal rate seems excessive
                return SLATestResult(
                    test_name=\"error_budget_burn_rate\",
                    objective_name=objective_name,
                    passed=False,
                    message=f\"Suspiciously high burn rate: {burn_rate}\",
                    actual_value=burn_rate
                )
            
            return SLATestResult(
                test_name=\"error_budget_burn_rate\",
                objective_name=objective_name,
                passed=True,
                message=\"Error budget burn rate validated\",
                actual_value=burn_rate
            )
            
        except Exception as e:
            return SLATestResult(
                test_name=\"error_budget_burn_rate\",
                objective_name=objective_name,
                passed=False,
                message=f\"Burn rate validation failed: {e}\"
            )


class SLATestSuite:
    \"\"\"Comprehensive SLA test suite.\"\"\"
    
    def __init__(self):
        self.validator = SLAValidator()
        self.sla_tracker = get_sla_tracker()
    
    async def run_all_tests(self) -> Dict[str, List[SLATestResult]]:
        \"\"\"Run all SLA validation tests.\"\"\"
        results = {
            \"system_tests\": [],
            \"objective_tests\": {},
            \"integration_tests\": []
        }
        
        # System-level tests
        logger.info(\"Running system-level SLA tests\")
        
        # Prometheus connectivity
        prom_result = await self.validator.validate_prometheus_connectivity()
        results[\"system_tests\"].append(prom_result)
        
        # Dashboard integrity
        dashboard_result = await self.validator.validate_dashboard_data_integrity()
        results[\"system_tests\"].append(dashboard_result)
        
        # Per-objective tests
        logger.info(\"Running per-objective SLA tests\")
        
        for objective_name in self.sla_tracker.objectives.keys():
            obj_results = []
            
            # SLA calculation validation
            calc_result = await self.validator.validate_sla_calculation(objective_name)
            obj_results.append(calc_result)
            
            # Alerting thresholds
            alert_result = await self.validator.validate_alerting_thresholds(objective_name)
            obj_results.append(alert_result)
            
            # Historical data consistency
            hist_result = await self.validator.validate_historical_data_consistency(objective_name)
            obj_results.append(hist_result)
            
            # Error budget burn rate
            burn_result = await self.validator.validate_error_budget_burn_rate(objective_name)
            obj_results.append(burn_result)
            
            results[\"objective_tests\"][objective_name] = obj_results
        
        # Integration tests
        logger.info(\"Running integration tests\")
        
        # End-to-end SLA workflow test
        e2e_result = await self._test_end_to_end_workflow()
        results[\"integration_tests\"].append(e2e_result)
        
        return results
    
    async def _test_end_to_end_workflow(self) -> SLATestResult:
        \"\"\"Test complete SLA workflow from calculation to alerting.\"\"\"
        try:
            # Pick the first available objective
            if not self.sla_tracker.objectives:
                return SLATestResult(
                    test_name=\"end_to_end_workflow\",
                    objective_name=\"system\",
                    passed=False,
                    message=\"No SLA objectives configured\"
                )
            
            objective_name = list(self.sla_tracker.objectives.keys())[0]
            objective = self.sla_tracker.objectives[objective_name]
            
            # 1. Calculate SLA
            report = await self.sla_tracker.check_objective(objective)
            
            # 2. Record in history
            await self.validator.history_tracker.record_sla_measurement(report)
            
            # 3. Check alerting
            alerts = await self.validator.alert_manager.check_all_slas()
            
            # 4. Get dashboard data
            dashboard_data = await self.validator.dashboard_api.get_dashboard_data()
            
            # Verify data flow
            if objective_name not in dashboard_data.objectives:
                return SLATestResult(
                    test_name=\"end_to_end_workflow\",
                    objective_name=objective_name,
                    passed=False,
                    message=\"Objective not found in dashboard data\"
                )
            
            return SLATestResult(
                test_name=\"end_to_end_workflow\",
                objective_name=objective_name,
                passed=True,
                message=\"End-to-end workflow validated successfully\"
            )
            
        except Exception as e:
            return SLATestResult(
                test_name=\"end_to_end_workflow\",
                objective_name=\"system\",
                passed=False,
                message=f\"End-to-end test failed: {e}\"
            )
    
    def generate_test_report(self, results: Dict[str, Any]) -> str:
        \"\"\"Generate a comprehensive test report.\"\"\"
        total_tests = 0
        passed_tests = 0
        failed_tests = []
        
        # Count system tests
        for result in results[\"system_tests\"]:
            total_tests += 1
            if result.passed:
                passed_tests += 1
            else:
                failed_tests.append(result)
        
        # Count objective tests
        for obj_name, obj_results in results[\"objective_tests\"].items():
            for result in obj_results:
                total_tests += 1
                if result.passed:
                    passed_tests += 1
                else:
                    failed_tests.append(result)
        
        # Count integration tests
        for result in results[\"integration_tests\"]:
            total_tests += 1
            if result.passed:
                passed_tests += 1
            else:
                failed_tests.append(result)
        
        # Generate report
        report_lines = [
            \"# SLA Validation Test Report\",
            f\"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\",
            \"\",
            \"## Summary\",
            f\"- **Total Tests**: {total_tests}\",
            f\"- **Passed**: {passed_tests}\",
            f\"- **Failed**: {len(failed_tests)}\",
            f\"- **Success Rate**: {(passed_tests/total_tests*100):.1f}%\" if total_tests > 0 else \"- **Success Rate**: N/A\",
            \"\"
        ]
        
        if failed_tests:
            report_lines.extend([
                \"## Failed Tests\",
                \"\"
            ])
            
            for failure in failed_tests:
                report_lines.extend([
                    f\"### ❌ {failure.test_name} ({failure.objective_name})\",
                    f\"**Message**: {failure.message}\",
                    \"\"
                ])
                
                if failure.actual_value is not None:
                    report_lines.append(f\"**Actual Value**: {failure.actual_value}\")
                
                if failure.expected_value is not None:
                    report_lines.append(f\"**Expected Value**: {failure.expected_value}\")
                
                report_lines.append(\"\")
        
        return \"\
\".join(report_lines)


# Convenience function for running validation
async def run_sla_validation() -> Dict[str, Any]:
    \"\"\"Run complete SLA validation suite.\"\"\"
    test_suite = SLATestSuite()
    results = await test_suite.run_all_tests()
    
    # Generate summary
    summary = {
        \"timestamp\": datetime.now().isoformat(),
        \"results\": {}
    }
    
    # Convert results to dictionaries for JSON serialization
    for category, tests in results.items():
        if isinstance(tests, list):
            summary[\"results\"][category] = [test.to_dict() for test in tests]
        else:
            summary[\"results\"][category] = {
                obj_name: [test.to_dict() for test in obj_tests]
                for obj_name, obj_tests in tests.items()
            }
    
    # Generate text report
    summary[\"report\"] = test_suite.generate_test_report(results)
    
    return summary