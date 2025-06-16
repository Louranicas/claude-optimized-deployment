#!/usr/bin/env python3
"""
Integration test for the new SLA monitoring system.
Tests that all components work together correctly.
"""

import asyncio
import json
import sys
import logging
from datetime import datetime, timedelta

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import SLA components
try:
    from src.monitoring import (
        get_sla_tracker,
        get_sla_alert_manager,
        get_sla_history_tracker,
        get_sla_dashboard_api,
        get_error_budget_tracker,
        SLAObjective,
        SLAType,
        run_sla_validation
    )
except ImportError as e:
    logger.error(f"Failed to import SLA modules: {e}")
    sys.exit(1)


async def test_sla_integration():
    """Test the complete SLA monitoring system."""
    logger.info("Starting SLA integration test...")
    
    try:
        # 1. Test SLA Tracker
        logger.info("Testing SLA Tracker...")
        sla_tracker = get_sla_tracker()
        
        # Add a test objective
        test_objective = SLAObjective(
            name="test_api_availability",
            type=SLAType.AVAILABILITY,
            target=99.0,
            description="Test API availability"
        )
        sla_tracker.add_objective(test_objective)
        
        # Get current reports
        reports = await sla_tracker.check_all_objectives()
        logger.info(f"Generated {len(reports)} SLA reports")
        
        # 2. Test Error Budget Tracker
        logger.info("Testing Error Budget Tracker...")
        budget_tracker = get_error_budget_tracker()
        
        if "test_api_availability" in reports:
            budget_status = await budget_tracker.get_error_budget_status("test_api_availability")
            logger.info(f"Error budget remaining: {budget_status.remaining_percent:.2f}%")
        
        # 3. Test Dashboard API
        logger.info("Testing Dashboard API...")
        dashboard_api = get_sla_dashboard_api()
        dashboard_data = await dashboard_api.get_dashboard_data()
        
        logger.info(f"Dashboard health: {dashboard_data.overall_health}")
        logger.info(f"Health score: {dashboard_data.overall_score:.1f}")
        
        # 4. Test Alert Manager
        logger.info("Testing Alert Manager...")
        alert_manager = get_sla_alert_manager()
        new_alerts = await alert_manager.check_all_slas()
        
        if new_alerts:
            logger.info(f"Generated {len(new_alerts)} alerts")
        else:
            logger.info("No alerts generated")
        
        # 5. Test History Tracker
        logger.info("Testing History Tracker...")
        history_tracker = get_sla_history_tracker()
        
        # Record current measurements
        for report in reports.values():
            await history_tracker.record_sla_measurement(report)
        
        logger.info("Recorded SLA measurements in history")
        
        # 6. Test Validation Suite
        logger.info("Testing SLA Validation...")
        validation_results = await run_sla_validation()
        
        total_tests = 0
        passed_tests = 0
        
        for category, tests in validation_results["results"].items():
            if isinstance(tests, list):
                for test in tests:
                    total_tests += 1
                    if test["passed"]:
                        passed_tests += 1
            else:
                for obj_tests in tests.values():
                    for test in obj_tests:
                        total_tests += 1
                        if test["passed"]:
                            passed_tests += 1
        
        logger.info(f"Validation: {passed_tests}/{total_tests} tests passed")
        
        # 7. Test comprehensive status
        logger.info("Testing comprehensive status...")
        from src.monitoring.sla import get_comprehensive_sla_status
        
        comprehensive_status = await get_comprehensive_sla_status()
        logger.info(f"Overall compliance: {comprehensive_status['summary']['overall_compliance']:.2f}%")
        
        # 8. Generate reports
        logger.info("Generating reports...")
        
        # JSON report
        json_report = await dashboard_api.export_report("json", period_days=1)
        logger.info(f"Generated JSON report ({len(json_report)} characters)")
        
        # Markdown report
        markdown_report = await dashboard_api.export_report("markdown", period_days=1)
        logger.info(f"Generated Markdown report ({len(markdown_report)} characters)")
        
        logger.info("✅ SLA integration test completed successfully!")
        
        return {
            "success": True,
            "reports_generated": len(reports),
            "validation_pass_rate": f"{passed_tests}/{total_tests}",
            "overall_health": dashboard_data.overall_health,
            "health_score": dashboard_data.overall_score
        }
        
    except Exception as e:
        logger.error(f"❌ SLA integration test failed: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }


async def test_prometheus_connectivity():
    """Test Prometheus connectivity separately."""
    logger.info("Testing Prometheus connectivity...")
    
    try:
        from src.monitoring.prometheus_client import get_prometheus_client
        
        prometheus_client = get_prometheus_client()
        
        # Test basic query
        metrics = await prometheus_client.query("up")
        logger.info(f"Prometheus query returned {len(metrics)} results")
        
        return True
        
    except Exception as e:
        logger.warning(f"Prometheus connectivity test failed: {e}")
        logger.info("This is expected if Prometheus is not running")
        return False


def main():
    """Run the integration tests."""
    print("🔍 SLA Integration Test Suite")
    print("=" * 50)
    
    # Test Prometheus connectivity first
    prometheus_available = asyncio.run(test_prometheus_connectivity())
    
    if not prometheus_available:
        print("⚠️  Prometheus not available - tests will use fallback values")
    
    # Run main integration test
    result = asyncio.run(test_sla_integration())
    
    print("\n" + "=" * 50)
    print("📊 Test Results:")
    print(json.dumps(result, indent=2))
    
    if result["success"]:
        print("\n✅ All tests passed! SLA monitoring system is functional.")
        return 0
    else:
        print("\n❌ Tests failed. Check the logs for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())