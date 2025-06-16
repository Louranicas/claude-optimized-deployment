#!/usr/bin/env python3
"""
SLI/SLO Tracking System Example

This example demonstrates how to use the comprehensive SLI/SLO tracking system
with error budget management, alerting, and integration with monitoring tools.
"""

import asyncio
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from src.monitoring.sli_slo_tracking import (
    SLOTrackingSystem,
    SLIDefinition,
    SLOTarget,
    ErrorBudgetPolicy,
    SLIType,
    TimeWindow,
    AlertSeverity,
    SLIDataPoint
)
from src.monitoring.slo_integration import (
    SLOIntegrationOrchestrator,
    INTEGRATION_CONFIG_EXAMPLE
)


async def basic_slo_tracking_example():
    """Basic example of SLO tracking."""
    print("🎯 SLI/SLO Tracking System - Basic Example")
    print("=" * 50)
    
    # Initialize the tracking system
    system = SLOTrackingSystem()
    await system.initialize()
    
    # Define custom SLIs
    api_availability_sli = SLIDefinition(
        name="example_api_availability",
        type=SLIType.AVAILABILITY,
        description="Example API availability",
        unit="ratio",
        query='up{job="example-api"}',
        aggregation="avg"
    )
    
    api_latency_sli = SLIDefinition(
        name="example_api_latency",
        type=SLIType.LATENCY,
        description="Example API P95 latency",
        unit="seconds",
        query='histogram_quantile(0.95, http_request_duration_seconds_bucket{job="example-api"})',
        aggregation="p95"
    )
    
    # Register SLIs
    system.sli_collector.register_sli(api_availability_sli)
    system.sli_collector.register_sli(api_latency_sli)
    
    # Define SLO targets
    availability_slo = SLOTarget(
        sli_name="example_api_availability",
        target=99.9,
        comparison="gte",
        time_window=TimeWindow.ROLLING_30D,
        description="API should be available 99.9% of the time"
    )
    
    latency_slo = SLOTarget(
        sli_name="example_api_latency",
        target=0.5,
        comparison="lte",
        time_window=TimeWindow.ROLLING_24H,
        description="API P95 latency should be less than 500ms"
    )
    
    # Register SLOs
    system.slo_calculator.register_slo(availability_slo)
    system.slo_calculator.register_slo(latency_slo)
    
    # Define error budget policy
    policy = ErrorBudgetPolicy(
        name="example_api_policy",
        slo_name="example_api_availability",
        actions=[
            {
                "budget_threshold": 50,
                "type": "notify_team",
                "message": "Error budget 50% consumed"
            },
            {
                "budget_threshold": 10,
                "type": "deployment_freeze",
                "message": "Deployment freeze activated"
            }
        ],
        freeze_threshold=0.1,
        alert_thresholds={
            0.5: AlertSeverity.WARNING,
            0.2: AlertSeverity.ERROR,
            0.1: AlertSeverity.CRITICAL
        }
    )
    
    # Register error budget policy
    system.error_budget_manager.register_policy(policy)
    
    # Simulate SLI data collection and compliance calculation
    print("\n📊 Simulating SLI data collection...")
    
    # Generate mock SLI data
    current_time = datetime.utcnow()
    mock_availability_data = []
    mock_latency_data = []
    
    # Generate 24 hours of data points (hourly)
    for i in range(24):
        timestamp = current_time - timedelta(hours=23-i)
        
        # Simulate 99.95% availability with occasional dips
        availability = 99.98 if i != 5 else 99.8  # Dip at hour 5
        mock_availability_data.append(SLIDataPoint(
            timestamp=timestamp,
            value=availability
        ))
        
        # Simulate latency with some variation
        latency = 0.3 + (i % 3) * 0.1  # 0.3s to 0.5s
        if i == 5:  # Spike during the availability dip
            latency = 0.8
        mock_latency_data.append(SLIDataPoint(
            timestamp=timestamp,
            value=latency
        ))
    
    # Calculate compliance for availability SLO
    availability_compliance = system.slo_calculator.calculate_compliance(
        mock_availability_data,
        availability_slo,
        current_time
    )
    
    # Calculate compliance for latency SLO
    latency_compliance = system.slo_calculator.calculate_compliance(
        mock_latency_data,
        latency_slo,
        current_time
    )
    
    # Display results
    print(f"\n✅ Availability SLO Compliance:")
    print(f"   Current: {availability_compliance.compliance_percentage:.2f}%")
    print(f"   Target: {availability_compliance.target_value}%")
    print(f"   Compliant: {'✅' if availability_compliance.is_compliant else '❌'}")
    print(f"   Error Budget Remaining: {availability_compliance.error_budget_remaining:.2f}%")
    print(f"   Trend: {availability_compliance.trend}")
    
    print(f"\n⏱️  Latency SLO Compliance:")
    print(f"   Current: {latency_compliance.compliance_percentage:.2f}%")
    print(f"   Target: {latency_compliance.target_value}%")
    print(f"   Compliant: {'✅' if latency_compliance.is_compliant else '❌'}")
    print(f"   Error Budget Remaining: {latency_compliance.error_budget_remaining:.2f}%")
    print(f"   Trend: {latency_compliance.trend}")
    
    # Record compliance for reporting
    system.reporter.record_compliance(availability_compliance)
    system.reporter.record_compliance(latency_compliance)
    
    # Evaluate error budget actions
    budget_actions = await system.error_budget_manager.evaluate_budget(availability_compliance)
    if budget_actions:
        print(f"\n⚠️  Error Budget Actions Triggered:")
        for action in budget_actions:
            print(f"   - {action['type']}: {action['message']}")
    
    # Generate a report
    print(f"\n📋 Generating SLO Report...")
    report = system.reporter.generate_report(
        time_range=(current_time - timedelta(days=1), current_time),
        format="json"
    )
    
    print(f"   Report covers {len(report['slos'])} SLOs")
    for slo_key, slo_data in report['slos'].items():
        print(f"   - {slo_data['slo_name']}: {slo_data['current_status']['compliance']:.2f}% compliance")
    
    await system.stop()
    print("\n✅ Basic SLO tracking example completed!")


async def error_budget_management_example():
    """Example demonstrating error budget management."""
    print("\n💰 Error Budget Management Example")
    print("=" * 40)
    
    system = SLOTrackingSystem()
    await system.initialize()
    
    # Create a scenario where error budget is being consumed
    sli = SLIDefinition(
        name="critical_service_availability",
        type=SLIType.AVAILABILITY,
        description="Critical service availability",
        unit="ratio",
        query='up{service="critical"}',
        aggregation="avg"
    )
    
    slo = SLOTarget(
        sli_name="critical_service_availability",
        target=99.9,
        comparison="gte",
        time_window=TimeWindow.ROLLING_30D,
        description="Critical service 99.9% availability"
    )
    
    policy = ErrorBudgetPolicy(
        name="critical_service_policy",
        slo_name="critical_service_availability",
        actions=[
            {
                "budget_threshold": 50,
                "type": "alert_team",
                "message": "Error budget half consumed"
            },
            {
                "budget_threshold": 20,
                "type": "escalate_oncall",
                "message": "Error budget critically low"
            },
            {
                "budget_threshold": 10,
                "type": "deployment_freeze",
                "message": "Emergency deployment freeze"
            }
        ],
        freeze_threshold=0.1
    )
    
    system.sli_collector.register_sli(sli)
    system.slo_calculator.register_slo(slo)
    system.error_budget_manager.register_policy(policy)
    
    # Simulate different error budget scenarios
    scenarios = [
        ("Healthy Operation", 99.95, "Normal operations"),
        ("Minor Issues", 99.85, "Some degradation"),
        ("Significant Issues", 99.5, "Major incident"),
        ("Critical Outage", 98.0, "Critical outage")
    ]
    
    for scenario_name, availability, description in scenarios:
        print(f"\n🎭 Scenario: {scenario_name}")
        print(f"   Description: {description}")
        print(f"   Availability: {availability}%")
        
        # Generate data for this scenario
        current_time = datetime.utcnow()
        scenario_data = []
        
        for i in range(24):
            timestamp = current_time - timedelta(hours=23-i)
            scenario_data.append(SLIDataPoint(
                timestamp=timestamp,
                value=availability
            ))
        
        # Calculate compliance
        compliance = system.slo_calculator.calculate_compliance(
            scenario_data,
            slo,
            current_time
        )
        
        # Evaluate budget actions
        actions = await system.error_budget_manager.evaluate_budget(compliance)
        
        print(f"   Compliance: {compliance.compliance_percentage:.2f}%")
        print(f"   Error Budget Remaining: {compliance.error_budget_remaining:.2f}%")
        
        if actions:
            print(f"   Triggered Actions:")
            for action in actions:
                print(f"     - {action['type']}: {action['message']}")
        else:
            print(f"   No actions triggered")
        
        # Check burn rate
        burn_rate = system.error_budget_manager.get_budget_burn_rate(
            "critical_service_policy",
            timedelta(hours=1)
        )
        print(f"   Burn Rate: {burn_rate:.2f}% per hour")
    
    await system.stop()
    print("\n✅ Error budget management example completed!")


async def governance_and_reporting_example():
    """Example demonstrating SLO governance and reporting."""
    print("\n🏛️  SLO Governance and Reporting Example")
    print("=" * 45)
    
    system = SLOTrackingSystem()
    await system.initialize()
    
    # Set up some SLOs for governance demonstration
    slis_and_slos = [
        ("api_availability", 99.9, "API availability SLO"),
        ("api_latency", 95.0, "API latency SLO (95% under 500ms)"),
        ("database_availability", 99.95, "Database availability SLO")
    ]
    
    for sli_name, target, description in slis_and_slos:
        sli = SLIDefinition(
            name=sli_name,
            type=SLIType.AVAILABILITY,
            description=description,
            unit="ratio",
            query=f'up{{service="{sli_name}"}}',
            aggregation="avg"
        )
        
        slo = SLOTarget(
            sli_name=sli_name,
            target=target,
            comparison="gte",
            time_window=TimeWindow.ROLLING_30D,
            description=description
        )
        
        system.sli_collector.register_sli(sli)
        system.slo_calculator.register_slo(slo)
        
        # Generate mock compliance data
        current_time = datetime.utcnow()
        mock_data = []
        for i in range(72):  # 3 days of hourly data
            timestamp = current_time - timedelta(hours=71-i)
            # Add some variation and occasional dips
            value = target + (i % 10) * 0.01 - 0.05
            if i % 20 == 5:  # Occasional dip
                value -= 0.5
            mock_data.append(SLIDataPoint(timestamp=timestamp, value=value))
        
        compliance = system.slo_calculator.calculate_compliance(mock_data, slo, current_time)
        system.reporter.record_compliance(compliance)
    
    # Governance operations
    print("\n📅 SLO Governance Operations:")
    
    # Schedule reviews
    review_date = datetime.utcnow() + timedelta(days=7)
    system.governance.schedule_review(
        "api_availability",
        review_date,
        ["sre-lead", "product-manager"],
        "quarterly"
    )
    
    # Propose an SLO change
    change_id = system.governance.propose_slo_change(
        "api_latency",
        {"target": 97.0, "justification": "Improved infrastructure"},
        "Increase target based on performance improvements",
        "sre-engineer"
    )
    
    # Approve the change
    system.governance.approve_change(change_id, "sre-lead", "Approved for Q2")
    
    # Check pending reviews
    pending = system.governance.get_pending_reviews()
    print(f"   Pending Reviews: {len(pending)}")
    for review in pending:
        print(f"     - {review['slo_name']}: {review['review_date'].strftime('%Y-%m-%d')}")
    
    print(f"   Change Proposals: {len(system.governance.slo_changes)}")
    for change in system.governance.slo_changes:
        print(f"     - {change['change_id']}: {change['status']}")
    
    # Generate comprehensive report
    print(f"\n📊 Generating Comprehensive Report...")
    report = system.reporter.generate_report(
        time_range=(datetime.utcnow() - timedelta(days=3), datetime.utcnow()),
        format="markdown"
    )
    
    print(f"   Report generated ({len(report)} characters)")
    
    # Analyze trends for each SLO
    print(f"\n📈 Trend Analysis:")
    for sli_name, _, _ in slis_and_slos:
        try:
            analysis = system.reporter.analyze_trends(
                sli_name,
                TimeWindow.ROLLING_30D,
                timedelta(days=3)
            )
            
            if "error" not in analysis:
                print(f"   {sli_name}:")
                print(f"     Trend: {analysis['trend']['overall']}")
                print(f"     Current: {analysis['trend']['current_compliance']:.2f}%")
                print(f"     Volatility: {analysis['trend']['volatility']:.2f}%")
        except Exception as e:
            print(f"   {sli_name}: Analysis failed - {e}")
    
    await system.stop()
    print("\n✅ Governance and reporting example completed!")


async def integration_example():
    """Example demonstrating integrations with external systems."""
    print("\n🔗 Integration Example")
    print("=" * 25)
    
    # Configure integrations (using mock configuration)
    config = {
        "prometheus": {
            "url": "http://localhost:9090",
            "pushgateway_url": "http://localhost:9091"
        },
        "slack": {
            "webhook_urls": {
                "sre-alerts": "https://hooks.slack.com/mock/sre",
                "deployments": "https://hooks.slack.com/mock/deploy"
            }
        },
        "deployment": {
            "webhook_url": "https://ci-cd.example.com/webhook"
        }
    }
    
    # Initialize integration orchestrator
    orchestrator = SLOIntegrationOrchestrator(config)
    
    # Create a mock compliance that would trigger alerts
    from src.monitoring.sli_slo_tracking import SLOCompliance
    
    mock_compliance = SLOCompliance(
        slo_name="api_availability",
        current_value=99.5,
        target_value=99.9,
        is_compliant=False,
        compliance_percentage=95.0,
        error_budget_remaining=5.0,
        error_budget_consumed=95.0,
        time_window=TimeWindow.ROLLING_30D,
        calculated_at=datetime.utcnow(),
        trend="degrading"
    )
    
    print(f"📡 Processing SLO Events:")
    print(f"   SLO: {mock_compliance.slo_name}")
    print(f"   Compliance: {mock_compliance.compliance_percentage}%")
    print(f"   Error Budget: {mock_compliance.error_budget_remaining}%")
    
    # Process different types of events
    events = [
        ("slo_breach", "SLO target breached"),
        ("error_budget_low", "Error budget critically low"),
        ("deployment_freeze", "Deployment freeze activated")
    ]
    
    for event_type, description in events:
        print(f"\n   Processing: {event_type}")
        print(f"   Description: {description}")
        
        try:
            await orchestrator.process_slo_event(
                event_type,
                mock_compliance,
                {"source": "example", "environment": "production"}
            )
            print(f"   ✅ Event processed successfully")
        except Exception as e:
            print(f"   ⚠️  Event processing failed: {e}")
    
    print("\n✅ Integration example completed!")


async def dashboard_data_example():
    """Example demonstrating dashboard data generation."""
    print("\n📊 Dashboard Data Example")
    print("=" * 30)
    
    system = SLOTrackingSystem()
    await system.initialize()
    
    # Set up mock data for dashboard
    slos = ["api_availability", "api_latency", "database_availability"]
    
    for slo_name in slos:
        sli = SLIDefinition(
            name=slo_name,
            type=SLIType.AVAILABILITY,
            description=f"{slo_name} SLI",
            unit="ratio",
            query=f'up{{service="{slo_name}"}}',
            aggregation="avg"
        )
        
        slo = SLOTarget(
            sli_name=slo_name,
            target=99.9,
            comparison="gte",
            time_window=TimeWindow.ROLLING_24H,
            description=f"{slo_name} SLO"
        )
        
        system.sli_collector.register_sli(sli)
        system.slo_calculator.register_slo(slo)
        
        # Generate compliance data
        current_time = datetime.utcnow()
        mock_data = []
        
        for i in range(24):
            timestamp = current_time - timedelta(hours=23-i)
            # Vary compliance to create interesting dashboard data
            base_value = 99.9
            if slo_name == "api_latency":
                base_value = 99.0  # Lower compliance
            if i % 8 == 0:
                base_value -= 0.5  # Periodic dips
            
            mock_data.append(SLIDataPoint(timestamp=timestamp, value=base_value))
        
        compliance = system.slo_calculator.calculate_compliance(mock_data, slo, current_time)
        system.reporter.record_compliance(compliance)
    
    # Generate dashboard data
    dashboard_data = system.dashboard.get_dashboard_data()
    
    print(f"📈 Dashboard Summary:")
    print(f"   Total SLOs: {dashboard_data['summary']['total_slos']}")
    print(f"   Compliant SLOs: {dashboard_data['summary']['compliant_slos']}")
    print(f"   Compliance Rate: {dashboard_data['summary']['compliance_rate']:.1f}%")
    print(f"   At Risk: {dashboard_data['summary']['at_risk_count']}")
    print(f"   Breaching: {dashboard_data['summary']['breaching_count']}")
    
    print(f"\n📊 SLO Status Breakdown:")
    for status, slos in dashboard_data['slos_by_status'].items():
        print(f"   {status.title()}: {len(slos)} SLOs")
        for slo in slos:
            print(f"     - {slo['slo_name']}: {slo['current_status']['compliance']:.1f}%")
    
    # Generate time series data for one SLO
    time_series = system.dashboard.get_time_series_data(
        "api_availability",
        TimeWindow.ROLLING_24H,
        points=24
    )
    
    print(f"\n📈 Time Series Data for api_availability:")
    print(f"   Data Points: {len(time_series)}")
    if time_series:
        latest = time_series[-1]
        print(f"   Latest: {latest['compliance']:.2f}% at {latest['timestamp']}")
    
    await system.stop()
    print("\n✅ Dashboard data example completed!")


async def main():
    """Run all examples."""
    print("🎯 SLI/SLO Tracking System - Comprehensive Examples")
    print("=" * 60)
    print()
    
    try:
        # Run all examples
        await basic_slo_tracking_example()
        await error_budget_management_example()
        await governance_and_reporting_example()
        await integration_example()
        await dashboard_data_example()
        
        print("\n🎉 All examples completed successfully!")
        print("\nNext steps:")
        print("1. Configure real data sources (Prometheus, etc.)")
        print("2. Set up notification channels (Slack, PagerDuty)")
        print("3. Deploy Grafana dashboards")
        print("4. Configure CI/CD integration")
        print("5. Establish SLO governance processes")
        
    except Exception as e:
        print(f"\n❌ Example failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())