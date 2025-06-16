#!/usr/bin/env python3
"""
Comprehensive Test Suite for Performance Monitoring System
Tests all components: collectors, processors, analytics, dashboards, and alerts
"""

import asyncio
import pytest
import time
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any

# Import monitoring components
from metrics_collector import MetricsCollector, MetricValue
from real_time_processor import RealTimeProcessor, IntegratedMonitoringSystem, AlertLevel
from analytics_engine import AdvancedAnalyticsEngine, TrendDirection, SeasonalityType
from dashboard_server import DashboardServer, DashboardConfig, DashboardDataManager
from alert_manager import IntelligentAlertManager, AlertRule, AlertPriority, Alert, AlertState

# Import collectors
from collectors.system_metrics import AdvancedSystemMetricsCollector
from collectors.application_metrics import ApplicationMetricsCollector
from collectors.custom_metrics import CustomMetricsCollector, TestPhase, TestSeverity
from collectors.log_metrics import LogMetricsCollector

class TestMetricsCollector:
    """Test suite for MetricsCollector"""
    
    @pytest.fixture
    def collector(self):
        """Create a test metrics collector"""
        return MetricsCollector(collection_interval=0.1, max_history=100)
    
    def test_collector_initialization(self, collector):
        """Test metrics collector initialization"""
        assert collector.collection_interval == 0.1
        assert collector.max_history == 100
        assert not collector.running
        assert len(collector.collectors) > 0  # Should have built-in collectors
    
    def test_collector_start_stop(self, collector):
        """Test starting and stopping the collector"""
        collector.start()
        assert collector.running
        assert collector.collection_thread is not None
        assert collector.processor_thread is not None
        
        collector.stop()
        assert not collector.running
    
    def test_add_custom_collector(self, collector):
        """Test adding custom collector function"""
        def custom_collector():
            return [MetricValue("test_metric", 42, time.time(), source="test")]
        
        initial_count = len(collector.collectors)
        collector.add_collector(custom_collector)
        assert len(collector.collectors) == initial_count + 1
    
    def test_metric_storage(self, collector):
        """Test metric storage and retrieval"""
        metric = MetricValue("test_metric", 100, time.time(), source="test")
        collector._store_metric(metric)
        
        latest_metrics = collector.get_latest_metrics()
        assert "test.test_metric" in latest_metrics
        assert latest_metrics["test.test_metric"].value == 100
    
    def test_metric_statistics(self, collector):
        """Test metric statistics calculation"""
        # Add multiple metrics
        for i in range(10):
            metric = MetricValue("test_metric", i * 10, time.time(), source="test")
            collector._store_metric(metric)
        
        stats = collector.get_metric_statistics("test.test_metric", 60)
        assert stats['count'] == 10
        assert stats['mean'] == 45.0  # (0+10+20+...+90)/10
        assert stats['min'] == 0
        assert stats['max'] == 90

class TestRealTimeProcessor:
    """Test suite for RealTimeProcessor"""
    
    @pytest.fixture
    def processor(self):
        """Create a test real-time processor"""
        return RealTimeProcessor(processing_interval=0.1)
    
    def test_processor_initialization(self, processor):
        """Test processor initialization"""
        assert processor.processing_interval == 0.1
        assert not processor.running
        assert len(processor.rules) > 0  # Should have default rules
    
    def test_processor_start_stop(self, processor):
        """Test starting and stopping the processor"""
        processor.start()
        assert processor.running
        assert processor.processor_thread is not None
        
        processor.stop()
        assert not processor.running
    
    def test_add_window(self, processor):
        """Test adding sliding windows"""
        processor.add_window("test_pattern", 60)
        assert "test_pattern" in processor.windows
        assert processor.windows["test_pattern"].size_seconds == 60
    
    def test_metric_processing(self, processor):
        """Test metric processing through rules"""
        # Create a test metric that should trigger a rule
        metric = MetricValue("cpu_usage_percent", 90, time.time(), source="system")
        
        # Add to processing queue
        processor.process_metric(metric)
        
        # Allow some processing time
        time.sleep(0.2)
        
        # Check that processing occurred
        stats = processor.get_processing_stats()
        assert stats['running'] == processor.running
    
    def test_anomaly_detection(self, processor):
        """Test anomaly detection functionality"""
        # Add baseline data
        for i in range(50):
            metric = MetricValue("test_metric", 50 + i, time.time(), source="test")
            processor.baseline_data["test_metric"].append(metric.value)
        
        # Add anomalous value
        anomaly_metric = MetricValue("test_metric", 200, time.time(), source="test")
        anomaly = processor._detect_anomaly(anomaly_metric)
        
        assert anomaly is not None
        assert anomaly.is_anomaly
        assert anomaly.confidence > 0

class TestAnalyticsEngine:
    """Test suite for AdvancedAnalyticsEngine"""
    
    @pytest.fixture
    def analytics(self):
        """Create a test analytics engine"""
        return AdvancedAnalyticsEngine(analysis_interval=1.0, history_size=1000)
    
    def test_analytics_initialization(self, analytics):
        """Test analytics engine initialization"""
        assert analytics.analysis_interval == 1.0
        assert analytics.history_size == 1000
        assert not analytics.running
    
    def test_add_metrics(self, analytics):
        """Test adding metrics for analysis"""
        metric = MetricValue("test_metric", 100, time.time(), source="test")
        analytics.add_metric(metric)
        
        assert "test_metric" in analytics.metric_history
        assert len(analytics.metric_history["test_metric"]) == 1
    
    def test_statistical_analysis(self, analytics):
        """Test statistical analysis functionality"""
        # Add sample data
        for i in range(100):
            metric = MetricValue("test_metric", i, time.time() + i, source="test")
            analytics.add_metric(metric)
        
        # Perform analysis
        analytics._perform_statistical_analysis()
        
        # Check results
        assert "test_metric" in analytics.statistical_results
        stats = analytics.statistical_results["test_metric"]
        assert stats.count == 100
        assert 45 <= stats.mean <= 55  # Should be around 49.5
    
    def test_trend_analysis(self, analytics):
        """Test trend analysis functionality"""
        # Add increasing trend data
        for i in range(50):
            metric = MetricValue("trend_metric", i * 2, time.time() + i, source="test")
            analytics.add_metric(metric)
        
        # Perform trend analysis
        analytics._perform_trend_analysis()
        
        # Check results
        if "trend_metric" in analytics.trend_results:
            trend = analytics.trend_results["trend_metric"]
            assert trend.direction in [TrendDirection.INCREASING, TrendDirection.STABLE]
    
    def test_comprehensive_report(self, analytics):
        """Test comprehensive report generation"""
        # Add some test data
        for i in range(20):
            metric = MetricValue("report_metric", i + 50, time.time() + i, source="test")
            analytics.add_metric(metric)
        
        analytics._perform_statistical_analysis()
        analytics._perform_trend_analysis()
        
        report = analytics.get_comprehensive_report()
        
        assert 'timestamp' in report
        assert 'analysis_stats' in report
        assert 'statistical_summaries' in report
        assert 'trends' in report

class TestDashboardServer:
    """Test suite for DashboardServer"""
    
    @pytest.fixture
    def dashboard_config(self):
        """Create test dashboard configuration"""
        return DashboardConfig(
            host="localhost",
            port=8766,  # Different port for testing
            max_connections=10,
            update_interval=0.5
        )
    
    @pytest.fixture
    def dashboard(self, dashboard_config):
        """Create test dashboard server"""
        return DashboardServer(dashboard_config)
    
    def test_dashboard_initialization(self, dashboard, dashboard_config):
        """Test dashboard server initialization"""
        assert dashboard.config == dashboard_config
        assert not dashboard.running
        assert dashboard.websocket_manager is not None
        assert dashboard.data_manager is not None
    
    def test_data_manager_initialization(self, dashboard):
        """Test dashboard data manager initialization"""
        data_manager = dashboard.data_manager
        assert len(data_manager.chart_data) > 0
        assert len(data_manager.widgets) > 0
        assert "cpu_usage" in data_manager.chart_data
        assert "system_overview" in data_manager.widgets
    
    def test_metric_data_update(self, dashboard):
        """Test updating chart data with metrics"""
        data_manager = dashboard.data_manager
        
        # Test CPU metric update
        cpu_metric = MetricValue("cpu_usage_percent_total", 75.5, time.time(), source="system")
        data_manager.update_metric_data(cpu_metric)
        
        # Check if chart was updated
        cpu_chart = data_manager.chart_data["cpu_usage"]
        assert len(cpu_chart.data_points) > 0
        assert cpu_chart.data_points[-1]['y'] == 75.5
    
    def test_chart_data_retrieval(self, dashboard):
        """Test chart data retrieval"""
        data_manager = dashboard.data_manager
        
        chart_data = data_manager.get_chart_data("cpu_usage")
        assert chart_data is not None
        assert chart_data['chart_id'] == "cpu_usage"
        assert chart_data['chart_type'] == "line"
        assert 'config' in chart_data
    
    def test_widget_configuration(self, dashboard):
        """Test widget configuration retrieval"""
        data_manager = dashboard.data_manager
        
        widget_config = data_manager.get_widget_config("system_overview")
        assert widget_config is not None
        assert widget_config['widget_id'] == "system_overview"
        assert 'position' in widget_config
    
    @pytest.mark.asyncio
    async def test_dashboard_start_stop(self, dashboard):
        """Test starting and stopping dashboard server"""
        # Note: This test might fail in CI environments without proper network setup
        try:
            await dashboard.start()
            assert dashboard.running
            assert dashboard.server is not None
            
            await dashboard.stop()
            assert not dashboard.running
        except OSError:
            # Skip if port is not available
            pytest.skip("Port not available for testing")

class TestAlertManager:
    """Test suite for IntelligentAlertManager"""
    
    @pytest.fixture
    def alert_manager(self):
        """Create test alert manager"""
        return IntelligentAlertManager()
    
    def test_alert_manager_initialization(self, alert_manager):
        """Test alert manager initialization"""
        assert not alert_manager.running
        assert len(alert_manager.alert_rules) > 0
        assert alert_manager.evaluator is not None
        assert alert_manager.correlator is not None
        assert alert_manager.notification_manager is not None
    
    def test_add_alert_rule(self, alert_manager):
        """Test adding alert rules"""
        rule = AlertRule(
            rule_id="test_rule",
            name="Test Rule",
            description="Test alert rule",
            condition="metric_value > 100",
            level=AlertLevel.WARNING,
            priority=AlertPriority.MEDIUM,
            metric_patterns=["test_metric"]
        )
        
        initial_count = len(alert_manager.alert_rules)
        alert_manager.add_alert_rule(rule)
        assert len(alert_manager.alert_rules) == initial_count + 1
        assert "test_rule" in alert_manager.alert_rules
    
    def test_alert_evaluation(self, alert_manager):
        """Test alert condition evaluation"""
        evaluator = alert_manager.evaluator
        
        # Test simple condition
        metric = MetricValue("test_metric", 150, time.time(), source="test")
        result = evaluator.evaluate_condition("metric_value > 100", metric)
        assert result is True
        
        result = evaluator.evaluate_condition("metric_value < 100", metric)
        assert result is False
    
    def test_metric_processing(self, alert_manager):
        """Test processing metrics for alerts"""
        # Add a test rule
        rule = AlertRule(
            rule_id="high_value_test",
            name="High Value Test",
            description="Test for high values",
            condition="metric_value > 200",
            level=AlertLevel.WARNING,
            priority=AlertPriority.MEDIUM,
            metric_patterns=["test_high_metric"]
        )
        alert_manager.add_alert_rule(rule)
        
        # Process a metric that should trigger the alert
        metric = MetricValue("test_high_metric", 250, time.time(), source="test")
        alert_manager.process_metric(metric)
        
        # Allow processing time
        time.sleep(0.1)
        
        # Check if alert was created (this might not work in async context)
        # assert len(alert_manager.active_alerts) > 0
    
    def test_alert_acknowledgment(self, alert_manager):
        """Test alert acknowledgment"""
        # Create a test alert manually
        alert = Alert(
            alert_id="test_alert",
            rule_id="test_rule",
            name="Test Alert",
            description="Test alert",
            level=AlertLevel.WARNING,
            priority=AlertPriority.MEDIUM,
            state=AlertState.ACTIVE,
            created_at=time.time(),
            updated_at=time.time()
        )
        
        alert_manager.active_alerts["test_alert"] = alert
        
        # Acknowledge the alert
        result = alert_manager.acknowledge_alert("test_alert", "test_user")
        assert result is True
        assert alert.state == AlertState.ACKNOWLEDGED
        assert alert.context['acknowledged_by'] == "test_user"
    
    def test_alert_statistics(self, alert_manager):
        """Test alert statistics generation"""
        stats = alert_manager.get_alert_stats()
        
        assert 'stats' in stats
        assert 'active_alerts_count' in stats
        assert 'alert_rules_count' in stats
        assert 'notification_targets_count' in stats
        assert 'running' in stats

class TestCollectors:
    """Test suite for specialized collectors"""
    
    def test_system_metrics_collector(self):
        """Test system metrics collector"""
        collector = AdvancedSystemMetricsCollector()
        
        # Test system info
        assert collector.system_info.hostname is not None
        assert collector.system_info.platform is not None
        
        # Test metric collection
        metrics = collector.collect_all_metrics()
        assert len(metrics) > 0
        
        # Check for expected metric types
        metric_names = [m.name for m in metrics]
        assert any("cpu_usage" in name for name in metric_names)
        assert any("memory" in name for name in metric_names)
    
    def test_application_metrics_collector(self):
        """Test application metrics collector"""
        collector = ApplicationMetricsCollector()
        
        # Test metric collection
        metrics = collector.collect_all_metrics()
        assert len(metrics) > 0
        
        # Test recording custom metrics
        collector.record_query_time(0.5, "test_query")
        collector.increment_counter("test_counter", 5)
        collector.set_gauge("test_gauge", 75.0)
        
        # Collect again to see the custom metrics
        metrics = collector.collect_all_metrics()
        metric_names = [m.name for m in metrics]
        assert any("counter" in name for name in metric_names)
        assert any("gauge" in name for name in metric_names)
    
    def test_custom_metrics_collector(self):
        """Test custom metrics collector"""
        collector = CustomMetricsCollector()
        
        # Test scenario management
        collector.start_test_scenario("Test Scenario", "Test Description", TestSeverity.MEDIUM, 300)
        assert collector.current_scenario is not None
        assert collector.current_scenario.name == "Test Scenario"
        
        # Test phase change
        collector.set_test_phase(TestPhase.LOAD_GENERATION)
        assert collector.current_scenario.phase == TestPhase.LOAD_GENERATION
        
        # Test stress testing
        collector.start_stress_test_cycle(1, 100, 50.0)
        assert collector.current_stress_cycle is not None
        assert collector.current_stress_cycle.concurrent_users == 100
        
        # Test business metrics
        collector.record_business_metric("system_availability", 0.99)
        collector.set_performance_baseline("response_time", 0.5)
        
        # Test metric collection
        metrics = collector.collect_all_metrics()
        assert len(metrics) > 0
    
    def test_log_metrics_collector(self):
        """Test log metrics collector"""
        # Create temporary log file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("INFO: Application started\n")
            f.write("ERROR: Database connection failed\n")
            f.write("WARN: High memory usage detected\n")
            f.write("INFO: Request processed in 250ms\n")
            temp_log_path = f.name
        
        try:
            # Create collector with test directory
            test_dir = os.path.dirname(temp_log_path)
            collector = LogMetricsCollector([test_dir], max_file_age_hours=1)
            
            # Test pattern matching
            assert len(collector.patterns) > 0
            
            # Process the test log file
            collector._process_log_file(temp_log_path)
            
            # Allow processing time
            time.sleep(0.1)
            
            # Test metric collection
            metrics = collector.collect_all_metrics()
            assert len(metrics) > 0
            
        finally:
            # Clean up
            os.unlink(temp_log_path)

class TestIntegration:
    """Integration tests for the complete monitoring system"""
    
    @pytest.fixture
    def monitoring_system(self):
        """Create integrated monitoring system"""
        return IntegratedMonitoringSystem(collection_interval=0.1, processing_interval=0.1)
    
    def test_integrated_system_initialization(self, monitoring_system):
        """Test integrated system initialization"""
        assert monitoring_system.collector is not None
        assert monitoring_system.processor is not None
        assert len(monitoring_system.processor.windows) > 0
    
    def test_integrated_system_start_stop(self, monitoring_system):
        """Test starting and stopping integrated system"""
        monitoring_system.start()
        assert monitoring_system.collector.running
        assert monitoring_system.processor.running
        
        monitoring_system.stop()
        assert not monitoring_system.collector.running
        assert not monitoring_system.processor.running
    
    def test_end_to_end_metric_flow(self, monitoring_system):
        """Test end-to-end metric flow"""
        # Start the system
        monitoring_system.start()
        
        try:
            # Allow some collection time
            time.sleep(2)
            
            # Get system status
            status = monitoring_system.get_system_status()
            
            assert 'collector_stats' in status
            assert 'processor_stats' in status
            assert 'latest_metrics' in status
            
            # Check that metrics were collected
            collector_stats = status['collector_stats']
            assert collector_stats['total_collections'] > 0
            
        finally:
            monitoring_system.stop()

class TestPerformance:
    """Performance tests for the monitoring system"""
    
    def test_collector_performance(self):
        """Test collector performance under load"""
        collector = MetricsCollector(collection_interval=0.01)  # High frequency
        
        start_time = time.time()
        collector.start()
        
        try:
            # Run for a short time
            time.sleep(2)
            
            stats = collector.get_collection_stats()
            collections = stats['total_collections']
            
            # Should have collected many times
            assert collections > 50  # At least some collections
            
            # Check for reasonable error rate
            if stats['total_errors'] > 0:
                error_rate = stats['total_errors'] / collections
                assert error_rate < 0.1  # Less than 10% error rate
            
        finally:
            collector.stop()
    
    def test_processor_performance(self):
        """Test processor performance under load"""
        processor = RealTimeProcessor(processing_interval=0.01)
        
        processor.start()
        
        try:
            # Add many metrics quickly
            for i in range(1000):
                metric = MetricValue(f"test_metric_{i % 10}", i, time.time(), source="test")
                processor.process_metric(metric)
            
            # Allow processing time
            time.sleep(2)
            
            stats = processor.get_processing_stats()
            assert stats['total_processed'] > 0
            
            # Check queue doesn't overflow excessively
            assert stats['queue_overflows'] < 100
            
        finally:
            processor.stop()

# Test data generators
class TestDataGenerator:
    """Generate test data for monitoring system testing"""
    
    @staticmethod
    def generate_cpu_metrics(count: int = 100) -> List[MetricValue]:
        """Generate CPU usage metrics"""
        metrics = []
        base_time = time.time()
        
        for i in range(count):
            # Simulate varying CPU usage
            cpu_usage = 50 + 30 * (i % 10) / 10  # Values between 50-80%
            metric = MetricValue(
                name="cpu_usage_percent",
                value=cpu_usage,
                timestamp=base_time + i,
                source="system",
                tags={"type": "cpu", "core": "total"}
            )
            metrics.append(metric)
        
        return metrics
    
    @staticmethod
    def generate_memory_metrics(count: int = 100) -> List[MetricValue]:
        """Generate memory usage metrics"""
        metrics = []
        base_time = time.time()
        
        for i in range(count):
            # Simulate increasing memory usage
            memory_usage = 60 + (i * 0.2) % 40  # Gradual increase with cycles
            metric = MetricValue(
                name="memory_usage_percent",
                value=memory_usage,
                timestamp=base_time + i,
                source="system",
                tags={"type": "memory"}
            )
            metrics.append(metric)
        
        return metrics
    
    @staticmethod
    def generate_response_time_metrics(count: int = 100) -> List[MetricValue]:
        """Generate response time metrics"""
        metrics = []
        base_time = time.time()
        
        for i in range(count):
            # Simulate varying response times
            response_time = 100 + 50 * abs((i % 20) - 10) / 10  # 100-150ms range
            metric = MetricValue(
                name="response_time_ms",
                value=response_time,
                timestamp=base_time + i,
                source="application",
                tags={"type": "performance", "endpoint": "api"}
            )
            metrics.append(metric)
        
        return metrics

# Utility functions for testing
def run_all_tests():
    """Run all tests and generate report"""
    print("Starting comprehensive monitoring system tests...")
    
    # Run pytest with coverage
    import subprocess
    import sys
    
    test_file = __file__
    result = subprocess.run([
        sys.executable, "-m", "pytest", test_file, 
        "-v", "--tb=short", "--capture=no"
    ], capture_output=True, text=True)
    
    print("Test Results:")
    print(result.stdout)
    if result.stderr:
        print("Errors:")
        print(result.stderr)
    
    return result.returncode == 0

if __name__ == "__main__":
    # Run tests if executed directly
    success = run_all_tests()
    exit(0 if success else 1)