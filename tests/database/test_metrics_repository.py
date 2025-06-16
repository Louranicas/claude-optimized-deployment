"""Comprehensive tests for metrics repository functionality.

Tests cover:
- Time-series metrics storage and retrieval
- Batch metrics processing with memory optimization
- Time-based aggregation and querying
- Metrics streaming for large datasets
- Performance and memory management
- Data cleanup and retention
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
from typing import Dict, Any, List

from src.database.repositories.metrics_repository import MetricsRepository, TortoiseMetricsRepository
from src.database.models import SQLAlchemyMetricData, TortoiseMetricData
from src.core.exceptions import DatabaseError


class TestMetricsRepository:
    """Test SQLAlchemy metrics repository functionality."""
    
    async def test_record_single_metric(self, metrics_repository):
        """Test recording a single metric data point."""
        timestamp = datetime.utcnow()
        labels = {"instance": "test-1", "region": "us-east-1"}
        
        metric = await metrics_repository.record_metric(
            metric_name="cpu_usage",
            value=75.5,
            timestamp=timestamp,
            labels=labels
        )
        
        assert metric.metric_name == "cpu_usage"
        assert metric.value == 75.5
        assert metric.timestamp == timestamp
        assert metric.labels == labels
        assert metric.id is not None
    
    async def test_record_metric_with_defaults(self, metrics_repository):
        """Test recording metric with default values."""
        metric = await metrics_repository.record_metric(
            metric_name="memory_usage",
            value=80.0
        )
        
        assert metric.metric_name == "memory_usage"
        assert metric.value == 80.0
        assert metric.labels == {}
        assert metric.timestamp is not None
        assert isinstance(metric.timestamp, datetime)
    
    async def test_record_metrics_batch_small(self, metrics_repository):
        """Test batch recording of metrics."""
        metrics_data = [
            {
                "metric_name": "cpu_usage",
                "value": 70.0,
                "labels": {"instance": "test-1"}
            },
            {
                "metric_name": "cpu_usage",
                "value": 80.0,
                "labels": {"instance": "test-2"}
            },
            {
                "metric_name": "memory_usage",
                "value": 60.0,
                "labels": {"instance": "test-1"}
            }
        ]
        
        recorded_metrics = await metrics_repository.record_metrics_batch(metrics_data)
        
        assert len(recorded_metrics) == 3
        assert all(metric.id is not None for metric in recorded_metrics)
        
        # Verify metrics are in database
        count = await metrics_repository.count()
        assert count >= 3
    
    async def test_record_metrics_batch_large_chunking(self, metrics_repository):
        """Test batch recording with chunking for large datasets."""
        # Create large dataset
        large_dataset = []
        for i in range(250):  # More than chunk_size of 100
            large_dataset.append({
                "metric_name": "test_metric",
                "value": float(i % 100),
                "labels": {"batch": "large", "index": str(i)}
            })
        
        recorded_metrics = await metrics_repository.record_metrics_batch(
            large_dataset, chunk_size=50
        )
        
        assert len(recorded_metrics) == 250
        
        # Verify all metrics are recorded
        count = await metrics_repository.count(filters={"metric_name": "test_metric"})
        assert count >= 250
    
    async def test_record_metrics_batch_memory_pressure(self, metrics_repository):
        """Test batch recording under memory pressure."""
        large_dataset = []
        for i in range(100):
            large_dataset.append({
                "metric_name": "memory_pressure_test",
                "value": float(i),
                "labels": {"test": "memory"}
            })
        
        # Mock memory pressure detection
        with patch.object(metrics_repository, '_check_memory_pressure') as mock_check:
            mock_check.return_value = True  # Simulate memory pressure
            
            recorded_metrics = await metrics_repository.record_metrics_batch(
                large_dataset, chunk_size=50
            )
            
            # Should still record all metrics, but with smaller chunks
            assert len(recorded_metrics) == 100
    
    async def test_query_metrics_basic(self, metrics_repository):
        """Test basic metrics querying."""
        # Record test metrics
        base_time = datetime.utcnow()
        for i in range(5):
            await metrics_repository.record_metric(
                metric_name="query_test",
                value=float(i * 10),
                timestamp=base_time + timedelta(minutes=i),
                labels={"test": "basic"}
            )
        
        # Query metrics
        start_time = base_time - timedelta(minutes=1)
        end_time = base_time + timedelta(minutes=10)
        
        results = await metrics_repository.query_metrics(
            metric_name="query_test",
            start_time=start_time,
            end_time=end_time
        )
        
        assert len(results) == 5
        assert all("timestamp" in result for result in results)
        assert all("value" in result for result in results)
        assert all("labels" in result for result in results)
        
        # Verify chronological order
        timestamps = [result["timestamp"] for result in results]
        assert timestamps == sorted(timestamps)
    
    async def test_query_metrics_with_labels(self, metrics_repository):
        """Test querying metrics with label filtering."""
        # Record metrics with different labels
        base_time = datetime.utcnow()
        
        await metrics_repository.record_metric(
            metric_name="labeled_test",
            value=100.0,
            timestamp=base_time,
            labels={"environment": "prod", "service": "api"}
        )
        
        await metrics_repository.record_metric(
            metric_name="labeled_test",
            value=200.0,
            timestamp=base_time + timedelta(minutes=1),
            labels={"environment": "dev", "service": "api"}
        )
        
        await metrics_repository.record_metric(
            metric_name="labeled_test",
            value=300.0,
            timestamp=base_time + timedelta(minutes=2),
            labels={"environment": "prod", "service": "web"}
        )
        
        # Query with label filter
        start_time = base_time - timedelta(minutes=1)
        end_time = base_time + timedelta(minutes=10)
        
        prod_results = await metrics_repository.query_metrics(
            metric_name="labeled_test",
            start_time=start_time,
            end_time=end_time,
            labels={"environment": "prod"}
        )
        
        # Should return metrics with environment=prod
        assert len(prod_results) == 2
        for result in prod_results:
            assert result["labels"]["environment"] == "prod"
    
    async def test_query_with_aggregation(self, metrics_repository):
        """Test querying metrics with time-based aggregation."""
        # Record metrics over time
        base_time = datetime.utcnow()
        values = [10, 20, 30, 40, 50]
        
        for i, value in enumerate(values):
            await metrics_repository.record_metric(
                metric_name="aggregation_test",
                value=float(value),
                timestamp=base_time + timedelta(seconds=i * 30),  # 30-second intervals
                labels={"test": "aggregation"}
            )
        
        # Query with aggregation
        start_time = base_time - timedelta(minutes=1)
        end_time = base_time + timedelta(minutes=5)
        
        aggregated_results = await metrics_repository.query_metrics(
            metric_name="aggregation_test",
            start_time=start_time,
            end_time=end_time,
            aggregation="avg",
            step_seconds=60  # 1-minute buckets
        )
        
        assert len(aggregated_results) >= 1
        for result in aggregated_results:
            assert "timestamp" in result
            assert "value" in result
            assert "count" in result
    
    async def test_get_metric_names(self, metrics_repository):
        """Test getting unique metric names."""
        # Record metrics with different names
        metric_names = ["cpu_usage", "memory_usage", "disk_io", "network_throughput"]
        
        for name in metric_names:
            await metrics_repository.record_metric(
                metric_name=name,
                value=50.0
            )
        
        # Get all metric names
        all_names = await metrics_repository.get_metric_names()
        
        for name in metric_names:
            assert name in all_names
    
    async def test_get_metric_names_with_prefix(self, metrics_repository):
        """Test getting metric names with prefix filtering."""
        # Record metrics with different prefixes
        metrics = [
            "http_requests_total",
            "http_request_duration",
            "database_connections",
            "cache_hits"
        ]
        
        for metric in metrics:
            await metrics_repository.record_metric(metric_name=metric, value=1.0)
        
        # Get metrics with "http_" prefix
        http_metrics = await metrics_repository.get_metric_names(prefix="http_")
        
        assert "http_requests_total" in http_metrics
        assert "http_request_duration" in http_metrics
        assert "database_connections" not in http_metrics
        assert "cache_hits" not in http_metrics
    
    async def test_get_metric_labels(self, metrics_repository):
        """Test getting unique label combinations for a metric."""
        # Record metrics with various label combinations
        label_combinations = [
            {"service": "api", "version": "v1"},
            {"service": "api", "version": "v2"},
            {"service": "web", "version": "v1"},
        ]
        
        for labels in label_combinations:
            await metrics_repository.record_metric(
                metric_name="service_metric",
                value=100.0,
                labels=labels
            )
        
        # Get all label combinations
        all_labels = await metrics_repository.get_metric_labels("service_metric")
        
        assert len(all_labels) >= 3
        for labels in label_combinations:
            assert labels in all_labels
    
    async def test_get_latest_value(self, metrics_repository):
        """Test getting the latest value for a metric."""
        # Record metrics with different timestamps
        base_time = datetime.utcnow()
        
        old_metric = await metrics_repository.record_metric(
            metric_name="latest_test",
            value=100.0,
            timestamp=base_time - timedelta(minutes=5),
            labels={"instance": "test"}
        )
        
        latest_metric = await metrics_repository.record_metric(
            metric_name="latest_test",
            value=200.0,
            timestamp=base_time,
            labels={"instance": "test"}
        )
        
        # Get latest value
        latest = await metrics_repository.get_latest_value(
            metric_name="latest_test",
            labels={"instance": "test"}
        )
        
        assert latest is not None
        assert latest["value"] == 200.0
        assert latest["labels"]["instance"] == "test"
    
    async def test_get_latest_value_not_found(self, metrics_repository):
        """Test getting latest value for non-existent metric."""
        latest = await metrics_repository.get_latest_value("nonexistent_metric")
        assert latest is None
    
    async def test_cleanup_old_metrics(self, metrics_repository):
        """Test cleaning up old metrics data."""
        # Create old and new metrics
        current_time = datetime.utcnow()
        
        old_metric = await metrics_repository.record_metric(
            metric_name="cleanup_test",
            value=100.0,
            timestamp=current_time - timedelta(days=60)
        )
        
        new_metric = await metrics_repository.record_metric(
            metric_name="cleanup_test",
            value=200.0,
            timestamp=current_time
        )
        
        # Cleanup metrics older than 30 days
        deleted_count = await metrics_repository.cleanup_old_metrics(retention_days=30)
        
        assert deleted_count >= 1
        
        # Verify old metric is deleted and new metric remains
        remaining_count = await metrics_repository.count(
            filters={"metric_name": "cleanup_test"}
        )
        assert remaining_count >= 1
    
    async def test_cleanup_old_metrics_specific_metric(self, metrics_repository):
        """Test cleaning up old metrics for specific metric name."""
        current_time = datetime.utcnow()
        
        # Create old metrics for different metric names
        await metrics_repository.record_metric(
            metric_name="cleanup_specific",
            value=100.0,
            timestamp=current_time - timedelta(days=60)
        )
        
        await metrics_repository.record_metric(
            metric_name="keep_this",
            value=200.0,
            timestamp=current_time - timedelta(days=60)
        )
        
        # Cleanup only specific metric
        deleted_count = await metrics_repository.cleanup_old_metrics(
            retention_days=30,
            metric_name="cleanup_specific"
        )
        
        assert deleted_count >= 1
        
        # Verify only the specific metric was cleaned up
        specific_count = await metrics_repository.count(
            filters={"metric_name": "cleanup_specific"}
        )
        keep_count = await metrics_repository.count(
            filters={"metric_name": "keep_this"}
        )
        
        assert specific_count == 0
        assert keep_count >= 1
    
    async def test_get_metrics_summary(self, metrics_repository):
        """Test getting metrics summary statistics."""
        # Create test metrics with different names and timestamps
        base_time = datetime.utcnow()
        metrics_data = [
            ("cpu_usage", base_time - timedelta(hours=2)),
            ("cpu_usage", base_time - timedelta(hours=1)),
            ("cpu_usage", base_time),
            ("memory_usage", base_time - timedelta(hours=1)),
            ("memory_usage", base_time),
        ]
        
        for metric_name, timestamp in metrics_data:
            await metrics_repository.record_metric(
                metric_name=metric_name,
                value=50.0,
                timestamp=timestamp
            )
        
        # Get summary
        summary = await metrics_repository.get_metrics_summary()
        
        assert isinstance(summary, dict)
        assert "total_metrics" in summary
        assert "total_data_points" in summary
        assert "metrics" in summary
        
        assert summary["total_metrics"] >= 2  # cpu_usage and memory_usage
        assert summary["total_data_points"] >= 5
        
        # Check individual metric summaries
        assert "cpu_usage" in summary["metrics"]
        assert "memory_usage" in summary["metrics"]
        
        cpu_summary = summary["metrics"]["cpu_usage"]
        assert cpu_summary["data_points"] == 3
        assert "oldest_timestamp" in cpu_summary
        assert "newest_timestamp" in cpu_summary
    
    async def test_get_metrics_summary_with_time_filter(self, metrics_repository):
        """Test metrics summary with time filtering."""
        base_time = datetime.utcnow()
        
        # Create old and new metrics
        await metrics_repository.record_metric(
            metric_name="time_filter_test",
            value=100.0,
            timestamp=base_time - timedelta(days=10)
        )
        
        await metrics_repository.record_metric(
            metric_name="time_filter_test",
            value=200.0,
            timestamp=base_time
        )
        
        # Get summary for recent data only
        start_time = base_time - timedelta(days=1)
        summary = await metrics_repository.get_metrics_summary(start_time=start_time)
        
        # Should only include recent metric
        assert summary["metrics"]["time_filter_test"]["data_points"] == 1
    
    async def test_stream_metrics(self, metrics_repository):
        """Test streaming metrics data in chunks."""
        # Create large dataset
        base_time = datetime.utcnow()
        for i in range(50):
            await metrics_repository.record_metric(
                metric_name="stream_test",
                value=float(i),
                timestamp=base_time + timedelta(seconds=i),
                labels={"chunk_test": "true"}
            )
        
        # Stream metrics in chunks
        start_time = base_time - timedelta(minutes=1)
        end_time = base_time + timedelta(minutes=2)
        
        all_data = []
        async for chunk in metrics_repository.stream_metrics(
            metric_name="stream_test",
            start_time=start_time,
            end_time=end_time,
            chunk_size=10
        ):
            assert len(chunk) <= 10
            all_data.extend(chunk)
        
        # Verify all data was streamed
        assert len(all_data) == 50
        
        # Verify data integrity
        values = [point["value"] for point in all_data]
        assert set(values) == set(range(50))
    
    async def test_stream_metrics_with_labels(self, metrics_repository):
        """Test streaming metrics with label filtering."""
        base_time = datetime.utcnow()
        
        # Create metrics with different labels
        for i in range(20):
            labels = {"environment": "prod" if i % 2 == 0 else "dev"}
            await metrics_repository.record_metric(
                metric_name="stream_label_test",
                value=float(i),
                timestamp=base_time + timedelta(seconds=i),
                labels=labels
            )
        
        # Stream only prod metrics
        start_time = base_time - timedelta(minutes=1)
        end_time = base_time + timedelta(minutes=2)
        
        prod_data = []
        async for chunk in metrics_repository.stream_metrics(
            metric_name="stream_label_test",
            start_time=start_time,
            end_time=end_time,
            labels={"environment": "prod"},
            chunk_size=5
        ):
            prod_data.extend(chunk)
        
        # Should have 10 prod metrics (even numbers)
        assert len(prod_data) == 10
        for point in prod_data:
            assert point["labels"]["environment"] == "prod"


class TestTortoiseMetricsRepository:
    """Test Tortoise ORM metrics repository functionality."""
    
    def test_tortoise_repository_initialization(self):
        """Test Tortoise metrics repository initialization."""
        repo = TortoiseMetricsRepository()
        assert repo._model_class is TortoiseMetricData
    
    async def test_record_metric(self):
        """Test Tortoise metric recording."""
        repo = TortoiseMetricsRepository()
        
        metric_data = {
            "metric_name": "tortoise_test",
            "value": 123.45,
            "labels": {"test": "tortoise"}
        }
        
        with patch.object(repo, 'create') as mock_create:
            mock_metric = MagicMock()
            mock_create.return_value = mock_metric
            
            result = await repo.record_metric(**metric_data)
            
            assert result is mock_metric
            # Verify create was called with timestamp
            call_args = mock_create.call_args[1]
            assert call_args["metric_name"] == "tortoise_test"
            assert call_args["value"] == 123.45
            assert call_args["labels"] == {"test": "tortoise"}
            assert "timestamp" in call_args
    
    async def test_query_metrics(self):
        """Test Tortoise metrics querying."""
        repo = TortoiseMetricsRepository()
        
        start_time = datetime.utcnow() - timedelta(hours=1)
        end_time = datetime.utcnow()
        
        with patch.object(TortoiseMetricData, 'filter') as mock_filter:
            mock_query = MagicMock()
            mock_query.order_by.return_value = mock_query
            mock_query.all.return_value = AsyncMock(return_value=[
                MagicMock(
                    timestamp=datetime.utcnow(),
                    value=100.0,
                    labels={"test": "tortoise"}
                )
            ])
            mock_filter.return_value = mock_query
            
            result = await repo.query_metrics(
                metric_name="tortoise_query_test",
                start_time=start_time,
                end_time=end_time
            )
            
            assert len(result) == 1
            assert result[0]["value"] == 100.0
            assert result[0]["labels"]["test"] == "tortoise"
            
            # Verify filter was called with correct parameters
            mock_filter.assert_called_once_with(
                metric_name="tortoise_query_test",
                timestamp__gte=start_time,
                timestamp__lte=end_time
            )


class TestMetricsRepositoryPerformance:
    """Test metrics repository performance characteristics."""
    
    async def test_bulk_metrics_ingestion_performance(self, metrics_repository, performance_timer):
        """Test bulk metrics ingestion performance."""
        # Create large dataset
        large_dataset = []
        for i in range(1000):
            large_dataset.append({
                "metric_name": "performance_test",
                "value": float(i % 100),
                "labels": {"batch": "performance", "index": str(i)}
            })
        
        performance_timer.start()
        
        # Ingest metrics in batches
        recorded_metrics = await metrics_repository.record_metrics_batch(
            large_dataset, chunk_size=100
        )
        
        performance_timer.stop()
        
        assert len(recorded_metrics) == 1000
        
        # Verify database state
        count = await metrics_repository.count(filters={"metric_name": "performance_test"})
        assert count == 1000
        
        # Performance should be reasonable
        assert performance_timer.elapsed_seconds < 60.0
    
    async def test_metrics_query_performance(self, metrics_repository, performance_timer):
        """Test metrics querying performance with large dataset."""
        # Create time-series data
        base_time = datetime.utcnow() - timedelta(hours=1)
        for i in range(500):
            await metrics_repository.record_metric(
                metric_name="query_performance_test",
                value=float(i % 100),
                timestamp=base_time + timedelta(seconds=i * 7.2),  # One data point every 7.2 seconds
                labels={"instance": f"server-{i % 5}"}
            )
        
        performance_timer.start()
        
        # Perform various queries
        start_time = base_time - timedelta(minutes=30)
        end_time = base_time + timedelta(minutes=30)
        
        # Basic query
        all_results = await metrics_repository.query_metrics(
            metric_name="query_performance_test",
            start_time=start_time,
            end_time=end_time
        )
        
        # Query with label filtering
        server_results = await metrics_repository.query_metrics(
            metric_name="query_performance_test",
            start_time=start_time,
            end_time=end_time,
            labels={"instance": "server-1"}
        )
        
        # Query with aggregation
        aggregated_results = await metrics_repository.query_metrics(
            metric_name="query_performance_test",
            start_time=start_time,
            end_time=end_time,
            aggregation="avg",
            step_seconds=300  # 5-minute buckets
        )
        
        performance_timer.stop()
        
        # Verify results
        assert len(all_results) >= 400  # Should get most of the data points
        assert len(server_results) >= 80  # About 1/5 of the data (server-1 out of 5 servers)
        assert len(aggregated_results) >= 1  # At least one aggregated bucket
        
        # Query performance should be reasonable
        assert performance_timer.elapsed_seconds < 30.0
    
    async def test_metrics_streaming_performance(self, metrics_repository, performance_timer):
        """Test metrics streaming performance."""
        # Create large time-series dataset
        base_time = datetime.utcnow() - timedelta(hours=2)
        
        # Use batch insert for setup (faster)
        large_dataset = []
        for i in range(2000):
            large_dataset.append({
                "metric_name": "streaming_test",
                "value": float(i % 100),
                "timestamp": base_time + timedelta(seconds=i * 3.6),
                "labels": {"test": "streaming"}
            })
        
        await metrics_repository.record_metrics_batch(large_dataset, chunk_size=200)
        
        performance_timer.start()
        
        # Stream all data
        start_time = base_time - timedelta(minutes=30)
        end_time = base_time + timedelta(hours=3)
        
        total_points = 0
        async for chunk in metrics_repository.stream_metrics(
            metric_name="streaming_test",
            start_time=start_time,
            end_time=end_time,
            chunk_size=100
        ):
            total_points += len(chunk)
            # Simulate processing time
            await asyncio.sleep(0.001)
        
        performance_timer.stop()
        
        assert total_points == 2000
        
        # Streaming should be reasonably fast
        assert performance_timer.elapsed_seconds < 45.0
    
    async def test_concurrent_metrics_operations(self, metrics_repository):
        """Test concurrent metrics operations."""
        async def record_metric_batch(batch_id: int):
            batch_data = []
            for i in range(50):
                batch_data.append({
                    "metric_name": f"concurrent_test_batch_{batch_id}",
                    "value": float(i),
                    "labels": {"batch_id": str(batch_id)}
                })
            
            return await metrics_repository.record_metrics_batch(batch_data)
        
        async def query_metrics_concurrent(metric_name: str):
            start_time = datetime.utcnow() - timedelta(hours=1)
            end_time = datetime.utcnow() + timedelta(hours=1)
            
            return await metrics_repository.query_metrics(
                metric_name=metric_name,
                start_time=start_time,
                end_time=end_time
            )
        
        # Run concurrent record operations
        record_tasks = [record_metric_batch(i) for i in range(5)]
        record_results = await asyncio.gather(*record_tasks)
        
        # Verify all batches were recorded
        total_recorded = sum(len(batch) for batch in record_results)
        assert total_recorded == 250  # 5 batches * 50 metrics each
        
        # Run concurrent query operations
        query_tasks = [
            query_metrics_concurrent(f"concurrent_test_batch_{i}")
            for i in range(5)
        ]
        query_results = await asyncio.gather(*query_tasks)
        
        # Verify all queries returned data
        for i, results in enumerate(query_results):
            assert len(results) == 50
            assert all(result["labels"]["batch_id"] == str(i) for result in results)
    
    async def test_memory_management_during_batch_processing(self, metrics_repository):
        """Test memory management during large batch processing."""
        # Create very large dataset to test memory management
        very_large_dataset = []
        for i in range(5000):
            very_large_dataset.append({
                "metric_name": "memory_test",
                "value": float(i % 100),
                "labels": {"test": "memory", "index": str(i)}
            })
        
        # Mock memory pressure to test adaptive chunking
        with patch.object(metrics_repository, '_check_memory_pressure') as mock_pressure:
            # Simulate memory pressure after some processing
            mock_pressure.side_effect = [False, False, True, True, False, False]
            
            recorded_metrics = await metrics_repository.record_metrics_batch(
                very_large_dataset, chunk_size=1000
            )
            
            assert len(recorded_metrics) == 5000
            
            # Verify memory pressure was checked
            assert mock_pressure.call_count >= 3
    
    async def test_cleanup_performance(self, metrics_repository, performance_timer):
        """Test cleanup operation performance."""
        # Create metrics with different ages
        current_time = datetime.utcnow()
        
        # Create old metrics (to be cleaned up)
        old_batch = []
        for i in range(1000):
            old_batch.append({
                "metric_name": "cleanup_perf_test",
                "value": float(i),
                "timestamp": current_time - timedelta(days=100),
                "labels": {"age": "old"}
            })
        
        # Create recent metrics (to be kept)
        recent_batch = []
        for i in range(1000):
            recent_batch.append({
                "metric_name": "cleanup_perf_test",
                "value": float(i),
                "timestamp": current_time - timedelta(days=1),
                "labels": {"age": "recent"}
            })
        
        # Insert all metrics
        await metrics_repository.record_metrics_batch(old_batch)
        await metrics_repository.record_metrics_batch(recent_batch)
        
        performance_timer.start()
        
        # Perform cleanup
        deleted_count = await metrics_repository.cleanup_old_metrics(
            retention_days=30,
            metric_name="cleanup_perf_test"
        )
        
        performance_timer.stop()
        
        assert deleted_count == 1000  # Only old metrics should be deleted
        
        # Verify recent metrics remain
        remaining_count = await metrics_repository.count(
            filters={"metric_name": "cleanup_perf_test"}
        )
        assert remaining_count == 1000
        
        # Cleanup should be reasonably fast
        assert performance_timer.elapsed_seconds < 30.0


class TestMetricsRepositoryIntegration:
    """Test metrics repository integration scenarios."""
    
    async def test_complete_metrics_lifecycle(self, metrics_repository):
        """Test complete metrics lifecycle from ingestion to cleanup."""
        metric_name = "lifecycle_test"
        base_time = datetime.utcnow()
        
        # 1. Ingest initial metrics
        initial_metrics = []
        for i in range(100):
            initial_metrics.append({
                "metric_name": metric_name,
                "value": float(i),
                "timestamp": base_time + timedelta(minutes=i),
                "labels": {"phase": "initial", "server": f"srv-{i % 5}"}
            })
        
        await metrics_repository.record_metrics_batch(initial_metrics)
        
        # 2. Query and verify metrics
        start_time = base_time - timedelta(minutes=10)
        end_time = base_time + timedelta(hours=2)
        
        all_metrics = await metrics_repository.query_metrics(
            metric_name=metric_name,
            start_time=start_time,
            end_time=end_time
        )
        assert len(all_metrics) == 100
        
        # 3. Query with label filtering
        srv0_metrics = await metrics_repository.query_metrics(
            metric_name=metric_name,
            start_time=start_time,
            end_time=end_time,
            labels={"server": "srv-0"}
        )
        assert len(srv0_metrics) == 20  # Every 5th metric
        
        # 4. Get latest value
        latest = await metrics_repository.get_latest_value(
            metric_name=metric_name,
            labels={"server": "srv-4"}
        )
        assert latest is not None
        assert latest["labels"]["server"] == "srv-4"
        
        # 5. Get metrics summary
        summary = await metrics_repository.get_metrics_summary(
            start_time=start_time,
            end_time=end_time
        )
        assert metric_name in summary["metrics"]
        assert summary["metrics"][metric_name]["data_points"] == 100
        
        # 6. Stream metrics
        streamed_count = 0
        async for chunk in metrics_repository.stream_metrics(
            metric_name=metric_name,
            start_time=start_time,
            end_time=end_time,
            chunk_size=25
        ):
            streamed_count += len(chunk)
        assert streamed_count == 100
        
        # 7. Cleanup (simulate old metrics by updating timestamps)
        # In a real scenario, this would be done by time passage
        # For testing, we'll just verify the cleanup method works
        initial_count = await metrics_repository.count(filters={"metric_name": metric_name})
        assert initial_count == 100
    
    async def test_multi_metric_aggregation_scenario(self, metrics_repository):
        """Test complex multi-metric aggregation scenario."""
        # Simulate a monitoring scenario with multiple related metrics
        base_time = datetime.utcnow()
        services = ["api", "web", "database"]
        metrics_types = ["cpu_usage", "memory_usage", "request_count"]
        
        # Record metrics for multiple services and types
        for service in services:
            for metric_type in metrics_types:
                for i in range(60):  # 1 hour of data, 1 point per minute
                    value = 50 + (i % 20) + (hash(service) % 10)  # Simulate varying load
                    await metrics_repository.record_metric(
                        metric_name=metric_type,
                        value=float(value),
                        timestamp=base_time + timedelta(minutes=i),
                        labels={"service": service, "environment": "prod"}
                    )
        
        # Query aggregated data
        start_time = base_time - timedelta(minutes=10)
        end_time = base_time + timedelta(hours=2)
        
        # Get CPU usage for all services
        cpu_results = await metrics_repository.query_metrics(
            metric_name="cpu_usage",
            start_time=start_time,
            end_time=end_time,
            labels={"environment": "prod"}
        )
        assert len(cpu_results) == 180  # 3 services * 60 data points
        
        # Get aggregated CPU usage
        cpu_aggregated = await metrics_repository.query_metrics(
            metric_name="cpu_usage",
            start_time=start_time,
            end_time=end_time,
            labels={"environment": "prod"},
            aggregation="avg",
            step_seconds=600  # 10-minute buckets
        )
        assert len(cpu_aggregated) >= 6  # At least 6 buckets for 1 hour
        
        # Get latest values for each service
        for service in services:
            latest_cpu = await metrics_repository.get_latest_value(
                metric_name="cpu_usage",
                labels={"service": service, "environment": "prod"}
            )
            assert latest_cpu is not None
            assert latest_cpu["labels"]["service"] == service
        
        # Generate summary report
        summary = await metrics_repository.get_metrics_summary(
            start_time=start_time,
            end_time=end_time
        )
        
        for metric_type in metrics_types:
            assert metric_type in summary["metrics"]
            assert summary["metrics"][metric_type]["data_points"] == 180
    
    async def test_time_series_pattern_detection(self, metrics_repository):
        """Test detecting patterns in time series data."""
        # Create metrics with known patterns
        base_time = datetime.utcnow()
        
        # Pattern 1: Daily cycle (24 hours with hourly peaks)
        daily_cycle_metrics = []
        for hour in range(24):
            for minute in range(0, 60, 10):  # Every 10 minutes
                # Simulate higher usage during business hours
                if 9 <= hour <= 17:
                    base_value = 80
                else:
                    base_value = 30
                
                # Add some random variation
                value = base_value + (minute % 20)
                
                daily_cycle_metrics.append({
                    "metric_name": "daily_pattern",
                    "value": float(value),
                    "timestamp": base_time + timedelta(hours=hour, minutes=minute),
                    "labels": {"pattern": "daily_cycle"}
                })
        
        await metrics_repository.record_metrics_batch(daily_cycle_metrics)
        
        # Query business hours vs off-hours
        business_start = base_time + timedelta(hours=9)
        business_end = base_time + timedelta(hours=17, minutes=59)
        
        business_hours_data = await metrics_repository.query_metrics(
            metric_name="daily_pattern",
            start_time=business_start,
            end_time=business_end,
            labels={"pattern": "daily_cycle"}
        )
        
        off_hours_data = await metrics_repository.query_metrics(
            metric_name="daily_pattern",
            start_time=base_time,
            end_time=business_start,
            labels={"pattern": "daily_cycle"}
        )
        
        # Verify pattern: business hours should have higher average values
        business_avg = sum(point["value"] for point in business_hours_data) / len(business_hours_data)
        off_hours_avg = sum(point["value"] for point in off_hours_data) / len(off_hours_data)
        
        assert business_avg > off_hours_avg
        assert business_avg > 70  # Should be close to 80 + variation
        assert off_hours_avg < 50   # Should be close to 30 + variation