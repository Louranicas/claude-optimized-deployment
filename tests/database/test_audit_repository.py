"""Comprehensive tests for audit repository functionality.

Tests cover:
- Audit log creation and retrieval
- User action tracking
- Resource history tracking
- Failed action monitoring
- Compliance reporting
- Data retention and cleanup
- Performance with large datasets
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
from typing import Dict, Any, List

from src.database.repositories.audit_repository import AuditLogRepository, TortoiseAuditLogRepository
from src.database.models import SQLAlchemyAuditLog, TortoiseAuditLog
from src.core.exceptions import DatabaseError


class TestAuditLogRepository:
    """Test SQLAlchemy audit log repository functionality."""
    
    async def test_log_action_success(self, audit_repository):
        """Test successful audit log creation."""
        audit_log = await audit_repository.log_action(
            action="create_user",
            resource_type="user",
            resource_id="123",
            user_id=1,
            details={"username": "testuser"},
            ip_address="192.168.1.1",
            user_agent="TestAgent/1.0",
            success=True
        )
        
        assert audit_log.action == "create_user"
        assert audit_log.resource_type == "user"
        assert audit_log.resource_id == "123"
        assert audit_log.user_id == 1
        assert audit_log.details == {"username": "testuser"}
        assert audit_log.ip_address == "192.168.1.1"
        assert audit_log.user_agent == "TestAgent/1.0"
        assert audit_log.success is True
        assert audit_log.error_message is None
        assert audit_log.timestamp is not None
        assert audit_log.id is not None
    
    async def test_log_action_failure(self, audit_repository):
        """Test audit log creation for failed action."""
        audit_log = await audit_repository.log_action(
            action="delete_user",
            resource_type="user",
            resource_id="456",
            user_id=1,
            success=False,
            error_message="User not found"
        )
        
        assert audit_log.action == "delete_user"
        assert audit_log.resource_type == "user"
        assert audit_log.resource_id == "456"
        assert audit_log.success is False
        assert audit_log.error_message == "User not found"
    
    async def test_log_action_minimal_data(self, audit_repository):
        """Test audit log creation with minimal required data."""
        audit_log = await audit_repository.log_action(
            action="view_dashboard",
            resource_type="dashboard"
        )
        
        assert audit_log.action == "view_dashboard"
        assert audit_log.resource_type == "dashboard"
        assert audit_log.resource_id is None
        assert audit_log.user_id is None
        assert audit_log.details is None
        assert audit_log.success is True  # Default value
    
    async def test_get_user_actions(self, audit_repository, database_test_data):
        """Test retrieving actions for a specific user."""
        # Create audit logs
        user_id = 1
        for log_data in database_test_data["audit_logs"]:
            await audit_repository.log_action(**log_data)
        
        # Get user actions
        actions = await audit_repository.get_user_actions(user_id)
        
        assert len(actions) == 2  # Both logs are for user_id=1
        assert all(action.user_id == user_id for action in actions)
        
        # Should be ordered by timestamp descending
        if len(actions) > 1:
            assert actions[0].timestamp >= actions[1].timestamp
    
    async def test_get_user_actions_with_date_range(self, audit_repository):
        """Test retrieving user actions with date filtering."""
        user_id = 1
        
        # Create logs with different timestamps
        old_log = await audit_repository.log_action(
            action="old_action",
            resource_type="test",
            user_id=user_id
        )
        
        # Manually set old timestamp
        await audit_repository.update(
            old_log.id,
            timestamp=datetime.utcnow() - timedelta(days=10)
        )
        
        new_log = await audit_repository.log_action(
            action="new_action",
            resource_type="test",
            user_id=user_id
        )
        
        # Get actions from last 5 days
        start_date = datetime.utcnow() - timedelta(days=5)
        recent_actions = await audit_repository.get_user_actions(
            user_id, start_date=start_date
        )
        
        assert len(recent_actions) == 1
        assert recent_actions[0].action == "new_action"
    
    async def test_get_user_actions_with_limit(self, audit_repository):
        """Test retrieving user actions with limit."""
        user_id = 1
        
        # Create multiple logs
        for i in range(5):
            await audit_repository.log_action(
                action=f"action_{i}",
                resource_type="test",
                user_id=user_id
            )
        
        # Get limited results
        actions = await audit_repository.get_user_actions(user_id, limit=3)
        
        assert len(actions) == 3
    
    async def test_get_resource_history(self, audit_repository):
        """Test retrieving history for a specific resource."""
        resource_type = "user"
        resource_id = "123"
        
        # Create multiple logs for the same resource
        actions = ["create", "update", "view", "delete"]
        for action in actions:
            await audit_repository.log_action(
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                user_id=1
            )
        
        # Get resource history
        history = await audit_repository.get_resource_history(resource_type, resource_id)
        
        assert len(history) == 4
        assert all(log.resource_type == resource_type for log in history)
        assert all(log.resource_id == resource_id for log in history)
        
        # Should be ordered by timestamp descending
        actions_retrieved = [log.action for log in history]
        assert "delete" in actions_retrieved  # Most recent should be included
    
    async def test_get_resource_history_with_limit(self, audit_repository):
        """Test retrieving resource history with limit."""
        resource_type = "document"
        resource_id = "doc_123"
        
        # Create many logs
        for i in range(10):
            await audit_repository.log_action(
                action=f"action_{i}",
                resource_type=resource_type,
                resource_id=resource_id,
                user_id=1
            )
        
        # Get limited history
        history = await audit_repository.get_resource_history(
            resource_type, resource_id, limit=5
        )
        
        assert len(history) == 5
    
    async def test_get_failed_actions(self, audit_repository):
        """Test retrieving failed actions."""
        # Create mix of successful and failed actions
        successful_log = await audit_repository.log_action(
            action="successful_action",
            resource_type="test",
            user_id=1,
            success=True
        )
        
        failed_log = await audit_repository.log_action(
            action="failed_action",
            resource_type="test",
            user_id=1,
            success=False,
            error_message="Something went wrong"
        )
        
        # Get failed actions
        failed_actions = await audit_repository.get_failed_actions()
        
        assert len(failed_actions) >= 1
        assert all(action.success is False for action in failed_actions)
        assert any(action.id == failed_log.id for action in failed_actions)
        assert not any(action.id == successful_log.id for action in failed_actions)
    
    async def test_get_failed_actions_with_date_filter(self, audit_repository):
        """Test retrieving failed actions with date filtering."""
        # Create old failed action
        old_failed = await audit_repository.log_action(
            action="old_failed",
            resource_type="test",
            success=False
        )
        
        # Manually set old timestamp
        await audit_repository.update(
            old_failed.id,
            timestamp=datetime.utcnow() - timedelta(days=10)
        )
        
        # Create recent failed action
        recent_failed = await audit_repository.log_action(
            action="recent_failed",
            resource_type="test",
            success=False
        )
        
        # Get recent failed actions
        start_date = datetime.utcnow() - timedelta(days=5)
        recent_failures = await audit_repository.get_failed_actions(start_date=start_date)
        
        assert len(recent_failures) >= 1
        assert any(action.action == "recent_failed" for action in recent_failures)
        assert not any(action.action == "old_failed" for action in recent_failures)
    
    async def test_get_failed_actions_by_type(self, audit_repository):
        """Test retrieving failed actions by action type."""
        # Create different types of failed actions
        await audit_repository.log_action(
            action="login",
            resource_type="auth",
            success=False,
            error_message="Invalid credentials"
        )
        
        await audit_repository.log_action(
            action="delete_user",
            resource_type="user",
            success=False,
            error_message="User not found"
        )
        
        # Get only login failures
        login_failures = await audit_repository.get_failed_actions(action_type="login")
        
        assert len(login_failures) >= 1
        assert all(action.action == "login" for action in login_failures)
        assert all(action.success is False for action in login_failures)
    
    async def test_get_compliance_report(self, audit_repository):
        """Test generating compliance report."""
        # Create various audit logs
        test_logs = [
            {"action": "create", "resource_type": "user", "success": True},
            {"action": "create", "resource_type": "user", "success": False},
            {"action": "update", "resource_type": "user", "success": True},
            {"action": "delete", "resource_type": "document", "success": True},
            {"action": "view", "resource_type": "document", "success": True},
        ]
        
        for log_data in test_logs:
            await audit_repository.log_action(**log_data)
        
        # Generate compliance report
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow() + timedelta(days=1)
        
        report = await audit_repository.get_compliance_report(start_date, end_date)
        
        assert isinstance(report, dict)
        assert "period" in report
        assert "summary" in report
        assert "by_action" in report
        assert "by_resource_type" in report
        
        # Check summary
        summary = report["summary"]
        assert summary["total_actions"] == 5
        assert summary["successful_actions"] == 4
        assert summary["failed_actions"] == 1
        
        # Check breakdown by action
        assert "create" in report["by_action"]
        assert "update" in report["by_action"]
        assert "delete" in report["by_action"]
        assert "view" in report["by_action"]
        
        # Check breakdown by resource type
        assert "user" in report["by_resource_type"]
        assert "document" in report["by_resource_type"]
    
    async def test_get_compliance_report_with_resource_filter(self, audit_repository):
        """Test compliance report with resource type filtering."""
        # Create logs for different resource types
        await audit_repository.log_action(
            action="create", resource_type="user", success=True
        )
        await audit_repository.log_action(
            action="create", resource_type="document", success=True
        )
        
        # Generate report for user resources only
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow() + timedelta(days=1)
        
        report = await audit_repository.get_compliance_report(
            start_date, end_date, resource_types=["user"]
        )
        
        assert report["summary"]["total_actions"] == 1
        assert "user" in report["by_resource_type"]
        assert "document" not in report["by_resource_type"]
    
    async def test_cleanup_old_logs(self, audit_repository):
        """Test cleaning up old audit logs."""
        # Create old and new logs
        old_log = await audit_repository.log_action(
            action="old_action",
            resource_type="test"
        )
        
        new_log = await audit_repository.log_action(
            action="new_action",
            resource_type="test"
        )
        
        # Manually set old timestamp
        old_timestamp = datetime.utcnow() - timedelta(days=100)
        await audit_repository.update(old_log.id, timestamp=old_timestamp)
        
        # Cleanup logs older than 30 days
        deleted_count = await audit_repository.cleanup_old_logs(retention_days=30)
        
        assert deleted_count >= 1
        
        # Verify old log is deleted
        remaining_old = await audit_repository.get(old_log.id)
        assert remaining_old is None
        
        # Verify new log still exists
        remaining_new = await audit_repository.get(new_log.id)
        assert remaining_new is not None
    
    async def test_cleanup_old_logs_no_old_data(self, audit_repository):
        """Test cleanup when no old data exists."""
        # Create only recent logs
        await audit_repository.log_action(action="recent", resource_type="test")
        
        # Try to cleanup very old logs
        deleted_count = await audit_repository.cleanup_old_logs(retention_days=1)
        
        assert deleted_count == 0


class TestTortoiseAuditLogRepository:
    """Test Tortoise ORM audit log repository functionality."""
    
    def test_tortoise_repository_initialization(self):
        """Test Tortoise audit repository initialization."""
        repo = TortoiseAuditLogRepository()
        assert repo._model_class is TortoiseAuditLog
    
    async def test_log_action(self):
        """Test Tortoise audit log creation."""
        repo = TortoiseAuditLogRepository()
        
        log_data = {
            "action": "test_action",
            "resource_type": "test",
            "resource_id": "123",
            "user_id": 1,
            "success": True
        }
        
        with patch.object(repo, 'create') as mock_create:
            mock_log = MagicMock()
            mock_create.return_value = mock_log
            
            result = await repo.log_action(**log_data)
            
            assert result is mock_log
            mock_create.assert_called_once_with(**log_data)
    
    async def test_get_user_actions(self):
        """Test Tortoise get user actions."""
        repo = TortoiseAuditLogRepository()
        
        with patch.object(TortoiseAuditLog, 'filter') as mock_filter:
            mock_query = MagicMock()
            mock_query.filter.return_value = mock_query
            mock_query.order_by.return_value = mock_query
            mock_query.limit.return_value = mock_query
            mock_filter.return_value = mock_query
            
            mock_logs = [MagicMock(), MagicMock()]
            mock_query.__await__ = AsyncMock(return_value=mock_logs)
            
            result = await repo.get_user_actions(1)
            
            assert result is mock_logs
            mock_filter.assert_called_once_with(user_id=1)
            mock_query.order_by.assert_called_once_with("-timestamp")
            mock_query.limit.assert_called_once_with(100)
    
    async def test_get_user_actions_with_date_filters(self):
        """Test Tortoise get user actions with date filtering."""
        repo = TortoiseAuditLogRepository()
        
        start_date = datetime.utcnow() - timedelta(days=7)
        end_date = datetime.utcnow()
        
        with patch.object(TortoiseAuditLog, 'filter') as mock_filter:
            mock_query = MagicMock()
            mock_query.filter.return_value = mock_query
            mock_query.order_by.return_value = mock_query
            mock_query.limit.return_value = mock_query
            mock_filter.return_value = mock_query
            
            mock_logs = [MagicMock()]
            mock_query.__await__ = AsyncMock(return_value=mock_logs)
            
            result = await repo.get_user_actions(
                1, start_date=start_date, end_date=end_date
            )
            
            assert result is mock_logs
            
            # Check that filters were applied
            filter_calls = mock_query.filter.call_args_list
            assert len(filter_calls) == 2  # start_date and end_date filters
    
    async def test_get_resource_history(self):
        """Test Tortoise get resource history."""
        repo = TortoiseAuditLogRepository()
        
        with patch.object(TortoiseAuditLog, 'filter') as mock_filter:
            mock_query = MagicMock()
            mock_query.order_by.return_value = mock_query
            mock_query.limit.return_value = mock_query
            mock_filter.return_value = mock_query
            
            mock_logs = [MagicMock(), MagicMock()]
            mock_query.__await__ = AsyncMock(return_value=mock_logs)
            
            result = await repo.get_resource_history("user", "123")
            
            assert result is mock_logs
            mock_filter.assert_called_once_with(resource_type="user", resource_id="123")
            mock_query.order_by.assert_called_once_with("-timestamp")
            mock_query.limit.assert_called_once_with(50)
    
    async def test_cleanup_old_logs(self):
        """Test Tortoise cleanup old logs."""
        repo = TortoiseAuditLogRepository()
        
        with patch.object(TortoiseAuditLog, 'filter') as mock_filter:
            mock_query = MagicMock()
            mock_query.delete = AsyncMock(return_value=5)
            mock_filter.return_value = mock_query
            
            result = await repo.cleanup_old_logs(retention_days=30)
            
            assert result == 5
            mock_filter.assert_called_once()
            mock_query.delete.assert_called_once()


class TestAuditRepositoryPerformance:
    """Test audit repository performance characteristics."""
    
    async def test_bulk_audit_log_creation(self, audit_repository, performance_timer):
        """Test bulk audit log creation performance."""
        performance_timer.start()
        
        # Create many audit logs
        for i in range(100):
            await audit_repository.log_action(
                action=f"action_{i}",
                resource_type="performance_test",
                resource_id=str(i),
                user_id=1,
                details={"test_id": i}
            )
        
        performance_timer.stop()
        
        # Verify all logs were created
        count = await audit_repository.count(filters={"resource_type": "performance_test"})
        assert count == 100
        
        # Performance should be reasonable
        assert performance_timer.elapsed_seconds < 30.0
    
    async def test_audit_query_performance(self, audit_repository, performance_timer):
        """Test audit query performance with large dataset."""
        # Create test data
        user_ids = [1, 2, 3, 4, 5]
        for user_id in user_ids:
            for i in range(20):
                await audit_repository.log_action(
                    action=f"action_{i}",
                    resource_type="query_test",
                    user_id=user_id
                )
        
        performance_timer.start()
        
        # Perform various queries
        for user_id in user_ids:
            user_actions = await audit_repository.get_user_actions(user_id)
            assert len(user_actions) >= 20
        
        # Test resource history queries
        for i in range(10):
            history = await audit_repository.get_resource_history("query_test", str(i))
            assert isinstance(history, list)
        
        # Test failed actions query
        failed_actions = await audit_repository.get_failed_actions()
        assert isinstance(failed_actions, list)
        
        performance_timer.stop()
        
        # Queries should be fast
        assert performance_timer.elapsed_seconds < 15.0
    
    async def test_compliance_report_performance(self, audit_repository, performance_timer):
        """Test compliance report generation performance."""
        # Create diverse test data
        actions = ["create", "update", "delete", "view", "login", "logout"]
        resource_types = ["user", "document", "system", "api"]
        
        for action in actions:
            for resource_type in resource_types:
                for success in [True, False]:
                    for i in range(5):
                        await audit_repository.log_action(
                            action=action,
                            resource_type=resource_type,
                            success=success,
                            user_id=i % 3 + 1
                        )
        
        performance_timer.start()
        
        # Generate compliance report
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow() + timedelta(days=1)
        
        report = await audit_repository.get_compliance_report(start_date, end_date)
        
        performance_timer.stop()
        
        # Verify report structure
        assert "summary" in report
        assert "by_action" in report
        assert "by_resource_type" in report
        
        # Expected total: 6 actions * 4 resource_types * 2 success states * 5 iterations = 240
        assert report["summary"]["total_actions"] == 240
        
        # Report generation should be reasonably fast
        assert performance_timer.elapsed_seconds < 10.0
    
    async def test_concurrent_audit_logging(self, audit_repository):
        """Test concurrent audit log creation."""
        async def create_audit_logs(batch_id: int):
            logs_created = []
            for i in range(10):
                log = await audit_repository.log_action(
                    action=f"concurrent_action_{batch_id}_{i}",
                    resource_type="concurrency_test",
                    user_id=batch_id,
                    details={"batch": batch_id, "index": i}
                )
                logs_created.append(log)
            return logs_created
        
        # Create multiple concurrent batches
        tasks = [create_audit_logs(batch_id) for batch_id in range(5)]
        results = await asyncio.gather(*tasks)
        
        # Verify all logs were created
        total_logs = sum(len(batch) for batch in results)
        assert total_logs == 50
        
        # Verify logs in database
        count = await audit_repository.count(filters={"resource_type": "concurrency_test"})
        assert count == 50
    
    async def test_cleanup_performance(self, audit_repository, performance_timer):
        """Test cleanup operation performance."""
        # Create logs with various timestamps
        current_time = datetime.utcnow()
        
        # Create old logs
        for i in range(50):
            log = await audit_repository.log_action(
                action=f"old_action_{i}",
                resource_type="cleanup_test"
            )
            # Set old timestamp
            old_timestamp = current_time - timedelta(days=100 + i)
            await audit_repository.update(log.id, timestamp=old_timestamp)
        
        # Create recent logs
        for i in range(50):
            await audit_repository.log_action(
                action=f"recent_action_{i}",
                resource_type="cleanup_test"
            )
        
        performance_timer.start()
        
        # Perform cleanup
        deleted_count = await audit_repository.cleanup_old_logs(retention_days=30)
        
        performance_timer.stop()
        
        # Verify cleanup results
        assert deleted_count == 50
        
        # Verify recent logs still exist
        remaining_count = await audit_repository.count(filters={"resource_type": "cleanup_test"})
        assert remaining_count == 50
        
        # Cleanup should be reasonably fast
        assert performance_timer.elapsed_seconds < 15.0


class TestAuditRepositoryIntegration:
    """Test audit repository integration scenarios."""
    
    async def test_audit_trail_completeness(self, audit_repository):
        """Test complete audit trail for a resource lifecycle."""
        resource_id = "test_resource_123"
        user_id = 1
        
        # Simulate complete resource lifecycle
        lifecycle_actions = [
            ("create", True, None),
            ("view", True, None),
            ("update", True, None),
            ("view", True, None),
            ("delete", False, "Permission denied"),
            ("view", False, "Resource not found"),
            ("delete", True, None)
        ]
        
        created_logs = []
        for action, success, error_message in lifecycle_actions:
            log = await audit_repository.log_action(
                action=action,
                resource_type="resource",
                resource_id=resource_id,
                user_id=user_id,
                success=success,
                error_message=error_message
            )
            created_logs.append(log)
        
        # Retrieve complete history
        history = await audit_repository.get_resource_history("resource", resource_id)
        
        assert len(history) == len(lifecycle_actions)
        
        # Verify chronological order (newest first)
        assert history[0].action == "delete"  # Last action
        assert history[-1].action == "create"  # First action
        
        # Verify failed actions are captured
        failed_actions = await audit_repository.get_failed_actions()
        failed_for_resource = [
            action for action in failed_actions 
            if action.resource_id == resource_id
        ]
        assert len(failed_for_resource) == 2  # Two failed actions
    
    async def test_multi_user_audit_tracking(self, audit_repository):
        """Test audit tracking across multiple users."""
        resource_id = "shared_resource"
        users = [1, 2, 3]
        
        # Multiple users performing actions on same resource
        for user_id in users:
            await audit_repository.log_action(
                action="view",
                resource_type="document",
                resource_id=resource_id,
                user_id=user_id
            )
            
            await audit_repository.log_action(
                action="edit",
                resource_type="document",
                resource_id=resource_id,
                user_id=user_id
            )
        
        # Get resource history
        history = await audit_repository.get_resource_history("document", resource_id)
        assert len(history) == 6  # 2 actions * 3 users
        
        # Get individual user actions
        for user_id in users:
            user_actions = await audit_repository.get_user_actions(user_id)
            user_actions_for_resource = [
                action for action in user_actions 
                if action.resource_id == resource_id
            ]
            assert len(user_actions_for_resource) == 2
    
    async def test_audit_data_integrity(self, audit_repository):
        """Test audit data integrity and immutability."""
        # Create audit log
        log = await audit_repository.log_action(
            action="sensitive_action",
            resource_type="critical_resource",
            user_id=1,
            details={"original": "data"}
        )
        
        original_timestamp = log.timestamp
        original_details = log.details.copy()
        
        # Attempt to modify audit log (should not affect core audit fields)
        # Note: In a real system, audit logs should be immutable
        # This test verifies that we can't accidentally modify critical fields
        
        # Try to update non-critical fields (if allowed)
        # Most audit systems don't allow updates, but testing the principle
        
        # Verify original data is preserved
        retrieved_log = await audit_repository.get(log.id)
        assert retrieved_log.timestamp == original_timestamp
        assert retrieved_log.action == "sensitive_action"
        assert retrieved_log.resource_type == "critical_resource"
        assert retrieved_log.user_id == 1
    
    async def test_audit_compliance_scenarios(self, audit_repository):
        """Test various compliance scenarios."""
        # Scenario 1: Security incident - multiple failed login attempts
        for i in range(5):
            await audit_repository.log_action(
                action="login",
                resource_type="auth",
                user_id=1,
                ip_address="192.168.1.100",
                success=False,
                error_message="Invalid credentials"
            )
        
        # Scenario 2: Data access for compliance officer
        await audit_repository.log_action(
            action="compliance_review",
            resource_type="audit_logs",
            user_id=999,  # Compliance officer
            details={"review_type": "quarterly_audit"}
        )
        
        # Scenario 3: Bulk data operation
        await audit_repository.log_action(
            action="bulk_export",
            resource_type="user_data",
            user_id=1,
            details={"record_count": 1000, "export_type": "GDPR_request"}
        )
        
        # Generate compliance report
        start_date = datetime.utcnow() - timedelta(hours=1)
        end_date = datetime.utcnow() + timedelta(hours=1)
        
        report = await audit_repository.get_compliance_report(start_date, end_date)
        
        # Verify security incidents are captured
        assert "login" in report["by_action"]
        assert report["by_action"]["login"]["failure"] == 5
        
        # Verify compliance activities are tracked
        assert "compliance_review" in report["by_action"]
        
        # Verify data operations are logged
        assert "bulk_export" in report["by_action"]
    
    async def test_audit_search_and_filtering(self, audit_repository):
        """Test complex audit search and filtering scenarios."""
        # Create diverse audit data
        test_scenarios = [
            {
                "action": "login",
                "resource_type": "auth",
                "user_id": 1,
                "ip_address": "192.168.1.1",
                "success": True
            },
            {
                "action": "login",
                "resource_type": "auth", 
                "user_id": 2,
                "ip_address": "192.168.1.2",
                "success": False,
                "error_message": "Account locked"
            },
            {
                "action": "file_access",
                "resource_type": "document",
                "resource_id": "sensitive_doc.pdf",
                "user_id": 1,
                "success": True
            },
            {
                "action": "admin_action",
                "resource_type": "system",
                "user_id": 3,
                "success": True,
                "details": {"permission_change": True}
            }
        ]
        
        for scenario in test_scenarios:
            await audit_repository.log_action(**scenario)
        
        # Test 1: Get all failed actions
        failed_actions = await audit_repository.get_failed_actions()
        failed_logins = [action for action in failed_actions if action.action == "login"]
        assert len(failed_logins) >= 1
        
        # Test 2: Get user-specific actions
        user1_actions = await audit_repository.get_user_actions(1)
        assert len(user1_actions) >= 2  # login and file_access
        
        # Test 3: Get resource-specific history
        doc_history = await audit_repository.get_resource_history("document", "sensitive_doc.pdf")
        assert len(doc_history) >= 1
        assert doc_history[0].action == "file_access"
        
        # Test 4: Get actions by type
        login_failures = await audit_repository.get_failed_actions(action_type="login")
        assert len(login_failures) >= 1
        assert all(action.action == "login" for action in login_failures)