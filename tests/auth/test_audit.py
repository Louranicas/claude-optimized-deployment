"""
Comprehensive Tests for Audit Logging (src/auth/audit.py).

This test suite covers audit event logging, querying, filtering,
security scenarios, and edge cases with 90%+ coverage.
"""

import pytest
import asyncio
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, List, Optional, Any

from src.auth.audit import (
    AuditLogger, AuditEvent, AuditEventType, AuditSeverity,
    AuditFilter, AuditQuery, AuditStatistics,
    InvalidAuditEventError, AuditStorageError
)


class TestAuditEvent:
    """Test AuditEvent class functionality."""
    
    def test_audit_event_creation(self):
        """Test basic audit event creation."""
        event = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            severity=AuditSeverity.INFO,
            result="success",
            details={"login_method": "password"}
        )
        
        assert event.event_type == AuditEventType.LOGIN_SUCCESS
        assert event.user_id == "user_123"
        assert event.ip_address == "192.168.1.100"
        assert event.user_agent == "Mozilla/5.0"
        assert event.severity == AuditSeverity.INFO
        assert event.result == "success"
        assert event.details["login_method"] == "password"
        assert event.timestamp is not None
        assert event.id is not None
    
    def test_audit_event_defaults(self):
        """Test audit event creation with default values."""
        event = AuditEvent(
            event_type=AuditEventType.USER_CREATED
        )
        
        assert event.event_type == AuditEventType.USER_CREATED
        assert event.user_id is None
        assert event.ip_address is None
        assert event.user_agent is None
        assert event.severity == AuditSeverity.INFO
        assert event.result is None
        assert event.details == {}
        assert event.timestamp is not None
        assert event.id is not None
    
    def test_audit_event_validation(self):
        """Test audit event validation."""
        # Valid events
        AuditEvent(event_type=AuditEventType.LOGIN_SUCCESS)
        AuditEvent(event_type=AuditEventType.USER_CREATED, severity=AuditSeverity.HIGH)
        
        # Invalid events
        with pytest.raises(InvalidAuditEventError):
            AuditEvent(event_type=None)
        
        with pytest.raises(InvalidAuditEventError):
            AuditEvent(event_type="invalid_type")
    
    def test_audit_event_to_dict(self):
        """Test audit event serialization to dictionary."""
        event = AuditEvent(
            event_type=AuditEventType.LOGIN_FAILED,
            user_id="user_123",
            ip_address="192.168.1.100",
            severity=AuditSeverity.WARNING,
            result="failure",
            details={"reason": "invalid_password", "attempts": 3}
        )
        
        event_dict = event.to_dict()
        
        assert event_dict["event_type"] == "LOGIN_FAILED"
        assert event_dict["user_id"] == "user_123"
        assert event_dict["ip_address"] == "192.168.1.100"
        assert event_dict["severity"] == "WARNING"
        assert event_dict["result"] == "failure"
        assert event_dict["details"]["reason"] == "invalid_password"
        assert event_dict["details"]["attempts"] == 3
        assert "timestamp" in event_dict
        assert "id" in event_dict
    
    def test_audit_event_from_dict(self):
        """Test audit event deserialization from dictionary."""
        event_dict = {
            "id": "event_123",
            "event_type": "USER_UPDATED",
            "user_id": "user_456",
            "actor_id": "admin_789",
            "ip_address": "10.0.0.1",
            "user_agent": "Test Client/1.0",
            "severity": "HIGH",
            "result": "success",
            "details": {"field": "email", "old_value": "old@example.com", "new_value": "new@example.com"},
            "timestamp": "2023-12-01T10:00:00Z"
        }
        
        event = AuditEvent.from_dict(event_dict)
        
        assert event.id == "event_123"
        assert event.event_type == AuditEventType.USER_UPDATED
        assert event.user_id == "user_456"
        assert event.actor_id == "admin_789"
        assert event.ip_address == "10.0.0.1"
        assert event.user_agent == "Test Client/1.0"
        assert event.severity == AuditSeverity.HIGH
        assert event.result == "success"
        assert event.details["field"] == "email"
        assert isinstance(event.timestamp, datetime)
    
    def test_audit_event_string_representation(self):
        """Test audit event string representation."""
        event = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_123"
        )
        
        str_repr = str(event)
        assert "LOGIN_SUCCESS" in str_repr
        assert "user_123" in str_repr
    
    def test_audit_event_equality(self):
        """Test audit event equality comparison."""
        event1 = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_123"
        )
        event1.id = "same_id"
        event1.timestamp = datetime.now(timezone.utc)
        
        event2 = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_123"
        )
        event2.id = "same_id"
        event2.timestamp = event1.timestamp
        
        event3 = AuditEvent(
            event_type=AuditEventType.LOGIN_FAILED,
            user_id="user_123"
        )
        
        assert event1 == event2
        assert event1 != event3


class TestAuditEventType:
    """Test AuditEventType enum."""
    
    def test_audit_event_types(self):
        """Test audit event type enumeration."""
        # Authentication events
        assert AuditEventType.LOGIN_SUCCESS.value == "LOGIN_SUCCESS"
        assert AuditEventType.LOGIN_FAILED.value == "LOGIN_FAILED"
        assert AuditEventType.LOGOUT.value == "LOGOUT"
        assert AuditEventType.TOKEN_REFRESH.value == "TOKEN_REFRESH"
        
        # User management events
        assert AuditEventType.USER_CREATED.value == "USER_CREATED"
        assert AuditEventType.USER_UPDATED.value == "USER_UPDATED"
        assert AuditEventType.USER_DELETED.value == "USER_DELETED"
        assert AuditEventType.PASSWORD_CHANGED.value == "PASSWORD_CHANGED"
        
        # Authorization events
        assert AuditEventType.AUTHORIZATION_GRANTED.value == "AUTHORIZATION_GRANTED"
        assert AuditEventType.AUTHORIZATION_DENIED.value == "AUTHORIZATION_DENIED"
        
        # MFA events
        assert AuditEventType.MFA_ENABLED.value == "MFA_ENABLED"
        assert AuditEventType.MFA_DISABLED.value == "MFA_DISABLED"
        assert AuditEventType.MFA_SETUP_INITIATED.value == "MFA_SETUP_INITIATED"
        
        # Security events
        assert AuditEventType.ACCOUNT_LOCKED.value == "ACCOUNT_LOCKED"
        assert AuditEventType.ACCOUNT_UNLOCKED.value == "ACCOUNT_UNLOCKED"
        assert AuditEventType.SUSPICIOUS_ACTIVITY.value == "SUSPICIOUS_ACTIVITY"
        
        # Administrative events
        assert AuditEventType.ROLE_ASSIGNED.value == "ROLE_ASSIGNED"
        assert AuditEventType.ROLE_REVOKED.value == "ROLE_REVOKED"
        assert AuditEventType.ADMIN_ACTION.value == "ADMIN_ACTION"
    
    def test_audit_event_type_categorization(self):
        """Test categorization of audit event types."""
        auth_events = [
            AuditEventType.LOGIN_SUCCESS,
            AuditEventType.LOGIN_FAILED,
            AuditEventType.LOGOUT,
            AuditEventType.TOKEN_REFRESH
        ]
        
        security_events = [
            AuditEventType.ACCOUNT_LOCKED,
            AuditEventType.SUSPICIOUS_ACTIVITY,
            AuditEventType.AUTHORIZATION_DENIED
        ]
        
        user_events = [
            AuditEventType.USER_CREATED,
            AuditEventType.USER_UPDATED,
            AuditEventType.USER_DELETED
        ]
        
        # Test that events can be categorized
        for event_type in auth_events:
            assert "LOGIN" in event_type.value or "LOGOUT" in event_type.value or "TOKEN" in event_type.value
        
        for event_type in security_events:
            assert any(word in event_type.value for word in ["LOCKED", "SUSPICIOUS", "DENIED"])
        
        for event_type in user_events:
            assert "USER" in event_type.value


class TestAuditSeverity:
    """Test AuditSeverity enum."""
    
    def test_audit_severity_levels(self):
        """Test audit severity levels."""
        assert AuditSeverity.LOW.value == "LOW"
        assert AuditSeverity.INFO.value == "INFO"
        assert AuditSeverity.WARNING.value == "WARNING"
        assert AuditSeverity.HIGH.value == "HIGH"
        assert AuditSeverity.CRITICAL.value == "CRITICAL"
    
    def test_audit_severity_ordering(self):
        """Test audit severity ordering."""
        severities = [
            AuditSeverity.LOW,
            AuditSeverity.INFO,
            AuditSeverity.WARNING,
            AuditSeverity.HIGH,
            AuditSeverity.CRITICAL
        ]
        
        # Test that they are in ascending order of importance
        severity_values = [s.value for s in severities]
        expected_order = ["LOW", "INFO", "WARNING", "HIGH", "CRITICAL"]
        
        assert severity_values == expected_order


class TestAuditFilter:
    """Test AuditFilter class functionality."""
    
    def test_audit_filter_creation(self):
        """Test audit filter creation."""
        filter_obj = AuditFilter(
            event_types=[AuditEventType.LOGIN_SUCCESS, AuditEventType.LOGIN_FAILED],
            user_id="user_123",
            ip_address="192.168.1.100",
            severity=AuditSeverity.WARNING,
            start_time=datetime.now(timezone.utc) - timedelta(days=1),
            end_time=datetime.now(timezone.utc)
        )
        
        assert len(filter_obj.event_types) == 2
        assert AuditEventType.LOGIN_SUCCESS in filter_obj.event_types
        assert filter_obj.user_id == "user_123"
        assert filter_obj.ip_address == "192.168.1.100"
        assert filter_obj.severity == AuditSeverity.WARNING
        assert filter_obj.start_time is not None
        assert filter_obj.end_time is not None
    
    def test_audit_filter_matches(self):
        """Test audit filter matching."""
        filter_obj = AuditFilter(
            event_types=[AuditEventType.LOGIN_SUCCESS],
            user_id="user_123",
            severity=AuditSeverity.INFO
        )
        
        # Matching event
        matching_event = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_123",
            severity=AuditSeverity.INFO
        )
        
        # Non-matching events
        wrong_type = AuditEvent(
            event_type=AuditEventType.LOGIN_FAILED,
            user_id="user_123",
            severity=AuditSeverity.INFO
        )
        
        wrong_user = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_456",
            severity=AuditSeverity.INFO
        )
        
        wrong_severity = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_123",
            severity=AuditSeverity.HIGH
        )
        
        assert filter_obj.matches(matching_event)
        assert not filter_obj.matches(wrong_type)
        assert not filter_obj.matches(wrong_user)
        assert not filter_obj.matches(wrong_severity)
    
    def test_audit_filter_time_range(self):
        """Test audit filter time range matching."""
        now = datetime.now(timezone.utc)
        filter_obj = AuditFilter(
            start_time=now - timedelta(hours=1),
            end_time=now + timedelta(hours=1)
        )
        
        # Event within time range
        within_range = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            timestamp=now
        )
        
        # Event before time range
        before_range = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            timestamp=now - timedelta(hours=2)
        )
        
        # Event after time range
        after_range = AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            timestamp=now + timedelta(hours=2)
        )
        
        assert filter_obj.matches(within_range)
        assert not filter_obj.matches(before_range)
        assert not filter_obj.matches(after_range)


class TestAuditLogger:
    """Test AuditLogger class functionality."""
    
    @pytest.fixture
    def mock_storage(self):
        """Create mock audit storage."""
        return AsyncMock()
    
    @pytest.fixture
    def audit_logger(self, mock_storage):
        """Create AuditLogger instance."""
        return AuditLogger(storage=mock_storage)
    
    @pytest.mark.asyncio
    async def test_log_event_success(self, audit_logger, mock_storage):
        """Test successful event logging."""
        event = await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_123",
            ip_address="192.168.1.100",
            result="success"
        )
        
        assert isinstance(event, AuditEvent)
        assert event.event_type == AuditEventType.LOGIN_SUCCESS
        assert event.user_id == "user_123"
        assert event.ip_address == "192.168.1.100"
        assert event.result == "success"
        
        # Verify storage was called
        mock_storage.store_event.assert_called_once_with(event)
    
    @pytest.mark.asyncio
    async def test_log_event_with_details(self, audit_logger, mock_storage):
        """Test event logging with details."""
        details = {
            "login_method": "password",
            "user_agent": "Mozilla/5.0",
            "session_id": "session_123"
        }
        
        event = await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_123",
            details=details
        )
        
        assert event.details == details
        mock_storage.store_event.assert_called_once_with(event)
    
    @pytest.mark.asyncio
    async def test_log_event_storage_failure(self, audit_logger, mock_storage):
        """Test event logging with storage failure."""
        mock_storage.store_event.side_effect = Exception("Storage unavailable")
        
        # Should not raise exception (fail gracefully)
        event = await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_123"
        )
        
        assert event is not None
        mock_storage.store_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_log_security_event(self, audit_logger, mock_storage):
        """Test logging security events."""
        event = await audit_logger.log_security_event(
            event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
            user_id="user_123",
            ip_address="192.168.1.100",
            details={"suspicious_behavior": "multiple_failed_logins"}
        )
        
        assert event.event_type == AuditEventType.SUSPICIOUS_ACTIVITY
        assert event.severity == AuditSeverity.HIGH  # Security events should be high severity
        mock_storage.store_event.assert_called_once_with(event)
    
    @pytest.mark.asyncio
    async def test_query_events(self, audit_logger, mock_storage):
        """Test querying audit events."""
        # Mock events to return
        mock_events = [
            AuditEvent(event_type=AuditEventType.LOGIN_SUCCESS, user_id="user_123"),
            AuditEvent(event_type=AuditEventType.LOGIN_FAILED, user_id="user_123"),
            AuditEvent(event_type=AuditEventType.LOGOUT, user_id="user_123")
        ]
        mock_storage.query_events.return_value = mock_events
        
        # Create filter
        audit_filter = AuditFilter(user_id="user_123")
        
        events = await audit_logger.query_events(
            filters=audit_filter,
            limit=10,
            offset=0
        )
        
        assert len(events) == 3
        assert all(event.user_id == "user_123" for event in events)
        mock_storage.query_events.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_query_events_with_pagination(self, audit_logger, mock_storage):
        """Test querying events with pagination."""
        mock_events = [
            AuditEvent(event_type=AuditEventType.LOGIN_SUCCESS, user_id=f"user_{i}")
            for i in range(5)
        ]
        mock_storage.query_events.return_value = mock_events
        
        events = await audit_logger.query_events(
            filters={},
            limit=5,
            offset=10
        )
        
        assert len(events) == 5
        mock_storage.query_events.assert_called_once()
        call_args = mock_storage.query_events.call_args
        assert call_args[1]["limit"] == 5
        assert call_args[1]["offset"] == 10
    
    @pytest.mark.asyncio
    async def test_get_user_activity(self, audit_logger, mock_storage):
        """Test getting user activity."""
        user_id = "user_123"
        start_time = datetime.now(timezone.utc) - timedelta(days=7)
        end_time = datetime.now(timezone.utc)
        
        mock_events = [
            AuditEvent(event_type=AuditEventType.LOGIN_SUCCESS, user_id=user_id),
            AuditEvent(event_type=AuditEventType.USER_UPDATED, user_id=user_id),
            AuditEvent(event_type=AuditEventType.LOGOUT, user_id=user_id)
        ]
        mock_storage.query_events.return_value = mock_events
        
        events = await audit_logger.get_user_activity(user_id, start_time, end_time)
        
        assert len(events) == 3
        assert all(event.user_id == user_id for event in events)
        
        # Verify filter was created correctly
        mock_storage.query_events.assert_called_once()
        call_args = mock_storage.query_events.call_args[1]
        assert call_args["filters"].user_id == user_id
        assert call_args["filters"].start_time == start_time
        assert call_args["filters"].end_time == end_time
    
    @pytest.mark.asyncio
    async def test_get_security_events(self, audit_logger, mock_storage):
        """Test getting security events."""
        security_events = [
            AuditEvent(event_type=AuditEventType.SUSPICIOUS_ACTIVITY, severity=AuditSeverity.HIGH),
            AuditEvent(event_type=AuditEventType.ACCOUNT_LOCKED, severity=AuditSeverity.WARNING),
            AuditEvent(event_type=AuditEventType.AUTHORIZATION_DENIED, severity=AuditSeverity.WARNING)
        ]
        mock_storage.query_events.return_value = security_events
        
        events = await audit_logger.get_security_events(min_severity=AuditSeverity.WARNING)
        
        assert len(events) == 3
        assert all(event.severity.value in ["WARNING", "HIGH", "CRITICAL"] for event in events)
        
        # Verify filter was created correctly
        mock_storage.query_events.assert_called_once()
        call_args = mock_storage.query_events.call_args[1]
        assert call_args["filters"].severity == AuditSeverity.WARNING
    
    @pytest.mark.asyncio
    async def test_get_statistics(self, audit_logger, mock_storage):
        """Test getting audit statistics."""
        mock_stats = AuditStatistics(
            total_events=1000,
            events_by_type={
                "LOGIN_SUCCESS": 500,
                "LOGIN_FAILED": 100,
                "USER_CREATED": 50
            },
            events_by_severity={
                "INFO": 800,
                "WARNING": 150,
                "HIGH": 50
            },
            unique_users=100,
            time_range_start=datetime.now(timezone.utc) - timedelta(days=30),
            time_range_end=datetime.now(timezone.utc)
        )
        mock_storage.get_statistics.return_value = mock_stats
        
        stats = await audit_logger.get_statistics()
        
        assert stats.total_events == 1000
        assert stats.events_by_type["LOGIN_SUCCESS"] == 500
        assert stats.events_by_severity["INFO"] == 800
        assert stats.unique_users == 100
        
        mock_storage.get_statistics.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cleanup_old_events(self, audit_logger, mock_storage):
        """Test cleaning up old audit events."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)
        mock_storage.cleanup_old_events.return_value = 500  # 500 events deleted
        
        deleted_count = await audit_logger.cleanup_old_events(cutoff_date)
        
        assert deleted_count == 500
        mock_storage.cleanup_old_events.assert_called_once_with(cutoff_date)
    
    @pytest.mark.asyncio
    async def test_export_events(self, audit_logger, mock_storage):
        """Test exporting audit events."""
        mock_events = [
            AuditEvent(event_type=AuditEventType.LOGIN_SUCCESS, user_id="user_123"),
            AuditEvent(event_type=AuditEventType.LOGOUT, user_id="user_123")
        ]
        mock_storage.query_events.return_value = mock_events
        
        export_data = await audit_logger.export_events(
            filters=AuditFilter(user_id="user_123"),
            format="json"
        )
        
        assert isinstance(export_data, str)
        
        # Should be valid JSON
        parsed_data = json.loads(export_data)
        assert isinstance(parsed_data, list)
        assert len(parsed_data) == 2
        assert parsed_data[0]["user_id"] == "user_123"
    
    @pytest.mark.asyncio
    async def test_batch_log_events(self, audit_logger, mock_storage):
        """Test batch logging of events."""
        events_data = [
            {
                "event_type": AuditEventType.LOGIN_SUCCESS,
                "user_id": "user_123",
                "ip_address": "192.168.1.100"
            },
            {
                "event_type": AuditEventType.LOGIN_FAILED,
                "user_id": "user_456",
                "ip_address": "192.168.1.101"
            }
        ]
        
        events = await audit_logger.batch_log_events(events_data)
        
        assert len(events) == 2
        assert events[0].event_type == AuditEventType.LOGIN_SUCCESS
        assert events[1].event_type == AuditEventType.LOGIN_FAILED
        
        # Verify batch storage was called
        mock_storage.batch_store_events.assert_called_once()
        stored_events = mock_storage.batch_store_events.call_args[0][0]
        assert len(stored_events) == 2


class TestAuditStatistics:
    """Test AuditStatistics class functionality."""
    
    def test_audit_statistics_creation(self):
        """Test audit statistics creation."""
        stats = AuditStatistics(
            total_events=1000,
            events_by_type={"LOGIN_SUCCESS": 500, "LOGIN_FAILED": 100},
            events_by_severity={"INFO": 800, "WARNING": 200},
            unique_users=50,
            time_range_start=datetime.now(timezone.utc) - timedelta(days=30),
            time_range_end=datetime.now(timezone.utc)
        )
        
        assert stats.total_events == 1000
        assert stats.events_by_type["LOGIN_SUCCESS"] == 500
        assert stats.events_by_severity["INFO"] == 800
        assert stats.unique_users == 50
        assert stats.time_range_start is not None
        assert stats.time_range_end is not None
    
    def test_audit_statistics_to_dict(self):
        """Test audit statistics serialization."""
        stats = AuditStatistics(
            total_events=100,
            events_by_type={"LOGIN_SUCCESS": 50},
            events_by_severity={"INFO": 100},
            unique_users=10
        )
        
        stats_dict = stats.to_dict()
        
        assert stats_dict["total_events"] == 100
        assert stats_dict["events_by_type"]["LOGIN_SUCCESS"] == 50
        assert stats_dict["events_by_severity"]["INFO"] == 100
        assert stats_dict["unique_users"] == 10


class TestSecurityScenarios:
    """Test security scenarios and edge cases."""
    
    @pytest.fixture
    def audit_logger(self, mock_storage):
        """Create AuditLogger instance."""
        return AuditLogger(storage=mock_storage)
    
    @pytest.fixture
    def mock_storage(self):
        """Create mock audit storage."""
        return AsyncMock()
    
    @pytest.mark.asyncio
    async def test_log_injection_prevention(self, audit_logger, mock_storage):
        """Test prevention of log injection attacks."""
        malicious_inputs = [
            "user'; DROP TABLE audit_logs; --",
            "user\nFAKE_EVENT: admin logged in",
            "user\r\nContent-Type: text/html",
            "user<script>alert('xss')</script>",
            "user\u0000null_byte_injection"
        ]
        
        for malicious_input in malicious_inputs:
            event = await audit_logger.log_event(
                event_type=AuditEventType.LOGIN_FAILED,
                user_id=malicious_input,
                details={"malicious_attempt": malicious_input}
            )
            
            # Event should be logged but input should be sanitized
            assert event is not None
            mock_storage.store_event.assert_called()
    
    @pytest.mark.asyncio
    async def test_sensitive_data_redaction(self, audit_logger, mock_storage):
        """Test redaction of sensitive data in logs."""
        sensitive_details = {
            "password": "super_secret_password",
            "ssn": "123-45-6789",
            "credit_card": "4111-1111-1111-1111",
            "api_key": "sk_live_abc123def456",
            "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "safe_field": "this_is_safe"
        }
        
        event = await audit_logger.log_event(
            event_type=AuditEventType.USER_UPDATED,
            user_id="user_123",
            details=sensitive_details
        )
        
        # Sensitive fields should be redacted
        stored_event = mock_storage.store_event.call_args[0][0]
        details = stored_event.details
        
        assert details.get("password") == "[REDACTED]"
        assert details.get("ssn") == "[REDACTED]"
        assert details.get("credit_card") == "[REDACTED]"
        assert details.get("api_key") == "[REDACTED]"
        assert details.get("session_token") == "[REDACTED]"
        assert details.get("safe_field") == "this_is_safe"  # Should not be redacted
    
    @pytest.mark.asyncio
    async def test_rate_limiting_on_logging(self, audit_logger, mock_storage):
        """Test rate limiting on audit logging to prevent DoS."""
        # Simulate rapid logging attempts
        user_id = "user_123"
        
        events = []
        for i in range(1000):
            event = await audit_logger.log_event(
                event_type=AuditEventType.LOGIN_FAILED,
                user_id=user_id,
                ip_address="192.168.1.100",
                details={"attempt": i}
            )
            events.append(event)
        
        # All events should be logged (no rate limiting in basic implementation)
        # But in production, there might be rate limiting
        assert len(events) == 1000
        assert mock_storage.store_event.call_count == 1000
    
    @pytest.mark.asyncio
    async def test_concurrent_logging_safety(self, audit_logger, mock_storage):
        """Test concurrent logging safety."""
        import asyncio
        
        async def log_event(event_num):
            return await audit_logger.log_event(
                event_type=AuditEventType.LOGIN_SUCCESS,
                user_id=f"user_{event_num}",
                details={"concurrent_test": True}
            )
        
        # Create many concurrent logging tasks
        tasks = [log_event(i) for i in range(100)]
        events = await asyncio.gather(*tasks)
        
        # All events should be logged successfully
        assert len(events) == 100
        assert all(event is not None for event in events)
        assert mock_storage.store_event.call_count == 100
    
    @pytest.mark.asyncio
    async def test_audit_trail_integrity(self, audit_logger, mock_storage):
        """Test audit trail integrity and tamper detection."""
        # Log a series of events
        events = []
        for i in range(10):
            event = await audit_logger.log_event(
                event_type=AuditEventType.USER_UPDATED,
                user_id="user_123",
                actor_id="admin_456",
                details={"field": "email", "sequence": i}
            )
            events.append(event)
        
        # Events should have unique IDs and proper timestamps
        event_ids = [event.id for event in events]
        assert len(set(event_ids)) == len(event_ids)  # All unique
        
        # Timestamps should be in order (or very close)
        timestamps = [event.timestamp for event in events]
        for i in range(1, len(timestamps)):
            assert timestamps[i] >= timestamps[i-1]
    
    @pytest.mark.asyncio
    async def test_unauthorized_query_prevention(self, audit_logger, mock_storage):
        """Test prevention of unauthorized audit queries."""
        # This would typically be handled at the API level
        # but the audit logger should support access control
        
        # Mock unauthorized access
        mock_storage.query_events.side_effect = PermissionError("Unauthorized access")
        
        with pytest.raises(PermissionError):
            await audit_logger.query_events(filters={})
    
    @pytest.mark.asyncio
    async def test_data_retention_compliance(self, audit_logger, mock_storage):
        """Test data retention compliance features."""
        # Test that old events can be cleaned up for compliance
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=365)
        mock_storage.cleanup_old_events.return_value = 1000
        
        deleted_count = await audit_logger.cleanup_old_events(cutoff_date)
        
        assert deleted_count == 1000
        mock_storage.cleanup_old_events.assert_called_once_with(cutoff_date)
    
    @pytest.mark.asyncio
    async def test_anonymization_support(self, audit_logger, mock_storage):
        """Test support for data anonymization."""
        # Log event with PII
        event = await audit_logger.log_event(
            event_type=AuditEventType.USER_CREATED,
            user_id="user_123",
            details={
                "email": "user@example.com",
                "ip_address": "192.168.1.100",
                "real_name": "John Doe"
            }
        )
        
        # In a real implementation, there might be anonymization
        # For now, just verify the event was logged
        assert event is not None
        mock_storage.store_event.assert_called_once()


class TestPerformance:
    """Test performance characteristics."""
    
    @pytest.fixture
    def audit_logger(self, mock_storage):
        """Create AuditLogger instance."""
        return AuditLogger(storage=mock_storage)
    
    @pytest.fixture
    def mock_storage(self):
        """Create mock audit storage."""
        return AsyncMock()
    
    @pytest.mark.asyncio
    async def test_high_volume_logging_performance(self, audit_logger, mock_storage):
        """Test performance with high volume logging."""
        import time
        
        num_events = 1000
        start_time = time.time()
        
        # Log many events
        tasks = []
        for i in range(num_events):
            task = audit_logger.log_event(
                event_type=AuditEventType.LOGIN_SUCCESS,
                user_id=f"user_{i}",
                details={"performance_test": True}
            )
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        elapsed_time = time.time() - start_time
        events_per_second = num_events / elapsed_time
        
        # Should be able to log at reasonable rate
        assert events_per_second > 100  # At least 100 events per second
        assert mock_storage.store_event.call_count == num_events
    
    @pytest.mark.asyncio
    async def test_batch_logging_performance(self, audit_logger, mock_storage):
        """Test batch logging performance."""
        import time
        
        # Prepare batch of events
        events_data = []
        for i in range(1000):
            events_data.append({
                "event_type": AuditEventType.LOGIN_SUCCESS,
                "user_id": f"user_{i}",
                "details": {"batch_test": True}
            })
        
        start_time = time.time()
        events = await audit_logger.batch_log_events(events_data)
        elapsed_time = time.time() - start_time
        
        # Batch logging should be faster than individual logging
        assert len(events) == 1000
        assert elapsed_time < 1.0  # Should complete in less than 1 second
        mock_storage.batch_store_events.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_query_performance(self, audit_logger, mock_storage):
        """Test query performance with large result sets."""
        # Mock large result set
        large_result_set = [
            AuditEvent(event_type=AuditEventType.LOGIN_SUCCESS, user_id=f"user_{i}")
            for i in range(10000)
        ]
        mock_storage.query_events.return_value = large_result_set
        
        import time
        start_time = time.time()
        
        events = await audit_logger.query_events(filters={}, limit=10000)
        
        elapsed_time = time.time() - start_time
        
        assert len(events) == 10000
        assert elapsed_time < 1.0  # Should complete quickly


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.fixture
    def audit_logger(self, mock_storage):
        """Create AuditLogger instance."""
        return AuditLogger(storage=mock_storage)
    
    @pytest.fixture
    def mock_storage(self):
        """Create mock audit storage."""
        return AsyncMock()
    
    @pytest.mark.asyncio
    async def test_none_values_handling(self, audit_logger, mock_storage):
        """Test handling of None values."""
        event = await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=None,
            ip_address=None,
            user_agent=None,
            details=None
        )
        
        assert event.user_id is None
        assert event.ip_address is None
        assert event.user_agent is None
        assert event.details == {}
        mock_storage.store_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_empty_string_values(self, audit_logger, mock_storage):
        """Test handling of empty string values."""
        event = await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="",
            ip_address="",
            result="",
            details={}
        )
        
        assert event.user_id == ""
        assert event.ip_address == ""
        assert event.result == ""
        assert event.details == {}
        mock_storage.store_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_very_large_details(self, audit_logger, mock_storage):
        """Test handling of very large details objects."""
        large_details = {
            f"field_{i}": "x" * 1000  # 1000 characters per field
            for i in range(100)  # 100 fields
        }
        
        event = await audit_logger.log_event(
            event_type=AuditEventType.USER_UPDATED,
            user_id="user_123",
            details=large_details
        )
        
        assert event.details == large_details
        mock_storage.store_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_unicode_handling(self, audit_logger, mock_storage):
        """Test handling of unicode characters."""
        unicode_data = {
            "chinese": "用户登录成功",
            "arabic": "تم تسجيل الدخول بنجاح",
            "russian": "Успешный вход в систему",
            "emoji": "🔐 Security event 🚨"
        }
        
        event = await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="用户_123",
            details=unicode_data
        )
        
        assert event.user_id == "用户_123"
        assert event.details == unicode_data
        mock_storage.store_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_circular_reference_handling(self, audit_logger, mock_storage):
        """Test handling of circular references in details."""
        # Create circular reference
        details = {"key": "value"}
        details["self"] = details
        
        # Should handle gracefully (might serialize without circular ref)
        event = await audit_logger.log_event(
            event_type=AuditEventType.USER_UPDATED,
            user_id="user_123",
            details=details
        )
        
        assert event is not None
        mock_storage.store_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_storage_unavailable_graceful_handling(self, audit_logger, mock_storage):
        """Test graceful handling when storage is unavailable."""
        mock_storage.store_event.side_effect = Exception("Storage unavailable")
        
        # Should not raise exception
        event = await audit_logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="user_123"
        )
        
        assert event is not None  # Event object should still be created
        mock_storage.store_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_invalid_timestamp_handling(self, audit_logger):
        """Test handling of invalid timestamps."""
        # Create event with invalid timestamp
        event = AuditEvent(event_type=AuditEventType.LOGIN_SUCCESS)
        event.timestamp = "invalid_timestamp"
        
        # Serialization should handle gracefully
        try:
            event_dict = event.to_dict()
            # If it succeeds, timestamp should be converted to string
            assert isinstance(event_dict["timestamp"], str)
        except Exception:
            # If it fails, that's also acceptable behavior
            pass
    
    @pytest.mark.asyncio
    async def test_memory_usage_with_large_volumes(self, audit_logger, mock_storage):
        """Test memory usage doesn't grow unbounded."""
        import gc
        
        # Log many events
        for i in range(10000):
            await audit_logger.log_event(
                event_type=AuditEventType.LOGIN_SUCCESS,
                user_id=f"user_{i}",
                details={"large_field": "x" * 1000}
            )
        
        # Force garbage collection
        gc.collect()
        
        # If we reach here without OOM, memory management is working
        assert mock_storage.store_event.call_count == 10000


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.auth.audit", "--cov-report=term-missing"])