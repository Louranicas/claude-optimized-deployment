#!/usr/bin/env python3
"""
MCP Server Structured Logging Infrastructure
Implements comprehensive logging with structured data, log aggregation, 
analysis, and alert generation for MCP servers.
"""

import asyncio
import json
import logging
import logging.handlers
import os
import sys
import time
import traceback
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import structlog
import loguru
from pythonjsonlogger import jsonlogger

class LogLevel(Enum):
    """Log levels with numeric values"""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

class LogEventType(Enum):
    """Types of log events"""
    REQUEST = "request"
    RESPONSE = "response"
    ERROR = "error"
    PERFORMANCE = "performance"
    SECURITY = "security"
    AUDIT = "audit"
    SYSTEM = "system"
    BUSINESS = "business"

@dataclass
class LogContext:
    """Context information for structured logging"""
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    server_name: Optional[str] = None
    request_id: Optional[str] = None
    operation: Optional[str] = None

@dataclass
class LogEntry:
    """Structured log entry"""
    timestamp: datetime
    level: LogLevel
    message: str
    logger_name: str
    event_type: LogEventType
    context: LogContext
    fields: Dict[str, Any]
    exception: Optional[Dict[str, Any]] = None
    performance_metrics: Optional[Dict[str, float]] = None

class MCPLogger:
    """Comprehensive structured logging system for MCP servers"""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.log_entries: List[LogEntry] = []
        self.max_entries = self.config.get("max_memory_entries", 10000)
        self._setup_logging()
        self._setup_structlog()
        self._setup_loguru()
        self.logger = structlog.get_logger("mcp_logger")
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load logging configuration"""
        default_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "log_level": "INFO",
            "structured": True,
            "json_format": True,
            "include_timestamp": True,
            "include_caller": True,
            "include_thread": True,
            "include_process": True,
            "max_memory_entries": 10000,
            "outputs": {
                "console": {
                    "enabled": True,
                    "level": "INFO",
                    "format": "human",
                    "colors": True
                },
                "file": {
                    "enabled": True,
                    "level": "DEBUG",
                    "path": "/var/log/mcp-servers/mcp.log",
                    "max_size_mb": 100,
                    "backup_count": 10,
                    "format": "json"
                },
                "syslog": {
                    "enabled": True,
                    "level": "WARNING",
                    "address": "/dev/log",
                    "facility": "local0",
                    "format": "json"
                },
                "elasticsearch": {
                    "enabled": False,
                    "level": "INFO",
                    "hosts": ["localhost:9200"],
                    "index": "mcp-logs",
                    "doc_type": "_doc"
                },
                "fluentd": {
                    "enabled": False,
                    "level": "INFO",
                    "host": "localhost",
                    "port": 24224,
                    "tag": "mcp.logs"
                },
                "prometheus": {
                    "enabled": True,
                    "level": "ERROR",
                    "metrics_prefix": "mcp_log"
                }
            },
            "security": {
                "sanitize_sensitive_data": True,
                "sensitive_fields": [
                    "password", "token", "key", "secret", "auth",
                    "credential", "api_key", "private_key", "access_token"
                ],
                "max_field_length": 1000,
                "truncate_large_fields": True
            },
            "aggregation": {
                "enabled": True,
                "batch_size": 100,
                "flush_interval_seconds": 30,
                "error_threshold": 0.05,
                "alert_on_error_spike": True
            },
            "analysis": {
                "enabled": True,
                "pattern_detection": True,
                "anomaly_detection": True,
                "correlation_analysis": True,
                "performance_analysis": True
            },
            "alerting": {
                "enabled": True,
                "error_rate_threshold": 0.1,
                "response_time_threshold_ms": 5000,
                "alert_cooldown_minutes": 15,
                "escalation_levels": ["warning", "critical", "emergency"]
            }
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"Warning: Failed to load config file: {e}")
                
        return default_config

    def _setup_logging(self):
        """Setup standard Python logging"""
        # Ensure log directory exists
        file_config = self.config["outputs"]["file"]
        if file_config["enabled"]:
            log_path = Path(file_config["path"])
            log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.config["log_level"]))
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Setup formatters
        if self.config["json_format"]:
            formatter = jsonlogger.JsonFormatter(
                '%(asctime)s %(name)s %(levelname)s %(message)s',
                timestamp=True
            )
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        # Console handler
        console_config = self.config["outputs"]["console"]
        if console_config["enabled"]:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, console_config["level"]))
            
            if console_config["format"] == "human" and not self.config["json_format"]:
                console_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                console_handler.setFormatter(console_formatter)
            else:
                console_handler.setFormatter(formatter)
            
            root_logger.addHandler(console_handler)
        
        # File handler
        if file_config["enabled"]:
            file_handler = logging.handlers.RotatingFileHandler(
                file_config["path"],
                maxBytes=file_config["max_size_mb"] * 1024 * 1024,
                backupCount=file_config["backup_count"]
            )
            file_handler.setLevel(getattr(logging, file_config["level"]))
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        
        # Syslog handler
        syslog_config = self.config["outputs"]["syslog"]
        if syslog_config["enabled"]:
            try:
                syslog_handler = logging.handlers.SysLogHandler(
                    address=syslog_config["address"],
                    facility=getattr(
                        logging.handlers.SysLogHandler, 
                        f"LOG_{syslog_config['facility'].upper()}"
                    )
                )
                syslog_handler.setLevel(getattr(logging, syslog_config["level"]))
                syslog_handler.setFormatter(formatter)
                root_logger.addHandler(syslog_handler)
            except Exception as e:
                print(f"Warning: Failed to setup syslog handler: {e}")

    def _setup_structlog(self):
        """Setup structlog for structured logging"""
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            self._add_context_processor,
            self._sanitize_processor,
        ]
        
        if self.config["json_format"]:
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer(colors=True))
        
        structlog.configure(
            processors=processors,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

    def _setup_loguru(self):
        """Setup loguru for enhanced logging capabilities"""
        try:
            from loguru import logger as loguru_logger
            
            # Remove default handler
            loguru_logger.remove()
            
            # Add custom handlers
            file_config = self.config["outputs"]["file"]
            if file_config["enabled"]:
                loguru_logger.add(
                    file_config["path"],
                    level=file_config["level"],
                    format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {name}:{function}:{line} | {message}",
                    rotation=f"{file_config['max_size_mb']} MB",
                    retention=file_config["backup_count"],
                    serialize=self.config["json_format"]
                )
            
            console_config = self.config["outputs"]["console"]
            if console_config["enabled"]:
                loguru_logger.add(
                    sys.stdout,
                    level=console_config["level"],
                    format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>",
                    colorize=console_config.get("colors", True)
                )
        except ImportError:
            pass  # loguru is optional

    def _add_context_processor(self, logger, method_name, event_dict):
        """Add context information to log entries"""
        # Add default context
        event_dict.setdefault("service", "mcp-servers")
        event_dict.setdefault("environment", os.getenv("ENVIRONMENT", "production"))
        event_dict.setdefault("hostname", os.getenv("HOSTNAME", "unknown"))
        
        # Add process and thread info
        if self.config["include_process"]:
            event_dict["process_id"] = os.getpid()
        
        if self.config["include_thread"]:
            import threading
            event_dict["thread_id"] = threading.get_ident()
            event_dict["thread_name"] = threading.current_thread().name
        
        # Add caller information
        if self.config["include_caller"]:
            frame = sys._getframe(6)  # Adjust frame depth as needed
            event_dict["caller"] = {
                "filename": os.path.basename(frame.f_code.co_filename),
                "function": frame.f_code.co_name,
                "line": frame.f_lineno
            }
        
        return event_dict

    def _sanitize_processor(self, logger, method_name, event_dict):
        """Sanitize sensitive data in log entries"""
        if not self.config["security"]["sanitize_sensitive_data"]:
            return event_dict
        
        sensitive_fields = self.config["security"]["sensitive_fields"]
        max_length = self.config["security"]["max_field_length"]
        
        def sanitize_value(key, value):
            # Check if field is sensitive
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                return "[REDACTED]"
            
            # Truncate large fields
            if isinstance(value, str) and len(value) > max_length:
                if self.config["security"]["truncate_large_fields"]:
                    return value[:max_length] + "..."
                else:
                    return "[TRUNCATED]"
            
            return value
        
        def sanitize_dict(d):
            if isinstance(d, dict):
                return {k: sanitize_value(k, sanitize_dict(v)) for k, v in d.items()}
            elif isinstance(d, (list, tuple)):
                return [sanitize_dict(item) for item in d]
            else:
                return d
        
        return sanitize_dict(event_dict)

    def create_log_context(
        self,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        server_name: Optional[str] = None,
        request_id: Optional[str] = None,
        operation: Optional[str] = None
    ) -> LogContext:
        """Create a log context with correlation IDs"""
        return LogContext(
            trace_id=trace_id,
            span_id=span_id,
            correlation_id=correlation_id or str(uuid.uuid4()),
            user_id=user_id,
            session_id=session_id,
            server_name=server_name,
            request_id=request_id or str(uuid.uuid4()),
            operation=operation
        )

    def log_structured(
        self,
        level: LogLevel,
        message: str,
        event_type: LogEventType = LogEventType.SYSTEM,
        context: Optional[LogContext] = None,
        **fields
    ):
        """Log a structured message"""
        # Create log entry
        log_entry = LogEntry(
            timestamp=datetime.utcnow(),
            level=level,
            message=message,
            logger_name="mcp_logger",
            event_type=event_type,
            context=context or LogContext(),
            fields=fields
        )
        
        # Store in memory
        self.log_entries.append(log_entry)
        if len(self.log_entries) > self.max_entries:
            self.log_entries.pop(0)
        
        # Log using structlog
        logger = structlog.get_logger()
        log_data = {
            "event_type": event_type.value,
            "message": message,
            **fields
        }
        
        # Add context if provided
        if context:
            log_data.update({
                "trace_id": context.trace_id,
                "span_id": context.span_id,
                "correlation_id": context.correlation_id,
                "user_id": context.user_id,
                "session_id": context.session_id,
                "server_name": context.server_name,
                "request_id": context.request_id,
                "operation": context.operation
            })
        
        # Log at appropriate level
        if level == LogLevel.TRACE:
            logger.debug(**log_data)
        elif level == LogLevel.DEBUG:
            logger.debug(**log_data)
        elif level == LogLevel.INFO:
            logger.info(**log_data)
        elif level == LogLevel.WARNING:
            logger.warning(**log_data)
        elif level == LogLevel.ERROR:
            logger.error(**log_data)
        elif level == LogLevel.CRITICAL:
            logger.critical(**log_data)

    def log_request(
        self,
        method: str,
        url: str,
        context: LogContext,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Any] = None,
        duration_ms: Optional[float] = None
    ):
        """Log an MCP request"""
        fields = {
            "method": method,
            "url": url,
            "headers": headers or {},
            "duration_ms": duration_ms
        }
        
        if body is not None:
            # Limit body size for logging
            if isinstance(body, str):
                fields["body"] = body[:1000] + "..." if len(body) > 1000 else body
            else:
                fields["body_type"] = type(body).__name__
                fields["body_size"] = len(str(body))
        
        self.log_structured(
            LogLevel.INFO,
            f"MCP request: {method} {url}",
            LogEventType.REQUEST,
            context,
            **fields
        )

    def log_response(
        self,
        status_code: int,
        context: LogContext,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Any] = None,
        duration_ms: Optional[float] = None
    ):
        """Log an MCP response"""
        fields = {
            "status_code": status_code,
            "headers": headers or {},
            "duration_ms": duration_ms
        }
        
        if body is not None:
            if isinstance(body, str):
                fields["body"] = body[:1000] + "..." if len(body) > 1000 else body
            else:
                fields["body_type"] = type(body).__name__
                fields["body_size"] = len(str(body))
        
        level = LogLevel.INFO if status_code < 400 else LogLevel.ERROR
        message = f"MCP response: {status_code}"
        
        self.log_structured(
            level,
            message,
            LogEventType.RESPONSE,
            context,
            **fields
        )

    def log_error(
        self,
        error: Exception,
        context: LogContext,
        error_type: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ):
        """Log an error with full context"""
        fields = {
            "error_type": error_type or type(error).__name__,
            "error_message": str(error),
            "traceback": traceback.format_exc(),
            **(additional_data or {})
        }
        
        self.log_structured(
            LogLevel.ERROR,
            f"Error occurred: {str(error)}",
            LogEventType.ERROR,
            context,
            **fields
        )

    def log_performance(
        self,
        operation: str,
        duration_ms: float,
        context: LogContext,
        metrics: Optional[Dict[str, float]] = None,
        success: bool = True
    ):
        """Log performance metrics"""
        fields = {
            "operation": operation,
            "duration_ms": duration_ms,
            "success": success,
            **(metrics or {})
        }
        
        # Determine log level based on performance
        threshold = self.config["alerting"]["response_time_threshold_ms"]
        level = LogLevel.WARNING if duration_ms > threshold else LogLevel.INFO
        
        self.log_structured(
            level,
            f"Performance: {operation} took {duration_ms:.2f}ms",
            LogEventType.PERFORMANCE,
            context,
            **fields
        )

    def log_security_event(
        self,
        event_type: str,
        severity: str,
        context: LogContext,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log security-related events"""
        fields = {
            "security_event_type": event_type,
            "severity": severity,
            **(details or {})
        }
        
        level = {
            "low": LogLevel.INFO,
            "medium": LogLevel.WARNING,
            "high": LogLevel.ERROR,
            "critical": LogLevel.CRITICAL
        }.get(severity.lower(), LogLevel.WARNING)
        
        self.log_structured(
            level,
            f"Security event: {event_type}",
            LogEventType.SECURITY,
            context,
            **fields
        )

    def log_audit(
        self,
        action: str,
        resource: str,
        context: LogContext,
        outcome: str = "success",
        details: Optional[Dict[str, Any]] = None
    ):
        """Log audit events"""
        fields = {
            "action": action,
            "resource": resource,
            "outcome": outcome,
            **(details or {})
        }
        
        self.log_structured(
            LogLevel.INFO,
            f"Audit: {action} on {resource} - {outcome}",
            LogEventType.AUDIT,
            context,
            **fields
        )

    def log_business_event(
        self,
        event_name: str,
        context: LogContext,
        metrics: Optional[Dict[str, Any]] = None,
        user_impact: Optional[str] = None
    ):
        """Log business-related events"""
        fields = {
            "event_name": event_name,
            "user_impact": user_impact,
            **(metrics or {})
        }
        
        self.log_structured(
            LogLevel.INFO,
            f"Business event: {event_name}",
            LogEventType.BUSINESS,
            context,
            **fields
        )

    def analyze_logs(self, time_window_minutes: int = 60) -> Dict[str, Any]:
        """Analyze recent logs for patterns and anomalies"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        recent_logs = [
            entry for entry in self.log_entries 
            if entry.timestamp >= cutoff_time
        ]
        
        if not recent_logs:
            return {"error": "No logs in specified time window"}
        
        # Basic statistics
        total_logs = len(recent_logs)
        error_logs = len([e for e in recent_logs if e.level == LogLevel.ERROR])
        warning_logs = len([e for e in recent_logs if e.level == LogLevel.WARNING])
        
        # Event type distribution
        event_types = {}
        for entry in recent_logs:
            event_type = entry.event_type.value
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # Server distribution
        servers = {}
        for entry in recent_logs:
            server = entry.context.server_name or "unknown"
            servers[server] = servers.get(server, 0) + 1
        
        # Error rate
        error_rate = error_logs / total_logs if total_logs > 0 else 0
        
        # Performance analysis
        performance_logs = [
            e for e in recent_logs 
            if e.event_type == LogEventType.PERFORMANCE and e.performance_metrics
        ]
        
        avg_response_time = 0
        if performance_logs:
            response_times = [
                e.performance_metrics.get("duration_ms", 0) 
                for e in performance_logs
                if e.performance_metrics
            ]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Common error patterns
        error_patterns = {}
        error_entries = [e for e in recent_logs if e.level == LogLevel.ERROR]
        for entry in error_entries:
            error_type = entry.fields.get("error_type", "unknown")
            error_patterns[error_type] = error_patterns.get(error_type, 0) + 1
        
        analysis = {
            "time_window_minutes": time_window_minutes,
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "statistics": {
                "total_logs": total_logs,
                "error_logs": error_logs,
                "warning_logs": warning_logs,
                "error_rate": error_rate,
                "avg_response_time_ms": avg_response_time
            },
            "distributions": {
                "event_types": event_types,
                "servers": servers,
                "error_patterns": error_patterns
            },
            "alerts": []
        }
        
        # Generate alerts based on thresholds
        alerting_config = self.config["alerting"]
        if alerting_config["enabled"]:
            if error_rate > alerting_config["error_rate_threshold"]:
                analysis["alerts"].append({
                    "type": "high_error_rate",
                    "severity": "warning",
                    "message": f"Error rate ({error_rate:.2%}) exceeds threshold ({alerting_config['error_rate_threshold']:.2%})",
                    "value": error_rate,
                    "threshold": alerting_config["error_rate_threshold"]
                })
            
            if avg_response_time > alerting_config["response_time_threshold_ms"]:
                analysis["alerts"].append({
                    "type": "slow_response_time",
                    "severity": "warning",
                    "message": f"Average response time ({avg_response_time:.2f}ms) exceeds threshold ({alerting_config['response_time_threshold_ms']}ms)",
                    "value": avg_response_time,
                    "threshold": alerting_config["response_time_threshold_ms"]
                })
        
        return analysis

    def get_log_summary(self, server_name: Optional[str] = None) -> Dict[str, Any]:
        """Get summary of logged events"""
        logs_to_analyze = self.log_entries
        
        if server_name:
            logs_to_analyze = [
                e for e in self.log_entries 
                if e.context.server_name == server_name
            ]
        
        if not logs_to_analyze:
            return {"message": "No logs found"}
        
        # Recent activity (last hour)
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_logs = [e for e in logs_to_analyze if e.timestamp >= one_hour_ago]
        
        level_counts = {}
        event_type_counts = {}
        
        for entry in recent_logs:
            level = entry.level.name
            level_counts[level] = level_counts.get(level, 0) + 1
            
            event_type = entry.event_type.value
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        
        return {
            "total_logs": len(logs_to_analyze),
            "recent_logs_1h": len(recent_logs),
            "level_distribution": level_counts,
            "event_type_distribution": event_type_counts,
            "oldest_log": logs_to_analyze[0].timestamp.isoformat() if logs_to_analyze else None,
            "newest_log": logs_to_analyze[-1].timestamp.isoformat() if logs_to_analyze else None,
            "server_filter": server_name
        }

    def search_logs(
        self,
        query: str,
        level: Optional[LogLevel] = None,
        event_type: Optional[LogEventType] = None,
        server_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search logs with filters"""
        results = []
        
        for entry in self.log_entries:
            # Apply filters
            if level and entry.level != level:
                continue
            if event_type and entry.event_type != event_type:
                continue
            if server_name and entry.context.server_name != server_name:
                continue
            if start_time and entry.timestamp < start_time:
                continue
            if end_time and entry.timestamp > end_time:
                continue
            
            # Search in message and fields
            entry_text = json.dumps(asdict(entry), default=str).lower()
            if query.lower() in entry_text:
                results.append(asdict(entry))
                
                if len(results) >= limit:
                    break
        
        return results

# Context manager for automatic logging
class LoggingContext:
    """Context manager for automatic request/response logging"""
    
    def __init__(
        self,
        logger: MCPLogger,
        operation: str,
        context: LogContext,
        log_request: bool = True,
        log_response: bool = True,
        log_performance: bool = True
    ):
        self.logger = logger
        self.operation = operation
        self.context = context
        self.log_request = log_request
        self.log_response = log_response
        self.log_performance = log_performance
        self.start_time: Optional[float] = None

    def __enter__(self):
        self.start_time = time.time()
        if self.log_request:
            self.logger.log_structured(
                LogLevel.INFO,
                f"Starting operation: {self.operation}",
                LogEventType.REQUEST,
                self.context,
                operation=self.operation
            )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = (time.time() - self.start_time) * 1000 if self.start_time else 0
        success = exc_type is None
        
        if exc_type:
            self.logger.log_error(exc_val, self.context, additional_data={
                "operation": self.operation,
                "duration_ms": duration_ms
            })
        
        if self.log_response:
            level = LogLevel.INFO if success else LogLevel.ERROR
            message = f"Completed operation: {self.operation}"
            if not success:
                message += f" with error: {exc_type.__name__}"
            
            self.logger.log_structured(
                level,
                message,
                LogEventType.RESPONSE,
                self.context,
                operation=self.operation,
                success=success,
                duration_ms=duration_ms
            )
        
        if self.log_performance:
            self.logger.log_performance(
                self.operation,
                duration_ms,
                self.context,
                success=success
            )

# Decorators for automatic logging
def log_mcp_operation(
    operation_name: Optional[str] = None,
    log_args: bool = False,
    log_result: bool = False
):
    """Decorator to automatically log MCP operations"""
    def decorator(func: Callable) -> Callable:
        async def async_wrapper(*args, **kwargs):
            # Try to get logger from globals or create one
            logger = getattr(func, '_mcp_logger', None) or MCPLogger()
            
            operation = operation_name or f"{func.__module__}.{func.__name__}"
            context = LogContext(
                operation=operation,
                correlation_id=str(uuid.uuid4())
            )
            
            with LoggingContext(logger, operation, context):
                if log_args and (args or kwargs):
                    logger.log_structured(
                        LogLevel.DEBUG,
                        f"Function arguments for {operation}",
                        LogEventType.AUDIT,
                        context,
                        args=str(args)[:500],
                        kwargs=str(kwargs)[:500]
                    )
                
                result = await func(*args, **kwargs)
                
                if log_result and result is not None:
                    logger.log_structured(
                        LogLevel.DEBUG,
                        f"Function result for {operation}",
                        LogEventType.AUDIT,
                        context,
                        result_type=type(result).__name__,
                        result_size=len(str(result)) if hasattr(result, '__len__') else None
                    )
                
                return result
        
        def sync_wrapper(*args, **kwargs):
            logger = getattr(func, '_mcp_logger', None) or MCPLogger()
            
            operation = operation_name or f"{func.__module__}.{func.__name__}"
            context = LogContext(
                operation=operation,
                correlation_id=str(uuid.uuid4())
            )
            
            with LoggingContext(logger, operation, context):
                if log_args and (args or kwargs):
                    logger.log_structured(
                        LogLevel.DEBUG,
                        f"Function arguments for {operation}",
                        LogEventType.AUDIT,
                        context,
                        args=str(args)[:500],
                        kwargs=str(kwargs)[:500]
                    )
                
                result = func(*args, **kwargs)
                
                if log_result and result is not None:
                    logger.log_structured(
                        LogLevel.DEBUG,
                        f"Function result for {operation}",
                        LogEventType.AUDIT,
                        context,
                        result_type=type(result).__name__,
                        result_size=len(str(result)) if hasattr(result, '__len__') else None
                    )
                
                return result
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

# Global logger instance
_global_logger: Optional[MCPLogger] = None

def init_global_logger(config_path: str = None) -> MCPLogger:
    """Initialize global logger instance"""
    global _global_logger
    _global_logger = MCPLogger(config_path)
    return _global_logger

def get_global_logger() -> Optional[MCPLogger]:
    """Get global logger instance"""
    return _global_logger

# Example usage and CLI
async def main():
    import argparse
    parser = argparse.ArgumentParser(description="MCP Server Logging System")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--demo", action="store_true", help="Run logging demonstration")
    parser.add_argument("--analyze", action="store_true", help="Analyze recent logs")
    parser.add_argument("--search", help="Search logs for specific query")
    parser.add_argument("--server", help="Filter by server name")
    parser.add_argument("--level", help="Filter by log level")
    parser.add_argument("--summary", action="store_true", help="Show log summary")
    
    args = parser.parse_args()
    
    # Initialize logger
    logger = init_global_logger(args.config)
    
    if args.demo:
        print("Running logging demonstration...")
        
        # Create context
        context = logger.create_log_context(
            server_name="demo-server",
            operation="demo_operation",
            user_id="demo_user"
        )
        
        # Demonstrate different log types
        logger.log_structured(LogLevel.INFO, "Starting demonstration", context=context)
        
        logger.log_request("GET", "/api/tools", context, headers={"User-Agent": "Demo"})
        
        logger.log_performance("tool_execution", 150.5, context, 
                             metrics={"cpu_usage": 25.0, "memory_mb": 128})
        
        logger.log_security_event("authentication_attempt", "medium", context,
                                details={"source_ip": "192.168.1.100"})
        
        logger.log_audit("tool_access", "filesystem", context, outcome="success")
        
        logger.log_business_event("user_interaction", context, 
                                metrics={"tools_used": 3, "session_duration": 300})
        
        # Simulate an error
        try:
            raise ValueError("Demo error for logging")
        except Exception as e:
            logger.log_error(e, context, error_type="demo_error")
        
        logger.log_response(200, context, duration_ms=175.2)
        
        print("Demonstration completed.")
    
    if args.analyze:
        analysis = logger.analyze_logs()
        print("Log Analysis:")
        print(json.dumps(analysis, indent=2))
    
    if args.search:
        level_filter = None
        if args.level:
            level_filter = getattr(LogLevel, args.level.upper(), None)
        
        results = logger.search_logs(
            args.search,
            level=level_filter,
            server_name=args.server,
            limit=50
        )
        
        print(f"Search Results ({len(results)} entries):")
        for result in results:
            print(json.dumps(result, indent=2, default=str))
    
    if args.summary:
        summary = logger.get_log_summary(args.server)
        print("Log Summary:")
        print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    asyncio.run(main())