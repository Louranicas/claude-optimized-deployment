#!/usr/bin/env python3
"""
Log-Based Metrics Collector
Extract metrics and insights from application and system logs
"""

import re
import time
import logging
import threading
import os
import glob
import gzip
import json
import queue
from typing import Dict, List, Any, Optional, Pattern, Callable, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import statistics
from datetime import datetime, timedelta

from ..metrics_collector import MetricValue

logger = logging.getLogger(__name__)

class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class LogSource(Enum):
    APPLICATION = "application"
    SYSTEM = "system"
    SECURITY = "security"
    PERFORMANCE = "performance"
    AUDIT = "audit"
    ACCESS = "access"

@dataclass
class LogPattern:
    """Log pattern definition for metrics extraction"""
    name: str
    pattern: Pattern[str]
    extract_func: Callable[[re.Match], Dict[str, Any]]
    log_level: Optional[LogLevel] = None
    source: LogSource = LogSource.APPLICATION
    description: str = ""

@dataclass
class LogMetric:
    """Metric extracted from logs"""
    name: str
    value: float
    timestamp: float
    log_level: LogLevel
    source: LogSource
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class LogAnalysis:
    """Log analysis results"""
    total_lines: int
    lines_by_level: Dict[LogLevel, int]
    error_rate: float
    warning_rate: float
    patterns_matched: Dict[str, int]
    time_range: Tuple[float, float]
    unique_errors: List[str]
    performance_metrics: Dict[str, float]

class LogMetricsCollector:
    """Advanced log-based metrics collector with real-time analysis"""
    
    def __init__(self, log_directories: List[str] = None, max_file_age_hours: int = 24):
        self.log_directories = log_directories or [
            "/var/log",
            "/tmp",
            "/home/louranicas/projects/claude-optimized-deployment/test_environments/stress_testing/logs",
            "/home/louranicas/projects/claude-optimized-deployment/src/monitoring"
        ]
        self.max_file_age_hours = max_file_age_hours
        self.collection_errors = defaultdict(int)
        
        # Log file tracking
        self.tracked_files: Dict[str, Dict[str, Any]] = {}
        self.file_positions: Dict[str, int] = {}
        
        # Pattern registry
        self.patterns: Dict[str, LogPattern] = {}
        self.pattern_matches: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Metrics storage
        self.log_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.log_statistics: Dict[str, Dict[str, Any]] = defaultdict(dict)
        
        # Real-time processing
        self.processing_queue = queue.Queue(maxsize=10000)
        self.processing_thread: Optional[threading.Thread] = None
        self.running = False
        
        # Analysis state
        self.lines_processed = 0
        self.errors_detected = 0
        self.warnings_detected = 0
        self.performance_events = 0
        
        # Initialize default patterns
        self._initialize_default_patterns()
        
        logger.info(f"Initialized log metrics collector with {len(self.log_directories)} directories")
    
    def _initialize_default_patterns(self):
        """Initialize default log patterns for common metrics"""
        
        # Error patterns
        self.add_pattern(LogPattern(
            name="generic_error",
            pattern=re.compile(r'ERROR|FATAL|CRITICAL|Exception|Traceback', re.IGNORECASE),
            extract_func=lambda m: {"error_type": "generic", "severity": "error"},
            log_level=LogLevel.ERROR,
            description="Generic error detection"
        ))
        
        # Warning patterns
        self.add_pattern(LogPattern(
            name="generic_warning",
            pattern=re.compile(r'WARN(?:ING)?|ALERT', re.IGNORECASE),
            extract_func=lambda m: {"warning_type": "generic", "severity": "warning"},
            log_level=LogLevel.WARNING,
            description="Generic warning detection"
        ))
        
        # Performance patterns
        self.add_pattern(LogPattern(
            name="response_time",
            pattern=re.compile(r'(?:response|execution|processing).*?time.*?(\d+(?:\.\d+)?)\s*(ms|milliseconds?|s|seconds?)', re.IGNORECASE),
            extract_func=self._extract_response_time,
            source=LogSource.PERFORMANCE,
            description="Response time extraction"
        ))
        
        self.add_pattern(LogPattern(
            name="memory_usage",
            pattern=re.compile(r'memory.*?(?:usage|used|allocated).*?(\d+(?:\.\d+)?)\s*(mb|gb|bytes?)', re.IGNORECASE),
            extract_func=self._extract_memory_usage,
            source=LogSource.PERFORMANCE,
            description="Memory usage extraction"
        ))
        
        # HTTP patterns
        self.add_pattern(LogPattern(
            name="http_request",
            pattern=re.compile(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+(\d{3})\s+(\d+(?:\.\d+)?)', re.IGNORECASE),
            extract_func=self._extract_http_request,
            source=LogSource.ACCESS,
            description="HTTP request logging"
        ))
        
        # Database patterns
        self.add_pattern(LogPattern(
            name="database_query",
            pattern=re.compile(r'(?:query|sql).*?(?:executed|took|duration).*?(\d+(?:\.\d+)?)\s*(ms|milliseconds?)', re.IGNORECASE),
            extract_func=self._extract_database_query,
            source=LogSource.PERFORMANCE,
            description="Database query performance"
        ))
        
        # Security patterns
        self.add_pattern(LogPattern(
            name="authentication_failure",
            pattern=re.compile(r'(?:auth|login|authentication).*?(?:fail|denied|invalid|unauthorized)', re.IGNORECASE),
            extract_func=lambda m: {"event_type": "auth_failure", "severity": "security"},
            log_level=LogLevel.WARNING,
            source=LogSource.SECURITY,
            description="Authentication failure detection"
        ))
        
        # Circle of Experts patterns
        self.add_pattern(LogPattern(
            name="expert_query",
            pattern=re.compile(r'expert.*?query.*?(?:completed|finished|took).*?(\d+(?:\.\d+)?)\s*(ms|s)', re.IGNORECASE),
            extract_func=self._extract_expert_query,
            source=LogSource.PERFORMANCE,
            description="Circle of Experts query timing"
        ))
        
        # MCP patterns
        self.add_pattern(LogPattern(
            name="mcp_request",
            pattern=re.compile(r'mcp.*?(?:request|call|invoke).*?(\w+).*?(?:completed|took).*?(\d+(?:\.\d+)?)\s*ms', re.IGNORECASE),
            extract_func=self._extract_mcp_request,
            source=LogSource.PERFORMANCE,
            description="MCP server request timing"
        ))
        
        # System resource patterns
        self.add_pattern(LogPattern(
            name="cpu_spike",
            pattern=re.compile(r'cpu.*?(?:usage|load|spike).*?(\d+(?:\.\d+)?)%', re.IGNORECASE),
            extract_func=self._extract_cpu_usage,
            source=LogSource.SYSTEM,
            description="CPU usage spikes"
        ))
        
        # Garbage collection patterns
        self.add_pattern(LogPattern(
            name="garbage_collection",
            pattern=re.compile(r'gc|garbage.*?collect.*?(\d+(?:\.\d+)?)\s*(ms|s)', re.IGNORECASE),
            extract_func=self._extract_gc_time,
            source=LogSource.PERFORMANCE,
            description="Garbage collection timing"
        ))
    
    def add_pattern(self, pattern: LogPattern):
        """Add a log pattern for metrics extraction"""
        self.patterns[pattern.name] = pattern
        logger.info(f"Added log pattern: {pattern.name}")
    
    def start(self):
        """Start log monitoring and processing"""
        if self.running:
            logger.warning("Log metrics collector already running")
            return
        
        self.running = True
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
        self.processing_thread.start()
        
        # Start file monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        logger.info("Started log metrics collector")
    
    def stop(self):
        """Stop log monitoring and processing"""
        self.running = False
        
        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5)
        
        if hasattr(self, 'monitoring_thread') and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        logger.info("Stopped log metrics collector")
    
    def _monitoring_loop(self):
        """Main monitoring loop for log files"""
        while self.running:
            try:
                # Discover and process log files
                for directory in self.log_directories:
                    if os.path.exists(directory):
                        self._process_directory(directory)
                
                # Sleep before next scan
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Log monitoring error: {e}")
                self.collection_errors['monitoring'] += 1
                time.sleep(10)
    
    def _process_directory(self, directory: str):
        """Process all log files in a directory"""
        try:
            # Find log files
            log_patterns = [
                "*.log", "*.log.*", "*.out", "*.err", 
                "*.json", "*.txt", "syslog*", "messages*"
            ]
            
            for pattern in log_patterns:
                files = glob.glob(os.path.join(directory, pattern))
                for file_path in files:
                    if self._should_process_file(file_path):
                        self._process_log_file(file_path)
        
        except Exception as e:
            logger.error(f"Directory processing error for {directory}: {e}")
            self.collection_errors['directory_processing'] += 1
    
    def _should_process_file(self, file_path: str) -> bool:
        """Check if a file should be processed"""
        try:
            # Check file age
            file_age = time.time() - os.path.getmtime(file_path)
            if file_age > self.max_file_age_hours * 3600:
                return False
            
            # Check file size (skip very large files > 100MB)
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:
                return False
            
            # Skip binary files
            if self._is_binary_file(file_path):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _is_binary_file(self, file_path: str) -> bool:
        """Check if file is binary"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\0' in chunk
        except Exception:
            return True
    
    def _process_log_file(self, file_path: str):
        """Process a single log file"""
        try:
            # Get current position for this file
            current_pos = self.file_positions.get(file_path, 0)
            
            # Open file and seek to position
            opener = gzip.open if file_path.endswith('.gz') else open
            mode = 'rt' if file_path.endswith('.gz') else 'r'
            
            with opener(file_path, mode, encoding='utf-8', errors='ignore') as f:
                f.seek(current_pos)
                
                lines_processed = 0
                for line in f:
                    if not self.running:
                        break
                    
                    # Add line to processing queue
                    if not self.processing_queue.full():
                        self.processing_queue.put((file_path, line.strip()))
                        lines_processed += 1
                    else:
                        self.collection_errors['queue_overflow'] += 1
                        break
                    
                    # Limit processing per iteration
                    if lines_processed >= 1000:
                        break
                
                # Update file position
                self.file_positions[file_path] = f.tell()
        
        except Exception as e:
            logger.error(f"Log file processing error for {file_path}: {e}")
            self.collection_errors['file_processing'] += 1
    
    def _processing_loop(self):
        """Main processing loop for log lines"""
        while self.running:
            try:
                # Process lines from queue
                processed_count = 0
                while not self.processing_queue.empty() and processed_count < 100:
                    try:
                        file_path, line = self.processing_queue.get(timeout=1.0)
                        self._process_log_line(file_path, line)
                        processed_count += 1
                        self.processing_queue.task_done()
                    except queue.Empty:
                        break
                    except Exception as e:
                        logger.error(f"Line processing error: {e}")
                        self.collection_errors['line_processing'] += 1
                
                # Sleep if no work
                if processed_count == 0:
                    time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Processing loop error: {e}")
                time.sleep(1)
    
    def _process_log_line(self, file_path: str, line: str):
        """Process a single log line"""
        if not line.strip():
            return
        
        self.lines_processed += 1
        timestamp = time.time()
        
        # Extract timestamp from log line if possible
        log_timestamp = self._extract_timestamp(line) or timestamp
        
        # Apply all patterns to the line
        for pattern_name, pattern in self.patterns.items():
            try:
                match = pattern.pattern.search(line)
                if match:
                    # Extract metrics using pattern function
                    extracted_data = pattern.extract_func(match)
                    
                    # Create log metric
                    metric = LogMetric(
                        name=pattern_name,
                        value=extracted_data.get('value', 1.0),
                        timestamp=log_timestamp,
                        log_level=pattern.log_level or LogLevel.INFO,
                        source=pattern.source,
                        context={
                            'file_path': file_path,
                            'line': line,
                            'extracted': extracted_data
                        }
                    )
                    
                    # Store metric
                    self.log_metrics[pattern_name].append(metric)
                    self.pattern_matches[pattern_name].append(timestamp)
                    
                    # Update counters
                    if pattern.log_level == LogLevel.ERROR:
                        self.errors_detected += 1
                    elif pattern.log_level == LogLevel.WARNING:
                        self.warnings_detected += 1
                    elif pattern.source == LogSource.PERFORMANCE:
                        self.performance_events += 1
            
            except Exception as e:
                logger.error(f"Pattern processing error for {pattern_name}: {e}")
                self.collection_errors['pattern_processing'] += 1
    
    def _extract_timestamp(self, line: str) -> Optional[float]:
        """Extract timestamp from log line"""
        # Common timestamp patterns
        timestamp_patterns = [
            # ISO 8601: 2023-12-25T10:30:45.123Z
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z?)',
            # Standard log format: 2023-12-25 10:30:45
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            # Syslog format: Dec 25 10:30:45
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            # Unix timestamp: 1703505045.123
            r'(\d{10}(?:\.\d{3})?)'
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                try:
                    # Try different parsing approaches
                    if timestamp_str.isdigit() or '.' in timestamp_str:
                        return float(timestamp_str)
                    else:
                        # Parse datetime string
                        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        return dt.timestamp()
                except Exception:
                    continue
        
        return None
    
    # Pattern extraction functions
    def _extract_response_time(self, match: re.Match) -> Dict[str, Any]:
        """Extract response time metrics"""
        time_value = float(match.group(1))
        time_unit = match.group(2).lower()
        
        # Convert to milliseconds
        if 's' in time_unit and 'ms' not in time_unit:
            time_value *= 1000
        
        return {
            'value': time_value,
            'unit': 'ms',
            'metric_type': 'response_time'
        }
    
    def _extract_memory_usage(self, match: re.Match) -> Dict[str, Any]:
        """Extract memory usage metrics"""
        memory_value = float(match.group(1))
        memory_unit = match.group(2).lower()
        
        # Convert to MB
        if 'gb' in memory_unit:
            memory_value *= 1024
        elif 'bytes' in memory_unit:
            memory_value /= (1024 * 1024)
        
        return {
            'value': memory_value,
            'unit': 'mb',
            'metric_type': 'memory_usage'
        }
    
    def _extract_http_request(self, match: re.Match) -> Dict[str, Any]:
        """Extract HTTP request metrics"""
        endpoint = match.group(1)
        status_code = int(match.group(2))
        response_time = float(match.group(3))
        
        return {
            'value': response_time,
            'endpoint': endpoint,
            'status_code': status_code,
            'metric_type': 'http_request'
        }
    
    def _extract_database_query(self, match: re.Match) -> Dict[str, Any]:
        """Extract database query metrics"""
        query_time = float(match.group(1))
        
        return {
            'value': query_time,
            'unit': 'ms',
            'metric_type': 'database_query'
        }
    
    def _extract_expert_query(self, match: re.Match) -> Dict[str, Any]:
        """Extract Circle of Experts query metrics"""
        query_time = float(match.group(1))
        unit = match.group(2).lower()
        
        if 's' in unit:
            query_time *= 1000  # Convert to ms
        
        return {
            'value': query_time,
            'unit': 'ms',
            'metric_type': 'expert_query'
        }
    
    def _extract_mcp_request(self, match: re.Match) -> Dict[str, Any]:
        """Extract MCP request metrics"""
        server_type = match.group(1)
        request_time = float(match.group(2))
        
        return {
            'value': request_time,
            'server_type': server_type,
            'unit': 'ms',
            'metric_type': 'mcp_request'
        }
    
    def _extract_cpu_usage(self, match: re.Match) -> Dict[str, Any]:
        """Extract CPU usage metrics"""
        cpu_usage = float(match.group(1))
        
        return {
            'value': cpu_usage,
            'unit': 'percent',
            'metric_type': 'cpu_usage'
        }
    
    def _extract_gc_time(self, match: re.Match) -> Dict[str, Any]:
        """Extract garbage collection time metrics"""
        gc_time = float(match.group(1))
        unit = match.group(2).lower()
        
        if 's' in unit:
            gc_time *= 1000  # Convert to ms
        
        return {
            'value': gc_time,
            'unit': 'ms',
            'metric_type': 'gc_time'
        }
    
    def collect_all_metrics(self) -> List[MetricValue]:
        """Collect all log-based metrics"""
        timestamp = time.time()
        metrics = []
        
        try:
            # Processing statistics
            metrics.extend(self._collect_processing_metrics(timestamp))
            
            # Pattern match metrics
            metrics.extend(self._collect_pattern_metrics(timestamp))
            
            # Log level distribution metrics
            metrics.extend(self._collect_log_level_metrics(timestamp))
            
            # Performance metrics from logs
            metrics.extend(self._collect_performance_metrics(timestamp))
            
            # Error analysis metrics
            metrics.extend(self._collect_error_metrics(timestamp))
            
            # Trend analysis metrics
            metrics.extend(self._collect_trend_metrics(timestamp))
            
        except Exception as e:
            logger.error(f"Error collecting log metrics: {e}")
            self.collection_errors['collection'] += 1
        
        return metrics
    
    def _collect_processing_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect log processing statistics"""
        metrics = []
        
        try:
            metrics.extend([
                MetricValue("log_lines_processed_total", self.lines_processed, timestamp,
                          source="log_collector", tags={"type": "processing"}),
                MetricValue("log_errors_detected_total", self.errors_detected, timestamp,
                          source="log_collector", tags={"type": "processing"}),
                MetricValue("log_warnings_detected_total", self.warnings_detected, timestamp,
                          source="log_collector", tags={"type": "processing"}),
                MetricValue("log_performance_events_total", self.performance_events, timestamp,
                          source="log_collector", tags={"type": "processing"}),
                MetricValue("log_files_tracked", len(self.tracked_files), timestamp,
                          source="log_collector", tags={"type": "processing"}),
                MetricValue("log_patterns_active", len(self.patterns), timestamp,
                          source="log_collector", tags={"type": "processing"}),
                MetricValue("log_processing_queue_size", self.processing_queue.qsize(), timestamp,
                          source="log_collector", tags={"type": "processing"})
            ])
            
            # Error rates
            if self.lines_processed > 0:
                error_rate = self.errors_detected / self.lines_processed
                warning_rate = self.warnings_detected / self.lines_processed
                
                metrics.extend([
                    MetricValue("log_error_rate", error_rate, timestamp,
                              source="log_collector", tags={"type": "rate"}),
                    MetricValue("log_warning_rate", warning_rate, timestamp,
                              source="log_collector", tags={"type": "rate"})
                ])
        
        except Exception as e:
            logger.error(f"Processing metrics collection error: {e}")
            self.collection_errors['processing_metrics'] += 1
        
        return metrics
    
    def _collect_pattern_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect pattern matching metrics"""
        metrics = []
        
        try:
            for pattern_name, matches in self.pattern_matches.items():
                if matches:
                    # Total matches
                    metrics.append(MetricValue(
                        f"log_pattern_{pattern_name}_matches_total", len(matches), timestamp,
                        source="log_collector", tags={"type": "pattern", "pattern": pattern_name}
                    ))
                    
                    # Recent activity (last 5 minutes)
                    recent_cutoff = timestamp - 300
                    recent_matches = sum(1 for t in matches if t >= recent_cutoff)
                    
                    metrics.append(MetricValue(
                        f"log_pattern_{pattern_name}_recent_matches", recent_matches, timestamp,
                        source="log_collector", tags={"type": "pattern", "pattern": pattern_name}
                    ))
                    
                    # Match rate (matches per minute)
                    if len(matches) > 1:
                        time_span = max(matches) - min(matches)
                        if time_span > 0:
                            match_rate = len(matches) / (time_span / 60)
                            metrics.append(MetricValue(
                                f"log_pattern_{pattern_name}_rate_per_minute", match_rate, timestamp,
                                source="log_collector", tags={"type": "pattern", "pattern": pattern_name}
                            ))
        
        except Exception as e:
            logger.error(f"Pattern metrics collection error: {e}")
            self.collection_errors['pattern_metrics'] += 1
        
        return metrics
    
    def _collect_log_level_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect log level distribution metrics"""
        metrics = []
        
        try:
            level_counts = defaultdict(int)
            
            # Count metrics by log level
            for metric_list in self.log_metrics.values():
                for metric in metric_list:
                    level_counts[metric.log_level] += 1
            
            # Create metrics for each level
            for level, count in level_counts.items():
                metrics.append(MetricValue(
                    f"log_level_{level.value.lower()}_count", count, timestamp,
                    source="log_collector", tags={"type": "log_level", "level": level.value}
                ))
            
            # Level distribution percentages
            total_count = sum(level_counts.values())
            if total_count > 0:
                for level, count in level_counts.items():
                    percentage = (count / total_count) * 100
                    metrics.append(MetricValue(
                        f"log_level_{level.value.lower()}_percentage", percentage, timestamp,
                        source="log_collector", tags={"type": "log_level_distribution", "level": level.value}
                    ))
        
        except Exception as e:
            logger.error(f"Log level metrics collection error: {e}")
            self.collection_errors['log_level_metrics'] += 1
        
        return metrics
    
    def _collect_performance_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect performance metrics extracted from logs"""
        metrics = []
        
        try:
            # Response time metrics
            response_times = []
            for metric in self.log_metrics.get('response_time', []):
                if metric.context.get('extracted', {}).get('metric_type') == 'response_time':
                    response_times.append(metric.value)
            
            if response_times:
                metrics.extend([
                    MetricValue("log_response_time_avg", statistics.mean(response_times), timestamp,
                              source="log_collector", tags={"type": "performance", "metric": "response_time"}),
                    MetricValue("log_response_time_min", min(response_times), timestamp,
                              source="log_collector", tags={"type": "performance", "metric": "response_time"}),
                    MetricValue("log_response_time_max", max(response_times), timestamp,
                              source="log_collector", tags={"type": "performance", "metric": "response_time"})
                ])
                
                if len(response_times) > 5:
                    sorted_times = sorted(response_times)
                    p95_idx = int(len(sorted_times) * 0.95)
                    p99_idx = int(len(sorted_times) * 0.99)
                    
                    metrics.extend([
                        MetricValue("log_response_time_p95", sorted_times[p95_idx], timestamp,
                                  source="log_collector", tags={"type": "performance", "metric": "response_time"}),
                        MetricValue("log_response_time_p99", sorted_times[p99_idx], timestamp,
                                  source="log_collector", tags={"type": "performance", "metric": "response_time"})
                    ])
            
            # Memory usage metrics
            memory_values = []
            for metric in self.log_metrics.get('memory_usage', []):
                if metric.context.get('extracted', {}).get('metric_type') == 'memory_usage':
                    memory_values.append(metric.value)
            
            if memory_values:
                metrics.extend([
                    MetricValue("log_memory_usage_avg", statistics.mean(memory_values), timestamp,
                              source="log_collector", tags={"type": "performance", "metric": "memory"}),
                    MetricValue("log_memory_usage_max", max(memory_values), timestamp,
                              source="log_collector", tags={"type": "performance", "metric": "memory"})
                ])
            
            # Database query metrics
            db_query_times = []
            for metric in self.log_metrics.get('database_query', []):
                if metric.context.get('extracted', {}).get('metric_type') == 'database_query':
                    db_query_times.append(metric.value)
            
            if db_query_times:
                metrics.extend([
                    MetricValue("log_database_query_time_avg", statistics.mean(db_query_times), timestamp,
                              source="log_collector", tags={"type": "performance", "metric": "database"}),
                    MetricValue("log_database_query_count", len(db_query_times), timestamp,
                              source="log_collector", tags={"type": "performance", "metric": "database"})
                ])
        
        except Exception as e:
            logger.error(f"Performance metrics collection error: {e}")
            self.collection_errors['performance_metrics'] += 1
        
        return metrics
    
    def _collect_error_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect error analysis metrics"""
        metrics = []
        
        try:
            # Error frequency analysis
            error_patterns = ['generic_error', 'authentication_failure']
            for pattern in error_patterns:
                error_metrics = self.log_metrics.get(pattern, [])
                if error_metrics:
                    # Recent errors (last hour)
                    recent_cutoff = timestamp - 3600
                    recent_errors = [m for m in error_metrics if m.timestamp >= recent_cutoff]
                    
                    metrics.extend([
                        MetricValue(f"log_errors_{pattern}_total", len(error_metrics), timestamp,
                                  source="log_collector", tags={"type": "error_analysis", "pattern": pattern}),
                        MetricValue(f"log_errors_{pattern}_recent", len(recent_errors), timestamp,
                                  source="log_collector", tags={"type": "error_analysis", "pattern": pattern})
                    ])
                    
                    # Error rate per hour
                    if len(error_metrics) > 1:
                        time_span = max(m.timestamp for m in error_metrics) - min(m.timestamp for m in error_metrics)
                        if time_span > 0:
                            error_rate = len(error_metrics) / (time_span / 3600)
                            metrics.append(MetricValue(
                                f"log_errors_{pattern}_rate_per_hour", error_rate, timestamp,
                                source="log_collector", tags={"type": "error_analysis", "pattern": pattern}
                            ))
            
            # Overall error health score
            total_errors = sum(len(self.log_metrics.get(p, [])) for p in error_patterns)
            if self.lines_processed > 0:
                error_health = max(0, 1 - (total_errors / max(self.lines_processed, 1)))
                metrics.append(MetricValue(
                    "log_error_health_score", error_health, timestamp,
                    source="log_collector", tags={"type": "error_health"}
                ))
        
        except Exception as e:
            logger.error(f"Error metrics collection error: {e}")
            self.collection_errors['error_metrics'] += 1
        
        return metrics
    
    def _collect_trend_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect trend analysis metrics"""
        metrics = []
        
        try:
            # Analyze trends for key patterns
            trend_patterns = ['response_time', 'memory_usage', 'generic_error']
            
            for pattern in trend_patterns:
                pattern_metrics = self.log_metrics.get(pattern, [])
                if len(pattern_metrics) > 10:  # Need sufficient data for trend analysis
                    # Get recent values
                    recent_cutoff = timestamp - 1800  # Last 30 minutes
                    recent_values = [m.value for m in pattern_metrics if m.timestamp >= recent_cutoff]
                    
                    if len(recent_values) > 5:
                        # Simple trend detection
                        first_half = recent_values[:len(recent_values)//2]
                        second_half = recent_values[len(recent_values)//2:]
                        
                        first_avg = statistics.mean(first_half)
                        second_avg = statistics.mean(second_half)
                        
                        if first_avg > 0:
                            trend_ratio = second_avg / first_avg
                            
                            # Trend direction
                            if trend_ratio > 1.1:
                                trend_direction = 1  # Increasing
                            elif trend_ratio < 0.9:
                                trend_direction = -1  # Decreasing
                            else:
                                trend_direction = 0  # Stable
                            
                            metrics.extend([
                                MetricValue(f"log_trend_{pattern}_ratio", trend_ratio, timestamp,
                                          source="log_collector", tags={"type": "trend", "pattern": pattern}),
                                MetricValue(f"log_trend_{pattern}_direction", trend_direction, timestamp,
                                          source="log_collector", tags={"type": "trend", "pattern": pattern})
                            ])
        
        except Exception as e:
            logger.error(f"Trend metrics collection error: {e}")
            self.collection_errors['trend_metrics'] += 1
        
        return metrics
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        return {
            'collection_errors': dict(self.collection_errors),
            'total_errors': sum(self.collection_errors.values()),
            'lines_processed': self.lines_processed,
            'errors_detected': self.errors_detected,
            'warnings_detected': self.warnings_detected,
            'performance_events': self.performance_events,
            'patterns_count': len(self.patterns),
            'tracked_files_count': len(self.tracked_files),
            'log_directories': self.log_directories,
            'running': self.running
        }

# Example usage
if __name__ == "__main__":
    collector = LogMetricsCollector()
    
    # Start monitoring
    collector.start()
    
    try:
        # Run for 30 seconds
        time.sleep(30)
        
        # Collect metrics
        metrics = collector.collect_all_metrics()
        
        print(f"=== Log Metrics Collection ===")
        print(f"Collected {len(metrics)} log-based metrics")
        
        # Show sample metrics
        for metric in metrics[:15]:
            print(f"{metric.name}: {metric.value} (tags: {metric.tags})")
        
        print("\n=== Collection Statistics ===")
        stats = collector.get_collection_stats()
        print(json.dumps(stats, indent=2, default=str))
    
    finally:
        collector.stop()