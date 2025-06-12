#!/usr/bin/env python3
"""
Real-time Stream Processing for Performance Metrics
Advanced real-time analytics with sub-second processing capabilities
"""

import asyncio
import time
import logging
from typing import Dict, List, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import json
import statistics
import threading
import queue
from datetime import datetime, timedelta
import numpy as np
from enum import Enum

from metrics_collector import MetricValue, MetricsCollector

# Enhanced logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AlertLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

@dataclass
class ProcessingRule:
    """Rule for real-time metric processing"""
    name: str
    metric_pattern: str
    condition: Callable[[MetricValue], bool]
    action: Callable[[MetricValue], Any]
    priority: int = 1
    enabled: bool = True
    
@dataclass
class StreamWindow:
    """Sliding window for stream processing"""
    size_seconds: int
    values: deque = field(default_factory=deque)
    max_size: int = 1000
    
    def add_value(self, value: MetricValue):
        current_time = time.time()
        # Remove old values
        while self.values and self.values[0].timestamp < current_time - self.size_seconds:
            self.values.popleft()
        
        # Add new value
        self.values.append(value)
        
        # Limit size
        if len(self.values) > self.max_size:
            self.values.popleft()
    
    def get_values(self) -> List[MetricValue]:
        return list(self.values)
    
    def get_numeric_values(self) -> List[float]:
        return [v.value for v in self.values if isinstance(v.value, (int, float))]
    
    def is_empty(self) -> bool:
        return len(self.values) == 0

@dataclass
class AnomalyDetectionResult:
    """Result of anomaly detection analysis"""
    metric_name: str
    is_anomaly: bool
    confidence: float
    reason: str
    current_value: float
    expected_range: Tuple[float, float]
    timestamp: float

class RealTimeProcessor:
    """Advanced real-time stream processor for metrics"""
    
    def __init__(self, processing_interval: float = 0.1):
        self.processing_interval = processing_interval
        self.windows: Dict[str, StreamWindow] = {}
        self.rules: List[ProcessingRule] = []
        self.running = False
        self.processor_thread: Optional[threading.Thread] = None
        self.input_queue = queue.Queue(maxsize=10000)
        self.output_callbacks: List[Callable] = []
        
        # Anomaly detection
        self.baseline_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.anomaly_thresholds: Dict[str, Dict[str, float]] = {}
        
        # Performance statistics
        self.processing_stats = {
            'total_processed': 0,
            'processing_errors': 0,
            'anomalies_detected': 0,
            'rules_triggered': 0,
            'avg_processing_time': 0.0,
            'queue_overflows': 0
        }
        
        # Initialize default processing rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default processing rules"""
        
        # High CPU usage rule
        self.add_rule(ProcessingRule(
            name="high_cpu_usage",
            metric_pattern=".*cpu_usage_percent",
            condition=lambda m: isinstance(m.value, (int, float)) and m.value > 80,
            action=self._handle_high_cpu,
            priority=1
        ))
        
        # High memory usage rule
        self.add_rule(ProcessingRule(
            name="high_memory_usage",
            metric_pattern=".*memory_usage_percent",
            condition=lambda m: isinstance(m.value, (int, float)) and m.value > 85,
            action=self._handle_high_memory,
            priority=1
        ))
        
        # Disk space warning
        self.add_rule(ProcessingRule(
            name="low_disk_space",
            metric_pattern=".*disk_usage_percent",
            condition=lambda m: isinstance(m.value, (int, float)) and m.value > 90,
            action=self._handle_low_disk_space,
            priority=2
        ))
        
        # Network error detection
        self.add_rule(ProcessingRule(
            name="network_errors",
            metric_pattern=".*network_errors.*",
            condition=lambda m: isinstance(m.value, (int, float)) and m.value > 0,
            action=self._handle_network_errors,
            priority=2
        ))
    
    def add_rule(self, rule: ProcessingRule):
        """Add a processing rule"""
        self.rules.append(rule)
        logger.info(f"Added processing rule: {rule.name}")
    
    def add_output_callback(self, callback: Callable):
        """Add output callback for processed data"""
        self.output_callbacks.append(callback)
    
    def add_window(self, metric_pattern: str, window_size_seconds: int):
        """Add a sliding window for metric pattern"""
        self.windows[metric_pattern] = StreamWindow(window_size_seconds)
        logger.info(f"Added window for {metric_pattern}: {window_size_seconds}s")
    
    def start(self):
        """Start real-time processing"""
        if self.running:
            logger.warning("Real-time processor already running")
            return
        
        self.running = True
        self.processor_thread = threading.Thread(target=self._processing_loop, daemon=True)
        self.processor_thread.start()
        
        logger.info("Started real-time processor")
    
    def stop(self):
        """Stop real-time processing"""
        self.running = False
        
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=5)
        
        logger.info("Stopped real-time processor")
    
    def process_metric(self, metric: MetricValue):
        """Add metric to processing queue"""
        try:
            if not self.input_queue.full():
                self.input_queue.put(metric)
            else:
                self.processing_stats['queue_overflows'] += 1
        except Exception as e:
            logger.error(f"Error adding metric to queue: {e}")
    
    def _processing_loop(self):
        """Main processing loop"""
        while self.running:
            try:
                start_time = time.time()
                
                # Process metrics from queue
                processed_count = 0
                while not self.input_queue.empty() and processed_count < 100:
                    try:
                        metric = self.input_queue.get(timeout=0.1)
                        self._process_single_metric(metric)
                        processed_count += 1
                        self.input_queue.task_done()
                    except queue.Empty:
                        break
                    except Exception as e:
                        logger.error(f"Error processing metric: {e}")
                        self.processing_stats['processing_errors'] += 1
                
                # Update processing statistics
                if processed_count > 0:
                    processing_time = time.time() - start_time
                    self.processing_stats['total_processed'] += processed_count
                    self.processing_stats['avg_processing_time'] = (
                        (self.processing_stats['avg_processing_time'] * 0.9) + 
                        (processing_time * 0.1)
                    )
                
                # Sleep for remaining interval
                elapsed = time.time() - start_time
                sleep_time = max(0, self.processing_interval - elapsed)
                if sleep_time > 0:
                    time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Processing loop error: {e}")
                time.sleep(self.processing_interval)
    
    def _process_single_metric(self, metric: MetricValue):
        """Process a single metric through all rules and windows"""
        
        # Update sliding windows
        for pattern, window in self.windows.items():
            if self._matches_pattern(metric.name, pattern):
                window.add_value(metric)
        
        # Update baseline data for anomaly detection
        if isinstance(metric.value, (int, float)):
            self.baseline_data[metric.name].append(metric.value)
        
        # Apply processing rules
        for rule in self.rules:
            if rule.enabled and self._matches_pattern(metric.name, rule.metric_pattern):
                try:
                    if rule.condition(metric):
                        rule.action(metric)
                        self.processing_stats['rules_triggered'] += 1
                except Exception as e:
                    logger.error(f"Error applying rule {rule.name}: {e}")
        
        # Anomaly detection
        anomaly_result = self._detect_anomaly(metric)
        if anomaly_result and anomaly_result.is_anomaly:
            self._handle_anomaly(anomaly_result)
        
        # Call output callbacks
        for callback in self.output_callbacks:
            try:
                callback(metric)
            except Exception as e:
                logger.error(f"Output callback error: {e}")
    
    def _matches_pattern(self, text: str, pattern: str) -> bool:
        """Simple pattern matching (can be enhanced with regex)"""
        import re
        try:
            return bool(re.search(pattern, text))
        except re.error:
            return pattern in text
    
    def _detect_anomaly(self, metric: MetricValue) -> Optional[AnomalyDetectionResult]:
        """Detect anomalies using statistical analysis"""
        if not isinstance(metric.value, (int, float)):
            return None
        
        baseline = list(self.baseline_data[metric.name])
        if len(baseline) < 10:  # Need minimum data points
            return None
        
        try:
            # Calculate statistical thresholds
            mean_val = statistics.mean(baseline)
            stdev_val = statistics.stdev(baseline) if len(baseline) > 1 else 0
            
            # Use 3-sigma rule for anomaly detection
            lower_bound = mean_val - (3 * stdev_val)
            upper_bound = mean_val + (3 * stdev_val)
            
            is_anomaly = metric.value < lower_bound or metric.value > upper_bound
            
            if is_anomaly:
                # Calculate confidence based on distance from bounds
                if metric.value < lower_bound:
                    distance = abs(metric.value - lower_bound)
                else:
                    distance = abs(metric.value - upper_bound)
                
                confidence = min(1.0, distance / (stdev_val + 0.001))  # Avoid division by zero
                
                return AnomalyDetectionResult(
                    metric_name=metric.name,
                    is_anomaly=True,
                    confidence=confidence,
                    reason=f"Value {metric.value} outside 3-sigma bounds",
                    current_value=metric.value,
                    expected_range=(lower_bound, upper_bound),
                    timestamp=metric.timestamp
                )
        
        except Exception as e:
            logger.error(f"Anomaly detection error for {metric.name}: {e}")
        
        return None
    
    def _handle_anomaly(self, anomaly: AnomalyDetectionResult):
        """Handle detected anomaly"""
        self.processing_stats['anomalies_detected'] += 1
        
        logger.warning(
            f"ANOMALY DETECTED: {anomaly.metric_name} = {anomaly.current_value} "
            f"(expected: {anomaly.expected_range[0]:.2f} - {anomaly.expected_range[1]:.2f}) "
            f"Confidence: {anomaly.confidence:.2f}"
        )
        
        # Create alert event
        alert_data = {
            'type': 'anomaly',
            'level': AlertLevel.WARNING.value,
            'metric': anomaly.metric_name,
            'value': anomaly.current_value,
            'expected_range': anomaly.expected_range,
            'confidence': anomaly.confidence,
            'timestamp': anomaly.timestamp,
            'reason': anomaly.reason
        }
        
        # Send to output callbacks
        for callback in self.output_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def get_window_statistics(self, metric_pattern: str) -> Dict[str, Any]:
        """Get statistics for a windowed metric"""
        if metric_pattern not in self.windows:
            return {}
        
        window = self.windows[metric_pattern]
        values = window.get_numeric_values()
        
        if not values:
            return {'count': 0}
        
        try:
            return {
                'count': len(values),
                'mean': statistics.mean(values),
                'median': statistics.median(values),
                'min': min(values),
                'max': max(values),
                'stdev': statistics.stdev(values) if len(values) > 1 else 0,
                'latest': values[-1] if values else None,
                'trend': self._calculate_trend(values)
            }
        except Exception as e:
            logger.error(f"Statistics calculation error: {e}")
            return {'count': len(values)}
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for values"""
        if len(values) < 2:
            return "insufficient_data"
        
        # Simple trend calculation using linear regression slope
        x = list(range(len(values)))
        try:
            slope = np.polyfit(x, values, 1)[0] if len(values) > 1 else 0
            
            if abs(slope) < 0.01:
                return "stable"
            elif slope > 0:
                return "increasing"
            else:
                return "decreasing"
        except Exception:
            return "unknown"
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        stats = self.processing_stats.copy()
        stats['queue_size'] = self.input_queue.qsize()
        stats['active_windows'] = len(self.windows)
        stats['active_rules'] = len([r for r in self.rules if r.enabled])
        stats['running'] = self.running
        return stats
    
    # Default rule handlers
    def _handle_high_cpu(self, metric: MetricValue):
        """Handle high CPU usage"""
        logger.warning(f"HIGH CPU USAGE: {metric.value}% at {metric.timestamp}")
        
        alert = {
            'type': 'threshold',
            'level': AlertLevel.WARNING.value,
            'metric': metric.name,
            'value': metric.value,
            'threshold': 80,
            'message': f"CPU usage is {metric.value}%",
            'timestamp': metric.timestamp
        }
        
        # Send alert to callbacks
        for callback in self.output_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def _handle_high_memory(self, metric: MetricValue):
        """Handle high memory usage"""
        logger.warning(f"HIGH MEMORY USAGE: {metric.value}% at {metric.timestamp}")
        
        alert = {
            'type': 'threshold',
            'level': AlertLevel.WARNING.value,
            'metric': metric.name,
            'value': metric.value,
            'threshold': 85,
            'message': f"Memory usage is {metric.value}%",
            'timestamp': metric.timestamp
        }
        
        for callback in self.output_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def _handle_low_disk_space(self, metric: MetricValue):
        """Handle low disk space"""
        logger.error(f"LOW DISK SPACE: {metric.value}% at {metric.timestamp}")
        
        alert = {
            'type': 'threshold',
            'level': AlertLevel.CRITICAL.value,
            'metric': metric.name,
            'value': metric.value,
            'threshold': 90,
            'message': f"Disk usage is {metric.value}%",
            'timestamp': metric.timestamp
        }
        
        for callback in self.output_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def _handle_network_errors(self, metric: MetricValue):
        """Handle network errors"""
        logger.warning(f"NETWORK ERRORS: {metric.value} errors at {metric.timestamp}")
        
        alert = {
            'type': 'threshold',
            'level': AlertLevel.WARNING.value,
            'metric': metric.name,
            'value': metric.value,
            'threshold': 0,
            'message': f"Network errors detected: {metric.value}",
            'timestamp': metric.timestamp
        }
        
        for callback in self.output_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

# Integration with metrics collector
class IntegratedMonitoringSystem:
    """Integrated monitoring system with collection and processing"""
    
    def __init__(self, collection_interval: float = 1.0, processing_interval: float = 0.1):
        self.collector = MetricsCollector(collection_interval)
        self.processor = RealTimeProcessor(processing_interval)
        
        # Connect collector to processor
        self.collector.add_callback(self.processor.process_metric)
        
        # Add default windows
        self.processor.add_window(".*cpu_usage_percent", 60)
        self.processor.add_window(".*memory_usage_percent", 60)
        self.processor.add_window(".*disk_usage_percent", 300)
        self.processor.add_window(".*network_.*", 30)
    
    def start(self):
        """Start integrated monitoring"""
        self.processor.start()
        self.collector.start()
        logger.info("Started integrated monitoring system")
    
    def stop(self):
        """Stop integrated monitoring"""
        self.collector.stop()
        self.processor.stop()
        logger.info("Stopped integrated monitoring system")
    
    def add_custom_rule(self, rule: ProcessingRule):
        """Add custom processing rule"""
        self.processor.add_rule(rule)
    
    def add_alert_callback(self, callback: Callable):
        """Add alert callback"""
        self.processor.add_output_callback(callback)
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            'collector_stats': self.collector.get_collection_stats(),
            'processor_stats': self.processor.get_processing_stats(),
            'latest_metrics': self.collector.get_latest_metrics(),
            'timestamp': time.time()
        }

# Example usage
async def main():
    """Example usage of the integrated monitoring system"""
    
    # Create integrated system
    monitor = IntegratedMonitoringSystem(collection_interval=1.0, processing_interval=0.1)
    
    # Add custom alert handler
    def alert_handler(alert_data):
        if isinstance(alert_data, dict) and 'level' in alert_data:
            print(f"🚨 ALERT [{alert_data['level'].upper()}]: {alert_data.get('message', 'Unknown alert')}")
        else:
            print(f"📊 METRIC: {alert_data}")
    
    monitor.add_alert_callback(alert_handler)
    
    # Add custom rule for process memory
    custom_rule = ProcessingRule(
        name="high_process_memory",
        metric_pattern="process_memory_rss",
        condition=lambda m: isinstance(m.value, (int, float)) and m.value > 500_000_000,  # 500MB
        action=lambda m: logger.warning(f"High process memory: {m.value / 1_000_000:.1f}MB"),
        priority=1
    )
    monitor.add_custom_rule(custom_rule)
    
    # Start monitoring
    monitor.start()
    
    try:
        # Run for 60 seconds
        await asyncio.sleep(60)
        
        # Print system status
        print("\n=== System Status ===")
        status = monitor.get_system_status()
        
        print("Collector Stats:", status['collector_stats'])
        print("Processor Stats:", status['processor_stats'])
        
        # Show window statistics
        print("\n=== Window Statistics ===")
        cpu_stats = monitor.processor.get_window_statistics(".*cpu_usage_percent")
        print("CPU (60s window):", cpu_stats)
        
        memory_stats = monitor.processor.get_window_statistics(".*memory_usage_percent")
        print("Memory (60s window):", memory_stats)
    
    finally:
        monitor.stop()

if __name__ == "__main__":
    asyncio.run(main())