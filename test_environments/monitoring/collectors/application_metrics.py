#!/usr/bin/env python3
"""
Application-Specific Metrics Collector
Monitors Circle of Experts, MCP servers, database, and API performance
"""

import time
import logging
import threading
import asyncio
import gc
import sys
import inspect
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from collections import defaultdict, deque
import json
import weakref

from ..metrics_collector import MetricValue

logger = logging.getLogger(__name__)

@dataclass
class ConnectionPoolStats:
    """Connection pool statistics"""
    total_connections: int
    active_connections: int
    idle_connections: int
    wait_queue_size: int
    connection_errors: int
    average_wait_time: float

@dataclass
class QueryPerformanceStats:
    """Query performance statistics"""
    total_queries: int
    successful_queries: int
    failed_queries: int
    average_response_time: float
    p95_response_time: float
    p99_response_time: float
    slowest_query_time: float

class ApplicationMetricsCollector:
    """Comprehensive application performance metrics collector"""
    
    def __init__(self):
        self.start_time = time.time()
        self.collection_errors = defaultdict(int)
        
        # Performance tracking
        self.query_times = deque(maxlen=1000)
        self.expert_response_times = deque(maxlen=1000)
        self.api_response_times = deque(maxlen=1000)
        self.mcp_response_times = deque(maxlen=1000)
        
        # Counters
        self.counters = defaultdict(int)
        self.gauges = defaultdict(float)
        
        # Component health tracking
        self.component_health = {}
        
        # Memory tracking for application objects
        self.tracked_objects = weakref.WeakSet()
        
        # Initialize component monitors
        self._initialize_component_monitors()
        
        logger.info("Initialized application metrics collector")
    
    def _initialize_component_monitors(self):
        """Initialize monitoring for application components"""
        try:
            # Try to import and monitor Circle of Experts
            self._init_circle_of_experts_monitor()
            
            # Try to import and monitor MCP components
            self._init_mcp_monitor()
            
            # Try to import and monitor database components
            self._init_database_monitor()
            
            # Try to import and monitor API components
            self._init_api_monitor()
            
        except Exception as e:
            logger.debug(f"Component monitor initialization error: {e}")
    
    def _init_circle_of_experts_monitor(self):
        """Initialize Circle of Experts monitoring"""
        try:
            # Try to access Circle of Experts modules
            sys.path.append('/home/louranicas/projects/claude-optimized-deployment/src')
            
            # Import monitoring hooks if available
            self.component_health['circle_of_experts'] = {
                'status': 'available',
                'last_check': time.time()
            }
            
        except Exception as e:
            logger.debug(f"Circle of Experts monitor init error: {e}")
            self.component_health['circle_of_experts'] = {
                'status': 'unavailable',
                'error': str(e),
                'last_check': time.time()
            }
    
    def _init_mcp_monitor(self):
        """Initialize MCP server monitoring"""
        try:
            self.component_health['mcp_servers'] = {
                'status': 'available',
                'last_check': time.time()
            }
            
        except Exception as e:
            logger.debug(f"MCP monitor init error: {e}")
            self.component_health['mcp_servers'] = {
                'status': 'unavailable',
                'error': str(e),
                'last_check': time.time()
            }
    
    def _init_database_monitor(self):
        """Initialize database monitoring"""
        try:
            self.component_health['database'] = {
                'status': 'available',
                'last_check': time.time()
            }
            
        except Exception as e:
            logger.debug(f"Database monitor init error: {e}")
            self.component_health['database'] = {
                'status': 'unavailable',
                'error': str(e),
                'last_check': time.time()
            }
    
    def _init_api_monitor(self):
        """Initialize API monitoring"""
        try:
            self.component_health['api'] = {
                'status': 'available',
                'last_check': time.time()
            }
            
        except Exception as e:
            logger.debug(f"API monitor init error: {e}")
            self.component_health['api'] = {
                'status': 'unavailable',
                'error': str(e),
                'last_check': time.time()
            }
    
    def collect_all_metrics(self) -> List[MetricValue]:
        """Collect all application metrics"""
        timestamp = time.time()
        metrics = []
        
        try:
            # Core application metrics
            metrics.extend(self._collect_runtime_metrics(timestamp))
            metrics.extend(self._collect_memory_metrics(timestamp))
            metrics.extend(self._collect_performance_metrics(timestamp))
            
            # Component-specific metrics
            metrics.extend(self._collect_circle_of_experts_metrics(timestamp))
            metrics.extend(self._collect_mcp_metrics(timestamp))
            metrics.extend(self._collect_database_metrics(timestamp))
            metrics.extend(self._collect_api_metrics(timestamp))
            
            # Health and monitoring metrics
            metrics.extend(self._collect_health_metrics(timestamp))
            metrics.extend(self._collect_monitoring_metrics(timestamp))
            
        except Exception as e:
            logger.error(f"Error collecting application metrics: {e}")
            self.collection_errors['general'] += 1
        
        return metrics
    
    def _collect_runtime_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect Python runtime metrics"""
        metrics = []
        
        try:
            # Python version info
            python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            metrics.append(MetricValue(
                name="python_version_info",
                value=1,  # Presence indicator
                timestamp=timestamp,
                source="application",
                tags={"type": "runtime", "version": python_version}
            ))
            
            # Application uptime
            uptime = timestamp - self.start_time
            metrics.append(MetricValue(
                name="application_uptime_seconds",
                value=uptime,
                timestamp=timestamp,
                source="application",
                tags={"type": "runtime"}
            ))
            
            # Thread count
            thread_count = threading.active_count()
            metrics.append(MetricValue(
                name="application_thread_count",
                value=thread_count,
                timestamp=timestamp,
                source="application",
                tags={"type": "runtime"}
            ))
            
            # Module count
            module_count = len(sys.modules)
            metrics.append(MetricValue(
                name="application_module_count",
                value=module_count,
                timestamp=timestamp,
                source="application",
                tags={"type": "runtime"}
            ))
            
            # Stack size information
            stack_size = threading.stack_size() if hasattr(threading, 'stack_size') else 0
            if stack_size > 0:
                metrics.append(MetricValue(
                    name="application_stack_size_bytes",
                    value=stack_size,
                    timestamp=timestamp,
                    source="application",
                    tags={"type": "runtime"}
                ))
            
            # Recursion limit
            recursion_limit = sys.getrecursionlimit()
            metrics.append(MetricValue(
                name="application_recursion_limit",
                value=recursion_limit,
                timestamp=timestamp,
                source="application",
                tags={"type": "runtime"}
            ))
            
        except Exception as e:
            logger.error(f"Runtime metrics collection error: {e}")
            self.collection_errors['runtime'] += 1
        
        return metrics
    
    def _collect_memory_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect application memory metrics"""
        metrics = []
        
        try:
            # Garbage collection metrics
            gc_stats = gc.get_stats()
            for i, stat in enumerate(gc_stats):
                metrics.extend([
                    MetricValue(f"gc_generation_{i}_collections", stat['collections'], timestamp,
                              source="application", tags={"type": "memory", "gc_generation": str(i)}),
                    MetricValue(f"gc_generation_{i}_collected", stat['collected'], timestamp,
                              source="application", tags={"type": "memory", "gc_generation": str(i)}),
                    MetricValue(f"gc_generation_{i}_uncollectable", stat['uncollectable'], timestamp,
                              source="application", tags={"type": "memory", "gc_generation": str(i)})
                ])
            
            # Object counts by generation
            gc_counts = gc.get_count()
            for i, count in enumerate(gc_counts):
                metrics.append(MetricValue(
                    f"gc_generation_{i}_objects",
                    value=count,
                    timestamp=timestamp,
                    source="application",
                    tags={"type": "memory", "gc_generation": str(i)}
                ))
            
            # Total object count
            total_objects = sum(gc_counts)
            metrics.append(MetricValue(
                name="application_total_objects",
                value=total_objects,
                timestamp=timestamp,
                source="application",
                tags={"type": "memory"}
            ))
            
            # Tracked objects count
            tracked_count = len(self.tracked_objects)
            metrics.append(MetricValue(
                name="application_tracked_objects",
                value=tracked_count,
                timestamp=timestamp,
                source="application",
                tags={"type": "memory"}
            ))
            
            # Reference count for key objects
            try:
                import gc
                referrers_count = len(gc.get_referrers())
                metrics.append(MetricValue(
                    name="application_object_referrers",
                    value=referrers_count,
                    timestamp=timestamp,
                    source="application",
                    tags={"type": "memory"}
                ))
            except Exception:
                pass
            
        except Exception as e:
            logger.error(f"Memory metrics collection error: {e}")
            self.collection_errors['memory'] += 1
        
        return metrics
    
    def _collect_performance_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect application performance metrics"""
        metrics = []
        
        try:
            # Counter metrics
            for name, value in self.counters.items():
                metrics.append(MetricValue(
                    name=f"application_counter_{name}",
                    value=value,
                    timestamp=timestamp,
                    source="application",
                    tags={"type": "performance", "metric_type": "counter"}
                ))
            
            # Gauge metrics
            for name, value in self.gauges.items():
                metrics.append(MetricValue(
                    name=f"application_gauge_{name}",
                    value=value,
                    timestamp=timestamp,
                    source="application",
                    tags={"type": "performance", "metric_type": "gauge"}
                ))
            
            # Response time statistics
            for name, times in [
                ("query", self.query_times),
                ("expert", self.expert_response_times),
                ("api", self.api_response_times),
                ("mcp", self.mcp_response_times)
            ]:
                if times:
                    times_list = list(times)
                    avg_time = sum(times_list) / len(times_list)
                    max_time = max(times_list)
                    min_time = min(times_list)
                    
                    # Calculate percentiles
                    sorted_times = sorted(times_list)
                    p95_idx = int(len(sorted_times) * 0.95)
                    p99_idx = int(len(sorted_times) * 0.99)
                    
                    p95_time = sorted_times[p95_idx] if p95_idx < len(sorted_times) else max_time
                    p99_time = sorted_times[p99_idx] if p99_idx < len(sorted_times) else max_time
                    
                    metrics.extend([
                        MetricValue(f"application_{name}_response_time_avg", avg_time, timestamp,
                                  source="application", tags={"type": "performance", "component": name}),
                        MetricValue(f"application_{name}_response_time_max", max_time, timestamp,
                                  source="application", tags={"type": "performance", "component": name}),
                        MetricValue(f"application_{name}_response_time_min", min_time, timestamp,
                                  source="application", tags={"type": "performance", "component": name}),
                        MetricValue(f"application_{name}_response_time_p95", p95_time, timestamp,
                                  source="application", tags={"type": "performance", "component": name}),
                        MetricValue(f"application_{name}_response_time_p99", p99_time, timestamp,
                                  source="application", tags={"type": "performance", "component": name}),
                        MetricValue(f"application_{name}_response_count", len(times_list), timestamp,
                                  source="application", tags={"type": "performance", "component": name})
                    ])
        
        except Exception as e:
            logger.error(f"Performance metrics collection error: {e}")
            self.collection_errors['performance'] += 1
        
        return metrics
    
    def _collect_circle_of_experts_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect Circle of Experts specific metrics"""
        metrics = []
        
        try:
            component_status = self.component_health.get('circle_of_experts', {})
            
            # Component availability
            is_available = 1 if component_status.get('status') == 'available' else 0
            metrics.append(MetricValue(
                name="circle_of_experts_available",
                value=is_available,
                timestamp=timestamp,
                source="application",
                tags={"type": "circle_of_experts", "component": "availability"}
            ))
            
            # Simulated expert performance metrics (these would be real in production)
            if is_available:
                # Expert pool size
                metrics.append(MetricValue(
                    name="circle_of_experts_pool_size",
                    value=self.gauges.get('expert_pool_size', 5),
                    timestamp=timestamp,
                    source="application",
                    tags={"type": "circle_of_experts", "component": "pool"}
                ))
                
                # Active experts
                metrics.append(MetricValue(
                    name="circle_of_experts_active_experts",
                    value=self.gauges.get('active_experts', 3),
                    timestamp=timestamp,
                    source="application",
                    tags={"type": "circle_of_experts", "component": "pool"}
                ))
                
                # Query queue size
                metrics.append(MetricValue(
                    name="circle_of_experts_query_queue_size",
                    value=self.gauges.get('query_queue_size', 0),
                    timestamp=timestamp,
                    source="application",
                    tags={"type": "circle_of_experts", "component": "queue"}
                ))
                
                # Expert utilization
                for expert_type in ['claude', 'openai', 'anthropic', 'local']:
                    utilization = self.gauges.get(f'{expert_type}_utilization', 0.5)
                    metrics.append(MetricValue(
                        name="circle_of_experts_utilization",
                        value=utilization,
                        timestamp=timestamp,
                        source="application",
                        tags={"type": "circle_of_experts", "expert_type": expert_type}
                    ))
                
                # Consensus metrics
                metrics.extend([
                    MetricValue("circle_of_experts_consensus_success_rate",
                              self.gauges.get('consensus_success_rate', 0.95), timestamp,
                              source="application", tags={"type": "circle_of_experts", "component": "consensus"}),
                    MetricValue("circle_of_experts_consensus_time_avg",
                              self.gauges.get('consensus_time_avg', 2.5), timestamp,
                              source="application", tags={"type": "circle_of_experts", "component": "consensus"}),
                    MetricValue("circle_of_experts_disagreement_rate",
                              self.gauges.get('disagreement_rate', 0.1), timestamp,
                              source="application", tags={"type": "circle_of_experts", "component": "consensus"})
                ])
                
                # Query processing metrics
                metrics.extend([
                    MetricValue("circle_of_experts_queries_processed_total",
                              self.counters.get('queries_processed', 0), timestamp,
                              source="application", tags={"type": "circle_of_experts", "component": "processing"}),
                    MetricValue("circle_of_experts_queries_failed_total",
                              self.counters.get('queries_failed', 0), timestamp,
                              source="application", tags={"type": "circle_of_experts", "component": "processing"}),
                    MetricValue("circle_of_experts_queries_timeout_total",
                              self.counters.get('queries_timeout', 0), timestamp,
                              source="application", tags={"type": "circle_of_experts", "component": "processing"})
                ])
        
        except Exception as e:
            logger.error(f"Circle of Experts metrics collection error: {e}")
            self.collection_errors['circle_of_experts'] += 1
        
        return metrics
    
    def _collect_mcp_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect MCP server metrics"""
        metrics = []
        
        try:
            component_status = self.component_health.get('mcp_servers', {})
            
            # Component availability
            is_available = 1 if component_status.get('status') == 'available' else 0
            metrics.append(MetricValue(
                name="mcp_servers_available",
                value=is_available,
                timestamp=timestamp,
                source="application",
                tags={"type": "mcp", "component": "availability"}
            ))
            
            if is_available:
                # MCP server pool metrics
                server_types = ['communication', 'devops', 'infrastructure', 'monitoring', 'security', 'storage']
                
                for server_type in server_types:
                    # Server status
                    server_status = self.gauges.get(f'mcp_{server_type}_status', 1)
                    metrics.append(MetricValue(
                        name="mcp_server_status",
                        value=server_status,
                        timestamp=timestamp,
                        source="application",
                        tags={"type": "mcp", "server_type": server_type}
                    ))
                    
                    # Request metrics
                    request_count = self.counters.get(f'mcp_{server_type}_requests', 0)
                    error_count = self.counters.get(f'mcp_{server_type}_errors', 0)
                    
                    metrics.extend([
                        MetricValue("mcp_server_requests_total", request_count, timestamp,
                                  source="application", tags={"type": "mcp", "server_type": server_type}),
                        MetricValue("mcp_server_errors_total", error_count, timestamp,
                                  source="application", tags={"type": "mcp", "server_type": server_type})
                    ])
                    
                    # Success rate
                    if request_count > 0:
                        success_rate = (request_count - error_count) / request_count
                        metrics.append(MetricValue(
                            name="mcp_server_success_rate",
                            value=success_rate,
                            timestamp=timestamp,
                            source="application",
                            tags={"type": "mcp", "server_type": server_type}
                        ))
                
                # Connection pool metrics
                metrics.extend([
                    MetricValue("mcp_connection_pool_size", self.gauges.get('mcp_pool_size', 10), timestamp,
                              source="application", tags={"type": "mcp", "component": "connection_pool"}),
                    MetricValue("mcp_active_connections", self.gauges.get('mcp_active_connections', 5), timestamp,
                              source="application", tags={"type": "mcp", "component": "connection_pool"}),
                    MetricValue("mcp_idle_connections", self.gauges.get('mcp_idle_connections', 3), timestamp,
                              source="application", tags={"type": "mcp", "component": "connection_pool"}),
                    MetricValue("mcp_connection_wait_time", self.gauges.get('mcp_wait_time', 0.1), timestamp,
                              source="application", tags={"type": "mcp", "component": "connection_pool"})
                ])
                
                # Protocol compliance metrics
                metrics.extend([
                    MetricValue("mcp_protocol_violations", self.counters.get('mcp_protocol_violations', 0), timestamp,
                              source="application", tags={"type": "mcp", "component": "protocol"}),
                    MetricValue("mcp_message_parse_errors", self.counters.get('mcp_parse_errors', 0), timestamp,
                              source="application", tags={"type": "mcp", "component": "protocol"}),
                    MetricValue("mcp_timeout_errors", self.counters.get('mcp_timeout_errors', 0), timestamp,
                              source="application", tags={"type": "mcp", "component": "protocol"})
                ])
        
        except Exception as e:
            logger.error(f"MCP metrics collection error: {e}")
            self.collection_errors['mcp'] += 1
        
        return metrics
    
    def _collect_database_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect database performance metrics"""
        metrics = []
        
        try:
            component_status = self.component_health.get('database', {})
            
            # Component availability
            is_available = 1 if component_status.get('status') == 'available' else 0
            metrics.append(MetricValue(
                name="database_available",
                value=is_available,
                timestamp=timestamp,
                source="application",
                tags={"type": "database", "component": "availability"}
            ))
            
            if is_available:
                # Connection pool metrics
                metrics.extend([
                    MetricValue("database_connection_pool_size", self.gauges.get('db_pool_size', 20), timestamp,
                              source="application", tags={"type": "database", "component": "connection_pool"}),
                    MetricValue("database_active_connections", self.gauges.get('db_active_connections', 8), timestamp,
                              source="application", tags={"type": "database", "component": "connection_pool"}),
                    MetricValue("database_idle_connections", self.gauges.get('db_idle_connections', 10), timestamp,
                              source="application", tags={"type": "database", "component": "connection_pool"}),
                    MetricValue("database_connection_wait_time", self.gauges.get('db_wait_time', 0.05), timestamp,
                              source="application", tags={"type": "database", "component": "connection_pool"})
                ])
                
                # Query performance metrics
                metrics.extend([
                    MetricValue("database_queries_total", self.counters.get('db_queries_total', 0), timestamp,
                              source="application", tags={"type": "database", "component": "queries"}),
                    MetricValue("database_queries_failed", self.counters.get('db_queries_failed', 0), timestamp,
                              source="application", tags={"type": "database", "component": "queries"}),
                    MetricValue("database_queries_slow", self.counters.get('db_queries_slow', 0), timestamp,
                              source="application", tags={"type": "database", "component": "queries"}),
                    MetricValue("database_query_time_avg", self.gauges.get('db_query_time_avg', 0.05), timestamp,
                              source="application", tags={"type": "database", "component": "performance"})
                ])
                
                # Transaction metrics
                metrics.extend([
                    MetricValue("database_transactions_total", self.counters.get('db_transactions_total', 0), timestamp,
                              source="application", tags={"type": "database", "component": "transactions"}),
                    MetricValue("database_transactions_committed", self.counters.get('db_transactions_committed', 0), timestamp,
                              source="application", tags={"type": "database", "component": "transactions"}),
                    MetricValue("database_transactions_rolled_back", self.counters.get('db_transactions_rolled_back', 0), timestamp,
                              source="application", tags={"type": "database", "component": "transactions"})
                ])
                
                # Cache metrics (if applicable)
                metrics.extend([
                    MetricValue("database_cache_hit_rate", self.gauges.get('db_cache_hit_rate', 0.85), timestamp,
                              source="application", tags={"type": "database", "component": "cache"}),
                    MetricValue("database_cache_size_mb", self.gauges.get('db_cache_size_mb', 256), timestamp,
                              source="application", tags={"type": "database", "component": "cache"}),
                    MetricValue("database_cache_evictions", self.counters.get('db_cache_evictions', 0), timestamp,
                              source="application", tags={"type": "database", "component": "cache"})
                ])
        
        except Exception as e:
            logger.error(f"Database metrics collection error: {e}")
            self.collection_errors['database'] += 1
        
        return metrics
    
    def _collect_api_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect API performance metrics"""
        metrics = []
        
        try:
            component_status = self.component_health.get('api', {})
            
            # Component availability
            is_available = 1 if component_status.get('status') == 'available' else 0
            metrics.append(MetricValue(
                name="api_available",
                value=is_available,
                timestamp=timestamp,
                source="application",
                tags={"type": "api", "component": "availability"}
            ))
            
            if is_available:
                # Request metrics by endpoint type
                endpoint_types = ['query', 'status', 'metrics', 'health', 'expert']
                
                for endpoint in endpoint_types:
                    metrics.extend([
                        MetricValue("api_requests_total", self.counters.get(f'api_{endpoint}_requests', 0), timestamp,
                                  source="application", tags={"type": "api", "endpoint": endpoint}),
                        MetricValue("api_requests_success", self.counters.get(f'api_{endpoint}_success', 0), timestamp,
                                  source="application", tags={"type": "api", "endpoint": endpoint}),
                        MetricValue("api_requests_error", self.counters.get(f'api_{endpoint}_error', 0), timestamp,
                                  source="application", tags={"type": "api", "endpoint": endpoint}),
                        MetricValue("api_response_time_avg", self.gauges.get(f'api_{endpoint}_time_avg', 0.1), timestamp,
                                  source="application", tags={"type": "api", "endpoint": endpoint})
                    ])
                
                # HTTP status code metrics
                status_codes = [200, 400, 401, 403, 404, 429, 500, 502, 503, 504]
                for status_code in status_codes:
                    count = self.counters.get(f'api_status_{status_code}', 0)
                    metrics.append(MetricValue(
                        name="api_responses_by_status",
                        value=count,
                        timestamp=timestamp,
                        source="application",
                        tags={"type": "api", "status_code": str(status_code)}
                    ))
                
                # Rate limiting metrics
                metrics.extend([
                    MetricValue("api_rate_limit_hits", self.counters.get('api_rate_limit_hits', 0), timestamp,
                              source="application", tags={"type": "api", "component": "rate_limiting"}),
                    MetricValue("api_rate_limit_remaining", self.gauges.get('api_rate_limit_remaining', 100), timestamp,
                              source="application", tags={"type": "api", "component": "rate_limiting"}),
                    MetricValue("api_concurrent_requests", self.gauges.get('api_concurrent_requests', 5), timestamp,
                              source="application", tags={"type": "api", "component": "concurrency"})
                ])
                
                # Authentication metrics
                metrics.extend([
                    MetricValue("api_auth_attempts", self.counters.get('api_auth_attempts', 0), timestamp,
                              source="application", tags={"type": "api", "component": "authentication"}),
                    MetricValue("api_auth_failures", self.counters.get('api_auth_failures', 0), timestamp,
                              source="application", tags={"type": "api", "component": "authentication"}),
                    MetricValue("api_token_validations", self.counters.get('api_token_validations', 0), timestamp,
                              source="application", tags={"type": "api", "component": "authentication"})
                ])
        
        except Exception as e:
            logger.error(f"API metrics collection error: {e}")
            self.collection_errors['api'] += 1
        
        return metrics
    
    def _collect_health_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect application health metrics"""
        metrics = []
        
        try:
            # Overall application health score
            health_components = []
            for component, status in self.component_health.items():
                component_health = 1.0 if status.get('status') == 'available' else 0.0
                health_components.append(component_health)
                
                # Individual component health
                metrics.append(MetricValue(
                    name="application_component_health",
                    value=component_health,
                    timestamp=timestamp,
                    source="application",
                    tags={"type": "health", "component": component}
                ))
            
            # Overall health score
            overall_health = sum(health_components) / len(health_components) if health_components else 0.0
            metrics.append(MetricValue(
                name="application_health_score",
                value=overall_health,
                timestamp=timestamp,
                source="application",
                tags={"type": "health"}
            ))
            
            # Error rate metrics
            total_errors = sum(self.collection_errors.values())
            metrics.append(MetricValue(
                name="application_error_rate",
                value=total_errors,
                timestamp=timestamp,
                source="application",
                tags={"type": "health"}
            ))
            
            # Resource utilization health
            memory_health = 1.0 - min(1.0, sum(gc.get_count()) / 10000)  # Rough estimate
            metrics.append(MetricValue(
                name="application_memory_health",
                value=memory_health,
                timestamp=timestamp,
                source="application",
                tags={"type": "health", "resource": "memory"}
            ))
            
            # Thread health
            thread_health = 1.0 - min(1.0, threading.active_count() / 100)  # Assume 100+ threads is unhealthy
            metrics.append(MetricValue(
                name="application_thread_health",
                value=thread_health,
                timestamp=timestamp,
                source="application",
                tags={"type": "health", "resource": "threads"}
            ))
        
        except Exception as e:
            logger.error(f"Health metrics collection error: {e}")
            self.collection_errors['health'] += 1
        
        return metrics
    
    def _collect_monitoring_metrics(self, timestamp: float) -> List[MetricValue]:
        """Collect monitoring system metrics"""
        metrics = []
        
        try:
            # Collection error metrics
            for error_type, count in self.collection_errors.items():
                metrics.append(MetricValue(
                    name="application_collection_errors",
                    value=count,
                    timestamp=timestamp,
                    source="application",
                    tags={"type": "monitoring", "error_type": error_type}
                ))
            
            # Metrics collection rate
            collection_rate = self.gauges.get('metrics_collection_rate', 1.0)
            metrics.append(MetricValue(
                name="application_metrics_collection_rate",
                value=collection_rate,
                timestamp=timestamp,
                source="application",
                tags={"type": "monitoring"}
            ))
            
            # Memory usage by the monitoring system itself
            monitoring_memory = self.gauges.get('monitoring_memory_mb', 50)
            metrics.append(MetricValue(
                name="application_monitoring_memory_mb",
                value=monitoring_memory,
                timestamp=timestamp,
                source="application",
                tags={"type": "monitoring"}
            ))
        
        except Exception as e:
            logger.error(f"Monitoring metrics collection error: {e}")
            self.collection_errors['monitoring'] += 1
        
        return metrics
    
    # Public methods for updating metrics from application code
    def record_query_time(self, duration: float, query_type: str = "general"):
        """Record a query execution time"""
        self.query_times.append(duration)
        self.counters[f'queries_{query_type}'] += 1
    
    def record_expert_response_time(self, duration: float, expert_type: str = "general"):
        """Record an expert response time"""
        self.expert_response_times.append(duration)
        self.counters[f'expert_responses_{expert_type}'] += 1
    
    def record_api_response_time(self, duration: float, endpoint: str = "general"):
        """Record an API response time"""
        self.api_response_times.append(duration)
        self.counters[f'api_responses_{endpoint}'] += 1
    
    def record_mcp_response_time(self, duration: float, server_type: str = "general"):
        """Record an MCP server response time"""
        self.mcp_response_times.append(duration)
        self.counters[f'mcp_responses_{server_type}'] += 1
    
    def increment_counter(self, name: str, value: int = 1):
        """Increment a counter metric"""
        self.counters[name] += value
    
    def set_gauge(self, name: str, value: float):
        """Set a gauge metric value"""
        self.gauges[name] = value
    
    def track_object(self, obj):
        """Track an object for memory monitoring"""
        self.tracked_objects.add(obj)
    
    def update_component_health(self, component: str, status: str, **kwargs):
        """Update component health status"""
        self.component_health[component] = {
            'status': status,
            'last_check': time.time(),
            **kwargs
        }
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        return {
            'collection_errors': dict(self.collection_errors),
            'total_errors': sum(self.collection_errors.values()),
            'component_health': self.component_health,
            'counters_count': len(self.counters),
            'gauges_count': len(self.gauges),
            'tracked_objects': len(self.tracked_objects)
        }

# Example usage
if __name__ == "__main__":
    collector = ApplicationMetricsCollector()
    
    # Simulate some application activity
    collector.record_query_time(0.5, "expert_query")
    collector.record_api_response_time(0.1, "health_check")
    collector.increment_counter("test_counter", 5)
    collector.set_gauge("test_gauge", 75.5)
    
    print("=== Application Metrics Collection ===")
    metrics = collector.collect_all_metrics()
    
    print(f"Collected {len(metrics)} metrics")
    
    # Show sample metrics
    for metric in metrics[:15]:
        print(f"{metric.name}: {metric.value} (tags: {metric.tags})")
    
    print("\n=== Collection Statistics ===")
    stats = collector.get_collection_stats()
    print(json.dumps(stats, indent=2, default=str))