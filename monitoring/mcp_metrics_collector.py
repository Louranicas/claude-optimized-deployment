#!/usr/bin/env python3
"""
MCP Server Metrics Collection System
Implements comprehensive Prometheus metrics collection for MCP servers including
custom business metrics, performance counters, and error tracking.
"""

import asyncio
import json
import logging
import time
import psutil
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
from collections import defaultdict, deque
import httpx
import websockets
from prometheus_client import (
    CollectorRegistry, Gauge, Counter, Histogram, Summary, 
    Enum as PrometheusEnum, Info, push_to_gateway, start_http_server
)
import structlog

@dataclass
class MetricConfiguration:
    """Configuration for a custom metric"""
    name: str
    metric_type: str  # gauge, counter, histogram, summary
    description: str
    labels: List[str]
    buckets: Optional[List[float]] = None  # For histograms
    objectives: Optional[Dict[float, float]] = None  # For summaries

class MCPMetricsCollector:
    """Comprehensive metrics collector for MCP servers"""
    
    def __init__(self, config_path: str = None):
        self.logger = structlog.get_logger("mcp_metrics_collector")
        self.config = self._load_config(config_path)
        self.registry = CollectorRegistry()
        self.metrics = {}
        self.last_collection_time = {}
        self.metric_history = defaultdict(lambda: deque(maxlen=1000))
        self._setup_core_metrics()
        self._setup_custom_metrics()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load metrics configuration"""
        default_config = {
            "collection_interval": 30,
            "custom_metrics": [
                {
                    "name": "mcp_request_duration_seconds",
                    "metric_type": "histogram",
                    "description": "Duration of MCP requests",
                    "labels": ["server_name", "method", "status"],
                    "buckets": [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
                },
                {
                    "name": "mcp_active_connections",
                    "metric_type": "gauge",
                    "description": "Number of active MCP connections",
                    "labels": ["server_name"]
                },
                {
                    "name": "mcp_messages_processed_total",
                    "metric_type": "counter",
                    "description": "Total number of MCP messages processed",
                    "labels": ["server_name", "message_type", "status"]
                },
                {
                    "name": "mcp_memory_usage_bytes",
                    "metric_type": "gauge",
                    "description": "Memory usage of MCP servers in bytes",
                    "labels": ["server_name", "memory_type"]
                },
                {
                    "name": "mcp_cpu_usage_percent",
                    "metric_type": "gauge",
                    "description": "CPU usage percentage of MCP servers",
                    "labels": ["server_name"]
                },
                {
                    "name": "mcp_error_rate",
                    "metric_type": "gauge",
                    "description": "Error rate of MCP servers (errors per second)",
                    "labels": ["server_name", "error_type"]
                },
                {
                    "name": "mcp_response_size_bytes",
                    "metric_type": "histogram",
                    "description": "Size of MCP responses in bytes",
                    "labels": ["server_name", "method"],
                    "buckets": [100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000]
                },
                {
                    "name": "mcp_tool_execution_duration_seconds",
                    "metric_type": "histogram",
                    "description": "Duration of tool execution in MCP servers",
                    "labels": ["server_name", "tool_name", "status"],
                    "buckets": [0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0]
                },
                {
                    "name": "mcp_resource_usage_score",
                    "metric_type": "gauge",
                    "description": "Resource usage efficiency score (0-100)",
                    "labels": ["server_name", "resource_type"]
                },
                {
                    "name": "mcp_cache_hit_rate",
                    "metric_type": "gauge",
                    "description": "Cache hit rate percentage",
                    "labels": ["server_name", "cache_type"]
                },
                {
                    "name": "mcp_concurrent_operations",
                    "metric_type": "gauge",
                    "description": "Number of concurrent operations",
                    "labels": ["server_name", "operation_type"]
                }
            ],
            "servers": {
                "desktop-commander": {"port": 8001, "process_name": "node"},
                "filesystem": {"port": 8002, "process_name": "node"},
                "postgres": {"port": 8003, "process_name": "node"},
                "github": {"port": 8004, "process_name": "node"},
                "memory": {"port": 8005, "process_name": "node"},
                "brave-search": {"port": 8006, "process_name": "node"},
                "slack": {"port": 8007, "process_name": "node"},
                "puppeteer": {"port": 8008, "process_name": "node"}
            },
            "system_metrics": {
                "enabled": True,
                "collect_disk_io": True,
                "collect_network_io": True,
                "collect_file_descriptors": True
            }
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                self.logger.warning("Failed to load config file, using defaults", error=str(e))
                
        return default_config

    def _setup_core_metrics(self):
        """Setup core Prometheus metrics"""
        
        # Server availability
        self.metrics['server_up'] = Gauge(
            'mcp_server_up',
            'Whether the MCP server is up (1) or down (0)',
            ['server_name'],
            registry=self.registry
        )
        
        # Basic performance metrics
        self.metrics['response_time'] = Histogram(
            'mcp_response_time_seconds',
            'Response time for MCP server health checks',
            ['server_name', 'endpoint'],
            buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
            registry=self.registry
        )
        
        # System resource metrics
        self.metrics['cpu_usage'] = Gauge(
            'mcp_server_cpu_usage_percent',
            'CPU usage percentage of MCP server processes',
            ['server_name'],
            registry=self.registry
        )
        
        self.metrics['memory_usage'] = Gauge(
            'mcp_server_memory_usage_bytes',
            'Memory usage of MCP server processes in bytes',
            ['server_name', 'memory_type'],
            registry=self.registry
        )
        
        self.metrics['file_descriptors'] = Gauge(
            'mcp_server_file_descriptors',
            'Number of open file descriptors',
            ['server_name'],
            registry=self.registry
        )
        
        # Network metrics
        self.metrics['network_bytes'] = Gauge(
            'mcp_server_network_bytes_total',
            'Total network bytes sent/received',
            ['server_name', 'direction'],
            registry=self.registry
        )
        
        # Error tracking
        self.metrics['errors_total'] = Counter(
            'mcp_server_errors_total',
            'Total number of errors',
            ['server_name', 'error_type', 'severity'],
            registry=self.registry
        )
        
        # Connection metrics
        self.metrics['connections_active'] = Gauge(
            'mcp_server_connections_active',
            'Number of active connections',
            ['server_name'],
            registry=self.registry
        )
        
        self.metrics['connections_total'] = Counter(
            'mcp_server_connections_total',
            'Total number of connections created',
            ['server_name'],
            registry=self.registry
        )
        
        # Performance indicators
        self.metrics['throughput'] = Gauge(
            'mcp_server_throughput_requests_per_second',
            'Request throughput in requests per second',
            ['server_name'],
            registry=self.registry
        )
        
        self.metrics['latency_p50'] = Gauge(
            'mcp_server_latency_p50_seconds',
            '50th percentile latency',
            ['server_name'],
            registry=self.registry
        )
        
        self.metrics['latency_p95'] = Gauge(
            'mcp_server_latency_p95_seconds',
            '95th percentile latency',
            ['server_name'],
            registry=self.registry
        )
        
        self.metrics['latency_p99'] = Gauge(
            'mcp_server_latency_p99_seconds',
            '99th percentile latency',
            ['server_name'],
            registry=self.registry
        )

    def _setup_custom_metrics(self):
        """Setup custom business metrics"""
        for metric_config in self.config.get("custom_metrics", []):
            try:
                if metric_config["metric_type"] == "gauge":
                    self.metrics[metric_config["name"]] = Gauge(
                        metric_config["name"],
                        metric_config["description"],
                        metric_config["labels"],
                        registry=self.registry
                    )
                elif metric_config["metric_type"] == "counter":
                    self.metrics[metric_config["name"]] = Counter(
                        metric_config["name"],
                        metric_config["description"],
                        metric_config["labels"],
                        registry=self.registry
                    )
                elif metric_config["metric_type"] == "histogram":
                    buckets = metric_config.get("buckets")
                    self.metrics[metric_config["name"]] = Histogram(
                        metric_config["name"],
                        metric_config["description"],
                        metric_config["labels"],
                        buckets=buckets,
                        registry=self.registry
                    )
                elif metric_config["metric_type"] == "summary":
                    objectives = metric_config.get("objectives", {0.5: 0.05, 0.9: 0.01, 0.99: 0.001})
                    self.metrics[metric_config["name"]] = Summary(
                        metric_config["name"],
                        metric_config["description"],
                        metric_config["labels"],
                        registry=self.registry
                    )
            except Exception as e:
                self.logger.error("Failed to create custom metric", 
                                metric=metric_config["name"], error=str(e))

    async def collect_server_metrics(self, server_name: str) -> Dict[str, Any]:
        """Collect metrics for a specific server"""
        server_config = self.config["servers"].get(server_name, {})
        port = server_config.get("port")
        process_name = server_config.get("process_name", "node")
        
        metrics_data = {
            "server_name": server_name,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": {}
        }
        
        try:
            # Check if server is responding
            server_up = await self._check_server_availability(server_name, port)
            self.metrics['server_up'].labels(server_name=server_name).set(1 if server_up else 0)
            metrics_data["metrics"]["server_up"] = server_up
            
            if server_up:
                # Collect response time metrics
                response_time = await self._measure_response_time(server_name, port)
                if response_time is not None:
                    self.metrics['response_time'].labels(
                        server_name=server_name, 
                        endpoint="/health"
                    ).observe(response_time)
                    metrics_data["metrics"]["response_time_seconds"] = response_time
                
                # Collect server-specific metrics from endpoint
                server_metrics = await self._collect_server_endpoint_metrics(server_name, port)
                if server_metrics:
                    metrics_data["metrics"].update(server_metrics)
                    self._update_custom_metrics(server_name, server_metrics)
            
            # Collect process-level metrics
            process_metrics = self._collect_process_metrics(server_name, process_name)
            if process_metrics:
                metrics_data["metrics"].update(process_metrics)
                self._update_process_metrics(server_name, process_metrics)
            
            # Calculate derived metrics
            derived_metrics = self._calculate_derived_metrics(server_name, metrics_data["metrics"])
            metrics_data["metrics"].update(derived_metrics)
            
        except Exception as e:
            self.logger.error("Failed to collect metrics for server", 
                            server=server_name, error=str(e))
            self.metrics['errors_total'].labels(
                server_name=server_name,
                error_type="metrics_collection",
                severity="error"
            ).inc()
        
        # Store in history
        self.metric_history[server_name].append(metrics_data)
        self.last_collection_time[server_name] = time.time()
        
        return metrics_data

    async def _check_server_availability(self, server_name: str, port: int) -> bool:
        """Check if server is available"""
        try:
            if not port:
                return False
                
            url = f"http://localhost:{port}/health"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)
                return response.status_code < 400
        except Exception:
            return False

    async def _measure_response_time(self, server_name: str, port: int) -> Optional[float]:
        """Measure server response time"""
        try:
            url = f"http://localhost:{port}/health"
            start_time = time.time()
            
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)
                end_time = time.time()
                
                if response.status_code < 400:
                    return end_time - start_time
                else:
                    return None
        except Exception:
            return None

    async def _collect_server_endpoint_metrics(self, server_name: str, port: int) -> Dict[str, Any]:
        """Collect metrics from server's metrics endpoint"""
        try:
            url = f"http://localhost:{port}/metrics"
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(url)
                
                if response.status_code == 200:
                    # Parse metrics response (assuming JSON format)
                    try:
                        return response.json()
                    except json.JSONDecodeError:
                        # If not JSON, try to parse Prometheus format
                        return self._parse_prometheus_metrics(response.text)
                else:
                    return {}
        except Exception as e:
            self.logger.debug("Failed to collect endpoint metrics", 
                            server=server_name, error=str(e))
            return {}

    def _parse_prometheus_metrics(self, metrics_text: str) -> Dict[str, Any]:
        """Parse Prometheus format metrics"""
        metrics = {}
        for line in metrics_text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    # Simple parsing for basic metrics
                    if ' ' in line:
                        metric_name, value = line.rsplit(' ', 1)
                        # Remove labels for simplicity
                        if '{' in metric_name:
                            metric_name = metric_name.split('{')[0]
                        metrics[metric_name] = float(value)
                except (ValueError, IndexError):
                    continue
        return metrics

    def _collect_process_metrics(self, server_name: str, process_name: str) -> Dict[str, Any]:
        """Collect process-level metrics"""
        metrics = {}
        
        try:
            # Find processes matching the server
            matching_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_info', 'num_fds', 'connections']):
                try:
                    if (process_name.lower() in proc.info['name'].lower() or
                        any(server_name in arg for arg in proc.info.get('cmdline', []))):
                        matching_processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if matching_processes:
                # Aggregate metrics from all matching processes
                total_cpu = 0
                total_memory = 0
                total_rss = 0
                total_vms = 0
                total_fds = 0
                total_connections = 0
                
                for proc in matching_processes:
                    try:
                        cpu_percent = proc.cpu_percent()
                        memory_info = proc.memory_info()
                        
                        total_cpu += cpu_percent
                        total_memory += memory_info.rss
                        total_rss += memory_info.rss
                        total_vms += memory_info.vms
                        
                        # File descriptors (Unix-like systems)
                        try:
                            total_fds += proc.num_fds()
                        except (AttributeError, psutil.AccessDenied):
                            pass
                        
                        # Network connections
                        try:
                            total_connections += len(proc.connections())
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                metrics.update({
                    "process_count": len(matching_processes),
                    "cpu_percent": total_cpu,
                    "memory_rss_bytes": total_rss,
                    "memory_vms_bytes": total_vms,
                    "file_descriptors": total_fds,
                    "network_connections": total_connections
                })
                
        except Exception as e:
            self.logger.error("Failed to collect process metrics", 
                            server=server_name, error=str(e))
        
        return metrics

    def _update_process_metrics(self, server_name: str, process_metrics: Dict[str, Any]):
        """Update Prometheus metrics with process data"""
        if "cpu_percent" in process_metrics:
            self.metrics['cpu_usage'].labels(server_name=server_name).set(
                process_metrics["cpu_percent"]
            )
        
        if "memory_rss_bytes" in process_metrics:
            self.metrics['memory_usage'].labels(
                server_name=server_name, 
                memory_type="rss"
            ).set(process_metrics["memory_rss_bytes"])
        
        if "memory_vms_bytes" in process_metrics:
            self.metrics['memory_usage'].labels(
                server_name=server_name, 
                memory_type="vms"
            ).set(process_metrics["memory_vms_bytes"])
        
        if "file_descriptors" in process_metrics:
            self.metrics['file_descriptors'].labels(server_name=server_name).set(
                process_metrics["file_descriptors"]
            )
        
        if "network_connections" in process_metrics:
            self.metrics['connections_active'].labels(server_name=server_name).set(
                process_metrics["network_connections"]
            )

    def _update_custom_metrics(self, server_name: str, server_metrics: Dict[str, Any]):
        """Update custom metrics with server data"""
        for metric_name, value in server_metrics.items():
            try:
                if isinstance(value, (int, float)):
                    # Map common metric patterns to our custom metrics
                    if "request_duration" in metric_name and "mcp_request_duration_seconds" in self.metrics:
                        # This would need actual request data with labels
                        pass
                    elif "active_connections" in metric_name and "mcp_active_connections" in self.metrics:
                        self.metrics["mcp_active_connections"].labels(server_name=server_name).set(value)
                    elif "memory" in metric_name and "mcp_memory_usage_bytes" in self.metrics:
                        memory_type = "heap" if "heap" in metric_name else "total"
                        self.metrics["mcp_memory_usage_bytes"].labels(
                            server_name=server_name, 
                            memory_type=memory_type
                        ).set(value)
                    elif "cpu" in metric_name and "mcp_cpu_usage_percent" in self.metrics:
                        self.metrics["mcp_cpu_usage_percent"].labels(server_name=server_name).set(value)
            except Exception as e:
                self.logger.debug("Failed to update custom metric", 
                                metric=metric_name, error=str(e))

    def _calculate_derived_metrics(self, server_name: str, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate derived metrics based on collected data"""
        derived = {}
        
        try:
            # Calculate resource efficiency score
            cpu_percent = metrics.get("cpu_percent", 0)
            memory_bytes = metrics.get("memory_rss_bytes", 0)
            
            # Simple efficiency score (inverse of resource usage)
            cpu_efficiency = max(0, 100 - cpu_percent)
            memory_efficiency = max(0, 100 - min(100, (memory_bytes / (1024*1024*1024)) * 10))  # Rough GB scale
            
            overall_efficiency = (cpu_efficiency + memory_efficiency) / 2
            derived["resource_efficiency_score"] = overall_efficiency
            
            if "mcp_resource_usage_score" in self.metrics:
                self.metrics["mcp_resource_usage_score"].labels(
                    server_name=server_name, 
                    resource_type="cpu"
                ).set(cpu_efficiency)
                self.metrics["mcp_resource_usage_score"].labels(
                    server_name=server_name, 
                    resource_type="memory"
                ).set(memory_efficiency)
                self.metrics["mcp_resource_usage_score"].labels(
                    server_name=server_name, 
                    resource_type="overall"
                ).set(overall_efficiency)
            
            # Calculate throughput if we have historical data
            history = list(self.metric_history[server_name])
            if len(history) >= 2:
                current_time = time.time()
                last_time = self.last_collection_time.get(server_name, current_time)
                time_diff = current_time - last_time
                
                if time_diff > 0:
                    # This is a placeholder - real throughput would need request counts
                    estimated_throughput = 1.0 / time_diff  # Rough estimate
                    derived["estimated_throughput_rps"] = estimated_throughput
                    
                    if "throughput" in self.metrics:
                        self.metrics["throughput"].labels(server_name=server_name).set(estimated_throughput)
                        
        except Exception as e:
            self.logger.error("Failed to calculate derived metrics", 
                            server=server_name, error=str(e))
        
        return derived

    async def collect_all_metrics(self) -> Dict[str, Any]:
        """Collect metrics from all configured servers"""
        start_time = time.time()
        results = {}
        
        tasks = []
        for server_name in self.config["servers"].keys():
            task = self.collect_server_metrics(server_name)
            tasks.append((server_name, task))
        
        # Execute all collections concurrently
        completed_tasks = await asyncio.gather(
            *[task for _, task in tasks],
            return_exceptions=True
        )
        
        for (server_name, _), result in zip(tasks, completed_tasks):
            if isinstance(result, Exception):
                self.logger.error("Failed to collect metrics for server", 
                                server=server_name, error=str(result))
                self.metrics['errors_total'].labels(
                    server_name=server_name,
                    error_type="collection_exception",
                    severity="error"
                ).inc()
                results[server_name] = {
                    "error": str(result),
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                results[server_name] = result
        
        collection_time = time.time() - start_time
        
        return {
            "collection_timestamp": datetime.utcnow().isoformat(),
            "collection_duration_seconds": collection_time,
            "servers": results,
            "summary": {
                "total_servers": len(self.config["servers"]),
                "successful_collections": len([r for r in results.values() if "error" not in r]),
                "failed_collections": len([r for r in results.values() if "error" in r])
            }
        }

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of current metrics"""
        summary = {
            "timestamp": datetime.utcnow().isoformat(),
            "servers": {},
            "aggregated": {
                "total_servers": len(self.config["servers"]),
                "servers_up": 0,
                "avg_cpu_percent": 0,
                "total_memory_mb": 0,
                "total_connections": 0,
                "avg_response_time_ms": 0
            }
        }
        
        total_cpu = 0
        total_memory = 0
        total_connections = 0
        total_response_times = []
        servers_with_data = 0
        
        for server_name in self.config["servers"].keys():
            history = list(self.metric_history[server_name])
            if history:
                latest = history[-1]
                metrics = latest.get("metrics", {})
                
                server_summary = {
                    "up": metrics.get("server_up", False),
                    "cpu_percent": metrics.get("cpu_percent", 0),
                    "memory_mb": metrics.get("memory_rss_bytes", 0) / (1024*1024),
                    "connections": metrics.get("network_connections", 0),
                    "response_time_ms": metrics.get("response_time_seconds", 0) * 1000,
                    "last_update": latest.get("timestamp")
                }
                
                summary["servers"][server_name] = server_summary
                
                if server_summary["up"]:
                    summary["aggregated"]["servers_up"] += 1
                    total_cpu += server_summary["cpu_percent"]
                    total_memory += server_summary["memory_mb"]
                    total_connections += server_summary["connections"]
                    if server_summary["response_time_ms"] > 0:
                        total_response_times.append(server_summary["response_time_ms"])
                    servers_with_data += 1
        
        if servers_with_data > 0:
            summary["aggregated"]["avg_cpu_percent"] = total_cpu / servers_with_data
            summary["aggregated"]["avg_response_time_ms"] = (
                sum(total_response_times) / len(total_response_times) 
                if total_response_times else 0
            )
        
        summary["aggregated"]["total_memory_mb"] = total_memory
        summary["aggregated"]["total_connections"] = total_connections
        
        return summary

    async def push_metrics(self, gateway_url: str = "localhost:9091"):
        """Push metrics to Prometheus gateway"""
        try:
            push_to_gateway(
                gateway_url,
                job='mcp_metrics_collector',
                registry=self.registry
            )
            self.logger.info("Metrics pushed to gateway", gateway=gateway_url)
        except Exception as e:
            self.logger.error("Failed to push metrics", error=str(e))

    def start_metrics_server(self, port: int = 9090):
        """Start HTTP server to expose metrics"""
        try:
            start_http_server(port, registry=self.registry)
            self.logger.info("Metrics server started", port=port)
        except Exception as e:
            self.logger.error("Failed to start metrics server", error=str(e))

    async def run_continuous_collection(self, interval_seconds: int = None):
        """Run continuous metrics collection"""
        interval = interval_seconds or self.config.get("collection_interval", 30)
        self.logger.info("Starting continuous metrics collection", interval=interval)
        
        while True:
            try:
                start_time = time.time()
                
                # Collect all metrics
                results = await self.collect_all_metrics()
                
                # Log summary
                summary = results.get("summary", {})
                self.logger.info(
                    "Metrics collection completed",
                    total_servers=summary.get("total_servers", 0),
                    successful=summary.get("successful_collections", 0),
                    failed=summary.get("failed_collections", 0),
                    duration_seconds=results.get("collection_duration_seconds", 0)
                )
                
                # Push to gateway
                await self.push_metrics()
                
                # Wait for next interval
                await asyncio.sleep(interval)
                
            except Exception as e:
                self.logger.error("Error in continuous collection", error=str(e))
                await asyncio.sleep(interval)

# CLI interface
async def main():
    import argparse
    parser = argparse.ArgumentParser(description="MCP Server Metrics Collector")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--server", help="Collect metrics for specific server only")
    parser.add_argument("--continuous", action="store_true", help="Run continuous collection")
    parser.add_argument("--interval", type=int, default=30, help="Collection interval in seconds")
    parser.add_argument("--output", choices=["json", "summary"], default="summary")
    parser.add_argument("--metrics-server", action="store_true", help="Start metrics HTTP server")
    parser.add_argument("--port", type=int, default=9090, help="Metrics server port")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    collector = MCPMetricsCollector(args.config)
    
    if args.metrics_server:
        collector.start_metrics_server(args.port)
    
    if args.continuous:
        await collector.run_continuous_collection(args.interval)
    else:
        if args.server:
            result = await collector.collect_server_metrics(args.server)
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                print(f"Server: {result['server_name']}")
                print(f"Timestamp: {result['timestamp']}")
                for metric, value in result['metrics'].items():
                    print(f"  {metric}: {value}")
        else:
            if args.output == "summary":
                summary = collector.get_metrics_summary()
                print(json.dumps(summary, indent=2))
            else:
                results = await collector.collect_all_metrics()
                print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(main())