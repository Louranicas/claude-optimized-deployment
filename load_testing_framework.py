#!/usr/bin/env python3
"""
Comprehensive 24-Hour Sustained Load Testing Framework

This framework implements realistic production traffic patterns and validates
system stability under sustained load conditions.
"""

import asyncio
import aiohttp
import json
import time
import random
import statistics
import psutil
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from contextlib import asynccontextmanager
import logging
import sys
import os
from concurrent.futures import ThreadPoolExecutor
import signal
import csv
import numpy as np
from collections import defaultdict, deque
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('load_test.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class LoadTestConfig:
    """Configuration for load testing."""
    base_url: str = "http://localhost:8000"
    max_concurrent_users: int = 100
    test_duration_hours: int = 24
    ramp_up_minutes: int = 30
    ramp_down_minutes: int = 15
    scenarios: Dict[str, Any] = None
    monitoring_interval: int = 10
    report_interval: int = 300
    database_path: str = "load_test_results.db"
    enable_chaos_testing: bool = True
    memory_leak_threshold_mb: int = 500
    cpu_threshold_percent: int = 85
    response_time_sla_ms: int = 2000
    error_rate_sla_percent: float = 1.0
    
    def __post_init__(self):
        if self.scenarios is None:
            self.scenarios = {
                "user_registration": {"weight": 5, "endpoint": "/auth/register"},
                "user_login": {"weight": 15, "endpoint": "/auth/login"},
                "api_queries": {"weight": 30, "endpoint": "/api/query"},
                "mcp_tool_calls": {"weight": 20, "endpoint": "/mcp/tools"},
                "circle_of_experts": {"weight": 15, "endpoint": "/experts/query"},
                "monitoring_health": {"weight": 10, "endpoint": "/health"},
                "file_operations": {"weight": 5, "endpoint": "/files/upload"}
            }


@dataclass
class TestResult:
    """Individual test result."""
    timestamp: datetime
    scenario: str
    endpoint: str
    method: str
    status_code: int
    response_time_ms: float
    request_size_bytes: int
    response_size_bytes: int
    error_message: Optional[str]
    user_id: str
    thread_id: int


@dataclass
class SystemMetrics:
    """System resource metrics."""
    timestamp: datetime
    cpu_percent: float
    memory_used_mb: float
    memory_available_mb: float
    memory_percent: float
    disk_used_gb: float
    disk_free_gb: float
    network_bytes_sent: int
    network_bytes_recv: int
    open_files: int
    active_connections: int


@dataclass
class LoadTestReport:
    """Load test summary report."""
    test_start: datetime
    test_end: datetime
    duration_hours: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    error_rate_percent: float
    avg_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    max_response_time_ms: float
    min_response_time_ms: float
    requests_per_second: float
    peak_concurrent_users: int
    sla_compliance: Dict[str, bool]
    memory_leak_detected: bool
    performance_degradation: bool
    circuit_breaker_triggers: int
    retry_attempts: int
    system_stability_score: float


class RealisticTrafficGenerator:
    """Generates realistic traffic patterns based on daily cycles."""
    
    def __init__(self):
        self.daily_pattern = self._create_daily_pattern()
        self.weekly_pattern = self._create_weekly_pattern()
        
    def _create_daily_pattern(self) -> Dict[int, float]:
        """Create hourly traffic multipliers for a typical day."""
        # Typical web application traffic pattern
        return {
            0: 0.3,   # Midnight - 1 AM
            1: 0.2,   # 1 AM - 2 AM
            2: 0.15,  # 2 AM - 3 AM
            3: 0.1,   # 3 AM - 4 AM (lowest traffic)
            4: 0.12,  # 4 AM - 5 AM
            5: 0.2,   # 5 AM - 6 AM
            6: 0.4,   # 6 AM - 7 AM (morning ramp-up)
            7: 0.7,   # 7 AM - 8 AM
            8: 0.9,   # 8 AM - 9 AM (work day begins)
            9: 1.0,   # 9 AM - 10 AM (peak morning)
            10: 0.95, # 10 AM - 11 AM
            11: 0.9,  # 11 AM - 12 PM
            12: 0.8,  # 12 PM - 1 PM (lunch dip)
            13: 0.85, # 1 PM - 2 PM
            14: 0.95, # 2 PM - 3 PM (afternoon peak)
            15: 1.0,  # 3 PM - 4 PM (highest traffic)
            16: 0.9,  # 4 PM - 5 PM
            17: 0.7,  # 5 PM - 6 PM (work day ends)
            18: 0.6,  # 6 PM - 7 PM
            19: 0.7,  # 7 PM - 8 PM (evening usage)
            20: 0.8,  # 8 PM - 9 PM
            21: 0.75, # 9 PM - 10 PM
            22: 0.6,  # 10 PM - 11 PM
            23: 0.45  # 11 PM - Midnight
        }
    
    def _create_weekly_pattern(self) -> Dict[int, float]:
        """Create daily traffic multipliers for a typical week."""
        return {
            0: 1.0,   # Monday
            1: 1.05,  # Tuesday (peak day)
            2: 1.0,   # Wednesday
            3: 0.95,  # Thursday
            4: 0.8,   # Friday (early finish)
            5: 0.4,   # Saturday (weekend low)
            6: 0.3    # Sunday (weekend low)
        }
    
    def get_traffic_multiplier(self, current_time: datetime) -> float:
        """Get traffic multiplier for current time."""
        hour_multiplier = self.daily_pattern.get(current_time.hour, 0.5)
        day_multiplier = self.weekly_pattern.get(current_time.weekday(), 0.5)
        
        # Add some randomness (±20%)
        randomness = random.uniform(0.8, 1.2)
        
        return hour_multiplier * day_multiplier * randomness
    
    def calculate_concurrent_users(self, base_users: int) -> int:
        """Calculate concurrent users based on traffic pattern."""
        multiplier = self.get_traffic_multiplier(datetime.now())
        return max(1, int(base_users * multiplier))


class DatabaseManager:
    """Manages test result database storage."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS test_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    scenario TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    method TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    response_time_ms REAL NOT NULL,
                    request_size_bytes INTEGER NOT NULL,
                    response_size_bytes INTEGER NOT NULL,
                    error_message TEXT,
                    user_id TEXT NOT NULL,
                    thread_id INTEGER NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    cpu_percent REAL NOT NULL,
                    memory_used_mb REAL NOT NULL,
                    memory_available_mb REAL NOT NULL,
                    memory_percent REAL NOT NULL,
                    disk_used_gb REAL NOT NULL,
                    disk_free_gb REAL NOT NULL,
                    network_bytes_sent INTEGER NOT NULL,
                    network_bytes_recv INTEGER NOT NULL,
                    open_files INTEGER NOT NULL,
                    active_connections INTEGER NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS load_test_summary (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_start TEXT NOT NULL,
                    test_end TEXT NOT NULL,
                    duration_hours REAL NOT NULL,
                    total_requests INTEGER NOT NULL,
                    successful_requests INTEGER NOT NULL,
                    failed_requests INTEGER NOT NULL,
                    error_rate_percent REAL NOT NULL,
                    avg_response_time_ms REAL NOT NULL,
                    p95_response_time_ms REAL NOT NULL,
                    p99_response_time_ms REAL NOT NULL,
                    requests_per_second REAL NOT NULL,
                    peak_concurrent_users INTEGER NOT NULL,
                    sla_compliance TEXT NOT NULL,
                    memory_leak_detected BOOLEAN NOT NULL,
                    performance_degradation BOOLEAN NOT NULL,
                    system_stability_score REAL NOT NULL
                )
            """)
    
    def save_test_result(self, result: TestResult):
        """Save individual test result."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO test_results VALUES (
                    NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                result.timestamp.isoformat(),
                result.scenario,
                result.endpoint,
                result.method,
                result.status_code,
                result.response_time_ms,
                result.request_size_bytes,
                result.response_size_bytes,
                result.error_message,
                result.user_id,
                result.thread_id
            ))
    
    def save_system_metrics(self, metrics: SystemMetrics):
        """Save system metrics."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO system_metrics VALUES (
                    NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                metrics.timestamp.isoformat(),
                metrics.cpu_percent,
                metrics.memory_used_mb,
                metrics.memory_available_mb,
                metrics.memory_percent,
                metrics.disk_used_gb,
                metrics.disk_free_gb,
                metrics.network_bytes_sent,
                metrics.network_bytes_recv,
                metrics.open_files,
                metrics.active_connections
            ))
    
    def save_test_summary(self, summary: LoadTestReport):
        """Save test summary report."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO load_test_summary VALUES (
                    NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                summary.test_start.isoformat(),
                summary.test_end.isoformat(),
                summary.duration_hours,
                summary.total_requests,
                summary.successful_requests,
                summary.failed_requests,
                summary.error_rate_percent,
                summary.avg_response_time_ms,
                summary.p95_response_time_ms,
                summary.p99_response_time_ms,
                summary.requests_per_second,
                summary.peak_concurrent_users,
                json.dumps(summary.sla_compliance),
                summary.memory_leak_detected,
                summary.performance_degradation,
                summary.system_stability_score
            ))
    
    def get_test_results(self, start_time: datetime, end_time: datetime) -> List[TestResult]:
        """Get test results within time range."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM test_results 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp
            """, (start_time.isoformat(), end_time.isoformat()))
            
            results = []
            for row in cursor:
                results.append(TestResult(
                    timestamp=datetime.fromisoformat(row[1]),
                    scenario=row[2],
                    endpoint=row[3],
                    method=row[4],
                    status_code=row[5],
                    response_time_ms=row[6],
                    request_size_bytes=row[7],
                    response_size_bytes=row[8],
                    error_message=row[9],
                    user_id=row[10],
                    thread_id=row[11]
                ))
            
            return results


class SystemMonitor:
    """Monitors system resources during load testing."""
    
    def __init__(self, db_manager: DatabaseManager, interval: int = 10):
        self.db_manager = db_manager
        self.interval = interval
        self.monitoring = False
        self.initial_memory = None
        self.memory_history = deque(maxlen=360)  # 1 hour of 10s intervals
        self.cpu_history = deque(maxlen=360)
        
    def start_monitoring(self):
        """Start system monitoring."""
        self.monitoring = True
        self.initial_memory = psutil.virtual_memory().used
        
        def monitor_loop():
            while self.monitoring:
                try:
                    metrics = self._collect_metrics()
                    self.db_manager.save_system_metrics(metrics)
                    
                    # Store for trend analysis
                    self.memory_history.append(metrics.memory_used_mb)
                    self.cpu_history.append(metrics.cpu_percent)
                    
                    time.sleep(self.interval)
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
        
        threading.Thread(target=monitor_loop, daemon=True).start()
        logger.info("System monitoring started")
    
    def stop_monitoring(self):
        """Stop system monitoring."""
        self.monitoring = False
        logger.info("System monitoring stopped")
    
    def _collect_metrics(self) -> SystemMetrics:
        """Collect current system metrics."""
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_used_mb = memory.used / (1024 * 1024)
        memory_available_mb = memory.available / (1024 * 1024)
        memory_percent = memory.percent
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_used_gb = disk.used / (1024 * 1024 * 1024)
        disk_free_gb = disk.free / (1024 * 1024 * 1024)
        
        # Network usage
        network = psutil.net_io_counters()
        network_bytes_sent = network.bytes_sent
        network_bytes_recv = network.bytes_recv
        
        # Process metrics
        process = psutil.Process()
        open_files = len(process.open_files())
        active_connections = len(process.connections())
        
        return SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_used_mb=memory_used_mb,
            memory_available_mb=memory_available_mb,
            memory_percent=memory_percent,
            disk_used_gb=disk_used_gb,
            disk_free_gb=disk_free_gb,
            network_bytes_sent=network_bytes_sent,
            network_bytes_recv=network_bytes_recv,
            open_files=open_files,
            active_connections=active_connections
        )
    
    def detect_memory_leak(self, threshold_mb: int = 500) -> bool:
        """Detect potential memory leaks."""
        if len(self.memory_history) < 100:  # Need enough data
            return False
        
        # Calculate trend over last hour
        recent_memory = list(self.memory_history)[-100:]  # Last ~16 minutes
        older_memory = list(self.memory_history)[:100]    # Earlier data
        
        if not older_memory:
            return False
        
        recent_avg = statistics.mean(recent_memory)
        older_avg = statistics.mean(older_memory)
        
        memory_increase = recent_avg - older_avg
        return memory_increase > threshold_mb
    
    def detect_performance_degradation(self) -> bool:
        """Detect performance degradation trends."""
        if len(self.cpu_history) < 100:
            return False
        
        recent_cpu = list(self.cpu_history)[-100:]
        older_cpu = list(self.cpu_history)[:100]
        
        if not older_cpu:
            return False
        
        recent_avg = statistics.mean(recent_cpu)
        older_avg = statistics.mean(older_cpu)
        
        # Performance degradation if CPU usage increased significantly
        return recent_avg > older_avg + 20  # 20% increase threshold


class LoadTestScenario:
    """Individual load test scenario."""
    
    def __init__(self, name: str, endpoint: str, weight: int, method: str = "GET"):
        self.name = name
        self.endpoint = endpoint
        self.weight = weight
        self.method = method
        self.request_count = 0
        self.success_count = 0
        self.error_count = 0
        self.response_times = []
    
    async def execute(self, session: aiohttp.ClientSession, base_url: str, 
                     user_id: str, thread_id: int) -> TestResult:
        """Execute the scenario and return results."""
        start_time = time.time()
        request_size = 0
        response_size = 0
        error_message = None
        
        try:
            # Prepare request data based on scenario
            request_data = self._prepare_request_data()
            request_size = len(json.dumps(request_data).encode()) if request_data else 0
            
            # Execute request
            async with session.request(
                self.method,
                f"{base_url}{self.endpoint}",
                json=request_data if self.method in ["POST", "PUT", "PATCH"] else None,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                response_text = await response.text()
                response_size = len(response_text.encode())
                status_code = response.status
                
                if status_code < 400:
                    self.success_count += 1
                else:
                    self.error_count += 1
                    error_message = f"HTTP {status_code}: {response_text[:200]}"
                
        except asyncio.TimeoutError:
            status_code = 408
            error_message = "Request timeout"
            self.error_count += 1
        except Exception as e:
            status_code = 500
            error_message = str(e)[:200]
            self.error_count += 1
        
        response_time_ms = (time.time() - start_time) * 1000
        self.response_times.append(response_time_ms)
        self.request_count += 1
        
        return TestResult(
            timestamp=datetime.now(),
            scenario=self.name,
            endpoint=self.endpoint,
            method=self.method,
            status_code=status_code,
            response_time_ms=response_time_ms,
            request_size_bytes=request_size,
            response_size_bytes=response_size,
            error_message=error_message,
            user_id=user_id,
            thread_id=thread_id
        )
    
    def _prepare_request_data(self) -> Optional[Dict]:
        """Prepare request data based on scenario type."""
        if self.name == "user_registration":
            return {
                "username": f"testuser_{random.randint(1000, 9999)}",
                "email": f"test{random.randint(1000, 9999)}@example.com",
                "password": "TestPassword123!",
                "full_name": f"Test User {random.randint(1, 1000)}"
            }
        elif self.name == "user_login":
            return {
                "username": f"testuser_{random.randint(1, 100)}",
                "password": "TestPassword123!"
            }
        elif self.name == "api_queries":
            return {
                "query": random.choice([
                    "What is the weather like?",
                    "How to deploy applications?",
                    "Best practices for microservices",
                    "Database optimization techniques"
                ]),
                "parameters": {"format": "json", "detailed": True}
            }
        elif self.name == "mcp_tool_calls":
            return {
                "tool": random.choice(["file_read", "web_search", "database_query"]),
                "parameters": {"input": f"test_input_{random.randint(1, 1000)}"}
            }
        elif self.name == "circle_of_experts":
            return {
                "question": random.choice([
                    "How to scale a web application?",
                    "Security best practices for APIs",
                    "Performance optimization strategies"
                ]),
                "expert_count": random.randint(3, 7)
            }
        elif self.name == "file_operations":
            return {
                "filename": f"test_file_{random.randint(1, 1000)}.txt",
                "content": "This is test file content for load testing." * 10
            }
        
        return None


class CircuitBreakerTester:
    """Tests circuit breaker functionality under load."""
    
    def __init__(self):
        self.failure_count = 0
        self.success_count = 0
        self.circuit_open_count = 0
        self.last_failure_time = None
    
    def record_failure(self):
        """Record a circuit breaker failure."""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
    
    def record_success(self):
        """Record a successful request."""
        self.success_count += 1
    
    def record_circuit_open(self):
        """Record circuit breaker opening."""
        self.circuit_open_count += 1
        logger.warning("Circuit breaker opened due to failures")
    
    def get_failure_rate(self) -> float:
        """Get current failure rate."""
        total = self.failure_count + self.success_count
        return (self.failure_count / total * 100) if total > 0 else 0


class ChaosEngineeringTester:
    """Implements chaos engineering during load testing."""
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.chaos_events = []
        
    async def introduce_random_chaos(self):
        """Introduce random chaos events."""
        if not self.enabled:
            return
        
        # Random chaos events (10% chance per minute)
        if random.random() < 0.1:
            chaos_type = random.choice([
                "network_latency",
                "cpu_spike",
                "memory_pressure",
                "disk_full",
                "connection_drop"
            ])
            
            await self._execute_chaos_event(chaos_type)
    
    async def _execute_chaos_event(self, chaos_type: str):
        """Execute specific chaos event."""
        logger.warning(f"Chaos event triggered: {chaos_type}")
        
        self.chaos_events.append({
            "type": chaos_type,
            "timestamp": datetime.now(),
            "duration": random.randint(30, 120)  # 30-120 seconds
        })
        
        if chaos_type == "network_latency":
            # Simulate network delays
            await asyncio.sleep(random.uniform(0.5, 2.0))
        elif chaos_type == "cpu_spike":
            # Simulate CPU intensive operation
            start_time = time.time()
            while time.time() - start_time < 10:  # 10 seconds
                _ = sum(i ** 2 for i in range(1000))
        elif chaos_type == "memory_pressure":
            # Simulate memory allocation
            memory_hog = [random.random() for _ in range(1000000)]
            await asyncio.sleep(30)
            del memory_hog


class LoadTestRunner:
    """Main load test runner orchestrating all components."""
    
    def __init__(self, config: LoadTestConfig):
        self.config = config
        self.db_manager = DatabaseManager(config.database_path)
        self.system_monitor = SystemMonitor(self.db_manager, config.monitoring_interval)
        self.traffic_generator = RealisticTrafficGenerator()
        self.circuit_breaker = CircuitBreakerTester()
        self.chaos_tester = ChaosEngineeringTester(config.enable_chaos_testing)
        
        # Test state
        self.test_start_time = None
        self.test_end_time = None
        self.running = False
        self.scenarios = self._create_scenarios()
        self.active_users = 0
        self.peak_concurrent_users = 0
        
        # Results tracking
        self.all_results = []
        self.results_lock = threading.Lock()
        
        # Signal handling for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _create_scenarios(self) -> List[LoadTestScenario]:
        """Create test scenarios from configuration."""
        scenarios = []
        for name, config in self.config.scenarios.items():
            scenario = LoadTestScenario(
                name=name,
                endpoint=config["endpoint"],
                weight=config["weight"],
                method=config.get("method", "GET")
            )
            scenarios.append(scenario)
        return scenarios
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    async def run_load_test(self):
        """Run the complete load test."""
        logger.info("Starting 24-hour sustained load test")
        
        self.test_start_time = datetime.now()
        self.running = True
        
        # Start system monitoring
        self.system_monitor.start_monitoring()
        
        try:
            # Run test phases
            await self._run_ramp_up_phase()
            await self._run_sustained_load_phase()
            await self._run_ramp_down_phase()
            
        except Exception as e:
            logger.error(f"Load test error: {e}")
        finally:
            self.running = False
            self.test_end_time = datetime.now()
            
            # Stop monitoring
            self.system_monitor.stop_monitoring()
            
            # Generate final report
            await self._generate_final_report()
    
    async def _run_ramp_up_phase(self):
        """Gradually increase load to target concurrent users."""
        logger.info("Starting ramp-up phase")
        
        ramp_up_duration = self.config.ramp_up_minutes * 60
        target_users = self.config.max_concurrent_users
        
        for i in range(0, target_users, max(1, target_users // 30)):
            if not self.running:
                break
            
            concurrent_users = min(i + 1, target_users)
            self.active_users = concurrent_users
            
            logger.info(f"Ramping up to {concurrent_users} concurrent users")
            
            # Start user sessions
            tasks = []
            for user_id in range(concurrent_users):
                task = asyncio.create_task(
                    self._simulate_user_session(f"user_{user_id}", user_id)
                )
                tasks.append(task)
            
            # Wait for ramp-up interval
            await asyncio.sleep(ramp_up_duration / 30)
            
            # Cancel tasks for this ramp level
            for task in tasks:
                if not task.done():
                    task.cancel()
    
    async def _run_sustained_load_phase(self):
        """Run sustained load with realistic traffic patterns."""
        logger.info("Starting sustained load phase")
        
        sustained_duration = (self.config.test_duration_hours - 
                            (self.config.ramp_up_minutes + self.config.ramp_down_minutes) / 60) * 3600
        
        end_time = datetime.now() + timedelta(seconds=sustained_duration)
        
        while datetime.now() < end_time and self.running:
            # Calculate current load based on traffic patterns
            base_users = self.config.max_concurrent_users
            current_users = self.traffic_generator.calculate_concurrent_users(base_users)
            
            self.active_users = current_users
            self.peak_concurrent_users = max(self.peak_concurrent_users, current_users)
            
            logger.info(f"Sustaining load with {current_users} concurrent users")
            
            # Create user session tasks
            tasks = []
            for user_id in range(current_users):
                task = asyncio.create_task(
                    self._simulate_user_session(f"sustained_user_{user_id}", user_id)
                )
                tasks.append(task)
            
            # Introduce chaos engineering
            if self.config.enable_chaos_testing:
                await self.chaos_tester.introduce_random_chaos()
            
            # Run for report interval
            await asyncio.sleep(self.config.report_interval)
            
            # Cancel current tasks
            for task in tasks:
                if not task.done():
                    task.cancel()
            
            # Generate interim report
            await self._generate_interim_report()
    
    async def _run_ramp_down_phase(self):
        """Gradually reduce load to zero."""
        logger.info("Starting ramp-down phase")
        
        ramp_down_duration = self.config.ramp_down_minutes * 60
        current_users = self.active_users
        
        while current_users > 0 and self.running:
            current_users = max(0, current_users - max(1, self.config.max_concurrent_users // 15))
            self.active_users = current_users
            
            logger.info(f"Ramping down to {current_users} concurrent users")
            
            if current_users > 0:
                tasks = []
                for user_id in range(current_users):
                    task = asyncio.create_task(
                        self._simulate_user_session(f"rampdown_user_{user_id}", user_id)
                    )
                    tasks.append(task)
                
                await asyncio.sleep(ramp_down_duration / 15)
                
                for task in tasks:
                    if not task.done():
                        task.cancel()
    
    async def _simulate_user_session(self, user_id: str, thread_id: int):
        """Simulate individual user session."""
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": f"LoadTest/{user_id}"}
        ) as session:
            
            # Session duration (5-30 minutes)
            session_duration = random.randint(300, 1800)
            session_end = datetime.now() + timedelta(seconds=session_duration)
            
            request_count = 0
            
            while datetime.now() < session_end and self.running:
                try:
                    # Select scenario based on weights
                    scenario = self._select_weighted_scenario()
                    
                    # Execute scenario
                    result = await scenario.execute(
                        session, self.config.base_url, user_id, thread_id
                    )
                    
                    # Store result
                    with self.results_lock:
                        self.all_results.append(result)
                        self.db_manager.save_test_result(result)
                    
                    # Update circuit breaker
                    if result.status_code < 400:
                        self.circuit_breaker.record_success()
                    else:
                        self.circuit_breaker.record_failure()
                        
                        if self.circuit_breaker.get_failure_rate() > 50:
                            self.circuit_breaker.record_circuit_open()
                    
                    request_count += 1
                    
                    # Realistic think time between requests (1-10 seconds)
                    think_time = random.uniform(1, 10)
                    await asyncio.sleep(think_time)
                    
                except Exception as e:
                    logger.error(f"User session error: {e}")
                    await asyncio.sleep(5)  # Back off on errors
    
    def _select_weighted_scenario(self) -> LoadTestScenario:
        """Select scenario based on weights."""
        total_weight = sum(scenario.weight for scenario in self.scenarios)
        random_value = random.randint(1, total_weight)
        
        cumulative_weight = 0
        for scenario in self.scenarios:
            cumulative_weight += scenario.weight
            if random_value <= cumulative_weight:
                return scenario
        
        return self.scenarios[0]  # Fallback
    
    async def _generate_interim_report(self):
        """Generate interim progress report."""
        current_time = datetime.now()
        
        if not self.all_results:
            return
        
        with self.results_lock:
            recent_results = [
                r for r in self.all_results 
                if (current_time - r.timestamp).total_seconds() < self.config.report_interval
            ]
        
        if not recent_results:
            return
        
        total_requests = len(recent_results)
        successful_requests = sum(1 for r in recent_results if r.status_code < 400)
        error_rate = ((total_requests - successful_requests) / total_requests * 100) if total_requests > 0 else 0
        
        response_times = [r.response_time_ms for r in recent_results]
        avg_response_time = statistics.mean(response_times) if response_times else 0
        
        logger.info(f"""
        === INTERIM REPORT ===
        Time: {current_time.strftime('%Y-%m-%d %H:%M:%S')}
        Active Users: {self.active_users}
        Recent Requests: {total_requests}
        Success Rate: {((successful_requests / total_requests) * 100):.2f}%
        Error Rate: {error_rate:.2f}%
        Avg Response Time: {avg_response_time:.2f}ms
        Memory Leak Detected: {self.system_monitor.detect_memory_leak()}
        Performance Degradation: {self.system_monitor.detect_performance_degradation()}
        Circuit Breaker Failures: {self.circuit_breaker.failure_count}
        """)
    
    async def _generate_final_report(self):
        """Generate comprehensive final report."""
        logger.info("Generating final load test report")
        
        if not self.all_results:
            logger.error("No test results available for report generation")
            return
        
        # Calculate statistics
        total_requests = len(self.all_results)
        successful_requests = sum(1 for r in self.all_results if r.status_code < 400)
        failed_requests = total_requests - successful_requests
        error_rate = (failed_requests / total_requests * 100) if total_requests > 0 else 0
        
        response_times = [r.response_time_ms for r in self.all_results]
        avg_response_time = statistics.mean(response_times) if response_times else 0
        
        # Percentiles
        if response_times:
            p95_response_time = np.percentile(response_times, 95)
            p99_response_time = np.percentile(response_times, 99)
            max_response_time = max(response_times)
            min_response_time = min(response_times)
        else:
            p95_response_time = p99_response_time = max_response_time = min_response_time = 0
        
        # Calculate duration and RPS
        duration_hours = (self.test_end_time - self.test_start_time).total_seconds() / 3600
        requests_per_second = total_requests / (duration_hours * 3600) if duration_hours > 0 else 0
        
        # SLA compliance
        sla_compliance = {
            "response_time": avg_response_time <= self.config.response_time_sla_ms,
            "error_rate": error_rate <= self.config.error_rate_sla_percent,
            "availability": error_rate < 5.0  # 95% availability
        }
        
        # System stability metrics
        memory_leak_detected = self.system_monitor.detect_memory_leak(
            self.config.memory_leak_threshold_mb
        )
        performance_degradation = self.system_monitor.detect_performance_degradation()
        
        # Calculate stability score (0-100)
        stability_score = 100
        if memory_leak_detected:
            stability_score -= 30
        if performance_degradation:
            stability_score -= 20
        if error_rate > self.config.error_rate_sla_percent:
            stability_score -= 25
        if avg_response_time > self.config.response_time_sla_ms:
            stability_score -= 15
        if self.circuit_breaker.circuit_open_count > 0:
            stability_score -= 10
        
        stability_score = max(0, stability_score)
        
        # Create report
        report = LoadTestReport(
            test_start=self.test_start_time,
            test_end=self.test_end_time,
            duration_hours=duration_hours,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            error_rate_percent=error_rate,
            avg_response_time_ms=avg_response_time,
            p95_response_time_ms=p95_response_time,
            p99_response_time_ms=p99_response_time,
            max_response_time_ms=max_response_time,
            min_response_time_ms=min_response_time,
            requests_per_second=requests_per_second,
            peak_concurrent_users=self.peak_concurrent_users,
            sla_compliance=sla_compliance,
            memory_leak_detected=memory_leak_detected,
            performance_degradation=performance_degradation,
            circuit_breaker_triggers=self.circuit_breaker.circuit_open_count,
            retry_attempts=0,  # Would be tracked if retry logic was implemented
            system_stability_score=stability_score
        )
        
        # Save to database
        self.db_manager.save_test_summary(report)
        
        # Generate detailed reports
        await self._generate_detailed_reports(report)
        
        # Print summary
        self._print_final_summary(report)
    
    async def _generate_detailed_reports(self, report: LoadTestReport):
        """Generate detailed analysis reports."""
        # CSV export
        self._export_results_to_csv()
        
        # Performance analysis
        self._generate_performance_analysis()
        
        # Error analysis
        self._generate_error_analysis()
        
        # Capacity recommendations
        self._generate_capacity_recommendations(report)
    
    def _export_results_to_csv(self):
        """Export test results to CSV file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"load_test_results_{timestamp}.csv"
        
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = [
                'timestamp', 'scenario', 'endpoint', 'method', 'status_code',
                'response_time_ms', 'request_size_bytes', 'response_size_bytes',
                'error_message', 'user_id', 'thread_id'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in self.all_results:
                writer.writerow({
                    'timestamp': result.timestamp.isoformat(),
                    'scenario': result.scenario,
                    'endpoint': result.endpoint,
                    'method': result.method,
                    'status_code': result.status_code,
                    'response_time_ms': result.response_time_ms,
                    'request_size_bytes': result.request_size_bytes,
                    'response_size_bytes': result.response_size_bytes,
                    'error_message': result.error_message or '',
                    'user_id': result.user_id,
                    'thread_id': result.thread_id
                })
        
        logger.info(f"Test results exported to {filename}")
    
    def _generate_performance_analysis(self):
        """Generate performance analysis report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"performance_analysis_{timestamp}.json"
        
        # Group by scenario
        scenario_stats = defaultdict(list)
        for result in self.all_results:
            scenario_stats[result.scenario].append(result.response_time_ms)
        
        analysis = {}
        for scenario, response_times in scenario_stats.items():
            if response_times:
                analysis[scenario] = {
                    "count": len(response_times),
                    "avg_response_time": statistics.mean(response_times),
                    "median_response_time": statistics.median(response_times),
                    "p95_response_time": np.percentile(response_times, 95),
                    "p99_response_time": np.percentile(response_times, 99),
                    "min_response_time": min(response_times),
                    "max_response_time": max(response_times),
                    "std_deviation": statistics.stdev(response_times) if len(response_times) > 1 else 0
                }
        
        with open(filename, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        
        logger.info(f"Performance analysis saved to {filename}")
    
    def _generate_error_analysis(self):
        """Generate error analysis report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"error_analysis_{timestamp}.json"
        
        error_stats = defaultdict(lambda: defaultdict(int))
        
        for result in self.all_results:
            if result.status_code >= 400:
                error_stats[result.scenario][result.status_code] += 1
        
        with open(filename, 'w') as f:
            json.dump(dict(error_stats), f, indent=2)
        
        logger.info(f"Error analysis saved to {filename}")
    
    def _generate_capacity_recommendations(self, report: LoadTestReport):
        """Generate capacity planning recommendations."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capacity_recommendations_{timestamp}.yaml"
        
        recommendations = {
            "test_summary": {
                "duration_hours": report.duration_hours,
                "peak_concurrent_users": report.peak_concurrent_users,
                "requests_per_second": report.requests_per_second,
                "error_rate_percent": report.error_rate_percent,
                "avg_response_time_ms": report.avg_response_time_ms,
                "system_stability_score": report.system_stability_score
            },
            "capacity_recommendations": {
                "recommended_max_concurrent_users": self._calculate_recommended_capacity(),
                "scaling_recommendations": self._generate_scaling_recommendations(report),
                "resource_recommendations": self._generate_resource_recommendations(),
                "performance_optimizations": self._generate_performance_optimizations(report)
            },
            "sla_assessment": {
                "current_sla_compliance": report.sla_compliance,
                "recommended_sla_targets": self._recommend_sla_targets(report)
            },
            "production_readiness": {
                "ready_for_production": self._assess_production_readiness(report),
                "required_improvements": self._identify_required_improvements(report)
            }
        }
        
        with open(filename, 'w') as f:
            yaml.dump(recommendations, f, default_flow_style=False)
        
        logger.info(f"Capacity recommendations saved to {filename}")
    
    def _calculate_recommended_capacity(self) -> int:
        """Calculate recommended maximum concurrent users."""
        # Base recommendation on successful load handling
        if self.peak_concurrent_users > 0:
            # Conservative recommendation at 80% of peak if stable
            if self.system_monitor.detect_performance_degradation():
                return int(self.peak_concurrent_users * 0.6)
            else:
                return int(self.peak_concurrent_users * 0.8)
        
        return self.config.max_concurrent_users
    
    def _generate_scaling_recommendations(self, report: LoadTestReport) -> Dict:
        """Generate auto-scaling recommendations."""
        return {
            "horizontal_scaling": {
                "trigger_cpu_percent": 70,
                "trigger_memory_percent": 80,
                "trigger_response_time_ms": report.avg_response_time_ms * 1.5,
                "scale_up_instances": 2,
                "scale_down_delay_minutes": 10
            },
            "vertical_scaling": {
                "recommended_cpu_cores": 4 if report.avg_response_time_ms > 1000 else 2,
                "recommended_memory_gb": 8 if self.system_monitor.detect_memory_leak() else 4
            }
        }
    
    def _generate_resource_recommendations(self) -> Dict:
        """Generate resource configuration recommendations."""
        return {
            "database": {
                "connection_pool_size": min(20, self.peak_concurrent_users),
                "query_timeout_seconds": 30,
                "enable_connection_pooling": True
            },
            "caching": {
                "enable_redis_cache": True,
                "cache_ttl_seconds": 300,
                "max_cache_size_mb": 256
            },
            "load_balancing": {
                "algorithm": "least_connections",
                "health_check_interval_seconds": 30,
                "timeout_seconds": 5
            }
        }
    
    def _generate_performance_optimizations(self, report: LoadTestReport) -> List[str]:
        """Generate performance optimization recommendations."""
        optimizations = []
        
        if report.avg_response_time_ms > 2000:
            optimizations.extend([
                "Implement database query optimization",
                "Add response caching for frequent requests",
                "Consider database connection pooling"
            ])
        
        if report.error_rate_percent > 1.0:
            optimizations.extend([
                "Implement circuit breaker pattern",
                "Add retry logic with exponential backoff",
                "Improve error handling and logging"
            ])
        
        if self.system_monitor.detect_memory_leak():
            optimizations.extend([
                "Investigate memory leaks in application code",
                "Implement garbage collection tuning",
                "Add memory monitoring and alerting"
            ])
        
        if report.system_stability_score < 80:
            optimizations.extend([
                "Implement comprehensive health checks",
                "Add application performance monitoring",
                "Implement graceful degradation patterns"
            ])
        
        return optimizations
    
    def _recommend_sla_targets(self, report: LoadTestReport) -> Dict:
        """Recommend SLA targets based on test results."""
        return {
            "response_time_ms": max(1000, int(report.p95_response_time_ms * 1.2)),
            "availability_percent": 99.5 if report.error_rate_percent < 0.5 else 99.0,
            "error_rate_percent": max(0.5, report.error_rate_percent * 1.5)
        }
    
    def _assess_production_readiness(self, report: LoadTestReport) -> bool:
        """Assess if system is ready for production."""
        criteria = [
            report.error_rate_percent <= 2.0,
            report.avg_response_time_ms <= 3000,
            report.system_stability_score >= 70,
            not report.memory_leak_detected,
            report.sla_compliance.get("response_time", False)
        ]
        
        return sum(criteria) >= 4  # At least 4 out of 5 criteria must be met
    
    def _identify_required_improvements(self, report: LoadTestReport) -> List[str]:
        """Identify required improvements before production deployment."""
        improvements = []
        
        if report.error_rate_percent > 2.0:
            improvements.append("Reduce error rate to below 2%")
        
        if report.avg_response_time_ms > 3000:
            improvements.append("Improve average response time to below 3 seconds")
        
        if report.memory_leak_detected:
            improvements.append("Fix memory leaks")
        
        if report.system_stability_score < 70:
            improvements.append("Improve overall system stability")
        
        if not report.sla_compliance.get("response_time", False):
            improvements.append("Meet response time SLA requirements")
        
        return improvements
    
    def _print_final_summary(self, report: LoadTestReport):
        """Print final test summary to console."""
        print("\n" + "="*80)
        print("24-HOUR SUSTAINED LOAD TEST FINAL REPORT")
        print("="*80)
        print(f"Test Duration: {report.duration_hours:.2f} hours")
        print(f"Test Period: {report.test_start} to {report.test_end}")
        print(f"Peak Concurrent Users: {report.peak_concurrent_users}")
        print(f"Total Requests: {report.total_requests:,}")
        print(f"Successful Requests: {report.successful_requests:,}")
        print(f"Failed Requests: {report.failed_requests:,}")
        print(f"Error Rate: {report.error_rate_percent:.2f}%")
        print(f"Requests per Second: {report.requests_per_second:.2f}")
        print()
        print("RESPONSE TIME METRICS")
        print("-" * 40)
        print(f"Average: {report.avg_response_time_ms:.2f}ms")
        print(f"95th Percentile: {report.p95_response_time_ms:.2f}ms")
        print(f"99th Percentile: {report.p99_response_time_ms:.2f}ms")
        print(f"Maximum: {report.max_response_time_ms:.2f}ms")
        print(f"Minimum: {report.min_response_time_ms:.2f}ms")
        print()
        print("SLA COMPLIANCE")
        print("-" * 40)
        for sla_type, compliant in report.sla_compliance.items():
            status = "✓ PASS" if compliant else "✗ FAIL"
            print(f"{sla_type.replace('_', ' ').title()}: {status}")
        print()
        print("SYSTEM STABILITY")
        print("-" * 40)
        print(f"Memory Leak Detected: {'Yes' if report.memory_leak_detected else 'No'}")
        print(f"Performance Degradation: {'Yes' if report.performance_degradation else 'No'}")
        print(f"Circuit Breaker Triggers: {report.circuit_breaker_triggers}")
        print(f"System Stability Score: {report.system_stability_score:.1f}/100")
        print()
        print("PRODUCTION READINESS")
        print("-" * 40)
        ready = self._assess_production_readiness(report)
        print(f"Ready for Production: {'Yes' if ready else 'No'}")
        
        if not ready:
            improvements = self._identify_required_improvements(report)
            print("\nRequired Improvements:")
            for improvement in improvements:
                print(f"  • {improvement}")
        
        print("\n" + "="*80)


async def main():
    """Main entry point for load testing."""
    # Load configuration
    config = LoadTestConfig(
        base_url=os.getenv("LOAD_TEST_URL", "http://localhost:8000"),
        max_concurrent_users=int(os.getenv("MAX_USERS", "100")),
        test_duration_hours=int(os.getenv("TEST_DURATION_HOURS", "24")),
        enable_chaos_testing=os.getenv("ENABLE_CHAOS", "true").lower() == "true"
    )
    
    # Create and run load test
    runner = LoadTestRunner(config)
    
    try:
        await runner.run_load_test()
        logger.info("Load test completed successfully")
    except Exception as e:
        logger.error(f"Load test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())