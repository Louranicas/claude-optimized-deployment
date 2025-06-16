# Connection Pool Testing Documentation

## Overview

This document provides a comprehensive testing framework for validating connection pool optimizations, performance characteristics, and resilience capabilities in the Claude Optimized Deployment project.

## Table of Contents

1. [Connection Reuse Validation Tests](#connection-reuse-validation-tests)
2. [Multiplexing Performance Tests](#multiplexing-performance-tests)
3. [Failover and Resilience Testing](#failover-and-resilience-testing)
4. [Load Testing Procedures](#load-testing-procedures)
5. [Connection Leak Detection](#connection-leak-detection)
6. [Integration Test Examples](#integration-test-examples)
7. [Connection Metrics Monitoring](#connection-metrics-monitoring)
8. [Stress Testing Scenarios](#stress-testing-scenarios)
9. [Performance Baseline Tests](#performance-baseline-tests)

## Connection Reuse Validation Tests

### Test Suite: Connection Lifecycle Management

```python
import asyncio
import time
from typing import List, Dict, Any
import psutil
import pytest
from prometheus_client import Counter, Histogram, Gauge

from src.database.connection import get_connection_pool, ConnectionPool
from src.core.connections import ConnectionManager
from src.circle_of_experts.core.connection_pool_integration import (
    ConnectionPoolIntegration,
    PooledConnection
)

class ConnectionReuseValidator:
    """Validates proper connection reuse across multiple requests."""
    
    def __init__(self):
        self.connection_created = Counter(
            'test_connections_created_total',
            'Total number of new connections created'
        )
        self.connection_reused = Counter(
            'test_connections_reused_total',
            'Total number of connection reuses'
        )
        self.connection_ids: Dict[str, int] = {}
    
    async def test_connection_reuse_basic(self):
        """Test basic connection reuse functionality."""
        pool = await get_connection_pool()
        connection_ids = set()
        
        # Perform multiple operations
        for i in range(10):
            async with pool.acquire() as conn:
                conn_id = id(conn)
                connection_ids.add(conn_id)
                
                # Simulate work
                await asyncio.sleep(0.01)
        
        # Verify connection reuse
        assert len(connection_ids) < 10, "Connections should be reused"
        assert len(connection_ids) <= pool.max_size, "Should not exceed pool size"
        
        return {
            "unique_connections": len(connection_ids),
            "total_requests": 10,
            "reuse_ratio": (10 - len(connection_ids)) / 10
        }
    
    async def test_concurrent_connection_reuse(self):
        """Test connection reuse under concurrent load."""
        pool = await get_connection_pool()
        connection_tracking = asyncio.Lock()
        connection_usage = {}
        
        async def use_connection(request_id: int):
            async with pool.acquire() as conn:
                conn_id = id(conn)
                
                async with connection_tracking:
                    if conn_id not in connection_usage:
                        connection_usage[conn_id] = []
                    connection_usage[conn_id].append(request_id)
                
                # Simulate varying workload
                await asyncio.sleep(0.001 * (request_id % 5))
        
        # Run concurrent requests
        tasks = [use_connection(i) for i in range(100)]
        await asyncio.gather(*tasks)
        
        # Analyze results
        max_concurrent = pool.max_size
        actual_connections = len(connection_usage)
        
        assert actual_connections <= max_concurrent, \
            f"Used {actual_connections} connections, expected max {max_concurrent}"
        
        # Calculate reuse statistics
        reuse_counts = [len(usage) for usage in connection_usage.values()]
        avg_reuse = sum(reuse_counts) / len(reuse_counts)
        
        return {
            "total_connections": actual_connections,
            "max_pool_size": max_concurrent,
            "average_reuse_per_connection": avg_reuse,
            "max_reuse": max(reuse_counts),
            "min_reuse": min(reuse_counts)
        }
    
    async def test_connection_lifecycle_tracking(self):
        """Track complete connection lifecycle from creation to destruction."""
        manager = ConnectionManager()
        lifecycle_events = []
        
        # Hook into connection events
        original_create = manager._create_connection
        original_destroy = manager._destroy_connection
        
        async def tracked_create(*args, **kwargs):
            conn = await original_create(*args, **kwargs)
            lifecycle_events.append({
                "event": "created",
                "conn_id": id(conn),
                "timestamp": time.time()
            })
            return conn
        
        async def tracked_destroy(conn):
            lifecycle_events.append({
                "event": "destroyed",
                "conn_id": id(conn),
                "timestamp": time.time()
            })
            await original_destroy(conn)
        
        manager._create_connection = tracked_create
        manager._destroy_connection = tracked_destroy
        
        # Perform operations
        for i in range(20):
            async with manager.get_connection() as conn:
                await asyncio.sleep(0.01)
        
        # Analyze lifecycle
        created = [e for e in lifecycle_events if e["event"] == "created"]
        destroyed = [e for e in lifecycle_events if e["event"] == "destroyed"]
        
        return {
            "connections_created": len(created),
            "connections_destroyed": len(destroyed),
            "active_connections": len(created) - len(destroyed),
            "lifecycle_events": lifecycle_events
        }

## Multiplexing Performance Tests

### Test Suite: HTTP/2 and WebSocket Multiplexing

```python
import aiohttp
import websockets
from concurrent.futures import ThreadPoolExecutor
import numpy as np

class MultiplexingPerformanceTests:
    """Test multiplexing capabilities for various protocols."""
    
    async def test_http2_multiplexing(self):
        """Test HTTP/2 multiplexing performance."""
        url = "https://api.example.com/test"
        
        # Test sequential requests (HTTP/1.1 style)
        sequential_times = []
        async with aiohttp.ClientSession() as session:
            for i in range(50):
                start = time.time()
                async with session.get(url) as response:
                    await response.read()
                sequential_times.append(time.time() - start)
        
        # Test multiplexed requests (HTTP/2)
        multiplexed_times = []
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(force_close=False)
        ) as session:
            tasks = []
            start = time.time()
            
            for i in range(50):
                task = session.get(url)
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks)
            for resp in responses:
                await resp.read()
                resp.close()
            
            total_time = time.time() - start
            multiplexed_times = [total_time / 50] * 50  # Average time per request
        
        # Calculate performance improvement
        seq_avg = np.mean(sequential_times)
        mux_avg = np.mean(multiplexed_times)
        improvement = (seq_avg - mux_avg) / seq_avg * 100
        
        return {
            "sequential_avg_ms": seq_avg * 1000,
            "multiplexed_avg_ms": mux_avg * 1000,
            "performance_improvement": f"{improvement:.2f}%",
            "sequential_p95_ms": np.percentile(sequential_times, 95) * 1000,
            "multiplexed_p95_ms": np.percentile(multiplexed_times, 95) * 1000
        }
    
    async def test_websocket_multiplexing(self):
        """Test WebSocket connection multiplexing."""
        ws_url = "wss://api.example.com/ws"
        message_latencies = []
        
        async def send_receive_message(ws, message_id):
            start = time.time()
            await ws.send(f"message_{message_id}")
            response = await ws.recv()
            latency = time.time() - start
            return latency
        
        # Test with single WebSocket connection (multiplexed)
        async with websockets.connect(ws_url) as ws:
            tasks = []
            for i in range(100):
                task = send_receive_message(ws, i)
                tasks.append(task)
            
            latencies = await asyncio.gather(*tasks)
            message_latencies.extend(latencies)
        
        return {
            "avg_latency_ms": np.mean(message_latencies) * 1000,
            "p50_latency_ms": np.percentile(message_latencies, 50) * 1000,
            "p95_latency_ms": np.percentile(message_latencies, 95) * 1000,
            "p99_latency_ms": np.percentile(message_latencies, 99) * 1000,
            "total_messages": len(message_latencies)
        }
    
    async def test_database_connection_multiplexing(self):
        """Test database connection multiplexing with pipelining."""
        pool = await get_connection_pool()
        
        # Test without pipelining
        no_pipeline_times = []
        async with pool.acquire() as conn:
            for i in range(100):
                start = time.time()
                await conn.execute("SELECT 1")
                no_pipeline_times.append(time.time() - start)
        
        # Test with pipelining
        pipeline_times = []
        async with pool.acquire() as conn:
            # Create pipeline
            pipeline = conn.pipeline()
            
            start = time.time()
            for i in range(100):
                pipeline.execute("SELECT 1")
            
            results = await pipeline.run()
            total_time = time.time() - start
            pipeline_times = [total_time / 100] * 100
        
        return {
            "no_pipeline_avg_ms": np.mean(no_pipeline_times) * 1000,
            "pipeline_avg_ms": np.mean(pipeline_times) * 1000,
            "speedup_factor": np.mean(no_pipeline_times) / np.mean(pipeline_times)
        }

## Failover and Resilience Testing

### Test Suite: Connection Resilience

```python
import random
from unittest.mock import Mock, patch

class FailoverResilienceTests:
    """Test connection failover and resilience capabilities."""
    
    async def test_connection_failover(self):
        """Test automatic failover to backup connections."""
        primary_failures = 0
        failover_count = 0
        
        class FailingConnection:
            def __init__(self, fail_rate=0.5):
                self.fail_rate = fail_rate
                self.is_primary = True
            
            async def execute(self, query):
                if random.random() < self.fail_rate and self.is_primary:
                    nonlocal primary_failures
                    primary_failures += 1
                    raise ConnectionError("Primary connection failed")
                return {"status": "ok", "primary": self.is_primary}
        
        # Setup connection pool with failover
        pool = ConnectionPoolIntegration()
        pool.primary_connections = [FailingConnection(0.8) for _ in range(3)]
        pool.backup_connections = [FailingConnection(0.1) for _ in range(3)]
        
        for conn in pool.backup_connections:
            conn.is_primary = False
        
        # Execute requests with potential failures
        results = []
        for i in range(100):
            try:
                conn = await pool.acquire_with_failover()
                result = await conn.execute("SELECT 1")
                results.append(result)
                
                if not result["primary"]:
                    failover_count += 1
            except Exception as e:
                results.append({"error": str(e)})
        
        success_rate = len([r for r in results if "status" in r]) / len(results)
        
        return {
            "total_requests": len(results),
            "primary_failures": primary_failures,
            "failover_count": failover_count,
            "success_rate": f"{success_rate * 100:.2f}%",
            "error_count": len([r for r in results if "error" in r])
        }
    
    async def test_circuit_breaker_integration(self):
        """Test circuit breaker pattern with connection pools."""
        from src.core.circuit_breaker_config import CircuitBreaker
        
        circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=1.0,
            expected_exception=ConnectionError
        )
        
        failure_count = 0
        circuit_opens = 0
        
        @circuit_breaker
        async def risky_connection_operation():
            nonlocal failure_count
            if failure_count < 10:
                failure_count += 1
                raise ConnectionError("Connection failed")
            return "Success"
        
        results = []
        for i in range(20):
            try:
                result = await risky_connection_operation()
                results.append({"status": "success", "iteration": i})
            except Exception as e:
                if "Circuit breaker is OPEN" in str(e):
                    circuit_opens += 1
                results.append({"status": "failed", "error": str(e), "iteration": i})
            
            await asyncio.sleep(0.1)
        
        return {
            "total_attempts": len(results),
            "failures_before_circuit_open": failure_count,
            "circuit_open_rejections": circuit_opens,
            "eventual_success": any(r["status"] == "success" for r in results)
        }
    
    async def test_connection_retry_logic(self):
        """Test exponential backoff retry logic."""
        from src.core.retry import RetryConfig, exponential_backoff_retry
        
        retry_config = RetryConfig(
            max_attempts=5,
            initial_delay=0.1,
            max_delay=2.0,
            exponential_base=2
        )
        
        attempt_count = 0
        attempt_times = []
        
        @exponential_backoff_retry(retry_config)
        async def flaky_connection():
            nonlocal attempt_count
            attempt_count += 1
            attempt_times.append(time.time())
            
            if attempt_count < 3:
                raise ConnectionError(f"Failed attempt {attempt_count}")
            return "Connected successfully"
        
        start_time = time.time()
        result = await flaky_connection()
        total_time = time.time() - start_time
        
        # Calculate delays between attempts
        delays = []
        for i in range(1, len(attempt_times)):
            delays.append(attempt_times[i] - attempt_times[i-1])
        
        return {
            "total_attempts": attempt_count,
            "successful": result == "Connected successfully",
            "total_time_seconds": total_time,
            "retry_delays": delays,
            "expected_delays": [0.1 * (2 ** i) for i in range(len(delays))]
        }

## Load Testing Procedures

### Test Suite: Connection Pool Load Testing

```python
from locust import HttpUser, task, between
import matplotlib.pyplot as plt
from datetime import datetime

class ConnectionPoolLoadTest:
    """Comprehensive load testing for connection pools."""
    
    async def test_sustained_load(self, duration_seconds=300):
        """Test connection pool under sustained load."""
        pool = await get_connection_pool()
        metrics = {
            "timestamps": [],
            "active_connections": [],
            "waiting_requests": [],
            "response_times": [],
            "errors": []
        }
        
        async def worker(worker_id: int):
            while True:
                try:
                    start = time.time()
                    async with pool.acquire() as conn:
                        await conn.execute("SELECT pg_sleep(0.01)")
                    
                    response_time = time.time() - start
                    metrics["response_times"].append(response_time)
                except Exception as e:
                    metrics["errors"].append({
                        "worker": worker_id,
                        "error": str(e),
                        "timestamp": time.time()
                    })
                
                await asyncio.sleep(0.001)  # Small delay between requests
        
        # Start monitoring
        async def monitor():
            while True:
                metrics["timestamps"].append(time.time())
                metrics["active_connections"].append(pool.active_count)
                metrics["waiting_requests"].append(pool.waiting_count)
                await asyncio.sleep(1)
        
        # Run load test
        workers = [asyncio.create_task(worker(i)) for i in range(100)]
        monitor_task = asyncio.create_task(monitor())
        
        await asyncio.sleep(duration_seconds)
        
        # Cancel all tasks
        for w in workers:
            w.cancel()
        monitor_task.cancel()
        
        # Calculate statistics
        avg_response_time = np.mean(metrics["response_times"])
        p95_response_time = np.percentile(metrics["response_times"], 95)
        p99_response_time = np.percentile(metrics["response_times"], 99)
        error_rate = len(metrics["errors"]) / len(metrics["response_times"])
        
        return {
            "duration_seconds": duration_seconds,
            "total_requests": len(metrics["response_times"]),
            "avg_response_time_ms": avg_response_time * 1000,
            "p95_response_time_ms": p95_response_time * 1000,
            "p99_response_time_ms": p99_response_time * 1000,
            "error_rate": f"{error_rate * 100:.2f}%",
            "max_active_connections": max(metrics["active_connections"]),
            "avg_active_connections": np.mean(metrics["active_connections"]),
            "max_waiting_requests": max(metrics["waiting_requests"])
        }
    
    async def test_spike_load(self):
        """Test connection pool behavior during traffic spikes."""
        pool = await get_connection_pool()
        
        async def generate_spike(num_requests: int):
            tasks = []
            start = time.time()
            
            for i in range(num_requests):
                async def request():
                    async with pool.acquire() as conn:
                        await conn.execute("SELECT 1")
                
                tasks.append(asyncio.create_task(request()))
            
            await asyncio.gather(*tasks, return_exceptions=True)
            return time.time() - start
        
        # Test increasing spike sizes
        spike_results = []
        for spike_size in [10, 50, 100, 200, 500, 1000]:
            duration = await generate_spike(spike_size)
            
            spike_results.append({
                "spike_size": spike_size,
                "duration_seconds": duration,
                "requests_per_second": spike_size / duration
            })
            
            # Allow pool to recover
            await asyncio.sleep(2)
        
        return spike_results
    
    async def test_gradual_rampup(self):
        """Test connection pool with gradually increasing load."""
        pool = await get_connection_pool()
        rampup_duration = 60  # seconds
        max_workers = 200
        
        metrics = []
        active_workers = 0
        stop_flag = False
        
        async def worker():
            while not stop_flag:
                try:
                    start = time.time()
                    async with pool.acquire() as conn:
                        await conn.execute("SELECT 1")
                    latency = time.time() - start
                    
                    metrics.append({
                        "timestamp": time.time(),
                        "latency": latency,
                        "active_workers": active_workers
                    })
                except Exception as e:
                    metrics.append({
                        "timestamp": time.time(),
                        "error": str(e),
                        "active_workers": active_workers
                    })
                
                await asyncio.sleep(0.01)
        
        # Gradual rampup
        workers = []
        start_time = time.time()
        
        while active_workers < max_workers:
            elapsed = time.time() - start_time
            target_workers = int((elapsed / rampup_duration) * max_workers)
            
            while active_workers < target_workers:
                workers.append(asyncio.create_task(worker()))
                active_workers += 1
            
            await asyncio.sleep(0.5)
        
        # Run at max load for additional time
        await asyncio.sleep(30)
        
        # Shutdown
        stop_flag = True
        await asyncio.gather(*workers, return_exceptions=True)
        
        # Analyze rampup behavior
        latencies_by_load = {}
        for metric in metrics:
            if "latency" in metric:
                load = metric["active_workers"]
                if load not in latencies_by_load:
                    latencies_by_load[load] = []
                latencies_by_load[load].append(metric["latency"])
        
        return {
            "max_workers_reached": max_workers,
            "total_requests": len([m for m in metrics if "latency" in m]),
            "total_errors": len([m for m in metrics if "error" in m]),
            "latency_progression": {
                load: {
                    "avg_ms": np.mean(latencies) * 1000,
                    "p95_ms": np.percentile(latencies, 95) * 1000
                }
                for load, latencies in latencies_by_load.items()
                if len(latencies) > 10
            }
        }

## Connection Leak Detection

### Test Suite: Memory and Connection Leak Detection

```python
import gc
import tracemalloc
import objgraph

class ConnectionLeakDetector:
    """Detect and diagnose connection leaks."""
    
    def __init__(self):
        self.baseline_connections = 0
        self.connection_history = []
        tracemalloc.start()
    
    async def test_connection_leak_detection(self):
        """Detect connection leaks over extended operation."""
        pool = await get_connection_pool()
        
        # Establish baseline
        gc.collect()
        self.baseline_connections = len(gc.get_objects())
        baseline_memory = tracemalloc.get_traced_memory()[0]
        
        leak_indicators = []
        
        # Run operations that might leak
        for iteration in range(100):
            # Intentionally problematic patterns
            connections = []
            
            # Pattern 1: Forgotten connections
            for i in range(10):
                conn = await pool.acquire()
                connections.append(conn)
                # Oops, forgot to release some connections
                if i % 3 != 0:
                    await pool.release(conn)
            
            # Pattern 2: Exception during cleanup
            try:
                async with pool.acquire() as conn:
                    if iteration % 10 == 0:
                        raise Exception("Simulated error")
            except:
                pass
            
            # Check for leaks
            gc.collect()
            current_objects = len(gc.get_objects())
            current_memory = tracemalloc.get_traced_memory()[0]
            
            leak_indicators.append({
                "iteration": iteration,
                "object_count": current_objects,
                "memory_bytes": current_memory,
                "unreleased_connections": len(connections)
            })
            
            # Cleanup attempt
            for conn in connections:
                try:
                    await pool.release(conn)
                except:
                    pass
        
        # Analyze leak indicators
        memory_growth = leak_indicators[-1]["memory_bytes"] - baseline_memory
        object_growth = leak_indicators[-1]["object_count"] - self.baseline_connections
        
        # Get memory allocation statistics
        snapshot = tracemalloc.take_snapshot()
        top_stats = snapshot.statistics('lineno')[:10]
        
        return {
            "memory_growth_mb": memory_growth / 1024 / 1024,
            "object_growth": object_growth,
            "potential_leak": memory_growth > 1024 * 1024,  # 1MB threshold
            "top_memory_allocations": [
                {
                    "file": stat.traceback.format()[0],
                    "size_mb": stat.size / 1024 / 1024,
                    "count": stat.count
                }
                for stat in top_stats
            ],
            "leak_progression": leak_indicators
        }
    
    async def test_connection_reference_tracking(self):
        """Track connection references to identify holding patterns."""
        pool = await get_connection_pool()
        
        # Track connection lifecycle
        connection_refs = {}
        
        class TrackedConnection:
            def __init__(self, conn):
                self.conn = conn
                self.id = id(conn)
                self.created_at = time.time()
                self.stack_trace = traceback.extract_stack()
                connection_refs[self.id] = self
            
            def __del__(self):
                if self.id in connection_refs:
                    del connection_refs[self.id]
        
        # Monkey patch pool methods
        original_acquire = pool.acquire
        
        async def tracked_acquire():
            conn = await original_acquire()
            return TrackedConnection(conn)
        
        pool.acquire = tracked_acquire
        
        # Run test workload
        tasks = []
        for i in range(50):
            async def work():
                conn = await pool.acquire()
                await asyncio.sleep(random.uniform(0.1, 0.5))
                # Simulate forgotten release 10% of the time
                if random.random() > 0.1:
                    await pool.release(conn.conn)
            
            tasks.append(asyncio.create_task(work()))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.sleep(1)  # Allow cleanup
        
        # Identify leaked connections
        leaked_connections = []
        for conn_id, tracked in connection_refs.items():
            age = time.time() - tracked.created_at
            if age > 1.0:  # Connection alive for more than 1 second
                leaked_connections.append({
                    "connection_id": conn_id,
                    "age_seconds": age,
                    "stack_trace": "".join(traceback.format_list(tracked.stack_trace[-5:]))
                })
        
        return {
            "total_connections_tracked": len(connection_refs),
            "leaked_connections": len(leaked_connections),
            "leak_details": leaked_connections[:5]  # First 5 leaks
        }
    
    async def test_connection_pool_exhaustion(self):
        """Test behavior when connection pool is exhausted."""
        pool = await get_connection_pool()
        pool.max_size = 10  # Limit pool size
        
        exhaustion_events = []
        
        async def greedy_worker(worker_id: int):
            try:
                # Acquire connection with timeout
                conn = await asyncio.wait_for(
                    pool.acquire(),
                    timeout=5.0
                )
                # Hold connection for too long
                await asyncio.sleep(10)
                await pool.release(conn)
            except asyncio.TimeoutError:
                exhaustion_events.append({
                    "worker_id": worker_id,
                    "event": "timeout",
                    "timestamp": time.time()
                })
            except Exception as e:
                exhaustion_events.append({
                    "worker_id": worker_id,
                    "event": "error",
                    "error": str(e),
                    "timestamp": time.time()
                })
        
        # Launch more workers than pool size
        workers = [
            asyncio.create_task(greedy_worker(i))
            for i in range(20)
        ]
        
        await asyncio.gather(*workers, return_exceptions=True)
        
        return {
            "pool_size": pool.max_size,
            "worker_count": 20,
            "exhaustion_events": len(exhaustion_events),
            "timeout_events": len([e for e in exhaustion_events if e["event"] == "timeout"]),
            "error_events": len([e for e in exhaustion_events if e["event"] == "error"])
        }

## Integration Test Examples

### Complete Integration Test Suite

```python
import pytest
from unittest.mock import AsyncMock, patch
from sqlalchemy import create_engine
import redis
import motor.motor_asyncio

@pytest.mark.integration
class TestConnectionPoolIntegration:
    """Integration tests for connection pool with various backends."""
    
    @pytest.fixture
    async def multi_backend_setup(self):
        """Setup multiple backend connections."""
        # PostgreSQL
        pg_pool = await get_connection_pool(
            dsn="postgresql://localhost/testdb",
            min_size=5,
            max_size=20
        )
        
        # Redis
        redis_pool = await redis.create_redis_pool(
            'redis://localhost',
            minsize=5,
            maxsize=20
        )
        
        # MongoDB
        mongo_client = motor.motor_asyncio.AsyncIOMotorClient(
            'mongodb://localhost:27017',
            maxPoolSize=20
        )
        
        yield {
            "postgres": pg_pool,
            "redis": redis_pool,
            "mongodb": mongo_client
        }
        
        # Cleanup
        await pg_pool.close()
        redis_pool.close()
        await redis_pool.wait_closed()
        mongo_client.close()
    
    async def test_cross_backend_transaction(self, multi_backend_setup):
        """Test coordinated operations across multiple backends."""
        backends = multi_backend_setup
        
        # Start transaction coordination
        transaction_id = str(uuid.uuid4())
        
        try:
            # PostgreSQL operation
            async with backends["postgres"].acquire() as pg_conn:
                await pg_conn.execute(
                    "INSERT INTO transactions (id, status) VALUES ($1, $2)",
                    transaction_id, "pending"
                )
            
            # Redis operation
            async with backends["redis"].get() as redis_conn:
                await redis_conn.setex(
                    f"transaction:{transaction_id}",
                    300,  # 5 minute TTL
                    "processing"
                )
            
            # MongoDB operation
            db = backends["mongodb"].testdb
            await db.transactions.insert_one({
                "_id": transaction_id,
                "status": "completed",
                "timestamp": datetime.utcnow()
            })
            
            # Verify across all backends
            async with backends["postgres"].acquire() as pg_conn:
                result = await pg_conn.fetchrow(
                    "SELECT status FROM transactions WHERE id = $1",
                    transaction_id
                )
                assert result["status"] == "pending"
            
            async with backends["redis"].get() as redis_conn:
                status = await redis_conn.get(f"transaction:{transaction_id}")
                assert status == b"processing"
            
            mongo_result = await db.transactions.find_one({"_id": transaction_id})
            assert mongo_result["status"] == "completed"
            
            return {"transaction_id": transaction_id, "status": "success"}
            
        except Exception as e:
            # Rollback logic
            async with backends["postgres"].acquire() as pg_conn:
                await pg_conn.execute(
                    "DELETE FROM transactions WHERE id = $1",
                    transaction_id
                )
            
            async with backends["redis"].get() as redis_conn:
                await redis_conn.delete(f"transaction:{transaction_id}")
            
            await db.transactions.delete_one({"_id": transaction_id})
            
            raise e
    
    async def test_connection_pool_with_circuit_breaker(self):
        """Test connection pool integrated with circuit breaker."""
        from src.api.circuit_breaker_api import CircuitBreakerAPI
        
        api = CircuitBreakerAPI()
        pool = await get_connection_pool()
        
        # Simulate backend failures
        failure_count = 0
        
        async def flaky_operation():
            nonlocal failure_count
            async with pool.acquire() as conn:
                failure_count += 1
                if failure_count < 5:
                    raise Exception("Backend failure")
                return await conn.fetchval("SELECT 1")
        
        # Wrap with circuit breaker
        protected_operation = api.protect_endpoint(flaky_operation)
        
        results = []
        for i in range(10):
            try:
                result = await protected_operation()
                results.append({"attempt": i, "status": "success", "result": result})
            except Exception as e:
                results.append({"attempt": i, "status": "failed", "error": str(e)})
            
            await asyncio.sleep(0.5)
        
        # Verify circuit breaker behavior
        failures = [r for r in results if r["status"] == "failed"]
        successes = [r for r in results if r["status"] == "success"]
        circuit_open = any("Circuit breaker is OPEN" in r.get("error", "") for r in failures)
        
        return {
            "total_attempts": len(results),
            "failures": len(failures),
            "successes": len(successes),
            "circuit_breaker_triggered": circuit_open,
            "recovery_achieved": len(successes) > 0
        }
    
    async def test_connection_pool_monitoring_integration(self):
        """Test connection pool metrics integration with monitoring."""
        from src.monitoring.metrics import MetricsCollector
        
        metrics = MetricsCollector()
        pool = await get_connection_pool()
        
        # Register pool metrics
        metrics.register_gauge(
            "connection_pool_size",
            "Current size of connection pool",
            lambda: pool.size
        )
        metrics.register_gauge(
            "connection_pool_active",
            "Active connections",
            lambda: pool.active_count
        )
        metrics.register_gauge(
            "connection_pool_idle",
            "Idle connections",
            lambda: pool.idle_count
        )
        
        # Perform operations while collecting metrics
        metric_samples = []
        
        async def collect_metrics():
            while True:
                sample = {
                    "timestamp": time.time(),
                    "pool_size": pool.size,
                    "active": pool.active_count,
                    "idle": pool.idle_count,
                    "waiting": pool.waiting_count
                }
                metric_samples.append(sample)
                await asyncio.sleep(0.1)
        
        # Start metric collection
        collector_task = asyncio.create_task(collect_metrics())
        
        # Generate load
        async def worker():
            for _ in range(20):
                async with pool.acquire() as conn:
                    await conn.execute("SELECT pg_sleep(0.05)")
                await asyncio.sleep(0.01)
        
        workers = [asyncio.create_task(worker()) for _ in range(10)]
        await asyncio.gather(*workers)
        
        # Stop collection
        collector_task.cancel()
        
        # Analyze metrics
        max_active = max(s["active"] for s in metric_samples)
        avg_active = sum(s["active"] for s in metric_samples) / len(metric_samples)
        max_waiting = max(s["waiting"] for s in metric_samples)
        
        return {
            "samples_collected": len(metric_samples),
            "max_active_connections": max_active,
            "avg_active_connections": avg_active,
            "max_waiting_requests": max_waiting,
            "pool_utilization": avg_active / pool.max_size * 100
        }

## Connection Metrics Monitoring

### Key Metrics to Monitor

```python
from prometheus_client import Counter, Histogram, Gauge, Summary
import datadog

class ConnectionMetricsRegistry:
    """Registry of all connection pool metrics to monitor."""
    
    def __init__(self):
        # Connection lifecycle metrics
        self.connections_created = Counter(
            'connection_pool_connections_created_total',
            'Total number of connections created',
            ['pool_name', 'backend_type']
        )
        
        self.connections_closed = Counter(
            'connection_pool_connections_closed_total',
            'Total number of connections closed',
            ['pool_name', 'backend_type', 'reason']
        )
        
        # Pool state metrics
        self.pool_size = Gauge(
            'connection_pool_size',
            'Current size of the connection pool',
            ['pool_name', 'backend_type']
        )
        
        self.active_connections = Gauge(
            'connection_pool_active_connections',
            'Number of active connections',
            ['pool_name', 'backend_type']
        )
        
        self.idle_connections = Gauge(
            'connection_pool_idle_connections',
            'Number of idle connections',
            ['pool_name', 'backend_type']
        )
        
        self.waiting_requests = Gauge(
            'connection_pool_waiting_requests',
            'Number of requests waiting for a connection',
            ['pool_name', 'backend_type']
        )
        
        # Performance metrics
        self.acquisition_time = Histogram(
            'connection_pool_acquisition_duration_seconds',
            'Time to acquire a connection from the pool',
            ['pool_name', 'backend_type'],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
        )
        
        self.connection_usage_time = Histogram(
            'connection_pool_usage_duration_seconds',
            'Time a connection is held by a client',
            ['pool_name', 'backend_type'],
            buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)
        )
        
        # Error metrics
        self.connection_errors = Counter(
            'connection_pool_errors_total',
            'Total number of connection errors',
            ['pool_name', 'backend_type', 'error_type']
        )
        
        self.timeout_errors = Counter(
            'connection_pool_timeout_errors_total',
            'Number of timeout errors when acquiring connections',
            ['pool_name', 'backend_type']
        )
        
        # Health metrics
        self.health_check_duration = Summary(
            'connection_pool_health_check_duration_seconds',
            'Duration of connection health checks',
            ['pool_name', 'backend_type']
        )
        
        self.unhealthy_connections = Gauge(
            'connection_pool_unhealthy_connections',
            'Number of unhealthy connections detected',
            ['pool_name', 'backend_type']
        )
    
    def record_connection_acquired(self, pool_name: str, backend_type: str, duration: float):
        """Record successful connection acquisition."""
        self.acquisition_time.labels(
            pool_name=pool_name,
            backend_type=backend_type
        ).observe(duration)
    
    def record_connection_error(self, pool_name: str, backend_type: str, error_type: str):
        """Record connection error."""
        self.connection_errors.labels(
            pool_name=pool_name,
            backend_type=backend_type,
            error_type=error_type
        ).inc()
    
    def update_pool_stats(self, pool_name: str, backend_type: str, stats: dict):
        """Update pool statistics."""
        self.pool_size.labels(pool_name=pool_name, backend_type=backend_type).set(stats['size'])
        self.active_connections.labels(pool_name=pool_name, backend_type=backend_type).set(stats['active'])
        self.idle_connections.labels(pool_name=pool_name, backend_type=backend_type).set(stats['idle'])
        self.waiting_requests.labels(pool_name=pool_name, backend_type=backend_type).set(stats['waiting'])

# Monitoring Dashboard Configuration
GRAFANA_DASHBOARD_CONFIG = {
    "title": "Connection Pool Monitoring",
    "panels": [
        {
            "title": "Connection Pool Utilization",
            "type": "graph",
            "targets": [
                {
                    "expr": "connection_pool_active_connections / connection_pool_size * 100",
                    "legendFormat": "{{pool_name}} - {{backend_type}}"
                }
            ]
        },
        {
            "title": "Connection Acquisition Time (95th percentile)",
            "type": "graph",
            "targets": [
                {
                    "expr": "histogram_quantile(0.95, connection_pool_acquisition_duration_seconds_bucket)",
                    "legendFormat": "{{pool_name}} - {{backend_type}}"
                }
            ]
        },
        {
            "title": "Waiting Requests",
            "type": "graph",
            "targets": [
                {
                    "expr": "connection_pool_waiting_requests",
                    "legendFormat": "{{pool_name}} - {{backend_type}}"
                }
            ]
        },
        {
            "title": "Connection Errors Rate",
            "type": "graph",
            "targets": [
                {
                    "expr": "rate(connection_pool_errors_total[5m])",
                    "legendFormat": "{{pool_name}} - {{error_type}}"
                }
            ]
        }
    ]
}

## Stress Testing Scenarios

### Comprehensive Stress Test Suite

```python
class ConnectionPoolStressTests:
    """Extreme stress testing scenarios for connection pools."""
    
    async def test_connection_storm(self):
        """Test sudden massive connection requests (thundering herd)."""
        pool = await get_connection_pool()
        
        # Prepare metrics
        storm_metrics = {
            "start_time": time.time(),
            "acquisition_times": [],
            "errors": [],
            "timeouts": []
        }
        
        # Generate connection storm
        async def storm_request(request_id: int):
            try:
                start = time.time()
                async with asyncio.timeout(5.0):
                    async with pool.acquire() as conn:
                        acquisition_time = time.time() - start
                        storm_metrics["acquisition_times"].append(acquisition_time)
                        
                        # Minimal work
                        await conn.execute("SELECT 1")
                        
            except asyncio.TimeoutError:
                storm_metrics["timeouts"].append(request_id)
            except Exception as e:
                storm_metrics["errors"].append({
                    "request_id": request_id,
                    "error": str(e)
                })
        
        # Launch storm (1000 simultaneous requests)
        storm_size = 1000
        tasks = [
            asyncio.create_task(storm_request(i))
            for i in range(storm_size)
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Analyze results
        total_time = time.time() - storm_metrics["start_time"]
        successful = len(storm_metrics["acquisition_times"])
        
        return {
            "storm_size": storm_size,
            "duration_seconds": total_time,
            "successful_acquisitions": successful,
            "timeouts": len(storm_metrics["timeouts"]),
            "errors": len(storm_metrics["errors"]),
            "avg_acquisition_time_ms": np.mean(storm_metrics["acquisition_times"]) * 1000 if successful > 0 else 0,
            "max_acquisition_time_ms": max(storm_metrics["acquisition_times"]) * 1000 if successful > 0 else 0
        }
    
    async def test_memory_pressure(self):
        """Test connection pool under memory pressure."""
        import resource
        
        # Set memory limit (500MB)
        resource.setrlimit(
            resource.RLIMIT_AS,
            (500 * 1024 * 1024, 500 * 1024 * 1024)
        )
        
        pool = await get_connection_pool()
        memory_metrics = []
        
        try:
            # Create connections with large result sets
            tasks = []
            for i in range(50):
                async def memory_intensive_query():
                    async with pool.acquire() as conn:
                        # Query that returns large dataset
                        result = await conn.fetch(
                            "SELECT repeat('x', 1000000) as data FROM generate_series(1, 100)"
                        )
                        # Force materialization
                        data = [row['data'] for row in result]
                        
                        # Record memory usage
                        memory_metrics.append({
                            "timestamp": time.time(),
                            "memory_mb": psutil.Process().memory_info().rss / 1024 / 1024
                        })
                        
                        return len(data)
                
                tasks.append(asyncio.create_task(memory_intensive_query()))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Count successful vs failed operations
            successful = sum(1 for r in results if isinstance(r, int))
            memory_errors = sum(1 for r in results if isinstance(r, MemoryError))
            other_errors = len(results) - successful - memory_errors
            
            return {
                "total_operations": len(results),
                "successful": successful,
                "memory_errors": memory_errors,
                "other_errors": other_errors,
                "peak_memory_mb": max(m["memory_mb"] for m in memory_metrics) if memory_metrics else 0
            }
            
        finally:
            # Reset memory limit
            resource.setrlimit(resource.RLIMIT_AS, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    
    async def test_network_partition(self):
        """Test connection pool behavior during network partitions."""
        import iptc
        
        pool = await get_connection_pool()
        
        # Simulate network partition
        def block_database_traffic():
            # Block traffic to database port
            rule = iptc.Rule()
            rule.protocol = "tcp"
            match = iptc.Match(rule, "tcp")
            match.dport = "5432"
            rule.add_match(match)
            rule.target = iptc.Target(rule, "DROP")
            
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
            chain.insert_rule(rule)
            
            return rule
        
        def restore_network(rule):
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
            chain.delete_rule(rule)
        
        partition_events = []
        
        # Test operations during partition
        async def test_during_partition():
            try:
                async with pool.acquire() as conn:
                    await conn.execute("SELECT 1")
                    return "success"
            except Exception as e:
                return f"failed: {str(e)}"
        
        # Normal operation
        pre_partition = await test_during_partition()
        partition_events.append({"phase": "pre_partition", "result": pre_partition})
        
        # Create partition
        rule = block_database_traffic()
        partition_start = time.time()
        
        # Test during partition
        for i in range(5):
            result = await test_during_partition()
            partition_events.append({
                "phase": "during_partition",
                "attempt": i,
                "result": result,
                "elapsed": time.time() - partition_start
            })
            await asyncio.sleep(1)
        
        # Restore network
        restore_network(rule)
        
        # Test recovery
        recovery_start = time.time()
        for i in range(10):
            result = await test_during_partition()
            partition_events.append({
                "phase": "recovery",
                "attempt": i,
                "result": result,
                "elapsed": time.time() - recovery_start
            })
            
            if "success" in result:
                break
            
            await asyncio.sleep(1)
        
        # Analyze partition behavior
        during_partition = [e for e in partition_events if e.get("phase") == "during_partition"]
        recovery_events = [e for e in partition_events if e.get("phase") == "recovery"]
        
        recovery_time = next(
            (e["elapsed"] for e in recovery_events if "success" in e["result"]),
            None
        )
        
        return {
            "pre_partition_status": pre_partition,
            "failures_during_partition": len(during_partition),
            "recovery_achieved": any("success" in e["result"] for e in recovery_events),
            "recovery_time_seconds": recovery_time,
            "total_downtime_seconds": (recovery_start - partition_start) + (recovery_time or 0)
        }

## Performance Baseline Tests

### Establishing Performance Baselines

```python
class PerformanceBaselineTests:
    """Establish performance baselines for connection pools."""
    
    async def test_baseline_latency(self):
        """Establish baseline latency metrics."""
        pool = await get_connection_pool()
        
        # Test different operation types
        operation_types = {
            "simple_select": "SELECT 1",
            "table_scan": "SELECT * FROM users LIMIT 1000",
            "join_query": """
                SELECT u.*, p.* 
                FROM users u 
                JOIN profiles p ON u.id = p.user_id 
                LIMIT 100
            """,
            "aggregate_query": """
                SELECT COUNT(*), AVG(age), MAX(created_at) 
                FROM users 
                GROUP BY country
            """,
            "write_operation": "INSERT INTO logs (message) VALUES ($1)"
        }
        
        baselines = {}
        
        for op_name, query in operation_types.items():
            latencies = []
            
            # Warm up
            async with pool.acquire() as conn:
                if op_name == "write_operation":
                    await conn.execute(query, "warmup")
                else:
                    await conn.execute(query)
            
            # Measure baseline
            for i in range(100):
                async with pool.acquire() as conn:
                    start = time.time()
                    
                    if op_name == "write_operation":
                        await conn.execute(query, f"test_message_{i}")
                    else:
                        await conn.fetch(query)
                    
                    latencies.append(time.time() - start)
            
            baselines[op_name] = {
                "min_ms": min(latencies) * 1000,
                "avg_ms": np.mean(latencies) * 1000,
                "median_ms": np.median(latencies) * 1000,
                "p95_ms": np.percentile(latencies, 95) * 1000,
                "p99_ms": np.percentile(latencies, 99) * 1000,
                "max_ms": max(latencies) * 1000,
                "std_dev_ms": np.std(latencies) * 1000
            }
        
        return baselines
    
    async def test_baseline_throughput(self):
        """Establish baseline throughput metrics."""
        pool = await get_connection_pool()
        
        throughput_tests = []
        
        # Test different concurrency levels
        for concurrency in [1, 5, 10, 20, 50, 100]:
            operations_completed = 0
            start_time = time.time()
            
            async def worker():
                nonlocal operations_completed
                while time.time() - start_time < 10:  # 10 second test
                    async with pool.acquire() as conn:
                        await conn.execute("SELECT 1")
                        operations_completed += 1
            
            # Run workers
            workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
            await asyncio.gather(*workers)
            
            duration = time.time() - start_time
            throughput = operations_completed / duration
            
            throughput_tests.append({
                "concurrency": concurrency,
                "total_operations": operations_completed,
                "duration_seconds": duration,
                "operations_per_second": throughput
            })
        
        return {
            "throughput_by_concurrency": throughput_tests,
            "optimal_concurrency": max(
                throughput_tests,
                key=lambda x: x["operations_per_second"]
            )["concurrency"]
        }
    
    async def test_baseline_resource_usage(self):
        """Establish baseline resource usage metrics."""
        pool = await get_connection_pool()
        
        # Monitor resource usage during standard workload
        resource_samples = []
        
        async def monitor_resources():
            process = psutil.Process()
            while True:
                resource_samples.append({
                    "timestamp": time.time(),
                    "cpu_percent": process.cpu_percent(),
                    "memory_mb": process.memory_info().rss / 1024 / 1024,
                    "num_threads": process.num_threads(),
                    "num_fds": process.num_fds() if hasattr(process, 'num_fds') else 0,
                    "connections": len(process.connections())
                })
                await asyncio.sleep(0.5)
        
        # Start monitoring
        monitor_task = asyncio.create_task(monitor_resources())
        
        # Run standard workload
        async def standard_workload():
            for _ in range(1000):
                async with pool.acquire() as conn:
                    await conn.execute("SELECT 1")
                await asyncio.sleep(0.01)
        
        await standard_workload()
        
        # Stop monitoring
        monitor_task.cancel()
        
        # Calculate baselines
        return {
            "avg_cpu_percent": np.mean([s["cpu_percent"] for s in resource_samples]),
            "max_cpu_percent": max(s["cpu_percent"] for s in resource_samples),
            "avg_memory_mb": np.mean([s["memory_mb"] for s in resource_samples]),
            "max_memory_mb": max(s["memory_mb"] for s in resource_samples),
            "avg_connections": np.mean([s["connections"] for s in resource_samples]),
            "max_connections": max(s["connections"] for s in resource_samples),
            "samples_collected": len(resource_samples)
        }

## Test Execution Framework

### Main Test Runner

```python
async def run_connection_pool_tests():
    """Execute all connection pool tests and generate report."""
    
    test_results = {
        "execution_time": datetime.now().isoformat(),
        "test_suites": {}
    }
    
    # Initialize test classes
    reuse_validator = ConnectionReuseValidator()
    multiplex_tests = MultiplexingPerformanceTests()
    failover_tests = FailoverResilienceTests()
    load_tests = ConnectionPoolLoadTest()
    leak_detector = ConnectionLeakDetector()
    stress_tests = ConnectionPoolStressTests()
    baseline_tests = PerformanceBaselineTests()
    
    # Run test suites
    print("Running Connection Reuse Validation Tests...")
    test_results["test_suites"]["connection_reuse"] = {
        "basic_reuse": await reuse_validator.test_connection_reuse_basic(),
        "concurrent_reuse": await reuse_validator.test_concurrent_connection_reuse(),
        "lifecycle_tracking": await reuse_validator.test_connection_lifecycle_tracking()
    }
    
    print("Running Multiplexing Performance Tests...")
    test_results["test_suites"]["multiplexing"] = {
        "http2": await multiplex_tests.test_http2_multiplexing(),
        "websocket": await multiplex_tests.test_websocket_multiplexing(),
        "database": await multiplex_tests.test_database_connection_multiplexing()
    }
    
    print("Running Failover and Resilience Tests...")
    test_results["test_suites"]["failover"] = {
        "connection_failover": await failover_tests.test_connection_failover(),
        "circuit_breaker": await failover_tests.test_circuit_breaker_integration(),
        "retry_logic": await failover_tests.test_connection_retry_logic()
    }
    
    print("Running Load Tests...")
    test_results["test_suites"]["load_testing"] = {
        "sustained_load": await load_tests.test_sustained_load(60),  # 1 minute test
        "spike_load": await load_tests.test_spike_load(),
        "gradual_rampup": await load_tests.test_gradual_rampup()
    }
    
    print("Running Connection Leak Detection...")
    test_results["test_suites"]["leak_detection"] = {
        "leak_detection": await leak_detector.test_connection_leak_detection(),
        "reference_tracking": await leak_detector.test_connection_reference_tracking(),
        "pool_exhaustion": await leak_detector.test_connection_pool_exhaustion()
    }
    
    print("Running Stress Tests...")
    test_results["test_suites"]["stress_testing"] = {
        "connection_storm": await stress_tests.test_connection_storm(),
        "memory_pressure": await stress_tests.test_memory_pressure(),
        # "network_partition": await stress_tests.test_network_partition()  # Requires root
    }
    
    print("Establishing Performance Baselines...")
    test_results["test_suites"]["baselines"] = {
        "latency": await baseline_tests.test_baseline_latency(),
        "throughput": await baseline_tests.test_baseline_throughput(),
        "resource_usage": await baseline_tests.test_baseline_resource_usage()
    }
    
    # Generate report
    report_path = f"connection_pool_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, 'w') as f:
        json.dump(test_results, f, indent=2, default=str)
    
    print(f"\nTest execution complete. Report saved to: {report_path}")
    
    # Generate summary
    print("\n=== Test Summary ===")
    for suite_name, suite_results in test_results["test_suites"].items():
        print(f"\n{suite_name.upper()}:")
        for test_name, test_result in suite_results.items():
            if isinstance(test_result, dict):
                print(f"  {test_name}: {test_result.get('status', 'completed')}")
    
    return test_results

if __name__ == "__main__":
    asyncio.run(run_connection_pool_tests())
```

## Conclusion

This comprehensive testing framework provides:

1. **Connection reuse validation** - Ensures efficient connection recycling
2. **Multiplexing performance tests** - Validates protocol-level optimizations
3. **Failover and resilience testing** - Confirms system stability
4. **Load testing procedures** - Establishes capacity limits
5. **Connection leak detection** - Prevents resource exhaustion
6. **Integration test examples** - Real-world scenario validation
7. **Connection metrics monitoring** - Continuous performance tracking
8. **Stress testing scenarios** - Extreme condition validation
9. **Performance baseline tests** - Establishes expected performance

Regular execution of these tests ensures the connection pool optimization remains effective and identifies potential issues before they impact production systems.