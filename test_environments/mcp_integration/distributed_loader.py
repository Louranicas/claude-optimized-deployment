"""
Distributed Load Generator - MCP-enabled load generation nodes.
Generates distributed load across multiple test nodes with MCP coordination.
"""

import asyncio
import json
import logging
import random
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import aiohttp
import websockets
from concurrent.futures import ThreadPoolExecutor
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LoadPattern(Enum):
    """Load generation patterns"""
    CONSTANT = "constant"
    RAMP_UP = "ramp_up"
    SPIKE = "spike"
    WAVE = "wave"
    RANDOM = "random"
    BURST = "burst"


class LoadPhase(Enum):
    """Load generation phases"""
    WARMUP = "warmup"
    STEADY = "steady"
    PEAK = "peak"
    COOLDOWN = "cooldown"


@dataclass
class LoadTarget:
    """Load generation target configuration"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = None
    payload: Optional[str] = None
    expected_response_time: float = 1.0
    timeout: float = 30.0


@dataclass
class LoadProfile:
    """Load generation profile"""
    name: str
    pattern: LoadPattern
    duration: timedelta
    base_rps: float  # requests per second
    peak_rps: float
    ramp_duration: timedelta
    concurrent_users: int
    targets: List[LoadTarget]


@dataclass
class LoadMetrics:
    """Load generation metrics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    p95_response_time: float = 0.0
    p99_response_time: float = 0.0
    throughput: float = 0.0
    error_rate: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@dataclass
class LoadTask:
    """Individual load generation task"""
    task_id: str
    profile: LoadProfile
    assigned_node: str
    status: str = "pending"
    metrics: LoadMetrics = None
    created_at: datetime = None


class DistributedLoadGenerator:
    """MCP-enabled distributed load generator"""
    
    def __init__(self, node_id: str, orchestrator_host: str = "localhost", 
                 orchestrator_port: int = 8081):
        self.node_id = node_id
        self.orchestrator_host = orchestrator_host
        self.orchestrator_port = orchestrator_port
        self.capabilities = [
            "http_load_generation",
            "websocket_load_generation", 
            "database_load_generation",
            "file_io_load_generation",
            "cpu_stress_testing",
            "memory_stress_testing"
        ]
        
        # Load generation state
        self.active_tasks: Dict[str, LoadTask] = {}
        self.task_executors: Dict[str, asyncio.Task] = {}
        self.metrics_history: List[LoadMetrics] = []
        self.current_load = 0.0
        self.max_capacity = 1000  # max concurrent requests
        
        # Connection management
        self.orchestrator_connection: Optional[websockets.WebSocketClientProtocol] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.executor = ThreadPoolExecutor(max_workers=50)
        self.running = False
        
        # MCP server configuration
        self.mcp_servers = {
            "load_generator": {
                "name": "Distributed Load Generator",
                "version": "1.0.0",
                "description": "Generates distributed load across multiple targets",
                "methods": [
                    "start_load_test",
                    "stop_load_test", 
                    "get_metrics",
                    "configure_profile",
                    "get_capabilities"
                ]
            }
        }

    async def start(self):
        """Start the load generator node"""
        self.running = True
        logger.info(f"Starting distributed load generator node {self.node_id}")
        
        # Initialize HTTP session
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=200, limit_per_host=50)
        )
        
        # Connect to orchestrator
        await self.connect_to_orchestrator()
        
        # Start background tasks
        heartbeat_task = asyncio.create_task(self.send_heartbeat())
        metrics_task = asyncio.create_task(self.collect_metrics())
        
        try:
            await asyncio.gather(
                self.listen_for_commands(),
                heartbeat_task,
                metrics_task
            )
        except Exception as e:
            logger.error(f"Error in load generator: {e}")
        finally:
            await self.cleanup()

    async def connect_to_orchestrator(self):
        """Connect to the orchestrator via WebSocket"""
        try:
            uri = f"ws://{self.orchestrator_host}:{self.orchestrator_port}"
            self.orchestrator_connection = await websockets.connect(uri)
            
            # Register with orchestrator
            registration = {
                "type": "register",
                "node_info": {
                    "node_id": self.node_id,
                    "host": "localhost",  # This would be dynamically determined
                    "port": 8090,  # Load generator API port
                    "capabilities": self.capabilities,
                    "max_capacity": self.max_capacity,
                    "mcp_servers": list(self.mcp_servers.keys())
                }
            }
            
            await self.orchestrator_connection.send(json.dumps(registration))
            logger.info(f"Connected to orchestrator and registered node {self.node_id}")
            
        except Exception as e:
            logger.error(f"Failed to connect to orchestrator: {e}")
            raise

    async def listen_for_commands(self):
        """Listen for commands from orchestrator"""
        try:
            async for message in self.orchestrator_connection:
                data = json.loads(message)
                await self.handle_command(data)
                
        except websockets.exceptions.ConnectionClosed:
            logger.warning("Connection to orchestrator closed")
        except Exception as e:
            logger.error(f"Error listening for commands: {e}")

    async def handle_command(self, command: Dict[str, Any]):
        """Handle command from orchestrator"""
        command_type = command.get("type")
        
        if command_type == "execute_task":
            await self.execute_load_task(command)
        elif command_type == "stop_task":
            await self.stop_load_task(command.get("task_id"))
        elif command_type == "get_status":
            await self.send_status_update()
        elif command_type == "registration_confirmed":
            logger.info("Registration confirmed by orchestrator")
        else:
            logger.warning(f"Unknown command type: {command_type}")

    async def execute_load_task(self, command: Dict[str, Any]):
        """Execute a load generation task"""
        try:
            task_id = command["task_id"]
            task_type = command["task_type"]
            parameters = command["parameters"]
            
            # Create load profile from parameters
            profile = self.create_load_profile(parameters)
            
            # Create task
            task = LoadTask(
                task_id=task_id,
                profile=profile,
                assigned_node=self.node_id,
                status="running",
                metrics=LoadMetrics(),
                created_at=datetime.now()
            )
            
            self.active_tasks[task_id] = task
            
            # Start task execution
            executor_task = asyncio.create_task(self.run_load_test(task))
            self.task_executors[task_id] = executor_task
            
            logger.info(f"Started load task {task_id} with profile {profile.name}")
            
            # Send confirmation to orchestrator
            await self.send_task_update(task_id, "started", {"message": "Task started successfully"})
            
        except Exception as e:
            logger.error(f"Failed to execute load task: {e}")
            await self.send_task_update(task_id, "failed", {"error": str(e)})

    def create_load_profile(self, parameters: Dict[str, Any]) -> LoadProfile:
        """Create load profile from parameters"""
        targets = []
        for target_config in parameters.get("targets", []):
            target = LoadTarget(
                url=target_config["url"],
                method=target_config.get("method", "GET"),
                headers=target_config.get("headers", {}),
                payload=target_config.get("payload"),
                expected_response_time=target_config.get("expected_response_time", 1.0),
                timeout=target_config.get("timeout", 30.0)
            )
            targets.append(target)
        
        return LoadProfile(
            name=parameters.get("name", "default_profile"),
            pattern=LoadPattern(parameters.get("pattern", "constant")),
            duration=timedelta(seconds=parameters.get("duration", 60)),
            base_rps=parameters.get("base_rps", 10.0),
            peak_rps=parameters.get("peak_rps", 50.0),
            ramp_duration=timedelta(seconds=parameters.get("ramp_duration", 30)),
            concurrent_users=parameters.get("concurrent_users", 10),
            targets=targets
        )

    async def run_load_test(self, task: LoadTask):
        """Run a load test based on the profile"""
        try:
            profile = task.profile
            metrics = task.metrics
            metrics.start_time = datetime.now()
            
            logger.info(f"Running load test {task.task_id} for {profile.duration}")
            
            # Choose load generation strategy based on pattern
            if profile.pattern == LoadPattern.CONSTANT:
                await self.run_constant_load(task)
            elif profile.pattern == LoadPattern.RAMP_UP:
                await self.run_ramp_up_load(task)
            elif profile.pattern == LoadPattern.SPIKE:
                await self.run_spike_load(task)
            elif profile.pattern == LoadPattern.WAVE:
                await self.run_wave_load(task)
            elif profile.pattern == LoadPattern.RANDOM:
                await self.run_random_load(task)
            elif profile.pattern == LoadPattern.BURST:
                await self.run_burst_load(task)
            
            metrics.end_time = datetime.now()
            task.status = "completed"
            
            # Calculate final metrics
            self.calculate_final_metrics(metrics)
            
            # Send results to orchestrator
            await self.send_task_result(task.task_id, {
                "success": True,
                "metrics": asdict(metrics),
                "profile": asdict(profile)
            })
            
            logger.info(f"Load test {task.task_id} completed successfully")
            
        except Exception as e:
            task.status = "failed"
            logger.error(f"Load test {task.task_id} failed: {e}")
            
            await self.send_task_result(task.task_id, {
                "success": False,
                "error": str(e),
                "metrics": asdict(task.metrics) if task.metrics else None
            })
        
        finally:
            # Cleanup
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]
            if task.task_id in self.task_executors:
                del self.task_executors[task.task_id]

    async def run_constant_load(self, task: LoadTask):
        """Run constant load pattern"""
        profile = task.profile
        end_time = datetime.now() + profile.duration
        
        # Create worker tasks for concurrent load
        workers = []
        for i in range(profile.concurrent_users):
            worker = asyncio.create_task(
                self.load_worker(task, profile.base_rps / profile.concurrent_users, end_time)
            )
            workers.append(worker)
        
        await asyncio.gather(*workers, return_exceptions=True)

    async def run_ramp_up_load(self, task: LoadTask):
        """Run ramp-up load pattern"""
        profile = task.profile
        end_time = datetime.now() + profile.duration
        ramp_end = datetime.now() + profile.ramp_duration
        
        workers = []
        for i in range(profile.concurrent_users):
            worker = asyncio.create_task(
                self.ramp_up_worker(task, profile.base_rps, profile.peak_rps, 
                                  profile.concurrent_users, ramp_end, end_time)
            )
            workers.append(worker)
        
        await asyncio.gather(*workers, return_exceptions=True)

    async def run_spike_load(self, task: LoadTask):
        """Run spike load pattern"""
        profile = task.profile
        total_duration = profile.duration.total_seconds()
        spike_start = total_duration * 0.3  # Spike at 30% of duration
        spike_duration = total_duration * 0.1  # Spike lasts 10% of duration
        
        end_time = datetime.now() + profile.duration
        
        workers = []
        for i in range(profile.concurrent_users):
            worker = asyncio.create_task(
                self.spike_worker(task, profile.base_rps, profile.peak_rps,
                                spike_start, spike_duration, end_time)
            )
            workers.append(worker)
        
        await asyncio.gather(*workers, return_exceptions=True)

    async def run_wave_load(self, task: LoadTask):
        """Run wave load pattern"""
        profile = task.profile
        end_time = datetime.now() + profile.duration
        
        workers = []
        for i in range(profile.concurrent_users):
            worker = asyncio.create_task(
                self.wave_worker(task, profile.base_rps, profile.peak_rps, end_time)
            )
            workers.append(worker)
        
        await asyncio.gather(*workers, return_exceptions=True)

    async def run_random_load(self, task: LoadTask):
        """Run random load pattern"""
        profile = task.profile
        end_time = datetime.now() + profile.duration
        
        workers = []
        for i in range(profile.concurrent_users):
            worker = asyncio.create_task(
                self.random_worker(task, profile.base_rps, profile.peak_rps, end_time)
            )
            workers.append(worker)
        
        await asyncio.gather(*workers, return_exceptions=True)

    async def run_burst_load(self, task: LoadTask):
        """Run burst load pattern"""
        profile = task.profile
        end_time = datetime.now() + profile.duration
        burst_interval = 10.0  # Burst every 10 seconds
        burst_duration = 2.0   # Burst lasts 2 seconds
        
        workers = []
        for i in range(profile.concurrent_users):
            worker = asyncio.create_task(
                self.burst_worker(task, profile.base_rps, profile.peak_rps,
                                burst_interval, burst_duration, end_time)
            )
            workers.append(worker)
        
        await asyncio.gather(*workers, return_exceptions=True)

    async def load_worker(self, task: LoadTask, rps: float, end_time: datetime):
        """Basic load worker for constant load"""
        interval = 1.0 / rps if rps > 0 else 1.0
        
        while datetime.now() < end_time and task.status == "running":
            try:
                # Select random target
                target = random.choice(task.profile.targets)
                
                # Make request
                start_time = time.time()
                success = await self.make_request(target)
                response_time = time.time() - start_time
                
                # Update metrics
                self.update_metrics(task.metrics, success, response_time)
                
                # Wait for next request
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in load worker: {e}")
                self.update_metrics(task.metrics, False, 0.0)

    async def ramp_up_worker(self, task: LoadTask, base_rps: float, peak_rps: float,
                            concurrent_users: int, ramp_end: datetime, end_time: datetime):
        """Ramp-up load worker"""
        start_time = datetime.now()
        
        while datetime.now() < end_time and task.status == "running":
            current_time = datetime.now()
            
            # Calculate current RPS based on ramp-up
            if current_time < ramp_end:
                # Ramping up
                ramp_progress = (current_time - start_time).total_seconds() / (ramp_end - start_time).total_seconds()
                current_rps = base_rps + (peak_rps - base_rps) * ramp_progress
            else:
                # At peak
                current_rps = peak_rps
            
            interval = concurrent_users / current_rps if current_rps > 0 else 1.0
            
            try:
                target = random.choice(task.profile.targets)
                start_req_time = time.time()
                success = await self.make_request(target)
                response_time = time.time() - start_req_time
                
                self.update_metrics(task.metrics, success, response_time)
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in ramp-up worker: {e}")
                self.update_metrics(task.metrics, False, 0.0)

    async def spike_worker(self, task: LoadTask, base_rps: float, peak_rps: float,
                          spike_start: float, spike_duration: float, end_time: datetime):
        """Spike load worker"""
        start_time = datetime.now()
        
        while datetime.now() < end_time and task.status == "running":
            current_time = datetime.now()
            elapsed = (current_time - start_time).total_seconds()
            
            # Determine if we're in spike period
            if spike_start <= elapsed <= spike_start + spike_duration:
                current_rps = peak_rps
            else:
                current_rps = base_rps
            
            interval = 1.0 / current_rps if current_rps > 0 else 1.0
            
            try:
                target = random.choice(task.profile.targets)
                start_req_time = time.time()
                success = await self.make_request(target)
                response_time = time.time() - start_req_time
                
                self.update_metrics(task.metrics, success, response_time)
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in spike worker: {e}")
                self.update_metrics(task.metrics, False, 0.0)

    async def wave_worker(self, task: LoadTask, base_rps: float, peak_rps: float, end_time: datetime):
        """Wave load worker"""
        start_time = datetime.now()
        wave_period = 60.0  # 60 second wave period
        
        while datetime.now() < end_time and task.status == "running":
            current_time = datetime.now()
            elapsed = (current_time - start_time).total_seconds()
            
            # Calculate sine wave RPS
            wave_factor = (np.sin(2 * np.pi * elapsed / wave_period) + 1) / 2
            current_rps = base_rps + (peak_rps - base_rps) * wave_factor
            
            interval = 1.0 / current_rps if current_rps > 0 else 1.0
            
            try:
                target = random.choice(task.profile.targets)
                start_req_time = time.time()
                success = await self.make_request(target)
                response_time = time.time() - start_req_time
                
                self.update_metrics(task.metrics, success, response_time)
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in wave worker: {e}")
                self.update_metrics(task.metrics, False, 0.0)

    async def random_worker(self, task: LoadTask, base_rps: float, peak_rps: float, end_time: datetime):
        """Random load worker"""
        while datetime.now() < end_time and task.status == "running":
            # Random RPS between base and peak
            current_rps = random.uniform(base_rps, peak_rps)
            interval = 1.0 / current_rps if current_rps > 0 else 1.0
            
            try:
                target = random.choice(task.profile.targets)
                start_req_time = time.time()
                success = await self.make_request(target)
                response_time = time.time() - start_req_time
                
                self.update_metrics(task.metrics, success, response_time)
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in random worker: {e}")
                self.update_metrics(task.metrics, False, 0.0)

    async def burst_worker(self, task: LoadTask, base_rps: float, peak_rps: float,
                          burst_interval: float, burst_duration: float, end_time: datetime):
        """Burst load worker"""
        start_time = datetime.now()
        
        while datetime.now() < end_time and task.status == "running":
            current_time = datetime.now()
            elapsed = (current_time - start_time).total_seconds()
            
            # Check if we're in a burst period
            cycle_position = elapsed % burst_interval
            if cycle_position < burst_duration:
                current_rps = peak_rps
            else:
                current_rps = base_rps
            
            interval = 1.0 / current_rps if current_rps > 0 else 1.0
            
            try:
                target = random.choice(task.profile.targets)
                start_req_time = time.time()
                success = await self.make_request(target)
                response_time = time.time() - start_req_time
                
                self.update_metrics(task.metrics, success, response_time)
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in burst worker: {e}")
                self.update_metrics(task.metrics, False, 0.0)

    async def make_request(self, target: LoadTarget) -> bool:
        """Make HTTP request to target"""
        try:
            timeout = aiohttp.ClientTimeout(total=target.timeout)
            
            if target.method.upper() == "GET":
                async with self.session.get(
                    target.url, 
                    headers=target.headers,
                    timeout=timeout
                ) as response:
                    await response.read()
                    return 200 <= response.status < 400
                    
            elif target.method.upper() == "POST":
                async with self.session.post(
                    target.url,
                    headers=target.headers,
                    data=target.payload,
                    timeout=timeout
                ) as response:
                    await response.read()
                    return 200 <= response.status < 400
                    
            elif target.method.upper() == "PUT":
                async with self.session.put(
                    target.url,
                    headers=target.headers,
                    data=target.payload,
                    timeout=timeout
                ) as response:
                    await response.read()
                    return 200 <= response.status < 400
                    
            elif target.method.upper() == "DELETE":
                async with self.session.delete(
                    target.url,
                    headers=target.headers,
                    timeout=timeout
                ) as response:
                    await response.read()
                    return 200 <= response.status < 400
                    
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return False
        
        return False

    def update_metrics(self, metrics: LoadMetrics, success: bool, response_time: float):
        """Update load metrics"""
        metrics.total_requests += 1
        
        if success:
            metrics.successful_requests += 1
        else:
            metrics.failed_requests += 1
        
        # Update response time metrics
        if response_time > 0:
            metrics.min_response_time = min(metrics.min_response_time, response_time)
            metrics.max_response_time = max(metrics.max_response_time, response_time)
            
            # Simple moving average for response time
            if metrics.average_response_time == 0:
                metrics.average_response_time = response_time
            else:
                metrics.average_response_time = (
                    (metrics.average_response_time * (metrics.total_requests - 1) + response_time) /
                    metrics.total_requests
                )
        
        # Calculate error rate
        metrics.error_rate = metrics.failed_requests / metrics.total_requests if metrics.total_requests > 0 else 0.0

    def calculate_final_metrics(self, metrics: LoadMetrics):
        """Calculate final metrics after test completion"""
        if metrics.start_time and metrics.end_time:
            duration = (metrics.end_time - metrics.start_time).total_seconds()
            if duration > 0:
                metrics.throughput = metrics.successful_requests / duration

    async def stop_load_task(self, task_id: str):
        """Stop a running load task"""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            task.status = "cancelled"
            
            if task_id in self.task_executors:
                executor_task = self.task_executors[task_id]
                executor_task.cancel()
            
            logger.info(f"Stopped load task {task_id}")

    async def send_heartbeat(self):
        """Send heartbeat to orchestrator"""
        while self.running:
            try:
                if self.orchestrator_connection:
                    heartbeat = {
                        "type": "heartbeat",
                        "node_id": self.node_id,
                        "metrics": {
                            "current_load": self.current_load,
                            "active_tasks": len(self.active_tasks),
                            "total_capacity": self.max_capacity
                        }
                    }
                    
                    await self.orchestrator_connection.send(json.dumps(heartbeat))
                
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
                
            except Exception as e:
                logger.error(f"Error sending heartbeat: {e}")

    async def collect_metrics(self):
        """Collect and store metrics"""
        while self.running:
            try:
                # Calculate current load
                self.current_load = sum(
                    task.profile.concurrent_users for task in self.active_tasks.values()
                    if task.status == "running"
                )
                
                await asyncio.sleep(10)  # Collect metrics every 10 seconds
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")

    async def send_task_update(self, task_id: str, status: str, data: Dict[str, Any]):
        """Send task status update to orchestrator"""
        if self.orchestrator_connection:
            update = {
                "type": "task_update",
                "task_id": task_id,
                "status": status,
                "data": data,
                "timestamp": datetime.now().isoformat()
            }
            
            await self.orchestrator_connection.send(json.dumps(update))

    async def send_task_result(self, task_id: str, result: Dict[str, Any]):
        """Send task result to orchestrator"""
        if self.orchestrator_connection:
            message = {
                "type": "task_result",
                "task_id": task_id,
                "result": result,
                "timestamp": datetime.now().isoformat()
            }
            
            await self.orchestrator_connection.send(json.dumps(message))

    async def send_status_update(self):
        """Send status update to orchestrator"""
        if self.orchestrator_connection:
            status = {
                "type": "status_update",
                "node_id": self.node_id,
                "status": "available" if len(self.active_tasks) < self.max_capacity else "busy",
                "metrics": {
                    "active_tasks": len(self.active_tasks),
                    "current_load": self.current_load,
                    "capacity_utilization": self.current_load / self.max_capacity
                }
            }
            
            await self.orchestrator_connection.send(json.dumps(status))

    async def cleanup(self):
        """Cleanup resources"""
        self.running = False
        
        # Cancel all active tasks
        for task_id in list(self.task_executors.keys()):
            await self.stop_load_task(task_id)
        
        # Close HTTP session
        if self.session:
            await self.session.close()
        
        # Close orchestrator connection
        if self.orchestrator_connection:
            await self.orchestrator_connection.close()
        
        logger.info("Load generator cleanup completed")


if __name__ == "__main__":
    async def main():
        import sys
        node_id = sys.argv[1] if len(sys.argv) > 1 else f"load_generator_{uuid.uuid4().hex[:8]}"
        
        generator = DistributedLoadGenerator(node_id)
        try:
            await generator.start()
        except KeyboardInterrupt:
            await generator.cleanup()
    
    asyncio.run(main())