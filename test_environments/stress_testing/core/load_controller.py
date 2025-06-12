"""
Load Controller for Stress Testing Framework

Manages multiple types of system load generation including CPU, memory, I/O, and network.
Provides precise control over load intensity and coordination between load types.
"""

import asyncio
import threading
import multiprocessing
import time
import psutil
import logging
import random
import tempfile
import os
import socket
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import numpy as np


@dataclass
class LoadConfiguration:
    """Configuration for different load types"""
    cpu_cores: int
    memory_limit_gb: float
    io_operations_per_second: int
    network_bandwidth_mbps: float
    precision_interval_ms: int = 100
    ramp_smoothness: float = 0.1


class CPULoadGenerator:
    """CPU load generation with precise control"""
    
    def __init__(self, cores: int = None):
        self.cores = cores or multiprocessing.cpu_count()
        self.target_load = 0.0
        self.workers: List[multiprocessing.Process] = []
        self.control_queues: List[multiprocessing.Queue] = []
        self.status_queue = multiprocessing.Queue()
        self.running = False
        self.logger = logging.getLogger(f"{__name__}.CPULoadGenerator")
    
    async def initialize(self):
        """Initialize CPU load generation workers"""
        self.logger.info(f"Initializing CPU load generator with {self.cores} cores")
        
        for i in range(self.cores):
            control_queue = multiprocessing.Queue()
            worker = multiprocessing.Process(
                target=self._cpu_worker,
                args=(i, control_queue, self.status_queue)
            )
            
            self.workers.append(worker)
            self.control_queues.append(control_queue)
            worker.start()
        
        self.running = True
        self.logger.info("CPU load generator initialized")
    
    async def set_load(self, load_percent: float):
        """Set CPU load percentage (0-100)"""
        if not self.running:
            return
        
        self.target_load = max(0.0, min(100.0, load_percent))
        
        # Distribute load across cores
        per_core_load = self.target_load / self.cores
        
        for queue in self.control_queues:
            try:
                queue.put(('set_load', per_core_load), block=False)
            except:
                pass  # Queue might be full, skip this update
    
    async def stop(self):
        """Stop CPU load generation"""
        if not self.running:
            return
        
        self.logger.info("Stopping CPU load generator")
        
        # Signal all workers to stop
        for queue in self.control_queues:
            try:
                queue.put(('stop', None), block=False)
            except:
                pass
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5.0)
            if worker.is_alive():
                worker.terminate()
        
        self.running = False
        self.workers.clear()
        self.control_queues.clear()
    
    @staticmethod
    def _cpu_worker(core_id: int, control_queue: multiprocessing.Queue, 
                   status_queue: multiprocessing.Queue):
        """Worker process for generating CPU load on specific core"""
        try:
            # Set CPU affinity
            psutil.Process().cpu_affinity([core_id])
        except:
            pass  # CPU affinity might not be supported
        
        target_load = 0.0
        running = True
        
        while running:
            start_time = time.time()
            
            # Check for control messages
            try:
                while not control_queue.empty():
                    command, value = control_queue.get_nowait()
                    if command == 'set_load':
                        target_load = value
                    elif command == 'stop':
                        running = False
                        break
            except:
                pass
            
            if not running:
                break
            
            # Generate load for calculated time slice
            if target_load > 0:
                work_time = target_load / 100.0 * 0.1  # 100ms interval
                work_end = start_time + work_time
                
                # Busy wait to consume CPU
                while time.time() < work_end:
                    # Simple computation to use CPU
                    _ = sum(i * i for i in range(1000))
            
            # Sleep for remainder of interval
            elapsed = time.time() - start_time
            sleep_time = max(0, 0.1 - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)


class MemoryLoadGenerator:
    """Memory load generation with controlled allocation"""
    
    def __init__(self, limit_gb: float = None):
        self.limit_gb = limit_gb or (psutil.virtual_memory().total / (1024**3) * 0.8)
        self.target_load = 0.0
        self.allocated_memory: List[bytearray] = []
        self.running = False
        self.control_task: Optional[asyncio.Task] = None
        self.logger = logging.getLogger(f"{__name__}.MemoryLoadGenerator")
    
    async def initialize(self):
        """Initialize memory load generator"""
        self.logger.info(f"Initializing memory load generator with {self.limit_gb:.1f}GB limit")
        self.running = True
        self.control_task = asyncio.create_task(self._memory_controller())
    
    async def set_load(self, load_percent: float):
        """Set memory load percentage (0-100)"""
        if not self.running:
            return
        
        self.target_load = max(0.0, min(100.0, load_percent))
    
    async def stop(self):
        """Stop memory load generation"""
        if not self.running:
            return
        
        self.logger.info("Stopping memory load generator")
        self.running = False
        
        if self.control_task:
            self.control_task.cancel()
            try:
                await self.control_task
            except asyncio.CancelledError:
                pass
        
        # Free all allocated memory
        self.allocated_memory.clear()
    
    async def _memory_controller(self):
        """Control memory allocation based on target load"""
        while self.running:
            try:
                current_usage = len(self.allocated_memory) * 10  # 10MB chunks
                target_usage = (self.target_load / 100.0) * self.limit_gb * 1024  # MB
                
                if current_usage < target_usage:
                    # Allocate more memory
                    chunks_needed = int((target_usage - current_usage) / 10)
                    for _ in range(min(chunks_needed, 100)):  # Limit allocation rate
                        try:
                            chunk = bytearray(10 * 1024 * 1024)  # 10MB chunk
                            # Touch memory to ensure allocation
                            for i in range(0, len(chunk), 4096):
                                chunk[i] = 1
                            self.allocated_memory.append(chunk)
                        except MemoryError:
                            break
                
                elif current_usage > target_usage:
                    # Free memory
                    chunks_to_free = int((current_usage - target_usage) / 10)
                    for _ in range(min(chunks_to_free, len(self.allocated_memory))):
                        if self.allocated_memory:
                            self.allocated_memory.pop()
                
                await asyncio.sleep(0.5)  # 500ms update interval
                
            except Exception as e:
                self.logger.error(f"Memory controller error: {e}")
                await asyncio.sleep(1.0)


class IOLoadGenerator:
    """I/O load generation with controlled disk operations"""
    
    def __init__(self, operations_per_second: int = 1000):
        self.operations_per_second = operations_per_second
        self.target_load = 0.0
        self.running = False
        self.temp_dir = None
        self.io_tasks: List[asyncio.Task] = []
        self.logger = logging.getLogger(f"{__name__}.IOLoadGenerator")
    
    async def initialize(self):
        """Initialize I/O load generator"""
        self.logger.info(f"Initializing I/O load generator with {self.operations_per_second} ops/sec limit")
        
        # Create temporary directory for I/O operations
        self.temp_dir = tempfile.mkdtemp(prefix="stress_io_")
        self.running = True
        
        # Start I/O workers
        for i in range(4):  # 4 concurrent I/O workers
            task = asyncio.create_task(self._io_worker(i))
            self.io_tasks.append(task)
    
    async def set_load(self, load_percent: float):
        """Set I/O load percentage (0-100)"""
        if not self.running:
            return
        
        self.target_load = max(0.0, min(100.0, load_percent))
    
    async def stop(self):
        """Stop I/O load generation"""
        if not self.running:
            return
        
        self.logger.info("Stopping I/O load generator")
        self.running = False
        
        # Cancel all I/O tasks
        for task in self.io_tasks:
            task.cancel()
        
        await asyncio.gather(*self.io_tasks, return_exceptions=True)
        self.io_tasks.clear()
        
        # Cleanup temporary files
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                import shutil
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                self.logger.warning(f"Failed to cleanup temp directory: {e}")
    
    async def _io_worker(self, worker_id: int):
        """Worker for generating I/O load"""
        file_path = os.path.join(self.temp_dir, f"stress_file_{worker_id}.tmp")
        
        while self.running:
            try:
                if self.target_load > 0:
                    # Calculate operations per second for this worker
                    ops_per_sec = (self.target_load / 100.0) * self.operations_per_second / 4
                    
                    if ops_per_sec > 0:
                        interval = 1.0 / ops_per_sec
                        
                        # Perform I/O operation
                        await self._perform_io_operation(file_path)
                        
                        # Wait for next operation
                        await asyncio.sleep(max(0.001, interval))
                    else:
                        await asyncio.sleep(0.1)
                else:
                    await asyncio.sleep(0.1)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"I/O worker {worker_id} error: {e}")
                await asyncio.sleep(1.0)
    
    async def _perform_io_operation(self, file_path: str):
        """Perform a single I/O operation"""
        operation = random.choice(['write', 'read', 'seek'])
        
        try:
            if operation == 'write':
                with open(file_path, 'ab') as f:
                    data = random.randbytes(4096)  # 4KB write
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
            
            elif operation == 'read':
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    with open(file_path, 'rb') as f:
                        f.read(4096)
            
            elif operation == 'seek':
                if os.path.exists(file_path) and os.path.getsize(file_path) > 4096:
                    with open(file_path, 'rb') as f:
                        size = os.path.getsize(file_path)
                        f.seek(random.randint(0, size - 4096))
                        f.read(4096)
                        
        except Exception:
            pass  # Ignore individual operation failures


class NetworkLoadGenerator:
    """Network load generation with controlled bandwidth usage"""
    
    def __init__(self, bandwidth_mbps: float = 100.0):
        self.bandwidth_mbps = bandwidth_mbps
        self.target_load = 0.0
        self.running = False
        self.network_tasks: List[asyncio.Task] = []
        self.server_socket: Optional[socket.socket] = None
        self.server_port = 0
        self.logger = logging.getLogger(f"{__name__}.NetworkLoadGenerator")
    
    async def initialize(self):
        """Initialize network load generator"""
        self.logger.info(f"Initializing network load generator with {self.bandwidth_mbps}Mbps limit")
        
        # Start local server for network traffic
        await self._start_local_server()
        self.running = True
        
        # Start network workers
        for i in range(2):  # 2 concurrent network workers
            task = asyncio.create_task(self._network_worker(i))
            self.network_tasks.append(task)
    
    async def set_load(self, load_percent: float):
        """Set network load percentage (0-100)"""
        if not self.running:
            return
        
        self.target_load = max(0.0, min(100.0, load_percent))
    
    async def stop(self):
        """Stop network load generation"""
        if not self.running:
            return
        
        self.logger.info("Stopping network load generator")
        self.running = False
        
        # Cancel all network tasks
        for task in self.network_tasks:
            task.cancel()
        
        await asyncio.gather(*self.network_tasks, return_exceptions=True)
        self.network_tasks.clear()
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
    
    async def _start_local_server(self):
        """Start local server for network traffic generation"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('127.0.0.1', 0))
        self.server_port = self.server_socket.getsockname()[1]
        self.server_socket.listen(10)
        self.server_socket.setblocking(False)
        
        # Start server task
        server_task = asyncio.create_task(self._server_handler())
        self.network_tasks.append(server_task)
    
    async def _server_handler(self):
        """Handle incoming connections for network load testing"""
        while self.running:
            try:
                conn, addr = await asyncio.get_event_loop().sock_accept(self.server_socket)
                asyncio.create_task(self._handle_connection(conn))
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.1)
    
    async def _handle_connection(self, conn: socket.socket):
        """Handle individual connection for data transfer"""
        try:
            conn.setblocking(False)
            while self.running:
                try:
                    data = await asyncio.get_event_loop().sock_recv(conn, 8192)
                    if not data:
                        break
                    # Echo data back
                    await asyncio.get_event_loop().sock_sendall(conn, data)
                except Exception:
                    break
        finally:
            conn.close()
    
    async def _network_worker(self, worker_id: int):
        """Worker for generating network traffic"""
        while self.running:
            try:
                if self.target_load > 0:
                    # Calculate target bandwidth for this worker
                    target_bps = (self.target_load / 100.0) * self.bandwidth_mbps * 1024 * 1024 / 8 / 2
                    
                    if target_bps > 0:
                        # Connect and transfer data
                        await self._generate_network_traffic(target_bps)
                    else:
                        await asyncio.sleep(0.1)
                else:
                    await asyncio.sleep(0.1)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Network worker {worker_id} error: {e}")
                await asyncio.sleep(1.0)
    
    async def _generate_network_traffic(self, target_bps: float):
        """Generate network traffic at target bandwidth"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            
            await asyncio.get_event_loop().sock_connect(sock, ('127.0.0.1', self.server_port))
            
            # Calculate chunk size and interval
            chunk_size = min(8192, int(target_bps / 10))  # 10 chunks per second
            interval = chunk_size / target_bps if target_bps > 0 else 0.1
            
            data = b'x' * chunk_size
            
            for _ in range(10):  # Send 10 chunks
                if not self.running:
                    break
                
                start_time = time.time()
                await asyncio.get_event_loop().sock_sendall(sock, data)
                
                # Receive echo
                received = await asyncio.get_event_loop().sock_recv(sock, chunk_size)
                
                # Control bandwidth
                elapsed = time.time() - start_time
                sleep_time = max(0, interval - elapsed)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
            
            sock.close()
            
        except Exception:
            pass  # Ignore connection failures


class LoadController:
    """
    Main load controller coordinating all load generation types
    """
    
    def __init__(self, config: Optional[LoadConfiguration] = None):
        self.config = config or LoadConfiguration(
            cpu_cores=multiprocessing.cpu_count(),
            memory_limit_gb=psutil.virtual_memory().total / (1024**3) * 0.8,
            io_operations_per_second=1000,
            network_bandwidth_mbps=100.0
        )
        
        self.logger = logging.getLogger(__name__)
        
        # Load generators
        self.cpu_generator = CPULoadGenerator(self.config.cpu_cores)
        self.memory_generator = MemoryLoadGenerator(self.config.memory_limit_gb)
        self.io_generator = IOLoadGenerator(self.config.io_operations_per_second)
        self.network_generator = NetworkLoadGenerator(self.config.network_bandwidth_mbps)
        
        # Status tracking
        self.initialized = False
        self.current_loads = {
            'cpu': 0.0,
            'memory': 0.0,
            'io': 0.0,
            'network': 0.0
        }
    
    async def initialize(self):
        """Initialize all load generators"""
        if self.initialized:
            return
        
        self.logger.info("Initializing load controller")
        
        try:
            await self.cpu_generator.initialize()
            await self.memory_generator.initialize()
            await self.io_generator.initialize()
            await self.network_generator.initialize()
            
            self.initialized = True
            self.logger.info("Load controller initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Load controller initialization failed: {e}")
            await self.cleanup()
            raise
    
    async def set_cpu_load(self, load_percent: float):
        """Set CPU load percentage"""
        if not self.initialized:
            return
        
        await self.cpu_generator.set_load(load_percent)
        self.current_loads['cpu'] = load_percent
    
    async def set_memory_load(self, load_percent: float):
        """Set memory load percentage"""
        if not self.initialized:
            return
        
        await self.memory_generator.set_load(load_percent)
        self.current_loads['memory'] = load_percent
    
    async def set_io_load(self, load_percent: float):
        """Set I/O load percentage"""
        if not self.initialized:
            return
        
        await self.io_generator.set_load(load_percent)
        self.current_loads['io'] = load_percent
    
    async def set_network_load(self, load_percent: float):
        """Set network load percentage"""
        if not self.initialized:
            return
        
        await self.network_generator.set_load(load_percent)
        self.current_loads['network'] = load_percent
    
    async def set_all_loads(self, cpu: float = 0, memory: float = 0, 
                           io: float = 0, network: float = 0):
        """Set all load types simultaneously"""
        if not self.initialized:
            return
        
        await asyncio.gather(
            self.set_cpu_load(cpu),
            self.set_memory_load(memory),
            self.set_io_load(io),
            self.set_network_load(network)
        )
    
    async def stop_all_loads(self):
        """Stop all load generation"""
        if not self.initialized:
            return
        
        self.logger.info("Stopping all loads")
        await self.set_all_loads(0, 0, 0, 0)
        await asyncio.sleep(1.0)  # Allow loads to settle
    
    async def emergency_stop(self):
        """Emergency stop of all load generation"""
        self.logger.warning("Emergency stop of all loads")
        
        try:
            # Parallel shutdown of all generators
            await asyncio.gather(
                self.cpu_generator.stop(),
                self.memory_generator.stop(),
                self.io_generator.stop(),
                self.network_generator.stop(),
                return_exceptions=True
            )
        except Exception as e:
            self.logger.error(f"Emergency stop failed: {e}")
        
        self.initialized = False
        self.current_loads = {k: 0.0 for k in self.current_loads}
    
    async def graceful_shutdown(self):
        """Graceful shutdown with load ramp-down"""
        if not self.initialized:
            return
        
        self.logger.info("Performing graceful shutdown")
        
        # Gradual ramp-down
        for load_level in [75, 50, 25, 10, 0]:
            await self.set_all_loads(load_level, load_level, load_level, load_level)
            await asyncio.sleep(2.0)
        
        await self.cleanup()
    
    async def cleanup(self):
        """Cleanup all resources"""
        await asyncio.gather(
            self.cpu_generator.stop(),
            self.memory_generator.stop(),
            self.io_generator.stop(),
            self.network_generator.stop(),
            return_exceptions=True
        )
        
        self.initialized = False
        self.current_loads = {k: 0.0 for k in self.current_loads}
    
    def get_current_loads(self) -> Dict[str, float]:
        """Get current load levels for all types"""
        return self.current_loads.copy()
    
    def is_initialized(self) -> bool:
        """Check if controller is initialized"""
        return self.initialized