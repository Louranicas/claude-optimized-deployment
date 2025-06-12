#!/usr/bin/env python3
"""
Network Load Generator
======================

Advanced network load generation with HTTP/HTTPS requests, WebSocket connections,
UDP traffic, and realistic network patterns including latency simulation.
"""

import asyncio
import aiohttp
import websockets
import socket
import ssl
import time
import random
import logging
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import numpy as np
from urllib.parse import urljoin
import psutil

logger = logging.getLogger(__name__)

@dataclass
class NetworkLoadConfiguration:
    """Configuration for network load generation"""
    target_urls: List[str] = None  # List of target URLs
    request_types: List[str] = None  # GET, POST, PUT, DELETE, etc.
    concurrent_connections: int = 50  # Number of concurrent connections
    request_rate_per_second: int = 100  # Requests per second
    payload_size_kb: int = 1  # Size of request payload in KB
    connection_timeout: float = 30.0  # Connection timeout in seconds
    read_timeout: float = 30.0  # Read timeout in seconds
    user_agents: List[str] = None  # List of user agent strings
    headers: Dict[str, str] = None  # Custom headers
    websocket_enabled: bool = True  # Enable WebSocket connections
    udp_enabled: bool = True  # Enable UDP traffic
    simulate_bandwidth: bool = True  # Simulate bandwidth limitations
    geographic_distribution: bool = True  # Simulate geographic distribution

@dataclass
class NetworkRequest:
    """Represents a network request"""
    request_id: str
    method: str
    url: str
    headers: Dict[str, str]
    payload: Optional[bytes]
    start_time: float
    end_time: Optional[float] = None
    status_code: Optional[int] = None
    response_size: int = 0
    error_message: Optional[str] = None
    connection_time: float = 0.0
    dns_time: float = 0.0
    ssl_time: float = 0.0
    
    @property
    def total_time_ms(self) -> float:
        """Get total request time in milliseconds"""
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0
    
    @property
    def success(self) -> bool:
        """Check if request was successful"""
        return self.status_code is not None and 200 <= self.status_code < 400

class NetworkLoadGenerator:
    """
    Advanced Network Load Generator
    
    Generates realistic network traffic patterns including HTTP requests,
    WebSocket connections, UDP traffic, and various network scenarios.
    """
    
    def __init__(self, config: Optional[NetworkLoadConfiguration] = None):
        self.config = config or NetworkLoadConfiguration()
        self.running = False
        self.current_load = 0.0
        self.target_load = 0.0
        
        # Initialize default values
        if not self.config.target_urls:
            self.config.target_urls = [
                "http://httpbin.org/",
                "https://httpbin.org/",
                "http://jsonplaceholder.typicode.com/",
                "https://api.github.com/"
            ]
        
        if not self.config.request_types:
            self.config.request_types = ["GET", "POST", "PUT", "DELETE"]
        
        if not self.config.user_agents:
            self.config.user_agents = [
                "LoadTester/1.0 (Advanced Network Load Generator)",
                "Mozilla/5.0 (compatible; LoadGenerator/1.0)",
                "NetworkLoadTest/1.0 (Performance Testing)"
            ]
        
        if not self.config.headers:
            self.config.headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive"
            }
        
        # Network statistics
        self.request_history: List[NetworkRequest] = []
        self.websocket_connections: Dict[str, Any] = {}
        self.udp_sockets: List[socket.socket] = []
        
        # Performance monitoring
        self.performance_samples = []
        self.network_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'average_response_time_ms': 0.0,
            'requests_per_second': 0.0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'active_connections': 0,
            'connection_errors': 0,
            'timeout_errors': 0
        }
        
        # Session management
        self.http_session = None
        self.connector = None
        self.worker_tasks = []
        self.request_queue = asyncio.Queue()
    
    async def execute_pattern(self, pattern):
        """Execute a network load pattern"""
        logger.info(f"Starting network load pattern: {pattern.name}")
        self.running = True
        
        try:
            # Initialize HTTP session
            await self._initialize_session()
            
            # Start worker tasks
            for i in range(self.config.concurrent_connections):
                task = asyncio.create_task(self._http_worker(f"http_worker_{i}"))
                self.worker_tasks.append(task)
            
            # Start WebSocket workers if enabled
            if self.config.websocket_enabled:
                for i in range(min(5, self.config.concurrent_connections // 10)):
                    task = asyncio.create_task(self._websocket_worker(f"ws_worker_{i}"))
                    self.worker_tasks.append(task)
            
            # Start UDP workers if enabled
            if self.config.udp_enabled:
                for i in range(min(3, self.config.concurrent_connections // 20)):
                    task = asyncio.create_task(self._udp_worker(f"udp_worker_{i}"))
                    self.worker_tasks.append(task)
            
            # Start monitoring
            monitor_task = asyncio.create_task(self._monitor_performance())
            
            # Execute pattern points
            for point in pattern.points:
                if not self.running:
                    break
                
                # Update target load
                self.target_load = point.intensity
                
                # Generate requests based on intensity
                await self._generate_requests(point.intensity)
                
                # Wait for next point
                if pattern.points.index(point) < len(pattern.points) - 1:
                    next_point = pattern.points[pattern.points.index(point) + 1]
                    wait_time = next_point.timestamp - point.timestamp
                    await asyncio.sleep(max(1.0, wait_time))
            
            # Stop monitoring
            monitor_task.cancel()
            
            logger.info(f"Completed network load pattern: {pattern.name}")
            
        except Exception as e:
            logger.error(f"Network load pattern execution failed: {e}")
            raise
        finally:
            await self.stop()
    
    async def _initialize_session(self):
        """Initialize HTTP session with connection pooling"""
        connector_args = {
            'limit': self.config.concurrent_connections * 2,
            'limit_per_host': self.config.concurrent_connections,
            'ttl_dns_cache': 300,
            'use_dns_cache': True,
        }
        
        # SSL context for HTTPS
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        connector_args['ssl'] = ssl_context
        
        self.connector = aiohttp.TCPConnector(**connector_args)
        
        timeout = aiohttp.ClientTimeout(
            total=self.config.connection_timeout,
            connect=self.config.connection_timeout / 2,
            sock_read=self.config.read_timeout
        )
        
        self.http_session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=timeout,
            headers=self.config.headers
        )
    
    async def _generate_requests(self, intensity: float):
        """Generate network requests based on intensity"""
        # Calculate requests per second based on intensity
        target_rps = int(self.config.request_rate_per_second * intensity)
        
        if target_rps == 0:
            return
        
        # Generate requests for this interval
        requests_to_generate = max(1, target_rps)
        
        for _ in range(requests_to_generate):
            request = await self._create_network_request()
            if request:
                await self.request_queue.put(request)
    
    async def _create_network_request(self) -> NetworkRequest:
        """Create a network request based on configuration"""
        request_id = f"req_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
        method = random.choice(self.config.request_types)
        url = random.choice(self.config.target_urls)
        
        # Create realistic URL endpoints
        endpoints = self._get_realistic_endpoints(url, method)
        if endpoints:
            url = urljoin(url, random.choice(endpoints))
        
        # Create headers
        headers = self.config.headers.copy()
        headers['User-Agent'] = random.choice(self.config.user_agents)
        
        # Add geographic simulation headers
        if self.config.geographic_distribution:
            headers.update(self._get_geographic_headers())
        
        # Create payload for POST/PUT requests
        payload = None
        if method in ['POST', 'PUT', 'PATCH']:
            payload = self._generate_request_payload()
            headers['Content-Type'] = 'application/json'
            headers['Content-Length'] = str(len(payload))
        
        return NetworkRequest(
            request_id=request_id,
            method=method,
            url=url,
            headers=headers,
            payload=payload,
            start_time=time.time()
        )
    
    def _get_realistic_endpoints(self, base_url: str, method: str) -> List[str]:
        """Get realistic endpoints based on the base URL and method"""
        if "httpbin.org" in base_url:
            return {
                'GET': ['get', 'status/200', 'delay/1', 'json', 'uuid'],
                'POST': ['post', 'status/201'],
                'PUT': ['put'],
                'DELETE': ['delete'],
                'PATCH': ['patch']
            }.get(method, [''])
        
        elif "jsonplaceholder.typicode.com" in base_url:
            return {
                'GET': ['posts', 'users', 'comments', 'albums', 'photos'],
                'POST': ['posts'],
                'PUT': ['posts/1'],
                'DELETE': ['posts/1']
            }.get(method, [''])
        
        elif "api.github.com" in base_url:
            return {
                'GET': ['users', 'repos', 'events', 'zen'],
                'POST': ['user/repos'],
                'PUT': ['user/starred/octocat/Hello-World'],
                'DELETE': ['user/starred/octocat/Hello-World']
            }.get(method, [''])
        
        return ['']
    
    def _get_geographic_headers(self) -> Dict[str, str]:
        """Get headers simulating geographic distribution"""
        locations = [
            {'country': 'US', 'region': 'California', 'city': 'San Francisco'},
            {'country': 'GB', 'region': 'England', 'city': 'London'},
            {'country': 'DE', 'region': 'Bavaria', 'city': 'Munich'},
            {'country': 'JP', 'region': 'Tokyo', 'city': 'Tokyo'},
            {'country': 'AU', 'region': 'New South Wales', 'city': 'Sydney'},
            {'country': 'CA', 'region': 'Ontario', 'city': 'Toronto'},
            {'country': 'BR', 'region': 'Sao Paulo', 'city': 'Sao Paulo'},
            {'country': 'IN', 'region': 'Maharashtra', 'city': 'Mumbai'}
        ]
        
        location = random.choice(locations)
        
        return {
            'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            'X-Country': location['country'],
            'X-Region': location['region'],
            'X-City': location['city'],
            'Accept-Language': self._get_language_for_country(location['country'])
        }
    
    def _get_language_for_country(self, country: str) -> str:
        """Get language header for country"""
        language_map = {
            'US': 'en-US,en;q=0.9',
            'GB': 'en-GB,en;q=0.9',
            'DE': 'de-DE,de;q=0.9,en;q=0.8',
            'JP': 'ja-JP,ja;q=0.9,en;q=0.8',
            'AU': 'en-AU,en;q=0.9',
            'CA': 'en-CA,en;q=0.9,fr-CA;q=0.8',
            'BR': 'pt-BR,pt;q=0.9,en;q=0.8',
            'IN': 'en-IN,en;q=0.9,hi;q=0.8'
        }
        return language_map.get(country, 'en-US,en;q=0.9')
    
    def _generate_request_payload(self) -> bytes:
        """Generate request payload"""
        payload_size_bytes = self.config.payload_size_kb * 1024
        
        # Create realistic JSON payload
        data = {
            'timestamp': int(time.time()),
            'request_id': f"load_test_{random.randint(100000, 999999)}",
            'user_id': random.randint(1, 10000),
            'session_id': f"session_{random.randint(100000, 999999)}",
            'data': {
                'action': random.choice(['create', 'update', 'delete', 'view']),
                'resource': random.choice(['user', 'post', 'comment', 'file']),
                'metadata': {
                    'source': 'load_generator',
                    'version': '1.0.0',
                    'test_run': True
                }
            }
        }
        
        # Add padding to reach desired size
        json_str = json.dumps(data)
        current_size = len(json_str.encode())
        
        if current_size < payload_size_bytes:
            padding_size = payload_size_bytes - current_size - 50  # Leave some room
            if padding_size > 0:
                data['padding'] = 'x' * padding_size
        
        return json.dumps(data).encode()
    
    async def _http_worker(self, worker_id: str):
        """HTTP worker that processes requests from the queue"""
        logger.debug(f"Starting HTTP worker: {worker_id}")
        
        while self.running:
            try:
                # Get request from queue
                request = await asyncio.wait_for(
                    self.request_queue.get(),
                    timeout=1.0
                )
                
                # Execute request
                await self._execute_http_request(request)
                
                # Mark task as done
                self.request_queue.task_done()
                
                # Add small delay to control rate
                if self.config.simulate_bandwidth:
                    await asyncio.sleep(random.uniform(0.01, 0.05))
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"HTTP worker {worker_id} error: {e}")
                await asyncio.sleep(1.0)
        
        logger.debug(f"HTTP worker {worker_id} stopped")
    
    async def _execute_http_request(self, request: NetworkRequest):
        """Execute a single HTTP request"""
        try:
            start_time = time.time()
            
            async with self.http_session.request(
                method=request.method,
                url=request.url,
                headers=request.headers,
                data=request.payload
            ) as response:
                
                # Read response
                response_data = await response.read()
                
                request.end_time = time.time()
                request.status_code = response.status
                request.response_size = len(response_data)
                
                # Update statistics
                self._update_network_stats(request, len(request.payload) if request.payload else 0)
                
        except asyncio.TimeoutError:
            request.end_time = time.time()
            request.error_message = "Timeout"
            self.network_stats['timeout_errors'] += 1
            
        except aiohttp.ClientError as e:
            request.end_time = time.time()
            request.error_message = str(e)
            self.network_stats['connection_errors'] += 1
            
        except Exception as e:
            request.end_time = time.time()
            request.error_message = f"Unexpected error: {e}"
            self.network_stats['failed_requests'] += 1
        
        finally:
            self.request_history.append(request)
            
            # Keep only last 1000 requests
            if len(self.request_history) > 1000:
                self.request_history = self.request_history[-1000:]
    
    async def _websocket_worker(self, worker_id: str):
        """WebSocket worker for persistent connections"""
        logger.debug(f"Starting WebSocket worker: {worker_id}")
        
        while self.running:
            try:
                # Select WebSocket URL
                ws_urls = [url.replace('http', 'ws') + 'ws' for url in self.config.target_urls if url.startswith('http')]
                if not ws_urls:
                    await asyncio.sleep(5.0)
                    continue
                
                ws_url = random.choice(ws_urls)
                
                # Establish WebSocket connection
                async with websockets.connect(ws_url) as websocket:
                    self.websocket_connections[worker_id] = {
                        'url': ws_url,
                        'connected_at': time.time(),
                        'messages_sent': 0,
                        'messages_received': 0
                    }
                    
                    # Send periodic messages
                    for i in range(10):  # Send 10 messages per connection
                        if not self.running:
                            break
                        
                        message = {
                            'worker_id': worker_id,
                            'message_id': i,
                            'timestamp': time.time(),
                            'data': f"WebSocket test message {i}"
                        }
                        
                        await websocket.send(json.dumps(message))
                        self.websocket_connections[worker_id]['messages_sent'] += 1
                        
                        # Wait for response
                        try:
                            response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                            self.websocket_connections[worker_id]['messages_received'] += 1
                        except asyncio.TimeoutError:
                            pass
                        
                        await asyncio.sleep(1.0)
                
                # Clean up connection info
                if worker_id in self.websocket_connections:
                    del self.websocket_connections[worker_id]
                
                await asyncio.sleep(5.0)  # Wait before reconnecting
                
            except Exception as e:
                logger.debug(f"WebSocket worker {worker_id} error: {e}")
                await asyncio.sleep(10.0)
        
        logger.debug(f"WebSocket worker {worker_id} stopped")
    
    async def _udp_worker(self, worker_id: str):
        """UDP worker for UDP traffic generation"""
        logger.debug(f"Starting UDP worker: {worker_id}")
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            self.udp_sockets.append(sock)
            
            # UDP targets (echo servers)
            udp_targets = [
                ('8.8.8.8', 53),  # Google DNS
                ('1.1.1.1', 53),  # Cloudflare DNS
                ('208.67.222.222', 53)  # OpenDNS
            ]
            
            while self.running:
                try:
                    target = random.choice(udp_targets)
                    
                    # Create DNS query packet (simplified)
                    query_data = self._create_dns_query()
                    
                    # Send UDP packet
                    sock.sendto(query_data, target)
                    
                    # Try to receive response
                    try:
                        loop = asyncio.get_event_loop()
                        data = await asyncio.wait_for(
                            loop.sock_recv(sock, 1024),
                            timeout=2.0
                        )
                        self.network_stats['bytes_received'] += len(data)
                    except asyncio.TimeoutError:
                        pass
                    
                    self.network_stats['bytes_sent'] += len(query_data)
                    
                    await asyncio.sleep(random.uniform(1.0, 3.0))
                    
                except Exception as e:
                    logger.debug(f"UDP operation error in {worker_id}: {e}")
                    await asyncio.sleep(5.0)
        
        except Exception as e:
            logger.error(f"UDP worker {worker_id} initialization error: {e}")
        
        finally:
            if sock:
                sock.close()
                if sock in self.udp_sockets:
                    self.udp_sockets.remove(sock)
        
        logger.debug(f"UDP worker {worker_id} stopped")
    
    def _create_dns_query(self) -> bytes:
        """Create a simple DNS query packet"""
        # Simplified DNS query for google.com
        query = bytearray()
        
        # Header
        query.extend([0x12, 0x34])  # Transaction ID
        query.extend([0x01, 0x00])  # Flags
        query.extend([0x00, 0x01])  # Questions
        query.extend([0x00, 0x00])  # Answer RRs
        query.extend([0x00, 0x00])  # Authority RRs
        query.extend([0x00, 0x00])  # Additional RRs
        
        # Question
        query.extend([0x06])  # Length of "google"
        query.extend(b'google')
        query.extend([0x03])  # Length of "com"
        query.extend(b'com')
        query.extend([0x00])  # End of name
        query.extend([0x00, 0x01])  # Type A
        query.extend([0x00, 0x01])  # Class IN
        
        return bytes(query)
    
    def _update_network_stats(self, request: NetworkRequest, bytes_sent: int):
        """Update network statistics"""
        self.network_stats['total_requests'] += 1
        
        if request.success:
            self.network_stats['successful_requests'] += 1
        else:
            self.network_stats['failed_requests'] += 1
        
        self.network_stats['bytes_sent'] += bytes_sent
        self.network_stats['bytes_received'] += request.response_size
        
        # Update average response time
        if request.total_time_ms > 0:
            current_avg = self.network_stats['average_response_time_ms']
            total_requests = self.network_stats['total_requests']
            
            self.network_stats['average_response_time_ms'] = (
                (current_avg * (total_requests - 1) + request.total_time_ms) / total_requests
            )
    
    async def _monitor_performance(self):
        """Monitor network performance"""
        last_stats_time = time.time()
        last_request_count = 0
        
        while self.running:
            try:
                current_time = time.time()
                current_requests = self.network_stats['total_requests']
                
                # Calculate requests per second
                time_diff = current_time - last_stats_time
                if time_diff >= 1.0:
                    request_diff = current_requests - last_request_count
                    self.network_stats['requests_per_second'] = request_diff / time_diff
                    
                    last_stats_time = current_time
                    last_request_count = current_requests
                
                # Collect system network statistics
                network_io = psutil.net_io_counters()
                
                sample = {
                    'timestamp': current_time,
                    'requests_per_second': self.network_stats['requests_per_second'],
                    'average_response_time_ms': self.network_stats['average_response_time_ms'],
                    'active_connections': len(self.worker_tasks),
                    'websocket_connections': len(self.websocket_connections),
                    'queue_size': self.request_queue.qsize(),
                    'total_requests': self.network_stats['total_requests'],
                    'success_rate': (
                        self.network_stats['successful_requests'] / max(1, self.network_stats['total_requests'])
                    ),
                    'bytes_sent': self.network_stats['bytes_sent'],
                    'bytes_received': self.network_stats['bytes_received']
                }
                
                if network_io:
                    sample.update({
                        'system_bytes_sent': network_io.bytes_sent,
                        'system_bytes_recv': network_io.bytes_recv,
                        'system_packets_sent': network_io.packets_sent,
                        'system_packets_recv': network_io.packets_recv
                    })
                
                self.performance_samples.append(sample)
                
                # Keep only last 1000 samples
                if len(self.performance_samples) > 1000:
                    self.performance_samples = self.performance_samples[-1000:]
                
                await asyncio.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Network performance monitoring error: {e}")
                await asyncio.sleep(5.0)
    
    async def stop(self):
        """Stop the network load generator"""
        logger.info("Stopping network load generator")
        self.running = False
        
        # Cancel worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.worker_tasks:
            await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        
        # Close UDP sockets
        for sock in self.udp_sockets:
            sock.close()
        self.udp_sockets.clear()
        
        # Close HTTP session
        if self.http_session:
            await self.http_session.close()
        
        # Close connector
        if self.connector:
            await self.connector.close()
        
        logger.info("Network load generator stopped")
    
    async def reduce_intensity(self, factor: float):
        """Reduce network load intensity by a factor"""
        self.target_load = max(0.0, self.target_load * factor)
        logger.info(f"Reduced network load intensity to {self.target_load:.2f}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the network load generator"""
        return {
            'generator_id': 'network_load_generator',
            'generator_type': 'network',
            'status': 'running' if self.running else 'stopped',
            'current_load': self.current_load,
            'target_load': self.target_load,
            'active_connections': len(self.worker_tasks),
            'websocket_connections': len(self.websocket_connections),
            'udp_sockets': len(self.udp_sockets),
            'queue_size': self.request_queue.qsize() if self.request_queue else 0,
            'target_urls': len(self.config.target_urls),
            'metrics': self.network_stats.copy()
        }
    
    def get_network_statistics(self) -> Dict[str, Any]:
        """Get detailed network statistics"""
        if not self.performance_samples:
            return {}
        
        recent_samples = self.performance_samples[-60:]  # Last minute
        
        rps_values = [s['requests_per_second'] for s in recent_samples if 'requests_per_second' in s]
        response_times = [s['average_response_time_ms'] for s in recent_samples if 'average_response_time_ms' in s]
        success_rates = [s['success_rate'] for s in recent_samples if 'success_rate' in s]
        
        return {
            'requests_per_second': {
                'current': rps_values[-1] if rps_values else 0,
                'average': np.mean(rps_values) if rps_values else 0,
                'max': np.max(rps_values) if rps_values else 0
            },
            'response_time_ms': {
                'current': response_times[-1] if response_times else 0,
                'average': np.mean(response_times) if response_times else 0,
                'max': np.max(response_times) if response_times else 0
            },
            'success_rate': {
                'current': success_rates[-1] if success_rates else 0,
                'average': np.mean(success_rates) if success_rates else 0,
                'min': np.min(success_rates) if success_rates else 0
            },
            'connection_stats': {
                'concurrent_connections': self.config.concurrent_connections,
                'websocket_enabled': self.config.websocket_enabled,
                'udp_enabled': self.config.udp_enabled,
                'geographic_distribution': self.config.geographic_distribution
            },
            'bandwidth_usage': {
                'bytes_sent': self.network_stats['bytes_sent'],
                'bytes_received': self.network_stats['bytes_received'],
                'mb_sent': self.network_stats['bytes_sent'] / (1024 * 1024),
                'mb_received': self.network_stats['bytes_received'] / (1024 * 1024)
            }
        }


# Example usage
async def example_usage():
    """Example usage of NetworkLoadGenerator"""
    config = NetworkLoadConfiguration(
        target_urls=[
            "http://httpbin.org/",
            "https://httpbin.org/"
        ],
        concurrent_connections=20,
        request_rate_per_second=50,
        payload_size_kb=2,
        websocket_enabled=True,
        udp_enabled=True,
        geographic_distribution=True
    )
    
    generator = NetworkLoadGenerator(config)
    
    # Create a simple test pattern
    from patterns.pattern_engine import PatternEngine
    
    pattern_engine = PatternEngine()
    pattern = pattern_engine.generate_pattern("wave", 120, 0.6)
    
    # Execute pattern
    await generator.execute_pattern(pattern)
    
    # Get status and statistics
    status = generator.get_status()
    stats = generator.get_network_statistics()
    
    print(f"Network Generator Status: {status}")
    print(f"Network Statistics: {stats}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(example_usage())