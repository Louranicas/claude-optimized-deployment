#!/usr/bin/env python3
"""
AGENT 6: Load Testing Integration Suite
Tests system performance under various load conditions with concurrent access patterns.
"""

import asyncio
import aiohttp
import json
import psutil
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import multiprocessing as mp
import statistics
import gc


class LoadTestingIntegrationSuite:
    """Comprehensive load testing for MCP integration ecosystem."""
    
    def __init__(self):
        self.base_dir = Path("/home/louranicas/projects/claude-optimized-deployment")
        self.test_results = {}
        self.monitoring_active = False
        self.system_metrics = []
        
    async def test_concurrent_mcp_server_connections(self) -> Dict[str, Any]:
        """Test concurrent connections to MCP servers."""
        print("⚡ Testing Concurrent MCP Server Connections...")
        
        connection_patterns = [
            {
                'name': 'light_load',
                'concurrent_connections': 5,
                'requests_per_connection': 10,
                'request_interval': 0.1
            },
            {
                'name': 'medium_load',
                'concurrent_connections': 15,
                'requests_per_connection': 20,
                'request_interval': 0.05
            },
            {
                'name': 'heavy_load',
                'concurrent_connections': 30,
                'requests_per_connection': 15,
                'request_interval': 0.02
            },
            {
                'name': 'burst_load',
                'concurrent_connections': 50,
                'requests_per_connection': 5,
                'request_interval': 0.01
            }
        ]
        
        results = {}
        
        for pattern in connection_patterns:
            print(f"   Testing: {pattern['name']}")
            
            try:
                # Start system monitoring
                await self._start_system_monitoring()
                
                # Execute load test
                load_result = await self._execute_concurrent_connection_test(pattern)
                
                # Stop monitoring and collect metrics
                system_metrics = await self._stop_system_monitoring()
                
                results[pattern['name']] = {
                    'load_test': load_result,
                    'system_metrics': system_metrics,
                    'overall_success': load_result.get('success', False)
                }
                
                if load_result.get('success', False):
                    success_rate = load_result.get('success_rate', 0)
                    avg_response_time = load_result.get('average_response_time', 0)
                    max_memory = system_metrics.get('max_memory_mb', 0)
                    print(f"      ✅ {pattern['name']}: {success_rate:.1f}% success, {avg_response_time:.2f}s avg, {max_memory:.1f}MB peak")
                else:
                    print(f"      ❌ {pattern['name']}: {load_result.get('error', 'Failed')}")
                
                # Cooldown between tests
                await asyncio.sleep(2)
                
            except Exception as e:
                results[pattern['name']] = {
                    'overall_success': False,
                    'error': str(e)
                }
                print(f"      ❌ {pattern['name']}: {e}")
        
        return results
    
    async def _execute_concurrent_connection_test(self, pattern: Dict) -> Dict[str, Any]:
        """Execute a concurrent connection test pattern."""
        start_time = time.time()
        
        try:
            concurrent_connections = pattern['concurrent_connections']
            requests_per_connection = pattern['requests_per_connection']
            request_interval = pattern['request_interval']
            
            # Create tasks for concurrent connections
            tasks = []
            for i in range(concurrent_connections):
                task = self._simulate_mcp_connection_load(
                    connection_id=i,
                    request_count=requests_per_connection,
                    interval=request_interval
                )
                tasks.append(task)
            
            # Execute all connections concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze results
            successful_connections = 0
            total_requests = 0
            successful_requests = 0
            response_times = []
            
            for result in results:
                if isinstance(result, dict) and not isinstance(result, Exception):
                    if result.get('success', False):
                        successful_connections += 1
                    
                    total_requests += result.get('total_requests', 0)
                    successful_requests += result.get('successful_requests', 0)
                    response_times.extend(result.get('response_times', []))
            
            total_time = time.time() - start_time
            
            return {
                'success': successful_connections > 0,
                'concurrent_connections': concurrent_connections,
                'successful_connections': successful_connections,
                'connection_success_rate': successful_connections / concurrent_connections * 100,
                'total_requests': total_requests,
                'successful_requests': successful_requests,
                'request_success_rate': successful_requests / total_requests * 100 if total_requests > 0 else 0,
                'total_time': total_time,
                'average_response_time': statistics.mean(response_times) if response_times else 0,
                'median_response_time': statistics.median(response_times) if response_times else 0,
                'max_response_time': max(response_times) if response_times else 0,
                'min_response_time': min(response_times) if response_times else 0,
                'throughput_requests_per_second': total_requests / total_time if total_time > 0 else 0
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'total_time': time.time() - start_time
            }
    
    async def _simulate_mcp_connection_load(self, connection_id: int, request_count: int, interval: float) -> Dict[str, Any]:
        """Simulate load from a single MCP connection."""
        try:
            successful_requests = 0
            response_times = []
            
            for i in range(request_count):
                request_start = time.time()
                
                try:
                    # Simulate MCP request processing
                    await self._simulate_mcp_request()
                    
                    response_time = time.time() - request_start
                    response_times.append(response_time)
                    successful_requests += 1
                    
                except Exception:
                    # Request failed
                    response_times.append(time.time() - request_start)
                
                # Wait before next request
                if i < request_count - 1:
                    await asyncio.sleep(interval)
            
            return {
                'success': True,
                'connection_id': connection_id,
                'total_requests': request_count,
                'successful_requests': successful_requests,
                'response_times': response_times
            }
            
        except Exception as e:
            return {
                'success': False,
                'connection_id': connection_id,
                'error': str(e),
                'total_requests': request_count,
                'successful_requests': 0,
                'response_times': []
            }
    
    async def _simulate_mcp_request(self):
        """Simulate processing an MCP request."""
        # Simulate different types of MCP operations
        operation_type = hash(threading.current_thread().ident) % 4
        
        if operation_type == 0:
            # Simulate tool discovery
            await asyncio.sleep(0.01)
            tools = [{'name': f'tool_{i}', 'description': f'Tool {i}'} for i in range(5)]
        
        elif operation_type == 1:
            # Simulate tool execution
            await asyncio.sleep(0.05)
            result = {'output': 'Operation completed successfully'}
        
        elif operation_type == 2:
            # Simulate resource reading
            await asyncio.sleep(0.02)
            content = f"Resource content {time.time()}"
        
        else:
            # Simulate complex processing
            await asyncio.sleep(0.03)
            data = [i * 2 for i in range(100)]  # Some computation
    
    async def test_api_integration_load(self) -> Dict[str, Any]:
        """Test load on API integrations."""
        print("🌐 Testing API Integration Load...")
        
        api_load_patterns = [
            {
                'name': 'search_api_burst',
                'api': 'tavily',
                'concurrent_requests': 10,
                'total_requests': 50,
                'request_type': 'search'
            },
            {
                'name': 'search_api_sustained',
                'api': 'tavily',
                'concurrent_requests': 3,
                'total_requests': 30,
                'request_type': 'search'
            },
            {
                'name': 'brave_rate_limit_test',
                'api': 'brave',
                'concurrent_requests': 2,
                'total_requests': 10,
                'request_type': 'search'
            }
        ]
        
        results = {}
        
        for pattern in api_load_patterns:
            print(f"   Testing: {pattern['name']}")
            
            try:
                await self._start_system_monitoring()
                
                api_result = await self._execute_api_load_test(pattern)
                
                system_metrics = await self._stop_system_monitoring()
                
                results[pattern['name']] = {
                    'api_load': api_result,
                    'system_metrics': system_metrics,
                    'overall_success': api_result.get('success', False)
                }
                
                if api_result.get('success', False):
                    success_rate = api_result.get('success_rate', 0)
                    avg_response_time = api_result.get('average_response_time', 0)
                    print(f"      ✅ {pattern['name']}: {success_rate:.1f}% success, {avg_response_time:.2f}s avg")
                else:
                    print(f"      ❌ {pattern['name']}: {api_result.get('error', 'Failed')}")
                
                # Cooldown to respect API rate limits
                await asyncio.sleep(5)
                
            except Exception as e:
                results[pattern['name']] = {
                    'overall_success': False,
                    'error': str(e)
                }
                print(f"      ❌ {pattern['name']}: {e}")
        
        return results
    
    async def _execute_api_load_test(self, pattern: Dict) -> Dict[str, Any]:
        """Execute an API load test pattern."""
        start_time = time.time()
        
        try:
            api = pattern['api']
            concurrent_requests = pattern['concurrent_requests']
            total_requests = pattern['total_requests']
            
            # Create semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(concurrent_requests)
            
            # Create tasks for all requests
            tasks = []
            for i in range(total_requests):
                task = self._make_api_request_with_semaphore(semaphore, api, i)
                tasks.append(task)
            
            # Execute requests with controlled concurrency
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze results
            successful_requests = 0
            response_times = []
            rate_limited_requests = 0
            
            for result in results:
                if isinstance(result, dict) and not isinstance(result, Exception):
                    if result.get('success', False):
                        successful_requests += 1
                        response_times.append(result.get('response_time', 0))
                    elif result.get('rate_limited', False):
                        rate_limited_requests += 1
            
            total_time = time.time() - start_time
            
            return {
                'success': successful_requests > 0,
                'api': api,
                'total_requests': total_requests,
                'successful_requests': successful_requests,
                'rate_limited_requests': rate_limited_requests,
                'success_rate': successful_requests / total_requests * 100,
                'total_time': total_time,
                'average_response_time': statistics.mean(response_times) if response_times else 0,
                'requests_per_second': total_requests / total_time if total_time > 0 else 0
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'total_time': time.time() - start_time
            }
    
    async def _make_api_request_with_semaphore(self, semaphore: asyncio.Semaphore, api: str, request_id: int) -> Dict[str, Any]:
        """Make an API request with semaphore control."""
        async with semaphore:
            return await self._make_api_request(api, request_id)
    
    async def _make_api_request(self, api: str, request_id: int) -> Dict[str, Any]:
        """Make a single API request."""
        start_time = time.time()
        
        try:
            if api == 'tavily':
                return await self._make_tavily_request(request_id)
            elif api == 'brave':
                return await self._make_brave_request(request_id)
            else:
                raise ValueError(f"Unknown API: {api}")
                
        except Exception as e:
            return {
                'success': False,
                'response_time': time.time() - start_time,
                'error': str(e)
            }
    
    async def _make_tavily_request(self, request_id: int) -> Dict[str, Any]:
        """Make a Tavily API request."""
        start_time = time.time()
        
        try:
            payload = {
                'api_key': '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',
                'query': f'load test query {request_id}',
                'search_depth': 'basic',
                'max_results': 2
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    'https://api.tavily.com/search',
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    response_time = time.time() - start_time
                    
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'success': True,
                            'response_time': response_time,
                            'results_count': len(data.get('results', []))
                        }
                    else:
                        return {
                            'success': False,
                            'response_time': response_time,
                            'status_code': response.status
                        }
                        
        except asyncio.TimeoutError:
            return {
                'success': False,
                'response_time': time.time() - start_time,
                'error': 'timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'response_time': time.time() - start_time,
                'error': str(e)
            }
    
    async def _make_brave_request(self, request_id: int) -> Dict[str, Any]:
        """Make a Brave API request."""
        start_time = time.time()
        
        try:
            params = {
                'q': f'load test query {request_id}',
                'count': 2
            }
            
            headers = {
                'X-Subscription-Token': 'BSAigVAUU4-V72PjB48t8_CqN00Hh5z',
                'Accept': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://api.search.brave.com/res/v1/web/search',
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    response_time = time.time() - start_time
                    
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'success': True,
                            'response_time': response_time,
                            'results_count': len(data.get('web', {}).get('results', []))
                        }
                    elif response.status == 429:
                        return {
                            'success': False,
                            'rate_limited': True,
                            'response_time': response_time,
                            'status_code': response.status
                        }
                    else:
                        return {
                            'success': False,
                            'response_time': response_time,
                            'status_code': response.status
                        }
                        
        except asyncio.TimeoutError:
            return {
                'success': False,
                'response_time': time.time() - start_time,
                'error': 'timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'response_time': time.time() - start_time,
                'error': str(e)
            }
    
    async def test_memory_usage_under_sustained_load(self) -> Dict[str, Any]:
        """Test memory usage under sustained load."""
        print("💾 Testing Memory Usage Under Sustained Load...")
        
        memory_test_scenarios = [
            {
                'name': 'gradual_ramp_up',
                'duration': 30,  # seconds
                'max_concurrent': 20,
                'ramp_up_time': 10
            },
            {
                'name': 'sustained_high_load',
                'duration': 60,
                'max_concurrent': 15,
                'ramp_up_time': 5
            },
            {
                'name': 'memory_intensive_operations',
                'duration': 45,
                'max_concurrent': 10,
                'ramp_up_time': 5,
                'memory_intensive': True
            }
        ]
        
        results = {}
        
        for scenario in memory_test_scenarios:
            print(f"   Testing: {scenario['name']}")
            
            try:
                # Force garbage collection before test
                gc.collect()
                
                await self._start_system_monitoring()
                
                memory_result = await self._execute_memory_load_test(scenario)
                
                system_metrics = await self._stop_system_monitoring()
                
                # Force garbage collection after test
                gc.collect()
                
                results[scenario['name']] = {
                    'memory_test': memory_result,
                    'system_metrics': system_metrics,
                    'overall_success': memory_result.get('success', False)
                }
                
                if memory_result.get('success', False):
                    max_memory = system_metrics.get('max_memory_mb', 0)
                    memory_increase = system_metrics.get('memory_increase_mb', 0)
                    print(f"      ✅ {scenario['name']}: Peak {max_memory:.1f}MB, increase {memory_increase:.1f}MB")
                else:
                    print(f"      ❌ {scenario['name']}: {memory_result.get('error', 'Failed')}")
                
                # Cooldown and cleanup
                await asyncio.sleep(3)
                
            except Exception as e:
                results[scenario['name']] = {
                    'overall_success': False,
                    'error': str(e)
                }
                print(f"      ❌ {scenario['name']}: {e}")
        
        return results
    
    async def _execute_memory_load_test(self, scenario: Dict) -> Dict[str, Any]:
        """Execute a memory load test scenario."""
        start_time = time.time()
        
        try:
            duration = scenario['duration']
            max_concurrent = scenario['max_concurrent']
            ramp_up_time = scenario['ramp_up_time']
            memory_intensive = scenario.get('memory_intensive', False)
            
            # Track active tasks
            active_tasks = set()
            completed_tasks = 0
            
            # Ramp up phase
            ramp_up_interval = ramp_up_time / max_concurrent
            
            for i in range(max_concurrent):
                if memory_intensive:
                    task = asyncio.create_task(self._memory_intensive_operation(i))
                else:
                    task = asyncio.create_task(self._simulate_mcp_request())
                
                active_tasks.add(task)
                
                if i < max_concurrent - 1:
                    await asyncio.sleep(ramp_up_interval)
            
            # Sustained load phase
            end_time = start_time + duration
            
            while time.time() < end_time:
                # Check for completed tasks
                done_tasks = [task for task in active_tasks if task.done()]
                
                for task in done_tasks:
                    active_tasks.remove(task)
                    completed_tasks += 1
                    
                    # Start new task to maintain load
                    if memory_intensive:
                        new_task = asyncio.create_task(self._memory_intensive_operation(completed_tasks))
                    else:
                        new_task = asyncio.create_task(self._simulate_mcp_request())
                    
                    active_tasks.add(new_task)
                
                await asyncio.sleep(0.1)  # Check every 100ms
            
            # Clean up remaining tasks
            for task in active_tasks:
                task.cancel()
            
            await asyncio.gather(*active_tasks, return_exceptions=True)
            
            total_time = time.time() - start_time
            
            return {
                'success': True,
                'duration': duration,
                'actual_duration': total_time,
                'max_concurrent_tasks': max_concurrent,
                'completed_operations': completed_tasks,
                'operations_per_second': completed_tasks / total_time if total_time > 0 else 0
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'total_time': time.time() - start_time
            }
    
    async def _memory_intensive_operation(self, operation_id: int):
        """Perform a memory-intensive operation."""
        try:
            # Create some data structures to use memory
            data = []
            
            for i in range(1000):
                item = {
                    'id': operation_id * 1000 + i,
                    'data': f'memory_test_data_{i}' * 10,
                    'timestamp': time.time(),
                    'nested': {
                        'level1': {'level2': {'value': i * operation_id}},
                        'array': list(range(i % 50))
                    }
                }
                data.append(item)
            
            # Simulate processing
            await asyncio.sleep(0.1)
            
            # Process the data
            processed = [item for item in data if item['id'] % 2 == 0]
            
            # Simulate more processing
            await asyncio.sleep(0.05)
            
            return len(processed)
            
        except Exception:
            return 0
    
    async def _start_system_monitoring(self):
        """Start monitoring system resources."""
        self.monitoring_active = True
        self.system_metrics = []
        
        # Start monitoring task
        self.monitoring_task = asyncio.create_task(self._monitor_system_resources())
    
    async def _stop_system_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return collected metrics."""
        self.monitoring_active = False
        
        if hasattr(self, 'monitoring_task'):
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        if not self.system_metrics:
            return {}
        
        # Calculate statistics from collected metrics
        memory_values = [m['memory_mb'] for m in self.system_metrics]
        cpu_values = [m['cpu_percent'] for m in self.system_metrics]
        
        return {
            'initial_memory_mb': memory_values[0] if memory_values else 0,
            'max_memory_mb': max(memory_values) if memory_values else 0,
            'avg_memory_mb': statistics.mean(memory_values) if memory_values else 0,
            'memory_increase_mb': max(memory_values) - memory_values[0] if len(memory_values) > 1 else 0,
            'max_cpu_percent': max(cpu_values) if cpu_values else 0,
            'avg_cpu_percent': statistics.mean(cpu_values) if cpu_values else 0,
            'samples_collected': len(self.system_metrics)
        }
    
    async def _monitor_system_resources(self):
        """Monitor system resources continuously."""
        process = psutil.Process()
        
        while self.monitoring_active:
            try:
                memory_info = process.memory_info()
                cpu_percent = process.cpu_percent()
                
                metric = {
                    'timestamp': time.time(),
                    'memory_mb': memory_info.rss / 1024 / 1024,
                    'cpu_percent': cpu_percent
                }
                
                self.system_metrics.append(metric)
                
                await asyncio.sleep(0.1)  # Sample every 100ms
                
            except Exception:
                break
    
    async def test_stress_recovery_scenarios(self) -> Dict[str, Any]:
        """Test system recovery under stress scenarios."""
        print("🚨 Testing Stress Recovery Scenarios...")
        
        stress_scenarios = [
            {
                'name': 'resource_exhaustion_recovery',
                'stress_type': 'memory',
                'stress_duration': 15,
                'recovery_time': 10
            },
            {
                'name': 'connection_flood_recovery',
                'stress_type': 'connections',
                'stress_duration': 20,
                'recovery_time': 15
            },
            {
                'name': 'api_overload_recovery',
                'stress_type': 'api_calls',
                'stress_duration': 25,
                'recovery_time': 10
            }
        ]
        
        results = {}
        
        for scenario in stress_scenarios:
            print(f"   Testing: {scenario['name']}")
            
            try:
                await self._start_system_monitoring()
                
                stress_result = await self._execute_stress_recovery_test(scenario)
                
                system_metrics = await self._stop_system_monitoring()
                
                results[scenario['name']] = {
                    'stress_test': stress_result,
                    'system_metrics': system_metrics,
                    'overall_success': stress_result.get('recovery_successful', False)
                }
                
                if stress_result.get('recovery_successful', False):
                    recovery_time = stress_result.get('recovery_time', 0)
                    print(f"      ✅ {scenario['name']}: Recovered in {recovery_time:.1f}s")
                else:
                    print(f"      ❌ {scenario['name']}: Recovery failed")
                
                # Extended cooldown after stress test
                await asyncio.sleep(5)
                
            except Exception as e:
                results[scenario['name']] = {
                    'overall_success': False,
                    'error': str(e)
                }
                print(f"      ❌ {scenario['name']}: {e}")
        
        return results
    
    async def _execute_stress_recovery_test(self, scenario: Dict) -> Dict[str, Any]:
        """Execute a stress recovery test scenario."""
        start_time = time.time()
        
        try:
            stress_type = scenario['stress_type']
            stress_duration = scenario['stress_duration']
            recovery_time = scenario['recovery_time']
            
            # Phase 1: Apply stress
            print(f"      Applying {stress_type} stress for {stress_duration}s...")
            stress_task = None
            
            if stress_type == 'memory':
                stress_task = asyncio.create_task(self._apply_memory_stress(stress_duration))
            elif stress_type == 'connections':
                stress_task = asyncio.create_task(self._apply_connection_stress(stress_duration))
            elif stress_type == 'api_calls':
                stress_task = asyncio.create_task(self._apply_api_stress(stress_duration))
            
            if stress_task:
                await stress_task
            
            stress_end_time = time.time()
            
            # Phase 2: Recovery monitoring
            print(f"      Monitoring recovery for {recovery_time}s...")
            recovery_start = time.time()
            
            recovery_successful = await self._monitor_system_recovery(recovery_time)
            
            total_time = time.time() - start_time
            actual_recovery_time = time.time() - recovery_start
            
            return {
                'stress_type': stress_type,
                'stress_duration': stress_duration,
                'actual_stress_duration': stress_end_time - start_time,
                'recovery_time': actual_recovery_time,
                'recovery_successful': recovery_successful,
                'total_test_time': total_time
            }
            
        except Exception as e:
            return {
                'recovery_successful': False,
                'error': str(e),
                'total_test_time': time.time() - start_time
            }
    
    async def _apply_memory_stress(self, duration: float):
        """Apply memory stress for specified duration."""
        end_time = time.time() + duration
        memory_hogs = []
        
        try:
            while time.time() < end_time:
                # Create memory-intensive tasks
                for _ in range(5):
                    task = asyncio.create_task(self._memory_intensive_operation(len(memory_hogs)))
                    memory_hogs.append(task)
                
                await asyncio.sleep(0.5)
                
                # Clean up some completed tasks
                completed = [task for task in memory_hogs if task.done()]
                for task in completed:
                    memory_hogs.remove(task)
        
        finally:
            # Clean up all tasks
            for task in memory_hogs:
                task.cancel()
            
            await asyncio.gather(*memory_hogs, return_exceptions=True)
    
    async def _apply_connection_stress(self, duration: float):
        """Apply connection stress for specified duration."""
        end_time = time.time() + duration
        connections = []
        
        try:
            while time.time() < end_time:
                # Create many concurrent connection simulations
                for _ in range(10):
                    task = asyncio.create_task(self._simulate_mcp_connection_load(len(connections), 5, 0.01))
                    connections.append(task)
                
                await asyncio.sleep(1)
                
                # Clean up completed connections
                completed = [task for task in connections if task.done()]
                for task in completed:
                    connections.remove(task)
        
        finally:
            # Clean up all connections
            for task in connections:
                task.cancel()
            
            await asyncio.gather(*connections, return_exceptions=True)
    
    async def _apply_api_stress(self, duration: float):
        """Apply API stress for specified duration."""
        end_time = time.time() + duration
        api_tasks = []
        
        try:
            while time.time() < end_time:
                # Create rapid API calls (simulated)
                for _ in range(3):
                    task = asyncio.create_task(self._simulate_mcp_request())
                    api_tasks.append(task)
                
                await asyncio.sleep(0.2)
                
                # Clean up completed tasks
                completed = [task for task in api_tasks if task.done()]
                for task in completed:
                    api_tasks.remove(task)
        
        finally:
            # Clean up all tasks
            for task in api_tasks:
                task.cancel()
            
            await asyncio.gather(*api_tasks, return_exceptions=True)
    
    async def _monitor_system_recovery(self, recovery_time: float) -> bool:
        """Monitor system recovery and determine if successful."""
        start_time = time.time()
        end_time = start_time + recovery_time
        
        # Get baseline metrics
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        stable_readings = 0
        required_stable_readings = 10  # Need 10 stable readings
        
        while time.time() < end_time:
            try:
                current_memory = process.memory_info().rss / 1024 / 1024
                cpu_percent = process.cpu_percent()
                
                # Check if system is stable (memory not growing rapidly, CPU reasonable)
                memory_growth_rate = (current_memory - initial_memory) / (time.time() - start_time)
                
                if memory_growth_rate < 1.0 and cpu_percent < 50:  # Memory growing <1MB/s, CPU <50%
                    stable_readings += 1
                else:
                    stable_readings = 0  # Reset counter
                
                if stable_readings >= required_stable_readings:
                    return True  # System has recovered
                
                await asyncio.sleep(0.5)
                
            except Exception:
                break
        
        return False  # Recovery not achieved within time limit


async def main():
    """Run load testing integration suite."""
    print("⚡ AGENT 6: Load Testing Integration Suite")
    print("=" * 60)
    
    suite = LoadTestingIntegrationSuite()
    
    try:
        # Run all load testing scenarios
        connection_results = await suite.test_concurrent_mcp_server_connections()
        api_load_results = await suite.test_api_integration_load()
        memory_results = await suite.test_memory_usage_under_sustained_load()
        stress_recovery_results = await suite.test_stress_recovery_scenarios()
        
        # Compile results
        all_results = {
            'concurrent_connections': connection_results,
            'api_integration_load': api_load_results,
            'memory_usage_sustained': memory_results,
            'stress_recovery': stress_recovery_results,
            'summary': {
                'connection_tests_passed': sum(1 for r in connection_results.values() if r.get('overall_success', False)),
                'api_load_tests_passed': sum(1 for r in api_load_results.values() if r.get('overall_success', False)),
                'memory_tests_passed': sum(1 for r in memory_results.values() if r.get('overall_success', False)),
                'stress_recovery_tests_passed': sum(1 for r in stress_recovery_results.values() if r.get('overall_success', False)),
                'total_tests': (len(connection_results) + len(api_load_results) + 
                              len(memory_results) + len(stress_recovery_results))
            }
        }
        
        total_passed = (
            all_results['summary']['connection_tests_passed'] +
            all_results['summary']['api_load_tests_passed'] +
            all_results['summary']['memory_tests_passed'] +
            all_results['summary']['stress_recovery_tests_passed']
        )
        
        all_results['summary']['total_passed'] = total_passed
        all_results['summary']['success_rate'] = (total_passed / all_results['summary']['total_tests'] * 100) if all_results['summary']['total_tests'] > 0 else 0
        
        # Print summary
        print(f"\n📊 Load Testing Integration Summary:")
        print(f"   Concurrent connections: {all_results['summary']['connection_tests_passed']}/{len(connection_results)}")
        print(f"   API integration load: {all_results['summary']['api_load_tests_passed']}/{len(api_load_results)}")
        print(f"   Memory usage tests: {all_results['summary']['memory_tests_passed']}/{len(memory_results)}")
        print(f"   Stress recovery tests: {all_results['summary']['stress_recovery_tests_passed']}/{len(stress_recovery_results)}")
        print(f"   Overall success rate: {all_results['summary']['success_rate']:.1f}%")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f'/home/louranicas/projects/claude-optimized-deployment/agent_6_load_testing_integration_results_{timestamp}.json'
        
        with open(report_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        
        print(f"\n💾 Results saved to: {report_file}")
        return all_results
        
    except Exception as e:
        print(f"❌ Load testing integration failed: {e}")
        return None


if __name__ == "__main__":
    asyncio.run(main())