"""
MCP Test Orchestrator - Central coordination service for distributed testing.
Manages test execution across multiple MCP server nodes.
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import websockets
import aiohttp
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestStatus(Enum):
    """Test execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class NodeStatus(Enum):
    """Node status enumeration"""
    AVAILABLE = "available"
    BUSY = "busy"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"


@dataclass
class TestNode:
    """Represents a test execution node"""
    node_id: str
    host: str
    port: int
    capabilities: List[str]
    status: NodeStatus
    current_load: float
    max_capacity: int
    last_heartbeat: datetime
    mcp_servers: List[str]


@dataclass
class TestTask:
    """Represents a distributed test task"""
    task_id: str
    test_type: str
    parameters: Dict[str, Any]
    assigned_nodes: List[str]
    status: TestStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: Dict[str, Any] = None
    error_message: Optional[str] = None


@dataclass
class TestExecution:
    """Represents a complete test execution"""
    execution_id: str
    name: str
    tasks: List[TestTask]
    total_nodes: int
    status: TestStatus
    created_at: datetime
    estimated_duration: Optional[timedelta] = None
    actual_duration: Optional[timedelta] = None


class MCPTestOrchestrator:
    """Central coordinator for distributed MCP testing"""
    
    def __init__(self, host: str = "localhost", port: int = 8080):
        self.host = host
        self.port = port
        self.nodes: Dict[str, TestNode] = {}
        self.executions: Dict[str, TestExecution] = {}
        self.active_tasks: Dict[str, TestTask] = {}
        self.node_connections: Dict[str, websockets.WebSocketServerProtocol] = {}
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.running = False
        
        # MCP server configurations
        self.mcp_servers = {
            "test_orchestrator": {
                "name": "Test Orchestrator Server",
                "version": "1.0.0",
                "description": "Central coordination for distributed testing",
                "methods": [
                    "register_node",
                    "submit_test_execution",
                    "get_execution_status",
                    "cancel_execution",
                    "list_nodes",
                    "get_node_status"
                ]
            }
        }

    async def start(self):
        """Start the orchestrator service"""
        self.running = True
        logger.info(f"Starting MCP Test Orchestrator on {self.host}:{self.port}")
        
        # Start WebSocket server for node communication
        start_server = websockets.serve(
            self.handle_node_connection,
            self.host,
            self.port + 1
        )
        
        # Start HTTP API server
        app = self.create_http_app()
        
        # Start background tasks
        heartbeat_task = asyncio.create_task(self.heartbeat_monitor())
        cleanup_task = asyncio.create_task(self.cleanup_completed_tasks())
        
        await asyncio.gather(
            start_server,
            self.run_http_server(),
            heartbeat_task,
            cleanup_task
        )

    async def handle_node_connection(self, websocket, path):
        """Handle WebSocket connections from test nodes"""
        node_id = None
        try:
            async for message in websocket:
                data = json.loads(message)
                message_type = data.get("type")
                
                if message_type == "register":
                    node_id = await self.register_node(data["node_info"], websocket)
                elif message_type == "heartbeat":
                    await self.handle_heartbeat(data["node_id"], data.get("metrics", {}))
                elif message_type == "task_result":
                    await self.handle_task_result(data["task_id"], data["result"])
                elif message_type == "status_update":
                    await self.handle_status_update(data["node_id"], data["status"])
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Node {node_id} disconnected")
        except Exception as e:
            logger.error(f"Error handling node connection: {e}")
        finally:
            if node_id and node_id in self.node_connections:
                del self.node_connections[node_id]
                if node_id in self.nodes:
                    self.nodes[node_id].status = NodeStatus.OFFLINE

    async def register_node(self, node_info: Dict[str, Any], websocket) -> str:
        """Register a new test node"""
        node_id = node_info.get("node_id", str(uuid.uuid4()))
        
        node = TestNode(
            node_id=node_id,
            host=node_info["host"],
            port=node_info["port"],
            capabilities=node_info.get("capabilities", []),
            status=NodeStatus.AVAILABLE,
            current_load=0.0,
            max_capacity=node_info.get("max_capacity", 100),
            last_heartbeat=datetime.now(),
            mcp_servers=node_info.get("mcp_servers", [])
        )
        
        self.nodes[node_id] = node
        self.node_connections[node_id] = websocket
        
        logger.info(f"Registered node {node_id} at {node.host}:{node.port}")
        
        # Send registration confirmation
        await websocket.send(json.dumps({
            "type": "registration_confirmed",
            "node_id": node_id,
            "orchestrator_info": {
                "host": self.host,
                "port": self.port,
                "mcp_servers": list(self.mcp_servers.keys())
            }
        }))
        
        return node_id

    async def submit_test_execution(self, execution_config: Dict[str, Any]) -> str:
        """Submit a new test execution"""
        execution_id = str(uuid.uuid4())
        
        # Create test tasks based on configuration
        tasks = []
        for task_config in execution_config.get("tasks", []):
            task = TestTask(
                task_id=str(uuid.uuid4()),
                test_type=task_config["type"],
                parameters=task_config.get("parameters", {}),
                assigned_nodes=[],
                status=TestStatus.PENDING,
                created_at=datetime.now()
            )
            tasks.append(task)
        
        execution = TestExecution(
            execution_id=execution_id,
            name=execution_config["name"],
            tasks=tasks,
            total_nodes=execution_config.get("node_count", len(self.nodes)),
            status=TestStatus.PENDING,
            created_at=datetime.now()
        )
        
        self.executions[execution_id] = execution
        
        # Schedule execution
        asyncio.create_task(self.execute_test_plan(execution))
        
        logger.info(f"Submitted test execution {execution_id}: {execution.name}")
        return execution_id

    async def execute_test_plan(self, execution: TestExecution):
        """Execute a test plan across distributed nodes"""
        try:
            execution.status = TestStatus.RUNNING
            start_time = datetime.now()
            
            # Assign tasks to nodes
            await self.assign_tasks_to_nodes(execution)
            
            # Execute tasks in parallel
            task_futures = []
            for task in execution.tasks:
                if task.assigned_nodes:
                    future = asyncio.create_task(self.execute_task(task))
                    task_futures.append(future)
            
            # Wait for all tasks to complete
            await asyncio.gather(*task_futures, return_exceptions=True)
            
            # Check execution status
            failed_tasks = [t for t in execution.tasks if t.status == TestStatus.FAILED]
            if failed_tasks:
                execution.status = TestStatus.FAILED
            else:
                execution.status = TestStatus.COMPLETED
            
            execution.actual_duration = datetime.now() - start_time
            logger.info(f"Test execution {execution.execution_id} completed with status: {execution.status}")
            
        except Exception as e:
            execution.status = TestStatus.FAILED
            logger.error(f"Test execution {execution.execution_id} failed: {e}")

    async def assign_tasks_to_nodes(self, execution: TestExecution):
        """Assign tasks to available nodes based on capabilities and load"""
        available_nodes = [
            node for node in self.nodes.values()
            if node.status == NodeStatus.AVAILABLE
        ]
        
        if not available_nodes:
            raise RuntimeError("No available nodes for test execution")
        
        # Sort nodes by current load (ascending)
        available_nodes.sort(key=lambda n: n.current_load)
        
        for task in execution.tasks:
            # Find best node for this task
            best_node = None
            for node in available_nodes:
                # Check if node has required capabilities
                task_capabilities = task.parameters.get("required_capabilities", [])
                if all(cap in node.capabilities for cap in task_capabilities):
                    best_node = node
                    break
            
            if best_node:
                task.assigned_nodes.append(best_node.node_id)
                best_node.current_load += task.parameters.get("load_weight", 1.0)
                
                # Update node status if at capacity
                if best_node.current_load >= best_node.max_capacity:
                    best_node.status = NodeStatus.BUSY
            else:
                logger.warning(f"Could not assign task {task.task_id} - no suitable nodes")

    async def execute_task(self, task: TestTask):
        """Execute a single task on assigned nodes"""
        try:
            task.status = TestStatus.RUNNING
            task.started_at = datetime.now()
            self.active_tasks[task.task_id] = task
            
            # Send task to assigned nodes
            results = []
            for node_id in task.assigned_nodes:
                if node_id in self.node_connections:
                    websocket = self.node_connections[node_id]
                    
                    # Send task execution command
                    command = {
                        "type": "execute_task",
                        "task_id": task.task_id,
                        "task_type": task.test_type,
                        "parameters": task.parameters
                    }
                    
                    await websocket.send(json.dumps(command))
            
            # Wait for task completion (with timeout)
            timeout = task.parameters.get("timeout", 300)  # Default 5 minutes
            await asyncio.wait_for(
                self.wait_for_task_completion(task.task_id),
                timeout=timeout
            )
            
        except asyncio.TimeoutError:
            task.status = TestStatus.FAILED
            task.error_message = "Task execution timed out"
            logger.error(f"Task {task.task_id} timed out")
        except Exception as e:
            task.status = TestStatus.FAILED
            task.error_message = str(e)
            logger.error(f"Task {task.task_id} failed: {e}")
        finally:
            task.completed_at = datetime.now()
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]

    async def wait_for_task_completion(self, task_id: str):
        """Wait for a task to complete"""
        while task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            if task.status in [TestStatus.COMPLETED, TestStatus.FAILED, TestStatus.CANCELLED]:
                break
            await asyncio.sleep(1)

    async def handle_task_result(self, task_id: str, result: Dict[str, Any]):
        """Handle task result from a node"""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            task.results = result
            
            if result.get("success", False):
                task.status = TestStatus.COMPLETED
            else:
                task.status = TestStatus.FAILED
                task.error_message = result.get("error", "Unknown error")
            
            logger.info(f"Received result for task {task_id}: {task.status}")

    async def handle_heartbeat(self, node_id: str, metrics: Dict[str, Any]):
        """Handle heartbeat from a node"""
        if node_id in self.nodes:
            node = self.nodes[node_id]
            node.last_heartbeat = datetime.now()
            
            # Update node metrics
            if "current_load" in metrics:
                node.current_load = metrics["current_load"]
            
            # Update status based on load
            if node.current_load >= node.max_capacity:
                node.status = NodeStatus.BUSY
            elif node.status == NodeStatus.BUSY and node.current_load < node.max_capacity * 0.8:
                node.status = NodeStatus.AVAILABLE

    async def handle_status_update(self, node_id: str, status: str):
        """Handle status update from a node"""
        if node_id in self.nodes:
            try:
                self.nodes[node_id].status = NodeStatus(status)
                logger.info(f"Node {node_id} status updated to {status}")
            except ValueError:
                logger.warning(f"Invalid status update for node {node_id}: {status}")

    async def heartbeat_monitor(self):
        """Monitor node heartbeats and mark offline nodes"""
        while self.running:
            try:
                current_time = datetime.now()
                heartbeat_timeout = timedelta(minutes=2)
                
                for node in self.nodes.values():
                    if current_time - node.last_heartbeat > heartbeat_timeout:
                        if node.status != NodeStatus.OFFLINE:
                            logger.warning(f"Node {node.node_id} marked as offline - no heartbeat")
                            node.status = NodeStatus.OFFLINE
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in heartbeat monitor: {e}")

    async def cleanup_completed_tasks(self):
        """Clean up completed tasks and executions"""
        while self.running:
            try:
                current_time = datetime.now()
                cleanup_threshold = timedelta(hours=1)
                
                # Clean up completed executions
                completed_executions = []
                for execution_id, execution in self.executions.items():
                    if (execution.status in [TestStatus.COMPLETED, TestStatus.FAILED, TestStatus.CANCELLED] and
                        execution.completed_at and
                        current_time - execution.completed_at > cleanup_threshold):
                        completed_executions.append(execution_id)
                
                for execution_id in completed_executions:
                    del self.executions[execution_id]
                    logger.info(f"Cleaned up completed execution {execution_id}")
                
                await asyncio.sleep(300)  # Clean up every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")

    def create_http_app(self):
        """Create HTTP API application"""
        from aiohttp import web
        
        app = web.Application()
        
        # API routes
        app.router.add_post('/api/executions', self.api_submit_execution)
        app.router.add_get('/api/executions/{execution_id}', self.api_get_execution)
        app.router.add_delete('/api/executions/{execution_id}', self.api_cancel_execution)
        app.router.add_get('/api/nodes', self.api_list_nodes)
        app.router.add_get('/api/nodes/{node_id}', self.api_get_node)
        app.router.add_get('/api/health', self.api_health_check)
        
        return app

    async def run_http_server(self):
        """Run HTTP API server"""
        from aiohttp import web
        app = self.create_http_app()
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        logger.info(f"HTTP API server started on {self.host}:{self.port}")

    # HTTP API handlers
    async def api_submit_execution(self, request):
        """API endpoint to submit test execution"""
        from aiohttp import web
        try:
            data = await request.json()
            execution_id = await self.submit_test_execution(data)
            return web.json_response({"execution_id": execution_id})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def api_get_execution(self, request):
        """API endpoint to get execution status"""
        from aiohttp import web
        execution_id = request.match_info["execution_id"]
        
        if execution_id not in self.executions:
            return web.json_response({"error": "Execution not found"}, status=404)
        
        execution = self.executions[execution_id]
        return web.json_response(asdict(execution), default=str)

    async def api_cancel_execution(self, request):
        """API endpoint to cancel execution"""
        from aiohttp import web
        execution_id = request.match_info["execution_id"]
        
        if execution_id not in self.executions:
            return web.json_response({"error": "Execution not found"}, status=404)
        
        execution = self.executions[execution_id]
        if execution.status == TestStatus.RUNNING:
            execution.status = TestStatus.CANCELLED
            # Cancel all active tasks
            for task in execution.tasks:
                if task.status == TestStatus.RUNNING:
                    task.status = TestStatus.CANCELLED
        
        return web.json_response({"status": "cancelled"})

    async def api_list_nodes(self, request):
        """API endpoint to list all nodes"""
        from aiohttp import web
        nodes_data = [asdict(node) for node in self.nodes.values()]
        return web.json_response({"nodes": nodes_data}, default=str)

    async def api_get_node(self, request):
        """API endpoint to get node information"""
        from aiohttp import web
        node_id = request.match_info["node_id"]
        
        if node_id not in self.nodes:
            return web.json_response({"error": "Node not found"}, status=404)
        
        node = self.nodes[node_id]
        return web.json_response(asdict(node), default=str)

    async def api_health_check(self, request):
        """API endpoint for health check"""
        from aiohttp import web
        return web.json_response({
            "status": "healthy",
            "nodes": len(self.nodes),
            "active_executions": len([e for e in self.executions.values() if e.status == TestStatus.RUNNING]),
            "timestamp": datetime.now().isoformat()
        })

    async def stop(self):
        """Stop the orchestrator service"""
        self.running = False
        logger.info("MCP Test Orchestrator stopped")


if __name__ == "__main__":
    async def main():
        orchestrator = MCPTestOrchestrator()
        try:
            await orchestrator.start()
        except KeyboardInterrupt:
            await orchestrator.stop()
    
    asyncio.run(main())