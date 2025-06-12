#!/usr/bin/env python3
"""
Application Load Generator
=========================

Advanced application-specific load generation including Circle of Experts queries,
MCP server interactions, database operations, and realistic business logic execution.
"""

import asyncio
import random
import time
import logging
import json
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
import numpy as np
from pathlib import Path
import sys

# Add project paths
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "src"))

logger = logging.getLogger(__name__)

try:
    from circle_of_experts.core.expert_manager import ExpertManager
    from circle_of_experts.models.query import Query
    from mcp.manager import MCPManager
    from database.connection import DatabaseConnection
    INTEGRATIONS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Some integrations not available: {e}")
    INTEGRATIONS_AVAILABLE = False

@dataclass
class ApplicationLoadConfiguration:
    """Configuration for application load generation"""
    workload_types: List[str] = None  # circle_of_experts, mcp_operations, database_queries, api_calls
    expert_query_complexity: str = "medium"  # simple, medium, complex
    mcp_server_types: List[str] = None  # List of MCP server types to test
    database_operation_mix: Dict[str, float] = None  # read/write/update/delete ratios
    concurrent_users: int = 10  # Number of concurrent user sessions
    user_session_duration: int = 300  # Session duration in seconds
    think_time_range: tuple = (1, 5)  # User think time between operations (seconds)
    business_logic_complexity: str = "realistic"  # simple, realistic, complex
    cache_usage: bool = True  # Simulate cache usage patterns
    authentication_required: bool = True  # Require user authentication
    data_validation: bool = True  # Enable data validation

@dataclass
class ApplicationOperation:
    """Represents an application operation"""
    operation_id: str
    operation_type: str
    user_session_id: str
    start_time: float
    end_time: Optional[float] = None
    input_data: Dict[str, Any] = None
    output_data: Dict[str, Any] = None
    success: bool = False
    error_message: Optional[str] = None
    processing_time_ms: float = 0.0
    resource_usage: Dict[str, float] = None
    cache_hit: bool = False
    
    @property
    def duration_ms(self) -> float:
        """Get operation duration in milliseconds"""
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0

@dataclass
class UserSession:
    """Represents a user session"""
    session_id: str
    user_id: str
    start_time: float
    last_activity: float
    operations_count: int = 0
    authenticated: bool = False
    user_profile: Dict[str, Any] = None
    session_context: Dict[str, Any] = None

class ApplicationLoadGenerator:
    """
    Advanced Application Load Generator
    
    Generates realistic application workloads including Circle of Experts queries,
    MCP server operations, database interactions, and complex business logic.
    """
    
    def __init__(self, config: Optional[ApplicationLoadConfiguration] = None):
        self.config = config or ApplicationLoadConfiguration()
        self.running = False
        self.current_load = 0.0
        self.target_load = 0.0
        
        # Initialize default values
        if not self.config.workload_types:
            self.config.workload_types = ["circle_of_experts", "mcp_operations", "database_queries", "api_calls"]
        
        if not self.config.mcp_server_types:
            self.config.mcp_server_types = ["security", "infrastructure", "storage", "communication"]
        
        if not self.config.database_operation_mix:
            self.config.database_operation_mix = {
                "read": 0.6,
                "write": 0.2,
                "update": 0.15,
                "delete": 0.05
            }
        
        # Application components
        self.expert_manager = None
        self.mcp_manager = None
        self.database_connection = None
        
        # Session management
        self.active_sessions: Dict[str, UserSession] = {}
        self.operation_history: List[ApplicationOperation] = []
        self.user_counter = 0
        self.session_counter = 0
        
        # Performance monitoring
        self.performance_samples = []
        self.application_stats = {
            'total_operations': 0,
            'successful_operations': 0,
            'failed_operations': 0,
            'average_processing_time_ms': 0.0,
            'operations_per_second': 0.0,
            'active_sessions': 0,
            'cache_hit_rate': 0.0,
            'expert_queries': 0,
            'mcp_operations': 0,
            'database_operations': 0,
            'api_calls': 0
        }
        
        # Worker tasks
        self.worker_tasks = []
        self.operation_queue = asyncio.Queue()
        
        # Cache simulation
        self.cache = {}
        self.cache_hits = 0
        self.cache_misses = 0
    
    async def execute_pattern(self, pattern):
        """Execute an application load pattern"""
        logger.info(f"Starting application load pattern: {pattern.name}")
        self.running = True
        
        try:
            # Initialize application components
            await self._initialize_components()
            
            # Start worker tasks
            for i in range(self.config.concurrent_users):
                task = asyncio.create_task(self._user_session_worker(f"user_{i}"))
                self.worker_tasks.append(task)
            
            # Start operation processors
            for i in range(min(5, self.config.concurrent_users)):
                task = asyncio.create_task(self._operation_processor(f"processor_{i}"))
                self.worker_tasks.append(task)
            
            # Start monitoring
            monitor_task = asyncio.create_task(self._monitor_performance())
            
            # Execute pattern points
            for point in pattern.points:
                if not self.running:
                    break
                
                # Update target load
                self.target_load = point.intensity
                
                # Adjust user activity based on intensity
                await self._adjust_user_activity(point.intensity)
                
                # Wait for next point
                if pattern.points.index(point) < len(pattern.points) - 1:
                    next_point = pattern.points[pattern.points.index(point) + 1]
                    wait_time = next_point.timestamp - point.timestamp
                    await asyncio.sleep(max(1.0, wait_time))
            
            # Stop monitoring
            monitor_task.cancel()
            
            logger.info(f"Completed application load pattern: {pattern.name}")
            
        except Exception as e:
            logger.error(f"Application load pattern execution failed: {e}")
            raise
        finally:
            await self.stop()
    
    async def _initialize_components(self):
        """Initialize application components"""
        try:
            if INTEGRATIONS_AVAILABLE:
                # Initialize Circle of Experts
                if "circle_of_experts" in self.config.workload_types:
                    try:
                        self.expert_manager = ExpertManager()
                        logger.info("Circle of Experts initialized")
                    except Exception as e:
                        logger.warning(f"Failed to initialize Circle of Experts: {e}")
                
                # Initialize MCP Manager
                if "mcp_operations" in self.config.workload_types:
                    try:
                        self.mcp_manager = MCPManager()
                        logger.info("MCP Manager initialized")
                    except Exception as e:
                        logger.warning(f"Failed to initialize MCP Manager: {e}")
                
                # Initialize Database Connection
                if "database_queries" in self.config.workload_types:
                    try:
                        self.database_connection = DatabaseConnection()
                        logger.info("Database connection initialized")
                    except Exception as e:
                        logger.warning(f"Failed to initialize database connection: {e}")
            
        except Exception as e:
            logger.error(f"Component initialization failed: {e}")
    
    async def _adjust_user_activity(self, intensity: float):
        """Adjust user activity based on load intensity"""
        # Calculate target number of active sessions
        target_sessions = max(1, int(self.config.concurrent_users * intensity))
        current_sessions = len(self.active_sessions)
        
        if target_sessions > current_sessions:
            # Create new sessions
            for _ in range(target_sessions - current_sessions):
                await self._create_user_session()
        elif target_sessions < current_sessions:
            # End some sessions
            sessions_to_end = list(self.active_sessions.keys())[:current_sessions - target_sessions]
            for session_id in sessions_to_end:
                await self._end_user_session(session_id)
    
    async def _create_user_session(self) -> UserSession:
        """Create a new user session"""
        self.user_counter += 1
        self.session_counter += 1
        
        session = UserSession(
            session_id=f"session_{self.session_counter}",
            user_id=f"user_{self.user_counter}",
            start_time=time.time(),
            last_activity=time.time(),
            user_profile=self._generate_user_profile(),
            session_context={}
        )
        
        # Authenticate user if required
        if self.config.authentication_required:
            auth_success = await self._authenticate_user(session)
            session.authenticated = auth_success
        else:
            session.authenticated = True
        
        self.active_sessions[session.session_id] = session
        logger.debug(f"Created user session: {session.session_id}")
        
        return session
    
    async def _end_user_session(self, session_id: str):
        """End a user session"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            del self.active_sessions[session_id]
            logger.debug(f"Ended user session: {session_id} (duration: {time.time() - session.start_time:.1f}s)")
    
    def _generate_user_profile(self) -> Dict[str, Any]:
        """Generate a realistic user profile"""
        user_types = ["developer", "admin", "analyst", "manager", "support"]
        permissions = ["read", "write", "admin", "deploy", "monitor"]
        
        user_type = random.choice(user_types)
        
        # Different user types have different permission sets
        permission_sets = {
            "developer": ["read", "write", "deploy"],
            "admin": ["read", "write", "admin", "deploy", "monitor"],
            "analyst": ["read", "monitor"],
            "manager": ["read", "monitor"],
            "support": ["read", "write"]
        }
        
        return {
            "user_type": user_type,
            "permissions": permission_sets.get(user_type, ["read"]),
            "experience_level": random.choice(["beginner", "intermediate", "expert"]),
            "preferred_tools": random.sample(self.config.workload_types, k=random.randint(1, len(self.config.workload_types))),
            "working_hours": {
                "timezone": random.choice(["UTC", "PST", "EST", "GMT", "JST"]),
                "start_hour": random.randint(8, 10),
                "end_hour": random.randint(17, 19)
            },
            "usage_patterns": {
                "query_complexity": random.choice(["simple", "medium", "complex"]),
                "batch_operations": random.choice([True, False]),
                "concurrent_tasks": random.randint(1, 5)
            }
        }
    
    async def _authenticate_user(self, session: UserSession) -> bool:
        """Simulate user authentication"""
        # Simulate authentication delay
        await asyncio.sleep(random.uniform(0.1, 0.5))
        
        # 95% success rate for authentication
        success = random.random() < 0.95
        
        if success:
            session.session_context["auth_token"] = f"token_{random.randint(100000, 999999)}"
            session.session_context["auth_time"] = time.time()
        
        return success
    
    async def _user_session_worker(self, worker_id: str):
        """Worker that simulates user session behavior"""
        logger.debug(f"Starting user session worker: {worker_id}")
        
        current_session = None
        
        while self.running:
            try:
                # Create session if needed
                if not current_session or current_session.session_id not in self.active_sessions:
                    if len(self.active_sessions) < self.config.concurrent_users * self.target_load:
                        current_session = await self._create_user_session()
                        if not current_session.authenticated:
                            await self._end_user_session(current_session.session_id)
                            current_session = None
                            await asyncio.sleep(5.0)
                            continue
                    else:
                        await asyncio.sleep(2.0)
                        continue
                
                # Generate user operations
                if current_session and current_session.authenticated:
                    operation = await self._generate_user_operation(current_session)
                    if operation:
                        await self.operation_queue.put(operation)
                        current_session.operations_count += 1
                        current_session.last_activity = time.time()
                
                # User think time
                think_time = random.uniform(*self.config.think_time_range)
                await asyncio.sleep(think_time)
                
                # Check session timeout
                if current_session:
                    session_age = time.time() - current_session.start_time
                    if session_age > self.config.user_session_duration:
                        await self._end_user_session(current_session.session_id)
                        current_session = None
                
            except Exception as e:
                logger.error(f"User session worker {worker_id} error: {e}")
                await asyncio.sleep(5.0)
        
        # Clean up session
        if current_session and current_session.session_id in self.active_sessions:
            await self._end_user_session(current_session.session_id)
        
        logger.debug(f"User session worker {worker_id} stopped")
    
    async def _generate_user_operation(self, session: UserSession) -> Optional[ApplicationOperation]:
        """Generate a user operation based on session profile"""
        user_profile = session.user_profile
        preferred_tools = user_profile.get("preferred_tools", self.config.workload_types)
        
        # Select operation type based on user preferences
        operation_type = random.choice(preferred_tools)
        
        operation = ApplicationOperation(
            operation_id=f"op_{int(time.time() * 1000)}_{random.randint(1000, 9999)}",
            operation_type=operation_type,
            user_session_id=session.session_id,
            start_time=time.time(),
            input_data=await self._generate_operation_input(operation_type, user_profile),
            resource_usage={}
        )
        
        return operation
    
    async def _generate_operation_input(self, operation_type: str, user_profile: Dict[str, Any]) -> Dict[str, Any]:
        """Generate input data for an operation"""
        complexity = user_profile.get("usage_patterns", {}).get("query_complexity", "medium")
        
        if operation_type == "circle_of_experts":
            return await self._generate_expert_query_input(complexity)
        elif operation_type == "mcp_operations":
            return await self._generate_mcp_operation_input(complexity)
        elif operation_type == "database_queries":
            return await self._generate_database_query_input(complexity)
        elif operation_type == "api_calls":
            return await self._generate_api_call_input(complexity)
        else:
            return {"type": operation_type, "complexity": complexity}
    
    async def _generate_expert_query_input(self, complexity: str) -> Dict[str, Any]:
        """Generate Circle of Experts query input"""
        query_templates = {
            "simple": [
                "What is the best practice for {topic}?",
                "How do I configure {technology}?",
                "Explain {concept} in simple terms."
            ],
            "medium": [
                "Compare {option1} vs {option2} for {use_case} and provide recommendations.",
                "What are the security implications of {technology} in {environment}?",
                "Design a solution for {problem} considering {constraints}."
            ],
            "complex": [
                "Analyze the trade-offs between {approach1} and {approach2} for {complex_scenario}, considering performance, security, scalability, and cost.",
                "Design a comprehensive architecture for {complex_system} that handles {requirements} while maintaining {quality_attributes}.",
                "Evaluate the impact of {change} on {system} and provide a migration strategy with risk assessment."
            ]
        }
        
        templates = query_templates.get(complexity, query_templates["medium"])
        template = random.choice(templates)
        
        # Fill in template variables
        topics = ["Docker", "Kubernetes", "microservices", "CI/CD", "monitoring", "security", "performance"]
        technologies = ["Redis", "PostgreSQL", "MongoDB", "Elasticsearch", "Kafka", "RabbitMQ"]
        concepts = ["containerization", "orchestration", "load balancing", "caching", "authentication"]
        
        query = template.format(
            topic=random.choice(topics),
            technology=random.choice(technologies),
            concept=random.choice(concepts),
            option1=random.choice(technologies),
            option2=random.choice(technologies),
            use_case=random.choice(["high availability", "scalability", "security", "performance"]),
            environment=random.choice(["production", "development", "staging", "cloud"]),
            problem=random.choice(["data consistency", "service discovery", "rate limiting"]),
            constraints=random.choice(["budget limitations", "compliance requirements", "legacy systems"]),
            approach1=random.choice(["microservices", "monolithic", "serverless"]),
            approach2=random.choice(["event-driven", "RESTful", "GraphQL"]),
            complex_scenario=random.choice(["multi-region deployment", "disaster recovery", "zero-downtime updates"]),
            requirements=random.choice(["high throughput", "low latency", "data consistency"]),
            quality_attributes=random.choice(["reliability", "maintainability", "security"]),
            change=random.choice(["technology migration", "architecture refactoring", "scaling strategy"]),
            system=random.choice(["payment processing", "user management", "content delivery"]),
            complex_system=random.choice(["e-commerce platform", "data analytics pipeline", "real-time chat system"])
        )
        
        return {
            "query": query,
            "complexity": complexity,
            "context": {
                "user_expertise": random.choice(["beginner", "intermediate", "expert"]),
                "domain": random.choice(["web development", "data science", "DevOps", "security"]),
                "urgency": random.choice(["low", "medium", "high"])
            }
        }
    
    async def _generate_mcp_operation_input(self, complexity: str) -> Dict[str, Any]:
        """Generate MCP operation input"""
        server_type = random.choice(self.config.mcp_server_types)
        
        operations_by_type = {
            "security": ["vulnerability_scan", "security_audit", "compliance_check", "threat_analysis"],
            "infrastructure": ["health_check", "resource_monitoring", "deployment_status", "scaling_operation"],
            "storage": ["backup_operation", "data_migration", "storage_optimization", "retention_policy"],
            "communication": ["notification_send", "alert_management", "status_update", "team_coordination"]
        }
        
        operation = random.choice(operations_by_type.get(server_type, ["generic_operation"]))
        
        complexity_params = {
            "simple": {"timeout": 30, "retries": 1, "parallel": False},
            "medium": {"timeout": 60, "retries": 3, "parallel": True, "batch_size": 5},
            "complex": {"timeout": 120, "retries": 5, "parallel": True, "batch_size": 10, "dependencies": True}
        }
        
        return {
            "server_type": server_type,
            "operation": operation,
            "parameters": complexity_params.get(complexity, complexity_params["medium"]),
            "metadata": {
                "request_id": f"mcp_{int(time.time())}_{random.randint(1000, 9999)}",
                "priority": random.choice(["low", "medium", "high"]),
                "source": "load_generator"
            }
        }
    
    async def _generate_database_query_input(self, complexity: str) -> Dict[str, Any]:
        """Generate database query input"""
        operations = list(self.config.database_operation_mix.keys())
        weights = list(self.config.database_operation_mix.values())
        operation = random.choices(operations, weights=weights)[0]
        
        tables = ["users", "orders", "products", "logs", "configurations", "metrics", "sessions"]
        table = random.choice(tables)
        
        complexity_queries = {
            "simple": {
                "read": f"SELECT * FROM {table} WHERE id = ?",
                "write": f"INSERT INTO {table} (data) VALUES (?)",
                "update": f"UPDATE {table} SET status = ? WHERE id = ?",
                "delete": f"DELETE FROM {table} WHERE id = ?"
            },
            "medium": {
                "read": f"SELECT t1.*, t2.name FROM {table} t1 JOIN related t2 ON t1.id = t2.{table}_id WHERE t1.created_at > ?",
                "write": f"INSERT INTO {table} (data, metadata, created_at) VALUES (?, ?, NOW())",
                "update": f"UPDATE {table} SET data = ?, updated_at = NOW() WHERE status = ? AND created_at > ?",
                "delete": f"DELETE FROM {table} WHERE status = 'inactive' AND updated_at < ?"
            },
            "complex": {
                "read": f"""
                    WITH recursive_data AS (
                        SELECT * FROM {table} WHERE parent_id IS NULL
                        UNION ALL
                        SELECT t.* FROM {table} t JOIN recursive_data r ON t.parent_id = r.id
                    )
                    SELECT r.*, COUNT(children.id) as child_count 
                    FROM recursive_data r 
                    LEFT JOIN {table} children ON children.parent_id = r.id 
                    GROUP BY r.id 
                    ORDER BY r.created_at DESC 
                    LIMIT ?
                """,
                "write": f"""
                    INSERT INTO {table} (data, metadata, status, created_at)
                    SELECT ?, ?, 'active', NOW()
                    WHERE NOT EXISTS (SELECT 1 FROM {table} WHERE unique_key = ?)
                """,
                "update": f"""
                    UPDATE {table} 
                    SET data = CASE 
                        WHEN status = 'pending' THEN ?
                        WHEN status = 'processing' THEN ?
                        ELSE data 
                    END,
                    updated_at = NOW()
                    WHERE id IN (SELECT id FROM {table} WHERE status IN (?, ?) ORDER BY priority DESC LIMIT ?)
                """,
                "delete": f"""
                    DELETE FROM {table} 
                    WHERE id IN (
                        SELECT id FROM (
                            SELECT id FROM {table} 
                            WHERE status = 'archived' 
                            AND updated_at < DATE_SUB(NOW(), INTERVAL ? DAY)
                            ORDER BY updated_at ASC 
                            LIMIT ?
                        ) AS to_delete
                    )
                """
            }
        }
        
        query = complexity_queries.get(complexity, complexity_queries["medium"])[operation]
        
        return {
            "operation": operation,
            "table": table,
            "query": query,
            "parameters": self._generate_query_parameters(operation, complexity),
            "options": {
                "timeout": 30 if complexity == "simple" else 60 if complexity == "medium" else 120,
                "transaction": complexity in ["medium", "complex"],
                "connection_pool": True
            }
        }
    
    def _generate_query_parameters(self, operation: str, complexity: str) -> List[Any]:
        """Generate parameters for database queries"""
        if operation == "read":
            if complexity == "simple":
                return [random.randint(1, 1000)]
            elif complexity == "medium":
                return [time.time() - random.randint(86400, 604800)]  # 1-7 days ago
            else:
                return [random.randint(10, 100)]
        elif operation == "write":
            return [json.dumps({"test": "data", "timestamp": time.time()})]
        elif operation == "update":
            if complexity == "simple":
                return ["active", random.randint(1, 1000)]
            elif complexity == "medium":
                return [json.dumps({"updated": True}), "pending", time.time() - 3600]
            else:
                return ["processed", "completed", "pending", "processing", random.randint(5, 20)]
        elif operation == "delete":
            if complexity == "simple":
                return [random.randint(1, 1000)]
            elif complexity == "medium":
                return [time.time() - 86400]  # 1 day ago
            else:
                return [random.randint(30, 90), random.randint(100, 1000)]
        
        return []
    
    async def _generate_api_call_input(self, complexity: str) -> Dict[str, Any]:
        """Generate API call input"""
        api_types = ["REST", "GraphQL", "gRPC", "WebSocket"]
        api_type = random.choice(api_types)
        
        endpoints = {
            "simple": ["/health", "/status", "/version", "/ping"],
            "medium": ["/users/{id}", "/orders", "/search", "/analytics"],
            "complex": ["/batch/process", "/ml/predict", "/reports/generate", "/workflows/execute"]
        }
        
        endpoint = random.choice(endpoints.get(complexity, endpoints["medium"]))
        
        methods = {
            "simple": ["GET"],
            "medium": ["GET", "POST", "PUT"],
            "complex": ["GET", "POST", "PUT", "DELETE", "PATCH"]
        }
        
        method = random.choice(methods.get(complexity, methods["medium"]))
        
        return {
            "api_type": api_type,
            "endpoint": endpoint,
            "method": method,
            "headers": {
                "Content-Type": "application/json",
                "Authorization": f"Bearer token_{random.randint(100000, 999999)}",
                "X-Request-ID": f"req_{int(time.time())}_{random.randint(1000, 9999)}"
            },
            "payload": self._generate_api_payload(complexity),
            "timeout": 30 if complexity == "simple" else 60 if complexity == "medium" else 120,
            "retries": 1 if complexity == "simple" else 3 if complexity == "medium" else 5
        }
    
    def _generate_api_payload(self, complexity: str) -> Dict[str, Any]:
        """Generate API payload based on complexity"""
        if complexity == "simple":
            return {"id": random.randint(1, 1000)}
        elif complexity == "medium":
            return {
                "data": {
                    "items": [{"id": i, "value": random.randint(1, 100)} for i in range(10)],
                    "metadata": {"timestamp": time.time(), "source": "load_generator"}
                },
                "options": {"validate": True, "async": False}
            }
        else:  # complex
            return {
                "batch_data": [
                    {
                        "operation": random.choice(["create", "update", "delete"]),
                        "resource": f"resource_{i}",
                        "data": {"value": random.randint(1, 1000), "nested": {"items": list(range(10))}},
                        "dependencies": [f"dep_{j}" for j in range(random.randint(1, 5))]
                    }
                    for i in range(random.randint(5, 20))
                ],
                "workflow": {
                    "steps": [
                        {"name": f"step_{i}", "type": random.choice(["transform", "validate", "process"])}
                        for i in range(random.randint(3, 8))
                    ],
                    "parallel": True,
                    "rollback_on_error": True
                },
                "configuration": {
                    "timeout": 300,
                    "max_retries": 3,
                    "batch_size": 100,
                    "priority": random.choice(["low", "medium", "high"])
                }
            }
    
    async def _operation_processor(self, processor_id: str):
        """Process operations from the queue"""
        logger.debug(f"Starting operation processor: {processor_id}")
        
        while self.running:
            try:
                # Get operation from queue
                operation = await asyncio.wait_for(
                    self.operation_queue.get(),
                    timeout=1.0
                )
                
                # Execute operation
                await self._execute_operation(operation)
                
                # Mark task as done
                self.operation_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Operation processor {processor_id} error: {e}")
                await asyncio.sleep(1.0)
        
        logger.debug(f"Operation processor {processor_id} stopped")
    
    async def _execute_operation(self, operation: ApplicationOperation):
        """Execute a single application operation"""
        operation.start_time = time.time()
        
        try:
            # Check cache first if enabled
            if self.config.cache_usage:
                cache_result = await self._check_cache(operation)
                if cache_result:
                    operation.output_data = cache_result
                    operation.cache_hit = True
                    operation.success = True
                    self.cache_hits += 1
                    operation.end_time = time.time()
                    self._update_operation_stats(operation)
                    self.operation_history.append(operation)
                    return
                else:
                    self.cache_misses += 1
            
            # Execute based on operation type
            if operation.operation_type == "circle_of_experts":
                await self._execute_expert_query(operation)
            elif operation.operation_type == "mcp_operations":
                await self._execute_mcp_operation(operation)
            elif operation.operation_type == "database_queries":
                await self._execute_database_query(operation)
            elif operation.operation_type == "api_calls":
                await self._execute_api_call(operation)
            else:
                # Generic operation
                await self._execute_generic_operation(operation)
            
            operation.success = True
            
            # Cache result if applicable
            if self.config.cache_usage and operation.success:
                await self._cache_result(operation)
            
        except Exception as e:
            operation.error_message = str(e)
            logger.debug(f"Operation {operation.operation_id} failed: {e}")
        
        finally:
            operation.end_time = time.time()
            self._update_operation_stats(operation)
            self.operation_history.append(operation)
            
            # Keep only last 1000 operations
            if len(self.operation_history) > 1000:
                self.operation_history = self.operation_history[-1000:]
    
    async def _check_cache(self, operation: ApplicationOperation) -> Optional[Dict[str, Any]]:
        """Check if operation result is cached"""
        cache_key = self._generate_cache_key(operation)
        
        if cache_key in self.cache:
            cached_item = self.cache[cache_key]
            # Check if cache entry is still valid (TTL)
            if time.time() - cached_item['timestamp'] < 300:  # 5 minute TTL
                return cached_item['data']
            else:
                # Remove expired entry
                del self.cache[cache_key]
        
        return None
    
    async def _cache_result(self, operation: ApplicationOperation):
        """Cache operation result"""
        if operation.output_data:
            cache_key = self._generate_cache_key(operation)
            self.cache[cache_key] = {
                'data': operation.output_data,
                'timestamp': time.time()
            }
            
            # Limit cache size
            if len(self.cache) > 1000:
                # Remove oldest entries
                oldest_keys = sorted(self.cache.keys(), 
                                   key=lambda k: self.cache[k]['timestamp'])[:100]
                for key in oldest_keys:
                    del self.cache[key]
    
    def _generate_cache_key(self, operation: ApplicationOperation) -> str:
        """Generate cache key for operation"""
        key_parts = [
            operation.operation_type,
            str(hash(json.dumps(operation.input_data, sort_keys=True)))
        ]
        return "_".join(key_parts)
    
    async def _execute_expert_query(self, operation: ApplicationOperation):
        """Execute Circle of Experts query"""
        if not self.expert_manager:
            # Simulate expert query without actual integration
            await self._simulate_expert_query(operation)
            return
        
        try:
            input_data = operation.input_data
            query = Query(
                content=input_data["query"],
                context=input_data.get("context", {}),
                metadata={"complexity": input_data["complexity"]}
            )
            
            # Execute query through expert manager
            result = await self.expert_manager.process_query(query)
            
            operation.output_data = {
                "response": result.response if hasattr(result, 'response') else str(result),
                "experts_consulted": getattr(result, 'experts_used', []),
                "confidence": getattr(result, 'confidence', 0.8),
                "processing_time": operation.duration_ms
            }
            
            self.application_stats['expert_queries'] += 1
            
        except Exception as e:
            await self._simulate_expert_query(operation)
            logger.debug(f"Expert query fallback used due to: {e}")
    
    async def _simulate_expert_query(self, operation: ApplicationOperation):
        """Simulate expert query execution"""
        input_data = operation.input_data
        complexity = input_data.get("complexity", "medium")
        
        # Simulate processing time based on complexity
        processing_times = {"simple": (0.5, 2.0), "medium": (2.0, 5.0), "complex": (5.0, 15.0)}
        min_time, max_time = processing_times.get(complexity, (2.0, 5.0))
        await asyncio.sleep(random.uniform(min_time, max_time))
        
        # Generate simulated response
        responses = [
            "Based on the analysis, the recommended approach is to implement a microservices architecture.",
            "The best practice in this scenario is to use containerization with proper orchestration.",
            "Consider implementing a layered security approach with multiple validation points.",
            "For optimal performance, implement caching at multiple levels with appropriate TTL settings.",
            "The solution should include monitoring, alerting, and automated recovery mechanisms."
        ]
        
        operation.output_data = {
            "response": random.choice(responses),
            "experts_consulted": random.sample(["security", "performance", "architecture", "devops"], 
                                            k=random.randint(2, 4)),
            "confidence": random.uniform(0.7, 0.95),
            "simulated": True
        }
        
        self.application_stats['expert_queries'] += 1
    
    async def _execute_mcp_operation(self, operation: ApplicationOperation):
        """Execute MCP operation"""
        if not self.mcp_manager:
            await self._simulate_mcp_operation(operation)
            return
        
        try:
            input_data = operation.input_data
            
            # Execute MCP operation
            result = await self.mcp_manager.execute_operation(
                server_type=input_data["server_type"],
                operation=input_data["operation"],
                parameters=input_data["parameters"]
            )
            
            operation.output_data = {
                "result": result,
                "server_type": input_data["server_type"],
                "operation": input_data["operation"]
            }
            
            self.application_stats['mcp_operations'] += 1
            
        except Exception as e:
            await self._simulate_mcp_operation(operation)
            logger.debug(f"MCP operation fallback used due to: {e}")
    
    async def _simulate_mcp_operation(self, operation: ApplicationOperation):
        """Simulate MCP operation execution"""
        input_data = operation.input_data
        server_type = input_data["server_type"]
        operation_name = input_data["operation"]
        
        # Simulate processing time
        await asyncio.sleep(random.uniform(0.5, 3.0))
        
        # Generate simulated result
        results = {
            "security": {"status": "passed", "vulnerabilities": random.randint(0, 5)},
            "infrastructure": {"health": "healthy", "resources": {"cpu": 45, "memory": 67}},
            "storage": {"status": "completed", "size_gb": random.randint(10, 1000)},
            "communication": {"status": "sent", "recipients": random.randint(1, 50)}
        }
        
        operation.output_data = {
            "result": results.get(server_type, {"status": "completed"}),
            "server_type": server_type,
            "operation": operation_name,
            "simulated": True
        }
        
        self.application_stats['mcp_operations'] += 1
    
    async def _execute_database_query(self, operation: ApplicationOperation):
        """Execute database query"""
        if not self.database_connection:
            await self._simulate_database_query(operation)
            return
        
        try:
            input_data = operation.input_data
            
            # Execute database query
            result = await self.database_connection.execute_query(
                query=input_data["query"],
                parameters=input_data["parameters"],
                options=input_data["options"]
            )
            
            operation.output_data = {
                "result": result,
                "operation": input_data["operation"],
                "affected_rows": getattr(result, 'rowcount', 0)
            }
            
            self.application_stats['database_operations'] += 1
            
        except Exception as e:
            await self._simulate_database_query(operation)
            logger.debug(f"Database query fallback used due to: {e}")
    
    async def _simulate_database_query(self, operation: ApplicationOperation):
        """Simulate database query execution"""
        input_data = operation.input_data
        db_operation = input_data["operation"]
        
        # Simulate query execution time
        await asyncio.sleep(random.uniform(0.1, 1.0))
        
        # Generate simulated result
        if db_operation == "read":
            result = {"rows": [{"id": i, "data": f"row_{i}"} for i in range(random.randint(1, 10))]}
        elif db_operation == "write":
            result = {"inserted_id": random.randint(1000, 9999)}
        elif db_operation == "update":
            result = {"affected_rows": random.randint(1, 5)}
        elif db_operation == "delete":
            result = {"deleted_rows": random.randint(0, 3)}
        else:
            result = {"status": "completed"}
        
        operation.output_data = {
            "result": result,
            "operation": db_operation,
            "simulated": True
        }
        
        self.application_stats['database_operations'] += 1
    
    async def _execute_api_call(self, operation: ApplicationOperation):
        """Execute API call"""
        input_data = operation.input_data
        
        # Simulate API call processing time
        await asyncio.sleep(random.uniform(0.2, 2.0))
        
        # Simulate response based on endpoint
        endpoint = input_data["endpoint"]
        method = input_data["method"]
        
        if "health" in endpoint or "status" in endpoint:
            response = {"status": "healthy", "timestamp": time.time()}
        elif "users" in endpoint:
            response = {"users": [{"id": i, "name": f"user_{i}"} for i in range(5)]}
        elif "orders" in endpoint:
            response = {"orders": [{"id": i, "amount": random.randint(10, 500)} for i in range(3)]}
        else:
            response = {"result": "success", "data": {"processed": True}}
        
        operation.output_data = {
            "response": response,
            "status_code": random.choice([200, 201, 202]) if random.random() > 0.05 else random.choice([400, 404, 500]),
            "api_type": input_data["api_type"],
            "endpoint": endpoint,
            "method": method
        }
        
        self.application_stats['api_calls'] += 1
    
    async def _execute_generic_operation(self, operation: ApplicationOperation):
        """Execute generic operation"""
        # Simulate generic processing
        await asyncio.sleep(random.uniform(0.5, 2.0))
        
        operation.output_data = {
            "status": "completed",
            "operation_type": operation.operation_type,
            "processing_time_ms": operation.duration_ms
        }
    
    def _update_operation_stats(self, operation: ApplicationOperation):
        """Update application statistics"""
        self.application_stats['total_operations'] += 1
        
        if operation.success:
            self.application_stats['successful_operations'] += 1
        else:
            self.application_stats['failed_operations'] += 1
        
        # Update average processing time
        if operation.duration_ms > 0:
            current_avg = self.application_stats['average_processing_time_ms']
            total_ops = self.application_stats['total_operations']
            
            self.application_stats['average_processing_time_ms'] = (
                (current_avg * (total_ops - 1) + operation.duration_ms) / total_ops
            )
        
        # Update cache hit rate
        if self.config.cache_usage:
            total_cache_requests = self.cache_hits + self.cache_misses
            if total_cache_requests > 0:
                self.application_stats['cache_hit_rate'] = self.cache_hits / total_cache_requests
    
    async def _monitor_performance(self):
        """Monitor application performance"""
        last_stats_time = time.time()
        last_operation_count = 0
        
        while self.running:
            try:
                current_time = time.time()
                current_operations = self.application_stats['total_operations']
                
                # Calculate operations per second
                time_diff = current_time - last_stats_time
                if time_diff >= 1.0:
                    operation_diff = current_operations - last_operation_count
                    self.application_stats['operations_per_second'] = operation_diff / time_diff
                    self.application_stats['active_sessions'] = len(self.active_sessions)
                    
                    last_stats_time = current_time
                    last_operation_count = current_operations
                
                # Create performance sample
                sample = {
                    'timestamp': current_time,
                    'operations_per_second': self.application_stats['operations_per_second'],
                    'average_processing_time_ms': self.application_stats['average_processing_time_ms'],
                    'active_sessions': len(self.active_sessions),
                    'queue_size': self.operation_queue.qsize(),
                    'cache_hit_rate': self.application_stats['cache_hit_rate'],
                    'success_rate': (
                        self.application_stats['successful_operations'] / 
                        max(1, self.application_stats['total_operations'])
                    ),
                    'operation_breakdown': {
                        'expert_queries': self.application_stats['expert_queries'],
                        'mcp_operations': self.application_stats['mcp_operations'],
                        'database_operations': self.application_stats['database_operations'],
                        'api_calls': self.application_stats['api_calls']
                    }
                }
                
                self.performance_samples.append(sample)
                
                # Keep only last 1000 samples
                if len(self.performance_samples) > 1000:
                    self.performance_samples = self.performance_samples[-1000:]
                
                await asyncio.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Application performance monitoring error: {e}")
                await asyncio.sleep(5.0)
    
    async def stop(self):
        """Stop the application load generator"""
        logger.info("Stopping application load generator")
        self.running = False
        
        # Cancel worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.worker_tasks:
            await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        
        # End all active sessions
        for session_id in list(self.active_sessions.keys()):
            await self._end_user_session(session_id)
        
        # Clear cache
        self.cache.clear()
        
        logger.info("Application load generator stopped")
    
    async def reduce_intensity(self, factor: float):
        """Reduce application load intensity by a factor"""
        self.target_load = max(0.0, self.target_load * factor)
        logger.info(f"Reduced application load intensity to {self.target_load:.2f}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the application load generator"""
        return {
            'generator_id': 'application_load_generator',
            'generator_type': 'application',
            'status': 'running' if self.running else 'stopped',
            'current_load': self.current_load,
            'target_load': self.target_load,
            'active_sessions': len(self.active_sessions),
            'queue_size': self.operation_queue.qsize() if self.operation_queue else 0,
            'workload_types': self.config.workload_types,
            'concurrent_users': self.config.concurrent_users,
            'integrations_available': INTEGRATIONS_AVAILABLE,
            'metrics': self.application_stats.copy()
        }
    
    def get_application_statistics(self) -> Dict[str, Any]:
        """Get detailed application statistics"""
        if not self.performance_samples:
            return {}
        
        recent_samples = self.performance_samples[-60:]  # Last minute
        
        ops_per_second = [s['operations_per_second'] for s in recent_samples if 'operations_per_second' in s]
        processing_times = [s['average_processing_time_ms'] for s in recent_samples if 'average_processing_time_ms' in s]
        success_rates = [s['success_rate'] for s in recent_samples if 'success_rate' in s]
        cache_hit_rates = [s['cache_hit_rate'] for s in recent_samples if 'cache_hit_rate' in s]
        
        return {
            'performance': {
                'operations_per_second': {
                    'current': ops_per_second[-1] if ops_per_second else 0,
                    'average': np.mean(ops_per_second) if ops_per_second else 0,
                    'max': np.max(ops_per_second) if ops_per_second else 0
                },
                'processing_time_ms': {
                    'current': processing_times[-1] if processing_times else 0,
                    'average': np.mean(processing_times) if processing_times else 0,
                    'max': np.max(processing_times) if processing_times else 0
                },
                'success_rate': {
                    'current': success_rates[-1] if success_rates else 0,
                    'average': np.mean(success_rates) if success_rates else 0,
                    'min': np.min(success_rates) if success_rates else 0
                }
            },
            'caching': {
                'hit_rate': {
                    'current': cache_hit_rates[-1] if cache_hit_rates else 0,
                    'average': np.mean(cache_hit_rates) if cache_hit_rates else 0
                },
                'cache_size': len(self.cache),
                'total_hits': self.cache_hits,
                'total_misses': self.cache_misses
            },
            'sessions': {
                'active_sessions': len(self.active_sessions),
                'total_sessions_created': self.session_counter,
                'average_session_duration': self._calculate_average_session_duration(),
                'session_types': self._get_session_type_distribution()
            },
            'operations': {
                'total': self.application_stats['total_operations'],
                'by_type': {
                    'expert_queries': self.application_stats['expert_queries'],
                    'mcp_operations': self.application_stats['mcp_operations'],
                    'database_operations': self.application_stats['database_operations'],
                    'api_calls': self.application_stats['api_calls']
                }
            }
        }
    
    def _calculate_average_session_duration(self) -> float:
        """Calculate average session duration"""
        if not self.active_sessions:
            return 0.0
        
        current_time = time.time()
        durations = [current_time - session.start_time for session in self.active_sessions.values()]
        return np.mean(durations) if durations else 0.0
    
    def _get_session_type_distribution(self) -> Dict[str, int]:
        """Get distribution of session types"""
        type_counts = {}
        for session in self.active_sessions.values():
            user_type = session.user_profile.get('user_type', 'unknown')
            type_counts[user_type] = type_counts.get(user_type, 0) + 1
        return type_counts


# Example usage
async def example_usage():
    """Example usage of ApplicationLoadGenerator"""
    config = ApplicationLoadConfiguration(
        workload_types=["circle_of_experts", "mcp_operations", "database_queries", "api_calls"],
        concurrent_users=5,
        user_session_duration=180,
        expert_query_complexity="medium",
        business_logic_complexity="realistic",
        cache_usage=True,
        authentication_required=True
    )
    
    generator = ApplicationLoadGenerator(config)
    
    # Create a simple test pattern
    from patterns.pattern_engine import PatternEngine
    
    pattern_engine = PatternEngine()
    pattern = pattern_engine.generate_pattern("realistic", 120, 0.7, {"profile": "web_traffic"})
    
    # Execute pattern
    await generator.execute_pattern(pattern)
    
    # Get status and statistics
    status = generator.get_status()
    stats = generator.get_application_statistics()
    
    print(f"Application Generator Status: {status}")
    print(f"Application Statistics: {stats}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(example_usage())