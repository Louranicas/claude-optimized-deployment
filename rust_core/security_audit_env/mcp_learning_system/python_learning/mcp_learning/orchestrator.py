"""
Learning Orchestrator for MCP Learning System

Coordinates learning algorithms, manages workflows, and handles resource allocation.
"""

import asyncio
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import numpy as np
from celery import Celery, Task
from celery.result import AsyncResult
import redis
import structlog
from prometheus_client import Counter, Gauge, Histogram, Summary
import psutil
from concurrent.futures import ThreadPoolExecutor

from .algorithms import OnlineLearner, PatternRecognizer, AdaptationEngine, LearningMetrics
from .shared_memory import SharedMemoryInterface

logger = structlog.get_logger(__name__)

# Metrics
learning_tasks_total = Counter("mcp_learning_tasks_total", "Total learning tasks", ["task_type"])
learning_task_duration = Histogram("mcp_learning_task_duration_seconds", "Learning task duration", ["task_type"])
active_learners = Gauge("mcp_active_learners", "Number of active learners")
memory_usage_bytes = Gauge("mcp_learning_memory_bytes", "Memory usage in bytes")
model_accuracy = Gauge("mcp_model_accuracy", "Current model accuracy", ["model_id"])


class TaskStatus(Enum):
    """Learning task status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class LearningTask:
    """Represents a learning task"""
    task_id: str
    task_type: str
    status: TaskStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowStep:
    """Step in a learning workflow"""
    step_id: str
    step_type: str
    function: Callable
    inputs: Dict[str, Any]
    outputs: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING


class WorkflowManager:
    """Manages learning workflows"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.workflows: Dict[str, List[WorkflowStep]] = {}
        self.workflow_results: Dict[str, Dict[str, Any]] = {}
        self._executor = ThreadPoolExecutor(max_workers=config.get("max_workers", 4))
    
    def create_workflow(self, workflow_id: str, steps: List[WorkflowStep]) -> None:
        """Create a new workflow"""
        self.workflows[workflow_id] = steps
        self.workflow_results[workflow_id] = {}
        logger.info("Created workflow", workflow_id=workflow_id, steps=len(steps))
    
    async def execute_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Execute a workflow"""
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow not found: {workflow_id}")
        
        steps = self.workflows[workflow_id]
        results = {}
        
        # Build dependency graph
        completed = set()
        
        while len(completed) < len(steps):
            # Find steps ready to execute
            ready_steps = [
                step for step in steps
                if step.status == TaskStatus.PENDING and
                all(dep in completed for dep in step.dependencies)
            ]
            
            if not ready_steps:
                # Check for circular dependencies
                pending = [s for s in steps if s.status != TaskStatus.COMPLETED]
                if pending:
                    raise RuntimeError(f"Circular dependency detected in workflow {workflow_id}")
                break
            
            # Execute ready steps in parallel
            tasks = []
            for step in ready_steps:
                step.status = TaskStatus.RUNNING
                task = asyncio.create_task(self._execute_step(step, results))
                tasks.append((step, task))
            
            # Wait for completion
            for step, task in tasks:
                try:
                    result = await task
                    results[step.step_id] = result
                    step.outputs = result
                    step.status = TaskStatus.COMPLETED
                    completed.add(step.step_id)
                except Exception as e:
                    logger.error("Step failed", step_id=step.step_id, error=str(e))
                    step.status = TaskStatus.FAILED
                    raise
        
        self.workflow_results[workflow_id] = results
        return results
    
    async def _execute_step(self, step: WorkflowStep, previous_results: Dict[str, Any]) -> Any:
        """Execute a single workflow step"""
        # Prepare inputs with results from dependencies
        inputs = step.inputs.copy()
        for dep in step.dependencies:
            if dep in previous_results:
                inputs[f"{dep}_result"] = previous_results[dep]
        
        # Execute function
        if asyncio.iscoroutinefunction(step.function):
            return await step.function(**inputs)
        else:
            return await asyncio.get_event_loop().run_in_executor(
                self._executor, step.function, **inputs
            )
    
    def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get workflow status"""
        if workflow_id not in self.workflows:
            return {"status": "not_found"}
        
        steps = self.workflows[workflow_id]
        status_counts = {}
        for step in steps:
            if step.status.value not in status_counts:
                status_counts[step.status.value] = 0
            status_counts[step.status.value] += 1
        
        return {
            "workflow_id": workflow_id,
            "total_steps": len(steps),
            "status_counts": status_counts,
            "results": self.workflow_results.get(workflow_id, {})
        }


class LearningOrchestrator:
    """Main orchestrator for the learning system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Initialize Celery
        self.celery = Celery(
            "mcp_learning",
            broker=config.get("broker_url", "redis://localhost:6379/0"),
            backend=config.get("backend_url", "redis://localhost:6379/0")
        )
        
        # Components
        self.online_learner = OnlineLearner(config.get("online_learner", {}))
        self.pattern_recognizer = PatternRecognizer(config.get("pattern_recognizer", {}))
        self.adaptation_engine = AdaptationEngine(config.get("adaptation_engine", {}))
        self.workflow_manager = WorkflowManager(config.get("workflow_manager", {}))
        
        # Shared memory interface
        self.shared_memory = SharedMemoryInterface(
            config.get("shared_memory_path", "/tmp/mcp_learning_shared.mem")
        )
        
        # Task tracking
        self.active_tasks: Dict[str, LearningTask] = {}
        self.task_history: List[LearningTask] = []
        
        # Resource monitoring
        self._monitor_task: Optional[asyncio.Task] = None
        self._shutdown = asyncio.Event()
        
        # Register Celery tasks
        self._register_celery_tasks()
    
    def _register_celery_tasks(self) -> None:
        """Register Celery tasks"""
        
        @self.celery.task(name="mcp_learning.train_model")
        def train_model_task(data: List[float], labels: Optional[List[float]] = None) -> Dict[str, Any]:
            """Celery task for model training"""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            data_array = np.array(data).reshape(-1, self.online_learner.feature_dim)
            labels_array = np.array(labels).reshape(-1, self.online_learner.feature_dim) if labels else None
            
            metrics = loop.run_until_complete(
                self.online_learner.train(data_array, labels_array)
            )
            
            return {
                "accuracy": metrics.accuracy,
                "loss": metrics.loss,
                "training_time": metrics.training_time,
                "sample_count": metrics.sample_count
            }
        
        @self.celery.task(name="mcp_learning.analyze_patterns")
        def analyze_patterns_task(sequence: List[List[float]]) -> Dict[str, Any]:
            """Celery task for pattern analysis"""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            sequence_array = np.array(sequence)
            patterns = loop.run_until_complete(
                self.pattern_recognizer.analyze_sequence(sequence_array)
            )
            
            return {
                "patterns": [
                    {
                        "pattern_id": p.pattern_id,
                        "pattern_type": p.pattern_type,
                        "frequency": p.frequency,
                        "confidence": p.confidence
                    }
                    for p in patterns
                ],
                "summary": self.pattern_recognizer.get_pattern_summary()
            }
    
    async def start(self) -> None:
        """Start the orchestrator"""
        logger.info("Starting learning orchestrator")
        
        # Connect to shared memory
        self.shared_memory.connect()
        
        # Start resource monitoring
        self._monitor_task = asyncio.create_task(self._monitor_resources())
        
        # Start message consumer
        await self.shared_memory.message_queue.start_consumer()
        
        # Subscribe to training data
        self.shared_memory.message_queue.subscribe(self._handle_training_data)
        
        active_learners.inc()
        logger.info("Learning orchestrator started")
    
    async def stop(self) -> None:
        """Stop the orchestrator"""
        logger.info("Stopping learning orchestrator")
        
        # Signal shutdown
        self._shutdown.set()
        
        # Stop message consumer
        await self.shared_memory.message_queue.stop_consumer()
        
        # Wait for monitor task
        if self._monitor_task:
            await self._monitor_task
        
        # Disconnect from shared memory
        self.shared_memory.disconnect()
        
        active_learners.dec()
        logger.info("Learning orchestrator stopped")
    
    async def submit_learning_task(
        self,
        task_type: str,
        data: Union[np.ndarray, List],
        **kwargs
    ) -> str:
        """Submit a learning task"""
        task_id = f"{task_type}_{datetime.utcnow().timestamp()}"
        
        task = LearningTask(
            task_id=task_id,
            task_type=task_type,
            status=TaskStatus.PENDING,
            created_at=datetime.utcnow(),
            metadata=kwargs
        )
        
        self.active_tasks[task_id] = task
        learning_tasks_total.labels(task_type=task_type).inc()
        
        # Route to appropriate handler
        if task_type == "train":
            asyncio.create_task(self._handle_train_task(task, data, kwargs))
        elif task_type == "analyze":
            asyncio.create_task(self._handle_analyze_task(task, data, kwargs))
        elif task_type == "adapt":
            asyncio.create_task(self._handle_adapt_task(task, data, kwargs))
        else:
            task.status = TaskStatus.FAILED
            task.error = f"Unknown task type: {task_type}"
        
        return task_id
    
    async def _handle_train_task(
        self,
        task: LearningTask,
        data: Union[np.ndarray, List],
        kwargs: Dict[str, Any]
    ) -> None:
        """Handle training task"""
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.utcnow()
        
        try:
            with learning_task_duration.labels(task_type="train").time():
                # Convert data if needed
                if isinstance(data, list):
                    data = np.array(data)
                
                labels = kwargs.get("labels")
                if labels is not None and isinstance(labels, list):
                    labels = np.array(labels)
                
                # Train model
                metrics = await self.online_learner.train(data, labels)
                
                # Update metrics
                model_accuracy.labels(model_id="online_learner").set(metrics.accuracy)
                
                # Cache model
                model_data = self.online_learner.save()
                self.shared_memory.cache_model("online_learner_latest", model_data)
                
                # Send update
                await self.shared_memory.send_learning_update({
                    "model_id": "online_learner",
                    "metrics": {
                        "accuracy": metrics.accuracy,
                        "loss": metrics.loss,
                        "training_time": metrics.training_time
                    },
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                task.result = metrics
                task.status = TaskStatus.COMPLETED
                
        except Exception as e:
            logger.error("Training task failed", task_id=task.task_id, error=str(e))
            task.status = TaskStatus.FAILED
            task.error = str(e)
        
        finally:
            task.completed_at = datetime.utcnow()
            self.task_history.append(task)
            del self.active_tasks[task.task_id]
    
    async def _handle_analyze_task(
        self,
        task: LearningTask,
        data: Union[np.ndarray, List],
        kwargs: Dict[str, Any]
    ) -> None:
        """Handle pattern analysis task"""
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.utcnow()
        
        try:
            with learning_task_duration.labels(task_type="analyze").time():
                # Convert data if needed
                if isinstance(data, list):
                    data = np.array(data)
                
                # Analyze patterns
                patterns = await self.pattern_recognizer.analyze_sequence(data)
                
                # Detect anomalies
                anomalies, anomaly_score = await self.pattern_recognizer.detect_anomalies(data)
                
                result = {
                    "patterns": patterns,
                    "anomaly_score": anomaly_score,
                    "summary": self.pattern_recognizer.get_pattern_summary()
                }
                
                task.result = result
                task.status = TaskStatus.COMPLETED
                
        except Exception as e:
            logger.error("Analysis task failed", task_id=task.task_id, error=str(e))
            task.status = TaskStatus.FAILED
            task.error = str(e)
        
        finally:
            task.completed_at = datetime.utcnow()
            self.task_history.append(task)
            del self.active_tasks[task.task_id]
    
    async def _handle_adapt_task(
        self,
        task: LearningTask,
        data: Union[Dict[str, Any], List],
        kwargs: Dict[str, Any]
    ) -> None:
        """Handle adaptation task"""
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.utcnow()
        
        try:
            with learning_task_duration.labels(task_type="adapt").time():
                patterns = data.get("patterns", [])
                metrics = data.get("metrics", {})
                
                # Generate adaptations
                adaptations = await self.adaptation_engine.generate_adaptations(
                    patterns, metrics
                )
                
                # Apply high-confidence adaptations
                applied = []
                for adaptation in adaptations:
                    if adaptation.confidence > 0.8:
                        self.adaptation_engine.apply_adaptation(adaptation)
                        applied.append(adaptation)
                
                result = {
                    "generated": len(adaptations),
                    "applied": len(applied),
                    "adaptations": adaptations,
                    "summary": self.adaptation_engine.get_adaptation_summary()
                }
                
                task.result = result
                task.status = TaskStatus.COMPLETED
                
        except Exception as e:
            logger.error("Adaptation task failed", task_id=task.task_id, error=str(e))
            task.status = TaskStatus.FAILED
            task.error = str(e)
        
        finally:
            task.completed_at = datetime.utcnow()
            self.task_history.append(task)
            del self.active_tasks[task.task_id]
    
    async def _handle_training_data(self, message: Dict[str, Any]) -> None:
        """Handle incoming training data from shared memory"""
        if message.get("type") == "training_data":
            data = message.get("data", {})
            
            # Submit training task
            await self.submit_learning_task(
                "train",
                data.get("features", []),
                labels=data.get("labels")
            )
    
    async def _monitor_resources(self) -> None:
        """Monitor resource usage"""
        while not self._shutdown.is_set():
            try:
                # Get memory usage
                process = psutil.Process()
                memory_info = process.memory_info()
                memory_usage_bytes.set(memory_info.rss)
                
                # Log statistics
                logger.info(
                    "Resource usage",
                    memory_mb=memory_info.rss / 1024 / 1024,
                    active_tasks=len(self.active_tasks),
                    completed_tasks=len(self.task_history)
                )
                
            except Exception as e:
                logger.error("Resource monitoring error", error=str(e))
            
            await asyncio.sleep(30)  # Monitor every 30 seconds
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a learning task"""
        # Check active tasks
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            return {
                "task_id": task.task_id,
                "status": task.status.value,
                "created_at": task.created_at.isoformat(),
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "metadata": task.metadata
            }
        
        # Check history
        for task in self.task_history:
            if task.task_id == task_id:
                return {
                    "task_id": task.task_id,
                    "status": task.status.value,
                    "created_at": task.created_at.isoformat(),
                    "started_at": task.started_at.isoformat() if task.started_at else None,
                    "completed_at": task.completed_at.isoformat() if task.completed_at else None,
                    "result": task.result,
                    "error": task.error,
                    "metadata": task.metadata
                }
        
        return None
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        return {
            "active_tasks": len(self.active_tasks),
            "completed_tasks": len(self.task_history),
            "model_trained": self.online_learner.is_trained,
            "total_samples": self.online_learner.total_samples,
            "patterns_detected": len(self.pattern_recognizer.patterns),
            "adaptations_applied": len(self.adaptation_engine.adaptation_history),
            "memory_usage_mb": psutil.Process().memory_info().rss / 1024 / 1024
        }