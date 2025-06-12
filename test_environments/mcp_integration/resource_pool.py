"""
Distributed Resource Management - Shared resource allocation and monitoring.
Manages compute, memory, network, and storage resources across MCP test nodes.
"""

import asyncio
import json
import logging
import psutil
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
import aiohttp
import websockets
from concurrent.futures import ThreadPoolExecutor
import threading
import queue

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ResourceType(Enum):
    """Resource type enumeration"""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    GPU = "gpu"
    CUSTOM = "custom"


class ResourceState(Enum):
    """Resource state enumeration"""
    AVAILABLE = "available"
    ALLOCATED = "allocated"
    RESERVED = "reserved"
    UNAVAILABLE = "unavailable"
    MAINTENANCE = "maintenance"


class AllocationStrategy(Enum):
    """Resource allocation strategies"""
    FIRST_FIT = "first_fit"
    BEST_FIT = "best_fit"
    WORST_FIT = "worst_fit"
    BALANCED = "balanced"
    LOCALITY_AWARE = "locality_aware"


@dataclass
class ResourceSpec:
    """Resource specification"""
    resource_type: ResourceType
    amount: float
    unit: str
    attributes: Dict[str, Any] = None


@dataclass
class ResourceInstance:
    """Individual resource instance"""
    resource_id: str
    node_id: str
    resource_type: ResourceType
    total_capacity: float
    available_capacity: float
    allocated_capacity: float
    reserved_capacity: float
    unit: str
    state: ResourceState
    attributes: Dict[str, Any] = None
    last_updated: datetime = None
    allocations: List[str] = None  # List of allocation IDs


@dataclass
class ResourceAllocation:
    """Resource allocation record"""
    allocation_id: str
    requester_id: str
    resources: List[ResourceSpec]
    assigned_resources: Dict[str, ResourceInstance] = None
    allocation_time: datetime = None
    expiry_time: Optional[datetime] = None
    priority: int = 1
    tags: Set[str] = None
    metadata: Dict[str, Any] = None


@dataclass
class NodeResources:
    """Node resource summary"""
    node_id: str
    host: str
    port: int
    last_heartbeat: datetime
    cpu_cores: int
    cpu_usage: float
    memory_total: float
    memory_used: float
    memory_available: float
    disk_total: float
    disk_used: float
    disk_available: float
    network_bandwidth: float
    network_usage: float
    gpu_count: int = 0
    gpu_memory: float = 0
    custom_resources: Dict[str, float] = None
    load_average: float = 0.0
    temperature: float = 0.0


class ResourceMonitor:
    """Resource monitoring and metrics collection"""
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.running = False
        self.metrics_history: List[Dict[str, Any]] = []
        self.max_history_size = 1000
        self.collection_interval = 5.0

    async def start_monitoring(self):
        """Start resource monitoring"""
        self.running = True
        logger.info(f"Starting resource monitoring for node {self.node_id}")
        
        while self.running:
            try:
                metrics = await self.collect_metrics()
                
                # Store metrics
                self.metrics_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "metrics": metrics
                })
                
                # Trim history if needed
                if len(self.metrics_history) > self.max_history_size:
                    self.metrics_history = self.metrics_history[-self.max_history_size:]
                
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
                await asyncio.sleep(self.collection_interval)

    async def collect_metrics(self) -> Dict[str, Any]:
        """Collect current resource metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            load_avg = psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0.0
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            network = psutil.net_io_counters()
            
            # Process metrics
            process_count = len(psutil.pids())
            
            metrics = {
                "node_id": self.node_id,
                "cpu": {
                    "cores": cpu_count,
                    "usage_percent": cpu_percent,
                    "load_average": load_avg
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used,
                    "percent": memory.percent
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": (disk.used / disk.total) * 100
                },
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv
                },
                "processes": {
                    "count": process_count
                },
                "timestamp": datetime.now().isoformat()
            }
            
            # Add GPU metrics if available
            try:
                import GPUtil
                gpus = GPUtil.getGPUs()
                if gpus:
                    gpu_metrics = []
                    for gpu in gpus:
                        gpu_metrics.append({
                            "id": gpu.id,
                            "name": gpu.name,
                            "load": gpu.load * 100,
                            "memory_used": gpu.memoryUsed,
                            "memory_total": gpu.memoryTotal,
                            "memory_percent": (gpu.memoryUsed / gpu.memoryTotal) * 100,
                            "temperature": gpu.temperature
                        })
                    metrics["gpu"] = gpu_metrics
            except ImportError:
                pass
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return {}

    def get_current_metrics(self) -> Dict[str, Any]:
        """Get most recent metrics"""
        if self.metrics_history:
            return self.metrics_history[-1]
        return {}

    def get_metrics_history(self, duration: timedelta = None) -> List[Dict[str, Any]]:
        """Get metrics history for specified duration"""
        if not duration:
            return self.metrics_history
        
        cutoff_time = datetime.now() - duration
        filtered_metrics = []
        
        for entry in self.metrics_history:
            timestamp = datetime.fromisoformat(entry["timestamp"])
            if timestamp >= cutoff_time:
                filtered_metrics.append(entry)
        
        return filtered_metrics

    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.running = False


class ResourceManager:
    """Manages resource allocation and optimization across nodes"""
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.resources: Dict[str, ResourceInstance] = {}
        self.allocations: Dict[str, ResourceAllocation] = {}
        self.node_resources: Dict[str, NodeResources] = {}
        self.allocation_strategy = AllocationStrategy.BALANCED
        self.monitor = ResourceMonitor(node_id)
        self.lock = asyncio.Lock()

    async def initialize_resources(self):
        """Initialize local node resources"""
        try:
            # Collect initial metrics
            metrics = await self.monitor.collect_metrics()
            
            # Create CPU resource
            cpu_resource = ResourceInstance(
                resource_id=f"{self.node_id}_cpu",
                node_id=self.node_id,
                resource_type=ResourceType.CPU,
                total_capacity=float(metrics["cpu"]["cores"]),
                available_capacity=float(metrics["cpu"]["cores"]),
                allocated_capacity=0.0,
                reserved_capacity=0.0,
                unit="cores",
                state=ResourceState.AVAILABLE,
                attributes={"load_average": metrics["cpu"]["load_average"]},
                last_updated=datetime.now(),
                allocations=[]
            )
            self.resources[cpu_resource.resource_id] = cpu_resource
            
            # Create Memory resource
            memory_resource = ResourceInstance(
                resource_id=f"{self.node_id}_memory",
                node_id=self.node_id,
                resource_type=ResourceType.MEMORY,
                total_capacity=float(metrics["memory"]["total"]),
                available_capacity=float(metrics["memory"]["available"]),
                allocated_capacity=0.0,
                reserved_capacity=0.0,
                unit="bytes",
                state=ResourceState.AVAILABLE,
                last_updated=datetime.now(),
                allocations=[]
            )
            self.resources[memory_resource.resource_id] = memory_resource
            
            # Create Disk resource
            disk_resource = ResourceInstance(
                resource_id=f"{self.node_id}_disk",
                node_id=self.node_id,
                resource_type=ResourceType.DISK,
                total_capacity=float(metrics["disk"]["total"]),
                available_capacity=float(metrics["disk"]["free"]),
                allocated_capacity=0.0,
                reserved_capacity=0.0,
                unit="bytes",
                state=ResourceState.AVAILABLE,
                last_updated=datetime.now(),
                allocations=[]
            )
            self.resources[disk_resource.resource_id] = disk_resource
            
            # Create Network resource (estimated bandwidth)
            network_resource = ResourceInstance(
                resource_id=f"{self.node_id}_network",
                node_id=self.node_id,
                resource_type=ResourceType.NETWORK,
                total_capacity=1000.0,  # 1Gbps default
                available_capacity=1000.0,
                allocated_capacity=0.0,
                reserved_capacity=0.0,
                unit="mbps",
                state=ResourceState.AVAILABLE,
                last_updated=datetime.now(),
                allocations=[]
            )
            self.resources[network_resource.resource_id] = network_resource
            
            # Add GPU resources if available
            if "gpu" in metrics:
                for i, gpu_info in enumerate(metrics["gpu"]):
                    gpu_resource = ResourceInstance(
                        resource_id=f"{self.node_id}_gpu_{i}",
                        node_id=self.node_id,
                        resource_type=ResourceType.GPU,
                        total_capacity=float(gpu_info["memory_total"]),
                        available_capacity=float(gpu_info["memory_total"] - gpu_info["memory_used"]),
                        allocated_capacity=0.0,
                        reserved_capacity=0.0,
                        unit="mb",
                        state=ResourceState.AVAILABLE,
                        attributes={
                            "gpu_id": gpu_info["id"],
                            "gpu_name": gpu_info["name"],
                            "compute_capability": gpu_info.get("compute_capability")
                        },
                        last_updated=datetime.now(),
                        allocations=[]
                    )
                    self.resources[gpu_resource.resource_id] = gpu_resource
            
            logger.info(f"Initialized {len(self.resources)} resources for node {self.node_id}")
            
        except Exception as e:
            logger.error(f"Error initializing resources: {e}")

    async def update_resource_metrics(self):
        """Update resource metrics from monitoring"""
        try:
            metrics = self.monitor.get_current_metrics()
            if not metrics:
                return
            
            current_time = datetime.now()
            
            # Update CPU resource
            cpu_resource_id = f"{self.node_id}_cpu"
            if cpu_resource_id in self.resources:
                cpu_resource = self.resources[cpu_resource_id]
                cpu_usage = metrics["metrics"]["cpu"]["usage_percent"] / 100.0
                cpu_resource.available_capacity = cpu_resource.total_capacity * (1.0 - cpu_usage)
                cpu_resource.last_updated = current_time
                cpu_resource.attributes["load_average"] = metrics["metrics"]["cpu"]["load_average"]
            
            # Update Memory resource
            memory_resource_id = f"{self.node_id}_memory"
            if memory_resource_id in self.resources:
                memory_resource = self.resources[memory_resource_id]
                memory_resource.available_capacity = float(metrics["metrics"]["memory"]["available"])
                memory_resource.last_updated = current_time
            
            # Update Disk resource
            disk_resource_id = f"{self.node_id}_disk"
            if disk_resource_id in self.resources:
                disk_resource = self.resources[disk_resource_id]
                disk_resource.available_capacity = float(metrics["metrics"]["disk"]["free"])
                disk_resource.last_updated = current_time
            
            # Update GPU resources
            if "gpu" in metrics["metrics"]:
                for i, gpu_info in enumerate(metrics["metrics"]["gpu"]):
                    gpu_resource_id = f"{self.node_id}_gpu_{i}"
                    if gpu_resource_id in self.resources:
                        gpu_resource = self.resources[gpu_resource_id]
                        gpu_resource.available_capacity = float(
                            gpu_info["memory_total"] - gpu_info["memory_used"]
                        )
                        gpu_resource.last_updated = current_time
                        gpu_resource.attributes.update({
                            "load_percent": gpu_info["load"],
                            "temperature": gpu_info["temperature"]
                        })
            
        except Exception as e:
            logger.error(f"Error updating resource metrics: {e}")

    async def allocate_resources(self, allocation_request: ResourceAllocation) -> bool:
        """Allocate resources based on request"""
        async with self.lock:
            try:
                # Check if resources are available
                assigned_resources = {}
                
                for resource_spec in allocation_request.resources:
                    suitable_resource = await self._find_suitable_resource(resource_spec)
                    
                    if not suitable_resource:
                        logger.warning(f"No suitable resource found for {resource_spec.resource_type}")
                        return False
                    
                    # Check if resource has enough capacity
                    if suitable_resource.available_capacity < resource_spec.amount:
                        logger.warning(f"Insufficient capacity for {resource_spec.resource_type}")
                        return False
                    
                    assigned_resources[resource_spec.resource_type.value] = suitable_resource
                
                # Allocate resources
                for resource_spec in allocation_request.resources:
                    resource = assigned_resources[resource_spec.resource_type.value]
                    resource.allocated_capacity += resource_spec.amount
                    resource.available_capacity -= resource_spec.amount
                    
                    if resource.allocations is None:
                        resource.allocations = []
                    resource.allocations.append(allocation_request.allocation_id)
                    
                    resource.last_updated = datetime.now()
                
                # Store allocation
                allocation_request.assigned_resources = assigned_resources
                allocation_request.allocation_time = datetime.now()
                self.allocations[allocation_request.allocation_id] = allocation_request
                
                logger.info(f"Successfully allocated resources for {allocation_request.allocation_id}")
                return True
                
            except Exception as e:
                logger.error(f"Error allocating resources: {e}")
                return False

    async def _find_suitable_resource(self, resource_spec: ResourceSpec) -> Optional[ResourceInstance]:
        """Find suitable resource for specification"""
        suitable_resources = []
        
        for resource in self.resources.values():
            if (resource.resource_type == resource_spec.resource_type and
                resource.state == ResourceState.AVAILABLE and
                resource.available_capacity >= resource_spec.amount):
                
                # Check attributes if specified
                if resource_spec.attributes:
                    if not resource.attributes:
                        continue
                    
                    matches = True
                    for attr_key, attr_value in resource_spec.attributes.items():
                        if (attr_key not in resource.attributes or
                            resource.attributes[attr_key] != attr_value):
                            matches = False
                            break
                    
                    if not matches:
                        continue
                
                suitable_resources.append(resource)
        
        if not suitable_resources:
            return None
        
        # Apply allocation strategy
        if self.allocation_strategy == AllocationStrategy.FIRST_FIT:
            return suitable_resources[0]
        elif self.allocation_strategy == AllocationStrategy.BEST_FIT:
            # Find resource with least available capacity
            return min(suitable_resources, key=lambda r: r.available_capacity)
        elif self.allocation_strategy == AllocationStrategy.WORST_FIT:
            # Find resource with most available capacity
            return max(suitable_resources, key=lambda r: r.available_capacity)
        elif self.allocation_strategy == AllocationStrategy.BALANCED:
            # Find resource with lowest utilization
            return min(suitable_resources, 
                      key=lambda r: r.allocated_capacity / r.total_capacity)
        else:
            return suitable_resources[0]

    async def deallocate_resources(self, allocation_id: str) -> bool:
        """Deallocate resources"""
        async with self.lock:
            try:
                if allocation_id not in self.allocations:
                    logger.warning(f"Allocation {allocation_id} not found")
                    return False
                
                allocation = self.allocations[allocation_id]
                
                # Deallocate each resource
                for resource_spec in allocation.resources:
                    if resource_spec.resource_type.value in allocation.assigned_resources:
                        resource = allocation.assigned_resources[resource_spec.resource_type.value]
                        
                        # Update resource capacity
                        resource.allocated_capacity -= resource_spec.amount
                        resource.available_capacity += resource_spec.amount
                        
                        # Remove allocation ID
                        if resource.allocations and allocation_id in resource.allocations:
                            resource.allocations.remove(allocation_id)
                        
                        resource.last_updated = datetime.now()
                
                # Remove allocation record
                del self.allocations[allocation_id]
                
                logger.info(f"Successfully deallocated resources for {allocation_id}")
                return True
                
            except Exception as e:
                logger.error(f"Error deallocating resources: {e}")
                return False

    async def reserve_resources(self, allocation_request: ResourceAllocation, 
                              duration: timedelta) -> bool:
        """Reserve resources for future allocation"""
        async with self.lock:
            try:
                # Similar to allocate but mark as reserved
                assigned_resources = {}
                
                for resource_spec in allocation_request.resources:
                    suitable_resource = await self._find_suitable_resource(resource_spec)
                    
                    if not suitable_resource:
                        return False
                    
                    if suitable_resource.available_capacity < resource_spec.amount:
                        return False
                    
                    assigned_resources[resource_spec.resource_type.value] = suitable_resource
                
                # Reserve resources
                for resource_spec in allocation_request.resources:
                    resource = assigned_resources[resource_spec.resource_type.value]
                    resource.reserved_capacity += resource_spec.amount
                    resource.available_capacity -= resource_spec.amount
                    
                    if resource.allocations is None:
                        resource.allocations = []
                    resource.allocations.append(allocation_request.allocation_id)
                    
                    resource.last_updated = datetime.now()
                
                # Store reservation
                allocation_request.assigned_resources = assigned_resources
                allocation_request.allocation_time = datetime.now()
                allocation_request.expiry_time = datetime.now() + duration
                self.allocations[allocation_request.allocation_id] = allocation_request
                
                logger.info(f"Successfully reserved resources for {allocation_request.allocation_id}")
                return True
                
            except Exception as e:
                logger.error(f"Error reserving resources: {e}")
                return False

    async def cleanup_expired_allocations(self):
        """Clean up expired resource allocations"""
        current_time = datetime.now()
        expired_allocations = []
        
        for allocation_id, allocation in self.allocations.items():
            if (allocation.expiry_time and 
                current_time > allocation.expiry_time):
                expired_allocations.append(allocation_id)
        
        for allocation_id in expired_allocations:
            await self.deallocate_resources(allocation_id)
            logger.info(f"Cleaned up expired allocation {allocation_id}")

    def get_resource_utilization(self) -> Dict[str, Any]:
        """Get current resource utilization summary"""
        utilization = {}
        
        for resource_id, resource in self.resources.items():
            utilization_percent = 0.0
            if resource.total_capacity > 0:
                utilization_percent = (resource.allocated_capacity / resource.total_capacity) * 100
            
            utilization[resource_id] = {
                "resource_type": resource.resource_type.value,
                "total_capacity": resource.total_capacity,
                "allocated_capacity": resource.allocated_capacity,
                "available_capacity": resource.available_capacity,
                "reserved_capacity": resource.reserved_capacity,
                "utilization_percent": utilization_percent,
                "unit": resource.unit,
                "state": resource.state.value,
                "active_allocations": len(resource.allocations) if resource.allocations else 0
            }
        
        return utilization

    def get_allocation_info(self, allocation_id: str) -> Optional[Dict[str, Any]]:
        """Get allocation information"""
        if allocation_id in self.allocations:
            allocation = self.allocations[allocation_id]
            return {
                "allocation_id": allocation.allocation_id,
                "requester_id": allocation.requester_id,
                "allocation_time": allocation.allocation_time.isoformat() if allocation.allocation_time else None,
                "expiry_time": allocation.expiry_time.isoformat() if allocation.expiry_time else None,
                "priority": allocation.priority,
                "resources": [asdict(res) for res in allocation.resources],
                "assigned_resources": {
                    k: asdict(v) for k, v in allocation.assigned_resources.items()
                } if allocation.assigned_resources else None,
                "tags": list(allocation.tags) if allocation.tags else [],
                "metadata": allocation.metadata or {}
            }
        return None


class DistributedResourcePool:
    """Distributed resource pool coordinator"""
    
    def __init__(self, pool_id: str, coordinator_node: str):
        self.pool_id = pool_id
        self.coordinator_node = coordinator_node
        self.node_managers: Dict[str, ResourceManager] = {}
        self.global_allocations: Dict[str, ResourceAllocation] = {}
        self.running = False

    async def add_node(self, node_id: str, resource_manager: ResourceManager):
        """Add node to resource pool"""
        self.node_managers[node_id] = resource_manager
        await resource_manager.initialize_resources()
        logger.info(f"Added node {node_id} to resource pool {self.pool_id}")

    async def remove_node(self, node_id: str):
        """Remove node from resource pool"""
        if node_id in self.node_managers:
            # Deallocate all resources from this node
            node_manager = self.node_managers[node_id]
            
            # Find allocations on this node
            node_allocations = []
            for allocation_id, allocation in self.global_allocations.items():
                if (allocation.assigned_resources and 
                    any(res.node_id == node_id for res in allocation.assigned_resources.values())):
                    node_allocations.append(allocation_id)
            
            # Deallocate resources
            for allocation_id in node_allocations:
                await self.deallocate_resources(allocation_id)
            
            del self.node_managers[node_id]
            logger.info(f"Removed node {node_id} from resource pool {self.pool_id}")

    async def allocate_resources_globally(self, allocation_request: ResourceAllocation) -> bool:
        """Allocate resources across the distributed pool"""
        try:
            # Find best nodes for each resource requirement
            allocation_plan = await self._create_allocation_plan(allocation_request)
            
            if not allocation_plan:
                logger.warning("Could not create allocation plan")
                return False
            
            # Execute allocation plan
            success = await self._execute_allocation_plan(allocation_request, allocation_plan)
            
            if success:
                self.global_allocations[allocation_request.allocation_id] = allocation_request
                logger.info(f"Successfully allocated resources globally for {allocation_request.allocation_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error in global resource allocation: {e}")
            return False

    async def _create_allocation_plan(self, allocation_request: ResourceAllocation) -> Optional[Dict[str, Any]]:
        """Create allocation plan for resource request"""
        allocation_plan = {}
        
        for resource_spec in allocation_request.resources:
            # Find nodes that can satisfy this resource requirement
            candidate_nodes = []
            
            for node_id, manager in self.node_managers.items():
                suitable_resource = await manager._find_suitable_resource(resource_spec)
                if suitable_resource:
                    # Calculate node score based on various factors
                    score = await self._calculate_node_score(node_id, resource_spec, suitable_resource)
                    candidate_nodes.append((node_id, suitable_resource, score))
            
            if not candidate_nodes:
                logger.warning(f"No nodes available for resource {resource_spec.resource_type}")
                return None
            
            # Sort by score (higher is better)
            candidate_nodes.sort(key=lambda x: x[2], reverse=True)
            
            # Select best node
            selected_node, selected_resource, score = candidate_nodes[0]
            
            allocation_plan[resource_spec.resource_type.value] = {
                "node_id": selected_node,
                "resource": selected_resource,
                "spec": resource_spec
            }
        
        return allocation_plan

    async def _calculate_node_score(self, node_id: str, resource_spec: ResourceSpec, 
                                  resource: ResourceInstance) -> float:
        """Calculate node suitability score"""
        score = 0.0
        
        # Base score from available capacity
        utilization = resource.allocated_capacity / resource.total_capacity
        score += (1.0 - utilization) * 100  # Prefer less utilized nodes
        
        # Bonus for exact capacity match
        if resource.available_capacity == resource_spec.amount:
            score += 50
        
        # Penalty for over-provisioning
        if resource.available_capacity > resource_spec.amount * 2:
            score -= 25
        
        # Consider node load (if available)
        manager = self.node_managers[node_id]
        current_metrics = manager.monitor.get_current_metrics()
        
        if current_metrics and "metrics" in current_metrics:
            cpu_usage = current_metrics["metrics"]["cpu"]["usage_percent"]
            memory_usage = current_metrics["metrics"]["memory"]["percent"]
            
            # Prefer nodes with lower overall usage
            score += (100 - cpu_usage) * 0.5
            score += (100 - memory_usage) * 0.5
        
        # Consider locality (simplified - prefer local node)
        if node_id == self.coordinator_node:
            score += 10
        
        return score

    async def _execute_allocation_plan(self, allocation_request: ResourceAllocation, 
                                     allocation_plan: Dict[str, Any]) -> bool:
        """Execute the allocation plan"""
        allocated_resources = {}
        successful_allocations = []
        
        try:
            for resource_type, plan_item in allocation_plan.items():
                node_id = plan_item["node_id"]
                resource_spec = plan_item["spec"]
                
                # Create individual allocation request for this node
                node_allocation = ResourceAllocation(
                    allocation_id=f"{allocation_request.allocation_id}_{resource_type}",
                    requester_id=allocation_request.requester_id,
                    resources=[resource_spec],
                    priority=allocation_request.priority,
                    tags=allocation_request.tags,
                    metadata=allocation_request.metadata
                )
                
                # Allocate on the node
                manager = self.node_managers[node_id]
                success = await manager.allocate_resources(node_allocation)
                
                if success:
                    allocated_resources[resource_type] = plan_item["resource"]
                    successful_allocations.append((node_id, node_allocation.allocation_id))
                else:
                    # Rollback previous allocations
                    await self._rollback_allocations(successful_allocations)
                    return False
            
            # Update allocation request with assigned resources
            allocation_request.assigned_resources = allocated_resources
            allocation_request.allocation_time = datetime.now()
            
            return True
            
        except Exception as e:
            logger.error(f"Error executing allocation plan: {e}")
            await self._rollback_allocations(successful_allocations)
            return False

    async def _rollback_allocations(self, successful_allocations: List[Tuple[str, str]]):
        """Rollback successful allocations in case of failure"""
        for node_id, allocation_id in successful_allocations:
            try:
                manager = self.node_managers[node_id]
                await manager.deallocate_resources(allocation_id)
                logger.info(f"Rolled back allocation {allocation_id} on node {node_id}")
            except Exception as e:
                logger.error(f"Error rolling back allocation {allocation_id}: {e}")

    async def deallocate_resources(self, allocation_id: str) -> bool:
        """Deallocate resources globally"""
        if allocation_id not in self.global_allocations:
            logger.warning(f"Global allocation {allocation_id} not found")
            return False
        
        allocation = self.global_allocations[allocation_id]
        success = True
        
        # Deallocate from each node
        for resource_type, resource in allocation.assigned_resources.items():
            node_id = resource.node_id
            node_allocation_id = f"{allocation_id}_{resource_type}"
            
            if node_id in self.node_managers:
                manager = self.node_managers[node_id]
                node_success = await manager.deallocate_resources(node_allocation_id)
                if not node_success:
                    success = False
        
        if success:
            del self.global_allocations[allocation_id]
            logger.info(f"Successfully deallocated global allocation {allocation_id}")
        
        return success

    def get_pool_status(self) -> Dict[str, Any]:
        """Get overall pool status"""
        total_nodes = len(self.node_managers)
        total_allocations = len(self.global_allocations)
        
        # Aggregate resource utilization
        aggregate_utilization = {}
        
        for node_id, manager in self.node_managers.items():
            node_utilization = manager.get_resource_utilization()
            
            for resource_id, util_info in node_utilization.items():
                resource_type = util_info["resource_type"]
                
                if resource_type not in aggregate_utilization:
                    aggregate_utilization[resource_type] = {
                        "total_capacity": 0.0,
                        "allocated_capacity": 0.0,
                        "available_capacity": 0.0,
                        "reserved_capacity": 0.0,
                        "node_count": 0,
                        "unit": util_info["unit"]
                    }
                
                agg = aggregate_utilization[resource_type]
                agg["total_capacity"] += util_info["total_capacity"]
                agg["allocated_capacity"] += util_info["allocated_capacity"]
                agg["available_capacity"] += util_info["available_capacity"]
                agg["reserved_capacity"] += util_info["reserved_capacity"]
                agg["node_count"] += 1
        
        # Calculate utilization percentages
        for resource_type, agg in aggregate_utilization.items():
            if agg["total_capacity"] > 0:
                agg["utilization_percent"] = (agg["allocated_capacity"] / agg["total_capacity"]) * 100
            else:
                agg["utilization_percent"] = 0.0
        
        return {
            "pool_id": self.pool_id,
            "coordinator_node": self.coordinator_node,
            "total_nodes": total_nodes,
            "total_allocations": total_allocations,
            "aggregate_utilization": aggregate_utilization,
            "timestamp": datetime.now().isoformat()
        }


if __name__ == "__main__":
    async def main():
        # Example usage
        pool = DistributedResourcePool("test_pool", "coordinator_1")
        
        # Create resource managers for test nodes
        manager1 = ResourceManager("node_1")
        manager2 = ResourceManager("node_2")
        
        await pool.add_node("node_1", manager1)
        await pool.add_node("node_2", manager2)
        
        # Start monitoring
        await manager1.monitor.start_monitoring()
        await manager2.monitor.start_monitoring()
        
        # Example allocation request
        allocation_request = ResourceAllocation(
            allocation_id="test_allocation_1",
            requester_id="test_client",
            resources=[
                ResourceSpec(ResourceType.CPU, 2.0, "cores"),
                ResourceSpec(ResourceType.MEMORY, 4 * 1024 * 1024 * 1024, "bytes"),  # 4GB
                ResourceSpec(ResourceType.DISK, 10 * 1024 * 1024 * 1024, "bytes")   # 10GB
            ],
            priority=1,
            tags={"test", "load_generation"}
        )
        
        # Allocate resources
        success = await pool.allocate_resources_globally(allocation_request)
        print(f"Allocation success: {success}")
        
        # Get pool status
        status = pool.get_pool_status()
        print(f"Pool status: {json.dumps(status, indent=2)}")
        
        # Clean up
        if success:
            await pool.deallocate_resources("test_allocation_1")
    
    asyncio.run(main())