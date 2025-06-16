"""
Resource Manager - Intelligent resource allocation and optimization system

This module provides comprehensive resource management capabilities including
allocation, optimization, monitoring, and constraint-based management.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import threading
from collections import defaultdict, deque

# Try to import psutil, fall back if not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    # Mock psutil for testing
    class MockPsutil:
        @staticmethod
        def cpu_percent(interval=None):
            return 45.0
        
        @staticmethod
        def virtual_memory():
            class Memory:
                percent = 60.0
                available = 8 * 1024**3  # 8GB
            return Memory()
        
        @staticmethod
        def disk_usage(path):
            class Disk:
                total = 100 * 1024**3  # 100GB
                used = 50 * 1024**3   # 50GB
                free = 50 * 1024**3   # 50GB
            return Disk()
    
    psutil = MockPsutil()

try:
    from ...src.circle_of_experts import CircleOfExperts, QueryRequest
except ImportError:
    try:
        from src.circle_of_experts import CircleOfExperts, QueryRequest
    except ImportError:
        # Mock classes if not available
        class CircleOfExperts:
            async def process_query(self, query):
                class MockResponse:
                    def __init__(self):
                        self.expert_responses = []
                return MockResponse()
        
        class QueryRequest:
            def __init__(self, **kwargs):
                pass


class ResourceType(Enum):
    CPU = "cpu"
    MEMORY = "memory"
    STORAGE = "storage"
    NETWORK = "network"
    GPU = "gpu"


class AllocationStrategy(Enum):
    BALANCED = "balanced"
    CPU_OPTIMIZED = "cpu_optimized"
    MEMORY_OPTIMIZED = "memory_optimized"
    COST_OPTIMIZED = "cost_optimized"
    PERFORMANCE_OPTIMIZED = "performance_optimized"


@dataclass
class ResourceRequirement:
    """Resource requirement specification"""
    resource_type: ResourceType
    min_amount: float
    max_amount: float
    preferred_amount: float
    priority: int = 1
    constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceAllocation:
    """Resource allocation result"""
    resource_type: ResourceType
    allocated_amount: float
    allocation_id: str
    constraints_satisfied: bool
    efficiency_score: float
    cost_per_hour: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ResourcePool:
    """Resource pool configuration and state"""
    pool_id: str
    resource_type: ResourceType
    total_capacity: float
    available_capacity: float
    allocated_capacity: float
    reserved_capacity: float
    pool_efficiency: float
    cost_per_unit: float
    constraints: Dict[str, Any] = field(default_factory=dict)
    allocations: List[ResourceAllocation] = field(default_factory=list)


@dataclass
class ResourceMetrics:
    """Resource utilization and performance metrics"""
    resource_type: ResourceType
    utilization_percent: float
    throughput: float
    latency: float
    error_rate: float
    efficiency_score: float
    cost_efficiency: float
    timestamp: datetime = field(default_factory=datetime.now)


class ResourceManager:
    """
    Intelligent resource allocation and optimization system
    
    Manages resource pools, allocation strategies, constraint satisfaction,
    and optimization across multiple resource types and providers.
    """
    
    def __init__(self, circle_of_experts: Optional[CircleOfExperts] = None):
        self.logger = logging.getLogger(__name__)
        self.circle_of_experts = circle_of_experts
        
        # Resource pools management
        self.resource_pools: Dict[str, ResourcePool] = {}
        self.allocation_history: List[ResourceAllocation] = []
        self.active_allocations: Dict[str, ResourceAllocation] = {}
        
        # Metrics and monitoring
        self.resource_metrics: Dict[ResourceType, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        self.utilization_targets = {
            ResourceType.CPU: 75.0,
            ResourceType.MEMORY: 80.0,
            ResourceType.STORAGE: 85.0,
            ResourceType.NETWORK: 70.0,
            ResourceType.GPU: 85.0
        }
        
        # Allocation policies
        self.allocation_policies = {
            'default_strategy': AllocationStrategy.BALANCED,
            'enable_overcommit': True,
            'overcommit_ratio': 1.2,
            'reservation_buffer': 0.1,
            'rebalance_threshold': 0.2
        }
        
        # Constraints and limits
        self.global_constraints = {
            'max_allocation_size': {},
            'min_allocation_size': {},
            'allocation_limits': {},
            'anti_affinity_rules': [],
            'affinity_rules': []
        }
        
        # Performance tracking
        self.performance_history = deque(maxlen=10000)
        self.optimization_suggestions = []
        
        # Start monitoring thread
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        self._monitor_thread.start()
    
    async def allocate_resources(
        self,
        requirements: List[ResourceRequirement],
        strategy: AllocationStrategy = AllocationStrategy.BALANCED,
        constraints: Optional[Dict[str, Any]] = None
    ) -> List[ResourceAllocation]:
        """
        Allocate resources based on requirements and strategy
        
        Args:
            requirements: List of resource requirements
            strategy: Allocation strategy to use
            constraints: Additional allocation constraints
            
        Returns:
            List of resource allocations
        """
        try:
            # Validate requirements
            validated_requirements = await self._validate_requirements(requirements)
            
            # Find suitable resource pools
            candidate_pools = await self._find_candidate_pools(
                validated_requirements, constraints
            )
            
            # Generate allocation options
            allocation_options = await self._generate_allocation_options(
                validated_requirements, candidate_pools, strategy
            )
            
            # Get expert recommendations
            expert_recommendations = await self._get_allocation_recommendations(
                validated_requirements, allocation_options
            )
            
            # Select optimal allocation
            selected_allocation = await self._select_optimal_allocation(
                allocation_options, expert_recommendations
            )
            
            # Execute allocation
            allocated_resources = await self._execute_allocation(selected_allocation)
            
            # Update tracking
            for allocation in allocated_resources:
                self.active_allocations[allocation.allocation_id] = allocation
                self.allocation_history.append(allocation)
            
            return allocated_resources
            
        except Exception as e:
            self.logger.error(f"Resource allocation failed: {e}")
            raise
    
    async def optimize_allocations(
        self,
        target_efficiency: float = 0.85
    ) -> Dict[str, Any]:
        """
        Optimize current resource allocations for better efficiency
        
        Args:
            target_efficiency: Target efficiency score (0.0-1.0)
            
        Returns:
            Optimization results and recommendations
        """
        optimization_results = {
            'current_efficiency': 0.0,
            'target_efficiency': target_efficiency,
            'optimizations_applied': [],
            'potential_savings': 0.0,
            'performance_impact': {},
            'recommendations': []
        }
        
        try:
            # Calculate current efficiency
            current_efficiency = await self._calculate_overall_efficiency()
            optimization_results['current_efficiency'] = current_efficiency
            
            if current_efficiency >= target_efficiency:
                optimization_results['recommendations'].append(
                    "Current efficiency meets target. No optimization needed."
                )
                return optimization_results
            
            # Identify optimization opportunities
            opportunities = await self._identify_optimization_opportunities()
            
            # Get expert optimization recommendations
            expert_recommendations = await self._get_optimization_recommendations(
                opportunities, target_efficiency
            )
            
            # Apply optimizations
            applied_optimizations = await self._apply_optimizations(
                opportunities, expert_recommendations
            )
            
            optimization_results['optimizations_applied'] = applied_optimizations
            optimization_results['recommendations'] = expert_recommendations
            
            # Calculate new efficiency and savings
            new_efficiency = await self._calculate_overall_efficiency()
            efficiency_improvement = new_efficiency - current_efficiency
            
            optimization_results['efficiency_improvement'] = efficiency_improvement
            optimization_results['potential_savings'] = await self._calculate_cost_savings(
                applied_optimizations
            )
            
            return optimization_results
            
        except Exception as e:
            self.logger.error(f"Resource optimization failed: {e}")
            optimization_results['error'] = str(e)
            return optimization_results
    
    async def deallocate_resources(
        self,
        allocation_ids: List[str],
        force: bool = False
    ) -> Dict[str, bool]:
        """
        Deallocate specified resources
        
        Args:
            allocation_ids: List of allocation IDs to deallocate
            force: Force deallocation even if constraints violated
            
        Returns:
            Dictionary of allocation_id -> success status
        """
        results = {}
        
        for allocation_id in allocation_ids:
            try:
                if allocation_id not in self.active_allocations:
                    results[allocation_id] = False
                    continue
                
                allocation = self.active_allocations[allocation_id]
                
                # Check deallocation constraints
                if not force:
                    can_deallocate = await self._check_deallocation_constraints(allocation)
                    if not can_deallocate:
                        results[allocation_id] = False
                        continue
                
                # Execute deallocation
                success = await self._execute_deallocation(allocation)
                results[allocation_id] = success
                
                if success:
                    del self.active_allocations[allocation_id]
                    await self._update_pool_capacity(allocation, deallocate=True)
                
            except Exception as e:
                self.logger.error(f"Failed to deallocate {allocation_id}: {e}")
                results[allocation_id] = False
        
        return results
    
    async def get_current_resources(self) -> Dict[str, Any]:
        """Get current resource configuration and status"""
        return {
            'resource_pools': {
                pool_id: {
                    'total_capacity': pool.total_capacity,
                    'available_capacity': pool.available_capacity,
                    'allocated_capacity': pool.allocated_capacity,
                    'utilization_percent': (pool.allocated_capacity / pool.total_capacity * 100) 
                                         if pool.total_capacity > 0 else 0,
                    'efficiency_score': pool.pool_efficiency,
                    'cost_per_hour': pool.cost_per_unit * pool.allocated_capacity
                }
                for pool_id, pool in self.resource_pools.items()
            },
            'active_allocations': len(self.active_allocations),
            'total_allocations': len(self.allocation_history),
            'overall_efficiency': await self._calculate_overall_efficiency()
        }
    
    async def rebalance_resources(
        self,
        target_utilization: Optional[Dict[ResourceType, float]] = None
    ) -> Dict[str, Any]:
        """
        Rebalance resources across pools for optimal utilization
        
        Args:
            target_utilization: Target utilization levels per resource type
            
        Returns:
            Rebalancing results and metrics
        """
        if target_utilization is None:
            target_utilization = self.utilization_targets
        
        rebalance_results = {
            'rebalanced_allocations': [],
            'efficiency_improvement': 0.0,
            'cost_impact': 0.0,
            'performance_impact': {}
        }
        
        try:
            # Identify imbalanced pools
            imbalanced_pools = await self._identify_imbalanced_pools(target_utilization)
            
            if not imbalanced_pools:
                rebalance_results['message'] = "No rebalancing needed"
                return rebalance_results
            
            # Generate rebalancing plan
            rebalancing_plan = await self._generate_rebalancing_plan(
                imbalanced_pools, target_utilization
            )
            
            # Get expert validation
            expert_validation = await self._get_rebalancing_recommendations(
                rebalancing_plan
            )
            
            # Execute rebalancing
            if expert_validation.get('approved', True):
                executed_actions = await self._execute_rebalancing(rebalancing_plan)
                rebalance_results['rebalanced_allocations'] = executed_actions
                
                # Calculate impact
                efficiency_before = await self._calculate_overall_efficiency()
                # Efficiency after would be calculated post-execution
                
            return rebalance_results
            
        except Exception as e:
            self.logger.error(f"Resource rebalancing failed: {e}")
            rebalance_results['error'] = str(e)
            return rebalance_results
    
    async def add_resource_pool(
        self,
        pool_id: str,
        resource_type: ResourceType,
        capacity: float,
        cost_per_unit: float,
        constraints: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Add a new resource pool"""
        try:
            if pool_id in self.resource_pools:
                raise ValueError(f"Pool {pool_id} already exists")
            
            pool = ResourcePool(
                pool_id=pool_id,
                resource_type=resource_type,
                total_capacity=capacity,
                available_capacity=capacity,
                allocated_capacity=0.0,
                reserved_capacity=capacity * self.allocation_policies['reservation_buffer'],
                pool_efficiency=1.0,
                cost_per_unit=cost_per_unit,
                constraints=constraints or {}
            )
            
            self.resource_pools[pool_id] = pool
            self.logger.info(f"Added resource pool: {pool_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add resource pool {pool_id}: {e}")
            return False
    
    async def remove_resource_pool(
        self,
        pool_id: str,
        force: bool = False
    ) -> bool:
        """Remove a resource pool"""
        try:
            if pool_id not in self.resource_pools:
                return False
            
            pool = self.resource_pools[pool_id]
            
            # Check if pool has active allocations
            if pool.allocations and not force:
                raise ValueError(f"Pool {pool_id} has active allocations")
            
            # Deallocate all resources if force is True
            if force and pool.allocations:
                allocation_ids = [alloc.allocation_id for alloc in pool.allocations]
                await self.deallocate_resources(allocation_ids, force=True)
            
            del self.resource_pools[pool_id]
            self.logger.info(f"Removed resource pool: {pool_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to remove resource pool {pool_id}: {e}")
            return False
    
    async def _validate_requirements(
        self,
        requirements: List[ResourceRequirement]
    ) -> List[ResourceRequirement]:
        """Validate resource requirements"""
        validated = []
        
        for req in requirements:
            # Check minimum requirements
            if req.min_amount <= 0:
                raise ValueError(f"Invalid minimum amount: {req.min_amount}")
            
            if req.max_amount < req.min_amount:
                raise ValueError("Maximum amount cannot be less than minimum")
            
            if req.preferred_amount < req.min_amount or req.preferred_amount > req.max_amount:
                req.preferred_amount = req.min_amount
            
            validated.append(req)
        
        return validated
    
    async def _find_candidate_pools(
        self,
        requirements: List[ResourceRequirement],
        constraints: Optional[Dict[str, Any]] = None
    ) -> Dict[ResourceType, List[ResourcePool]]:
        """Find candidate resource pools for requirements"""
        candidates = defaultdict(list)
        
        for req in requirements:
            for pool_id, pool in self.resource_pools.items():
                if pool.resource_type != req.resource_type:
                    continue
                
                # Check capacity
                if pool.available_capacity >= req.min_amount:
                    # Check constraints
                    if await self._check_pool_constraints(pool, req, constraints):
                        candidates[req.resource_type].append(pool)
        
        return candidates
    
    async def _check_pool_constraints(
        self,
        pool: ResourcePool,
        requirement: ResourceRequirement,
        constraints: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Check if pool meets requirement constraints"""
        # Basic constraint checking
        if pool.available_capacity < requirement.min_amount:
            return False
        
        # Check pool-specific constraints
        if pool.constraints:
            for constraint_key, constraint_value in pool.constraints.items():
                if constraints and constraint_key in constraints:
                    if constraints[constraint_key] != constraint_value:
                        return False
        
        return True
    
    async def _generate_allocation_options(
        self,
        requirements: List[ResourceRequirement],
        candidate_pools: Dict[ResourceType, List[ResourcePool]],
        strategy: AllocationStrategy
    ) -> List[Dict[str, Any]]:
        """Generate allocation options based on strategy"""
        options = []
        
        if strategy == AllocationStrategy.BALANCED:
            options.extend(await self._generate_balanced_options(requirements, candidate_pools))
        elif strategy == AllocationStrategy.COST_OPTIMIZED:
            options.extend(await self._generate_cost_optimized_options(requirements, candidate_pools))
        elif strategy == AllocationStrategy.PERFORMANCE_OPTIMIZED:
            options.extend(await self._generate_performance_optimized_options(requirements, candidate_pools))
        
        return options
    
    async def _generate_balanced_options(
        self,
        requirements: List[ResourceRequirement],
        candidate_pools: Dict[ResourceType, List[ResourcePool]]
    ) -> List[Dict[str, Any]]:
        """Generate balanced allocation options"""
        options = []
        
        for req in requirements:
            pools = candidate_pools.get(req.resource_type, [])
            if not pools:
                continue
            
            # Sort pools by efficiency and availability
            sorted_pools = sorted(
                pools,
                key=lambda p: (p.pool_efficiency, p.available_capacity),
                reverse=True
            )
            
            # Create allocation option
            option = {
                'requirement': req,
                'selected_pool': sorted_pools[0],
                'allocated_amount': min(req.preferred_amount, sorted_pools[0].available_capacity),
                'strategy': AllocationStrategy.BALANCED,
                'score': sorted_pools[0].pool_efficiency
            }
            options.append(option)
        
        return options
    
    async def _generate_cost_optimized_options(
        self,
        requirements: List[ResourceRequirement],
        candidate_pools: Dict[ResourceType, List[ResourcePool]]
    ) -> List[Dict[str, Any]]:
        """Generate cost-optimized allocation options"""
        options = []
        
        for req in requirements:
            pools = candidate_pools.get(req.resource_type, [])
            if not pools:
                continue
            
            # Sort pools by cost efficiency
            sorted_pools = sorted(pools, key=lambda p: p.cost_per_unit)
            
            option = {
                'requirement': req,
                'selected_pool': sorted_pools[0],
                'allocated_amount': req.min_amount,  # Allocate minimum for cost optimization
                'strategy': AllocationStrategy.COST_OPTIMIZED,
                'score': 1.0 / (1.0 + sorted_pools[0].cost_per_unit)
            }
            options.append(option)
        
        return options
    
    async def _generate_performance_optimized_options(
        self,
        requirements: List[ResourceRequirement],
        candidate_pools: Dict[ResourceType, List[ResourcePool]]
    ) -> List[Dict[str, Any]]:
        """Generate performance-optimized allocation options"""
        options = []
        
        for req in requirements:
            pools = candidate_pools.get(req.resource_type, [])
            if not pools:
                continue
            
            # Sort pools by performance metrics
            sorted_pools = sorted(
                pools,
                key=lambda p: p.pool_efficiency,
                reverse=True
            )
            
            option = {
                'requirement': req,
                'selected_pool': sorted_pools[0],
                'allocated_amount': req.max_amount,  # Allocate maximum for performance
                'strategy': AllocationStrategy.PERFORMANCE_OPTIMIZED,
                'score': sorted_pools[0].pool_efficiency
            }
            options.append(option)
        
        return options
    
    async def _get_allocation_recommendations(
        self,
        requirements: List[ResourceRequirement],
        allocation_options: List[Dict[str, Any]]
    ) -> List[str]:
        """Get expert recommendations for allocation decisions"""
        if not self.circle_of_experts:
            return []
        
        try:
            query = QueryRequest(
                query=f"""
                Given these resource allocation requirements and options, what are your recommendations?
                
                Requirements:
                {json.dumps([{
                    'type': req.resource_type.value,
                    'min': req.min_amount,
                    'max': req.max_amount,
                    'preferred': req.preferred_amount,
                    'priority': req.priority
                } for req in requirements], indent=2)}
                
                Allocation Options:
                {json.dumps([{
                    'strategy': opt['strategy'].value,
                    'allocated_amount': opt['allocated_amount'],
                    'score': opt['score']
                } for opt in allocation_options], indent=2)}
                
                Please provide recommendations for:
                1. Optimal allocation strategy selection
                2. Resource amount adjustments
                3. Performance vs cost trade-offs
                4. Risk mitigation strategies
                """,
                experts=["resource_optimization_expert", "performance_expert"],
                require_consensus=False
            )
            
            response = await self.circle_of_experts.process_query(query)
            return [resp.content for resp in response.expert_responses]
            
        except Exception as e:
            self.logger.warning(f"Failed to get allocation recommendations: {e}")
            return []
    
    async def _select_optimal_allocation(
        self,
        allocation_options: List[Dict[str, Any]],
        expert_recommendations: List[str]
    ) -> List[Dict[str, Any]]:
        """Select optimal allocation from options"""
        if not allocation_options:
            return []
        
        # Score each option
        scored_options = []
        for option in allocation_options:
            score = option['score']
            
            # Adjust score based on expert recommendations
            if expert_recommendations:
                # Simple keyword matching for demonstration
                combined_recommendations = ' '.join(expert_recommendations).lower()
                if option['strategy'].value in combined_recommendations:
                    score *= 1.2
            
            scored_options.append((score, option))
        
        # Sort by score and return
        scored_options.sort(key=lambda x: x[0], reverse=True)
        return [option for _, option in scored_options]
    
    async def _execute_allocation(
        self,
        allocation_plan: List[Dict[str, Any]]
    ) -> List[ResourceAllocation]:
        """Execute resource allocation plan"""
        allocated_resources = []
        
        for plan_item in allocation_plan:
            try:
                pool = plan_item['selected_pool']
                amount = plan_item['allocated_amount']
                requirement = plan_item['requirement']
                
                # Generate allocation ID
                allocation_id = f"alloc_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{pool.pool_id}"
                
                # Create allocation
                allocation = ResourceAllocation(
                    resource_type=requirement.resource_type,
                    allocated_amount=amount,
                    allocation_id=allocation_id,
                    constraints_satisfied=True,
                    efficiency_score=pool.pool_efficiency,
                    cost_per_hour=pool.cost_per_unit * amount,
                    metadata={
                        'pool_id': pool.pool_id,
                        'strategy': plan_item['strategy'].value,
                        'requirement_priority': requirement.priority
                    }
                )
                
                # Update pool capacity
                pool.allocated_capacity += amount
                pool.available_capacity -= amount
                pool.allocations.append(allocation)
                
                allocated_resources.append(allocation)
                
            except Exception as e:
                self.logger.error(f"Failed to execute allocation: {e}")
                continue
        
        return allocated_resources
    
    async def _monitor_resources(self):
        """Background resource monitoring"""
        while self._monitoring_active:
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Update resource metrics
                timestamp = datetime.now()
                
                self.resource_metrics[ResourceType.CPU].append(
                    ResourceMetrics(
                        resource_type=ResourceType.CPU,
                        utilization_percent=cpu_percent,
                        throughput=100.0 - cpu_percent,
                        latency=0.0,
                        error_rate=0.0,
                        efficiency_score=min(1.0, (100.0 - cpu_percent) / 100.0),
                        cost_efficiency=1.0,
                        timestamp=timestamp
                    )
                )
                
                self.resource_metrics[ResourceType.MEMORY].append(
                    ResourceMetrics(
                        resource_type=ResourceType.MEMORY,
                        utilization_percent=memory.percent,
                        throughput=memory.available / (1024**3),  # GB
                        latency=0.0,
                        error_rate=0.0,
                        efficiency_score=min(1.0, (100.0 - memory.percent) / 100.0),
                        cost_efficiency=1.0,
                        timestamp=timestamp
                    )
                )
                
                await asyncio.sleep(10)  # Monitor every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Resource monitoring error: {e}")
                await asyncio.sleep(30)
    
    async def _calculate_overall_efficiency(self) -> float:
        """Calculate overall resource efficiency"""
        if not self.resource_pools:
            return 0.0
        
        total_efficiency = 0.0
        total_weight = 0.0
        
        for pool in self.resource_pools.values():
            if pool.total_capacity > 0:
                utilization = pool.allocated_capacity / pool.total_capacity
                weight = pool.total_capacity
                efficiency = pool.pool_efficiency * utilization
                
                total_efficiency += efficiency * weight
                total_weight += weight
        
        return total_efficiency / total_weight if total_weight > 0 else 0.0
    
    async def _identify_optimization_opportunities(self) -> List[Dict[str, Any]]:
        """Identify resource optimization opportunities"""
        opportunities = []
        
        for pool_id, pool in self.resource_pools.items():
            if pool.total_capacity == 0:
                continue
            
            utilization = pool.allocated_capacity / pool.total_capacity
            
            # Under-utilized pool
            if utilization < 0.3:
                opportunities.append({
                    'type': 'underutilized_pool',
                    'pool_id': pool_id,
                    'current_utilization': utilization,
                    'recommendation': 'Consider consolidating or reducing capacity'
                })
            
            # Over-utilized pool
            elif utilization > 0.9:
                opportunities.append({
                    'type': 'overutilized_pool',
                    'pool_id': pool_id,
                    'current_utilization': utilization,
                    'recommendation': 'Consider expanding capacity or load balancing'
                })
            
            # Inefficient allocations
            if pool.pool_efficiency < 0.7:
                opportunities.append({
                    'type': 'inefficient_pool',
                    'pool_id': pool_id,
                    'efficiency': pool.pool_efficiency,
                    'recommendation': 'Review allocation strategy and constraints'
                })
        
        return opportunities
    
    async def get_resource_metrics(
        self,
        resource_type: Optional[ResourceType] = None,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> Dict[str, Any]:
        """Get resource metrics for analysis"""
        metrics_data = {}
        
        if resource_type:
            resource_types = [resource_type]
        else:
            resource_types = list(ResourceType)
        
        for rt in resource_types:
            if rt in self.resource_metrics:
                metrics = list(self.resource_metrics[rt])
                
                if time_range:
                    start_time, end_time = time_range
                    metrics = [
                        m for m in metrics
                        if start_time <= m.timestamp <= end_time
                    ]
                
                metrics_data[rt.value] = [
                    {
                        'utilization_percent': m.utilization_percent,
                        'throughput': m.throughput,
                        'latency': m.latency,
                        'efficiency_score': m.efficiency_score,
                        'timestamp': m.timestamp.isoformat()
                    }
                    for m in metrics
                ]
        
        return metrics_data
    
    def cleanup(self):
        """Cleanup resources and stop monitoring"""
        self._monitoring_active = False
        if hasattr(self, '_monitor_thread'):
            self._monitor_thread.join(timeout=5)