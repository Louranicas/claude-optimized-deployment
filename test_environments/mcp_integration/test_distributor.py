"""
Test Workload Distribution - Intelligent test workload distribution across MCP nodes.
Distributes test scenarios based on node capabilities, load, and locality.
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
import aiohttp
import random
import math

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestType(Enum):
    """Test type enumeration"""
    LOAD_TEST = "load_test"
    STRESS_TEST = "stress_test"
    ENDURANCE_TEST = "endurance_test"
    SPIKE_TEST = "spike_test"
    VOLUME_TEST = "volume_test"
    SECURITY_TEST = "security_test"
    FUNCTIONAL_TEST = "functional_test"
    PERFORMANCE_TEST = "performance_test"
    CHAOS_TEST = "chaos_test"


class DistributionStrategy(Enum):
    """Distribution strategy enumeration"""
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    RANDOM = "random"
    CAPABILITY_BASED = "capability_based"
    LOCALITY_AWARE = "locality_aware"
    WEIGHTED = "weighted"
    ADAPTIVE = "adaptive"


class ExecutionMode(Enum):
    """Test execution mode"""
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    COORDINATED = "coordinated"
    INDEPENDENT = "independent"


@dataclass
class TestScenario:
    """Test scenario definition"""
    scenario_id: str
    name: str
    description: str
    test_type: TestType
    parameters: Dict[str, Any]
    required_capabilities: List[str]
    estimated_duration: timedelta
    resource_requirements: Dict[str, float]
    priority: int = 1
    tags: Set[str] = None
    dependencies: List[str] = None
    metadata: Dict[str, Any] = None


@dataclass
class TestWorkload:
    """Test workload to be distributed"""
    workload_id: str
    name: str
    scenarios: List[TestScenario]
    execution_mode: ExecutionMode
    target_nodes: Optional[List[str]] = None
    constraints: Dict[str, Any] = None
    timeout: Optional[timedelta] = None
    retry_policy: Dict[str, Any] = None


@dataclass
class NodeCapability:
    """Node capability information"""
    node_id: str
    capabilities: Set[str]
    capacity: Dict[str, float]
    current_load: Dict[str, float]
    location: Optional[str] = None
    performance_rating: float = 1.0
    reliability_score: float = 1.0
    last_updated: datetime = None


@dataclass
class TestAssignment:
    """Test assignment to a node"""
    assignment_id: str
    node_id: str
    scenario: TestScenario
    assigned_at: datetime
    estimated_completion: datetime
    status: str = "pending"
    actual_start: Optional[datetime] = None
    actual_completion: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None


@dataclass
class DistributionPlan:
    """Complete distribution plan"""
    plan_id: str
    workload_id: str
    strategy: DistributionStrategy
    assignments: List[TestAssignment]
    created_at: datetime
    estimated_duration: timedelta
    total_nodes: int
    load_balance_score: float


class LoadBalancer:
    """Load balancing utilities for test distribution"""
    
    @staticmethod
    def calculate_node_load_score(node: NodeCapability) -> float:
        """Calculate overall load score for a node (0-1, lower is better)"""
        if not node.capacity:
            return 1.0
        
        total_load = 0.0
        total_capacity = 0.0
        
        for resource, capacity in node.capacity.items():
            current_load = node.current_load.get(resource, 0.0)
            if capacity > 0:
                load_ratio = current_load / capacity
                total_load += load_ratio
                total_capacity += 1.0
        
        return total_load / total_capacity if total_capacity > 0 else 1.0

    @staticmethod
    def calculate_capability_match_score(scenario: TestScenario, node: NodeCapability) -> float:
        """Calculate how well a node matches scenario capabilities (0-1)"""
        if not scenario.required_capabilities:
            return 1.0
        
        matched_capabilities = len(
            set(scenario.required_capabilities) & node.capabilities
        )
        
        return matched_capabilities / len(scenario.required_capabilities)

    @staticmethod
    def calculate_resource_fitness_score(scenario: TestScenario, node: NodeCapability) -> float:
        """Calculate resource fitness score (0-1, higher is better)"""
        if not scenario.resource_requirements or not node.capacity:
            return 0.5
        
        fitness_scores = []
        
        for resource, required in scenario.resource_requirements.items():
            available = node.capacity.get(resource, 0.0) - node.current_load.get(resource, 0.0)
            
            if available <= 0:
                fitness_scores.append(0.0)
            elif available >= required:
                # Perfect fit gets high score, over-provisioning gets lower score
                if available <= required * 2:
                    fitness_scores.append(1.0)
                else:
                    fitness_scores.append(0.8)
            else:
                # Insufficient resources
                fitness_scores.append(available / required * 0.5)
        
        return sum(fitness_scores) / len(fitness_scores) if fitness_scores else 0.5


class TestDistributor:
    """Main test workload distributor"""
    
    def __init__(self, distributor_id: str):
        self.distributor_id = distributor_id
        self.nodes: Dict[str, NodeCapability] = {}
        self.active_workloads: Dict[str, TestWorkload] = {}
        self.distribution_plans: Dict[str, DistributionPlan] = {}
        self.assignments: Dict[str, TestAssignment] = {}
        self.load_balancer = LoadBalancer()
        
        # Distribution statistics
        self.distribution_history: List[Dict[str, Any]] = []
        self.performance_metrics: Dict[str, float] = {}

    def register_node(self, node: NodeCapability):
        """Register a test node with the distributor"""
        node.last_updated = datetime.now()
        self.nodes[node.node_id] = node
        logger.info(f"Registered node {node.node_id} with capabilities: {node.capabilities}")

    def unregister_node(self, node_id: str):
        """Unregister a test node"""
        if node_id in self.nodes:
            del self.nodes[node_id]
            logger.info(f"Unregistered node {node_id}")

    def update_node_status(self, node_id: str, capacity: Dict[str, float], 
                          current_load: Dict[str, float]):
        """Update node status information"""
        if node_id in self.nodes:
            node = self.nodes[node_id]
            node.capacity.update(capacity)
            node.current_load.update(current_load)
            node.last_updated = datetime.now()

    async def distribute_workload(self, workload: TestWorkload, 
                                strategy: DistributionStrategy = DistributionStrategy.ADAPTIVE) -> DistributionPlan:
        """Distribute test workload across available nodes"""
        try:
            logger.info(f"Distributing workload {workload.workload_id} using {strategy.value} strategy")
            
            # Validate workload
            if not self._validate_workload(workload):
                raise ValueError(f"Invalid workload: {workload.workload_id}")
            
            # Select appropriate distribution strategy
            if strategy == DistributionStrategy.ADAPTIVE:
                strategy = self._select_optimal_strategy(workload)
            
            # Create distribution plan
            plan = await self._create_distribution_plan(workload, strategy)
            
            if not plan.assignments:
                raise RuntimeError("No suitable nodes found for workload distribution")
            
            # Store plan and workload
            self.distribution_plans[plan.plan_id] = plan
            self.active_workloads[workload.workload_id] = workload
            
            # Record distribution statistics
            self._record_distribution_stats(plan)
            
            logger.info(f"Created distribution plan {plan.plan_id} with {len(plan.assignments)} assignments")
            return plan
            
        except Exception as e:
            logger.error(f"Error distributing workload {workload.workload_id}: {e}")
            raise

    def _validate_workload(self, workload: TestWorkload) -> bool:
        """Validate workload configuration"""
        if not workload.scenarios:
            return False
        
        # Check if we have enough nodes
        available_nodes = len([node for node in self.nodes.values() 
                             if self._is_node_available(node)])
        
        if available_nodes == 0:
            return False
        
        # Check if nodes can satisfy requirements
        for scenario in workload.scenarios:
            if not self._can_satisfy_scenario(scenario):
                logger.warning(f"No nodes can satisfy scenario {scenario.scenario_id}")
                return False
        
        return True

    def _is_node_available(self, node: NodeCapability) -> bool:
        """Check if node is available for assignment"""
        # Check if node is responsive (last update within reasonable time)
        if node.last_updated and datetime.now() - node.last_updated > timedelta(minutes=5):
            return False
        
        # Check if node has some available capacity
        load_score = self.load_balancer.calculate_node_load_score(node)
        return load_score < 0.95  # Node is available if less than 95% loaded

    def _can_satisfy_scenario(self, scenario: TestScenario) -> bool:
        """Check if any node can satisfy the scenario requirements"""
        for node in self.nodes.values():
            if not self._is_node_available(node):
                continue
            
            # Check capabilities
            capability_score = self.load_balancer.calculate_capability_match_score(scenario, node)
            if capability_score < 1.0:
                continue
            
            # Check resources
            resource_score = self.load_balancer.calculate_resource_fitness_score(scenario, node)
            if resource_score > 0.5:
                return True
        
        return False

    def _select_optimal_strategy(self, workload: TestWorkload) -> DistributionStrategy:
        """Select optimal distribution strategy based on workload characteristics"""
        # Analyze workload characteristics
        scenario_count = len(workload.scenarios)
        unique_capabilities = set()
        total_resource_requirements = {}
        
        for scenario in workload.scenarios:
            unique_capabilities.update(scenario.required_capabilities or [])
            for resource, amount in (scenario.resource_requirements or {}).items():
                total_resource_requirements[resource] = (
                    total_resource_requirements.get(resource, 0) + amount
                )
        
        # Decision logic
        if scenario_count == 1:
            return DistributionStrategy.LEAST_LOADED
        
        if len(unique_capabilities) > len(self.nodes) * 0.5:
            return DistributionStrategy.CAPABILITY_BASED
        
        if workload.execution_mode == ExecutionMode.COORDINATED:
            return DistributionStrategy.LOCALITY_AWARE
        
        # Default to weighted strategy for complex workloads
        return DistributionStrategy.WEIGHTED

    async def _create_distribution_plan(self, workload: TestWorkload, 
                                      strategy: DistributionStrategy) -> DistributionPlan:
        """Create distribution plan using specified strategy"""
        plan_id = str(uuid.uuid4())
        assignments = []
        
        if strategy == DistributionStrategy.ROUND_ROBIN:
            assignments = await self._distribute_round_robin(workload)
        elif strategy == DistributionStrategy.LEAST_LOADED:
            assignments = await self._distribute_least_loaded(workload)
        elif strategy == DistributionStrategy.RANDOM:
            assignments = await self._distribute_random(workload)
        elif strategy == DistributionStrategy.CAPABILITY_BASED:
            assignments = await self._distribute_capability_based(workload)
        elif strategy == DistributionStrategy.LOCALITY_AWARE:
            assignments = await self._distribute_locality_aware(workload)
        elif strategy == DistributionStrategy.WEIGHTED:
            assignments = await self._distribute_weighted(workload)
        else:
            assignments = await self._distribute_weighted(workload)
        
        # Calculate plan metrics
        estimated_duration = self._calculate_estimated_duration(assignments, workload.execution_mode)
        load_balance_score = self._calculate_load_balance_score(assignments)
        total_nodes = len(set(assignment.node_id for assignment in assignments))
        
        return DistributionPlan(
            plan_id=plan_id,
            workload_id=workload.workload_id,
            strategy=strategy,
            assignments=assignments,
            created_at=datetime.now(),
            estimated_duration=estimated_duration,
            total_nodes=total_nodes,
            load_balance_score=load_balance_score
        )

    async def _distribute_round_robin(self, workload: TestWorkload) -> List[TestAssignment]:
        """Distribute using round-robin strategy"""
        assignments = []
        available_nodes = [node for node in self.nodes.values() if self._is_node_available(node)]
        
        if not available_nodes:
            return assignments
        
        node_index = 0
        
        for scenario in workload.scenarios:
            # Find next suitable node
            assigned = False
            attempts = 0
            
            while not assigned and attempts < len(available_nodes):
                node = available_nodes[node_index % len(available_nodes)]
                
                if self._can_assign_scenario_to_node(scenario, node):
                    assignment = self._create_assignment(scenario, node)
                    assignments.append(assignment)
                    self._update_node_load_projection(node, scenario)
                    assigned = True
                
                node_index += 1
                attempts += 1
        
        return assignments

    async def _distribute_least_loaded(self, workload: TestWorkload) -> List[TestAssignment]:
        """Distribute using least-loaded strategy"""
        assignments = []
        
        for scenario in workload.scenarios:
            # Find least loaded suitable node
            best_node = None
            best_load_score = float('inf')
            
            for node in self.nodes.values():
                if not self._is_node_available(node):
                    continue
                
                if not self._can_assign_scenario_to_node(scenario, node):
                    continue
                
                load_score = self.load_balancer.calculate_node_load_score(node)
                if load_score < best_load_score:
                    best_load_score = load_score
                    best_node = node
            
            if best_node:
                assignment = self._create_assignment(scenario, best_node)
                assignments.append(assignment)
                self._update_node_load_projection(best_node, scenario)
        
        return assignments

    async def _distribute_random(self, workload: TestWorkload) -> List[TestAssignment]:
        """Distribute using random strategy"""
        assignments = []
        
        for scenario in workload.scenarios:
            # Get suitable nodes and pick randomly
            suitable_nodes = [
                node for node in self.nodes.values()
                if self._is_node_available(node) and self._can_assign_scenario_to_node(scenario, node)
            ]
            
            if suitable_nodes:
                selected_node = random.choice(suitable_nodes)
                assignment = self._create_assignment(scenario, selected_node)
                assignments.append(assignment)
                self._update_node_load_projection(selected_node, scenario)
        
        return assignments

    async def _distribute_capability_based(self, workload: TestWorkload) -> List[TestAssignment]:
        """Distribute based on node capabilities"""
        assignments = []
        
        for scenario in workload.scenarios:
            # Find node with best capability match
            best_node = None
            best_capability_score = 0.0
            
            for node in self.nodes.values():
                if not self._is_node_available(node):
                    continue
                
                if not self._can_assign_scenario_to_node(scenario, node):
                    continue
                
                capability_score = self.load_balancer.calculate_capability_match_score(scenario, node)
                if capability_score > best_capability_score:
                    best_capability_score = capability_score
                    best_node = node
            
            if best_node:
                assignment = self._create_assignment(scenario, best_node)
                assignments.append(assignment)
                self._update_node_load_projection(best_node, scenario)
        
        return assignments

    async def _distribute_locality_aware(self, workload: TestWorkload) -> List[TestAssignment]:
        """Distribute with locality awareness"""
        assignments = []
        
        # Group scenarios by locality requirements if any
        locality_groups = self._group_scenarios_by_locality(workload.scenarios)
        
        for location, scenarios in locality_groups.items():
            # Find nodes in the same location
            local_nodes = [
                node for node in self.nodes.values()
                if self._is_node_available(node) and 
                (node.location == location or location is None)
            ]
            
            # Distribute scenarios within locality group
            for scenario in scenarios:
                best_node = None
                best_score = 0.0
                
                for node in local_nodes:
                    if not self._can_assign_scenario_to_node(scenario, node):
                        continue
                    
                    # Combine load and capability scores
                    load_score = 1.0 - self.load_balancer.calculate_node_load_score(node)
                    capability_score = self.load_balancer.calculate_capability_match_score(scenario, node)
                    combined_score = (load_score + capability_score) / 2
                    
                    if combined_score > best_score:
                        best_score = combined_score
                        best_node = node
                
                if best_node:
                    assignment = self._create_assignment(scenario, best_node)
                    assignments.append(assignment)
                    self._update_node_load_projection(best_node, scenario)
        
        return assignments

    async def _distribute_weighted(self, workload: TestWorkload) -> List[TestAssignment]:
        """Distribute using weighted scoring"""
        assignments = []
        
        for scenario in workload.scenarios:
            # Calculate weighted scores for all suitable nodes
            node_scores = []
            
            for node in self.nodes.values():
                if not self._is_node_available(node):
                    continue
                
                if not self._can_assign_scenario_to_node(scenario, node):
                    continue
                
                # Calculate component scores
                load_score = 1.0 - self.load_balancer.calculate_node_load_score(node)
                capability_score = self.load_balancer.calculate_capability_match_score(scenario, node)
                resource_score = self.load_balancer.calculate_resource_fitness_score(scenario, node)
                performance_score = node.performance_rating
                reliability_score = node.reliability_score
                
                # Weighted combination
                weighted_score = (
                    load_score * 0.3 +
                    capability_score * 0.25 +
                    resource_score * 0.25 +
                    performance_score * 0.1 +
                    reliability_score * 0.1
                )
                
                node_scores.append((node, weighted_score))
            
            # Select node with highest score
            if node_scores:
                node_scores.sort(key=lambda x: x[1], reverse=True)
                best_node = node_scores[0][0]
                
                assignment = self._create_assignment(scenario, best_node)
                assignments.append(assignment)
                self._update_node_load_projection(best_node, scenario)
        
        return assignments

    def _group_scenarios_by_locality(self, scenarios: List[TestScenario]) -> Dict[Optional[str], List[TestScenario]]:
        """Group scenarios by locality requirements"""
        locality_groups = {}
        
        for scenario in scenarios:
            # Extract locality from metadata or constraints
            locality = None
            if scenario.metadata and "locality" in scenario.metadata:
                locality = scenario.metadata["locality"]
            
            if locality not in locality_groups:
                locality_groups[locality] = []
            
            locality_groups[locality].append(scenario)
        
        return locality_groups

    def _can_assign_scenario_to_node(self, scenario: TestScenario, node: NodeCapability) -> bool:
        """Check if scenario can be assigned to node"""
        # Check capabilities
        if scenario.required_capabilities:
            if not all(cap in node.capabilities for cap in scenario.required_capabilities):
                return False
        
        # Check resource availability
        if scenario.resource_requirements:
            for resource, required in scenario.resource_requirements.items():
                available = node.capacity.get(resource, 0.0) - node.current_load.get(resource, 0.0)
                if available < required:
                    return False
        
        return True

    def _create_assignment(self, scenario: TestScenario, node: NodeCapability) -> TestAssignment:
        """Create test assignment"""
        assignment_id = str(uuid.uuid4())
        assigned_at = datetime.now()
        estimated_completion = assigned_at + scenario.estimated_duration
        
        assignment = TestAssignment(
            assignment_id=assignment_id,
            node_id=node.node_id,
            scenario=scenario,
            assigned_at=assigned_at,
            estimated_completion=estimated_completion
        )
        
        self.assignments[assignment_id] = assignment
        return assignment

    def _update_node_load_projection(self, node: NodeCapability, scenario: TestScenario):
        """Update node load projection for planning"""
        if scenario.resource_requirements:
            for resource, amount in scenario.resource_requirements.items():
                current_load = node.current_load.get(resource, 0.0)
                node.current_load[resource] = current_load + amount

    def _calculate_estimated_duration(self, assignments: List[TestAssignment], 
                                    execution_mode: ExecutionMode) -> timedelta:
        """Calculate estimated duration for the distribution plan"""
        if not assignments:
            return timedelta(0)
        
        if execution_mode == ExecutionMode.SEQUENTIAL:
            # Sum all durations
            total_duration = sum([
                assignment.scenario.estimated_duration for assignment in assignments
            ], timedelta(0))
            return total_duration
        
        elif execution_mode == ExecutionMode.PARALLEL:
            # Maximum duration
            max_duration = max([
                assignment.scenario.estimated_duration for assignment in assignments
            ])
            return max_duration
        
        elif execution_mode == ExecutionMode.COORDINATED:
            # Group by node and calculate per-node duration
            node_durations = {}
            for assignment in assignments:
                node_id = assignment.node_id
                if node_id not in node_durations:
                    node_durations[node_id] = timedelta(0)
                node_durations[node_id] += assignment.scenario.estimated_duration
            
            return max(node_durations.values()) if node_durations else timedelta(0)
        
        else:  # INDEPENDENT
            # Average duration
            avg_duration = sum([
                assignment.scenario.estimated_duration for assignment in assignments
            ], timedelta(0)) / len(assignments)
            return avg_duration

    def _calculate_load_balance_score(self, assignments: List[TestAssignment]) -> float:
        """Calculate load balance score (0-1, higher is better)"""
        if not assignments:
            return 0.0
        
        # Count assignments per node
        node_assignment_counts = {}
        for assignment in assignments:
            node_id = assignment.node_id
            node_assignment_counts[node_id] = node_assignment_counts.get(node_id, 0) + 1
        
        # Calculate coefficient of variation
        counts = list(node_assignment_counts.values())
        if len(counts) <= 1:
            return 1.0
        
        mean_count = sum(counts) / len(counts)
        variance = sum((count - mean_count) ** 2 for count in counts) / len(counts)
        std_dev = math.sqrt(variance)
        
        if mean_count == 0:
            return 0.0
        
        coefficient_of_variation = std_dev / mean_count
        
        # Convert to score (lower CV = higher score)
        return max(0.0, 1.0 - coefficient_of_variation)

    def _record_distribution_stats(self, plan: DistributionPlan):
        """Record distribution statistics"""
        stats = {
            "plan_id": plan.plan_id,
            "strategy": plan.strategy.value,
            "assignment_count": len(plan.assignments),
            "node_count": plan.total_nodes,
            "load_balance_score": plan.load_balance_score,
            "estimated_duration": plan.estimated_duration.total_seconds(),
            "timestamp": plan.created_at.isoformat()
        }
        
        self.distribution_history.append(stats)
        
        # Keep only recent history
        if len(self.distribution_history) > 1000:
            self.distribution_history = self.distribution_history[-1000:]

    async def execute_distribution_plan(self, plan_id: str) -> bool:
        """Execute a distribution plan"""
        if plan_id not in self.distribution_plans:
            logger.error(f"Distribution plan {plan_id} not found")
            return False
        
        plan = self.distribution_plans[plan_id]
        logger.info(f"Executing distribution plan {plan_id} with {len(plan.assignments)} assignments")
        
        try:
            # Send assignments to nodes
            execution_tasks = []
            
            for assignment in plan.assignments:
                task = asyncio.create_task(self._execute_assignment(assignment))
                execution_tasks.append(task)
            
            # Wait for all assignments to complete
            results = await asyncio.gather(*execution_tasks, return_exceptions=True)
            
            # Check results
            success_count = sum(1 for result in results if result is True)
            total_count = len(results)
            
            logger.info(f"Distribution plan {plan_id} completed: {success_count}/{total_count} assignments successful")
            
            return success_count == total_count
            
        except Exception as e:
            logger.error(f"Error executing distribution plan {plan_id}: {e}")
            return False

    async def _execute_assignment(self, assignment: TestAssignment) -> bool:
        """Execute individual assignment"""
        try:
            assignment.status = "running"
            assignment.actual_start = datetime.now()
            
            # In a real implementation, this would send the test scenario
            # to the assigned node via MCP protocol
            logger.info(f"Executing assignment {assignment.assignment_id} on node {assignment.node_id}")
            
            # Simulate test execution
            await asyncio.sleep(1)  # Simulate some work
            
            assignment.status = "completed"
            assignment.actual_completion = datetime.now()
            assignment.result = {"success": True, "message": "Test completed successfully"}
            
            return True
            
        except Exception as e:
            assignment.status = "failed"
            assignment.actual_completion = datetime.now()
            assignment.result = {"success": False, "error": str(e)}
            logger.error(f"Assignment {assignment.assignment_id} failed: {e}")
            return False

    def get_distribution_status(self, plan_id: str) -> Optional[Dict[str, Any]]:
        """Get distribution plan status"""
        if plan_id not in self.distribution_plans:
            return None
        
        plan = self.distribution_plans[plan_id]
        
        # Count assignment statuses
        status_counts = {}
        for assignment in plan.assignments:
            status = assignment.status
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Calculate progress
        completed = status_counts.get("completed", 0) + status_counts.get("failed", 0)
        total = len(plan.assignments)
        progress = (completed / total) * 100 if total > 0 else 0
        
        return {
            "plan_id": plan_id,
            "workload_id": plan.workload_id,
            "strategy": plan.strategy.value,
            "total_assignments": total,
            "status_counts": status_counts,
            "progress_percent": progress,
            "estimated_duration": plan.estimated_duration.total_seconds(),
            "load_balance_score": plan.load_balance_score,
            "created_at": plan.created_at.isoformat()
        }

    def get_distributor_statistics(self) -> Dict[str, Any]:
        """Get distributor performance statistics"""
        if not self.distribution_history:
            return {"message": "No distribution history available"}
        
        # Calculate statistics from history
        strategies_used = {}
        avg_load_balance = 0.0
        avg_node_count = 0.0
        
        for stats in self.distribution_history:
            strategy = stats["strategy"]
            strategies_used[strategy] = strategies_used.get(strategy, 0) + 1
            avg_load_balance += stats["load_balance_score"]
            avg_node_count += stats["node_count"]
        
        count = len(self.distribution_history)
        avg_load_balance /= count
        avg_node_count /= count
        
        return {
            "total_distributions": count,
            "strategies_used": strategies_used,
            "average_load_balance_score": avg_load_balance,
            "average_nodes_per_distribution": avg_node_count,
            "registered_nodes": len(self.nodes),
            "active_workloads": len(self.active_workloads),
            "active_assignments": len([a for a in self.assignments.values() if a.status == "running"])
        }


if __name__ == "__main__":
    async def main():
        # Example usage
        distributor = TestDistributor("test_distributor_1")
        
        # Register test nodes
        node1 = NodeCapability(
            node_id="node_1",
            capabilities={"http_load", "stress_testing", "performance_monitoring"},
            capacity={"cpu": 8.0, "memory": 16.0, "network": 1000.0},
            current_load={"cpu": 2.0, "memory": 4.0, "network": 100.0},
            performance_rating=0.9,
            reliability_score=0.95
        )
        
        node2 = NodeCapability(
            node_id="node_2",
            capabilities={"security_testing", "chaos_engineering", "load_testing"},
            capacity={"cpu": 16.0, "memory": 32.0, "network": 1000.0},
            current_load={"cpu": 4.0, "memory": 8.0, "network": 200.0},
            performance_rating=0.95,
            reliability_score=0.98
        )
        
        distributor.register_node(node1)
        distributor.register_node(node2)
        
        # Create test scenarios
        scenario1 = TestScenario(
            scenario_id="load_test_1",
            name="HTTP Load Test",
            description="Test HTTP endpoint with increasing load",
            test_type=TestType.LOAD_TEST,
            parameters={"target_url": "http://example.com", "max_rps": 1000},
            required_capabilities=["http_load"],
            estimated_duration=timedelta(minutes=30),
            resource_requirements={"cpu": 2.0, "memory": 4.0, "network": 500.0}
        )
        
        scenario2 = TestScenario(
            scenario_id="security_test_1",
            name="Security Vulnerability Scan",
            description="Automated security testing",
            test_type=TestType.SECURITY_TEST,
            parameters={"target": "example.com", "scan_type": "full"},
            required_capabilities=["security_testing"],
            estimated_duration=timedelta(hours=1),
            resource_requirements={"cpu": 4.0, "memory": 8.0, "network": 200.0}
        )
        
        # Create workload
        workload = TestWorkload(
            workload_id="test_workload_1",
            name="Comprehensive Testing Suite",
            scenarios=[scenario1, scenario2],
            execution_mode=ExecutionMode.PARALLEL,
            timeout=timedelta(hours=2)
        )
        
        # Distribute workload
        plan = await distributor.distribute_workload(workload, DistributionStrategy.WEIGHTED)
        print(f"Created distribution plan: {plan.plan_id}")
        
        # Execute plan
        success = await distributor.execute_distribution_plan(plan.plan_id)
        print(f"Plan execution success: {success}")
        
        # Get status
        status = distributor.get_distribution_status(plan.plan_id)
        print(f"Distribution status: {json.dumps(status, indent=2)}")
        
        # Get statistics
        stats = distributor.get_distributor_statistics()
        print(f"Distributor statistics: {json.dumps(stats, indent=2)}")
    
    asyncio.run(main())