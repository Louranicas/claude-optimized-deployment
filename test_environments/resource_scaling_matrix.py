#!/usr/bin/env python3
"""
Ultimate Test Environment - Resource Scaling Matrix
Dynamic resource allocation and scaling for progressive stress testing
"""

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
import json
import time
from datetime import datetime

class ResourceType(Enum):
    CPU = "cpu"
    MEMORY = "memory"
    NETWORK = "network"
    STORAGE = "storage"
    INSTANCES = "instances"

class ScalingStrategy(Enum):
    IMMEDIATE = "immediate"
    GRADUAL = "gradual"
    PREDICTIVE = "predictive"
    REACTIVE = "reactive"

@dataclass
class ResourcePool:
    """Resource pool configuration and current state"""
    resource_type: ResourceType
    total_capacity: float
    allocated: float = 0.0
    reserved: float = 0.0
    available: float = field(init=False)
    utilization_threshold: float = 0.8
    scaling_factor: float = 1.5
    
    def __post_init__(self):
        self.available = self.total_capacity - self.allocated - self.reserved

@dataclass
class ScalingDecision:
    """Scaling decision with justification"""
    resource_type: ResourceType
    current_allocation: float
    target_allocation: float
    scaling_strategy: ScalingStrategy
    justification: str
    estimated_time: int  # seconds
    cost_impact: float
    risk_level: str

@dataclass
class ResourceMetrics:
    """Current resource utilization metrics"""
    cpu_utilization: float
    memory_utilization: float
    network_utilization: float
    storage_utilization: float
    instance_count: int
    timestamp: datetime
    
class ResourceScalingMatrix:
    """Advanced resource scaling matrix with predictive capabilities"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.resource_pools = self._initialize_resource_pools()
        self.scaling_history: List[ScalingDecision] = []
        self.metrics_history: List[ResourceMetrics] = []
        self.scaling_strategies = self._initialize_scaling_strategies()
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for resource scaling"""
        logger = logging.getLogger("resource_scaling_matrix")
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _initialize_resource_pools(self) -> Dict[ResourceType, ResourcePool]:
        """Initialize resource pools with default capacities"""
        return {
            ResourceType.CPU: ResourcePool(
                resource_type=ResourceType.CPU,
                total_capacity=1000.0,  # CPU cores
                utilization_threshold=0.75,
                scaling_factor=2.0
            ),
            ResourceType.MEMORY: ResourcePool(
                resource_type=ResourceType.MEMORY,
                total_capacity=2048.0,  # GB
                utilization_threshold=0.80,
                scaling_factor=1.5
            ),
            ResourceType.NETWORK: ResourcePool(
                resource_type=ResourceType.NETWORK,
                total_capacity=200.0,   # Gbps
                utilization_threshold=0.70,
                scaling_factor=1.8
            ),
            ResourceType.STORAGE: ResourcePool(
                resource_type=ResourceType.STORAGE,
                total_capacity=100.0,   # TB
                utilization_threshold=0.85,
                scaling_factor=1.3
            ),
            ResourceType.INSTANCES: ResourcePool(
                resource_type=ResourceType.INSTANCES,
                total_capacity=500.0,   # Instance count
                utilization_threshold=0.90,
                scaling_factor=2.0
            )
        }
    
    def _initialize_scaling_strategies(self) -> Dict[ScalingStrategy, Dict]:
        """Initialize scaling strategy configurations"""
        return {
            ScalingStrategy.IMMEDIATE: {
                "scale_up_threshold": 0.8,
                "scale_down_threshold": 0.3,
                "scale_up_factor": 2.0,
                "scale_down_factor": 0.5,
                "cooldown_period": 60  # seconds
            },
            ScalingStrategy.GRADUAL: {
                "scale_up_threshold": 0.7,
                "scale_down_threshold": 0.4,
                "scale_up_factor": 1.3,
                "scale_down_factor": 0.8,
                "cooldown_period": 300
            },
            ScalingStrategy.PREDICTIVE: {
                "prediction_window": 900,  # 15 minutes
                "confidence_threshold": 0.85,
                "proactive_scaling": True,
                "ml_model_enabled": True
            },
            ScalingStrategy.REACTIVE: {
                "scale_up_threshold": 0.9,
                "scale_down_threshold": 0.2,
                "emergency_scaling": True,
                "rapid_response": True
            }
        }
    
    def get_phase_resource_requirements(self, phase: str) -> Dict[ResourceType, float]:
        """Get resource requirements for a specific stress testing phase"""
        requirements = {
            "idle": {
                ResourceType.CPU: 4.0,
                ResourceType.MEMORY: 16.0,
                ResourceType.NETWORK: 1.0,
                ResourceType.STORAGE: 0.1,
                ResourceType.INSTANCES: 3.0
            },
            "baseline": {
                ResourceType.CPU: 8.0,
                ResourceType.MEMORY: 32.0,
                ResourceType.NETWORK: 5.0,
                ResourceType.STORAGE: 0.5,
                ResourceType.INSTANCES: 5.0
            },
            "light": {
                ResourceType.CPU: 16.0,
                ResourceType.MEMORY: 64.0,
                ResourceType.NETWORK: 10.0,
                ResourceType.STORAGE: 1.0,
                ResourceType.INSTANCES: 10.0
            },
            "medium": {
                ResourceType.CPU: 32.0,
                ResourceType.MEMORY: 128.0,
                ResourceType.NETWORK: 25.0,
                ResourceType.STORAGE: 2.0,
                ResourceType.INSTANCES: 20.0
            },
            "heavy": {
                ResourceType.CPU: 64.0,
                ResourceType.MEMORY: 256.0,
                ResourceType.NETWORK: 50.0,
                ResourceType.STORAGE: 5.0,
                ResourceType.INSTANCES: 40.0
            },
            "extreme": {
                ResourceType.CPU: 128.0,
                ResourceType.MEMORY: 512.0,
                ResourceType.NETWORK: 100.0,
                ResourceType.STORAGE: 10.0,
                ResourceType.INSTANCES: 80.0
            },
            "chaos": {
                ResourceType.CPU: 256.0,
                ResourceType.MEMORY: 1024.0,
                ResourceType.NETWORK: 200.0,
                ResourceType.STORAGE: 20.0,
                ResourceType.INSTANCES: 160.0
            }
        }
        
        return requirements.get(phase, requirements["baseline"])
    
    async def calculate_scaling_decisions(
        self, 
        target_phase: str,
        current_metrics: ResourceMetrics,
        strategy: ScalingStrategy = ScalingStrategy.GRADUAL
    ) -> List[ScalingDecision]:
        """Calculate scaling decisions for target phase"""
        
        target_requirements = self.get_phase_resource_requirements(target_phase)
        scaling_decisions = []
        
        for resource_type, target_value in target_requirements.items():
            decision = await self._calculate_resource_scaling_decision(
                resource_type, target_value, current_metrics, strategy
            )
            scaling_decisions.append(decision)
        
        return scaling_decisions
    
    async def _calculate_resource_scaling_decision(
        self,
        resource_type: ResourceType,
        target_allocation: float,
        current_metrics: ResourceMetrics,
        strategy: ScalingStrategy
    ) -> ScalingDecision:
        """Calculate scaling decision for specific resource"""
        
        current_allocation = self._get_current_allocation(resource_type)
        resource_pool = self.resource_pools[resource_type]
        
        # Determine scaling strategy
        if target_allocation > current_allocation:
            # Scale up decision
            scaling_factor = self._get_scale_up_factor(strategy, resource_type)
            estimated_time = self._estimate_scale_up_time(resource_type, target_allocation)
            risk_level = self._assess_scale_up_risk(resource_type, target_allocation)
            justification = f"Scaling up {resource_type.value} for phase requirements"
            
        elif target_allocation < current_allocation:
            # Scale down decision
            scaling_factor = self._get_scale_down_factor(strategy, resource_type)
            estimated_time = self._estimate_scale_down_time(resource_type, target_allocation)
            risk_level = self._assess_scale_down_risk(resource_type, target_allocation)
            justification = f"Scaling down {resource_type.value} to optimize costs"
            
        else:
            # No scaling needed
            scaling_factor = 1.0
            estimated_time = 0
            risk_level = "LOW"
            justification = f"No scaling required for {resource_type.value}"
        
        cost_impact = self._calculate_cost_impact(
            resource_type, current_allocation, target_allocation
        )
        
        return ScalingDecision(
            resource_type=resource_type,
            current_allocation=current_allocation,
            target_allocation=target_allocation,
            scaling_strategy=strategy,
            justification=justification,
            estimated_time=estimated_time,
            cost_impact=cost_impact,
            risk_level=risk_level
        )
    
    def _get_current_allocation(self, resource_type: ResourceType) -> float:
        """Get current resource allocation"""
        return self.resource_pools[resource_type].allocated
    
    def _get_scale_up_factor(self, strategy: ScalingStrategy, resource_type: ResourceType) -> float:
        """Get scale up factor based on strategy"""
        strategy_config = self.scaling_strategies[strategy]
        base_factor = strategy_config.get("scale_up_factor", 1.5)
        resource_factor = self.resource_pools[resource_type].scaling_factor
        
        return min(base_factor, resource_factor)
    
    def _get_scale_down_factor(self, strategy: ScalingStrategy, resource_type: ResourceType) -> float:
        """Get scale down factor based on strategy"""
        strategy_config = self.scaling_strategies[strategy]
        return strategy_config.get("scale_down_factor", 0.7)
    
    def _estimate_scale_up_time(self, resource_type: ResourceType, target_allocation: float) -> int:
        """Estimate time required for scaling up"""
        base_times = {
            ResourceType.CPU: 120,      # 2 minutes
            ResourceType.MEMORY: 90,    # 1.5 minutes
            ResourceType.NETWORK: 180,  # 3 minutes
            ResourceType.STORAGE: 300,  # 5 minutes
            ResourceType.INSTANCES: 240 # 4 minutes
        }
        
        base_time = base_times.get(resource_type, 120)
        current_allocation = self._get_current_allocation(resource_type)
        scaling_factor = target_allocation / max(current_allocation, 1)
        
        # More aggressive scaling takes longer
        if scaling_factor > 2.0:
            return int(base_time * 1.5)
        elif scaling_factor > 1.5:
            return int(base_time * 1.2)
        else:
            return base_time
    
    def _estimate_scale_down_time(self, resource_type: ResourceType, target_allocation: float) -> int:
        """Estimate time required for scaling down"""
        # Scale down is generally faster than scale up
        scale_up_time = self._estimate_scale_up_time(resource_type, target_allocation)
        return int(scale_up_time * 0.6)
    
    def _assess_scale_up_risk(self, resource_type: ResourceType, target_allocation: float) -> str:
        """Assess risk level for scaling up"""
        resource_pool = self.resource_pools[resource_type]
        utilization_after_scaling = target_allocation / resource_pool.total_capacity
        
        if utilization_after_scaling > 0.9:
            return "HIGH"
        elif utilization_after_scaling > 0.7:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _assess_scale_down_risk(self, resource_type: ResourceType, target_allocation: float) -> str:
        """Assess risk level for scaling down"""
        current_allocation = self._get_current_allocation(resource_type)
        reduction_factor = target_allocation / max(current_allocation, 1)
        
        if reduction_factor < 0.5:
            return "MEDIUM"  # Aggressive scale down
        else:
            return "LOW"
    
    def _calculate_cost_impact(
        self, 
        resource_type: ResourceType, 
        current: float, 
        target: float
    ) -> float:
        """Calculate cost impact of scaling decision"""
        # Cost per unit per hour (simplified model)
        cost_rates = {
            ResourceType.CPU: 0.10,     # $0.10 per core per hour
            ResourceType.MEMORY: 0.05,  # $0.05 per GB per hour
            ResourceType.NETWORK: 0.02, # $0.02 per Gbps per hour
            ResourceType.STORAGE: 0.01, # $0.01 per TB per hour
            ResourceType.INSTANCES: 1.00 # $1.00 per instance per hour
        }
        
        rate = cost_rates.get(resource_type, 0.1)
        delta = target - current
        
        return delta * rate
    
    async def execute_scaling_decisions(self, decisions: List[ScalingDecision]) -> Dict:
        """Execute scaling decisions"""
        self.logger.info(f"Executing {len(decisions)} scaling decisions")
        
        execution_results = {
            "start_time": datetime.now().isoformat(),
            "decisions": [],
            "total_cost_impact": 0.0,
            "total_execution_time": 0,
            "success": True,
            "errors": []
        }
        
        for decision in decisions:
            try:
                result = await self._execute_single_scaling_decision(decision)
                execution_results["decisions"].append(result)
                execution_results["total_cost_impact"] += decision.cost_impact
                execution_results["total_execution_time"] = max(
                    execution_results["total_execution_time"], 
                    decision.estimated_time
                )
                
            except Exception as e:
                self.logger.error(f"Failed to execute scaling decision: {str(e)}")
                execution_results["errors"].append(str(e))
                execution_results["success"] = False
        
        execution_results["end_time"] = datetime.now().isoformat()
        
        return execution_results
    
    async def _execute_single_scaling_decision(self, decision: ScalingDecision) -> Dict:
        """Execute a single scaling decision"""
        self.logger.info(
            f"Scaling {decision.resource_type.value} from {decision.current_allocation} "
            f"to {decision.target_allocation}"
        )
        
        start_time = time.time()
        
        # Update resource pool allocation
        resource_pool = self.resource_pools[decision.resource_type]
        resource_pool.allocated = decision.target_allocation
        resource_pool.available = (
            resource_pool.total_capacity - 
            resource_pool.allocated - 
            resource_pool.reserved
        )
        
        # Simulate scaling time
        await asyncio.sleep(min(decision.estimated_time / 10, 5))  # Scaled down for demo
        
        # Record scaling decision
        self.scaling_history.append(decision)
        
        execution_time = time.time() - start_time
        
        return {
            "resource_type": decision.resource_type.value,
            "success": True,
            "execution_time": execution_time,
            "new_allocation": decision.target_allocation,
            "cost_impact": decision.cost_impact
        }
    
    def get_resource_utilization_summary(self) -> Dict:
        """Get current resource utilization summary"""
        summary = {}
        
        for resource_type, pool in self.resource_pools.items():
            utilization = pool.allocated / pool.total_capacity if pool.total_capacity > 0 else 0
            
            summary[resource_type.value] = {
                "total_capacity": pool.total_capacity,
                "allocated": pool.allocated,
                "available": pool.available,
                "utilization_percent": round(utilization * 100, 2),
                "status": self._get_utilization_status(utilization, pool.utilization_threshold)
            }
        
        return summary
    
    def _get_utilization_status(self, utilization: float, threshold: float) -> str:
        """Get utilization status based on threshold"""
        if utilization >= threshold:
            return "HIGH"
        elif utilization >= threshold * 0.7:
            return "MEDIUM"
        else:
            return "LOW"
    
    async def predict_resource_requirements(
        self, 
        target_phase: str,
        historical_data: List[ResourceMetrics]
    ) -> Dict[ResourceType, float]:
        """Predict resource requirements using historical data"""
        
        if not historical_data:
            return self.get_phase_resource_requirements(target_phase)
        
        # Simple prediction based on trend analysis
        predictions = {}
        base_requirements = self.get_phase_resource_requirements(target_phase)
        
        for resource_type in ResourceType:
            # Calculate trend from historical data
            trend_factor = self._calculate_trend_factor(resource_type, historical_data)
            base_requirement = base_requirements[resource_type]
            
            # Apply trend factor with bounds
            predicted_requirement = base_requirement * max(0.5, min(2.0, trend_factor))
            predictions[resource_type] = predicted_requirement
        
        return predictions
    
    def _calculate_trend_factor(
        self, 
        resource_type: ResourceType, 
        historical_data: List[ResourceMetrics]
    ) -> float:
        """Calculate trend factor for resource type"""
        if len(historical_data) < 2:
            return 1.0
        
        # Extract utilization values for the resource type
        utilization_values = []
        for metrics in historical_data[-10:]:  # Last 10 data points
            if resource_type == ResourceType.CPU:
                utilization_values.append(metrics.cpu_utilization)
            elif resource_type == ResourceType.MEMORY:
                utilization_values.append(metrics.memory_utilization)
            elif resource_type == ResourceType.NETWORK:
                utilization_values.append(metrics.network_utilization)
            elif resource_type == ResourceType.STORAGE:
                utilization_values.append(metrics.storage_utilization)
            else:
                utilization_values.append(1.0)
        
        # Simple linear trend calculation
        if len(utilization_values) >= 2:
            recent_avg = sum(utilization_values[-3:]) / min(3, len(utilization_values))
            earlier_avg = sum(utilization_values[:3]) / min(3, len(utilization_values))
            
            if earlier_avg > 0:
                trend_factor = recent_avg / earlier_avg
                return trend_factor
        
        return 1.0
    
    def generate_scaling_report(self) -> Dict:
        """Generate comprehensive scaling report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "resource_utilization": self.get_resource_utilization_summary(),
            "scaling_history": [
                {
                    "resource_type": decision.resource_type.value,
                    "scaling_strategy": decision.scaling_strategy.value,
                    "cost_impact": decision.cost_impact,
                    "risk_level": decision.risk_level,
                    "justification": decision.justification
                }
                for decision in self.scaling_history[-10:]  # Last 10 decisions
            ],
            "efficiency_metrics": self._calculate_efficiency_metrics(),
            "recommendations": self._generate_scaling_recommendations()
        }
        
        return report
    
    def _calculate_efficiency_metrics(self) -> Dict:
        """Calculate resource efficiency metrics"""
        total_cost = sum(decision.cost_impact for decision in self.scaling_history)
        successful_scalings = len([d for d in self.scaling_history if d.cost_impact >= 0])
        
        return {
            "total_scaling_cost": round(total_cost, 2),
            "successful_scalings": successful_scalings,
            "total_scalings": len(self.scaling_history),
            "success_rate": round(successful_scalings / max(len(self.scaling_history), 1) * 100, 2)
        }
    
    def _generate_scaling_recommendations(self) -> List[str]:
        """Generate scaling recommendations"""
        recommendations = []
        utilization_summary = self.get_resource_utilization_summary()
        
        for resource_type, info in utilization_summary.items():
            if info["status"] == "HIGH":
                recommendations.append(
                    f"Consider increasing {resource_type} capacity - currently at {info['utilization_percent']}%"
                )
            elif info["status"] == "LOW" and info["utilization_percent"] < 20:
                recommendations.append(
                    f"Consider reducing {resource_type} allocation - only using {info['utilization_percent']}%"
                )
        
        return recommendations

if __name__ == "__main__":
    async def main():
        matrix = ResourceScalingMatrix()
        
        # Example usage
        current_metrics = ResourceMetrics(
            cpu_utilization=45.0,
            memory_utilization=60.0,
            network_utilization=30.0,
            storage_utilization=25.0,
            instance_count=10,
            timestamp=datetime.now()
        )
        
        decisions = await matrix.calculate_scaling_decisions(
            "heavy", current_metrics, ScalingStrategy.GRADUAL
        )
        
        for decision in decisions:
            print(f"Scaling Decision: {decision.resource_type.value}")
            print(f"  Current: {decision.current_allocation}")
            print(f"  Target: {decision.target_allocation}")
            print(f"  Strategy: {decision.scaling_strategy.value}")
            print(f"  Cost Impact: ${decision.cost_impact:.2f}")
            print(f"  Risk Level: {decision.risk_level}")
            print(f"  Justification: {decision.justification}")
            print()
        
        # Execute scaling decisions
        results = await matrix.execute_scaling_decisions(decisions)
        print("Scaling Results:")
        print(json.dumps(results, indent=2))
        
        # Generate report
        report = matrix.generate_scaling_report()
        print("\nScaling Report:")
        print(json.dumps(report, indent=2))
    
    asyncio.run(main())