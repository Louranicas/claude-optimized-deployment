"""
Dynamic Environment Scaling and Resource Management

This module provides comprehensive dynamic scaling and intelligent resource management
for optimal test execution across different load scenarios.

Key Components:
- Scaling Orchestrator: Central scaling coordination and control
- Resource Manager: Intelligent resource allocation system
- Cost Optimizer: Budget-aware scaling optimization
- Capacity Planner: Capacity planning and forecasting
- Autoscaler: Automatic scaling based on metrics and rules

Features:
- Dynamic horizontal and vertical scaling
- Multi-cloud support (AWS, Azure, GCP)
- Expert-driven scaling decisions
- Cost-aware resource management
- Predictive scaling with ML
"""

from .scaling_orchestrator import ScalingOrchestrator
from .resource_manager import ResourceManager
from .cost_optimizer import CostOptimizer
from .capacity_planner import CapacityPlanner
from .autoscaler import Autoscaler

__all__ = [
    'ScalingOrchestrator',
    'ResourceManager', 
    'CostOptimizer',
    'CapacityPlanner',
    'Autoscaler'
]

__version__ = "1.0.0"