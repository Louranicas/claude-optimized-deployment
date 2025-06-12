"""
Test Environments - Dynamic Environment Scaling and Resource Management

This module provides comprehensive test environment management with
dynamic scaling, resource optimization, and expert-driven decisions.
"""

from .scaling import (
    ScalingOrchestrator,
    ResourceManager,
    CostOptimizer,
    CapacityPlanner,
    Autoscaler
)

__all__ = [
    'ScalingOrchestrator',
    'ResourceManager',
    'CostOptimizer', 
    'CapacityPlanner',
    'Autoscaler'
]

__version__ = "1.0.0"