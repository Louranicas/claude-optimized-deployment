"""
Scaling Strategies for Dynamic Environment Management

This module provides various scaling strategies including predictive,
reactive, expert-driven, cost-aware, and performance-focused approaches.
"""

from .predictive_scaling import PredictiveScaling
from .reactive_scaling import ReactiveScaling
from .expert_scaling import ExpertScaling
from .cost_aware_scaling import CostAwareScaling
from .performance_scaling import PerformanceScaling

__all__ = [
    'PredictiveScaling',
    'ReactiveScaling', 
    'ExpertScaling',
    'CostAwareScaling',
    'PerformanceScaling'
]