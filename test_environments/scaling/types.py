"""
Shared types and enums for the scaling system
"""

from enum import Enum


class ScalingAction(Enum):
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    SCALE_OUT = "scale_out"
    SCALE_IN = "scale_in"
    OPTIMIZE = "optimize"
    MAINTAIN = "maintain"


class ScalingStrategy(Enum):
    REACTIVE = "reactive"
    PREDICTIVE = "predictive"
    EXPERT_DRIVEN = "expert_driven"
    COST_AWARE = "cost_aware"
    PERFORMANCE_FOCUSED = "performance_focused"