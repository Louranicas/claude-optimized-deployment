"""
Chaos Engineering Framework for Resilience Testing

This package provides comprehensive chaos engineering capabilities including:
- Systematic failure injection across all system layers
- Resilience testing and validation
- Breaking point analysis and system limit identification
- Recovery validation and measurement
- Expert-driven chaos scenario orchestration

Components:
- chaos_orchestrator: Central coordination and experiment management
- failure_injector: Core failure injection system
- resilience_validator: Recovery and fault tolerance validation
- breaking_point_analyzer: System limit identification
- recovery_measurer: Recovery time and effectiveness measurement
- injectors/: Specialized failure injection modules
- scenarios/: Pre-defined chaos experiment scenarios
- validators/: Resilience testing and validation tools
- analyzers/: Analysis and measurement components
- safety/: Safety mechanisms and emergency procedures
"""

from .chaos_orchestrator import ChaosOrchestrator
from .failure_injector import FailureInjector
from .resilience_validator import ResilienceValidator
from .breaking_point_analyzer import BreakingPointAnalyzer
from .recovery_measurer import RecoveryMeasurer

__all__ = [
    'ChaosOrchestrator',
    'FailureInjector', 
    'ResilienceValidator',
    'BreakingPointAnalyzer',
    'RecoveryMeasurer'
]

__version__ = "1.0.0"