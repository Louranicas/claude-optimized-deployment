"""
Chaos Engineering Scenarios

Pre-defined chaos experiment scenarios for various failure modes and testing patterns.
"""

from .cascade_failure import CascadeFailureScenario
from .partial_outage import PartialOutageScenario
from .resource_starvation import ResourceStarvationScenario
from .data_corruption import DataCorruptionScenario
from .network_partition import NetworkPartitionScenario

__all__ = [
    'CascadeFailureScenario',
    'PartialOutageScenario',
    'ResourceStarvationScenario', 
    'DataCorruptionScenario',
    'NetworkPartitionScenario'
]