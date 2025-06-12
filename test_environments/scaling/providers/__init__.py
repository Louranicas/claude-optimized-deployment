"""
Cloud Provider Integrations for Dynamic Scaling

This module provides integrations with major cloud providers for
automated infrastructure scaling and resource management.
"""

from .aws_scaler import AWSScaler
from .azure_scaler import AzureScaler
from .gcp_scaler import GCPScaler
from .kubernetes_scaler import KubernetesScaler
from .docker_scaler import DockerScaler

__all__ = [
    'AWSScaler',
    'AzureScaler', 
    'GCPScaler',
    'KubernetesScaler',
    'DockerScaler'
]