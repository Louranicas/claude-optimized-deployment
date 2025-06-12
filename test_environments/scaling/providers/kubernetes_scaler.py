"""
Kubernetes Scaler - Kubernetes horizontal and vertical pod autoscaling

This module provides comprehensive Kubernetes scaling capabilities including
HPA, VPA, cluster autoscaling, and custom resource scaling.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
import json
import yaml

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    KUBERNETES_AVAILABLE = True
except ImportError:
    KUBERNETES_AVAILABLE = False
    client = None
    config = None
    ApiException = Exception


class KubernetesResourceType(Enum):
    DEPLOYMENT = "deployment"
    STATEFULSET = "statefulset"
    REPLICASET = "replicaset"
    DAEMONSET = "daemonset"
    HPA = "hpa"
    VPA = "vpa"
    CLUSTER = "cluster"


class ScalingType(Enum):
    HORIZONTAL = "horizontal"
    VERTICAL = "vertical"
    CLUSTER = "cluster"


@dataclass
class KubernetesResource:
    """Kubernetes resource configuration"""
    resource_type: KubernetesResourceType
    name: str
    namespace: str
    current_replicas: int
    min_replicas: int
    max_replicas: int
    cpu_request: Optional[str] = None
    memory_request: Optional[str] = None
    cpu_limit: Optional[str] = None
    memory_limit: Optional[str] = None
    metadata: Dict[str, Any] = None


@dataclass
class HPAConfiguration:
    """HPA configuration"""
    name: str
    namespace: str
    target_resource: str
    min_replicas: int
    max_replicas: int
    target_cpu_utilization: Optional[int] = None
    target_memory_utilization: Optional[int] = None
    custom_metrics: List[Dict[str, Any]] = None
    behavior: Optional[Dict[str, Any]] = None


@dataclass
class VPAConfiguration:
    """VPA configuration"""
    name: str
    namespace: str
    target_resource: str
    update_mode: str = "Auto"  # Auto, Initial, Off
    resource_policy: Optional[Dict[str, Any]] = None


class KubernetesScaler:
    """
    Kubernetes horizontal and vertical pod autoscaling
    
    Provides comprehensive Kubernetes scaling including HPA, VPA,
    cluster autoscaling, and custom resource management.
    """
    
    def __init__(
        self,
        kubeconfig_path: Optional[str] = None,
        in_cluster: bool = False
    ):
        self.logger = logging.getLogger(__name__)
        self.kubeconfig_path = kubeconfig_path
        self.in_cluster = in_cluster
        
        # Kubernetes clients
        self.api_client = None
        self.apps_v1 = None
        self.autoscaling_v1 = None
        self.autoscaling_v2 = None
        self.metrics_v1beta1 = None
        
        if KUBERNETES_AVAILABLE:
            try:
                self._initialize_kubernetes_clients()
            except Exception as e:
                self.logger.warning(f"Kubernetes client initialization failed: {e}")
        else:
            self.logger.warning("kubernetes package not available - scaling will be simulated")
        
        # Resource tracking
        self.managed_resources: Dict[str, KubernetesResource] = {}
        self.hpa_configurations: Dict[str, HPAConfiguration] = {}
        self.vpa_configurations: Dict[str, VPAConfiguration] = {}
        self.scaling_operations: Dict[str, Dict] = {}
        
        # Scaling configuration
        self.default_scaling_config = {
            'scale_up_stabilization_window': 60,  # seconds
            'scale_down_stabilization_window': 300,  # seconds
            'scale_up_percent': 100,  # max 100% increase per step
            'scale_down_percent': 50,  # max 50% decrease per step
            'sync_period': 15  # seconds
        }
    
    async def scale_deployment(
        self,
        name: str,
        namespace: str,
        replicas: int,
        wait_for_completion: bool = True
    ) -> Dict[str, Any]:
        """
        Scale Kubernetes deployment
        
        Args:
            name: Deployment name
            namespace: Kubernetes namespace
            replicas: Target replica count
            wait_for_completion: Wait for scaling to complete
            
        Returns:
            Scaling operation result
        """
        try:
            if not self.apps_v1:
                return await self._simulate_deployment_scaling(name, namespace, replicas)
            
            # Get current deployment
            deployment = self.apps_v1.read_namespaced_deployment(
                name=name,
                namespace=namespace
            )
            
            current_replicas = deployment.spec.replicas
            
            # Update deployment replicas
            deployment.spec.replicas = replicas
            
            self.apps_v1.patch_namespaced_deployment(
                name=name,
                namespace=namespace,
                body=deployment
            )
            
            operation_id = f"k8s_deploy_scale_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            self.scaling_operations[operation_id] = {
                'resource_type': KubernetesResourceType.DEPLOYMENT,
                'name': name,
                'namespace': namespace,
                'operation': 'scale',
                'start_time': datetime.now(),
                'old_replicas': current_replicas,
                'new_replicas': replicas,
                'status': 'in_progress'
            }
            
            result = {
                'success': True,
                'operation_id': operation_id,
                'old_replicas': current_replicas,
                'new_replicas': replicas,
                'message': f'Scaling deployment {name} to {replicas} replicas'
            }
            
            # Wait for completion if requested
            if wait_for_completion:
                completion_result = await self._wait_for_deployment_scaling(
                    name, namespace, replicas, operation_id
                )
                result.update(completion_result)
            
            return result
            
        except ApiException as e:
            self.logger.error(f"Kubernetes deployment scaling failed: {e}")
            return {
                'success': False,
                'error': f'Kubernetes API error: {e.reason}',
                'status_code': e.status
            }
        except Exception as e:
            self.logger.error(f"Deployment scaling failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def create_hpa(
        self,
        hpa_config: HPAConfiguration
    ) -> Dict[str, Any]:
        """
        Create Horizontal Pod Autoscaler
        
        Args:
            hpa_config: HPA configuration
            
        Returns:
            HPA creation result
        """
        try:
            if not self.autoscaling_v2:
                return await self._simulate_hpa_creation(hpa_config)
            
            # Build HPA manifest
            hpa_manifest = self._build_hpa_manifest(hpa_config)
            
            # Create HPA
            self.autoscaling_v2.create_namespaced_horizontal_pod_autoscaler(
                namespace=hpa_config.namespace,
                body=hpa_manifest
            )
            
            # Store configuration
            hpa_key = f"{hpa_config.namespace}/{hpa_config.name}"
            self.hpa_configurations[hpa_key] = hpa_config
            
            operation_id = f"k8s_hpa_create_{hpa_config.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            self.scaling_operations[operation_id] = {
                'resource_type': KubernetesResourceType.HPA,
                'name': hpa_config.name,
                'namespace': hpa_config.namespace,
                'operation': 'create',
                'start_time': datetime.now(),
                'status': 'completed'
            }
            
            return {
                'success': True,
                'operation_id': operation_id,
                'hpa_name': hpa_config.name,
                'namespace': hpa_config.namespace,
                'message': f'Created HPA {hpa_config.name} in namespace {hpa_config.namespace}'
            }
            
        except ApiException as e:
            self.logger.error(f"HPA creation failed: {e}")
            return {
                'success': False,
                'error': f'Kubernetes API error: {e.reason}',
                'status_code': e.status
            }
        except Exception as e:
            self.logger.error(f"HPA creation failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def create_vpa(
        self,
        vpa_config: VPAConfiguration
    ) -> Dict[str, Any]:
        """
        Create Vertical Pod Autoscaler
        
        Args:
            vpa_config: VPA configuration
            
        Returns:
            VPA creation result
        """
        try:
            if not self.api_client:
                return await self._simulate_vpa_creation(vpa_config)
            
            # Build VPA manifest
            vpa_manifest = self._build_vpa_manifest(vpa_config)
            
            # Create VPA using custom resource API
            custom_objects_api = client.CustomObjectsApi(self.api_client)
            
            custom_objects_api.create_namespaced_custom_object(
                group="autoscaling.k8s.io",
                version="v1",
                namespace=vpa_config.namespace,
                plural="verticalpodautoscalers",
                body=vpa_manifest
            )
            
            # Store configuration
            vpa_key = f"{vpa_config.namespace}/{vpa_config.name}"
            self.vpa_configurations[vpa_key] = vpa_config
            
            operation_id = f"k8s_vpa_create_{vpa_config.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            self.scaling_operations[operation_id] = {
                'resource_type': KubernetesResourceType.VPA,
                'name': vpa_config.name,
                'namespace': vpa_config.namespace,
                'operation': 'create',
                'start_time': datetime.now(),
                'status': 'completed'
            }
            
            return {
                'success': True,
                'operation_id': operation_id,
                'vpa_name': vpa_config.name,
                'namespace': vpa_config.namespace,
                'message': f'Created VPA {vpa_config.name} in namespace {vpa_config.namespace}'
            }
            
        except ApiException as e:
            self.logger.error(f"VPA creation failed: {e}")
            return {
                'success': False,
                'error': f'Kubernetes API error: {e.reason}',
                'status_code': e.status
            }
        except Exception as e:
            self.logger.error(f"VPA creation failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_pod_metrics(
        self,
        namespace: str,
        label_selector: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get pod metrics from metrics server
        
        Args:
            namespace: Kubernetes namespace
            label_selector: Label selector for filtering pods
            
        Returns:
            Pod metrics data
        """
        try:
            if not self.metrics_v1beta1:
                return await self._simulate_pod_metrics(namespace, label_selector)
            
            # Get pod metrics
            if label_selector:
                metrics = self.metrics_v1beta1.list_namespaced_pod_metrics(
                    namespace=namespace,
                    label_selector=label_selector
                )
            else:
                metrics = self.metrics_v1beta1.list_namespaced_pod_metrics(
                    namespace=namespace
                )
            
            pod_metrics = []
            for item in metrics.items:
                pod_data = {
                    'name': item.metadata.name,
                    'namespace': item.metadata.namespace,
                    'timestamp': item.timestamp.isoformat(),
                    'containers': []
                }
                
                for container in item.containers:
                    container_data = {
                        'name': container.name,
                        'cpu_usage': container.usage.get('cpu', '0'),
                        'memory_usage': container.usage.get('memory', '0')
                    }
                    pod_data['containers'].append(container_data)
                
                pod_metrics.append(pod_data)
            
            return {
                'success': True,
                'pod_metrics': pod_metrics,
                'namespace': namespace,
                'total_pods': len(pod_metrics)
            }
            
        except ApiException as e:
            self.logger.error(f"Failed to get pod metrics: {e}")
            return {
                'success': False,
                'error': f'Kubernetes API error: {e.reason}',
                'status_code': e.status
            }
        except Exception as e:
            self.logger.error(f"Failed to get pod metrics: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_hpa_status(
        self,
        name: str,
        namespace: str
    ) -> Dict[str, Any]:
        """
        Get HPA status and metrics
        
        Args:
            name: HPA name
            namespace: Kubernetes namespace
            
        Returns:
            HPA status information
        """
        try:
            if not self.autoscaling_v2:
                return await self._simulate_hpa_status(name, namespace)
            
            # Get HPA
            hpa = self.autoscaling_v2.read_namespaced_horizontal_pod_autoscaler(
                name=name,
                namespace=namespace
            )
            
            status_data = {
                'name': hpa.metadata.name,
                'namespace': hpa.metadata.namespace,
                'target_resource': {
                    'kind': hpa.spec.scale_target_ref.kind,
                    'name': hpa.spec.scale_target_ref.name
                },
                'min_replicas': hpa.spec.min_replicas,
                'max_replicas': hpa.spec.max_replicas,
                'current_replicas': hpa.status.current_replicas,
                'desired_replicas': hpa.status.desired_replicas,
                'current_metrics': [],
                'conditions': []
            }
            
            # Current metrics
            if hpa.status.current_metrics:
                for metric in hpa.status.current_metrics:
                    metric_data = {
                        'type': metric.type,
                        'current_value': None
                    }
                    
                    if metric.resource:
                        if metric.resource.current:
                            metric_data['current_value'] = metric.resource.current.average_utilization
                    
                    status_data['current_metrics'].append(metric_data)
            
            # Conditions
            if hpa.status.conditions:
                for condition in hpa.status.conditions:
                    condition_data = {
                        'type': condition.type,
                        'status': condition.status,
                        'reason': condition.reason,
                        'message': condition.message,
                        'last_transition_time': condition.last_transition_time.isoformat() if condition.last_transition_time else None
                    }
                    status_data['conditions'].append(condition_data)
            
            return {
                'success': True,
                'hpa_status': status_data
            }
            
        except ApiException as e:
            self.logger.error(f"Failed to get HPA status: {e}")
            return {
                'success': False,
                'error': f'Kubernetes API error: {e.reason}',
                'status_code': e.status
            }
        except Exception as e:
            self.logger.error(f"Failed to get HPA status: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def update_resource_requests(
        self,
        deployment_name: str,
        namespace: str,
        container_name: str,
        cpu_request: Optional[str] = None,
        memory_request: Optional[str] = None,
        cpu_limit: Optional[str] = None,
        memory_limit: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update resource requests and limits for deployment
        
        Args:
            deployment_name: Deployment name
            namespace: Kubernetes namespace
            container_name: Container name
            cpu_request: CPU request (e.g., "100m")
            memory_request: Memory request (e.g., "128Mi")
            cpu_limit: CPU limit (e.g., "500m")
            memory_limit: Memory limit (e.g., "512Mi")
            
        Returns:
            Update operation result
        """
        try:
            if not self.apps_v1:
                return await self._simulate_resource_update(
                    deployment_name, namespace, container_name,
                    cpu_request, memory_request, cpu_limit, memory_limit
                )
            
            # Get current deployment
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deployment_name,
                namespace=namespace
            )
            
            # Find and update container resources
            container_found = False
            for container in deployment.spec.template.spec.containers:
                if container.name == container_name:
                    container_found = True
                    
                    if not container.resources:
                        container.resources = client.V1ResourceRequirements()
                    
                    # Update requests
                    if cpu_request or memory_request:
                        if not container.resources.requests:
                            container.resources.requests = {}
                        
                        if cpu_request:
                            container.resources.requests['cpu'] = cpu_request
                        if memory_request:
                            container.resources.requests['memory'] = memory_request
                    
                    # Update limits
                    if cpu_limit or memory_limit:
                        if not container.resources.limits:
                            container.resources.limits = {}
                        
                        if cpu_limit:
                            container.resources.limits['cpu'] = cpu_limit
                        if memory_limit:
                            container.resources.limits['memory'] = memory_limit
                    
                    break
            
            if not container_found:
                return {
                    'success': False,
                    'error': f'Container {container_name} not found in deployment {deployment_name}'
                }
            
            # Apply update
            self.apps_v1.patch_namespaced_deployment(
                name=deployment_name,
                namespace=namespace,
                body=deployment
            )
            
            operation_id = f"k8s_resource_update_{deployment_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            self.scaling_operations[operation_id] = {
                'resource_type': KubernetesResourceType.DEPLOYMENT,
                'name': deployment_name,
                'namespace': namespace,
                'operation': 'update_resources',
                'start_time': datetime.now(),
                'status': 'completed'
            }
            
            return {
                'success': True,
                'operation_id': operation_id,
                'deployment_name': deployment_name,
                'container_name': container_name,
                'updated_resources': {
                    'cpu_request': cpu_request,
                    'memory_request': memory_request,
                    'cpu_limit': cpu_limit,
                    'memory_limit': memory_limit
                },
                'message': f'Updated resources for container {container_name} in deployment {deployment_name}'
            }
            
        except ApiException as e:
            self.logger.error(f"Resource update failed: {e}")
            return {
                'success': False,
                'error': f'Kubernetes API error: {e.reason}',
                'status_code': e.status
            }
        except Exception as e:
            self.logger.error(f"Resource update failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _initialize_kubernetes_clients(self):
        """Initialize Kubernetes API clients"""
        try:
            if self.in_cluster:
                config.load_incluster_config()
            else:
                config.load_kube_config(config_file=self.kubeconfig_path)
            
            self.api_client = client.ApiClient()
            self.apps_v1 = client.AppsV1Api()
            self.autoscaling_v1 = client.AutoscalingV1Api()
            self.autoscaling_v2 = client.AutoscalingV2Api()
            
            # Try to initialize metrics API (may not be available)
            try:
                self.metrics_v1beta1 = client.MetricsV1beta1Api()
            except Exception:
                self.logger.warning("Metrics API not available")
                self.metrics_v1beta1 = None
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Kubernetes clients: {e}")
            raise
    
    def _build_hpa_manifest(self, hpa_config: HPAConfiguration) -> Dict[str, Any]:
        """Build HPA manifest from configuration"""
        manifest = {
            'apiVersion': 'autoscaling/v2',
            'kind': 'HorizontalPodAutoscaler',
            'metadata': {
                'name': hpa_config.name,
                'namespace': hpa_config.namespace
            },
            'spec': {
                'scaleTargetRef': {
                    'apiVersion': 'apps/v1',
                    'kind': 'Deployment',
                    'name': hpa_config.target_resource
                },
                'minReplicas': hpa_config.min_replicas,
                'maxReplicas': hpa_config.max_replicas,
                'metrics': []
            }
        }
        
        # Add CPU utilization metric
        if hpa_config.target_cpu_utilization:
            manifest['spec']['metrics'].append({
                'type': 'Resource',
                'resource': {
                    'name': 'cpu',
                    'target': {
                        'type': 'Utilization',
                        'averageUtilization': hpa_config.target_cpu_utilization
                    }
                }
            })
        
        # Add memory utilization metric
        if hpa_config.target_memory_utilization:
            manifest['spec']['metrics'].append({
                'type': 'Resource',
                'resource': {
                    'name': 'memory',
                    'target': {
                        'type': 'Utilization',
                        'averageUtilization': hpa_config.target_memory_utilization
                    }
                }
            })
        
        # Add custom metrics
        if hpa_config.custom_metrics:
            manifest['spec']['metrics'].extend(hpa_config.custom_metrics)
        
        # Add behavior configuration
        if hpa_config.behavior:
            manifest['spec']['behavior'] = hpa_config.behavior
        
        return manifest
    
    def _build_vpa_manifest(self, vpa_config: VPAConfiguration) -> Dict[str, Any]:
        """Build VPA manifest from configuration"""
        manifest = {
            'apiVersion': 'autoscaling.k8s.io/v1',
            'kind': 'VerticalPodAutoscaler',
            'metadata': {
                'name': vpa_config.name,
                'namespace': vpa_config.namespace
            },
            'spec': {
                'targetRef': {
                    'apiVersion': 'apps/v1',
                    'kind': 'Deployment',
                    'name': vpa_config.target_resource
                },
                'updatePolicy': {
                    'updateMode': vpa_config.update_mode
                }
            }
        }
        
        # Add resource policy
        if vpa_config.resource_policy:
            manifest['spec']['resourcePolicy'] = vpa_config.resource_policy
        
        return manifest
    
    async def _simulate_deployment_scaling(
        self,
        name: str,
        namespace: str,
        replicas: int
    ) -> Dict[str, Any]:
        """Simulate deployment scaling"""
        await asyncio.sleep(0.1)
        
        operation_id = f"sim_k8s_deploy_scale_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return {
            'success': True,
            'operation_id': operation_id,
            'old_replicas': 2,  # Simulated
            'new_replicas': replicas,
            'message': f'Simulated scaling deployment {name} to {replicas} replicas',
            'simulated': True
        }
    
    async def _simulate_hpa_creation(self, hpa_config: HPAConfiguration) -> Dict[str, Any]:
        """Simulate HPA creation"""
        await asyncio.sleep(0.1)
        
        operation_id = f"sim_k8s_hpa_create_{hpa_config.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return {
            'success': True,
            'operation_id': operation_id,
            'hpa_name': hpa_config.name,
            'namespace': hpa_config.namespace,
            'message': f'Simulated HPA creation for {hpa_config.name}',
            'simulated': True
        }
    
    async def _simulate_vpa_creation(self, vpa_config: VPAConfiguration) -> Dict[str, Any]:
        """Simulate VPA creation"""
        await asyncio.sleep(0.1)
        
        operation_id = f"sim_k8s_vpa_create_{vpa_config.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return {
            'success': True,
            'operation_id': operation_id,
            'vpa_name': vpa_config.name,
            'namespace': vpa_config.namespace,
            'message': f'Simulated VPA creation for {vpa_config.name}',
            'simulated': True
        }
    
    async def get_scaling_status(self) -> Dict[str, Any]:
        """Get current Kubernetes scaling status"""
        return {
            'kubernetes_available': KUBERNETES_AVAILABLE and self.api_client is not None,
            'in_cluster': self.in_cluster,
            'active_operations': len([
                op for op in self.scaling_operations.values()
                if op['status'] == 'in_progress'
            ]),
            'total_operations': len(self.scaling_operations),
            'managed_hpas': len(self.hpa_configurations),
            'managed_vpas': len(self.vpa_configurations),
            'managed_resources': len(self.managed_resources),
            'recent_operations': [
                {
                    'operation_id': op_id,
                    'resource_type': op['resource_type'].value,
                    'name': op['name'],
                    'namespace': op['namespace'],
                    'status': op['status'],
                    'start_time': op['start_time'].isoformat()
                }
                for op_id, op in list(self.scaling_operations.items())[-10:]
            ]
        }