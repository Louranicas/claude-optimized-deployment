"""
AWS Scaler - AWS infrastructure scaling implementation

This module provides comprehensive AWS infrastructure scaling capabilities
including EC2, ECS, EKS, Lambda, RDS, and ElastiCache scaling.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import json

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    boto3 = None
    ClientError = Exception
    NoCredentialsError = Exception


class AWSService(Enum):
    EC2 = "ec2"
    ECS = "ecs"
    EKS = "eks"
    LAMBDA = "lambda"
    RDS = "rds"
    ELASTICACHE = "elasticache"
    AUTO_SCALING = "autoscaling"


@dataclass
class AWSResource:
    """AWS resource configuration"""
    service: AWSService
    resource_id: str
    resource_type: str
    region: str
    current_capacity: int
    min_capacity: int
    max_capacity: int
    metadata: Dict[str, Any]


class AWSScaler:
    """
    AWS infrastructure scaling implementation
    
    Provides scaling capabilities for EC2, ECS, EKS, Lambda, RDS,
    and ElastiCache services with cost optimization and monitoring.
    """
    
    def __init__(
        self,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        region_name: str = 'us-east-1'
    ):
        self.logger = logging.getLogger(__name__)
        self.region_name = region_name
        
        # AWS clients
        self.clients = {}
        self.session = None
        
        if AWS_AVAILABLE:
            try:
                # Initialize AWS session
                if aws_access_key_id and aws_secret_access_key:
                    self.session = boto3.Session(
                        aws_access_key_id=aws_access_key_id,
                        aws_secret_access_key=aws_secret_access_key,
                        region_name=region_name
                    )
                else:
                    self.session = boto3.Session(region_name=region_name)
                
                # Initialize clients
                self._initialize_clients()
                
            except (NoCredentialsError, Exception) as e:
                self.logger.warning(f"AWS credentials not available: {e}")
                self.session = None
        else:
            self.logger.warning("boto3 not available - AWS scaling will be simulated")
        
        # Resource tracking
        self.managed_resources: Dict[str, AWSResource] = {}
        self.scaling_operations: Dict[str, Dict] = {}
        
        # Configuration
        self.default_timeouts = {
            AWSService.EC2: 300,  # 5 minutes
            AWSService.ECS: 600,  # 10 minutes
            AWSService.EKS: 900,  # 15 minutes
            AWSService.LAMBDA: 60,  # 1 minute
            AWSService.RDS: 1800,  # 30 minutes
            AWSService.ELASTICACHE: 1200  # 20 minutes
        }
    
    async def scale_ec2_instances(
        self,
        auto_scaling_group_name: str,
        desired_capacity: int,
        wait_for_completion: bool = True
    ) -> Dict[str, Any]:
        """
        Scale EC2 Auto Scaling Group
        
        Args:
            auto_scaling_group_name: ASG name
            desired_capacity: Target instance count
            wait_for_completion: Wait for scaling to complete
            
        Returns:
            Scaling operation result
        """
        try:
            if not self.session:
                return await self._simulate_ec2_scaling(
                    auto_scaling_group_name, desired_capacity
                )
            
            autoscaling_client = self.clients.get('autoscaling')
            if not autoscaling_client:
                raise Exception("Auto Scaling client not available")
            
            # Get current ASG configuration
            asg_response = autoscaling_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[auto_scaling_group_name]
            )
            
            if not asg_response['AutoScalingGroups']:
                raise Exception(f"Auto Scaling Group {auto_scaling_group_name} not found")
            
            asg = asg_response['AutoScalingGroups'][0]
            current_capacity = asg['DesiredCapacity']
            min_size = asg['MinSize']
            max_size = asg['MaxSize']
            
            # Validate capacity
            if desired_capacity < min_size or desired_capacity > max_size:
                raise Exception(
                    f"Desired capacity {desired_capacity} outside range [{min_size}, {max_size}]"
                )
            
            # Update ASG capacity
            autoscaling_client.set_desired_capacity(
                AutoScalingGroupName=auto_scaling_group_name,
                DesiredCapacity=desired_capacity,
                HonorCooldown=False
            )
            
            operation_id = f"ec2_scale_{auto_scaling_group_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            self.scaling_operations[operation_id] = {
                'service': AWSService.EC2,
                'resource_id': auto_scaling_group_name,
                'operation': 'scale',
                'start_time': datetime.now(),
                'old_capacity': current_capacity,
                'new_capacity': desired_capacity,
                'status': 'in_progress'
            }
            
            result = {
                'success': True,
                'operation_id': operation_id,
                'old_capacity': current_capacity,
                'new_capacity': desired_capacity,
                'message': f'Scaling ASG {auto_scaling_group_name} to {desired_capacity} instances'
            }
            
            # Wait for completion if requested
            if wait_for_completion:
                completion_result = await self._wait_for_ec2_scaling_completion(
                    auto_scaling_group_name, desired_capacity, operation_id
                )
                result.update(completion_result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"EC2 scaling failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'service': 'ec2'
            }
    
    async def scale_ecs_service(
        self,
        cluster_name: str,
        service_name: str,
        desired_count: int,
        wait_for_completion: bool = True
    ) -> Dict[str, Any]:
        """
        Scale ECS service
        
        Args:
            cluster_name: ECS cluster name
            service_name: ECS service name
            desired_count: Target task count
            wait_for_completion: Wait for scaling to complete
            
        Returns:
            Scaling operation result
        """
        try:
            if not self.session:
                return await self._simulate_ecs_scaling(
                    cluster_name, service_name, desired_count
                )
            
            ecs_client = self.clients.get('ecs')
            if not ecs_client:
                raise Exception("ECS client not available")
            
            # Get current service configuration
            services_response = ecs_client.describe_services(
                cluster=cluster_name,
                services=[service_name]
            )
            
            if not services_response['services']:
                raise Exception(f"ECS service {service_name} not found in cluster {cluster_name}")
            
            service = services_response['services'][0]
            current_count = service['desiredCount']
            
            # Update service
            ecs_client.update_service(
                cluster=cluster_name,
                service=service_name,
                desiredCount=desired_count
            )
            
            operation_id = f"ecs_scale_{service_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            self.scaling_operations[operation_id] = {
                'service': AWSService.ECS,
                'resource_id': f"{cluster_name}/{service_name}",
                'operation': 'scale',
                'start_time': datetime.now(),
                'old_capacity': current_count,
                'new_capacity': desired_count,
                'status': 'in_progress'
            }
            
            result = {
                'success': True,
                'operation_id': operation_id,
                'old_capacity': current_count,
                'new_capacity': desired_count,
                'message': f'Scaling ECS service {service_name} to {desired_count} tasks'
            }
            
            # Wait for completion if requested
            if wait_for_completion:
                completion_result = await self._wait_for_ecs_scaling_completion(
                    cluster_name, service_name, desired_count, operation_id
                )
                result.update(completion_result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"ECS scaling failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'service': 'ecs'
            }
    
    async def scale_eks_nodes(
        self,
        cluster_name: str,
        nodegroup_name: str,
        desired_size: int,
        wait_for_completion: bool = True
    ) -> Dict[str, Any]:
        """
        Scale EKS node group
        
        Args:
            cluster_name: EKS cluster name
            nodegroup_name: Node group name
            desired_size: Target node count
            wait_for_completion: Wait for scaling to complete
            
        Returns:
            Scaling operation result
        """
        try:
            if not self.session:
                return await self._simulate_eks_scaling(
                    cluster_name, nodegroup_name, desired_size
                )
            
            eks_client = self.clients.get('eks')
            if not eks_client:
                raise Exception("EKS client not available")
            
            # Get current nodegroup configuration
            nodegroup_response = eks_client.describe_nodegroup(
                clusterName=cluster_name,
                nodegroupName=nodegroup_name
            )
            
            nodegroup = nodegroup_response['nodegroup']
            current_size = nodegroup['scalingConfig']['desiredSize']
            min_size = nodegroup['scalingConfig']['minSize']
            max_size = nodegroup['scalingConfig']['maxSize']
            
            # Validate size
            if desired_size < min_size or desired_size > max_size:
                raise Exception(
                    f"Desired size {desired_size} outside range [{min_size}, {max_size}]"
                )
            
            # Update nodegroup
            eks_client.update_nodegroup_config(
                clusterName=cluster_name,
                nodegroupName=nodegroup_name,
                scalingConfig={
                    'minSize': min_size,
                    'maxSize': max_size,
                    'desiredSize': desired_size
                }
            )
            
            operation_id = f"eks_scale_{nodegroup_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            self.scaling_operations[operation_id] = {
                'service': AWSService.EKS,
                'resource_id': f"{cluster_name}/{nodegroup_name}",
                'operation': 'scale',
                'start_time': datetime.now(),
                'old_capacity': current_size,
                'new_capacity': desired_size,
                'status': 'in_progress'
            }
            
            result = {
                'success': True,
                'operation_id': operation_id,
                'old_capacity': current_size,
                'new_capacity': desired_size,
                'message': f'Scaling EKS nodegroup {nodegroup_name} to {desired_size} nodes'
            }
            
            # Wait for completion if requested
            if wait_for_completion:
                completion_result = await self._wait_for_eks_scaling_completion(
                    cluster_name, nodegroup_name, desired_size, operation_id
                )
                result.update(completion_result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"EKS scaling failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'service': 'eks'
            }
    
    async def scale_lambda_concurrency(
        self,
        function_name: str,
        reserved_concurrency: int
    ) -> Dict[str, Any]:
        """
        Scale Lambda function concurrency
        
        Args:
            function_name: Lambda function name
            reserved_concurrency: Reserved concurrency limit
            
        Returns:
            Scaling operation result
        """
        try:
            if not self.session:
                return await self._simulate_lambda_scaling(
                    function_name, reserved_concurrency
                )
            
            lambda_client = self.clients.get('lambda')
            if not lambda_client:
                raise Exception("Lambda client not available")
            
            # Get current configuration
            try:
                current_response = lambda_client.get_provisioned_concurrency_config(
                    FunctionName=function_name
                )
                current_concurrency = current_response.get('AllocatedConcurrency', 0)
            except ClientError:
                current_concurrency = 0
            
            # Update concurrency
            if reserved_concurrency > 0:
                lambda_client.put_reserved_concurrency_config(
                    FunctionName=function_name,
                    ReservedConcurrencyConfig={
                        'ReservedConcurrentExecutions': reserved_concurrency
                    }
                )
            else:
                # Remove reserved concurrency
                try:
                    lambda_client.delete_reserved_concurrency_config(
                        FunctionName=function_name
                    )
                except ClientError:
                    pass  # May not exist
            
            operation_id = f"lambda_scale_{function_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            self.scaling_operations[operation_id] = {
                'service': AWSService.LAMBDA,
                'resource_id': function_name,
                'operation': 'scale_concurrency',
                'start_time': datetime.now(),
                'old_capacity': current_concurrency,
                'new_capacity': reserved_concurrency,
                'status': 'completed'
            }
            
            return {
                'success': True,
                'operation_id': operation_id,
                'old_concurrency': current_concurrency,
                'new_concurrency': reserved_concurrency,
                'message': f'Updated Lambda {function_name} concurrency to {reserved_concurrency}'
            }
            
        except Exception as e:
            self.logger.error(f"Lambda scaling failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'service': 'lambda'
            }
    
    async def scale_rds_cluster(
        self,
        cluster_identifier: str,
        min_capacity: int,
        max_capacity: int
    ) -> Dict[str, Any]:
        """
        Scale RDS Aurora Serverless cluster
        
        Args:
            cluster_identifier: RDS cluster identifier
            min_capacity: Minimum ACU capacity
            max_capacity: Maximum ACU capacity
            
        Returns:
            Scaling operation result
        """
        try:
            if not self.session:
                return await self._simulate_rds_scaling(
                    cluster_identifier, min_capacity, max_capacity
                )
            
            rds_client = self.clients.get('rds')
            if not rds_client:
                raise Exception("RDS client not available")
            
            # Get current cluster configuration
            clusters_response = rds_client.describe_db_clusters(
                DBClusterIdentifier=cluster_identifier
            )
            
            if not clusters_response['DBClusters']:
                raise Exception(f"RDS cluster {cluster_identifier} not found")
            
            cluster = clusters_response['DBClusters'][0]
            current_scaling_config = cluster.get('ScalingConfigurationInfo', {})
            
            # Update scaling configuration
            rds_client.modify_current_db_cluster_capacity(
                DBClusterIdentifier=cluster_identifier,
                Capacity=max_capacity,
                SecondsBeforeTimeout=300,
                TimeoutAction='ForceApplyCapacityChange'
            )
            
            operation_id = f"rds_scale_{cluster_identifier}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            self.scaling_operations[operation_id] = {
                'service': AWSService.RDS,
                'resource_id': cluster_identifier,
                'operation': 'scale',
                'start_time': datetime.now(),
                'old_capacity': current_scaling_config.get('MaxCapacity', 0),
                'new_capacity': max_capacity,
                'status': 'in_progress'
            }
            
            return {
                'success': True,
                'operation_id': operation_id,
                'old_min_capacity': current_scaling_config.get('MinCapacity', 0),
                'old_max_capacity': current_scaling_config.get('MaxCapacity', 0),
                'new_min_capacity': min_capacity,
                'new_max_capacity': max_capacity,
                'message': f'Scaling RDS cluster {cluster_identifier}'
            }
            
        except Exception as e:
            self.logger.error(f"RDS scaling failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'service': 'rds'
            }
    
    async def get_resource_metrics(
        self,
        service: AWSService,
        resource_id: str,
        metric_names: List[str],
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """
        Get CloudWatch metrics for AWS resources
        
        Args:
            service: AWS service type
            resource_id: Resource identifier
            metric_names: List of metric names to retrieve
            start_time: Metrics start time
            end_time: Metrics end time
            
        Returns:
            Resource metrics data
        """
        try:
            if not self.session:
                return await self._simulate_metrics(service, resource_id, metric_names)
            
            cloudwatch_client = self.clients.get('cloudwatch')
            if not cloudwatch_client:
                raise Exception("CloudWatch client not available")
            
            # Define namespace mapping
            namespace_mapping = {
                AWSService.EC2: 'AWS/EC2',
                AWSService.ECS: 'AWS/ECS',
                AWSService.EKS: 'AWS/EKS',
                AWSService.LAMBDA: 'AWS/Lambda',
                AWSService.RDS: 'AWS/RDS',
                AWSService.ELASTICACHE: 'AWS/ElastiCache'
            }
            
            namespace = namespace_mapping.get(service)
            if not namespace:
                raise Exception(f"Unknown service: {service}")
            
            metrics_data = {}
            
            for metric_name in metric_names:
                response = cloudwatch_client.get_metric_statistics(
                    Namespace=namespace,
                    MetricName=metric_name,
                    Dimensions=[
                        {
                            'Name': self._get_dimension_name(service),
                            'Value': resource_id
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=300,  # 5 minutes
                    Statistics=['Average', 'Maximum']
                )
                
                metrics_data[metric_name] = {
                    'datapoints': response['Datapoints'],
                    'unit': response.get('Unit', 'None')
                }
            
            return {
                'success': True,
                'metrics': metrics_data,
                'service': service.value,
                'resource_id': resource_id
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get metrics: {e}")
            return {
                'success': False,
                'error': str(e),
                'service': service.value
            }
    
    def _initialize_clients(self):
        """Initialize AWS service clients"""
        if not self.session:
            return
        
        try:
            self.clients = {
                'autoscaling': self.session.client('autoscaling'),
                'ec2': self.session.client('ec2'),
                'ecs': self.session.client('ecs'),
                'eks': self.session.client('eks'),
                'lambda': self.session.client('lambda'),
                'rds': self.session.client('rds'),
                'elasticache': self.session.client('elasticache'),
                'cloudwatch': self.session.client('cloudwatch')
            }
        except Exception as e:
            self.logger.error(f"Failed to initialize AWS clients: {e}")
            self.clients = {}
    
    def _get_dimension_name(self, service: AWSService) -> str:
        """Get CloudWatch dimension name for service"""
        dimension_mapping = {
            AWSService.EC2: 'InstanceId',
            AWSService.ECS: 'ServiceName',
            AWSService.EKS: 'ClusterName',
            AWSService.LAMBDA: 'FunctionName',
            AWSService.RDS: 'DBClusterIdentifier',
            AWSService.ELASTICACHE: 'CacheClusterId'
        }
        
        return dimension_mapping.get(service, 'ResourceId')
    
    async def _simulate_ec2_scaling(
        self,
        asg_name: str,
        desired_capacity: int
    ) -> Dict[str, Any]:
        """Simulate EC2 scaling operation"""
        await asyncio.sleep(0.1)  # Simulate API call
        
        operation_id = f"sim_ec2_scale_{asg_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return {
            'success': True,
            'operation_id': operation_id,
            'old_capacity': 2,  # Simulated
            'new_capacity': desired_capacity,
            'message': f'Simulated scaling ASG {asg_name} to {desired_capacity} instances',
            'simulated': True
        }
    
    async def _simulate_ecs_scaling(
        self,
        cluster_name: str,
        service_name: str,
        desired_count: int
    ) -> Dict[str, Any]:
        """Simulate ECS scaling operation"""
        await asyncio.sleep(0.1)
        
        operation_id = f"sim_ecs_scale_{service_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return {
            'success': True,
            'operation_id': operation_id,
            'old_capacity': 1,  # Simulated
            'new_capacity': desired_count,
            'message': f'Simulated scaling ECS service {service_name} to {desired_count} tasks',
            'simulated': True
        }
    
    async def _simulate_eks_scaling(
        self,
        cluster_name: str,
        nodegroup_name: str,
        desired_size: int
    ) -> Dict[str, Any]:
        """Simulate EKS scaling operation"""
        await asyncio.sleep(0.1)
        
        operation_id = f"sim_eks_scale_{nodegroup_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return {
            'success': True,
            'operation_id': operation_id,
            'old_capacity': 2,  # Simulated
            'new_capacity': desired_size,
            'message': f'Simulated scaling EKS nodegroup {nodegroup_name} to {desired_size} nodes',
            'simulated': True
        }
    
    async def _simulate_lambda_scaling(
        self,
        function_name: str,
        reserved_concurrency: int
    ) -> Dict[str, Any]:
        """Simulate Lambda scaling operation"""
        await asyncio.sleep(0.1)
        
        operation_id = f"sim_lambda_scale_{function_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return {
            'success': True,
            'operation_id': operation_id,
            'old_concurrency': 0,  # Simulated
            'new_concurrency': reserved_concurrency,
            'message': f'Simulated Lambda {function_name} concurrency scaling',
            'simulated': True
        }
    
    async def _simulate_rds_scaling(
        self,
        cluster_identifier: str,
        min_capacity: int,
        max_capacity: int
    ) -> Dict[str, Any]:
        """Simulate RDS scaling operation"""
        await asyncio.sleep(0.1)
        
        operation_id = f"sim_rds_scale_{cluster_identifier}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return {
            'success': True,
            'operation_id': operation_id,
            'old_min_capacity': 1,  # Simulated
            'old_max_capacity': 2,  # Simulated
            'new_min_capacity': min_capacity,
            'new_max_capacity': max_capacity,
            'message': f'Simulated RDS cluster {cluster_identifier} scaling',
            'simulated': True
        }
    
    async def _simulate_metrics(
        self,
        service: AWSService,
        resource_id: str,
        metric_names: List[str]
    ) -> Dict[str, Any]:
        """Simulate metrics retrieval"""
        await asyncio.sleep(0.1)
        
        # Generate simulated metrics
        metrics_data = {}
        for metric_name in metric_names:
            metrics_data[metric_name] = {
                'datapoints': [
                    {
                        'Timestamp': datetime.now() - timedelta(minutes=i*5),
                        'Average': 50.0 + (i % 10) * 5,
                        'Maximum': 80.0 + (i % 10) * 3,
                        'Unit': 'Percent'
                    }
                    for i in range(12)  # Last hour
                ],
                'unit': 'Percent'
            }
        
        return {
            'success': True,
            'metrics': metrics_data,
            'service': service.value,
            'resource_id': resource_id,
            'simulated': True
        }
    
    async def get_scaling_status(self) -> Dict[str, Any]:
        """Get current scaling operations status"""
        return {
            'aws_available': AWS_AVAILABLE and self.session is not None,
            'region': self.region_name,
            'active_operations': len([
                op for op in self.scaling_operations.values()
                if op['status'] == 'in_progress'
            ]),
            'total_operations': len(self.scaling_operations),
            'managed_resources': len(self.managed_resources),
            'recent_operations': [
                {
                    'operation_id': op_id,
                    'service': op['service'].value,
                    'resource_id': op['resource_id'],
                    'status': op['status'],
                    'start_time': op['start_time'].isoformat()
                }
                for op_id, op in list(self.scaling_operations.items())[-10:]
            ]
        }