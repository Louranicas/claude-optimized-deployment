"""
MCP Integration for Distributed Testing

This package implements a comprehensive MCP (Model Context Protocol) server integration
for distributed testing capabilities across multiple nodes and services.

Components:
- orchestrator.py: Central coordination service for distributed testing
- distributed_loader.py: MCP-enabled load generation nodes
- service_discovery.py: Automatic node registration and discovery
- communication.py: Inter-node messaging and coordination
- resource_pool.py: Distributed resource allocation and monitoring
- node_monitor.py: Node health monitoring and alerting
- test_distributor.py: Test workload distribution engine

Key Features:
- Distributed test coordination across multiple MCP servers
- Automatic service discovery and registration
- Intelligent workload distribution with multiple strategies
- Resource pooling and management across nodes
- Comprehensive health monitoring and alerting
- Reliable inter-node communication with fault tolerance
- Load generation with multiple patterns and protocols

Usage:
    from test_environments.mcp_integration import MCPTestOrchestrator
    from test_environments.mcp_integration import DistributedLoadGenerator
    from test_environments.mcp_integration import ServiceDiscovery
    
    # Start orchestrator
    orchestrator = MCPTestOrchestrator()
    await orchestrator.start()
    
    # Start load generator nodes
    generator = DistributedLoadGenerator("node_1")
    await generator.start()
    
    # Start service discovery
    discovery = ServiceDiscovery()
    await discovery.start()
"""

__version__ = "1.0.0"
__author__ = "Claude Code MCP Integration Team"

# Import main classes
from .orchestrator import MCPTestOrchestrator, TestExecution, TestTask, TestNode
from .distributed_loader import DistributedLoadGenerator, LoadProfile, LoadPattern, LoadMetrics
from .service_discovery import ServiceDiscovery, ServiceRegistry, ServiceInstance, ServiceType
from .communication import CommunicationHub, MessageRouter, Message, MessageType
from .resource_pool import DistributedResourcePool, ResourceManager, ResourceInstance, ResourceType
from .node_monitor import NodeMonitor, ClusterMonitor, NodeHealth, HealthStatus
from .test_distributor import TestDistributor, TestWorkload, TestScenario, DistributionStrategy

__all__ = [
    # Orchestrator
    "MCPTestOrchestrator",
    "TestExecution", 
    "TestTask",
    "TestNode",
    
    # Load Generation
    "DistributedLoadGenerator",
    "LoadProfile",
    "LoadPattern", 
    "LoadMetrics",
    
    # Service Discovery
    "ServiceDiscovery",
    "ServiceRegistry",
    "ServiceInstance",
    "ServiceType",
    
    # Communication
    "CommunicationHub",
    "MessageRouter",
    "Message",
    "MessageType",
    
    # Resource Management
    "DistributedResourcePool",
    "ResourceManager",
    "ResourceInstance",
    "ResourceType",
    
    # Monitoring
    "NodeMonitor",
    "ClusterMonitor", 
    "NodeHealth",
    "HealthStatus",
    
    # Test Distribution
    "TestDistributor",
    "TestWorkload",
    "TestScenario",
    "DistributionStrategy"
]