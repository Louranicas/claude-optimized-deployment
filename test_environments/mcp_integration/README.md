# MCP Server Integration for Distributed Testing

This package provides a comprehensive MCP (Model Context Protocol) server integration for distributed testing capabilities across multiple nodes and services. It enables coordinated testing at scale with intelligent workload distribution, resource management, and monitoring.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Components](#components)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Deployment](#deployment)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Overview

The MCP Distributed Testing System provides:

- **Distributed Test Coordination**: Central orchestration of tests across multiple nodes
- **Automatic Service Discovery**: Zero-configuration node discovery and registration
- **Intelligent Load Distribution**: Advanced algorithms for optimal workload distribution
- **Resource Management**: Shared resource allocation and monitoring across nodes
- **Health Monitoring**: Comprehensive node health and performance monitoring
- **Fault Tolerance**: Automatic failover and error recovery mechanisms
- **Multiple Test Types**: Support for load, stress, security, and performance testing

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Orchestrator  │    │ Service         │    │ Resource Pool   │
│                 │◄──►│ Discovery       │◄──►│ Manager         │
│   - Coordination│    │ - Auto Register │    │ - CPU/Memory    │
│   - Task Mgmt   │    │ - Health Check  │    │ - Allocation    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Communication   │    │ Test            │    │ Node            │
│ Hub             │◄──►│ Distributor     │◄──►│ Monitor         │
│ - Messaging     │    │ - Load Balance  │    │ - Health Checks │
│ - Reliability   │    │ - Strategies    │    │ - Alerting      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Load Generation Nodes                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Node 1    │  │   Node 2    │  │   Node N    │              │
│  │ - HTTP Load │  │ - Security  │  │ - Stress    │              │
│  │ - Metrics   │  │ - Testing   │  │ - Testing   │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Orchestrator (`orchestrator.py`)
Central coordination service that manages test executions across distributed nodes.

**Key Features:**
- Test execution planning and coordination
- Node registration and management
- Task assignment and monitoring
- Real-time status tracking
- RESTful API for external integration

### 2. Distributed Load Generator (`distributed_loader.py`)
MCP-enabled load generation nodes that can generate various load patterns.

**Load Patterns:**
- Constant load
- Ramp-up/ramp-down
- Spike testing
- Wave patterns
- Random load
- Burst patterns

### 3. Service Discovery (`service_discovery.py`)
Automatic service discovery and registration using multicast protocols.

**Features:**
- Zero-configuration discovery
- Health-based filtering
- Capability-based matching
- Automatic cleanup of stale services

### 4. Communication Hub (`communication.py`)
Reliable inter-node messaging system with multiple delivery guarantees.

**Delivery Modes:**
- Fire-and-forget
- At-least-once
- Exactly-once
- Reliable with retries

### 5. Resource Pool Manager (`resource_pool.py`)
Distributed resource allocation and monitoring across the cluster.

**Resources Managed:**
- CPU cores and utilization
- Memory allocation
- Disk space
- Network bandwidth
- Custom resources

### 6. Node Monitor (`node_monitor.py`)
Comprehensive health monitoring with alerting and metrics collection.

**Monitoring:**
- System metrics (CPU, memory, disk, network)
- Health checks with customizable thresholds
- Alert generation and management
- Cluster-wide health aggregation

### 7. Test Distributor (`test_distributor.py`)
Intelligent workload distribution with multiple allocation strategies.

**Distribution Strategies:**
- Round-robin
- Least-loaded
- Capability-based
- Locality-aware
- Weighted scoring
- Adaptive selection

## Installation

### Prerequisites

```bash
# Required Python packages
pip install aiohttp websockets psutil numpy

# Optional packages for enhanced features
pip install GPUtil  # For GPU monitoring
```

### Clone and Setup

```bash
git clone <repository-url>
cd test_environments/mcp_integration

# Install dependencies
pip install -r requirements.txt

# Run integration test to verify setup
python integration_test.py
```

## Quick Start

### 1. Start the Orchestrator

```python
from mcp_integration import MCPTestOrchestrator

async def start_orchestrator():
    orchestrator = MCPTestOrchestrator(host="localhost", port=8080)
    await orchestrator.start()

# Run with: python -c "import asyncio; asyncio.run(start_orchestrator())"
```

### 2. Start Load Generator Nodes

```python
from mcp_integration import DistributedLoadGenerator

async def start_load_generator():
    generator = DistributedLoadGenerator(
        node_id="load_gen_1",
        orchestrator_host="localhost",
        orchestrator_port=8081
    )
    await generator.start()

# Run multiple instances with different node_ids
```

### 3. Start Service Discovery

```python
from mcp_integration import ServiceDiscovery

async def start_discovery():
    discovery = ServiceDiscovery()
    await discovery.start()
    
    # Register a service
    from mcp_integration import ServiceInstance, ServiceType
    service = ServiceInstance(
        service_id="my_service",
        service_type=ServiceType.LOAD_GENERATOR,
        name="My Load Generator",
        host="localhost",
        port=8090,
        capabilities=["http_load", "stress_testing"]
    )
    await discovery.register_local_service(service)
```

### 4. Submit Test Execution

```python
import aiohttp
import json

async def submit_test():
    execution_config = {
        "name": "Sample Load Test",
        "tasks": [
            {
                "type": "load_test",
                "parameters": {
                    "targets": [
                        {
                            "url": "http://example.com/api",
                            "method": "GET"
                        }
                    ],
                    "duration": 300,
                    "base_rps": 100,
                    "peak_rps": 500,
                    "pattern": "ramp_up",
                    "concurrent_users": 50
                }
            }
        ]
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "http://localhost:8080/api/executions",
            json=execution_config
        ) as response:
            result = await response.json()
            execution_id = result["execution_id"]
            print(f"Test execution started: {execution_id}")
```

## Configuration

### Environment Variables

```bash
# Orchestrator Configuration
MCP_ORCHESTRATOR_HOST=localhost
MCP_ORCHESTRATOR_PORT=8080
MCP_ORCHESTRATOR_LOG_LEVEL=INFO

# Service Discovery Configuration
MCP_DISCOVERY_MULTICAST_GROUP=239.255.255.250
MCP_DISCOVERY_MULTICAST_PORT=1900
MCP_DISCOVERY_BROADCAST_INTERVAL=30

# Resource Management Configuration
MCP_RESOURCE_MONITOR_INTERVAL=30
MCP_RESOURCE_CLEANUP_INTERVAL=300

# Communication Configuration
MCP_COMM_HEARTBEAT_INTERVAL=30
MCP_COMM_MESSAGE_TIMEOUT=60

# Health Monitoring Configuration
MCP_HEALTH_CHECK_INTERVAL=30
MCP_HEALTH_ALERT_THRESHOLD=3
```

### Configuration Files

Create `mcp_config.yaml`:

```yaml
orchestrator:
  host: "localhost"
  port: 8080
  max_concurrent_executions: 10
  task_timeout: 3600

load_generation:
  default_timeout: 300
  max_concurrent_requests: 1000
  connection_pool_size: 100

service_discovery:
  multicast_group: "239.255.255.250"
  multicast_port: 1900
  service_timeout: 90
  health_check_enabled: true

resource_management:
  allocation_timeout: 60
  cleanup_interval: 300
  monitoring_interval: 30

health_monitoring:
  check_interval: 30
  alert_thresholds:
    cpu_warning: 80.0
    cpu_critical: 95.0
    memory_warning: 85.0
    memory_critical: 95.0
    disk_warning: 80.0
    disk_critical: 95.0
```

## Usage Examples

### Advanced Load Testing

```python
from mcp_integration import TestDistributor, TestWorkload, TestScenario, TestType

async def advanced_load_test():
    # Create distributor
    distributor = TestDistributor("advanced_distributor")
    
    # Register nodes with different capabilities
    from mcp_integration import NodeCapability
    
    web_node = NodeCapability(
        node_id="web_node_1",
        capabilities={"http_load", "api_testing"},
        capacity={"cpu": 16.0, "memory": 32.0, "network": 10000.0},
        current_load={"cpu": 2.0, "memory": 4.0, "network": 1000.0},
        location="us-west-1"
    )
    
    security_node = NodeCapability(
        node_id="security_node_1", 
        capabilities={"security_testing", "vulnerability_scanning"},
        capacity={"cpu": 8.0, "memory": 16.0, "network": 1000.0},
        current_load={"cpu": 1.0, "memory": 2.0, "network": 100.0},
        location="us-east-1"
    )
    
    distributor.register_node(web_node)
    distributor.register_node(security_node)
    
    # Create test scenarios
    scenarios = [
        TestScenario(
            scenario_id="api_load_test",
            name="API Load Test",
            description="Test API endpoints under load",
            test_type=TestType.LOAD_TEST,
            parameters={
                "targets": [
                    {"url": "http://api.example.com/users", "method": "GET"},
                    {"url": "http://api.example.com/orders", "method": "POST"}
                ],
                "duration": 1800,  # 30 minutes
                "base_rps": 100,
                "peak_rps": 1000,
                "pattern": "wave"
            },
            required_capabilities=["http_load", "api_testing"],
            estimated_duration=timedelta(minutes=30),
            resource_requirements={"cpu": 8.0, "memory": 16.0, "network": 5000.0}
        ),
        TestScenario(
            scenario_id="security_scan",
            name="Security Vulnerability Scan", 
            description="Comprehensive security testing",
            test_type=TestType.SECURITY_TEST,
            parameters={
                "target": "example.com",
                "scan_types": ["xss", "sql_injection", "csrf"],
                "depth": "deep"
            },
            required_capabilities=["security_testing"],
            estimated_duration=timedelta(hours=2),
            resource_requirements={"cpu": 4.0, "memory": 8.0, "network": 500.0}
        )
    ]
    
    # Create workload
    workload = TestWorkload(
        workload_id="comprehensive_test",
        name="Comprehensive Testing Suite",
        scenarios=scenarios,
        execution_mode=ExecutionMode.COORDINATED,
        timeout=timedelta(hours=3)
    )
    
    # Distribute and execute
    plan = await distributor.distribute_workload(workload, DistributionStrategy.LOCALITY_AWARE)
    success = await distributor.execute_distribution_plan(plan.plan_id)
    
    # Monitor progress
    while True:
        status = distributor.get_distribution_status(plan.plan_id)
        print(f"Progress: {status['progress_percent']:.1f}%")
        
        if status['progress_percent'] >= 100:
            break
            
        await asyncio.sleep(30)
    
    print("Test execution completed!")
```

### Resource-Aware Testing

```python
from mcp_integration import DistributedResourcePool, ResourceManager, ResourceAllocation, ResourceSpec, ResourceType

async def resource_aware_testing():
    # Create resource pool
    pool = DistributedResourcePool("production_pool", "coordinator_1")
    
    # Add resource managers
    for i in range(5):
        manager = ResourceManager(f"node_{i}")
        await pool.add_node(f"node_{i}", manager)
    
    # Request resources for high-intensity testing
    allocation = ResourceAllocation(
        allocation_id="high_intensity_test",
        requester_id="test_suite",
        resources=[
            ResourceSpec(ResourceType.CPU, 64.0, "cores"),
            ResourceSpec(ResourceType.MEMORY, 128 * 1024 * 1024 * 1024, "bytes"),  # 128GB
            ResourceSpec(ResourceType.NETWORK, 10000.0, "mbps")
        ],
        priority=1
    )
    
    # Allocate resources
    if await pool.allocate_resources_globally(allocation):
        print("Resources allocated successfully")
        
        # Run your tests here
        # ...
        
        # Deallocate when done
        await pool.deallocate_resources("high_intensity_test")
    else:
        print("Insufficient resources available")
```

### Custom Health Monitoring

```python
from mcp_integration import NodeMonitor, HealthCheck, HealthMetric, MetricType

async def custom_monitoring():
    monitor = NodeMonitor("custom_node")
    
    # Add custom health check
    async def check_database_connection():
        # Custom database connectivity check
        try:
            # Simulate database connection test
            await asyncio.sleep(0.1)
            return True
        except:
            return False
    
    db_health_check = HealthCheck(
        check_id="database_connectivity",
        name="Database Connection",
        description="Check database connectivity",
        check_function=check_database_connection,
        interval=timedelta(seconds=60),
        timeout=timedelta(seconds=10)
    )
    
    monitor.register_health_check(db_health_check)
    
    # Add custom metric
    async def collect_custom_metrics():
        while monitor.running:
            # Collect application-specific metrics
            metric = HealthMetric(
                name="custom_application_metric",
                value=42.0,  # Your custom value
                unit="requests/sec",
                metric_type=MetricType.GAUGE,
                timestamp=datetime.now(),
                threshold_warning=50.0,
                threshold_critical=100.0
            )
            
            monitor.current_metrics["custom_application_metric"] = metric
            await asyncio.sleep(30)
    
    # Start monitoring with custom metrics
    await asyncio.gather(
        monitor.start_monitoring(),
        collect_custom_metrics()
    )
```

## API Reference

### REST API Endpoints

#### Orchestrator API

```
POST /api/executions
- Submit new test execution
- Body: execution configuration JSON
- Returns: {"execution_id": "uuid"}

GET /api/executions/{execution_id}
- Get execution status
- Returns: execution details and progress

DELETE /api/executions/{execution_id}
- Cancel running execution
- Returns: {"status": "cancelled"}

GET /api/nodes
- List all registered nodes
- Returns: {"nodes": [...]}

GET /api/health
- Health check endpoint
- Returns: system status
```

#### Load Generator API

```
POST /load/start
- Start load generation
- Body: load profile configuration

POST /load/stop/{task_id}
- Stop running load test

GET /load/metrics/{task_id}
- Get load test metrics

GET /load/status
- Get generator status
```

### Python API

#### Core Classes

```python
# Orchestrator
class MCPTestOrchestrator:
    async def start()
    async def submit_test_execution(config: Dict) -> str
    async def get_execution_status(execution_id: str) -> Dict
    async def cancel_execution(execution_id: str) -> bool

# Load Generator
class DistributedLoadGenerator:
    async def start()
    async def run_load_test(task: LoadTask)
    def get_current_metrics() -> Dict

# Service Discovery
class ServiceDiscovery:
    async def start()
    async def register_local_service(service: ServiceInstance)
    async def query_services(service_type: str = None) -> List[ServiceInstance]

# Resource Pool
class DistributedResourcePool:
    async def add_node(node_id: str, manager: ResourceManager)
    async def allocate_resources_globally(request: ResourceAllocation) -> bool
    async def deallocate_resources(allocation_id: str) -> bool

# Test Distributor
class TestDistributor:
    def register_node(node: NodeCapability)
    async def distribute_workload(workload: TestWorkload, strategy: DistributionStrategy) -> DistributionPlan
    async def execute_distribution_plan(plan_id: str) -> bool
```

## Testing

### Run Integration Tests

```bash
# Run full integration test suite
python integration_test.py

# Run specific component tests
python -m pytest tests/test_orchestrator.py
python -m pytest tests/test_load_generator.py
python -m pytest tests/test_service_discovery.py
```

### Test Coverage

The integration test covers:
- ✅ Service discovery and registration
- ✅ Node health monitoring
- ✅ Inter-node communication
- ✅ Resource management and allocation
- ✅ Distributed load generation
- ✅ Test workload distribution
- ✅ End-to-end orchestration
- ✅ Fault tolerance and error handling

### Performance Testing

```bash
# Benchmark load generation performance
python benchmarks/load_generation_benchmark.py

# Test resource allocation performance
python benchmarks/resource_allocation_benchmark.py

# Measure communication latency
python benchmarks/communication_latency_test.py
```

## Deployment

### Docker Deployment

```dockerfile
# Dockerfile for orchestrator
FROM python:3.9-alpine

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY mcp_integration/ ./mcp_integration/
EXPOSE 8080 8081

CMD ["python", "-m", "mcp_integration.orchestrator"]
```

### Kubernetes Deployment

```yaml
# orchestrator-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-orchestrator
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mcp-orchestrator
  template:
    metadata:
      labels:
        app: mcp-orchestrator
    spec:
      containers:
      - name: orchestrator
        image: mcp-orchestrator:latest
        ports:
        - containerPort: 8080
        - containerPort: 8081
        env:
        - name: MCP_ORCHESTRATOR_HOST
          value: "0.0.0.0"
        - name: MCP_ORCHESTRATOR_PORT
          value: "8080"
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-orchestrator-service
spec:
  selector:
    app: mcp-orchestrator
  ports:
  - name: api
    port: 8080
    targetPort: 8080
  - name: websocket
    port: 8081
    targetPort: 8081
  type: LoadBalancer
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  orchestrator:
    build: .
    ports:
      - "8080:8080"
      - "8081:8081"
    environment:
      - MCP_ORCHESTRATOR_HOST=0.0.0.0
      - MCP_ORCHESTRATOR_PORT=8080
    networks:
      - mcp-network

  load-generator-1:
    build: .
    command: python -m mcp_integration.distributed_loader load_gen_1
    environment:
      - MCP_ORCHESTRATOR_HOST=orchestrator
      - MCP_ORCHESTRATOR_PORT=8081
    depends_on:
      - orchestrator
    networks:
      - mcp-network

  load-generator-2:
    build: .
    command: python -m mcp_integration.distributed_loader load_gen_2
    environment:
      - MCP_ORCHESTRATOR_HOST=orchestrator
      - MCP_ORCHESTRATOR_PORT=8081
    depends_on:
      - orchestrator
    networks:
      - mcp-network

  service-discovery:
    build: .
    command: python -m mcp_integration.service_discovery
    networks:
      - mcp-network

networks:
  mcp-network:
    driver: bridge
```

## Monitoring

### Metrics and Alerting

The system provides comprehensive metrics for monitoring:

```python
# Available metrics
{
  "orchestrator": {
    "active_executions": 5,
    "total_nodes": 10,
    "tasks_completed": 1250,
    "tasks_failed": 15,
    "average_execution_time": 300.5
  },
  "load_generation": {
    "total_requests": 50000,
    "requests_per_second": 167.3,
    "average_response_time": 245.6,
    "error_rate": 0.02
  },
  "resource_utilization": {
    "cpu_usage": 45.2,
    "memory_usage": 67.8,
    "network_usage": 23.4,
    "disk_usage": 12.1
  },
  "node_health": {
    "healthy_nodes": 8,
    "warning_nodes": 2,
    "failed_nodes": 0,
    "average_health_score": 94.5
  }
}
```

### Grafana Dashboard

Example Grafana queries:

```sql
-- Active test executions
sum(mcp_orchestrator_active_executions)

-- Request rate across all load generators
sum(rate(mcp_load_generator_total_requests[5m]))

-- Resource utilization by node
avg(mcp_node_cpu_usage) by (node_id)

-- Health score distribution
histogram_quantile(0.95, mcp_node_health_score)
```

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'mcp-orchestrator'
    static_configs:
      - targets: ['orchestrator:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'mcp-load-generators'
    static_configs:
      - targets: ['load-gen-1:8090', 'load-gen-2:8090']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

## Troubleshooting

### Common Issues

#### 1. Service Discovery Not Working

```bash
# Check multicast connectivity
ping 239.255.255.250

# Verify firewall settings
sudo ufw allow 1900/udp

# Check network interface
ip maddr show
```

#### 2. Load Generation Timeouts

```python
# Increase timeout settings
load_target = LoadTarget(
    url="http://slow-service.com",
    timeout=60.0,  # Increase from default 30s
    expected_response_time=10.0
)
```

#### 3. Resource Allocation Failures

```python
# Check available resources
pool_status = resource_pool.get_pool_status()
print(f"Available CPU: {pool_status['aggregate_utilization']['cpu']['available_capacity']}")

# Reduce resource requirements
allocation = ResourceAllocation(
    allocation_id="test_reduced",
    requester_id="test",
    resources=[
        ResourceSpec(ResourceType.CPU, 2.0, "cores"),  # Reduced from 8.0
        ResourceSpec(ResourceType.MEMORY, 4.0 * 1024**3, "bytes")  # Reduced from 16GB
    ]
)
```

#### 4. Communication Issues

```python
# Enable debug logging
logging.getLogger('mcp_integration.communication').setLevel(logging.DEBUG)

# Check connection status
hub = CommunicationHub("debug_hub")
connected_nodes = hub.get_connected_nodes()
print(f"Connected nodes: {connected_nodes}")

# Test connectivity
connection_info = hub.get_connection_info("target_node")
print(f"Connection info: {connection_info}")
```

### Debug Mode

Enable comprehensive debug logging:

```python
import logging

# Enable debug logging for all MCP components
logging.getLogger('mcp_integration').setLevel(logging.DEBUG)

# Enable specific component debugging
logging.getLogger('mcp_integration.orchestrator').setLevel(logging.DEBUG)
logging.getLogger('mcp_integration.load_generator').setLevel(logging.DEBUG)
logging.getLogger('mcp_integration.service_discovery').setLevel(logging.DEBUG)
```

### Health Checks

Verify system health:

```bash
# Check orchestrator health
curl http://localhost:8080/api/health

# Check node health
curl http://localhost:8090/health

# Check service discovery
curl http://localhost:1900/services
```

## Contributing

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd test_environments/mcp_integration

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run pre-commit hooks
pre-commit install
```

### Code Style

```bash
# Format code
black mcp_integration/
isort mcp_integration/

# Lint code
flake8 mcp_integration/
pylint mcp_integration/

# Type checking
mypy mcp_integration/
```

### Testing

```bash
# Run unit tests
pytest tests/

# Run integration tests
python integration_test.py

# Run with coverage
pytest --cov=mcp_integration tests/
```

### Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Support

For support and questions:

- 📧 Email: support@mcp-testing.org
- 💬 Discord: [MCP Testing Community](https://discord.gg/mcp-testing)
- 📖 Documentation: [https://docs.mcp-testing.org](https://docs.mcp-testing.org)
- 🐛 Issues: [GitHub Issues](https://github.com/org/mcp-testing/issues)

---

**Happy Testing with MCP! 🚀**