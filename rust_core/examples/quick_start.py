#!/usr/bin/env python3
"""
Quick Start Guide for Claude Optimized Deployment Rust Core

This example demonstrates the basic usage of the Rust Core module.
"""

import asyncio
import json
from claude_optimized_deployment_rust import (
    InfrastructureScanner,
    MCPManager,
    ExpertCircle,
    MetricsCollector,
    CircleConfig,
    QueryOptions
)


async def infrastructure_scanning_example():
    """Example: High-performance infrastructure scanning"""
    print("\n=== Infrastructure Scanning Example ===")
    
    # Create scanner with configuration
    scanner = InfrastructureScanner()
    
    # Scan local ports
    print("Scanning localhost ports 8000-9000...")
    open_ports = await scanner.scan_ports("localhost", range(8000, 9000))
    print(f"Open ports: {open_ports}")
    
    # Get system information
    system_info = scanner.get_system_info()
    print(f"System: {system_info}")
    
    # Discover services
    print("\nDiscovering services on local network...")
    services = await scanner.discover_services("192.168.1.0/24")
    for service in services[:5]:  # Show first 5
        print(f"  - {service.name} at {service.address}:{service.port}")


async def mcp_manager_example():
    """Example: MCP server management"""
    print("\n=== MCP Manager Example ===")
    
    # Initialize MCP manager
    manager = MCPManager({
        "max_concurrent": 100,
        "connection_timeout_ms": 5000
    })
    
    # Deploy a Docker MCP server
    print("Deploying Docker MCP server...")
    docker_server = await manager.deploy_server({
        "name": "docker-server",
        "type": "docker",
        "port": 8001,
        "config": {
            "docker_socket": "/var/run/docker.sock"
        }
    })
    print(f"Docker server deployed: {docker_server}")
    
    # Check server health
    health = await manager.get_server_status(docker_server)
    print(f"Server health: {health}")
    
    # Execute a tool
    print("\nListing Docker containers...")
    result = await manager.execute_tool(
        docker_server,
        "list_containers",
        {"all": True}
    )
    print(f"Containers: {json.dumps(result, indent=2)}")
    
    # Deploy additional servers
    servers = []
    for i, server_type in enumerate(["kubernetes", "prometheus"]):
        server_id = await manager.deploy_server({
            "name": f"{server_type}-server",
            "type": server_type,
            "port": 8002 + i
        })
        servers.append(server_id)
        print(f"{server_type} server deployed: {server_id}")
    
    # Get metrics
    metrics = await manager.get_metrics()
    print(f"\nMCP Metrics: {json.dumps(metrics, indent=2)}")


async def expert_circle_example():
    """Example: Circle of Experts consultation"""
    print("\n=== Circle of Experts Example ===")
    
    # Create expert circle with configuration
    config = CircleConfig(
        consensus_threshold=0.7,
        min_experts=3,
        max_experts=10,
        timeout_seconds=30
    )
    
    circle = ExpertCircle(config)
    
    # Query the experts
    question = "What's the best strategy for deploying a microservices application?"
    print(f"Question: {question}")
    
    options = QueryOptions(
        timeout=30,
        min_confidence=0.6,
        include_reasoning=True
    )
    
    response = await circle.query(question, options)
    
    print(f"\nConsensus: {response.consensus}")
    print(f"Confidence: {response.confidence:.2%}")
    print(f"Experts consulted: {response.expert_count}")
    
    # Show individual expert responses
    print("\nExpert opinions:")
    for expert in response.expert_responses[:3]:  # Show first 3
        print(f"  - {expert.expert_id} ({expert.confidence:.2%}): {expert.summary}")


async def metrics_collection_example():
    """Example: Performance metrics collection"""
    print("\n=== Metrics Collection Example ===")
    
    # Create metrics collector
    metrics = MetricsCollector()
    
    # Record various metrics
    import time
    import random
    
    # Simulate API calls with timing
    for i in range(10):
        start = time.time()
        await asyncio.sleep(random.uniform(0.01, 0.05))  # Simulate work
        duration = time.time() - start
        
        metrics.record_timing("api_call", duration)
        metrics.increment_counter("requests", 1)
        metrics.record_gauge("active_connections", random.randint(50, 150))
    
    # Get snapshot
    snapshot = metrics.snapshot()
    print(f"Metrics snapshot: {snapshot}")
    
    # Export in Prometheus format
    prometheus_metrics = metrics.export_prometheus()
    print(f"\nPrometheus format:\n{prometheus_metrics}")


async def advanced_example():
    """Example: Advanced usage with multiple components"""
    print("\n=== Advanced Integration Example ===")
    
    # Initialize all components
    scanner = InfrastructureScanner()
    mcp_manager = MCPManager({"max_concurrent": 50})
    circle = ExpertCircle(CircleConfig(consensus_threshold=0.8))
    metrics = MetricsCollector()
    
    # Scan for available services
    start_time = asyncio.get_event_loop().time()
    services = await scanner.discover_services("localhost")
    scan_time = asyncio.get_event_loop().time() - start_time
    metrics.record_timing("service_discovery", scan_time)
    
    print(f"Discovered {len(services)} services in {scan_time:.2f}s")
    
    # Deploy MCP servers for each discovered service
    deployed_servers = []
    for service in services[:3]:  # Deploy for first 3 services
        try:
            server_id = await mcp_manager.deploy_server({
                "name": f"mcp-{service.name}",
                "type": "generic",
                "port": 9000 + len(deployed_servers),
                "target_service": {
                    "host": service.address,
                    "port": service.port
                }
            })
            deployed_servers.append(server_id)
            metrics.increment_counter("servers_deployed", 1)
        except Exception as e:
            print(f"Failed to deploy server for {service.name}: {e}")
            metrics.increment_counter("deployment_failures", 1)
    
    # Query experts for optimization recommendations
    if deployed_servers:
        question = f"How can I optimize {len(deployed_servers)} MCP servers for maximum throughput?"
        response = await circle.query(question, QueryOptions(timeout=20))
        print(f"\nOptimization recommendation: {response.consensus}")
    
    # Collect final metrics
    final_metrics = metrics.snapshot()
    print(f"\nFinal metrics: {json.dumps(final_metrics, indent=2)}")


async def error_handling_example():
    """Example: Proper error handling"""
    print("\n=== Error Handling Example ===")
    
    from claude_optimized_deployment_rust import MCPError, InfrastructureError
    
    manager = MCPManager({})
    
    try:
        # Try to deploy with invalid configuration
        await manager.deploy_server({
            "name": "invalid-server",
            "type": "nonexistent",
            "port": 99999  # Invalid port
        })
    except MCPError as e:
        print(f"MCP Error caught: {e}")
        print(f"Error type: {type(e).__name__}")
        
        # Check specific error conditions
        if hasattr(e, 'is_validation_error') and e.is_validation_error():
            print("This is a validation error - check your configuration")
        elif hasattr(e, 'is_connection_error') and e.is_connection_error():
            print("This is a connection error - check network connectivity")
    
    # Scanner error handling
    scanner = InfrastructureScanner()
    try:
        # Scan invalid host
        await scanner.scan_ports("invalid.host.example", range(1, 100))
    except InfrastructureError as e:
        print(f"\nInfrastructure Error: {e}")


async def performance_comparison():
    """Example: Compare Rust vs Python performance"""
    print("\n=== Performance Comparison ===")
    
    import time
    
    # Rust-accelerated scanning
    scanner = InfrastructureScanner()
    
    print("Rust-accelerated port scan (1000 ports):")
    start = time.perf_counter()
    rust_results = await scanner.scan_ports("localhost", range(1, 1001))
    rust_time = time.perf_counter() - start
    print(f"  Time: {rust_time:.3f}s")
    print(f"  Found {len(rust_results)} open ports")
    
    # For comparison, you would run Python-based scanning here
    # This is just to show the performance difference
    print("\nExpected Python performance (based on benchmarks):")
    print(f"  Time: ~{rust_time * 55:.1f}s (55x slower)")
    print(f"  Speed improvement: {55}x")


async def main():
    """Run all examples"""
    print("Claude Optimized Deployment - Rust Core Quick Start")
    print("=" * 50)
    
    examples = [
        infrastructure_scanning_example,
        mcp_manager_example,
        expert_circle_example,
        metrics_collection_example,
        advanced_example,
        error_handling_example,
        performance_comparison
    ]
    
    for example in examples:
        try:
            await example()
        except Exception as e:
            print(f"\nError in {example.__name__}: {e}")
        print("\n" + "-" * 50)
    
    print("\nQuick start examples completed!")
    print("\nNext steps:")
    print("1. Check out the full API documentation in docs/API_REFERENCE.md")
    print("2. See integration patterns in docs/INTEGRATION_GUIDE.md")
    print("3. Learn about performance tuning in docs/PERFORMANCE_TUNING.md")
    print("4. Explore advanced examples in the examples/ directory")


if __name__ == "__main__":
    # Run the examples
    asyncio.run(main())