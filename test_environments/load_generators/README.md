# Advanced Load Generators with Realistic Workload Patterns

This comprehensive load generation framework provides sophisticated load testing capabilities with realistic workload patterns, intelligent coordination, and multi-dimensional load simulation.

## Features

### 🚀 **Multi-Modal Load Generation**
- **CPU Load Generator**: Prime calculation, matrix multiplication, sorting algorithms, crypto hashing
- **Memory Load Generator**: Various allocation patterns, fragmentation simulation, GC pressure testing
- **I/O Load Generator**: Sequential/random access, database simulation, log file patterns
- **Network Load Generator**: HTTP/HTTPS requests, WebSocket connections, UDP traffic, geographic distribution
- **Application Load Generator**: Circle of Experts queries, MCP operations, database queries, API calls

### 📊 **Intelligent Pattern Engine**
- **Pattern Types**: Steady state, ramp up/down, spikes, bursts, cyclic, realistic profiles
- **Real-World Simulation**: Web traffic, API services, batch processing, gaming patterns
- **Mathematical Models**: Exponential, logarithmic, wave, triangular, sawtooth patterns
- **Pattern Combination**: Additive, multiplicative, maximum, average combination methods

### 🎯 **Workload Profiles**
- **Pre-defined Profiles**: Development, staging, production, peak traffic, stress test, endurance
- **Custom Profiles**: Clone, modify, and create custom workload profiles
- **Profile Validation**: Comprehensive validation with warnings and error detection
- **Scenario Recommendations**: Get recommended profiles for specific testing scenarios

### 🎭 **Custom Scenario Builder**
- **Interactive Builder**: Step-by-step scenario construction with validation
- **Visual Timeline**: Generate visual previews of scenario execution
- **Execution Planning**: Detailed execution plans with resource requirements
- **Condition-Based Steps**: Execute steps based on system conditions
- **Action Integration**: Trigger specific actions during scenario execution

### 🤝 **Advanced Coordination**
- **Coordination Modes**: Independent, synchronized, load-balanced, adaptive, circuit breaker, priority-based
- **Intelligent Rules**: Custom coordination rules with conditions and actions
- **Circuit Breakers**: Automatic failure detection and recovery
- **Load Balancing**: Dynamic load distribution across generators
- **Adaptive Control**: System-aware load adjustment

### 📈 **Comprehensive Monitoring**
- **Real-time Metrics**: Performance, throughput, error rates, resource usage
- **Historical Data**: Trend analysis and performance baselines
- **Alert System**: Configurable thresholds and emergency stop conditions
- **Export Capabilities**: JSON, CSV, and custom format exports

## Quick Start

### Basic Usage

```python
import asyncio
from load_generators import LoadOrchestrator, LoadConfiguration, LoadGeneratorType

async def basic_load_test():
    # Initialize orchestrator
    orchestrator = LoadOrchestrator()
    
    # Add CPU load configuration
    cpu_config = LoadConfiguration(
        generator_type=LoadGeneratorType.CPU,
        pattern_name="steady_state",
        intensity=0.5,
        duration=120,
        parameters={'threads': 4, 'algorithm': 'prime_calculation'}
    )
    orchestrator.add_load_configuration(cpu_config)
    
    # Execute load test
    await orchestrator.start_load_generation("basic_test")
    
    # Export results
    orchestrator.export_metrics("basic_test_results.json")

# Run the test
asyncio.run(basic_load_test())
```

### Using Workload Profiles

```python
from load_generators.profiles import WorkloadProfileManager

# Initialize profile manager
profile_manager = WorkloadProfileManager()

# List available profiles
profiles = profile_manager.list_profiles()
print(f"Available profiles: {profiles}")

# Get production profile
prod_profile = profile_manager.get_profile("production")

# Clone and customize
profile_manager.clone_profile("production", "custom_production")
profile_manager.modify_profile("custom_production", {
    "duration_minutes": 180,
    "generator_modifications": {
        "cpu": {"intensity_multiplier": 0.8},
        "network": {"custom_parameters": {"request_rate_per_second": 200}}
    }
})
```

### Custom Scenario Building

```python
from load_generators import CustomScenarioBuilder

# Initialize builder
builder = CustomScenarioBuilder()

# Start new scenario
builder.start_new_scenario("e_commerce_test", "E-commerce load testing scenario")

# Add baseline step
builder.add_step_from_profile("baseline", "baseline", 10, 1.0)

# Add ramp-up step
builder.add_ramp_up_step(
    "traffic_ramp_up", 30,
    target_intensities={"cpu": 0.8, "memory": 0.7, "network": 1.2},
    start_intensities={"cpu": 0.2, "memory": 0.3, "network": 0.3}
)

# Add spike test
builder.add_spike_step(
    "peak_traffic", 60,
    base_intensities={"cpu": 0.8, "network": 1.5},
    spike_intensities={"cpu": 1.2, "network": 2.0},
    spike_count=5, spike_duration_minutes=3
)

# Validate and generate execution plan
validation = builder.validate_scenario()
execution_plan = builder.generate_execution_plan()

# Save scenario
builder.save_scenario("e_commerce_scenario.json")
```

### Advanced Coordination

```python
from load_generators.coordination import CoordinationEngine, CoordinationMode, CoordinationRule

# Initialize coordination engine
engine = CoordinationEngine(CoordinationMode.ADAPTIVE)

# Register generators
engine.register_generator("cpu_gen", "cpu")
engine.register_generator("memory_gen", "memory")
engine.register_generator("network_gen", "network")

# Add custom coordination rule
custom_rule = CoordinationRule(
    rule_id="high_cpu_protection",
    name="Reduce Load on High CPU",
    condition="system_state.cpu_usage > 80",
    action="reduce_all_generators(0.7)",
    priority=800
)
engine.add_coordination_rule(custom_rule)

# Start coordination
await engine.start_coordination()
```

## Generator Configurations

### CPU Load Generator

```python
from load_generators.generators import CPULoadGenerator, CPULoadConfiguration

config = CPULoadConfiguration(
    threads=8,                    # Number of CPU threads
    algorithm="matrix_multiplication",  # Algorithm type
    intensity=0.7,               # Load intensity (0.0-1.0)
    duration=300,                # Duration in seconds
    work_cycle=0.1,              # Work cycle duration
    rest_cycle=0.05,             # Rest cycle duration
    adaptive=True                # Enable adaptive control
)

generator = CPULoadGenerator(config)
```

**Available Algorithms:**
- `prime_calculation`: Prime number computation
- `matrix_multiplication`: Matrix operations
- `fibonacci`: Recursive Fibonacci calculation
- `pi_calculation`: Monte Carlo π calculation
- `crypto_hash`: Cryptographic hashing
- `sort_algorithms`: Various sorting algorithms
- `compression`: Data compression/decompression
- `floating_point`: Floating-point operations

### Memory Load Generator

```python
from load_generators.generators import MemoryLoadGenerator, MemoryLoadConfiguration

config = MemoryLoadConfiguration(
    max_memory_mb=2048,          # Maximum memory allocation
    allocation_size_mb=50,       # Size of each allocation
    allocation_pattern="mixed",   # Allocation pattern
    fragmentation_level=0.3,     # Fragmentation level (0.0-1.0)
    gc_pressure=True,            # Enable GC pressure
    leak_simulation=False,       # Simulate memory leaks
    adaptive=True                # Adaptive memory management
)

generator = MemoryLoadGenerator(config)
```

**Allocation Patterns:**
- `steady`: Predictable, steady allocation
- `burst`: Sudden memory allocation bursts
- `fragmented`: Fragmented allocation pattern
- `leak_simulation`: Memory leak simulation
- `mixed`: Combination of patterns

### Network Load Generator

```python
from load_generators.generators import NetworkLoadGenerator, NetworkLoadConfiguration

config = NetworkLoadConfiguration(
    target_urls=["https://api.example.com"],
    concurrent_connections=100,   # Concurrent connections
    request_rate_per_second=200, # Requests per second
    payload_size_kb=5,           # Request payload size
    websocket_enabled=True,      # Enable WebSocket testing
    udp_enabled=True,            # Enable UDP traffic
    geographic_distribution=True  # Simulate geographic distribution
)

generator = NetworkLoadGenerator(config)
```

### Application Load Generator

```python
from load_generators.generators import ApplicationLoadGenerator, ApplicationLoadConfiguration

config = ApplicationLoadConfiguration(
    workload_types=["circle_of_experts", "mcp_operations", "database_queries", "api_calls"],
    concurrent_users=20,         # Concurrent user sessions
    expert_query_complexity="medium",  # Query complexity
    business_logic_complexity="realistic",
    cache_usage=True,            # Enable cache simulation
    authentication_required=True # Require authentication
)

generator = ApplicationLoadGenerator(config)
```

## Pattern Types

### Basic Patterns
- **steady_state**: Constant load with optional variance
- **ramp_up**: Gradual load increase
- **ramp_down**: Gradual load decrease
- **spike**: Short high-intensity peaks
- **burst**: Periodic high-intensity intervals
- **cyclic**: Repeating cycles

### Advanced Patterns
- **wave**: Sine/cosine wave patterns
- **triangular**: Triangular wave patterns
- **sawtooth**: Sawtooth wave patterns
- **exponential**: Exponential growth/decay
- **logarithmic**: Logarithmic curves
- **random**: Random variations with smoothing

### Realistic Patterns
- **web_traffic**: Web application traffic (business hours pattern)
- **api_service**: API service usage (consistent with spikes)
- **batch_processing**: Batch job workloads (startup spike, gradual decrease)
- **gaming**: Gaming platform traffic (evening peaks, match-based spikes)

## Workload Profiles

### Development Environment
- Light load suitable for development testing
- Minimal resource usage
- Short duration (30 minutes)
- Conservative thresholds

### Staging Environment
- Moderate load for staging validation
- Realistic but controlled load
- Medium duration (60 minutes)
- Production-like patterns with safety margins

### Production Environment
- Production-like load patterns
- Realistic user behavior simulation
- Extended duration (120 minutes)
- Full feature utilization

### Peak Traffic
- High-traffic scenarios (Black Friday, product launches)
- Spike and burst patterns
- High intensity multipliers
- Circuit breaker protection

### Stress Test
- Find system breaking points
- Exponential load growth
- Memory leak simulation
- Resource exhaustion testing

### Endurance Test
- Long-running stability testing
- 8-hour duration
- Memory leak detection
- Performance degradation monitoring

## Coordination Modes

### Independent
Generators operate independently without coordination.

### Synchronized
Generators synchronize their execution phases for coordinated load patterns.

### Load Balanced
Dynamically balance load across generators based on system capacity.

### Adaptive
Automatically adapt coordination strategy based on system metrics and performance.

### Circuit Breaker
Implement circuit breaker patterns for failure handling and recovery.

### Priority Based
Allocate resources based on generator priorities and importance.

## Configuration Examples

### Complete Orchestrated Test

```python
import asyncio
from load_generators import *

async def comprehensive_load_test():
    # Initialize orchestrator with coordination
    orchestrator = LoadOrchestrator()
    coordination_engine = CoordinationEngine(CoordinationMode.ADAPTIVE)
    
    # Configure multiple generators
    configs = [
        LoadConfiguration(
            generator_type=LoadGeneratorType.CPU,
            pattern_name="realistic",
            intensity=0.8,
            duration=600,
            parameters={
                'threads': 8,
                'algorithm': 'mixed',
                'adaptive': True
            }
        ),
        LoadConfiguration(
            generator_type=LoadGeneratorType.MEMORY,
            pattern_name="burst",
            intensity=0.7,
            duration=600,
            parameters={
                'max_memory_mb': 2048,
                'allocation_pattern': 'mixed',
                'gc_pressure': True
            }
        ),
        LoadConfiguration(
            generator_type=LoadGeneratorType.NETWORK,
            pattern_name="realistic",
            intensity=0.9,
            duration=600,
            parameters={
                'concurrent_connections': 100,
                'request_rate_per_second': 300,
                'geographic_distribution': True
            }
        ),
        LoadConfiguration(
            generator_type=LoadGeneratorType.APPLICATION,
            pattern_name="realistic",
            intensity=0.8,
            duration=600,
            parameters={
                'concurrent_users': 50,
                'workload_types': ['circle_of_experts', 'mcp_operations', 'database_queries'],
                'expert_query_complexity': 'complex'
            }
        )
    ]
    
    # Add configurations
    for config in configs:
        orchestrator.add_load_configuration(config)
    
    # Set up coordination
    await coordination_engine.start_coordination()
    
    # Execute test
    await orchestrator.start_load_generation("comprehensive_test")
    
    # Export results
    orchestrator.export_metrics("comprehensive_test_results.json")
    
    # Cleanup
    await coordination_engine.stop_coordination()

asyncio.run(comprehensive_load_test())
```

## Monitoring and Metrics

### System Metrics
- CPU usage percentage
- Memory usage percentage
- Disk I/O operations and bandwidth
- Network I/O operations and bandwidth
- System load averages
- Active connections

### Generator Metrics
- Operations per second
- Response times and latencies
- Error rates and success rates
- Throughput measurements
- Resource utilization
- Cache hit rates (application generator)

### Coordination Metrics
- Coordination decisions made
- Load adjustments performed
- Circuit breaker trips
- Rule executions
- Emergency stops triggered
- Coordination efficiency

## Best Practices

### 1. Start Small
Begin with baseline profiles and gradually increase intensity.

### 2. Monitor System Health
Always monitor system metrics and set appropriate thresholds.

### 3. Use Realistic Patterns
Prefer realistic patterns over artificial constant loads.

### 4. Enable Coordination
Use coordination for multi-generator tests to prevent system overload.

### 5. Validate Scenarios
Always validate custom scenarios before execution.

### 6. Set Safety Limits
Configure emergency stop conditions and circuit breakers.

### 7. Export Results
Always export test results for analysis and reporting.

### 8. Gradual Ramp-Up
Use ramp-up patterns to warm up systems before peak load.

### 9. Clean Shutdown
Implement proper cleanup and graceful shutdown procedures.

### 10. Performance Baselines
Establish baselines before making system changes.

## Troubleshooting

### Common Issues

**High System Load**
- Reduce intensity multipliers
- Enable adaptive coordination
- Set lower performance thresholds

**Memory Issues**
- Reduce memory allocation limits
- Enable garbage collection pressure relief
- Use memory monitoring

**Network Timeouts**
- Increase connection and read timeouts
- Reduce concurrent connections
- Check target server capacity

**Generator Failures**
- Enable circuit breakers
- Check system resources
- Review error logs

**Coordination Issues**
- Verify rule conditions
- Check coordination mode compatibility
- Monitor rule execution history

### Debug Mode

Enable debug logging for detailed information:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Performance Tuning

1. **CPU Generators**: Adjust thread count and work/rest cycles
2. **Memory Generators**: Tune allocation sizes and patterns
3. **Network Generators**: Optimize connection pooling and payload sizes
4. **Application Generators**: Balance user session duration and complexity

## API Reference

See individual module documentation for detailed API reference:

- `load_orchestrator.py`: Main orchestration engine
- `patterns/pattern_engine.py`: Pattern generation
- `profiles/workload_profiles.py`: Profile management
- `custom_scenario_builder.py`: Scenario building
- `coordination/coordination_engine.py`: Coordination and synchronization
- `generators/`: Individual generator implementations

## Examples

Complete examples are available in the `demo_load_generation.py` file, which demonstrates all framework capabilities in a comprehensive test suite.

## License

This load generation framework is part of the Claude Optimized Deployment project and follows the project's licensing terms.

## Contributing

Contributions are welcome! Please follow the project's contribution guidelines and ensure all new generators and patterns include comprehensive tests and documentation.