# Stress Testing Framework

A comprehensive, production-ready stress testing framework with intelligent ramping logic, adaptive load management, and real-time safety controls.

## Overview

The Stress Testing Framework provides a complete solution for systematic stress testing with seven progressive phases, intelligent load orchestration, and comprehensive safety mechanisms. It's designed to push systems to their limits while maintaining safe operation through circuit breakers and real-time monitoring.

## Key Features

### 🏗️ **7-Phase Progressive Ramping System**
- **IDLE** (0-5%): Baseline measurement
- **LIGHT** (10-25%): Normal operation simulation  
- **MEDIUM** (25-50%): Busy period simulation
- **HEAVY** (50-75%): Peak usage simulation
- **EXTREME** (75-90%): Overload condition testing
- **CRITICAL** (90-95%): Near-failure testing
- **CHAOS** (95-100%): Failure condition testing

### 🎯 **Intelligent Load Orchestration**
- Multi-dimensional load generation (CPU, Memory, I/O, Network)
- Adaptive ramping based on system response
- Real-time load adjustment during execution
- Configurable load weights per phase

### 🛡️ **Comprehensive Safety Systems**
- Circuit breakers for automatic protection
- Real-time threshold monitoring
- Emergency shutdown mechanisms
- System health validation

### 📊 **Advanced Monitoring & Metrics**
- High-precision metrics collection (0.1s intervals)
- Real-time performance profiling
- Comprehensive system snapshots
- WebSocket-based real-time streaming

### 🔧 **Real-Time Control Interface**
- REST API for cycle control
- WebSocket for live monitoring
- Dynamic load adjustments
- Emergency controls

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Control API Layer                        │
│              (REST + WebSocket Interface)                   │
├─────────────────────────────────────────────────────────────┤
│                  Cycle Manager Core                         │
│           (7-Phase Orchestration Engine)                    │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ Load         │ Safety       │ Metrics      │ Adaptive       │
│ Controller   │ Manager      │ Collector    │ Ramping        │
│              │              │              │ Engine         │
├──────────────┴──────────────┴──────────────┴────────────────┤
│                    System Resource Layer                    │
│            (CPU, Memory, I/O, Network)                      │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd stress_testing

# Install dependencies
pip install -r requirements.txt

# Install optional dependencies for full functionality
pip install fastapi uvicorn websockets pydantic
```

### Basic Usage

```python
import asyncio
from stress_testing import StressTestingFramework, quick_stress_test

# Quick stress test
async def simple_test():
    result = await quick_stress_test(target_load=50, duration=60)
    print(f"Test result: {result}")

# Full framework usage
async def full_test():
    framework = StressTestingFramework()
    
    # Start specific phases
    success = await framework.cycle_manager.start_cycle(['light', 'medium', 'heavy'])
    
    if success:
        while framework.cycle_manager.is_running():
            status = framework.cycle_manager.get_status()
            print(f"Phase: {status.current_phase}, Load: {status.current_load_percent}%")
            await asyncio.sleep(5)

asyncio.run(simple_test())
```

### Control API Server

```bash
# Start the control API server
python -m stress_testing.interfaces.control_api --port 8000

# Or with custom configuration
python -m stress_testing.interfaces.control_api --config custom_config.yaml --port 8000
```

### API Endpoints

```bash
# Start a stress test cycle
curl -X POST http://localhost:8000/cycle/start \
  -H "Content-Type: application/json" \
  -d '{"phases": ["light", "medium", "heavy"]}'

# Get current status
curl http://localhost:8000/status

# Emergency stop
curl -X POST http://localhost:8000/emergency/stop

# Adjust load dynamically
curl -X POST http://localhost:8000/load/adjust \
  -H "Content-Type: application/json" \
  -d '{"phase": "medium", "target_load": 60.0}'

# Stream real-time metrics
curl http://localhost:8000/metrics/stream
```

## Configuration

### Phase Configuration (stress_cycles.yaml)

```yaml
phases:
  - phase: 1  # LIGHT
    name: "Light Load"
    min_load_percent: 10.0
    max_load_percent: 25.0
    duration_seconds: 120
    ramp_up_seconds: 30
    ramp_down_seconds: 20
    
    # Load type weights
    cpu_weight: 1.0
    memory_weight: 0.8
    io_weight: 0.6
    network_weight: 0.4
    
    # Safety thresholds
    safety_thresholds:
      cpu_usage: 40.0
      memory_usage: 50.0
      temperature: 65.0
    
    # Adaptive settings
    adaptive_enabled: true
    ramping_strategy: "linear"
```

### Load Generator Configuration

```yaml
load_generators:
  cpu:
    cores: "auto"
    precision_interval_ms: 100
    
  memory:
    limit_gb: "auto"  # 80% of available
    chunk_size_mb: 10
    
  io:
    operations_per_second: 1000
    operation_mix:
      read: 0.4
      write: 0.4
      seek: 0.2
    
  network:
    bandwidth_mbps: 100.0
    connection_pool_size: 10
```

## Advanced Features

### Adaptive Ramping

The framework includes an intelligent adaptive ramping engine that adjusts load based on system response:

```python
from stress_testing.core.adaptive_ramping import AdaptiveRampingEngine, RampingProfile, RampingStrategy

# Create custom ramping profile
profile = RampingProfile(
    strategy=RampingStrategy.ADAPTIVE,
    aggressiveness=0.7,
    stability_threshold=0.15,
    degradation_threshold=0.25,
    adaptation_rate=0.2
)

engine = AdaptiveRampingEngine(profile)
await engine.initialize()
```

### Safety Management

Comprehensive safety controls prevent system damage:

```python
from stress_testing.core.safety_manager import SafetyManager

safety_manager = SafetyManager()
await safety_manager.initialize()

# Set custom thresholds
await safety_manager.set_thresholds({
    "cpu_usage": 85.0,
    "memory_usage": 90.0,
    "temperature": 80.0
})

# Register safety callbacks
def on_safety_violation(violation):
    print(f"Safety violation: {violation.message}")

safety_manager.register_violation_callback(on_safety_violation)
```

### Metrics Collection

High-precision metrics collection with export capabilities:

```python
from stress_testing.core.metrics_collector import MetricsCollector

collector = MetricsCollector(collection_interval=0.1)
await collector.start_collection()

# Collect baseline
baseline = await collector.collect_baseline()

# Create performance profiler
profiler = collector.create_profiler("my_operation")
profiler.start()
# ... do work ...
profiler.end()

# Export metrics
collector.export_metrics_json("test_metrics.json")
```

## WebSocket Integration

Real-time monitoring via WebSocket:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    if (data.type === 'real_time_update') {
        console.log('Current load:', data.metrics.cpu_usage);
    } else if (data.type === 'phase_change') {
        console.log('Phase changed:', data.phase, data.event);
    } else if (data.type === 'safety_event') {
        console.log('Safety event:', data.event);
    }
};

// Send command
ws.send(JSON.stringify({
    type: 'command',
    command: {
        type: 'emergency_stop'
    }
}));
```

## Testing and Validation

Run the test suite to validate framework functionality:

```bash
# Run all tests
python test_framework.py

# Run specific examples
python example_usage.py --mode simple
python example_usage.py --mode advanced
python example_usage.py --mode demo
```

## Performance Characteristics

### Load Generation Precision
- CPU load control: ±2% accuracy
- Memory allocation: 10MB chunks with linear scaling
- I/O operations: Configurable IOPS with mixed read/write/seek
- Network traffic: Controlled bandwidth with connection pooling

### Monitoring Overhead
- Metrics collection: <1ms per sample at 0.1s intervals
- Safety monitoring: <0.5ms per check at 1s intervals
- WebSocket streaming: <0.1ms per message broadcast

### Safety Response Times
- Threshold violation detection: <1 second
- Circuit breaker activation: <100ms
- Emergency shutdown: <5 seconds

## Integration

### Circle of Experts Integration

```python
# Framework integrates with Circle of Experts for enhanced analysis
framework = StressTestingFramework()
framework.cycle_manager.register_phase_change_callback(experts_consultation)

async def experts_consultation(phase, event, status):
    if event == "completed":
        # Consult experts for analysis
        analysis = await circle_of_experts.analyze_stress_test_results(status)
        print(f"Expert analysis: {analysis}")
```

### Container Deployment

```dockerfile
FROM python:3.9-slim

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt

EXPOSE 8000

CMD ["python", "-m", "stress_testing.interfaces.control_api", "--host", "0.0.0.0", "--port", "8000"]
```

## Troubleshooting

### Common Issues

1. **High CPU Usage During Testing**
   - This is expected behavior during CPU stress phases
   - Monitor safety thresholds to prevent system overload
   - Use emergency stop if system becomes unresponsive

2. **Memory Allocation Errors**
   - Reduce memory_limit_gb in configuration
   - Ensure sufficient swap space is available
   - Monitor memory usage during extreme phases

3. **Permission Errors for I/O Testing**
   - Ensure write permissions to temporary directory
   - Run with appropriate user privileges
   - Check disk space availability

4. **Network Load Generation Issues**
   - Ensure firewall allows localhost connections
   - Check available ports for network testing
   - Verify network interface capabilities

### Debug Mode

Enable detailed logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Or in configuration
logging:
  level: DEBUG
  handlers:
    - file: stress_test_debug.log
    - console: true
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- Create an issue in the GitHub repository
- Check the troubleshooting section above
- Review the example usage scripts

## Roadmap

- [ ] GPU stress testing support
- [ ] Distributed stress testing across multiple nodes
- [ ] Machine learning-based load prediction
- [ ] Integration with monitoring systems (Prometheus, Grafana)
- [ ] Mobile/tablet control interface
- [ ] Cloud deployment templates (AWS, Azure, GCP)