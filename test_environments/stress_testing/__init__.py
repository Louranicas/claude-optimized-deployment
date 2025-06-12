"""
Stress Testing Framework for Claude Optimized Deployment

Complete stress testing framework with intelligent ramping logic, safety controls,
and real-time monitoring capabilities.

Key Features:
- 7-phase progressive stress testing
- Intelligent adaptive load ramping
- Comprehensive safety controls with circuit breakers
- Real-time metrics collection and monitoring
- WebSocket-based control API
- Integration with Circle of Experts
"""

__version__ = "1.0.0"
__author__ = "Claude Optimized Deployment System"

# Core components
from .core.cycle_manager import (
    StressCycleManager,
    StressPhase,
    CycleState,
    PhaseConfig,
    CycleStatus
)

from .core.load_controller import (
    LoadController,
    LoadConfiguration,
    CPULoadGenerator,
    MemoryLoadGenerator,
    IOLoadGenerator,
    NetworkLoadGenerator
)

from .core.safety_manager import (
    SafetyManager,
    SafetyLevel,
    ThresholdType,
    SafetyThreshold,
    SafetyViolation,
    CircuitBreaker,
    CircuitBreakerState,
    SystemMonitor
)

from .core.metrics_collector import (
    MetricsCollector,
    MetricSeries,
    MetricPoint,
    SystemSnapshot,
    PerformanceProfiler
)

from .core.adaptive_ramping import (
    AdaptiveRampingEngine,
    RampingStrategy,
    SystemResponse,
    RampingProfile,
    SystemState,
    RampingDecision
)

# Control interface
from .interfaces.control_api import (
    StressTestingControlAPI,
    ControlCommand,
    ControlResponse,
    SystemStatus,
    WebSocketManager
)

# Package information
__all__ = [
    # Core framework
    'StressCycleManager',
    'LoadController', 
    'SafetyManager',
    'MetricsCollector',
    'AdaptiveRampingEngine',
    
    # Control interface
    'StressTestingControlAPI',
    
    # Enums and states
    'StressPhase',
    'CycleState',
    'SafetyLevel',
    'ThresholdType',
    'RampingStrategy',
    'SystemResponse',
    'ControlCommand',
    
    # Configuration classes
    'PhaseConfig',
    'LoadConfiguration',
    'SafetyThreshold',
    'RampingProfile',
    
    # Status and data classes
    'CycleStatus',
    'SystemStatus',
    'SafetyViolation',
    'SystemSnapshot',
    'RampingDecision',
    'MetricSeries',
    'MetricPoint',
    
    # Utility classes
    'PerformanceProfiler',
    'CircuitBreaker',
    'SystemMonitor',
    'WebSocketManager'
]


def get_version():
    """Get framework version"""
    return __version__


def get_default_config_path():
    """Get path to default configuration file"""
    import os
    return os.path.join(os.path.dirname(__file__), "config", "stress_cycles.yaml")


class StressTestingFramework:
    """
    Main framework class for easy initialization and management
    """
    
    def __init__(self, config_path=None):
        """
        Initialize the stress testing framework
        
        Args:
            config_path: Path to configuration file (uses default if None)
        """
        if config_path is None:
            config_path = get_default_config_path()
        
        # Initialize core components
        self.cycle_manager = StressCycleManager(config_path)
        self.control_api = StressTestingControlAPI(config_path)
        
    async def start(self, api_host="0.0.0.0", api_port=8000):
        """
        Start the complete stress testing framework
        
        Args:
            api_host: Host for control API
            api_port: Port for control API
        """
        # Start the control API which will manage everything
        await self.control_api.start_api(api_host, api_port)
    
    async def stop(self):
        """Stop the stress testing framework"""
        await self.control_api.stop_api()
        if self.cycle_manager.is_running():
            await self.cycle_manager.stop_cycle()
    
    def get_cycle_manager(self):
        """Get the cycle manager instance"""
        return self.cycle_manager
    
    def get_control_api(self):
        """Get the control API instance"""
        return self.control_api


# Convenience functions
async def run_stress_test(phases=None, config_path=None):
    """
    Run a complete stress test with specified phases
    
    Args:
        phases: List of phase names to run (all phases if None)
        config_path: Path to configuration file
        
    Returns:
        Dict with test results
    """
    framework = StressTestingFramework(config_path)
    
    try:
        # Convert phase names to enums if provided
        stress_phases = None
        if phases:
            stress_phases = [StressPhase[phase.upper()] for phase in phases]
        
        # Run the test
        success = await framework.cycle_manager.start_cycle(stress_phases)
        
        if success:
            # Wait for completion
            while framework.cycle_manager.is_running():
                await asyncio.sleep(1)
            
            # Get results
            history = framework.cycle_manager.get_cycle_history()
            return {
                "success": True,
                "results": history[-1] if history else None
            }
        else:
            return {
                "success": False,
                "error": "Failed to start stress test"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
    
    finally:
        await framework.stop()


async def quick_stress_test(target_load=50, duration=60):
    """
    Run a quick stress test with specified load and duration
    
    Args:
        target_load: Target load percentage (0-100)
        duration: Test duration in seconds
        
    Returns:
        Dict with test results
    """
    framework = StressTestingFramework()
    
    try:
        # Get load controller directly for simple test
        load_controller = framework.cycle_manager.load_controller
        await load_controller.initialize()
        
        # Apply load
        await load_controller.set_all_loads(
            cpu=target_load,
            memory=target_load * 0.8,
            io=target_load * 0.6,
            network=target_load * 0.4
        )
        
        # Wait for duration
        await asyncio.sleep(duration)
        
        # Stop loads
        await load_controller.stop_all_loads()
        
        return {
            "success": True,
            "target_load": target_load,
            "duration": duration,
            "loads_applied": load_controller.get_current_loads()
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
    
    finally:
        await framework.stop()


# Import asyncio for convenience functions
import asyncio