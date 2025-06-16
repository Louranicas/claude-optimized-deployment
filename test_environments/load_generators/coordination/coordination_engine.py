#!/usr/bin/env python3
"""
Load Generator Coordination Engine
=================================

Advanced coordination system for synchronizing multiple load generators
with intelligent load balancing, failure handling, and adaptive control.
"""

import asyncio
import time
import logging
import json
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, asdict
from enum import Enum
import numpy as np
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class CoordinationMode(Enum):
    """Coordination modes for load generators"""
    INDEPENDENT = "independent"      # Generators work independently
    SYNCHRONIZED = "synchronized"   # Generators synchronize their phases
    LOAD_BALANCED = "load_balanced" # Coordinate to balance system load
    ADAPTIVE = "adaptive"           # Adaptive coordination based on system state
    CIRCUIT_BREAKER = "circuit_breaker"  # Circuit breaker pattern
    PRIORITY_BASED = "priority_based"    # Priority-based coordination

@dataclass
class GeneratorStatus:
    """Status information for a load generator"""
    generator_id: str
    generator_type: str
    status: str  # running, stopped, error, paused
    current_load: float
    target_load: float
    performance_metrics: Dict[str, float]
    last_update: float
    error_count: int = 0
    circuit_breaker_state: str = "closed"  # closed, open, half_open

@dataclass
class CoordinationRule:
    """Rule for coordinating generators"""
    rule_id: str
    name: str
    condition: str  # Python expression
    action: str     # Action to take
    priority: int   # Higher priority rules execute first
    enabled: bool = True
    cooldown_seconds: float = 10.0
    last_triggered: float = 0.0

@dataclass
class SystemState:
    """Current system state for coordination decisions"""
    timestamp: float
    cpu_usage: float
    memory_usage: float
    disk_io: Dict[str, float]
    network_io: Dict[str, float]
    response_times: List[float]
    error_rates: Dict[str, float]
    active_connections: int
    system_load: float

class CoordinationEngine:
    """
    Advanced Load Generator Coordination Engine
    
    Manages coordination between multiple load generators with intelligent
    load balancing, failure handling, and adaptive control mechanisms.
    """
    
    def __init__(self, coordination_mode: CoordinationMode = CoordinationMode.ADAPTIVE):
        self.coordination_mode = coordination_mode
        self.running = False
        
        # Generator management
        self.generators: Dict[str, GeneratorStatus] = {}
        self.generator_callbacks: Dict[str, Callable] = {}
        
        # Coordination rules
        self.coordination_rules: List[CoordinationRule] = []
        self.rule_execution_history: deque = deque(maxlen=1000)
        
        # System monitoring
        self.system_state_history: deque = deque(maxlen=300)  # 5 minutes at 1 second intervals
        self.current_system_state: Optional[SystemState] = None
        
        # Performance tracking
        self.performance_metrics = {
            'coordination_decisions': 0,
            'load_adjustments': 0,
            'circuit_breaker_trips': 0,
            'rule_executions': 0,
            'emergency_stops': 0
        }
        
        # Configuration
        self.config = {
            'update_interval': 1.0,  # seconds
            'load_threshold_high': 0.85,
            'load_threshold_critical': 0.95,
            'error_rate_threshold': 0.10,
            'response_time_threshold': 5000,  # ms
            'circuit_breaker_threshold': 5,   # consecutive failures
            'circuit_breaker_timeout': 30,    # seconds
            'emergency_stop_threshold': 0.98,
            'load_balancing_window': 60      # seconds
        }
        
        # Circuit breaker states
        self.circuit_breakers: Dict[str, Dict[str, Any]] = {}
        
        # Load balancing
        self.load_distribution_history: deque = deque(maxlen=100)
        
        # Initialize default coordination rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default coordination rules"""
        default_rules = [
            CoordinationRule(
                rule_id="emergency_stop",
                name="Emergency Stop on Critical Load",
                condition="system_state.cpu_usage > 98 or system_state.memory_usage > 95",
                action="emergency_stop_all",
                priority=1000,
                cooldown_seconds=60.0
            ),
            CoordinationRule(
                rule_id="high_load_reduction",
                name="Reduce Load on High System Usage",
                condition="system_state.cpu_usage > 85 or system_state.memory_usage > 80",
                action="reduce_all_generators(0.8)",
                priority=900,
                cooldown_seconds=30.0
            ),
            CoordinationRule(
                rule_id="error_rate_protection",
                name="Reduce Load on High Error Rate",
                condition="max(system_state.error_rates.values()) > 0.10",
                action="reduce_all_generators(0.7)",
                priority=800,
                cooldown_seconds=20.0
            ),
            CoordinationRule(
                rule_id="response_time_protection",
                name="Reduce Load on High Response Times",
                condition="len(system_state.response_times) > 0 and max(system_state.response_times) > 5000",
                action="reduce_all_generators(0.9)",
                priority=700,
                cooldown_seconds=15.0
            ),
            CoordinationRule(
                rule_id="load_balancing",
                name="Balance Load Across Generators",
                condition="coordination_mode == 'load_balanced' and should_rebalance()",
                action="rebalance_generators()",
                priority=500,
                cooldown_seconds=60.0
            ),
            CoordinationRule(
                rule_id="circuit_breaker_check",
                name="Check Circuit Breaker States",
                condition="any_circuit_breaker_open()",
                action="handle_circuit_breakers()",
                priority=600,
                cooldown_seconds=5.0
            )
        ]
        
        self.coordination_rules.extend(default_rules)
        logger.info(f"Initialized {len(default_rules)} default coordination rules")
    
    def register_generator(self, generator_id: str, generator_type: str, 
                          callback: Callable = None) -> bool:
        """Register a load generator for coordination"""
        try:
            status = GeneratorStatus(
                generator_id=generator_id,
                generator_type=generator_type,
                status="stopped",
                current_load=0.0,
                target_load=0.0,
                performance_metrics={},
                last_update=time.time()
            )
            
            self.generators[generator_id] = status
            
            if callback:
                self.generator_callbacks[generator_id] = callback
            
            # Initialize circuit breaker
            self.circuit_breakers[generator_id] = {
                'state': 'closed',
                'failure_count': 0,
                'last_failure_time': 0,
                'next_attempt_time': 0
            }
            
            logger.info(f"Registered generator: {generator_id} ({generator_type})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register generator {generator_id}: {e}")
            return False
    
    def unregister_generator(self, generator_id: str) -> bool:
        """Unregister a load generator"""
        try:
            if generator_id in self.generators:
                del self.generators[generator_id]
            
            if generator_id in self.generator_callbacks:
                del self.generator_callbacks[generator_id]
            
            if generator_id in self.circuit_breakers:
                del self.circuit_breakers[generator_id]
            
            logger.info(f"Unregistered generator: {generator_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unregister generator {generator_id}: {e}")
            return False
    
    def update_generator_status(self, generator_id: str, status_update: Dict[str, Any]) -> bool:
        """Update generator status information"""
        if generator_id not in self.generators:
            logger.warning(f"Unknown generator: {generator_id}")
            return False
        
        try:
            status = self.generators[generator_id]
            
            # Update fields
            for field, value in status_update.items():
                if hasattr(status, field):
                    setattr(status, field, value)
            
            status.last_update = time.time()
            
            # Update circuit breaker state
            self._update_circuit_breaker(generator_id, status_update)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update generator status {generator_id}: {e}")
            return False
    
    def _update_circuit_breaker(self, generator_id: str, status_update: Dict[str, Any]):
        """Update circuit breaker state for a generator"""
        circuit_breaker = self.circuit_breakers[generator_id]
        current_time = time.time()
        
        # Check for errors
        if status_update.get('status') == 'error' or status_update.get('error_count', 0) > 0:
            circuit_breaker['failure_count'] += 1
            circuit_breaker['last_failure_time'] = current_time
            
            # Trip circuit breaker if threshold exceeded
            if (circuit_breaker['failure_count'] >= self.config['circuit_breaker_threshold'] and
                circuit_breaker['state'] == 'closed'):
                circuit_breaker['state'] = 'open'
                circuit_breaker['next_attempt_time'] = current_time + self.config['circuit_breaker_timeout']
                
                self.performance_metrics['circuit_breaker_trips'] += 1
                logger.warning(f"Circuit breaker opened for generator {generator_id}")
        
        # Handle circuit breaker state transitions
        elif circuit_breaker['state'] == 'open' and current_time >= circuit_breaker['next_attempt_time']:
            # Try half-open state
            circuit_breaker['state'] = 'half_open'
            logger.info(f"Circuit breaker half-open for generator {generator_id}")
        
        elif circuit_breaker['state'] == 'half_open' and status_update.get('status') == 'running':
            # Success in half-open state, close circuit breaker
            circuit_breaker['state'] = 'closed'
            circuit_breaker['failure_count'] = 0
            logger.info(f"Circuit breaker closed for generator {generator_id}")
        
        # Update generator status
        self.generators[generator_id].circuit_breaker_state = circuit_breaker['state']
    
    def update_system_state(self, system_metrics: Dict[str, Any]):
        """Update current system state for coordination decisions"""
        try:
            state = SystemState(
                timestamp=time.time(),
                cpu_usage=system_metrics.get('cpu_usage', 0.0),
                memory_usage=system_metrics.get('memory_usage', 0.0),
                disk_io=system_metrics.get('disk_io', {}),
                network_io=system_metrics.get('network_io', {}),
                response_times=system_metrics.get('response_times', []),
                error_rates=system_metrics.get('error_rates', {}),
                active_connections=system_metrics.get('active_connections', 0),
                system_load=system_metrics.get('system_load', 0.0)
            )
            
            self.current_system_state = state
            self.system_state_history.append(state)
            
        except Exception as e:
            logger.error(f"Failed to update system state: {e}")
    
    async def start_coordination(self):
        """Start the coordination engine"""
        if self.running:
            logger.warning("Coordination engine already running")
            return
        
        self.running = True
        logger.info(f"Starting coordination engine in {self.coordination_mode.value} mode")
        
        # Start coordination loop
        coordination_task = asyncio.create_task(self._coordination_loop())
        
        # Start monitoring tasks
        monitoring_task = asyncio.create_task(self._monitoring_loop())
        load_balancing_task = asyncio.create_task(self._load_balancing_loop())
        
        try:
            await asyncio.gather(coordination_task, monitoring_task, load_balancing_task)
        except asyncio.CancelledError:
            logger.info("Coordination engine tasks cancelled")
        except Exception as e:
            logger.error(f"Coordination engine error: {e}")
        finally:
            self.running = False
    
    async def stop_coordination(self):
        """Stop the coordination engine"""
        logger.info("Stopping coordination engine")
        self.running = False
    
    async def _coordination_loop(self):
        """Main coordination loop"""
        while self.running:
            try:
                await self._execute_coordination_cycle()
                await asyncio.sleep(self.config['update_interval'])
                
            except Exception as e:
                logger.error(f"Coordination loop error: {e}")
                await asyncio.sleep(5.0)
    
    async def _execute_coordination_cycle(self):
        """Execute one coordination cycle"""
        if not self.current_system_state:
            return
        
        # Evaluate coordination rules
        await self._evaluate_coordination_rules()
        
        # Perform coordination based on mode
        if self.coordination_mode == CoordinationMode.SYNCHRONIZED:
            await self._synchronized_coordination()
        elif self.coordination_mode == CoordinationMode.LOAD_BALANCED:
            await self._load_balanced_coordination()
        elif self.coordination_mode == CoordinationMode.ADAPTIVE:
            await self._adaptive_coordination()
        elif self.coordination_mode == CoordinationMode.CIRCUIT_BREAKER:
            await self._circuit_breaker_coordination()
        elif self.coordination_mode == CoordinationMode.PRIORITY_BASED:
            await self._priority_based_coordination()
        
        self.performance_metrics['coordination_decisions'] += 1
    
    async def _evaluate_coordination_rules(self):
        """Evaluate and execute coordination rules"""
        if not self.coordination_rules:
            return
        
        # Sort rules by priority (highest first)
        sorted_rules = sorted(
            [rule for rule in self.coordination_rules if rule.enabled],
            key=lambda r: r.priority,
            reverse=True
        )
        
        current_time = time.time()
        
        for rule in sorted_rules:
            # Check cooldown
            if current_time - rule.last_triggered < rule.cooldown_seconds:
                continue
            
            try:
                # Evaluate condition
                if self._evaluate_rule_condition(rule):
                    # Execute action
                    await self._execute_rule_action(rule)
                    
                    rule.last_triggered = current_time
                    self.performance_metrics['rule_executions'] += 1
                    
                    # Log rule execution
                    self.rule_execution_history.append({
                        'timestamp': current_time,
                        'rule_id': rule.rule_id,
                        'rule_name': rule.name,
                        'action': rule.action
                    })
                    
                    logger.info(f"Executed rule: {rule.name}")
                    
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id}: {e}")
    
    def _evaluate_rule_condition(self, rule: CoordinationRule) -> bool:
        """Evaluate a rule condition"""
        try:
            # Create evaluation context
            context = {
                'system_state': self.current_system_state,
                'generators': self.generators,
                'coordination_mode': self.coordination_mode.value,
                'performance_metrics': self.performance_metrics,
                'config': self.config,
                'time': time.time(),
                'should_rebalance': self._should_rebalance,
                'any_circuit_breaker_open': self._any_circuit_breaker_open,
                'max': max,
                'min': min,
                'len': len,
                'sum': sum,
                'any': any,
                'all': all
            }
            
            # Evaluate condition
            return eval(rule.condition, {"__builtins__": {}}, context)
            
        except Exception as e:
            logger.error(f"Error evaluating condition for rule {rule.rule_id}: {e}")
            return False
    
    async def _execute_rule_action(self, rule: CoordinationRule):
        """Execute a rule action"""
        action = rule.action
        
        try:
            if action == "emergency_stop_all":
                await self._emergency_stop_all()
            elif action.startswith("reduce_all_generators("):
                factor = float(action.split('(')[1].split(')')[0])
                await self._reduce_all_generators(factor)
            elif action == "rebalance_generators()":
                await self._rebalance_generators()
            elif action == "handle_circuit_breakers()":
                await self._handle_circuit_breakers()
            else:
                logger.warning(f"Unknown action: {action}")
                
        except Exception as e:
            logger.error(f"Error executing action {action}: {e}")
    
    async def _emergency_stop_all(self):
        """Emergency stop all generators"""
        logger.critical("EMERGENCY STOP: Stopping all generators due to critical system state")
        
        for generator_id in self.generators:
            await self._send_generator_command(generator_id, "emergency_stop")
        
        self.performance_metrics['emergency_stops'] += 1
    
    async def _reduce_all_generators(self, factor: float):
        """Reduce load on all generators by a factor"""
        logger.warning(f"Reducing all generator loads by factor {factor}")
        
        for generator_id, status in self.generators.items():
            if status.status == "running":
                new_target = status.target_load * factor
                await self._send_generator_command(generator_id, "set_target_load", {"target_load": new_target})
        
        self.performance_metrics['load_adjustments'] += 1
    
    async def _rebalance_generators(self):
        """Rebalance load across generators"""
        logger.info("Rebalancing generators")
        
        # Calculate optimal load distribution
        running_generators = [
            gen_id for gen_id, status in self.generators.items()
            if status.status == "running" and status.circuit_breaker_state == "closed"
        ]
        
        if not running_generators:
            return
        
        # Simple equal distribution for now
        total_target_load = sum(status.target_load for status in self.generators.values())
        target_load_per_generator = total_target_load / len(running_generators)
        
        for generator_id in running_generators:
            await self._send_generator_command(
                generator_id, 
                "set_target_load", 
                {"target_load": target_load_per_generator}
            )
    
    async def _handle_circuit_breakers(self):
        """Handle circuit breaker states"""
        current_time = time.time()
        
        for generator_id, circuit_breaker in self.circuit_breakers.items():
            if circuit_breaker['state'] == 'open':
                # Check if it's time to try half-open
                if current_time >= circuit_breaker['next_attempt_time']:
                    circuit_breaker['state'] = 'half_open'
                    await self._send_generator_command(generator_id, "resume")
                    logger.info(f"Attempting to resume generator {generator_id} (half-open)")
    
    def _should_rebalance(self) -> bool:
        """Check if load should be rebalanced"""
        if len(self.generators) < 2:
            return False
        
        # Check load distribution variance
        loads = [status.current_load for status in self.generators.values() if status.status == "running"]
        if len(loads) < 2:
            return False
        
        load_variance = np.var(loads)
        return load_variance > 0.1  # Threshold for rebalancing
    
    def _any_circuit_breaker_open(self) -> bool:
        """Check if any circuit breaker is open"""
        return any(cb['state'] == 'open' for cb in self.circuit_breakers.values())
    
    async def _synchronized_coordination(self):
        """Perform synchronized coordination"""
        # Ensure all generators are in sync
        target_phase = self._calculate_target_phase()
        
        for generator_id, status in self.generators.items():
            if status.status == "running":
                await self._send_generator_command(generator_id, "sync_phase", {"phase": target_phase})
    
    async def _load_balanced_coordination(self):
        """Perform load-balanced coordination"""
        # Continuously balance load based on system capacity
        system_capacity = self._calculate_system_capacity()
        
        # Distribute load based on generator capabilities and system capacity
        load_distribution = self._calculate_optimal_load_distribution(system_capacity)
        
        for generator_id, target_load in load_distribution.items():
            if generator_id in self.generators:
                await self._send_generator_command(generator_id, "set_target_load", {"target_load": target_load})
    
    async def _adaptive_coordination(self):
        """Perform adaptive coordination based on system state"""
        if not self.current_system_state:
            return
        
        # Adapt coordination strategy based on system metrics
        cpu_usage = self.current_system_state.cpu_usage
        memory_usage = self.current_system_state.memory_usage
        
        if cpu_usage > 90 or memory_usage > 85:
            # Switch to protective mode
            await self._reduce_all_generators(0.8)
        elif cpu_usage < 50 and memory_usage < 50:
            # System has capacity, can increase load
            await self._gradually_increase_load()
    
    async def _circuit_breaker_coordination(self):
        """Perform circuit breaker coordination"""
        # Manage generators based on circuit breaker states
        for generator_id, circuit_breaker in self.circuit_breakers.items():
            if circuit_breaker['state'] == 'open':
                # Redistribute load from failed generator
                await self._redistribute_load_from_failed_generator(generator_id)
    
    async def _priority_based_coordination(self):
        """Perform priority-based coordination"""
        # Allocate resources based on generator priorities
        sorted_generators = sorted(
            self.generators.items(),
            key=lambda x: x[1].priority if hasattr(x[1], 'priority') else 1,
            reverse=True
        )
        
        available_capacity = self._calculate_available_capacity()
        
        for generator_id, status in sorted_generators:
            if available_capacity <= 0:
                await self._send_generator_command(generator_id, "pause")
            else:
                allocated_capacity = min(status.target_load, available_capacity)
                await self._send_generator_command(
                    generator_id, 
                    "set_target_load", 
                    {"target_load": allocated_capacity}
                )
                available_capacity -= allocated_capacity
    
    async def _gradually_increase_load(self):
        """Gradually increase load when system has capacity"""
        increase_factor = 1.1
        
        for generator_id, status in self.generators.items():
            if status.status == "running" and status.circuit_breaker_state == "closed":
                new_target = min(1.0, status.target_load * increase_factor)
                if new_target > status.target_load:
                    await self._send_generator_command(
                        generator_id, 
                        "set_target_load", 
                        {"target_load": new_target}
                    )
    
    async def _redistribute_load_from_failed_generator(self, failed_generator_id: str):
        """Redistribute load from a failed generator to healthy ones"""
        failed_status = self.generators.get(failed_generator_id)
        if not failed_status:
            return
        
        failed_load = failed_status.target_load
        healthy_generators = [
            gen_id for gen_id, status in self.generators.items()
            if (gen_id != failed_generator_id and 
                status.status == "running" and 
                status.circuit_breaker_state == "closed")
        ]
        
        if not healthy_generators:
            return
        
        # Distribute failed load among healthy generators
        additional_load_per_generator = failed_load / len(healthy_generators)
        
        for generator_id in healthy_generators:
            status = self.generators[generator_id]
            new_target = min(1.0, status.target_load + additional_load_per_generator)
            await self._send_generator_command(
                generator_id, 
                "set_target_load", 
                {"target_load": new_target}
            )
    
    def _calculate_target_phase(self) -> float:
        """Calculate target phase for synchronized coordination"""
        # Simple phase calculation based on time
        return (time.time() % 300) / 300  # 5-minute cycle
    
    def _calculate_system_capacity(self) -> float:
        """Calculate current system capacity"""
        if not self.current_system_state:
            return 0.5
        
        cpu_capacity = max(0, (100 - self.current_system_state.cpu_usage) / 100)
        memory_capacity = max(0, (100 - self.current_system_state.memory_usage) / 100)
        
        return min(cpu_capacity, memory_capacity)
    
    def _calculate_optimal_load_distribution(self, system_capacity: float) -> Dict[str, float]:
        """Calculate optimal load distribution across generators"""
        distribution = {}
        
        active_generators = [
            gen_id for gen_id, status in self.generators.items()
            if status.status == "running" and status.circuit_breaker_state == "closed"
        ]
        
        if not active_generators:
            return distribution
        
        # Simple equal distribution based on system capacity
        load_per_generator = system_capacity / len(active_generators)
        
        for generator_id in active_generators:
            distribution[generator_id] = load_per_generator
        
        return distribution
    
    def _calculate_available_capacity(self) -> float:
        """Calculate available system capacity"""
        return self._calculate_system_capacity()
    
    async def _send_generator_command(self, generator_id: str, command: str, parameters: Dict[str, Any] = None):
        """Send command to a generator"""
        if generator_id in self.generator_callbacks:
            try:
                callback = self.generator_callbacks[generator_id]
                await callback(command, parameters or {})
            except Exception as e:
                logger.error(f"Error sending command to generator {generator_id}: {e}")
        else:
            logger.debug(f"No callback for generator {generator_id}, command: {command}")
    
    async def _monitoring_loop(self):
        """Monitor generator and system health"""
        while self.running:
            try:
                await self._check_generator_health()
                await self._update_performance_metrics()
                await asyncio.sleep(5.0)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(10.0)
    
    async def _load_balancing_loop(self):
        """Periodic load balancing"""
        while self.running:
            try:
                if self.coordination_mode in [CoordinationMode.LOAD_BALANCED, CoordinationMode.ADAPTIVE]:
                    await self._periodic_load_balancing()
                
                await asyncio.sleep(self.config['load_balancing_window'])
                
            except Exception as e:
                logger.error(f"Load balancing loop error: {e}")
                await asyncio.sleep(30.0)
    
    async def _check_generator_health(self):
        """Check health of all registered generators"""
        current_time = time.time()
        
        for generator_id, status in self.generators.items():
            # Check if generator is responsive
            time_since_update = current_time - status.last_update
            
            if time_since_update > 30.0 and status.status == "running":
                logger.warning(f"Generator {generator_id} hasn't updated in {time_since_update:.1f}s")
                status.status = "unresponsive"
                
                # Update circuit breaker
                circuit_breaker = self.circuit_breakers[generator_id]
                circuit_breaker['failure_count'] += 1
    
    async def _update_performance_metrics(self):
        """Update coordination performance metrics"""
        # Calculate coordination efficiency
        active_generators = sum(1 for status in self.generators.values() if status.status == "running")
        total_generators = len(self.generators)
        
        if total_generators > 0:
            efficiency = active_generators / total_generators
            self.performance_metrics['coordination_efficiency'] = efficiency
    
    async def _periodic_load_balancing(self):
        """Perform periodic load balancing"""
        # Record current load distribution
        current_distribution = {
            gen_id: status.current_load 
            for gen_id, status in self.generators.items()
            if status.status == "running"
        }
        
        self.load_distribution_history.append({
            'timestamp': time.time(),
            'distribution': current_distribution
        })
        
        # Check if rebalancing is needed
        if self._should_rebalance():
            await self._rebalance_generators()
    
    def add_coordination_rule(self, rule: CoordinationRule) -> bool:
        """Add a custom coordination rule"""
        try:
            # Check for duplicate rule IDs
            if any(r.rule_id == rule.rule_id for r in self.coordination_rules):
                logger.error(f"Rule with ID {rule.rule_id} already exists")
                return False
            
            self.coordination_rules.append(rule)
            logger.info(f"Added coordination rule: {rule.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add coordination rule: {e}")
            return False
    
    def remove_coordination_rule(self, rule_id: str) -> bool:
        """Remove a coordination rule"""
        try:
            self.coordination_rules = [
                rule for rule in self.coordination_rules 
                if rule.rule_id != rule_id
            ]
            logger.info(f"Removed coordination rule: {rule_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove coordination rule: {e}")
            return False
    
    def get_coordination_status(self) -> Dict[str, Any]:
        """Get current coordination status"""
        return {
            'mode': self.coordination_mode.value,
            'running': self.running,
            'generators': {
                gen_id: {
                    'type': status.generator_type,
                    'status': status.status,
                    'current_load': status.current_load,
                    'target_load': status.target_load,
                    'circuit_breaker_state': status.circuit_breaker_state,
                    'error_count': status.error_count
                }
                for gen_id, status in self.generators.items()
            },
            'system_state': asdict(self.current_system_state) if self.current_system_state else {},
            'performance_metrics': self.performance_metrics,
            'active_rules': len([r for r in self.coordination_rules if r.enabled]),
            'circuit_breakers': {
                gen_id: cb['state'] 
                for gen_id, cb in self.circuit_breakers.items()
            }
        }
    
    def get_coordination_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get coordination decision history"""
        return list(self.rule_execution_history)[-limit:]


# Example usage
async def example_usage():
    """Example usage of CoordinationEngine"""
    engine = CoordinationEngine(CoordinationMode.ADAPTIVE)
    
    # Register some mock generators
    engine.register_generator("cpu_gen", "cpu")
    engine.register_generator("memory_gen", "memory")
    engine.register_generator("network_gen", "network")
    
    # Add a custom rule
    custom_rule = CoordinationRule(
        rule_id="custom_load_limit",
        name="Custom Load Limit",
        condition="sum(gen.current_load for gen in generators.values()) > 2.0",
        action="reduce_all_generators(0.8)",
        priority=750
    )
    engine.add_coordination_rule(custom_rule)
    
    # Start coordination
    await engine.start_coordination()
    
    # Simulate for a short time
    await asyncio.sleep(10)
    
    # Stop coordination
    await engine.stop_coordination()
    
    # Get status
    status = engine.get_coordination_status()
    print(f"Coordination status: {status}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(example_usage())