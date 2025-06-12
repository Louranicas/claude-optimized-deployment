"""
Adaptive Ramping Engine for Stress Testing Framework

Implements intelligent load adjustment based on system response patterns,
performance degradation detection, and dynamic threshold adaptation.
"""

import asyncio
import time
import logging
import statistics
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import numpy as np


class RampingStrategy(Enum):
    """Different ramping strategies"""
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    LOGARITHMIC = "logarithmic"
    ADAPTIVE = "adaptive"
    CONSERVATIVE = "conservative"
    AGGRESSIVE = "aggressive"


class SystemResponse(Enum):
    """System response patterns"""
    STABLE = "stable"
    DEGRADING = "degrading"
    UNSTABLE = "unstable"
    RECOVERING = "recovering"
    OVERLOADED = "overloaded"


@dataclass
class RampingProfile:
    """Profile for adaptive ramping behavior"""
    strategy: RampingStrategy
    aggressiveness: float = 0.5  # 0.0 = very conservative, 1.0 = very aggressive
    stability_threshold: float = 0.1  # Acceptable variance in metrics
    degradation_threshold: float = 0.2  # Performance degradation detection
    recovery_factor: float = 0.8  # How much to reduce load on issues
    adaptation_rate: float = 0.1  # How quickly to adapt to conditions
    min_ramp_time: float = 5.0  # Minimum time between adjustments
    max_load_jump: float = 10.0  # Maximum load increase per step


@dataclass
class SystemState:
    """Current system state for ramping decisions"""
    timestamp: float
    cpu_usage: float
    memory_usage: float
    load_average: float
    response_time: float
    throughput: float
    error_rate: float
    stability_score: float
    performance_score: float


@dataclass
class RampingDecision:
    """Decision made by the adaptive ramping engine"""
    timestamp: float
    current_load: float
    target_load: float
    adjustment: float
    reason: str
    strategy_used: RampingStrategy
    confidence: float
    system_response: SystemResponse


class PerformanceAnalyzer:
    """Analyzes system performance patterns for ramping decisions"""
    
    def __init__(self, history_size: int = 100):
        self.history_size = history_size
        self.performance_history: List[SystemState] = []
        self.baseline_performance: Optional[SystemState] = None
        self.logger = logging.getLogger(f"{__name__}.PerformanceAnalyzer")
    
    def add_measurement(self, state: SystemState):
        """Add a new performance measurement"""
        self.performance_history.append(state)
        
        # Trim history
        if len(self.performance_history) > self.history_size:
            self.performance_history = self.performance_history[-self.history_size:]
        
        # Set baseline if not set
        if self.baseline_performance is None and len(self.performance_history) >= 5:
            self.baseline_performance = self._calculate_baseline()
    
    def _calculate_baseline(self) -> SystemState:
        """Calculate baseline performance from early measurements"""
        early_states = self.performance_history[:5]
        
        return SystemState(
            timestamp=early_states[0].timestamp,
            cpu_usage=statistics.mean([s.cpu_usage for s in early_states]),
            memory_usage=statistics.mean([s.memory_usage for s in early_states]),
            load_average=statistics.mean([s.load_average for s in early_states]),
            response_time=statistics.mean([s.response_time for s in early_states]),
            throughput=statistics.mean([s.throughput for s in early_states]),
            error_rate=statistics.mean([s.error_rate for s in early_states]),
            stability_score=1.0,  # Baseline is stable by definition
            performance_score=1.0
        )
    
    def analyze_system_response(self) -> SystemResponse:
        """Analyze current system response pattern"""
        if len(self.performance_history) < 10:
            return SystemResponse.STABLE
        
        recent_states = self.performance_history[-10:]
        
        # Check for overload conditions
        if self._is_overloaded(recent_states):
            return SystemResponse.OVERLOADED
        
        # Check for instability
        if self._is_unstable(recent_states):
            return SystemResponse.UNSTABLE
        
        # Check for degradation
        if self._is_degrading(recent_states):
            return SystemResponse.DEGRADING
        
        # Check for recovery
        if self._is_recovering(recent_states):
            return SystemResponse.RECOVERING
        
        return SystemResponse.STABLE
    
    def _is_overloaded(self, states: List[SystemState]) -> bool:
        """Check if system is overloaded"""
        recent_cpu = statistics.mean([s.cpu_usage for s in states])
        recent_memory = statistics.mean([s.memory_usage for s in states])
        recent_errors = statistics.mean([s.error_rate for s in states])
        
        return (
            recent_cpu > 90.0 or
            recent_memory > 95.0 or
            recent_errors > 5.0
        )
    
    def _is_unstable(self, states: List[SystemState]) -> bool:
        """Check if system performance is unstable"""
        if len(states) < 5:
            return False
        
        # Calculate coefficient of variation for key metrics
        cpu_values = [s.cpu_usage for s in states]
        response_times = [s.response_time for s in states]
        
        cpu_cv = statistics.stdev(cpu_values) / statistics.mean(cpu_values) if statistics.mean(cpu_values) > 0 else 0
        response_cv = statistics.stdev(response_times) / statistics.mean(response_times) if statistics.mean(response_times) > 0 else 0
        
        return cpu_cv > 0.3 or response_cv > 0.5
    
    def _is_degrading(self, states: List[SystemState]) -> bool:
        """Check if performance is degrading"""
        if not self.baseline_performance or len(states) < 5:
            return False
        
        recent_performance = statistics.mean([s.performance_score for s in states])
        baseline_performance = self.baseline_performance.performance_score
        
        degradation = (baseline_performance - recent_performance) / baseline_performance
        return degradation > 0.2
    
    def _is_recovering(self, states: List[SystemState]) -> bool:
        """Check if system is recovering from stress"""
        if len(states) < 10:
            return False
        
        older_half = states[:5]
        newer_half = states[5:]
        
        older_performance = statistics.mean([s.performance_score for s in older_half])
        newer_performance = statistics.mean([s.performance_score for s in newer_half])
        
        improvement = (newer_performance - older_performance) / older_performance if older_performance > 0 else 0
        return improvement > 0.1
    
    def calculate_stability_score(self) -> float:
        """Calculate system stability score (0.0 to 1.0)"""
        if len(self.performance_history) < 5:
            return 1.0
        
        recent_states = self.performance_history[-10:]
        
        # Calculate variance in key metrics
        cpu_values = [s.cpu_usage for s in recent_states]
        memory_values = [s.memory_usage for s in recent_states]
        response_times = [s.response_time for s in recent_states]
        
        # Normalize variances
        cpu_stability = max(0, 1.0 - (statistics.stdev(cpu_values) / 100.0))
        memory_stability = max(0, 1.0 - (statistics.stdev(memory_values) / 100.0))
        response_stability = max(0, 1.0 - (statistics.stdev(response_times) / 1000.0))
        
        return (cpu_stability + memory_stability + response_stability) / 3.0
    
    def calculate_performance_score(self) -> float:
        """Calculate performance score relative to baseline (0.0 to 1.0+)"""
        if not self.baseline_performance or not self.performance_history:
            return 1.0
        
        current_state = self.performance_history[-1]
        baseline = self.baseline_performance
        
        # Compare key performance metrics
        throughput_ratio = current_state.throughput / baseline.throughput if baseline.throughput > 0 else 1.0
        response_ratio = baseline.response_time / current_state.response_time if current_state.response_time > 0 else 1.0
        error_penalty = max(0, 1.0 - (current_state.error_rate / 100.0))
        
        return (throughput_ratio + response_ratio + error_penalty) / 3.0


class AdaptiveRampingEngine:
    """
    Main adaptive ramping engine that makes intelligent load adjustment decisions
    """
    
    def __init__(self, profile: Optional[RampingProfile] = None):
        self.profile = profile or RampingProfile(strategy=RampingStrategy.ADAPTIVE)
        self.logger = logging.getLogger(__name__)
        
        # Analysis components
        self.performance_analyzer = PerformanceAnalyzer()
        
        # Decision tracking
        self.decision_history: List[RampingDecision] = []
        self.last_adjustment_time = 0.0
        
        # State tracking
        self.current_load = 0.0
        self.target_load = 0.0
        self.initialized = False
        
        # Learning and adaptation
        self.strategy_performance: Dict[RampingStrategy, List[float]] = {
            strategy: [] for strategy in RampingStrategy
        }
        self.adaptation_learning_rate = 0.1
    
    async def initialize(self):
        """Initialize the adaptive ramping engine"""
        if self.initialized:
            return
        
        self.logger.info("Initializing adaptive ramping engine")
        self.initialized = True
        self.last_adjustment_time = time.time()
    
    async def calculate_target_load(self, phase_config, progress: float) -> float:
        """
        Calculate target load based on phase configuration and current system state
        
        Args:
            phase_config: Current phase configuration
            progress: Progress through the phase (0.0 to 1.0)
            
        Returns:
            Target load percentage
        """
        if not self.initialized:
            await self.initialize()
        
        # Get current system state
        system_state = await self._collect_system_state()
        self.performance_analyzer.add_measurement(system_state)
        
        # Analyze system response
        system_response = self.performance_analyzer.analyze_system_response()
        
        # Calculate base target load
        base_target = self._calculate_base_target_load(phase_config, progress)
        
        # Apply adaptive adjustments
        adjusted_target = await self._apply_adaptive_adjustments(
            base_target, system_response, system_state
        )
        
        # Record decision
        decision = RampingDecision(
            timestamp=time.time(),
            current_load=self.current_load,
            target_load=adjusted_target,
            adjustment=adjusted_target - base_target,
            reason=f"Adaptive adjustment based on {system_response.value} system response",
            strategy_used=self.profile.strategy,
            confidence=self._calculate_confidence(system_state),
            system_response=system_response
        )
        
        self.decision_history.append(decision)
        self.current_load = adjusted_target
        
        return adjusted_target
    
    async def adjust_steady_state_load(self, phase_config, current_target: float) -> float:
        """
        Adjust load during steady state based on system performance
        
        Args:
            phase_config: Current phase configuration
            current_target: Current target load
            
        Returns:
            Adjusted target load
        """
        # Check if enough time has passed since last adjustment
        if time.time() - self.last_adjustment_time < self.profile.min_ramp_time:
            return current_target
        
        # Get current system state
        system_state = await self._collect_system_state()
        self.performance_analyzer.add_measurement(system_state)
        
        # Analyze system response
        system_response = self.performance_analyzer.analyze_system_response()
        
        # Calculate adjustment
        adjustment = self._calculate_steady_state_adjustment(
            current_target, system_response, system_state
        )
        
        adjusted_target = max(
            phase_config.min_load_percent,
            min(phase_config.max_load_percent, current_target + adjustment)
        )
        
        if abs(adjustment) > 0.1:  # Only record significant adjustments
            decision = RampingDecision(
                timestamp=time.time(),
                current_load=current_target,
                target_load=adjusted_target,
                adjustment=adjustment,
                reason=f"Steady state adjustment for {system_response.value} condition",
                strategy_used=self.profile.strategy,
                confidence=self._calculate_confidence(system_state),
                system_response=system_response
            )
            
            self.decision_history.append(decision)
            self.last_adjustment_time = time.time()
        
        return adjusted_target
    
    def _calculate_base_target_load(self, phase_config, progress: float) -> float:
        """Calculate base target load using selected strategy"""
        min_load = phase_config.min_load_percent
        max_load = phase_config.max_load_percent
        load_range = max_load - min_load
        
        if self.profile.strategy == RampingStrategy.LINEAR:
            return min_load + (load_range * progress)
        
        elif self.profile.strategy == RampingStrategy.EXPONENTIAL:
            # Exponential curve: slow start, rapid acceleration
            exp_progress = (np.exp(progress * 3) - 1) / (np.exp(3) - 1)
            return min_load + (load_range * exp_progress)
        
        elif self.profile.strategy == RampingStrategy.LOGARITHMIC:
            # Logarithmic curve: rapid start, slow acceleration
            log_progress = np.log(1 + progress * 9) / np.log(10)
            return min_load + (load_range * log_progress)
        
        elif self.profile.strategy == RampingStrategy.CONSERVATIVE:
            # Conservative: slower than linear
            conservative_progress = progress ** 2
            return min_load + (load_range * conservative_progress)
        
        elif self.profile.strategy == RampingStrategy.AGGRESSIVE:
            # Aggressive: faster than linear
            aggressive_progress = np.sqrt(progress)
            return min_load + (load_range * aggressive_progress)
        
        else:  # ADAPTIVE
            # Choose strategy based on system performance
            return self._adaptive_strategy_selection(phase_config, progress)
    
    def _adaptive_strategy_selection(self, phase_config, progress: float) -> float:
        """Select best strategy based on historical performance"""
        # If we don't have enough history, use linear
        if len(self.strategy_performance[RampingStrategy.LINEAR]) < 3:
            return self._calculate_base_target_load_with_strategy(
                phase_config, progress, RampingStrategy.LINEAR
            )
        
        # Find the best performing strategy
        best_strategy = RampingStrategy.LINEAR
        best_score = 0.0
        
        for strategy, scores in self.strategy_performance.items():
            if scores:
                avg_score = statistics.mean(scores[-10:])  # Last 10 scores
                if avg_score > best_score:
                    best_score = avg_score
                    best_strategy = strategy
        
        return self._calculate_base_target_load_with_strategy(
            phase_config, progress, best_strategy
        )
    
    def _calculate_base_target_load_with_strategy(self, phase_config, progress: float, 
                                                strategy: RampingStrategy) -> float:
        """Calculate base target load with specific strategy"""
        original_strategy = self.profile.strategy
        self.profile.strategy = strategy
        result = self._calculate_base_target_load(phase_config, progress)
        self.profile.strategy = original_strategy
        return result
    
    async def _apply_adaptive_adjustments(self, base_target: float, 
                                        system_response: SystemResponse,
                                        system_state: SystemState) -> float:
        """Apply adaptive adjustments based on system response"""
        adjustment = 0.0
        
        if system_response == SystemResponse.OVERLOADED:
            # Reduce load significantly
            adjustment = -base_target * 0.3 * self.profile.recovery_factor
        
        elif system_response == SystemResponse.UNSTABLE:
            # Reduce load moderately
            adjustment = -base_target * 0.2 * self.profile.recovery_factor
        
        elif system_response == SystemResponse.DEGRADING:
            # Reduce load slightly or hold steady
            adjustment = -base_target * 0.1 * self.profile.recovery_factor
        
        elif system_response == SystemResponse.RECOVERING:
            # Allow slight increase if system is recovering
            adjustment = base_target * 0.05 * self.profile.aggressiveness
        
        elif system_response == SystemResponse.STABLE:
            # System is stable, can be more aggressive
            stability_bonus = system_state.stability_score * self.profile.aggressiveness * 0.1
            adjustment = base_target * stability_bonus
        
        # Limit adjustment based on profile
        max_adjustment = self.profile.max_load_jump
        adjustment = max(-max_adjustment, min(max_adjustment, adjustment))
        
        return max(0.0, min(100.0, base_target + adjustment))
    
    def _calculate_steady_state_adjustment(self, current_target: float,
                                         system_response: SystemResponse,
                                         system_state: SystemState) -> float:
        """Calculate adjustment for steady state phase"""
        base_adjustment = 0.0
        
        if system_response == SystemResponse.OVERLOADED:
            base_adjustment = -current_target * 0.2
        
        elif system_response == SystemResponse.UNSTABLE:
            base_adjustment = -current_target * 0.1
        
        elif system_response == SystemResponse.DEGRADING:
            base_adjustment = -current_target * 0.05
        
        elif system_response == SystemResponse.STABLE:
            # Can try to increase load if very stable
            if system_state.stability_score > 0.9 and system_state.performance_score > 0.9:
                base_adjustment = current_target * 0.02 * self.profile.aggressiveness
        
        elif system_response == SystemResponse.RECOVERING:
            # Hold steady during recovery
            base_adjustment = 0.0
        
        # Apply adaptation rate
        adjustment = base_adjustment * self.profile.adaptation_rate
        
        # Limit adjustment
        max_adjustment = self.profile.max_load_jump * 0.5  # Smaller adjustments in steady state
        return max(-max_adjustment, min(max_adjustment, adjustment))
    
    async def _collect_system_state(self) -> SystemState:
        """Collect current system state for analysis"""
        # This would typically interface with the metrics collector
        # For now, create a simulated state
        current_time = time.time()
        
        # Simulate system metrics (in a real implementation, these would come from MetricsCollector)
        cpu_usage = min(100.0, self.current_load * 0.8 + np.random.normal(0, 5))
        memory_usage = min(100.0, self.current_load * 0.6 + np.random.normal(0, 3))
        load_average = self.current_load / 10.0 + np.random.normal(0, 0.5)
        
        # Simulate performance metrics
        response_time = 100 + (self.current_load * 5) + np.random.normal(0, 10)
        throughput = max(0, 1000 - (self.current_load * 5) + np.random.normal(0, 50))
        error_rate = max(0, (self.current_load - 80) * 0.1) if self.current_load > 80 else 0
        
        # Calculate scores
        stability_score = self.performance_analyzer.calculate_stability_score()
        performance_score = self.performance_analyzer.calculate_performance_score()
        
        return SystemState(
            timestamp=current_time,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            load_average=load_average,
            response_time=response_time,
            throughput=throughput,
            error_rate=error_rate,
            stability_score=stability_score,
            performance_score=performance_score
        )
    
    def _calculate_confidence(self, system_state: SystemState) -> float:
        """Calculate confidence in the ramping decision"""
        # Base confidence on system stability and available data
        stability_confidence = system_state.stability_score
        
        # Data availability confidence
        data_confidence = min(1.0, len(self.performance_analyzer.performance_history) / 20.0)
        
        # Strategy performance confidence
        strategy_confidence = 0.5
        if self.profile.strategy in self.strategy_performance:
            scores = self.strategy_performance[self.profile.strategy]
            if scores:
                strategy_confidence = min(1.0, statistics.mean(scores[-5:]))
        
        return (stability_confidence + data_confidence + strategy_confidence) / 3.0
    
    # Learning and adaptation methods
    def record_strategy_performance(self, strategy: RampingStrategy, score: float):
        """Record performance score for a strategy"""
        if strategy not in self.strategy_performance:
            self.strategy_performance[strategy] = []
        
        self.strategy_performance[strategy].append(score)
        
        # Trim history
        if len(self.strategy_performance[strategy]) > 50:
            self.strategy_performance[strategy] = self.strategy_performance[strategy][-50:]
    
    def adapt_profile(self, performance_feedback: Dict[str, float]):
        """Adapt ramping profile based on performance feedback"""
        # Adjust aggressiveness based on stability
        if 'stability' in performance_feedback:
            stability = performance_feedback['stability']
            if stability < 0.7:
                # System is unstable, be more conservative
                self.profile.aggressiveness *= (1.0 - self.adaptation_learning_rate)
            elif stability > 0.9:
                # System is very stable, can be more aggressive
                self.profile.aggressiveness *= (1.0 + self.adaptation_learning_rate)
        
        # Adjust degradation threshold based on performance
        if 'performance_ratio' in performance_feedback:
            perf_ratio = performance_feedback['performance_ratio']
            if perf_ratio < 0.8:
                # Performance degraded, lower threshold for detection
                self.profile.degradation_threshold *= (1.0 - self.adaptation_learning_rate)
        
        # Ensure parameters stay within bounds
        self.profile.aggressiveness = max(0.1, min(1.0, self.profile.aggressiveness))
        self.profile.degradation_threshold = max(0.05, min(0.5, self.profile.degradation_threshold))
    
    # Information and status methods
    def get_decision_history(self) -> List[RampingDecision]:
        """Get history of ramping decisions"""
        return self.decision_history.copy()
    
    def get_strategy_performance(self) -> Dict[RampingStrategy, float]:
        """Get average performance for each strategy"""
        return {
            strategy: statistics.mean(scores) if scores else 0.0
            for strategy, scores in self.strategy_performance.items()
        }
    
    def get_current_profile(self) -> RampingProfile:
        """Get current ramping profile"""
        return self.profile
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get comprehensive analysis summary"""
        return {
            'current_load': self.current_load,
            'target_load': self.target_load,
            'ramping_profile': {
                'strategy': self.profile.strategy.value,
                'aggressiveness': self.profile.aggressiveness,
                'stability_threshold': self.profile.stability_threshold,
                'degradation_threshold': self.profile.degradation_threshold
            },
            'recent_decisions': [
                {
                    'timestamp': d.timestamp,
                    'adjustment': d.adjustment,
                    'reason': d.reason,
                    'confidence': d.confidence,
                    'system_response': d.system_response.value
                }
                for d in self.decision_history[-10:]
            ],
            'strategy_performance': self.get_strategy_performance(),
            'performance_history_size': len(self.performance_analyzer.performance_history)
        }