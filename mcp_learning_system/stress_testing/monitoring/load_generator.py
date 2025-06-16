"""
Load generator for stress testing.

Generates controlled load patterns for testing system behavior under stress.
"""

import asyncio
import time
from typing import Dict, Any, Optional, Callable, AsyncGenerator
from dataclasses import dataclass
import numpy as np
import logging

logger = logging.getLogger(__name__)


@dataclass
class LoadPattern:
    """Configuration for a load pattern."""
    name: str
    base_rate: float          # Base operations per second
    peak_rate: float          # Peak operations per second
    pattern_type: str         # 'constant', 'linear', 'sine', 'step', 'burst'
    duration: float           # Pattern duration in seconds
    parameters: Dict[str, Any] = None  # Pattern-specific parameters
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


class LoadGenerator:
    """Generates controlled load for stress testing."""
    
    def __init__(self, rate: float = 100, pattern: Optional[LoadPattern] = None):
        """Initialize load generator.
        
        Args:
            rate: Default operations per second
            pattern: Load pattern configuration
        """
        self.rate = rate
        self.pattern = pattern
        self.running = False
        self.start_time = 0
        self._operations_count = 0
        
        # Pre-defined patterns
        self.predefined_patterns = {
            'constant': self._constant_pattern,
            'linear': self._linear_pattern,
            'sine': self._sine_pattern,
            'step': self._step_pattern,
            'burst': self._burst_pattern,
            'realistic': self._realistic_pattern
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
    
    async def start(self):
        """Start load generation."""
        self.running = True
        self.start_time = time.time()
        self._operations_count = 0
        logger.info(f"Load generator started at {self.rate} ops/sec")
    
    async def stop(self):
        """Stop load generation."""
        self.running = False
        duration = time.time() - self.start_time
        avg_rate = self._operations_count / duration if duration > 0 else 0
        logger.info(f"Load generator stopped. Actual rate: {avg_rate:.1f} ops/sec")
    
    async def generate_load(self, duration: float) -> AsyncGenerator[Dict[str, Any], None]:
        """Generate load for specified duration.
        
        Args:
            duration: Duration in seconds
            
        Yields:
            Load interaction dictionaries
        """
        start_time = time.time()
        
        while time.time() - start_time < duration and self.running:
            # Calculate current rate based on pattern
            current_rate = await self._get_current_rate()
            
            # Generate interaction
            interaction = await self.generate_interaction()
            yield interaction
            
            self._operations_count += 1
            
            # Control rate
            if current_rate > 0:
                await asyncio.sleep(1.0 / current_rate)
    
    async def generate_interaction(self) -> Dict[str, Any]:
        """Generate a single load interaction."""
        self._operations_count += 1
        
        # Generate realistic interaction data
        interaction_types = ['learning', 'pattern_match', 'knowledge_share', 'data_query']
        interaction_type = np.random.choice(interaction_types)
        
        base_interaction = {
            'id': f"load_{self._operations_count}_{time.time()}",
            'type': interaction_type,
            'timestamp': time.time(),
            'source': 'load_generator'
        }
        
        # Add type-specific data
        if interaction_type == 'learning':
            base_interaction.update({
                'input_data': np.random.rand(100).tolist(),
                'expected_output': np.random.rand(10).tolist(),
                'context': {
                    'domain': np.random.choice(['nlp', 'vision', 'reasoning']),
                    'difficulty': np.random.choice(['easy', 'medium', 'hard'])
                }
            })
        
        elif interaction_type == 'pattern_match':
            base_interaction.update({
                'pattern': {
                    'features': np.random.rand(50).tolist(),
                    'pattern_type': np.random.choice(['template', 'sequence', 'structure'])
                },
                'threshold': np.random.uniform(0.7, 0.95)
            })
        
        elif interaction_type == 'knowledge_share':
            base_interaction.update({
                'source_instance': np.random.choice(['development', 'devops', 'quality', 'bash_god']),
                'target_instance': np.random.choice(['development', 'devops', 'quality', 'bash_god']),
                'knowledge': {
                    'patterns': np.random.rand(20).tolist(),
                    'confidence': np.random.uniform(0.8, 1.0)
                }
            })
        
        elif interaction_type == 'data_query':
            base_interaction.update({
                'query': {
                    'type': np.random.choice(['similarity', 'exact', 'fuzzy']),
                    'parameters': np.random.rand(5).tolist()
                },
                'limit': np.random.randint(1, 100)
            })
        
        return base_interaction
    
    async def _get_current_rate(self) -> float:
        """Get current rate based on pattern."""
        if not self.pattern:
            return self.rate
        
        elapsed = time.time() - self.start_time
        pattern_func = self.predefined_patterns.get(self.pattern.pattern_type)
        
        if pattern_func:
            return await pattern_func(elapsed)
        else:
            logger.warning(f"Unknown pattern type: {self.pattern.pattern_type}")
            return self.rate
    
    async def _constant_pattern(self, elapsed: float) -> float:
        """Constant rate pattern."""
        return self.pattern.base_rate
    
    async def _linear_pattern(self, elapsed: float) -> float:
        """Linear increase pattern."""
        progress = min(elapsed / self.pattern.duration, 1.0)
        rate_range = self.pattern.peak_rate - self.pattern.base_rate
        return self.pattern.base_rate + (rate_range * progress)
    
    async def _sine_pattern(self, elapsed: float) -> float:
        """Sinusoidal pattern."""
        period = self.pattern.parameters.get('period', 60)  # seconds
        amplitude = (self.pattern.peak_rate - self.pattern.base_rate) / 2
        center = self.pattern.base_rate + amplitude
        
        rate = center + amplitude * np.sin(2 * np.pi * elapsed / period)
        return max(0, rate)
    
    async def _step_pattern(self, elapsed: float) -> float:
        """Step function pattern."""
        step_duration = self.pattern.parameters.get('step_duration', 30)  # seconds
        steps = self.pattern.parameters.get('steps', 5)
        
        rate_per_step = (self.pattern.peak_rate - self.pattern.base_rate) / steps
        current_step = min(int(elapsed / step_duration), steps)
        
        return self.pattern.base_rate + (current_step * rate_per_step)
    
    async def _burst_pattern(self, elapsed: float) -> float:
        """Burst pattern with quiet periods."""
        burst_duration = self.pattern.parameters.get('burst_duration', 10)  # seconds
        quiet_duration = self.pattern.parameters.get('quiet_duration', 20)  # seconds
        cycle_duration = burst_duration + quiet_duration
        
        cycle_position = elapsed % cycle_duration
        
        if cycle_position < burst_duration:
            return self.pattern.peak_rate
        else:
            return self.pattern.base_rate
    
    async def _realistic_pattern(self, elapsed: float) -> float:
        """Realistic usage pattern with daily variations."""
        # Daily pattern with peak hours
        hours_per_day = 24
        seconds_per_hour = 3600
        current_hour = (elapsed / seconds_per_hour) % hours_per_day
        
        # Peak hours: 9-11 AM, 2-4 PM, 7-9 PM
        peak_hours = [(9, 11), (14, 16), (19, 21)]
        is_peak = any(start <= current_hour < end for start, end in peak_hours)
        
        # Base load with daily variation
        daily_multiplier = 0.7 + 0.6 * np.sin(2 * np.pi * current_hour / hours_per_day)
        
        # Peak multiplier
        peak_multiplier = 1.5 if is_peak else 1.0
        
        # Random variation (±20%)
        random_multiplier = np.random.uniform(0.8, 1.2)
        
        base_rate = self.pattern.base_rate
        rate = base_rate * daily_multiplier * peak_multiplier * random_multiplier
        
        return min(rate, self.pattern.peak_rate)


class MultiPatternLoadGenerator:
    """Generates load using multiple concurrent patterns."""
    
    def __init__(self):
        """Initialize multi-pattern load generator."""
        self.generators = []
        self.running = False
    
    def add_pattern(self, pattern: LoadPattern) -> 'LoadGenerator':
        """Add a load pattern.
        
        Args:
            pattern: Load pattern configuration
            
        Returns:
            LoadGenerator instance for this pattern
        """
        generator = LoadGenerator(pattern=pattern)
        self.generators.append(generator)
        return generator
    
    async def start_all(self):
        """Start all generators."""
        self.running = True
        for generator in self.generators:
            await generator.start()
        logger.info(f"Started {len(self.generators)} load generators")
    
    async def stop_all(self):
        """Stop all generators."""
        self.running = False
        for generator in self.generators:
            await generator.stop()
        logger.info("Stopped all load generators")
    
    async def generate_combined_load(self, duration: float) -> AsyncGenerator[Dict[str, Any], None]:
        """Generate combined load from all patterns.
        
        Args:
            duration: Duration in seconds
            
        Yields:
            Combined load interactions
        """
        if not self.generators:
            return
        
        # Start all generators
        generator_tasks = []
        for generator in self.generators:
            task = asyncio.create_task(
                self._generate_from_generator(generator, duration)
            )
            generator_tasks.append(task)
        
        # Collect interactions from all generators
        start_time = time.time()
        
        while time.time() - start_time < duration and self.running:
            # Check for completed interactions
            for task in generator_tasks:
                if task.done():
                    try:
                        interaction = await task
                        if interaction:
                            yield interaction
                    except Exception as e:
                        logger.error(f"Error in generator task: {e}")
            
            await asyncio.sleep(0.001)  # Small delay to prevent busy waiting
        
        # Cancel remaining tasks
        for task in generator_tasks:
            if not task.done():
                task.cancel()
    
    async def _generate_from_generator(
        self, 
        generator: LoadGenerator, 
        duration: float
    ) -> Optional[Dict[str, Any]]:
        """Generate from a single generator."""
        try:
            async for interaction in generator.generate_load(duration):
                return interaction
        except Exception as e:
            logger.error(f"Generator error: {e}")
            return None


class AdaptiveLoadGenerator:
    """Load generator that adapts based on system response."""
    
    def __init__(
        self, 
        initial_rate: float = 100,
        target_latency_ms: float = 100,
        adaptation_factor: float = 0.1
    ):
        """Initialize adaptive load generator.
        
        Args:
            initial_rate: Initial operations per second
            target_latency_ms: Target response latency in milliseconds
            adaptation_factor: How aggressively to adapt (0.0 to 1.0)
        """
        self.current_rate = initial_rate
        self.target_latency_ms = target_latency_ms
        self.adaptation_factor = adaptation_factor
        self.latency_history = []
        self.running = False
        
    async def generate_adaptive_load(
        self, 
        duration: float,
        response_callback: Callable[[Dict[str, Any]], float]
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Generate adaptive load based on system response.
        
        Args:
            duration: Duration in seconds
            response_callback: Function that returns response latency in seconds
            
        Yields:
            Load interactions
        """
        self.running = True
        start_time = time.time()
        operation_count = 0
        
        while time.time() - start_time < duration and self.running:
            # Generate interaction
            interaction = {
                'id': f"adaptive_{operation_count}_{time.time()}",
                'type': 'adaptive_test',
                'timestamp': time.time(),
                'rate': self.current_rate
            }
            
            # Measure response time
            response_start = time.time()
            yield interaction
            
            # Get response latency from callback
            try:
                response_latency = await response_callback(interaction)
                response_latency_ms = response_latency * 1000
                
                # Adapt rate based on latency
                await self._adapt_rate(response_latency_ms)
                
            except Exception as e:
                logger.error(f"Error in response callback: {e}")
                # Reduce rate on error
                self.current_rate *= 0.9
            
            operation_count += 1
            
            # Control rate
            if self.current_rate > 0:
                await asyncio.sleep(1.0 / self.current_rate)
    
    async def _adapt_rate(self, latency_ms: float):
        """Adapt generation rate based on observed latency."""
        self.latency_history.append(latency_ms)
        
        # Keep only recent history
        if len(self.latency_history) > 100:
            self.latency_history = self.latency_history[-50:]
        
        # Calculate recent average latency
        if len(self.latency_history) >= 5:
            recent_avg_latency = np.mean(self.latency_history[-5:])
            
            # Calculate adaptation
            latency_ratio = recent_avg_latency / self.target_latency_ms
            
            if latency_ratio > 1.2:  # Latency too high
                # Reduce rate
                rate_adjustment = 1.0 - (self.adaptation_factor * (latency_ratio - 1.0))
                self.current_rate *= max(0.5, rate_adjustment)
                
            elif latency_ratio < 0.8:  # Latency acceptable, can increase
                # Increase rate cautiously
                rate_adjustment = 1.0 + (self.adaptation_factor * 0.5)
                self.current_rate *= min(2.0, rate_adjustment)
            
            # Ensure reasonable bounds
            self.current_rate = max(1.0, min(10000.0, self.current_rate))
            
            logger.debug(f"Adapted rate to {self.current_rate:.1f} ops/sec "
                        f"(latency: {recent_avg_latency:.1f}ms)")


class WorkloadMixGenerator:
    """Generates realistic workload mixes for testing."""
    
    def __init__(self):
        """Initialize workload mix generator."""
        self.workload_profiles = {
            'development': {
                'learning': 0.4,
                'pattern_match': 0.3,
                'knowledge_share': 0.2,
                'data_query': 0.1
            },
            'production': {
                'learning': 0.1,
                'pattern_match': 0.6,
                'knowledge_share': 0.2,
                'data_query': 0.1
            },
            'training': {
                'learning': 0.8,
                'pattern_match': 0.1,
                'knowledge_share': 0.05,
                'data_query': 0.05
            },
            'inference': {
                'learning': 0.05,
                'pattern_match': 0.8,
                'knowledge_share': 0.1,
                'data_query': 0.05
            }
        }
    
    async def generate_workload_mix(
        self, 
        profile_name: str, 
        rate: float, 
        duration: float
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Generate workload mix based on profile.
        
        Args:
            profile_name: Workload profile name
            rate: Operations per second
            duration: Duration in seconds
            
        Yields:
            Workload interactions
        """
        if profile_name not in self.workload_profiles:
            raise ValueError(f"Unknown workload profile: {profile_name}")
        
        profile = self.workload_profiles[profile_name]
        operation_types = list(profile.keys())
        probabilities = list(profile.values())
        
        start_time = time.time()
        operation_count = 0
        
        while time.time() - start_time < duration:
            # Select operation type based on profile
            operation_type = np.random.choice(operation_types, p=probabilities)
            
            # Generate interaction
            interaction = await self._generate_workload_interaction(
                operation_type, 
                operation_count, 
                profile_name
            )
            
            yield interaction
            operation_count += 1
            
            # Control rate
            await asyncio.sleep(1.0 / rate)
    
    async def _generate_workload_interaction(
        self, 
        operation_type: str, 
        operation_count: int, 
        profile_name: str
    ) -> Dict[str, Any]:
        """Generate a workload interaction."""
        base_interaction = {
            'id': f"{profile_name}_{operation_type}_{operation_count}",
            'type': operation_type,
            'timestamp': time.time(),
            'profile': profile_name,
            'source': 'workload_generator'
        }
        
        # Add realistic complexity based on profile
        if profile_name == 'development':
            complexity_level = np.random.choice(['simple', 'medium', 'complex'], p=[0.5, 0.3, 0.2])
        elif profile_name == 'production':
            complexity_level = np.random.choice(['simple', 'medium', 'complex'], p=[0.7, 0.25, 0.05])
        elif profile_name == 'training':
            complexity_level = np.random.choice(['simple', 'medium', 'complex'], p=[0.2, 0.4, 0.4])
        else:  # inference
            complexity_level = np.random.choice(['simple', 'medium', 'complex'], p=[0.8, 0.15, 0.05])
        
        base_interaction['complexity'] = complexity_level
        
        # Add operation-specific data
        if operation_type == 'learning':
            data_size = {'simple': 50, 'medium': 200, 'complex': 1000}[complexity_level]
            base_interaction.update({
                'input_data': np.random.rand(data_size).tolist(),
                'learning_rate': np.random.uniform(0.001, 0.1),
                'epochs': np.random.randint(1, 10)
            })
        
        elif operation_type == 'pattern_match':
            pattern_size = {'simple': 20, 'medium': 100, 'complex': 500}[complexity_level]
            base_interaction.update({
                'pattern': np.random.rand(pattern_size).tolist(),
                'threshold': np.random.uniform(0.7, 0.95),
                'max_results': np.random.randint(1, 50)
            })
        
        return base_interaction