#!/usr/bin/env python3
"""
Load Pattern Generation Engine
=============================

Advanced pattern generation system for creating realistic load patterns
with mathematical models and real-world simulation capabilities.
"""

import math
import numpy as np
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import random
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class PatternType(Enum):
    """Available pattern types"""
    STEADY_STATE = "steady_state"
    RAMP_UP = "ramp_up"
    RAMP_DOWN = "ramp_down"
    BURST = "burst"
    SPIKE = "spike"
    CYCLIC = "cyclic"
    RANDOM = "random"
    REALISTIC = "realistic"
    GRADUAL_INCREASE = "gradual_increase"
    GRADUAL_DECREASE = "gradual_decrease"
    WAVE = "wave"
    TRIANGULAR = "triangular"
    SAWTOOTH = "sawtooth"
    EXPONENTIAL = "exponential"
    LOGARITHMIC = "logarithmic"

@dataclass
class LoadPoint:
    """Single load measurement point"""
    timestamp: float
    intensity: float
    parameters: Dict[str, Any]

@dataclass
class LoadPattern:
    """Complete load pattern definition"""
    name: str
    pattern_type: PatternType
    duration: int  # seconds
    points: List[LoadPoint]
    metadata: Dict[str, Any]

class PatternEngine:
    """
    Advanced Load Pattern Generation Engine
    
    Generates sophisticated load patterns using mathematical models
    and real-world simulation parameters.
    """
    
    def __init__(self):
        self.pattern_generators = {
            PatternType.STEADY_STATE: self._generate_steady_state,
            PatternType.RAMP_UP: self._generate_ramp_up,
            PatternType.RAMP_DOWN: self._generate_ramp_down,
            PatternType.BURST: self._generate_burst,
            PatternType.SPIKE: self._generate_spike,
            PatternType.CYCLIC: self._generate_cyclic,
            PatternType.RANDOM: self._generate_random,
            PatternType.REALISTIC: self._generate_realistic,
            PatternType.GRADUAL_INCREASE: self._generate_gradual_increase,
            PatternType.GRADUAL_DECREASE: self._generate_gradual_decrease,
            PatternType.WAVE: self._generate_wave,
            PatternType.TRIANGULAR: self._generate_triangular,
            PatternType.SAWTOOTH: self._generate_sawtooth,
            PatternType.EXPONENTIAL: self._generate_exponential,
            PatternType.LOGARITHMIC: self._generate_logarithmic
        }
        
        # Default parameters for each pattern type
        self.default_parameters = {
            PatternType.STEADY_STATE: {'variance': 0.05, 'noise_level': 0.02},
            PatternType.RAMP_UP: {'start_intensity': 0.1, 'acceleration': 'linear'},
            PatternType.RAMP_DOWN: {'end_intensity': 0.1, 'deceleration': 'linear'},
            PatternType.BURST: {'burst_count': 3, 'burst_duration': 30, 'rest_duration': 60},
            PatternType.SPIKE: {'spike_count': 5, 'spike_intensity': 0.9, 'spike_duration': 10},
            PatternType.CYCLIC: {'cycle_duration': 300, 'cycles': 3, 'amplitude': 0.8},
            PatternType.RANDOM: {'randomness': 0.3, 'smoothing': 0.1},
            PatternType.REALISTIC: {'profile': 'web_traffic', 'geography': 'global'},
            PatternType.GRADUAL_INCREASE: {'rate': 0.001, 'curve': 'logarithmic'},
            PatternType.GRADUAL_DECREASE: {'rate': 0.001, 'curve': 'exponential'},
            PatternType.WAVE: {'frequency': 0.01, 'amplitude': 0.5, 'phase': 0},
            PatternType.TRIANGULAR: {'peak_position': 0.5, 'sharpness': 1.0},
            PatternType.SAWTOOTH: {'rise_time': 0.7, 'fall_time': 0.3},
            PatternType.EXPONENTIAL: {'growth_rate': 0.01, 'max_intensity': 1.0},
            PatternType.LOGARITHMIC: {'decay_rate': 0.01, 'min_intensity': 0.1}
        }
    
    def generate_pattern(self, pattern_name: str, duration: int, 
                        base_intensity: float, parameters: Dict[str, Any] = None) -> LoadPattern:
        """Generate a load pattern based on name and parameters"""
        try:
            # Determine pattern type from name
            pattern_type = self._parse_pattern_name(pattern_name)
            
            # Merge parameters with defaults
            merged_params = self.default_parameters.get(pattern_type, {}).copy()
            if parameters:
                merged_params.update(parameters)
            
            # Generate pattern points
            generator = self.pattern_generators.get(pattern_type)
            if not generator:
                raise ValueError(f"Unknown pattern type: {pattern_type}")
            
            points = generator(duration, base_intensity, merged_params)
            
            # Create pattern object
            pattern = LoadPattern(
                name=pattern_name,
                pattern_type=pattern_type,
                duration=duration,
                points=points,
                metadata={
                    'base_intensity': base_intensity,
                    'parameters': merged_params,
                    'generated_at': datetime.now().isoformat(),
                    'point_count': len(points)
                }
            )
            
            logger.info(f"Generated pattern '{pattern_name}' with {len(points)} points")
            return pattern
            
        except Exception as e:
            logger.error(f"Failed to generate pattern '{pattern_name}': {e}")
            raise
    
    def _parse_pattern_name(self, pattern_name: str) -> PatternType:
        """Parse pattern name to determine pattern type"""
        pattern_name_lower = pattern_name.lower().replace('_', ' ').replace('-', ' ')
        
        # Direct mapping
        for pattern_type in PatternType:
            if pattern_type.value == pattern_name:
                return pattern_type
        
        # Keyword-based matching
        if any(keyword in pattern_name_lower for keyword in ['steady', 'constant', 'flat']):
            return PatternType.STEADY_STATE
        elif any(keyword in pattern_name_lower for keyword in ['ramp up', 'increase', 'grow']):
            return PatternType.RAMP_UP
        elif any(keyword in pattern_name_lower for keyword in ['ramp down', 'decrease', 'decline']):
            return PatternType.RAMP_DOWN
        elif any(keyword in pattern_name_lower for keyword in ['burst', 'sudden']):
            return PatternType.BURST
        elif any(keyword in pattern_name_lower for keyword in ['spike', 'peak']):
            return PatternType.SPIKE
        elif any(keyword in pattern_name_lower for keyword in ['cycle', 'periodic', 'repeat']):
            return PatternType.CYCLIC
        elif any(keyword in pattern_name_lower for keyword in ['random', 'chaos', 'unpredictable']):
            return PatternType.RANDOM
        elif any(keyword in pattern_name_lower for keyword in ['realistic', 'real world', 'production']):
            return PatternType.REALISTIC
        elif any(keyword in pattern_name_lower for keyword in ['wave', 'sine', 'cosine']):
            return PatternType.WAVE
        elif any(keyword in pattern_name_lower for keyword in ['triangle', 'triangular']):
            return PatternType.TRIANGULAR
        elif any(keyword in pattern_name_lower for keyword in ['sawtooth', 'saw tooth']):
            return PatternType.SAWTOOTH
        elif any(keyword in pattern_name_lower for keyword in ['exponential', 'exp']):
            return PatternType.EXPONENTIAL
        elif any(keyword in pattern_name_lower for keyword in ['logarithmic', 'log']):
            return PatternType.LOGARITHMIC
        else:
            # Default to steady state
            return PatternType.STEADY_STATE
    
    def _generate_steady_state(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate steady state pattern with optional variance"""
        points = []
        variance = params.get('variance', 0.05)
        noise_level = params.get('noise_level', 0.02)
        interval = 1.0  # 1 second intervals
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            
            # Add variance and noise
            intensity = base_intensity
            if variance > 0:
                intensity += random.uniform(-variance, variance)
            if noise_level > 0:
                intensity += random.uniform(-noise_level, noise_level)
            
            # Clamp to valid range
            intensity = max(0.0, min(1.0, intensity))
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=intensity,
                parameters={'variance': variance, 'noise_level': noise_level}
            ))
        
        return points
    
    def _generate_ramp_up(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate ramp-up pattern"""
        points = []
        start_intensity = params.get('start_intensity', 0.1)
        acceleration = params.get('acceleration', 'linear')
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            progress = timestamp / duration
            
            if acceleration == 'linear':
                intensity = start_intensity + (base_intensity - start_intensity) * progress
            elif acceleration == 'exponential':
                intensity = start_intensity + (base_intensity - start_intensity) * (progress ** 2)
            elif acceleration == 'logarithmic':
                intensity = start_intensity + (base_intensity - start_intensity) * math.log(1 + progress * (math.e - 1)) / math.log(math.e)
            else:
                intensity = start_intensity + (base_intensity - start_intensity) * progress
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'progress': progress, 'acceleration': acceleration}
            ))
        
        return points
    
    def _generate_ramp_down(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate ramp-down pattern"""
        points = []
        end_intensity = params.get('end_intensity', 0.1)
        deceleration = params.get('deceleration', 'linear')
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            progress = timestamp / duration
            
            if deceleration == 'linear':
                intensity = base_intensity - (base_intensity - end_intensity) * progress
            elif deceleration == 'exponential':
                intensity = base_intensity - (base_intensity - end_intensity) * (progress ** 2)
            elif deceleration == 'logarithmic':
                intensity = base_intensity - (base_intensity - end_intensity) * math.log(1 + progress * (math.e - 1)) / math.log(math.e)
            else:
                intensity = base_intensity - (base_intensity - end_intensity) * progress
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'progress': progress, 'deceleration': deceleration}
            ))
        
        return points
    
    def _generate_burst(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate burst pattern with periodic high-intensity intervals"""
        points = []
        burst_count = params.get('burst_count', 3)
        burst_duration = params.get('burst_duration', 30)
        rest_duration = params.get('rest_duration', 60)
        burst_intensity = params.get('burst_intensity', base_intensity * 1.5)
        interval = 1.0
        
        cycle_duration = burst_duration + rest_duration
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            cycle_position = timestamp % cycle_duration
            
            if cycle_position < burst_duration:
                # In burst phase
                intensity = burst_intensity
                phase = 'burst'
            else:
                # In rest phase
                intensity = base_intensity * 0.3  # Low baseline
                phase = 'rest'
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'phase': phase, 'cycle_position': cycle_position}
            ))
        
        return points
    
    def _generate_spike(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate spike pattern with short, high-intensity peaks"""
        points = []
        spike_count = params.get('spike_count', 5)
        spike_intensity = params.get('spike_intensity', 0.9)
        spike_duration = params.get('spike_duration', 10)
        interval = 1.0
        
        # Calculate spike timing
        spike_intervals = np.linspace(0, duration - spike_duration, spike_count)
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            intensity = base_intensity
            
            # Check if we're in a spike
            for spike_start in spike_intervals:
                if spike_start <= timestamp < spike_start + spike_duration:
                    intensity = spike_intensity
                    break
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'spike_active': intensity > base_intensity}
            ))
        
        return points
    
    def _generate_cyclic(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate cyclic pattern with configurable cycles"""
        points = []
        cycle_duration = params.get('cycle_duration', 300)
        cycles = params.get('cycles', 3)
        amplitude = params.get('amplitude', 0.8)
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            cycle_progress = (timestamp % cycle_duration) / cycle_duration
            
            # Sine wave cycle
            cycle_value = math.sin(2 * math.pi * cycle_progress)
            intensity = base_intensity + amplitude * cycle_value * 0.5
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'cycle_progress': cycle_progress, 'cycle_value': cycle_value}
            ))
        
        return points
    
    def _generate_random(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate random pattern with configurable randomness"""
        points = []
        randomness = params.get('randomness', 0.3)
        smoothing = params.get('smoothing', 0.1)
        interval = 1.0
        
        previous_intensity = base_intensity
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            
            # Generate random variation
            random_change = random.uniform(-randomness, randomness)
            target_intensity = base_intensity + random_change
            
            # Apply smoothing
            intensity = previous_intensity + (target_intensity - previous_intensity) * smoothing
            intensity = max(0.0, min(1.0, intensity))
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=intensity,
                parameters={'random_change': random_change, 'smoothed': True}
            ))
            
            previous_intensity = intensity
        
        return points
    
    def _generate_realistic(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate realistic pattern based on real-world profiles"""
        points = []
        profile = params.get('profile', 'web_traffic')
        geography = params.get('geography', 'global')
        interval = 1.0
        
        # Define realistic patterns based on profile
        if profile == 'web_traffic':
            points = self._generate_web_traffic_pattern(duration, base_intensity, params)
        elif profile == 'api_service':
            points = self._generate_api_service_pattern(duration, base_intensity, params)
        elif profile == 'batch_processing':
            points = self._generate_batch_processing_pattern(duration, base_intensity, params)
        elif profile == 'gaming':
            points = self._generate_gaming_pattern(duration, base_intensity, params)
        else:
            # Default to web traffic
            points = self._generate_web_traffic_pattern(duration, base_intensity, params)
        
        return points
    
    def _generate_web_traffic_pattern(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate realistic web traffic pattern"""
        points = []
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            hour_of_day = (timestamp / 3600) % 24  # Simulate hours in a day
            
            # Business hours pattern (9 AM - 5 PM peak)
            if 9 <= hour_of_day <= 17:
                time_multiplier = 1.5
            elif 6 <= hour_of_day <= 9 or 17 <= hour_of_day <= 22:
                time_multiplier = 1.0
            else:
                time_multiplier = 0.3
            
            # Add some randomness for realism
            noise = random.uniform(0.8, 1.2)
            intensity = base_intensity * time_multiplier * noise
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'hour_of_day': hour_of_day, 'time_multiplier': time_multiplier}
            ))
        
        return points
    
    def _generate_api_service_pattern(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate realistic API service pattern"""
        points = []
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            
            # API services tend to have more consistent load with occasional spikes
            base_load = base_intensity * 0.8
            
            # Random spikes (5% chance)
            if random.random() < 0.05:
                spike_multiplier = random.uniform(2.0, 5.0)
                intensity = min(1.0, base_load * spike_multiplier)
            else:
                # Normal variation
                variation = random.uniform(0.9, 1.1)
                intensity = base_load * variation
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'base_load': base_load, 'spike': intensity > base_load * 1.5}
            ))
        
        return points
    
    def _generate_batch_processing_pattern(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate realistic batch processing pattern"""
        points = []
        batch_duration = params.get('batch_duration', 3600)  # 1 hour batches
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            batch_progress = (timestamp % batch_duration) / batch_duration
            
            # High load at start of batch, tapering off
            if batch_progress < 0.1:
                intensity = base_intensity * 1.5  # Startup spike
            elif batch_progress < 0.8:
                intensity = base_intensity * (1.2 - batch_progress * 0.5)  # Gradual decrease
            else:
                intensity = base_intensity * 0.3  # Low maintenance load
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'batch_progress': batch_progress}
            ))
        
        return points
    
    def _generate_gaming_pattern(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate realistic gaming pattern"""
        points = []
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            hour_of_day = (timestamp / 3600) % 24
            
            # Gaming has peak evening hours (7 PM - 11 PM)
            if 19 <= hour_of_day <= 23:
                time_multiplier = 2.0
            elif 12 <= hour_of_day <= 19 or 23 <= hour_of_day <= 24:
                time_multiplier = 1.2
            else:
                time_multiplier = 0.4
            
            # Add match-based spikes (every 10-20 minutes)
            match_cycle = timestamp % random.uniform(600, 1200)
            if match_cycle < 60:  # Match start spike
                match_multiplier = 1.5
            else:
                match_multiplier = 1.0
            
            intensity = base_intensity * time_multiplier * match_multiplier
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'hour_of_day': hour_of_day, 'match_spike': match_multiplier > 1.0}
            ))
        
        return points
    
    def _generate_gradual_increase(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate gradual increase pattern"""
        points = []
        rate = params.get('rate', 0.001)
        curve = params.get('curve', 'logarithmic')
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            progress = timestamp / duration
            
            if curve == 'logarithmic':
                increase = math.log(1 + progress * rate * duration) / math.log(1 + rate * duration)
            elif curve == 'exponential':
                increase = (math.exp(progress * rate * duration) - 1) / (math.exp(rate * duration) - 1)
            else:  # linear
                increase = progress * rate * duration
            
            intensity = base_intensity + increase
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'progress': progress, 'increase': increase}
            ))
        
        return points
    
    def _generate_gradual_decrease(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate gradual decrease pattern"""
        points = []
        rate = params.get('rate', 0.001)
        curve = params.get('curve', 'exponential')
        min_intensity = params.get('min_intensity', 0.1)
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            progress = timestamp / duration
            
            if curve == 'exponential':
                decrease = (1 - math.exp(-progress * rate * duration))
            elif curve == 'logarithmic':
                decrease = math.log(1 + progress * rate * duration) / math.log(1 + rate * duration)
            else:  # linear
                decrease = progress * rate * duration
            
            intensity = base_intensity - (base_intensity - min_intensity) * decrease
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(min_intensity, min(1.0, intensity)),
                parameters={'progress': progress, 'decrease': decrease}
            ))
        
        return points
    
    def _generate_wave(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate wave pattern (sine/cosine)"""
        points = []
        frequency = params.get('frequency', 0.01)
        amplitude = params.get('amplitude', 0.5)
        phase = params.get('phase', 0)
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            wave_value = math.sin(2 * math.pi * frequency * timestamp + phase)
            intensity = base_intensity + amplitude * wave_value
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'wave_value': wave_value, 'frequency': frequency}
            ))
        
        return points
    
    def _generate_triangular(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate triangular wave pattern"""
        points = []
        peak_position = params.get('peak_position', 0.5)
        sharpness = params.get('sharpness', 1.0)
        interval = 1.0
        
        peak_time = duration * peak_position
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            
            if timestamp <= peak_time:
                # Rising edge
                progress = timestamp / peak_time
                intensity = base_intensity * (progress ** sharpness)
            else:
                # Falling edge
                progress = (duration - timestamp) / (duration - peak_time)
                intensity = base_intensity * (progress ** sharpness)
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'peak_reached': timestamp >= peak_time}
            ))
        
        return points
    
    def _generate_sawtooth(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate sawtooth pattern"""
        points = []
        rise_time = params.get('rise_time', 0.7)
        fall_time = params.get('fall_time', 0.3)
        cycle_duration = params.get('cycle_duration', 300)
        interval = 1.0
        
        rise_duration = cycle_duration * rise_time
        fall_duration = cycle_duration * fall_time
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            cycle_position = timestamp % cycle_duration
            
            if cycle_position <= rise_duration:
                # Rising edge
                intensity = base_intensity * (cycle_position / rise_duration)
            else:
                # Falling edge
                fall_progress = (cycle_position - rise_duration) / fall_duration
                intensity = base_intensity * (1 - fall_progress)
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=max(0.0, min(1.0, intensity)),
                parameters={'cycle_position': cycle_position, 'rising': cycle_position <= rise_duration}
            ))
        
        return points
    
    def _generate_exponential(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate exponential growth pattern"""
        points = []
        growth_rate = params.get('growth_rate', 0.01)
        max_intensity = params.get('max_intensity', 1.0)
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            exponential_factor = math.exp(growth_rate * timestamp)
            intensity = min(max_intensity, base_intensity * exponential_factor)
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=intensity,
                parameters={'exponential_factor': exponential_factor, 'capped': intensity >= max_intensity}
            ))
        
        return points
    
    def _generate_logarithmic(self, duration: int, base_intensity: float, params: Dict[str, Any]) -> List[LoadPoint]:
        """Generate logarithmic decay pattern"""
        points = []
        decay_rate = params.get('decay_rate', 0.01)
        min_intensity = params.get('min_intensity', 0.1)
        interval = 1.0
        
        for i in range(int(duration / interval)):
            timestamp = i * interval
            log_factor = math.log(1 + decay_rate * timestamp) / math.log(1 + decay_rate * duration)
            intensity = max(min_intensity, base_intensity * (1 - log_factor))
            
            points.append(LoadPoint(
                timestamp=timestamp,
                intensity=intensity,
                parameters={'log_factor': log_factor, 'floored': intensity <= min_intensity}
            ))
        
        return points
    
    def combine_patterns(self, patterns: List[LoadPattern], combination_method: str = 'additive') -> LoadPattern:
        """Combine multiple patterns into a single pattern"""
        if not patterns:
            raise ValueError("No patterns provided for combination")
        
        # Find common duration (use minimum)
        min_duration = min(pattern.duration for pattern in patterns)
        combined_points = []
        
        # Get all timestamps
        all_timestamps = set()
        for pattern in patterns:
            for point in pattern.points:
                if point.timestamp <= min_duration:
                    all_timestamps.add(point.timestamp)
        
        timestamps = sorted(all_timestamps)
        
        for timestamp in timestamps:
            combined_intensity = 0.0
            combined_params = {}
            
            for pattern in patterns:
                # Find closest point in this pattern
                pattern_point = self._get_intensity_at_time(pattern, timestamp)
                
                if combination_method == 'additive':
                    combined_intensity += pattern_point.intensity
                elif combination_method == 'multiplicative':
                    combined_intensity = combined_intensity * pattern_point.intensity if combined_intensity > 0 else pattern_point.intensity
                elif combination_method == 'maximum':
                    combined_intensity = max(combined_intensity, pattern_point.intensity)
                elif combination_method == 'average':
                    combined_intensity += pattern_point.intensity / len(patterns)
                
                # Merge parameters
                combined_params.update(pattern_point.parameters)
            
            # Clamp intensity
            combined_intensity = max(0.0, min(1.0, combined_intensity))
            
            combined_points.append(LoadPoint(
                timestamp=timestamp,
                intensity=combined_intensity,
                parameters=combined_params
            ))
        
        return LoadPattern(
            name=f"combined_{'_'.join([p.name for p in patterns])}",
            pattern_type=PatternType.REALISTIC,
            duration=min_duration,
            points=combined_points,
            metadata={
                'combination_method': combination_method,
                'source_patterns': [p.name for p in patterns],
                'combined_at': datetime.now().isoformat()
            }
        )
    
    def _get_intensity_at_time(self, pattern: LoadPattern, timestamp: float) -> LoadPoint:
        """Get intensity at a specific timestamp using interpolation"""
        if not pattern.points:
            return LoadPoint(timestamp=timestamp, intensity=0.0, parameters={})
        
        # Find surrounding points
        before_point = None
        after_point = None
        
        for point in pattern.points:
            if point.timestamp <= timestamp:
                before_point = point
            elif point.timestamp > timestamp and after_point is None:
                after_point = point
                break
        
        if before_point is None:
            return pattern.points[0]
        if after_point is None:
            return before_point
        
        # Linear interpolation
        time_diff = after_point.timestamp - before_point.timestamp
        if time_diff == 0:
            return before_point
        
        weight = (timestamp - before_point.timestamp) / time_diff
        interpolated_intensity = before_point.intensity + weight * (after_point.intensity - before_point.intensity)
        
        return LoadPoint(
            timestamp=timestamp,
            intensity=interpolated_intensity,
            parameters=before_point.parameters
        )