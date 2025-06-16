#!/usr/bin/env python3
"""
Custom Scenario Builder
======================

Tool for creating custom load testing scenarios with interactive configuration,
visual pattern preview, and scenario validation.
"""

import json
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

from profiles.workload_profiles import WorkloadProfileManager, WorkloadProfile, GeneratorProfile, ProfileType
from patterns.pattern_engine import PatternEngine, PatternType

logger = logging.getLogger(__name__)

@dataclass
class ScenarioStep:
    """Represents a step in a custom scenario"""
    step_name: str
    duration_minutes: int
    generators: List[GeneratorProfile]
    description: str = ""
    conditions: Dict[str, Any] = None  # Conditions for step execution
    actions: Dict[str, Any] = None     # Actions to take during step

@dataclass
class CustomScenario:
    """Complete custom scenario definition"""
    scenario_name: str
    description: str
    total_duration_minutes: int
    steps: List[ScenarioStep]
    global_settings: Dict[str, Any] = None
    validation_rules: Dict[str, Any] = None
    metadata: Dict[str, Any] = None

class CustomScenarioBuilder:
    """
    Custom Scenario Builder
    
    Interactive tool for creating sophisticated load testing scenarios with
    multiple phases, conditions, and custom patterns.
    """
    
    def __init__(self):
        self.profile_manager = WorkloadProfileManager()
        self.pattern_engine = PatternEngine()
        self.current_scenario: Optional[CustomScenario] = None
        self.scenario_library: Dict[str, CustomScenario] = {}
        
        # Available generator types
        self.generator_types = ["cpu", "memory", "io", "network", "application"]
        
        # Default settings
        self.default_settings = {
            "coordination": {
                "adaptive_scaling": True,
                "failure_handling": "graceful_degradation",
                "load_balancing": True
            },
            "monitoring": {
                "metrics_collection_interval": 5,
                "alert_thresholds": {
                    "cpu_max": 90.0,
                    "memory_max": 85.0,
                    "response_time_max": 10000,
                    "error_rate_max": 0.10
                }
            },
            "safety": {
                "emergency_stop_conditions": {
                    "cpu_critical": 98.0,
                    "memory_critical": 95.0,
                    "error_rate_critical": 0.50
                },
                "auto_rollback": True,
                "max_scenario_duration_hours": 24
            }
        }
    
    def start_new_scenario(self, scenario_name: str, description: str = "") -> bool:
        """Start building a new scenario"""
        try:
            self.current_scenario = CustomScenario(
                scenario_name=scenario_name,
                description=description,
                total_duration_minutes=0,
                steps=[],
                global_settings=self.default_settings.copy(),
                validation_rules={},
                metadata={
                    "created_at": time.time(),
                    "created_by": "scenario_builder",
                    "version": "1.0"
                }
            )
            
            logger.info(f"Started new scenario: {scenario_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start new scenario: {e}")
            return False
    
    def add_step_from_profile(self, step_name: str, profile_name: str, 
                             duration_minutes: int, intensity_modifier: float = 1.0) -> bool:
        """Add a step based on an existing workload profile"""
        if not self.current_scenario:
            logger.error("No active scenario. Start a new scenario first.")
            return False
        
        profile = self.profile_manager.get_profile(profile_name)
        if not profile:
            logger.error(f"Profile not found: {profile_name}")
            return False
        
        try:
            # Modify generators with intensity modifier
            modified_generators = []
            for gen in profile.generators:
                modified_gen = GeneratorProfile(
                    generator_type=gen.generator_type,
                    enabled=gen.enabled,
                    intensity_multiplier=gen.intensity_multiplier * intensity_modifier,
                    pattern_name=gen.pattern_name,
                    custom_parameters=gen.custom_parameters.copy() if gen.custom_parameters else None,
                    priority=gen.priority
                )
                modified_generators.append(modified_gen)
            
            step = ScenarioStep(
                step_name=step_name,
                duration_minutes=duration_minutes,
                generators=modified_generators,
                description=f"Based on {profile_name} profile with {intensity_modifier}x intensity"
            )
            
            self.current_scenario.steps.append(step)
            self.current_scenario.total_duration_minutes += duration_minutes
            
            logger.info(f"Added step '{step_name}' from profile '{profile_name}'")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add step from profile: {e}")
            return False
    
    def add_custom_step(self, step_name: str, duration_minutes: int, 
                       generator_configs: List[Dict[str, Any]], description: str = "") -> bool:
        """Add a custom step with specific generator configurations"""
        if not self.current_scenario:
            logger.error("No active scenario. Start a new scenario first.")
            return False
        
        try:
            generators = []
            for config in generator_configs:
                generator = GeneratorProfile(
                    generator_type=config["generator_type"],
                    enabled=config.get("enabled", True),
                    intensity_multiplier=config.get("intensity_multiplier", 1.0),
                    pattern_name=config.get("pattern_name", "steady_state"),
                    custom_parameters=config.get("custom_parameters"),
                    priority=config.get("priority", 1)
                )
                generators.append(generator)
            
            step = ScenarioStep(
                step_name=step_name,
                duration_minutes=duration_minutes,
                generators=generators,
                description=description
            )
            
            self.current_scenario.steps.append(step)
            self.current_scenario.total_duration_minutes += duration_minutes
            
            logger.info(f"Added custom step '{step_name}' with {len(generators)} generators")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add custom step: {e}")
            return False
    
    def add_ramp_up_step(self, step_name: str, duration_minutes: int, 
                        target_intensities: Dict[str, float], start_intensities: Dict[str, float] = None) -> bool:
        """Add a ramp-up step that gradually increases load"""
        if start_intensities is None:
            start_intensities = {gen_type: 0.1 for gen_type in target_intensities.keys()}
        
        generator_configs = []
        for gen_type, target_intensity in target_intensities.items():
            start_intensity = start_intensities.get(gen_type, 0.1)
            
            config = {
                "generator_type": gen_type,
                "enabled": True,
                "intensity_multiplier": target_intensity,
                "pattern_name": "ramp_up",
                "custom_parameters": {
                    "start_intensity": start_intensity,
                    "acceleration": "linear"
                }
            }
            generator_configs.append(config)
        
        return self.add_custom_step(
            step_name=step_name,
            duration_minutes=duration_minutes,
            generator_configs=generator_configs,
            description=f"Ramp-up step from {start_intensities} to {target_intensities}"
        )
    
    def add_spike_step(self, step_name: str, duration_minutes: int,
                      base_intensities: Dict[str, float], spike_intensities: Dict[str, float],
                      spike_count: int = 3, spike_duration_minutes: int = 2) -> bool:
        """Add a spike test step with sudden load increases"""
        generator_configs = []
        for gen_type, base_intensity in base_intensities.items():
            spike_intensity = spike_intensities.get(gen_type, base_intensity * 2.0)
            
            config = {
                "generator_type": gen_type,
                "enabled": True,
                "intensity_multiplier": base_intensity,
                "pattern_name": "spike",
                "custom_parameters": {
                    "spike_count": spike_count,
                    "spike_intensity": spike_intensity,
                    "spike_duration": spike_duration_minutes * 60  # Convert to seconds
                }
            }
            generator_configs.append(config)
        
        return self.add_custom_step(
            step_name=step_name,
            duration_minutes=duration_minutes,
            generator_configs=generator_configs,
            description=f"Spike test with {spike_count} spikes of {spike_duration_minutes}min each"
        )
    
    def add_step_with_conditions(self, step_name: str, duration_minutes: int,
                               generator_configs: List[Dict[str, Any]],
                               conditions: Dict[str, Any], description: str = "") -> bool:
        """Add a step with execution conditions"""
        if self.add_custom_step(step_name, duration_minutes, generator_configs, description):
            step = self.current_scenario.steps[-1]
            step.conditions = conditions
            logger.info(f"Added conditions to step '{step_name}': {conditions}")
            return True
        return False
    
    def add_step_with_actions(self, step_name: str, duration_minutes: int,
                            generator_configs: List[Dict[str, Any]],
                            actions: Dict[str, Any], description: str = "") -> bool:
        """Add a step with specific actions"""
        if self.add_custom_step(step_name, duration_minutes, generator_configs, description):
            step = self.current_scenario.steps[-1]
            step.actions = actions
            logger.info(f"Added actions to step '{step_name}': {actions}")
            return True
        return False
    
    def modify_step(self, step_index: int, modifications: Dict[str, Any]) -> bool:
        """Modify an existing step"""
        if not self.current_scenario or step_index >= len(self.current_scenario.steps):
            logger.error("Invalid step index or no active scenario")
            return False
        
        try:
            step = self.current_scenario.steps[step_index]
            
            for key, value in modifications.items():
                if hasattr(step, key):
                    # Update duration in total if changed
                    if key == "duration_minutes":
                        old_duration = step.duration_minutes
                        self.current_scenario.total_duration_minutes += (value - old_duration)
                    
                    setattr(step, key, value)
                else:
                    logger.warning(f"Unknown step attribute: {key}")
            
            logger.info(f"Modified step {step_index}: {step.step_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to modify step: {e}")
            return False
    
    def remove_step(self, step_index: int) -> bool:
        """Remove a step from the scenario"""
        if not self.current_scenario or step_index >= len(self.current_scenario.steps):
            logger.error("Invalid step index or no active scenario")
            return False
        
        try:
            step = self.current_scenario.steps.pop(step_index)
            self.current_scenario.total_duration_minutes -= step.duration_minutes
            
            logger.info(f"Removed step: {step.step_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove step: {e}")
            return False
    
    def set_global_settings(self, settings: Dict[str, Any]) -> bool:
        """Set global scenario settings"""
        if not self.current_scenario:
            logger.error("No active scenario")
            return False
        
        try:
            if self.current_scenario.global_settings is None:
                self.current_scenario.global_settings = {}
            
            self.current_scenario.global_settings.update(settings)
            logger.info("Updated global settings")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set global settings: {e}")
            return False
    
    def set_validation_rules(self, rules: Dict[str, Any]) -> bool:
        """Set scenario validation rules"""
        if not self.current_scenario:
            logger.error("No active scenario")
            return False
        
        try:
            self.current_scenario.validation_rules = rules
            logger.info("Updated validation rules")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set validation rules: {e}")
            return False
    
    def preview_scenario_timeline(self, save_path: Optional[str] = None) -> bool:
        """Generate and display a visual timeline of the scenario"""
        if not self.current_scenario or not self.current_scenario.steps:
            logger.error("No scenario steps to preview")
            return False
        
        try:
            # Create timeline data
            timeline_data = {}
            current_time = 0
            
            for step in self.current_scenario.steps:
                step_start = current_time
                step_end = current_time + step.duration_minutes
                
                for generator in step.generators:
                    if not generator.enabled:
                        continue
                    
                    gen_type = generator.generator_type
                    if gen_type not in timeline_data:
                        timeline_data[gen_type] = []
                    
                    timeline_data[gen_type].append({
                        'start': step_start,
                        'end': step_end,
                        'intensity': generator.intensity_multiplier,
                        'pattern': generator.pattern_name,
                        'step_name': step.step_name
                    })
                
                current_time = step_end
            
            # Create visualization
            fig, axes = plt.subplots(len(timeline_data), 1, figsize=(12, 2 * len(timeline_data)))
            if len(timeline_data) == 1:
                axes = [axes]
            
            colors = ['blue', 'red', 'green', 'orange', 'purple']
            
            for i, (gen_type, data) in enumerate(timeline_data.items()):
                ax = axes[i]
                
                # Plot intensity over time
                times = []
                intensities = []
                
                for segment in data:
                    times.extend([segment['start'], segment['end']])
                    intensities.extend([segment['intensity'], segment['intensity']])
                
                ax.plot(times, intensities, color=colors[i % len(colors)], linewidth=2, label=gen_type)
                ax.fill_between(times, intensities, alpha=0.3, color=colors[i % len(colors)])
                
                # Add step markers
                for step in self.current_scenario.steps:
                    step_time = sum(s.duration_minutes for s in self.current_scenario.steps[:self.current_scenario.steps.index(step)])
                    ax.axvline(x=step_time, color='gray', linestyle='--', alpha=0.5)
                    
                    # Add step labels
                    max_intensity = max(intensities) if intensities else 1.0
                    ax.text(step_time + step.duration_minutes/2, max_intensity * 0.9, 
                           step.step_name, rotation=45, ha='center', va='bottom', fontsize=8)
                
                ax.set_title(f'{gen_type.title()} Generator Load')
                ax.set_ylabel('Intensity Multiplier')
                ax.set_xlabel('Time (minutes)')
                ax.grid(True, alpha=0.3)
                ax.legend()
            
            plt.suptitle(f'Scenario Timeline: {self.current_scenario.scenario_name}', fontsize=14, fontweight='bold')
            plt.tight_layout()
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                logger.info(f"Timeline saved to {save_path}")
            else:
                plt.show()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create timeline preview: {e}")
            return False
    
    def validate_scenario(self) -> Dict[str, Any]:
        """Validate the current scenario"""
        if not self.current_scenario:
            return {"valid": False, "errors": ["No active scenario"]}
        
        errors = []
        warnings = []
        
        # Check basic scenario properties
        if not self.current_scenario.scenario_name:
            errors.append("Scenario name is required")
        
        if self.current_scenario.total_duration_minutes <= 0:
            errors.append("Scenario must have positive duration")
        elif self.current_scenario.total_duration_minutes > 1440:  # 24 hours
            warnings.append("Scenario duration is very long (>24 hours)")
        
        if not self.current_scenario.steps:
            errors.append("Scenario must have at least one step")
        
        # Check steps
        step_names = set()
        total_calculated_duration = 0
        
        for i, step in enumerate(self.current_scenario.steps):
            # Check for duplicate step names
            if step.step_name in step_names:
                warnings.append(f"Duplicate step name: {step.step_name}")
            step_names.add(step.step_name)
            
            # Check step duration
            if step.duration_minutes <= 0:
                errors.append(f"Step '{step.step_name}' has invalid duration")
            
            total_calculated_duration += step.duration_minutes
            
            # Check generators in step
            if not step.generators:
                warnings.append(f"Step '{step.step_name}' has no generators")
            
            enabled_generators = [g for g in step.generators if g.enabled]
            if not enabled_generators:
                warnings.append(f"Step '{step.step_name}' has no enabled generators")
            
            for generator in step.generators:
                if generator.intensity_multiplier < 0:
                    errors.append(f"Negative intensity in step '{step.step_name}' for {generator.generator_type}")
                elif generator.intensity_multiplier > 3.0:
                    warnings.append(f"Very high intensity in step '{step.step_name}' for {generator.generator_type}: {generator.intensity_multiplier}")
        
        # Check duration consistency
        if abs(total_calculated_duration - self.current_scenario.total_duration_minutes) > 1:
            errors.append("Total duration doesn't match sum of step durations")
        
        # Check for resource conflicts
        self._check_resource_conflicts(warnings)
        
        # Check safety settings
        self._validate_safety_settings(warnings, errors)
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "step_count": len(self.current_scenario.steps),
            "total_duration_minutes": self.current_scenario.total_duration_minutes,
            "unique_generator_types": len(set(
                gen.generator_type for step in self.current_scenario.steps 
                for gen in step.generators if gen.enabled
            ))
        }
    
    def _check_resource_conflicts(self, warnings: List[str]):
        """Check for potential resource conflicts between generators"""
        # Track peak resource usage across all steps
        peak_cpu_intensity = 0
        peak_memory_intensity = 0
        peak_io_intensity = 0
        peak_network_intensity = 0
        
        for step in self.current_scenario.steps:
            step_cpu = sum(g.intensity_multiplier for g in step.generators 
                          if g.enabled and g.generator_type == "cpu")
            step_memory = sum(g.intensity_multiplier for g in step.generators 
                            if g.enabled and g.generator_type == "memory")
            step_io = sum(g.intensity_multiplier for g in step.generators 
                         if g.enabled and g.generator_type == "io")
            step_network = sum(g.intensity_multiplier for g in step.generators 
                             if g.enabled and g.generator_type == "network")
            
            peak_cpu_intensity = max(peak_cpu_intensity, step_cpu)
            peak_memory_intensity = max(peak_memory_intensity, step_memory)
            peak_io_intensity = max(peak_io_intensity, step_io)
            peak_network_intensity = max(peak_network_intensity, step_network)
        
        # Warn about potential resource exhaustion
        if peak_cpu_intensity > 1.5:
            warnings.append(f"High CPU load detected (peak: {peak_cpu_intensity:.1f}x)")
        if peak_memory_intensity > 1.5:
            warnings.append(f"High memory load detected (peak: {peak_memory_intensity:.1f}x)")
        if peak_io_intensity > 1.5:
            warnings.append(f"High I/O load detected (peak: {peak_io_intensity:.1f}x)")
        if peak_network_intensity > 1.5:
            warnings.append(f"High network load detected (peak: {peak_network_intensity:.1f}x)")
    
    def _validate_safety_settings(self, warnings: List[str], errors: List[str]):
        """Validate safety settings"""
        if not self.current_scenario.global_settings:
            warnings.append("No global settings defined")
            return
        
        safety_settings = self.current_scenario.global_settings.get("safety", {})
        
        if not safety_settings.get("emergency_stop_conditions"):
            warnings.append("No emergency stop conditions defined")
        
        if not safety_settings.get("auto_rollback", False):
            warnings.append("Auto-rollback is disabled")
        
        max_duration = safety_settings.get("max_scenario_duration_hours", 24)
        if self.current_scenario.total_duration_minutes > max_duration * 60:
            errors.append(f"Scenario exceeds maximum allowed duration ({max_duration} hours)")
    
    def generate_execution_plan(self) -> Optional[Dict[str, Any]]:
        """Generate a detailed execution plan for the scenario"""
        if not self.current_scenario:
            logger.error("No active scenario")
            return None
        
        validation = self.validate_scenario()
        if not validation["valid"]:
            logger.error(f"Scenario validation failed: {validation['errors']}")
            return None
        
        try:
            execution_plan = {
                "scenario_info": {
                    "name": self.current_scenario.scenario_name,
                    "description": self.current_scenario.description,
                    "total_duration_minutes": self.current_scenario.total_duration_minutes,
                    "step_count": len(self.current_scenario.steps),
                    "created_at": self.current_scenario.metadata.get("created_at")
                },
                "execution_steps": [],
                "resource_requirements": self._calculate_resource_requirements(),
                "monitoring_plan": self._generate_monitoring_plan(),
                "safety_measures": self.current_scenario.global_settings.get("safety", {}),
                "validation_results": validation
            }
            
            # Generate detailed step execution plan
            current_time = 0
            for i, step in enumerate(self.current_scenario.steps):
                step_plan = {
                    "step_index": i,
                    "step_name": step.step_name,
                    "description": step.description,
                    "start_time_minutes": current_time,
                    "duration_minutes": step.duration_minutes,
                    "end_time_minutes": current_time + step.duration_minutes,
                    "generators": [],
                    "conditions": step.conditions or {},
                    "actions": step.actions or {}
                }
                
                # Add generator details
                for generator in step.generators:
                    if generator.enabled:
                        gen_plan = {
                            "type": generator.generator_type,
                            "intensity_multiplier": generator.intensity_multiplier,
                            "pattern": generator.pattern_name,
                            "priority": generator.priority,
                            "parameters": generator.custom_parameters or {},
                            "estimated_load": self._estimate_generator_load(generator)
                        }
                        step_plan["generators"].append(gen_plan)
                
                execution_plan["execution_steps"].append(step_plan)
                current_time += step.duration_minutes
            
            return execution_plan
            
        except Exception as e:
            logger.error(f"Failed to generate execution plan: {e}")
            return None
    
    def _calculate_resource_requirements(self) -> Dict[str, Any]:
        """Calculate estimated resource requirements"""
        requirements = {
            "cpu_cores": 0,
            "memory_gb": 0,
            "disk_space_gb": 0,
            "network_bandwidth_mbps": 0,
            "concurrent_connections": 0
        }
        
        for step in self.current_scenario.steps:
            for generator in step.generators:
                if not generator.enabled:
                    continue
                
                intensity = generator.intensity_multiplier
                params = generator.custom_parameters or {}
                
                if generator.generator_type == "cpu":
                    requirements["cpu_cores"] = max(
                        requirements["cpu_cores"],
                        params.get("threads", 4) * intensity
                    )
                elif generator.generator_type == "memory":
                    requirements["memory_gb"] = max(
                        requirements["memory_gb"],
                        (params.get("max_memory_mb", 1024) / 1024) * intensity
                    )
                elif generator.generator_type == "io":
                    requirements["disk_space_gb"] = max(
                        requirements["disk_space_gb"],
                        params.get("max_file_size_mb", 100) * params.get("concurrent_operations", 10) / 1024
                    )
                elif generator.generator_type == "network":
                    requirements["network_bandwidth_mbps"] = max(
                        requirements["network_bandwidth_mbps"],
                        params.get("request_rate_per_second", 100) * params.get("payload_size_kb", 1) * 8 / 1024 * intensity
                    )
                    requirements["concurrent_connections"] = max(
                        requirements["concurrent_connections"],
                        params.get("concurrent_connections", 50) * intensity
                    )
                elif generator.generator_type == "application":
                    requirements["concurrent_connections"] = max(
                        requirements["concurrent_connections"],
                        params.get("concurrent_users", 10) * intensity
                    )
        
        # Round up to reasonable values
        requirements["cpu_cores"] = max(1, int(requirements["cpu_cores"]))
        requirements["memory_gb"] = max(1, int(requirements["memory_gb"] + 0.5))
        requirements["disk_space_gb"] = max(1, int(requirements["disk_space_gb"] + 0.5))
        requirements["network_bandwidth_mbps"] = max(1, int(requirements["network_bandwidth_mbps"] + 0.5))
        requirements["concurrent_connections"] = max(1, int(requirements["concurrent_connections"]))
        
        return requirements
    
    def _generate_monitoring_plan(self) -> Dict[str, Any]:
        """Generate monitoring plan for the scenario"""
        monitoring_settings = self.current_scenario.global_settings.get("monitoring", {})
        
        return {
            "collection_interval_seconds": monitoring_settings.get("metrics_collection_interval", 5),
            "alert_thresholds": monitoring_settings.get("alert_thresholds", {}),
            "metrics_to_collect": [
                "cpu_usage",
                "memory_usage",
                "disk_io",
                "network_io",
                "response_times",
                "error_rates",
                "throughput",
                "active_connections"
            ],
            "dashboard_refresh_interval": 10,
            "log_retention_hours": 48,
            "performance_baselines": self._calculate_performance_baselines()
        }
    
    def _calculate_performance_baselines(self) -> Dict[str, float]:
        """Calculate expected performance baselines"""
        return {
            "max_cpu_usage": 85.0,
            "max_memory_usage": 80.0,
            "max_response_time_ms": 5000.0,
            "max_error_rate": 0.05,
            "min_throughput_rps": 10.0
        }
    
    def _estimate_generator_load(self, generator: GeneratorProfile) -> Dict[str, float]:
        """Estimate the load a generator will produce"""
        base_loads = {
            "cpu": {"cpu_percent": 25.0, "memory_mb": 100},
            "memory": {"memory_mb": 512, "cpu_percent": 5.0},
            "io": {"disk_iops": 1000, "cpu_percent": 10.0, "memory_mb": 50},
            "network": {"bandwidth_mbps": 10.0, "cpu_percent": 15.0, "memory_mb": 200},
            "application": {"cpu_percent": 20.0, "memory_mb": 300, "network_mbps": 5.0}
        }
        
        base_load = base_loads.get(generator.generator_type, {"cpu_percent": 10.0})
        intensity = generator.intensity_multiplier
        
        estimated_load = {}
        for metric, value in base_load.items():
            estimated_load[metric] = value * intensity
        
        return estimated_load
    
    def save_scenario(self, file_path: Optional[str] = None) -> bool:
        """Save the current scenario to a file"""
        if not self.current_scenario:
            logger.error("No active scenario to save")
            return False
        
        try:
            if file_path is None:
                file_path = f"scenarios/{self.current_scenario.scenario_name}.json"
            
            # Ensure directory exists
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Convert scenario to dictionary
            scenario_dict = {
                "scenario_name": self.current_scenario.scenario_name,
                "description": self.current_scenario.description,
                "total_duration_minutes": self.current_scenario.total_duration_minutes,
                "steps": [
                    {
                        "step_name": step.step_name,
                        "duration_minutes": step.duration_minutes,
                        "description": step.description,
                        "conditions": step.conditions,
                        "actions": step.actions,
                        "generators": [asdict(gen) for gen in step.generators]
                    }
                    for step in self.current_scenario.steps
                ],
                "global_settings": self.current_scenario.global_settings,
                "validation_rules": self.current_scenario.validation_rules,
                "metadata": self.current_scenario.metadata
            }
            
            with open(file_path, 'w') as f:
                json.dump(scenario_dict, f, indent=2, default=str)
            
            # Add to scenario library
            self.scenario_library[self.current_scenario.scenario_name] = self.current_scenario
            
            logger.info(f"Scenario saved to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save scenario: {e}")
            return False
    
    def load_scenario(self, file_path: str) -> bool:
        """Load a scenario from a file"""
        try:
            with open(file_path, 'r') as f:
                scenario_dict = json.load(f)
            
            # Reconstruct scenario object
            steps = []
            for step_data in scenario_dict["steps"]:
                generators = [
                    GeneratorProfile(**gen_data) 
                    for gen_data in step_data["generators"]
                ]
                
                step = ScenarioStep(
                    step_name=step_data["step_name"],
                    duration_minutes=step_data["duration_minutes"],
                    generators=generators,
                    description=step_data.get("description", ""),
                    conditions=step_data.get("conditions"),
                    actions=step_data.get("actions")
                )
                steps.append(step)
            
            self.current_scenario = CustomScenario(
                scenario_name=scenario_dict["scenario_name"],
                description=scenario_dict["description"],
                total_duration_minutes=scenario_dict["total_duration_minutes"],
                steps=steps,
                global_settings=scenario_dict.get("global_settings"),
                validation_rules=scenario_dict.get("validation_rules"),
                metadata=scenario_dict.get("metadata", {})
            )
            
            # Add to scenario library
            self.scenario_library[self.current_scenario.scenario_name] = self.current_scenario
            
            logger.info(f"Scenario loaded from {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load scenario: {e}")
            return False
    
    def list_scenarios(self) -> List[str]:
        """List all scenarios in the library"""
        return list(self.scenario_library.keys())
    
    def get_scenario_summary(self, scenario_name: str) -> Optional[Dict[str, Any]]:
        """Get a summary of a scenario"""
        scenario = self.scenario_library.get(scenario_name)
        if not scenario:
            return None
        
        return {
            "name": scenario.scenario_name,
            "description": scenario.description,
            "duration_minutes": scenario.total_duration_minutes,
            "step_count": len(scenario.steps),
            "generator_types": list(set(
                gen.generator_type for step in scenario.steps 
                for gen in step.generators if gen.enabled
            )),
            "created_at": scenario.metadata.get("created_at"),
            "has_conditions": any(step.conditions for step in scenario.steps),
            "has_actions": any(step.actions for step in scenario.steps)
        }


# Example usage and testing
def example_usage():
    """Example usage of CustomScenarioBuilder"""
    builder = CustomScenarioBuilder()
    
    # Start a new scenario
    builder.start_new_scenario(
        "e_commerce_black_friday",
        "Simulate Black Friday traffic for e-commerce platform"
    )
    
    # Add baseline step
    builder.add_step_from_profile("baseline", "baseline", 10, 1.0)
    
    # Add ramp-up step
    builder.add_ramp_up_step(
        "traffic_ramp_up",
        30,
        target_intensities={"cpu": 0.8, "memory": 0.7, "network": 1.2, "application": 1.0},
        start_intensities={"cpu": 0.2, "memory": 0.3, "network": 0.3, "application": 0.2}
    )
    
    # Add peak traffic step with spikes
    builder.add_spike_step(
        "peak_traffic_with_spikes",
        60,
        base_intensities={"cpu": 0.8, "memory": 0.8, "network": 1.5, "application": 1.3},
        spike_intensities={"cpu": 1.2, "memory": 1.1, "network": 2.0, "application": 1.8},
        spike_count=5,
        spike_duration_minutes=3
    )
    
    # Add sustained load step
    builder.add_step_from_profile("sustained_load", "production", 90, 1.1)
    
    # Add ramp-down step
    builder.add_custom_step(
        "traffic_ramp_down",
        20,
        [
            {
                "generator_type": "cpu",
                "intensity_multiplier": 0.3,
                "pattern_name": "ramp_down"
            },
            {
                "generator_type": "memory",
                "intensity_multiplier": 0.4,
                "pattern_name": "ramp_down"
            },
            {
                "generator_type": "network",
                "intensity_multiplier": 0.5,
                "pattern_name": "ramp_down"
            },
            {
                "generator_type": "application",
                "intensity_multiplier": 0.3,
                "pattern_name": "ramp_down"
            }
        ],
        "Gradual reduction of traffic load"
    )
    
    # Set global settings
    builder.set_global_settings({
        "coordination": {
            "adaptive_scaling": True,
            "circuit_breaker": True,
            "rate_limiting": True
        },
        "monitoring": {
            "alert_thresholds": {
                "cpu_max": 90.0,
                "memory_max": 85.0,
                "response_time_max": 8000,
                "error_rate_max": 0.15
            }
        }
    })
    
    # Validate scenario
    validation = builder.validate_scenario()
    print(f"Scenario validation: {validation}")
    
    # Generate execution plan
    execution_plan = builder.generate_execution_plan()
    if execution_plan:
        print(f"Execution plan generated with {len(execution_plan['execution_steps'])} steps")
    
    # Preview timeline (would show plot if matplotlib is available)
    try:
        builder.preview_scenario_timeline("scenario_timeline.png")
    except Exception as e:
        print(f"Timeline preview failed: {e}")
    
    # Save scenario
    builder.save_scenario("e_commerce_black_friday.json")
    
    print(f"Created scenario: {builder.current_scenario.scenario_name}")
    print(f"Total duration: {builder.current_scenario.total_duration_minutes} minutes")
    print(f"Steps: {len(builder.current_scenario.steps)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    example_usage()