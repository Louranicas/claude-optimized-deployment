#!/usr/bin/env python3
"""
Workload Profiles
================

Pre-defined workload profiles for various scenarios including development,
production, peak traffic, and specialized testing scenarios.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class ProfileType(Enum):
    """Available profile types"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    PEAK_TRAFFIC = "peak_traffic"
    STRESS_TEST = "stress_test"
    ENDURANCE = "endurance"
    SPIKE_TEST = "spike_test"
    BASELINE = "baseline"
    CUSTOM = "custom"

@dataclass
class GeneratorProfile:
    """Profile configuration for a specific generator"""
    generator_type: str
    enabled: bool = True
    intensity_multiplier: float = 1.0
    pattern_name: str = "steady_state"
    custom_parameters: Dict[str, Any] = None
    priority: int = 1

@dataclass
class WorkloadProfile:
    """Complete workload profile definition"""
    profile_name: str
    profile_type: ProfileType
    description: str
    duration_minutes: int
    generators: List[GeneratorProfile]
    coordination_rules: Dict[str, Any] = None
    performance_thresholds: Dict[str, float] = None
    metadata: Dict[str, Any] = None

class WorkloadProfileManager:
    """
    Workload Profile Manager
    
    Manages pre-defined and custom workload profiles for various testing scenarios.
    """
    
    def __init__(self):
        self.profiles: Dict[str, WorkloadProfile] = {}
        self._initialize_default_profiles()
    
    def _initialize_default_profiles(self):
        """Initialize default workload profiles"""
        # Development Environment Profile
        self.profiles["development"] = WorkloadProfile(
            profile_name="development",
            profile_type=ProfileType.DEVELOPMENT,
            description="Light load suitable for development environment testing",
            duration_minutes=30,
            generators=[
                GeneratorProfile(
                    generator_type="cpu",
                    intensity_multiplier=0.3,
                    pattern_name="steady_state",
                    custom_parameters={"threads": 2, "algorithm": "prime_calculation"}
                ),
                GeneratorProfile(
                    generator_type="memory",
                    intensity_multiplier=0.4,
                    pattern_name="gradual_increase",
                    custom_parameters={"max_memory_mb": 256, "allocation_pattern": "steady"}
                ),
                GeneratorProfile(
                    generator_type="network",
                    intensity_multiplier=0.2,
                    pattern_name="wave",
                    custom_parameters={"concurrent_connections": 10, "request_rate_per_second": 20}
                ),
                GeneratorProfile(
                    generator_type="application",
                    intensity_multiplier=0.5,
                    pattern_name="realistic",
                    custom_parameters={
                        "concurrent_users": 3,
                        "workload_types": ["circle_of_experts", "api_calls"],
                        "expert_query_complexity": "simple"
                    }
                )
            ],
            performance_thresholds={
                "cpu_max": 60.0,
                "memory_max": 50.0,
                "response_time_max": 2000,
                "error_rate_max": 0.01
            }
        )
        
        # Staging Environment Profile
        self.profiles["staging"] = WorkloadProfile(
            profile_name="staging",
            profile_type=ProfileType.STAGING,
            description="Moderate load for staging environment validation",
            duration_minutes=60,
            generators=[
                GeneratorProfile(
                    generator_type="cpu",
                    intensity_multiplier=0.6,
                    pattern_name="cyclic",
                    custom_parameters={"threads": 4, "algorithm": "matrix_multiplication"}
                ),
                GeneratorProfile(
                    generator_type="memory",
                    intensity_multiplier=0.7,
                    pattern_name="burst",
                    custom_parameters={"max_memory_mb": 512, "allocation_pattern": "fragmented"}
                ),
                GeneratorProfile(
                    generator_type="io",
                    intensity_multiplier=0.5,
                    pattern_name="mixed",
                    custom_parameters={"concurrent_operations": 8, "io_pattern": "database"}
                ),
                GeneratorProfile(
                    generator_type="network",
                    intensity_multiplier=0.6,
                    pattern_name="burst",
                    custom_parameters={"concurrent_connections": 25, "request_rate_per_second": 75}
                ),
                GeneratorProfile(
                    generator_type="application",
                    intensity_multiplier=0.7,
                    pattern_name="realistic",
                    custom_parameters={
                        "concurrent_users": 8,
                        "workload_types": ["circle_of_experts", "mcp_operations", "database_queries", "api_calls"],
                        "expert_query_complexity": "medium"
                    }
                )
            ],
            performance_thresholds={
                "cpu_max": 75.0,
                "memory_max": 70.0,
                "response_time_max": 3000,
                "error_rate_max": 0.02
            }
        )
        
        # Production Environment Profile
        self.profiles["production"] = WorkloadProfile(
            profile_name="production",
            profile_type=ProfileType.PRODUCTION,
            description="Production-like load patterns with realistic user behavior",
            duration_minutes=120,
            generators=[
                GeneratorProfile(
                    generator_type="cpu",
                    intensity_multiplier=0.8,
                    pattern_name="realistic",
                    custom_parameters={
                        "threads": 8,
                        "algorithm": "mixed",
                        "adaptive": True
                    }
                ),
                GeneratorProfile(
                    generator_type="memory",
                    intensity_multiplier=0.8,
                    pattern_name="realistic",
                    custom_parameters={
                        "max_memory_mb": 1024,
                        "allocation_pattern": "mixed",
                        "gc_pressure": True
                    }
                ),
                GeneratorProfile(
                    generator_type="io",
                    intensity_multiplier=0.7,
                    pattern_name="realistic",
                    custom_parameters={
                        "concurrent_operations": 15,
                        "io_pattern": "mixed",
                        "read_write_ratio": 0.7
                    }
                ),
                GeneratorProfile(
                    generator_type="network",
                    intensity_multiplier=0.8,
                    pattern_name="realistic",
                    custom_parameters={
                        "concurrent_connections": 50,
                        "request_rate_per_second": 150,
                        "geographic_distribution": True,
                        "websocket_enabled": True
                    }
                ),
                GeneratorProfile(
                    generator_type="application",
                    intensity_multiplier=0.8,
                    pattern_name="realistic",
                    custom_parameters={
                        "concurrent_users": 15,
                        "workload_types": ["circle_of_experts", "mcp_operations", "database_queries", "api_calls"],
                        "expert_query_complexity": "medium",
                        "business_logic_complexity": "realistic",
                        "cache_usage": True
                    }
                )
            ],
            coordination_rules={
                "load_balancing": True,
                "adaptive_scaling": True,
                "failure_handling": "graceful_degradation"
            },
            performance_thresholds={
                "cpu_max": 85.0,
                "memory_max": 80.0,
                "response_time_max": 5000,
                "error_rate_max": 0.05
            }
        )
        
        # Peak Traffic Profile
        self.profiles["peak_traffic"] = WorkloadProfile(
            profile_name="peak_traffic",
            profile_type=ProfileType.PEAK_TRAFFIC,
            description="High-traffic scenarios like Black Friday or product launches",
            duration_minutes=90,
            generators=[
                GeneratorProfile(
                    generator_type="cpu",
                    intensity_multiplier=1.2,
                    pattern_name="spike",
                    custom_parameters={
                        "threads": 12,
                        "algorithm": "mixed",
                        "spike_count": 8,
                        "spike_intensity": 0.95
                    }
                ),
                GeneratorProfile(
                    generator_type="memory",
                    intensity_multiplier=1.1,
                    pattern_name="burst",
                    custom_parameters={
                        "max_memory_mb": 2048,
                        "allocation_pattern": "burst",
                        "burst_count": 5
                    }
                ),
                GeneratorProfile(
                    generator_type="io",
                    intensity_multiplier=1.3,
                    pattern_name="spike",
                    custom_parameters={
                        "concurrent_operations": 25,
                        "io_pattern": "mixed",
                        "spike_duration": 60
                    }
                ),
                GeneratorProfile(
                    generator_type="network",
                    intensity_multiplier=1.5,
                    pattern_name="spike",
                    custom_parameters={
                        "concurrent_connections": 100,
                        "request_rate_per_second": 300,
                        "spike_intensity": 0.9,
                        "geographic_distribution": True
                    }
                ),
                GeneratorProfile(
                    generator_type="application",
                    intensity_multiplier=1.3,
                    pattern_name="spike",
                    custom_parameters={
                        "concurrent_users": 30,
                        "workload_types": ["circle_of_experts", "mcp_operations", "database_queries", "api_calls"],
                        "expert_query_complexity": "complex",
                        "user_session_duration": 600
                    }
                )
            ],
            coordination_rules={
                "circuit_breaker": True,
                "rate_limiting": True,
                "priority_queuing": True
            },
            performance_thresholds={
                "cpu_max": 95.0,
                "memory_max": 90.0,
                "response_time_max": 10000,
                "error_rate_max": 0.10
            }
        )
        
        # Stress Test Profile
        self.profiles["stress_test"] = WorkloadProfile(
            profile_name="stress_test",
            profile_type=ProfileType.STRESS_TEST,
            description="Stress testing to find system breaking points",
            duration_minutes=45,
            generators=[
                GeneratorProfile(
                    generator_type="cpu",
                    intensity_multiplier=1.5,
                    pattern_name="exponential",
                    custom_parameters={
                        "threads": 16,
                        "algorithm": "mixed",
                        "growth_rate": 0.02
                    }
                ),
                GeneratorProfile(
                    generator_type="memory",
                    intensity_multiplier=1.4,
                    pattern_name="exponential",
                    custom_parameters={
                        "max_memory_mb": 4096,
                        "allocation_pattern": "leak_simulation",
                        "leak_simulation": True
                    }
                ),
                GeneratorProfile(
                    generator_type="io",
                    intensity_multiplier=1.6,
                    pattern_name="exponential",
                    custom_parameters={
                        "concurrent_operations": 40,
                        "io_pattern": "random",
                        "max_file_size_mb": 500
                    }
                ),
                GeneratorProfile(
                    generator_type="network",
                    intensity_multiplier=2.0,
                    pattern_name="exponential",
                    custom_parameters={
                        "concurrent_connections": 200,
                        "request_rate_per_second": 500,
                        "payload_size_kb": 10
                    }
                ),
                GeneratorProfile(
                    generator_type="application",
                    intensity_multiplier=1.5,
                    pattern_name="exponential",
                    custom_parameters={
                        "concurrent_users": 50,
                        "expert_query_complexity": "complex",
                        "business_logic_complexity": "complex"
                    }
                )
            ],
            coordination_rules={
                "failure_injection": True,
                "resource_exhaustion": True,
                "cascading_failures": True
            },
            performance_thresholds={
                "cpu_max": 100.0,
                "memory_max": 95.0,
                "response_time_max": 30000,
                "error_rate_max": 0.50
            }
        )
        
        # Endurance Test Profile
        self.profiles["endurance"] = WorkloadProfile(
            profile_name="endurance",
            profile_type=ProfileType.ENDURANCE,
            description="Long-running test to detect memory leaks and performance degradation",
            duration_minutes=480,  # 8 hours
            generators=[
                GeneratorProfile(
                    generator_type="cpu",
                    intensity_multiplier=0.6,
                    pattern_name="cyclic",
                    custom_parameters={
                        "threads": 6,
                        "algorithm": "mixed",
                        "cycle_duration": 3600  # 1 hour cycles
                    }
                ),
                GeneratorProfile(
                    generator_type="memory",
                    intensity_multiplier=0.7,
                    pattern_name="cyclic",
                    custom_parameters={
                        "max_memory_mb": 1024,
                        "allocation_pattern": "mixed",
                        "gc_pressure": True,
                        "cycle_duration": 1800  # 30 minute cycles
                    }
                ),
                GeneratorProfile(
                    generator_type="io",
                    intensity_multiplier=0.5,
                    pattern_name="wave",
                    custom_parameters={
                        "concurrent_operations": 12,
                        "io_pattern": "mixed",
                        "frequency": 0.001  # Very low frequency for long waves
                    }
                ),
                GeneratorProfile(
                    generator_type="network",
                    intensity_multiplier=0.6,
                    pattern_name="wave",
                    custom_parameters={
                        "concurrent_connections": 40,
                        "request_rate_per_second": 100,
                        "frequency": 0.002
                    }
                ),
                GeneratorProfile(
                    generator_type="application",
                    intensity_multiplier=0.7,
                    pattern_name="cyclic",
                    custom_parameters={
                        "concurrent_users": 20,
                        "user_session_duration": 7200,  # 2 hour sessions
                        "cache_usage": True
                    }
                )
            ],
            coordination_rules={
                "memory_monitoring": True,
                "leak_detection": True,
                "performance_degradation_detection": True
            },
            performance_thresholds={
                "cpu_max": 80.0,
                "memory_max": 75.0,
                "response_time_max": 5000,
                "error_rate_max": 0.03,
                "memory_growth_rate_max": 0.1  # MB per hour
            }
        )
        
        # Baseline Performance Profile
        self.profiles["baseline"] = WorkloadProfile(
            profile_name="baseline",
            profile_type=ProfileType.BASELINE,
            description="Baseline performance measurement with minimal load",
            duration_minutes=20,
            generators=[
                GeneratorProfile(
                    generator_type="cpu",
                    intensity_multiplier=0.1,
                    pattern_name="steady_state",
                    custom_parameters={"threads": 1, "algorithm": "prime_calculation"}
                ),
                GeneratorProfile(
                    generator_type="memory",
                    intensity_multiplier=0.1,
                    pattern_name="steady_state",
                    custom_parameters={"max_memory_mb": 100, "allocation_pattern": "steady"}
                ),
                GeneratorProfile(
                    generator_type="io",
                    intensity_multiplier=0.1,
                    pattern_name="steady_state",
                    custom_parameters={"concurrent_operations": 2, "io_pattern": "sequential"}
                ),
                GeneratorProfile(
                    generator_type="network",
                    intensity_multiplier=0.1,
                    pattern_name="steady_state",
                    custom_parameters={"concurrent_connections": 5, "request_rate_per_second": 10}
                ),
                GeneratorProfile(
                    generator_type="application",
                    intensity_multiplier=0.2,
                    pattern_name="steady_state",
                    custom_parameters={
                        "concurrent_users": 2,
                        "workload_types": ["api_calls"],
                        "expert_query_complexity": "simple"
                    }
                )
            ],
            performance_thresholds={
                "cpu_max": 30.0,
                "memory_max": 25.0,
                "response_time_max": 1000,
                "error_rate_max": 0.001
            }
        )
        
        # Spike Test Profile
        self.profiles["spike_test"] = WorkloadProfile(
            profile_name="spike_test",
            profile_type=ProfileType.SPIKE_TEST,
            description="Test system response to sudden load spikes",
            duration_minutes=30,
            generators=[
                GeneratorProfile(
                    generator_type="cpu",
                    intensity_multiplier=0.8,
                    pattern_name="spike",
                    custom_parameters={
                        "threads": 8,
                        "spike_count": 3,
                        "spike_intensity": 0.95,
                        "spike_duration": 120
                    }
                ),
                GeneratorProfile(
                    generator_type="memory",
                    intensity_multiplier=0.7,
                    pattern_name="spike",
                    custom_parameters={
                        "max_memory_mb": 1024,
                        "spike_count": 3,
                        "spike_intensity": 0.9
                    }
                ),
                GeneratorProfile(
                    generator_type="network",
                    intensity_multiplier=1.0,
                    pattern_name="spike",
                    custom_parameters={
                        "concurrent_connections": 75,
                        "request_rate_per_second": 200,
                        "spike_count": 5,
                        "spike_duration": 60
                    }
                ),
                GeneratorProfile(
                    generator_type="application",
                    intensity_multiplier=0.9,
                    pattern_name="spike",
                    custom_parameters={
                        "concurrent_users": 25,
                        "spike_count": 3
                    }
                )
            ],
            coordination_rules={
                "spike_coordination": True,
                "recovery_monitoring": True
            },
            performance_thresholds={
                "cpu_max": 90.0,
                "memory_max": 85.0,
                "response_time_max": 8000,
                "error_rate_max": 0.15,
                "recovery_time_max": 300  # 5 minutes
            }
        )
        
        logger.info(f"Initialized {len(self.profiles)} default workload profiles")
    
    def get_profile(self, profile_name: str) -> Optional[WorkloadProfile]:
        """Get a workload profile by name"""
        return self.profiles.get(profile_name)
    
    def list_profiles(self) -> List[str]:
        """List all available profile names"""
        return list(self.profiles.keys())
    
    def list_profiles_by_type(self, profile_type: ProfileType) -> List[str]:
        """List profiles by type"""
        return [
            name for name, profile in self.profiles.items()
            if profile.profile_type == profile_type
        ]
    
    def create_custom_profile(self, profile: WorkloadProfile) -> bool:
        """Create a custom workload profile"""
        try:
            self.profiles[profile.profile_name] = profile
            logger.info(f"Created custom profile: {profile.profile_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create custom profile: {e}")
            return False
    
    def modify_profile(self, profile_name: str, modifications: Dict[str, Any]) -> bool:
        """Modify an existing profile"""
        if profile_name not in self.profiles:
            logger.error(f"Profile not found: {profile_name}")
            return False
        
        try:
            profile = self.profiles[profile_name]
            
            # Apply modifications
            for key, value in modifications.items():
                if hasattr(profile, key):
                    setattr(profile, key, value)
                elif key == "generator_modifications":
                    # Modify specific generators
                    self._modify_generators(profile, value)
                else:
                    logger.warning(f"Unknown profile attribute: {key}")
            
            logger.info(f"Modified profile: {profile_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to modify profile {profile_name}: {e}")
            return False
    
    def _modify_generators(self, profile: WorkloadProfile, generator_mods: Dict[str, Dict[str, Any]]):
        """Modify generators within a profile"""
        for gen_type, modifications in generator_mods.items():
            for generator in profile.generators:
                if generator.generator_type == gen_type:
                    for key, value in modifications.items():
                        if hasattr(generator, key):
                            setattr(generator, key, value)
                        elif key == "custom_parameters":
                            if generator.custom_parameters is None:
                                generator.custom_parameters = {}
                            generator.custom_parameters.update(value)
    
    def clone_profile(self, source_profile_name: str, new_profile_name: str) -> bool:
        """Clone an existing profile with a new name"""
        if source_profile_name not in self.profiles:
            logger.error(f"Source profile not found: {source_profile_name}")
            return False
        
        if new_profile_name in self.profiles:
            logger.error(f"Profile already exists: {new_profile_name}")
            return False
        
        try:
            source_profile = self.profiles[source_profile_name]
            
            # Deep copy the profile
            cloned_profile = WorkloadProfile(
                profile_name=new_profile_name,
                profile_type=ProfileType.CUSTOM,
                description=f"Cloned from {source_profile_name}: {source_profile.description}",
                duration_minutes=source_profile.duration_minutes,
                generators=[
                    GeneratorProfile(
                        generator_type=gen.generator_type,
                        enabled=gen.enabled,
                        intensity_multiplier=gen.intensity_multiplier,
                        pattern_name=gen.pattern_name,
                        custom_parameters=gen.custom_parameters.copy() if gen.custom_parameters else None,
                        priority=gen.priority
                    )
                    for gen in source_profile.generators
                ],
                coordination_rules=source_profile.coordination_rules.copy() if source_profile.coordination_rules else None,
                performance_thresholds=source_profile.performance_thresholds.copy() if source_profile.performance_thresholds else None,
                metadata=source_profile.metadata.copy() if source_profile.metadata else None
            )
            
            self.profiles[new_profile_name] = cloned_profile
            logger.info(f"Cloned profile {source_profile_name} to {new_profile_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clone profile: {e}")
            return False
    
    def delete_profile(self, profile_name: str) -> bool:
        """Delete a custom profile (cannot delete default profiles)"""
        if profile_name not in self.profiles:
            logger.error(f"Profile not found: {profile_name}")
            return False
        
        profile = self.profiles[profile_name]
        if profile.profile_type != ProfileType.CUSTOM:
            logger.error(f"Cannot delete default profile: {profile_name}")
            return False
        
        try:
            del self.profiles[profile_name]
            logger.info(f"Deleted custom profile: {profile_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete profile: {e}")
            return False
    
    def get_profile_summary(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Get a summary of a profile"""
        profile = self.get_profile(profile_name)
        if not profile:
            return None
        
        return {
            "name": profile.profile_name,
            "type": profile.profile_type.value,
            "description": profile.description,
            "duration_minutes": profile.duration_minutes,
            "generators": [
                {
                    "type": gen.generator_type,
                    "enabled": gen.enabled,
                    "intensity": gen.intensity_multiplier,
                    "pattern": gen.pattern_name
                }
                for gen in profile.generators
            ],
            "has_coordination_rules": profile.coordination_rules is not None,
            "has_performance_thresholds": profile.performance_thresholds is not None
        }
    
    def export_profile(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Export a profile to a dictionary"""
        profile = self.get_profile(profile_name)
        if not profile:
            return None
        
        return {
            "profile_name": profile.profile_name,
            "profile_type": profile.profile_type.value,
            "description": profile.description,
            "duration_minutes": profile.duration_minutes,
            "generators": [asdict(gen) for gen in profile.generators],
            "coordination_rules": profile.coordination_rules,
            "performance_thresholds": profile.performance_thresholds,
            "metadata": profile.metadata
        }
    
    def import_profile(self, profile_data: Dict[str, Any]) -> bool:
        """Import a profile from a dictionary"""
        try:
            generators = [
                GeneratorProfile(**gen_data) for gen_data in profile_data["generators"]
            ]
            
            profile = WorkloadProfile(
                profile_name=profile_data["profile_name"],
                profile_type=ProfileType(profile_data["profile_type"]),
                description=profile_data["description"],
                duration_minutes=profile_data["duration_minutes"],
                generators=generators,
                coordination_rules=profile_data.get("coordination_rules"),
                performance_thresholds=profile_data.get("performance_thresholds"),
                metadata=profile_data.get("metadata")
            )
            
            return self.create_custom_profile(profile)
            
        except Exception as e:
            logger.error(f"Failed to import profile: {e}")
            return False
    
    def validate_profile(self, profile_name: str) -> Dict[str, Any]:
        """Validate a profile configuration"""
        profile = self.get_profile(profile_name)
        if not profile:
            return {"valid": False, "errors": ["Profile not found"]}
        
        errors = []
        warnings = []
        
        # Check duration
        if profile.duration_minutes <= 0:
            errors.append("Duration must be positive")
        elif profile.duration_minutes > 1440:  # 24 hours
            warnings.append("Duration is very long (>24 hours)")
        
        # Check generators
        if not profile.generators:
            errors.append("No generators defined")
        
        generator_types = set()
        for generator in profile.generators:
            if generator.generator_type in generator_types:
                warnings.append(f"Duplicate generator type: {generator.generator_type}")
            generator_types.add(generator.generator_type)
            
            if generator.intensity_multiplier < 0:
                errors.append(f"Negative intensity multiplier for {generator.generator_type}")
            elif generator.intensity_multiplier > 2.0:
                warnings.append(f"Very high intensity multiplier for {generator.generator_type}: {generator.intensity_multiplier}")
        
        # Check thresholds
        if profile.performance_thresholds:
            for threshold, value in profile.performance_thresholds.items():
                if value < 0:
                    errors.append(f"Negative threshold value for {threshold}")
                elif threshold.endswith("_max") and value > 100 and not threshold.endswith("_time_max"):
                    warnings.append(f"Very high threshold for {threshold}: {value}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "generator_count": len(profile.generators),
            "enabled_generators": len([g for g in profile.generators if g.enabled])
        }
    
    def get_recommended_profiles_for_scenario(self, scenario: str) -> List[str]:
        """Get recommended profiles for a specific scenario"""
        scenario_mappings = {
            "development": ["development", "baseline"],
            "testing": ["staging", "stress_test", "spike_test"],
            "production_validation": ["production", "endurance"],
            "performance_testing": ["stress_test", "peak_traffic", "endurance"],
            "capacity_planning": ["production", "peak_traffic", "stress_test"],
            "regression_testing": ["baseline", "staging", "production"],
            "load_testing": ["production", "peak_traffic"],
            "reliability_testing": ["endurance", "stress_test", "spike_test"]
        }
        
        return scenario_mappings.get(scenario.lower(), [])


# Example usage and testing
def example_usage():
    """Example usage of WorkloadProfileManager"""
    manager = WorkloadProfileManager()
    
    # List all profiles
    print("Available profiles:")
    for profile_name in manager.list_profiles():
        summary = manager.get_profile_summary(profile_name)
        print(f"  {profile_name}: {summary['description']}")
    
    # Get a specific profile
    prod_profile = manager.get_profile("production")
    print(f"\nProduction profile duration: {prod_profile.duration_minutes} minutes")
    
    # Validate a profile
    validation = manager.validate_profile("stress_test")
    print(f"\nStress test profile validation: {validation}")
    
    # Get recommendations
    recommendations = manager.get_recommended_profiles_for_scenario("performance_testing")
    print(f"\nRecommended profiles for performance testing: {recommendations}")
    
    # Clone and modify a profile
    manager.clone_profile("production", "custom_production")
    manager.modify_profile("custom_production", {
        "duration_minutes": 180,
        "generator_modifications": {
            "cpu": {"intensity_multiplier": 0.9},
            "network": {"custom_parameters": {"request_rate_per_second": 200}}
        }
    })
    
    print(f"\nCreated custom profile: {manager.get_profile_summary('custom_production')}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    example_usage()