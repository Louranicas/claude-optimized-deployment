#!/usr/bin/env python3
"""
Advanced Load Generation Demo
============================

Comprehensive demonstration of the advanced load generation framework
with all generators, patterns, profiles, and coordination features.
"""

import asyncio
import logging
import json
import time
from pathlib import Path

from load_orchestrator import LoadOrchestrator, LoadConfiguration, LoadGeneratorType
from patterns.pattern_engine import PatternEngine, PatternType
from profiles.workload_profiles import WorkloadProfileManager, ProfileType
from custom_scenario_builder import CustomScenarioBuilder
from coordination.coordination_engine import CoordinationEngine, CoordinationMode

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class LoadGenerationDemo:
    """
    Comprehensive demonstration of advanced load generation capabilities
    """
    
    def __init__(self):
        self.orchestrator = None
        self.pattern_engine = PatternEngine()
        self.profile_manager = WorkloadProfileManager()
        self.scenario_builder = CustomScenarioBuilder()
        self.coordination_engine = None
        
        # Demo results
        self.demo_results = {}
    
    async def run_complete_demo(self):
        """Run complete demonstration of all features"""
        logger.info("Starting Advanced Load Generation Demo")
        
        try:
            # Demo 1: Basic Pattern Generation
            await self.demo_pattern_generation()
            
            # Demo 2: Profile Management
            await self.demo_profile_management()
            
            # Demo 3: Custom Scenario Building
            await self.demo_custom_scenarios()
            
            # Demo 4: Individual Generator Testing
            await self.demo_individual_generators()
            
            # Demo 5: Orchestrated Load Testing
            await self.demo_orchestrated_load_testing()
            
            # Demo 6: Coordination Engine
            await self.demo_coordination_engine()
            
            # Demo 7: Realistic Workload Simulation
            await self.demo_realistic_workloads()
            
            # Generate demo report
            self.generate_demo_report()
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            raise
        finally:
            await self.cleanup()
    
    async def demo_pattern_generation(self):
        """Demonstrate pattern generation capabilities"""
        logger.info("\n=== DEMO 1: Pattern Generation ===")
        
        demo_patterns = [
            ("steady_state", 60, 0.5),
            ("ramp_up", 120, 0.8),
            ("spike", 90, 0.7),
            ("realistic", 180, 0.6),
            ("wave", 150, 0.4),
            ("burst", 100, 0.9)
        ]
        
        pattern_results = {}
        
        for pattern_name, duration, intensity in demo_patterns:
            logger.info(f"Generating pattern: {pattern_name}")
            
            try:
                pattern = self.pattern_engine.generate_pattern(
                    pattern_name, duration, intensity
                )
                
                pattern_results[pattern_name] = {
                    'duration': duration,
                    'intensity': intensity,
                    'points_count': len(pattern.points),
                    'pattern_type': pattern.pattern_type.value,
                    'metadata': pattern.metadata
                }
                
                logger.info(f"  Generated {len(pattern.points)} points for {pattern_name}")
                
            except Exception as e:
                logger.error(f"Failed to generate pattern {pattern_name}: {e}")
        
        self.demo_results['pattern_generation'] = pattern_results
        logger.info(f"Pattern generation demo completed: {len(pattern_results)} patterns generated")
    
    async def demo_profile_management(self):
        """Demonstrate profile management capabilities"""
        logger.info("\n=== DEMO 2: Profile Management ===")
        
        # List available profiles
        profiles = self.profile_manager.list_profiles()
        logger.info(f"Available profiles: {profiles}")
        
        # Test different profile types
        profile_results = {}
        
        test_profiles = ["development", "staging", "production", "peak_traffic", "stress_test"]
        
        for profile_name in test_profiles:
            if profile_name in profiles:
                profile = self.profile_manager.get_profile(profile_name)
                summary = self.profile_manager.get_profile_summary(profile_name)
                validation = self.profile_manager.validate_profile(profile_name)
                
                profile_results[profile_name] = {
                    'summary': summary,
                    'validation': validation,
                    'duration': profile.duration_minutes,
                    'generator_count': len(profile.generators)
                }
                
                logger.info(f"  Profile {profile_name}: {len(profile.generators)} generators, {profile.duration_minutes}min")
        
        # Create and test custom profile
        custom_profile_success = self.profile_manager.clone_profile("production", "custom_demo")
        if custom_profile_success:
            logger.info("Created custom demo profile")
            profile_results['custom_demo'] = self.profile_manager.get_profile_summary("custom_demo")
        
        self.demo_results['profile_management'] = profile_results
        logger.info(f"Profile management demo completed: {len(profile_results)} profiles tested")
    
    async def demo_custom_scenarios(self):
        """Demonstrate custom scenario building"""
        logger.info("\n=== DEMO 3: Custom Scenario Building ===")
        
        # Start new scenario
        scenario_success = self.scenario_builder.start_new_scenario(
            "demo_scenario",
            "Demonstration scenario with multiple phases"
        )
        
        if not scenario_success:
            logger.error("Failed to start demo scenario")
            return
        
        scenario_results = {}
        
        # Add various steps
        steps_added = 0
        
        # Baseline step
        if self.scenario_builder.add_step_from_profile("baseline", "baseline", 5, 1.0):
            steps_added += 1
            logger.info("  Added baseline step")
        
        # Ramp-up step
        if self.scenario_builder.add_ramp_up_step(
            "ramp_up", 10,
            target_intensities={"cpu": 0.6, "memory": 0.5, "network": 0.7}
        ):
            steps_added += 1
            logger.info("  Added ramp-up step")
        
        # Spike test step
        if self.scenario_builder.add_spike_step(
            "spike_test", 8,
            base_intensities={"cpu": 0.6, "memory": 0.5},
            spike_intensities={"cpu": 0.9, "memory": 0.8},
            spike_count=2
        ):
            steps_added += 1
            logger.info("  Added spike test step")
        
        # Validation and execution plan
        validation = self.scenario_builder.validate_scenario()
        execution_plan = self.scenario_builder.generate_execution_plan()
        
        scenario_results = {
            'steps_added': steps_added,
            'validation': validation,
            'execution_plan_generated': execution_plan is not None,
            'total_duration': self.scenario_builder.current_scenario.total_duration_minutes if self.scenario_builder.current_scenario else 0
        }
        
        # Save scenario
        save_success = self.scenario_builder.save_scenario("demo_scenario.json")
        scenario_results['save_success'] = save_success
        
        self.demo_results['custom_scenarios'] = scenario_results
        logger.info(f"Custom scenario demo completed: {steps_added} steps, validation: {validation['valid']}")
    
    async def demo_individual_generators(self):
        """Demonstrate individual generator capabilities"""
        logger.info("\n=== DEMO 4: Individual Generators ===")
        
        generator_results = {}
        
        # Test CPU Generator
        try:
            from generators.cpu_load_generator import CPULoadGenerator, CPULoadConfiguration
            
            cpu_config = CPULoadConfiguration(
                threads=2,
                algorithm="prime_calculation",
                duration=10,
                adaptive=True
            )
            
            cpu_gen = CPULoadGenerator(cpu_config)
            pattern = self.pattern_engine.generate_pattern("steady_state", 10, 0.3)
            
            start_time = time.time()
            await cpu_gen.execute_pattern(pattern)
            execution_time = time.time() - start_time
            
            status = cpu_gen.get_status()
            generator_results['cpu'] = {
                'execution_time': execution_time,
                'status': status,
                'success': True
            }
            
            logger.info(f"  CPU Generator: {execution_time:.1f}s execution")
            
        except Exception as e:
            logger.error(f"CPU Generator demo failed: {e}")
            generator_results['cpu'] = {'success': False, 'error': str(e)}
        
        # Test Memory Generator
        try:
            from generators.memory_load_generator import MemoryLoadGenerator, MemoryLoadConfiguration
            
            memory_config = MemoryLoadConfiguration(
                max_memory_mb=256,
                allocation_pattern="steady",
                gc_pressure=True
            )
            
            memory_gen = MemoryLoadGenerator(memory_config)
            pattern = self.pattern_engine.generate_pattern("gradual_increase", 15, 0.4)
            
            start_time = time.time()
            await memory_gen.execute_pattern(pattern)
            execution_time = time.time() - start_time
            
            status = memory_gen.get_status()
            stats = memory_gen.get_memory_statistics()
            
            generator_results['memory'] = {
                'execution_time': execution_time,
                'status': status,
                'statistics': stats,
                'success': True
            }
            
            logger.info(f"  Memory Generator: {execution_time:.1f}s execution")
            
        except Exception as e:
            logger.error(f"Memory Generator demo failed: {e}")
            generator_results['memory'] = {'success': False, 'error': str(e)}
        
        # Test Network Generator (simplified)
        try:
            from generators.network_load_generator import NetworkLoadGenerator, NetworkLoadConfiguration
            
            network_config = NetworkLoadConfiguration(
                concurrent_connections=5,
                request_rate_per_second=10,
                target_urls=["http://httpbin.org/get"]
            )
            
            network_gen = NetworkLoadGenerator(network_config)
            pattern = self.pattern_engine.generate_pattern("wave", 20, 0.5)
            
            start_time = time.time()
            await network_gen.execute_pattern(pattern)
            execution_time = time.time() - start_time
            
            status = network_gen.get_status()
            stats = network_gen.get_network_statistics()
            
            generator_results['network'] = {
                'execution_time': execution_time,
                'status': status,
                'statistics': stats,
                'success': True
            }
            
            logger.info(f"  Network Generator: {execution_time:.1f}s execution")
            
        except Exception as e:
            logger.error(f"Network Generator demo failed: {e}")
            generator_results['network'] = {'success': False, 'error': str(e)}
        
        self.demo_results['individual_generators'] = generator_results
        successful_generators = sum(1 for result in generator_results.values() if result.get('success', False))
        logger.info(f"Individual generators demo completed: {successful_generators}/{len(generator_results)} successful")
    
    async def demo_orchestrated_load_testing(self):
        """Demonstrate orchestrated load testing"""
        logger.info("\n=== DEMO 5: Orchestrated Load Testing ===")
        
        try:
            # Initialize orchestrator
            self.orchestrator = LoadOrchestrator()
            
            # Add load configurations
            configurations = [
                LoadConfiguration(
                    generator_type=LoadGeneratorType.CPU,
                    pattern_name="steady_state",
                    intensity=0.4,
                    duration=30,
                    parameters={'threads': 2, 'algorithm': 'prime_calculation'}
                ),
                LoadConfiguration(
                    generator_type=LoadGeneratorType.MEMORY,
                    pattern_name="gradual_increase",
                    intensity=0.5,
                    duration=30,
                    parameters={'max_memory_mb': 256}
                ),
                LoadConfiguration(
                    generator_type=LoadGeneratorType.NETWORK,
                    pattern_name="wave",
                    intensity=0.3,
                    duration=30,
                    parameters={'concurrent_connections': 5}
                )
            ]
            
            for config in configurations:
                self.orchestrator.add_load_configuration(config)
            
            # Execute orchestrated test
            start_time = time.time()
            await self.orchestrator.start_load_generation("demo_orchestrated")
            execution_time = time.time() - start_time
            
            # Get results
            generator_status = self.orchestrator.get_generator_status()
            system_metrics = self.orchestrator.get_system_metrics_summary()
            
            orchestration_results = {
                'execution_time': execution_time,
                'configurations_count': len(configurations),
                'generator_status': [asdict(status) for status in generator_status],
                'system_metrics': system_metrics,
                'success': True
            }
            
            # Export metrics
            self.orchestrator.export_metrics("demo_orchestration_metrics.json")
            
            logger.info(f"  Orchestrated test: {execution_time:.1f}s, {len(configurations)} generators")
            
        except Exception as e:
            logger.error(f"Orchestrated load testing demo failed: {e}")
            orchestration_results = {'success': False, 'error': str(e)}
        
        self.demo_results['orchestrated_load_testing'] = orchestration_results
    
    async def demo_coordination_engine(self):
        """Demonstrate coordination engine capabilities"""
        logger.info("\n=== DEMO 6: Coordination Engine ===")
        
        try:
            # Initialize coordination engine
            self.coordination_engine = CoordinationEngine(CoordinationMode.ADAPTIVE)
            
            # Register mock generators
            generators = ["cpu_gen", "memory_gen", "network_gen"]
            for gen_id in generators:
                self.coordination_engine.register_generator(gen_id, gen_id.split('_')[0])
            
            # Add custom coordination rule
            from coordination.coordination_engine import CoordinationRule
            
            custom_rule = CoordinationRule(
                rule_id="demo_rule",
                name="Demo Load Limit",
                condition="sum(gen.current_load for gen in generators.values()) > 1.5",
                action="reduce_all_generators(0.8)",
                priority=750
            )
            
            self.coordination_engine.add_coordination_rule(custom_rule)
            
            # Simulate system state updates
            for i in range(5):
                system_metrics = {
                    'cpu_usage': 50 + i * 10,
                    'memory_usage': 40 + i * 8,
                    'response_times': [1000 + i * 200],
                    'error_rates': {'total': 0.01 + i * 0.01}
                }
                
                self.coordination_engine.update_system_state(system_metrics)
                
                # Update generator status
                for gen_id in generators:
                    self.coordination_engine.update_generator_status(gen_id, {
                        'status': 'running',
                        'current_load': 0.3 + i * 0.1,
                        'target_load': 0.5,
                        'performance_metrics': {'rps': 100 - i * 10}
                    })
                
                await asyncio.sleep(1)
            
            # Get coordination status
            coordination_status = self.coordination_engine.get_coordination_status()
            coordination_history = self.coordination_engine.get_coordination_history()
            
            coordination_results = {
                'generators_registered': len(generators),
                'rules_added': 1,
                'status': coordination_status,
                'history_length': len(coordination_history),
                'success': True
            }
            
            logger.info(f"  Coordination: {len(generators)} generators, {len(coordination_history)} decisions")
            
        except Exception as e:
            logger.error(f"Coordination engine demo failed: {e}")
            coordination_results = {'success': False, 'error': str(e)}
        
        self.demo_results['coordination_engine'] = coordination_results
    
    async def demo_realistic_workloads(self):
        """Demonstrate realistic workload patterns"""
        logger.info("\n=== DEMO 7: Realistic Workloads ===")
        
        realistic_results = {}
        
        # Test different realistic scenarios
        scenarios = [
            ("web_traffic", "Web application traffic pattern"),
            ("api_service", "API service usage pattern"),
            ("batch_processing", "Batch processing workload"),
            ("gaming", "Gaming platform load pattern")
        ]
        
        for scenario_name, description in scenarios:
            try:
                logger.info(f"  Testing scenario: {scenario_name}")
                
                # Generate realistic pattern
                pattern = self.pattern_engine.generate_pattern(
                    "realistic", 60, 0.6, 
                    {"profile": scenario_name, "geography": "global"}
                )
                
                realistic_results[scenario_name] = {
                    'description': description,
                    'points_generated': len(pattern.points),
                    'duration': pattern.duration,
                    'metadata': pattern.metadata,
                    'success': True
                }
                
            except Exception as e:
                logger.error(f"Realistic scenario {scenario_name} failed: {e}")
                realistic_results[scenario_name] = {'success': False, 'error': str(e)}
        
        # Test profile-based realistic loads
        try:
            profile = self.profile_manager.get_profile("production")
            if profile:
                realistic_results['production_profile'] = {
                    'generators': len(profile.generators),
                    'duration': profile.duration_minutes,
                    'description': profile.description,
                    'success': True
                }
        except Exception as e:
            realistic_results['production_profile'] = {'success': False, 'error': str(e)}
        
        self.demo_results['realistic_workloads'] = realistic_results
        successful_scenarios = sum(1 for result in realistic_results.values() if result.get('success', False))
        logger.info(f"Realistic workloads demo completed: {successful_scenarios}/{len(realistic_results)} successful")
    
    def generate_demo_report(self):
        """Generate comprehensive demo report"""
        logger.info("\n=== GENERATING DEMO REPORT ===")
        
        # Create report directory
        report_dir = Path("demo_reports")
        report_dir.mkdir(exist_ok=True)
        
        # Generate detailed report
        report = {
            'demo_info': {
                'timestamp': time.time(),
                'duration': time.time(),  # Will be updated
                'framework_version': "1.0.0"
            },
            'demo_results': self.demo_results,
            'summary': self._generate_summary()
        }
        
        # Save report
        report_file = report_dir / f"load_generation_demo_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Generate markdown summary
        self._generate_markdown_report(report_dir)
        
        logger.info(f"Demo report saved to {report_file}")
        
        # Print summary
        summary = report['summary']
        logger.info(f"\nDEMO SUMMARY:")
        logger.info(f"  Total demos: {summary['total_demos']}")
        logger.info(f"  Successful demos: {summary['successful_demos']}")
        logger.info(f"  Success rate: {summary['success_rate']:.1%}")
        logger.info(f"  Features tested: {summary['features_tested']}")
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate demo summary statistics"""
        total_demos = len(self.demo_results)
        successful_demos = 0
        features_tested = []
        
        for demo_name, results in self.demo_results.items():
            if isinstance(results, dict):
                if results.get('success', True):  # Assume success if not explicitly marked as failed
                    successful_demos += 1
                
                # Count sub-features
                if isinstance(results, dict):
                    for key, value in results.items():
                        if isinstance(value, dict) and value.get('success', True):
                            features_tested.append(f"{demo_name}.{key}")
        
        return {
            'total_demos': total_demos,
            'successful_demos': successful_demos,
            'success_rate': successful_demos / max(1, total_demos),
            'features_tested': len(features_tested),
            'feature_details': features_tested
        }
    
    def _generate_markdown_report(self, report_dir: Path):
        """Generate markdown report"""
        markdown_content = f"""# Advanced Load Generation Demo Report

Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

This report demonstrates the comprehensive capabilities of the Advanced Load Generation Framework.

"""
        
        # Add summary for each demo
        for demo_name, results in self.demo_results.items():
            markdown_content += f"### {demo_name.replace('_', ' ').title()}\n\n"
            
            if isinstance(results, dict):
                success_indicators = [k for k, v in results.items() 
                                    if isinstance(v, dict) and v.get('success', True)]
                markdown_content += f"- Features tested: {len(success_indicators)}\n"
                markdown_content += f"- Status: {'✅ Success' if success_indicators else '❌ Failed'}\n\n"
        
        # Save markdown report
        markdown_file = report_dir / f"demo_summary_{int(time.time())}.md"
        with open(markdown_file, 'w') as f:
            f.write(markdown_content)
    
    async def cleanup(self):
        """Cleanup demo resources"""
        logger.info("Cleaning up demo resources...")
        
        if self.orchestrator:
            try:
                await self.orchestrator.stop()
            except:
                pass
        
        if self.coordination_engine:
            try:
                await self.coordination_engine.stop_coordination()
            except:
                pass


async def main():
    """Main demo execution"""
    demo = LoadGenerationDemo()
    
    try:
        await demo.run_complete_demo()
        logger.info("✅ Advanced Load Generation Demo completed successfully!")
        
    except KeyboardInterrupt:
        logger.info("Demo interrupted by user")
    except Exception as e:
        logger.error(f"❌ Demo failed: {e}")
        raise
    finally:
        await demo.cleanup()


if __name__ == "__main__":
    asyncio.run(main())