"""
Chaos Engineering Engine

Central orchestration engine for managing chaos experiments across the system.
"""

import asyncio
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
import logging

from .chaos_experiment import ChaosExperiment, ExperimentConfig, ExperimentResult, ExperimentState
from .chaos_metrics import ChaosMetrics, MetricType
from ..monitoring.chaos_monitor import ChaosMonitor
from ..reporting.chaos_reporter import ChaosReporter

logger = logging.getLogger(__name__)


class ChaosEngine:
    """
    Central engine for orchestrating chaos engineering experiments.
    """
    
    def __init__(self, 
                 config_dir: str = "/tmp/chaos_config",
                 results_dir: str = "/tmp/chaos_results",
                 enable_monitoring: bool = True):
        self.config_dir = Path(config_dir)
        self.results_dir = Path(results_dir)
        self.enable_monitoring = enable_monitoring
        
        # Create directories
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.metrics = ChaosMetrics()
        self.monitor = ChaosMonitor() if enable_monitoring else None
        self.reporter = ChaosReporter(self.results_dir)
        
        # State management
        self.running_experiments: Dict[str, ChaosExperiment] = {}
        self.completed_experiments: Dict[str, ExperimentResult] = {}
        self.scheduled_experiments: List[Dict[str, Any]] = []
        
        # Load previous results
        self._load_previous_results()
    
    def _load_previous_results(self):
        """Load previous experiment results from disk."""
        try:
            results_file = self.results_dir / "experiment_history.json"
            if results_file.exists():
                with open(results_file, 'r') as f:
                    data = json.load(f)
                    # Convert to ExperimentResult objects
                    for exp_data in data:
                        # Simplified loading - in production would need proper deserialization
                        self.completed_experiments[exp_data['experiment_id']] = exp_data
        except Exception as e:
            logger.warning(f"Could not load previous results: {e}")
    
    def _save_results(self):
        """Save experiment results to disk."""
        try:
            results_file = self.results_dir / "experiment_history.json"
            # Convert results to serializable format
            serializable_results = []
            for result in self.completed_experiments.values():
                if hasattr(result, '__dict__'):
                    # Convert dataclass to dict
                    serializable_results.append(self._serialize_result(result))
                else:
                    serializable_results.append(result)
            
            with open(results_file, 'w') as f:
                json.dump(serializable_results, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Could not save results: {e}")
    
    def _serialize_result(self, result: ExperimentResult) -> Dict[str, Any]:
        """Convert ExperimentResult to serializable dictionary."""
        return {
            'experiment_id': result.experiment_id,
            'name': result.name,
            'state': result.state.value if hasattr(result.state, 'value') else str(result.state),
            'start_time': result.start_time.isoformat(),
            'end_time': result.end_time.isoformat() if result.end_time else None,
            'duration': str(result.duration) if result.duration else None,
            'overall_success': result.overall_success,
            'system_resilience_score': result.system_resilience_score,
            'recovery_score': result.recovery_score,
            'scenario_count': len(result.scenario_results),
            'observations': result.observations,
            'recommendations': result.recommendations,
            'metrics_summary': result.metrics_summary
        }
    
    async def create_experiment(self, config: ExperimentConfig) -> str:
        """
        Create a new chaos experiment.
        
        Args:
            config: Experiment configuration
            
        Returns:
            str: Experiment ID
        """
        experiment = ChaosExperiment(config)
        
        # Validate experiment
        if not await experiment.validate_experiment():
            raise ValueError(f"Experiment validation failed: {config.name}")
        
        # Store experiment
        self.running_experiments[experiment.experiment_id] = experiment
        
        # Record metrics
        self.metrics.record(
            MetricType.EXPERIMENT_CREATED,
            experiment.experiment_id,
            {'name': config.name, 'scenario_count': len(config.scenarios)}
        )
        
        logger.info(f"Created experiment: {experiment.experiment_id}")
        return experiment.experiment_id
    
    async def run_experiment(self, experiment_id: str) -> ExperimentResult:
        """
        Run a chaos experiment.
        
        Args:
            experiment_id: ID of the experiment to run
            
        Returns:
            ExperimentResult: Result of the experiment
        """
        if experiment_id not in self.running_experiments:
            raise ValueError(f"Experiment not found: {experiment_id}")
        
        experiment = self.running_experiments[experiment_id]
        
        try:
            # Start monitoring if enabled
            if self.monitor:
                await self.monitor.start_monitoring(experiment_id)
            
            # Record start metrics
            self.metrics.record(
                MetricType.EXPERIMENT_STARTED,
                experiment_id,
                {'start_time': datetime.now().isoformat()}
            )
            
            # Run the experiment
            result = await experiment.run()
            
            # Record completion metrics
            self.metrics.record(
                MetricType.EXPERIMENT_COMPLETED,
                experiment_id,
                {
                    'success': result.overall_success,
                    'resilience_score': result.system_resilience_score,
                    'duration': str(result.duration)
                }
            )
            
            # Move to completed experiments
            self.completed_experiments[experiment_id] = result
            del self.running_experiments[experiment_id]
            
            # Generate report
            if self.reporter:
                await self.reporter.generate_experiment_report(result)
            
            # Save results
            self._save_results()
            
            return result
            
        except Exception as e:
            logger.error(f"Experiment execution failed: {e}")
            self.metrics.record(
                MetricType.EXPERIMENT_FAILED,
                experiment_id,
                {'error': str(e)}
            )
            raise
        
        finally:
            # Stop monitoring
            if self.monitor:
                await self.monitor.stop_monitoring(experiment_id)
    
    async def schedule_experiment(self, 
                                config: ExperimentConfig,
                                schedule_time: datetime,
                                repeat_interval: Optional[timedelta] = None) -> str:
        """
        Schedule an experiment to run at a specific time.
        
        Args:
            config: Experiment configuration
            schedule_time: When to run the experiment
            repeat_interval: Optional repeat interval for recurring experiments
            
        Returns:
            str: Schedule ID
        """
        schedule_id = f"schedule_{int(datetime.now().timestamp())}"
        
        schedule_entry = {
            'schedule_id': schedule_id,
            'config': config,
            'schedule_time': schedule_time,
            'repeat_interval': repeat_interval,
            'created_at': datetime.now(),
            'active': True
        }
        
        self.scheduled_experiments.append(schedule_entry)
        
        # Start scheduler if not running
        asyncio.create_task(self._run_scheduler())
        
        logger.info(f"Scheduled experiment: {schedule_id} for {schedule_time}")
        return schedule_id
    
    async def _run_scheduler(self):
        """Run the experiment scheduler."""
        while True:
            try:
                current_time = datetime.now()
                
                for schedule in self.scheduled_experiments[:]:  # Copy list for safe iteration
                    if not schedule['active']:
                        continue
                    
                    if current_time >= schedule['schedule_time']:
                        # Time to run the experiment
                        try:
                            experiment_id = await self.create_experiment(schedule['config'])
                            await self.run_experiment(experiment_id)
                            
                            # Handle repeat interval
                            if schedule['repeat_interval']:
                                schedule['schedule_time'] += schedule['repeat_interval']
                                logger.info(f"Rescheduled recurring experiment: {schedule['schedule_id']}")
                            else:
                                schedule['active'] = False
                                
                        except Exception as e:
                            logger.error(f"Scheduled experiment failed: {e}")
                            schedule['active'] = False
                
                # Clean up inactive schedules
                self.scheduled_experiments = [
                    s for s in self.scheduled_experiments if s['active']
                ]
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(60)
    
    def cancel_experiment(self, experiment_id: str):
        """Cancel a running experiment."""
        if experiment_id in self.running_experiments:
            self.running_experiments[experiment_id].cancel()
            self.metrics.record(
                MetricType.EXPERIMENT_CANCELLED,
                experiment_id,
                {'cancelled_at': datetime.now().isoformat()}
            )
            logger.info(f"Cancelled experiment: {experiment_id}")
    
    def get_experiment_status(self, experiment_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of an experiment."""
        if experiment_id in self.running_experiments:
            return self.running_experiments[experiment_id].get_status()
        elif experiment_id in self.completed_experiments:
            result = self.completed_experiments[experiment_id]
            return {
                'experiment_id': experiment_id,
                'state': 'completed',
                'overall_success': result.overall_success,
                'resilience_score': result.system_resilience_score
            }
        return None
    
    def list_experiments(self, state_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all experiments with optional state filtering."""
        experiments = []
        
        # Running experiments
        for exp in self.running_experiments.values():
            status = exp.get_status()
            if not state_filter or status['state'] == state_filter:
                experiments.append(status)
        
        # Completed experiments
        for result in self.completed_experiments.values():
            exp_info = {
                'experiment_id': result.experiment_id,
                'name': result.name,
                'state': 'completed',
                'overall_success': result.overall_success,
                'start_time': result.start_time.isoformat(),
                'duration': str(result.duration) if result.duration else None
            }
            if not state_filter or exp_info['state'] == state_filter:
                experiments.append(exp_info)
        
        return experiments
    
    async def run_chaos_monkey(self, 
                             duration: timedelta = timedelta(hours=1),
                             interval: timedelta = timedelta(minutes=15),
                             intensity: str = "low") -> str:
        """
        Run a chaos monkey experiment with random scenarios.
        
        Args:
            duration: How long to run chaos monkey
            interval: Interval between chaos events
            intensity: Intensity level (low, medium, high)
            
        Returns:
            str: Experiment ID
        """
        from ..scenarios import (
            ServiceFailureScenario,
            NetworkPartitionScenario,
            ResourceExhaustionScenario
        )
        from .scenario_base import ScenarioConfig, ImpactLevel
        
        # Define scenario templates based on intensity
        scenario_templates = {
            'low': [
                {'type': ServiceFailureScenario, 'impact': ImpactLevel.LOW},
                {'type': NetworkPartitionScenario, 'impact': ImpactLevel.LOW}
            ],
            'medium': [
                {'type': ServiceFailureScenario, 'impact': ImpactLevel.MEDIUM},
                {'type': NetworkPartitionScenario, 'impact': ImpactLevel.MEDIUM},
                {'type': ResourceExhaustionScenario, 'impact': ImpactLevel.LOW}
            ],
            'high': [
                {'type': ServiceFailureScenario, 'impact': ImpactLevel.HIGH},
                {'type': NetworkPartitionScenario, 'impact': ImpactLevel.HIGH},
                {'type': ResourceExhaustionScenario, 'impact': ImpactLevel.MEDIUM}
            ]
        }
        
        templates = scenario_templates.get(intensity, scenario_templates['low'])
        
        # Create random scenarios
        scenarios = []
        import random
        
        end_time = datetime.now() + duration
        current_time = datetime.now()
        
        while current_time < end_time:
            template = random.choice(templates)
            
            scenario_config = ScenarioConfig(
                name=f"chaos_monkey_{template['type'].__name__}_{int(current_time.timestamp())}",
                description=f"Chaos monkey generated {template['type'].__name__}",
                duration=timedelta(minutes=5),  # Short duration for chaos monkey
                impact_level=template['impact'],
                target_components={'random'},
                safety_checks=True
            )
            
            scenario = template['type'](scenario_config)
            scenarios.append(scenario)
            
            current_time += interval
        
        # Create experiment config
        experiment_config = ExperimentConfig(
            name=f"chaos_monkey_{intensity}_{int(datetime.now().timestamp())}",
            description=f"Chaos monkey experiment with {intensity} intensity",
            scenarios=scenarios,
            parallel_execution=False,
            stop_on_failure=False
        )
        
        # Create and run experiment
        experiment_id = await self.create_experiment(experiment_config)
        
        # Run in background
        asyncio.create_task(self.run_experiment(experiment_id))
        
        return experiment_id
    
    async def get_system_resilience_report(self, 
                                         days: int = 30) -> Dict[str, Any]:
        """
        Generate a system resilience report based on recent experiments.
        
        Args:
            days: Number of days to include in the report
            
        Returns:
            Dict containing resilience metrics and trends
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        
        recent_experiments = [
            result for result in self.completed_experiments.values()
            if hasattr(result, 'start_time') and result.start_time >= cutoff_date
        ]
        
        if not recent_experiments:
            return {
                'period_days': days,
                'total_experiments': 0,
                'message': 'No experiments found in the specified period'
            }
        
        # Calculate metrics
        total_experiments = len(recent_experiments)
        successful_experiments = sum(1 for r in recent_experiments if r.overall_success)
        success_rate = successful_experiments / total_experiments
        
        avg_resilience_score = sum(r.system_resilience_score for r in recent_experiments) / total_experiments
        avg_recovery_score = sum(r.recovery_score for r in recent_experiments) / total_experiments
        
        # Trend analysis (simplified)
        first_half = recent_experiments[:len(recent_experiments)//2]
        second_half = recent_experiments[len(recent_experiments)//2:]
        
        if first_half and second_half:
            first_half_score = sum(r.system_resilience_score for r in first_half) / len(first_half)
            second_half_score = sum(r.system_resilience_score for r in second_half) / len(second_half)
            trend = "improving" if second_half_score > first_half_score else "declining"
        else:
            trend = "insufficient_data"
        
        return {
            'period_days': days,
            'total_experiments': total_experiments,
            'successful_experiments': successful_experiments,
            'success_rate': success_rate,
            'average_resilience_score': avg_resilience_score,
            'average_recovery_score': avg_recovery_score,
            'resilience_trend': trend,
            'generated_at': datetime.now().isoformat()
        }
    
    async def shutdown(self):
        """Shutdown the chaos engine gracefully."""
        logger.info("Shutting down chaos engine...")
        
        # Cancel all running experiments
        for experiment_id in list(self.running_experiments.keys()):
            self.cancel_experiment(experiment_id)
        
        # Wait for experiments to finish cancellation
        await asyncio.sleep(5)
        
        # Save final results
        self._save_results()
        
        # Shutdown monitor
        if self.monitor:
            await self.monitor.shutdown()
        
        logger.info("Chaos engine shutdown complete")