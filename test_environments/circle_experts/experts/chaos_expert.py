"""
Chaos Expert - Specialized in chaos engineering and resilience testing
Failure injection strategies, resilience testing scenarios, and system breaking point identification
"""

import asyncio
import logging
import time
import random
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class FailureType(Enum):
    NETWORK_PARTITION = "network_partition"
    SERVICE_CRASH = "service_crash"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    LATENCY_INJECTION = "latency_injection"
    ERROR_INJECTION = "error_injection"
    DATA_CORRUPTION = "data_corruption"
    DEPENDENCY_FAILURE = "dependency_failure"
    TRAFFIC_SURGE = "traffic_surge"


class ChaosLevel(Enum):
    MINIMAL = "minimal"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"
    EXTREME = "extreme"


class ResiliencePattern(Enum):
    CIRCUIT_BREAKER = "circuit_breaker"
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    BULKHEAD = "bulkhead"
    TIMEOUT = "timeout"
    FALLBACK = "fallback"
    GRACEFUL_DEGRADATION = "graceful_degradation"


@dataclass
class ChaosExperiment:
    """Chaos engineering experiment definition"""
    experiment_id: str
    name: str
    failure_type: FailureType
    target_components: List[str]
    duration_seconds: int
    intensity: float  # 0.0 to 1.0
    expected_impact: Dict[str, float]
    success_criteria: List[str]
    rollback_conditions: List[str]
    safety_checks: List[str]


@dataclass
class ResilienceAssessment:
    """System resilience assessment result"""
    resilience_score: float
    breaking_points: Dict[str, float]
    recovery_metrics: Dict[str, float]
    failure_modes: List[str]
    resilience_patterns: Dict[ResiliencePattern, bool]
    system_weaknesses: List[str]
    recommendation_priority: str


@dataclass
class ChaosAnalysis:
    """Chaos engineering analysis result"""
    chaos_experiments: List[ChaosExperiment]
    resilience_assessment: ResilienceAssessment
    chaos_readiness_score: float
    recommended_chaos_level: ChaosLevel
    safety_requirements: List[str]
    monitoring_requirements: List[str]
    expected_benefits: Dict[str, float]


class ChaosExpert:
    """
    Expert specializing in chaos engineering and system resilience testing
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.name = "Chaos Expert"
        self.specializations = [
            "chaos_engineering",
            "failure_injection",
            "resilience_testing",
            "breaking_point_analysis",
            "recovery_validation",
            "system_hardening",
            "fault_tolerance_assessment"
        ]
        
        # Chaos engineering principles
        self.chaos_principles = {
            'hypothesis_driven': True,
            'production_like': True,
            'minimal_blast_radius': True,
            'continuous_verification': True,
            'automated_rollback': True
        }
        
        # Failure injection strategies
        self.failure_strategies = {
            FailureType.NETWORK_PARTITION: {
                'description': 'Simulate network partitions and connectivity issues',
                'impact_areas': ['service_communication', 'data_consistency', 'user_experience'],
                'monitoring_metrics': ['network_latency', 'connection_failures', 'timeout_errors'],
                'typical_duration': 300,  # 5 minutes
                'safety_checks': ['network_monitoring', 'service_health_checks']
            },
            FailureType.SERVICE_CRASH: {
                'description': 'Simulate service crashes and unexpected shutdowns',
                'impact_areas': ['availability', 'load_distribution', 'failover_mechanisms'],
                'monitoring_metrics': ['service_uptime', 'restart_count', 'failover_time'],
                'typical_duration': 60,  # 1 minute
                'safety_checks': ['service_monitoring', 'auto_restart_verification']
            },
            FailureType.RESOURCE_EXHAUSTION: {
                'description': 'Simulate CPU, memory, or disk exhaustion',
                'impact_areas': ['performance', 'stability', 'resource_management'],
                'monitoring_metrics': ['resource_utilization', 'response_time', 'error_rate'],
                'typical_duration': 120,  # 2 minutes
                'safety_checks': ['resource_monitoring', 'performance_thresholds']
            },
            FailureType.LATENCY_INJECTION: {
                'description': 'Inject artificial latency into system operations',
                'impact_areas': ['response_time', 'timeout_handling', 'user_experience'],
                'monitoring_metrics': ['response_time', 'timeout_count', 'user_abandonment'],
                'typical_duration': 180,  # 3 minutes
                'safety_checks': ['latency_monitoring', 'timeout_validation']
            },
            FailureType.ERROR_INJECTION: {
                'description': 'Inject errors into API responses and operations',
                'impact_areas': ['error_handling', 'retry_mechanisms', 'data_integrity'],
                'monitoring_metrics': ['error_rate', 'retry_count', 'success_rate'],
                'typical_duration': 240,  # 4 minutes
                'safety_checks': ['error_monitoring', 'data_integrity_checks']
            }
        }
        
        # Resilience patterns and their effectiveness
        self.resilience_patterns = {
            ResiliencePattern.CIRCUIT_BREAKER: {
                'effectiveness': 0.85,
                'complexity': 'medium',
                'performance_impact': 0.05,
                'failure_types_addressed': [FailureType.SERVICE_CRASH, FailureType.LATENCY_INJECTION]
            },
            ResiliencePattern.RETRY_WITH_BACKOFF: {
                'effectiveness': 0.75,
                'complexity': 'low',
                'performance_impact': 0.1,
                'failure_types_addressed': [FailureType.NETWORK_PARTITION, FailureType.ERROR_INJECTION]
            },
            ResiliencePattern.BULKHEAD: {
                'effectiveness': 0.8,
                'complexity': 'high',
                'performance_impact': 0.15,
                'failure_types_addressed': [FailureType.RESOURCE_EXHAUSTION, FailureType.TRAFFIC_SURGE]
            },
            ResiliencePattern.TIMEOUT: {
                'effectiveness': 0.7,
                'complexity': 'low',
                'performance_impact': 0.02,
                'failure_types_addressed': [FailureType.LATENCY_INJECTION, FailureType.NETWORK_PARTITION]
            },
            ResiliencePattern.FALLBACK: {
                'effectiveness': 0.9,
                'complexity': 'medium',
                'performance_impact': 0.08,
                'failure_types_addressed': [FailureType.SERVICE_CRASH, FailureType.DEPENDENCY_FAILURE]
            }
        }
        
        # System breaking point indicators
        self.breaking_point_indicators = {
            'response_time_degradation': {'threshold': 5000, 'weight': 0.3},  # 5 seconds
            'error_rate_spike': {'threshold': 0.1, 'weight': 0.25},  # 10% error rate
            'resource_exhaustion': {'threshold': 0.95, 'weight': 0.2},  # 95% utilization
            'connection_failures': {'threshold': 0.05, 'weight': 0.15},  # 5% connection failures
            'data_inconsistency': {'threshold': 0.01, 'weight': 0.1}  # 1% data inconsistency
        }
        
        # Historical chaos data
        self.chaos_history: List[Dict[str, Any]] = []
        
    async def analyze_and_recommend(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze system chaos engineering readiness and provide expert recommendations
        """
        self.logger.info("Chaos Expert analyzing system resilience and chaos readiness")
        
        try:
            # Extract chaos-relevant metrics
            current_metrics = context.get('current_metrics', {})
            system_state = context.get('system_state', {})
            historical_data = context.get('historical_data', [])
            objectives = context.get('objectives', [])
            
            # Perform comprehensive chaos analysis
            analysis = await self._analyze_chaos_readiness(
                current_metrics, system_state, historical_data
            )
            
            # Generate chaos strategy
            strategy = await self._generate_chaos_strategy(analysis, objectives)
            
            # Assess confidence based on system observability and safety measures
            confidence = self._calculate_confidence(current_metrics, system_state)
            
            # Generate implementation steps
            implementation_steps = self._generate_implementation_steps(strategy, analysis)
            
            # Identify metrics to monitor
            metrics_to_monitor = self._identify_monitoring_metrics(analysis)
            
            recommendation = {
                'strategy': strategy['name'],
                'confidence': confidence,
                'reasoning': self._generate_reasoning(analysis, strategy),
                'expected_outcome': strategy['expected_outcome'],
                'risk_assessment': self._assess_chaos_risk(analysis),
                'implementation_steps': implementation_steps,
                'metrics_to_monitor': metrics_to_monitor,
                'chaos_analysis': {
                    'chaos_experiments': [self._experiment_to_dict(e) for e in analysis.chaos_experiments],
                    'resilience_assessment': self._resilience_to_dict(analysis.resilience_assessment),
                    'chaos_readiness_score': analysis.chaos_readiness_score,
                    'recommended_chaos_level': analysis.recommended_chaos_level.value,
                    'safety_requirements': analysis.safety_requirements,
                    'monitoring_requirements': analysis.monitoring_requirements,
                    'expected_benefits': analysis.expected_benefits
                }
            }
            
            # Store analysis for learning
            self._store_analysis(analysis, recommendation)
            
            return recommendation
            
        except Exception as e:
            self.logger.error(f"Chaos analysis failed: {str(e)}")
            return self._generate_fallback_recommendation()
    
    async def _analyze_chaos_readiness(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> ChaosAnalysis:
        """Comprehensive chaos engineering readiness analysis"""
        
        # Assess current system resilience
        resilience_assessment = await self._assess_system_resilience(
            current_metrics, system_state, historical_data
        )
        
        # Calculate chaos readiness score
        chaos_readiness_score = self._calculate_chaos_readiness_score(
            resilience_assessment, system_state
        )
        
        # Determine recommended chaos level
        recommended_chaos_level = self._determine_chaos_level(
            chaos_readiness_score, resilience_assessment
        )
        
        # Design chaos experiments
        chaos_experiments = await self._design_chaos_experiments(
            resilience_assessment, system_state, recommended_chaos_level
        )
        
        # Identify safety requirements
        safety_requirements = self._identify_safety_requirements(
            chaos_experiments, system_state
        )
        
        # Define monitoring requirements
        monitoring_requirements = self._define_monitoring_requirements(
            chaos_experiments, resilience_assessment
        )
        
        # Calculate expected benefits
        expected_benefits = self._calculate_expected_benefits(
            resilience_assessment, chaos_experiments
        )
        
        return ChaosAnalysis(
            chaos_experiments=chaos_experiments,
            resilience_assessment=resilience_assessment,
            chaos_readiness_score=chaos_readiness_score,
            recommended_chaos_level=recommended_chaos_level,
            safety_requirements=safety_requirements,
            monitoring_requirements=monitoring_requirements,
            expected_benefits=expected_benefits
        )
    
    async def _assess_system_resilience(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> ResilienceAssessment:
        """Assess current system resilience"""
        
        # Calculate resilience score
        resilience_score = self._calculate_resilience_score(current_metrics, system_state)
        
        # Identify breaking points
        breaking_points = await self._identify_breaking_points(current_metrics, historical_data)
        
        # Analyze recovery metrics
        recovery_metrics = self._analyze_recovery_metrics(historical_data)
        
        # Identify failure modes
        failure_modes = await self._identify_failure_modes(system_state, current_metrics)
        
        # Check resilience patterns implementation
        resilience_patterns = self._check_resilience_patterns(system_state)
        
        # Identify system weaknesses
        system_weaknesses = await self._identify_system_weaknesses(
            resilience_score, breaking_points, failure_modes
        )
        
        # Determine recommendation priority
        recommendation_priority = self._determine_priority(
            resilience_score, len(system_weaknesses)
        )
        
        return ResilienceAssessment(
            resilience_score=resilience_score,
            breaking_points=breaking_points,
            recovery_metrics=recovery_metrics,
            failure_modes=failure_modes,
            resilience_patterns=resilience_patterns,
            system_weaknesses=system_weaknesses,
            recommendation_priority=recommendation_priority
        )
    
    def _calculate_resilience_score(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any]
    ) -> float:
        """Calculate overall system resilience score (0-1)"""
        scores = []
        
        # Availability score
        uptime = current_metrics.get('uptime', 0.99)
        availability_score = uptime
        scores.append(availability_score * 0.25)  # 25% weight
        
        # Error handling score
        error_rate = current_metrics.get('error_rate', 0.01)
        error_handling_score = max(0, 1 - (error_rate / 0.1))  # Normalize to 10% max
        scores.append(error_handling_score * 0.2)  # 20% weight
        
        # Recovery time score
        recovery_time = current_metrics.get('recovery_time_minutes', 10)
        recovery_score = max(0, 1 - (recovery_time / 60))  # Normalize to 60 minutes max
        scores.append(recovery_score * 0.2)  # 20% weight
        
        # Resilience patterns score
        pattern_count = sum(1 for pattern in ResiliencePattern if system_state.get(pattern.value, False))
        total_patterns = len(ResiliencePattern)
        pattern_score = pattern_count / total_patterns if total_patterns > 0 else 0
        scores.append(pattern_score * 0.15)  # 15% weight
        
        # Monitoring and observability score
        monitoring_score = 0
        if system_state.get('monitoring_enabled', False):
            monitoring_score += 0.4
        if system_state.get('alerting_enabled', False):
            monitoring_score += 0.3
        if system_state.get('tracing_enabled', False):
            monitoring_score += 0.3
        scores.append(monitoring_score * 0.1)  # 10% weight
        
        # Redundancy score
        redundancy_score = 0
        if system_state.get('multi_instance', False):
            redundancy_score += 0.3
        if system_state.get('multi_az_deployment', False):
            redundancy_score += 0.4
        if system_state.get('backup_systems', False):
            redundancy_score += 0.3
        scores.append(redundancy_score * 0.1)  # 10% weight
        
        return sum(scores)
    
    async def _identify_breaking_points(
        self,
        current_metrics: Dict[str, Any],
        historical_data: List[Dict[str, Any]]
    ) -> Dict[str, float]:
        """Identify system breaking points"""
        breaking_points = {}
        
        # Response time breaking point
        current_response_time = current_metrics.get('response_time', 100)
        response_time_threshold = self.breaking_point_indicators['response_time_degradation']['threshold']
        response_time_ratio = current_response_time / response_time_threshold
        breaking_points['response_time'] = min(1.0, response_time_ratio)
        
        # Error rate breaking point
        current_error_rate = current_metrics.get('error_rate', 0.001)
        error_rate_threshold = self.breaking_point_indicators['error_rate_spike']['threshold']
        error_rate_ratio = current_error_rate / error_rate_threshold
        breaking_points['error_rate'] = min(1.0, error_rate_ratio)
        
        # Resource utilization breaking point
        cpu_usage = current_metrics.get('cpu_utilization', 50) / 100
        memory_usage = current_metrics.get('memory_usage', 50) / 100
        max_resource_usage = max(cpu_usage, memory_usage)
        resource_threshold = self.breaking_point_indicators['resource_exhaustion']['threshold']
        breaking_points['resource_utilization'] = max_resource_usage / resource_threshold
        
        # Connection failure breaking point
        connection_failures = current_metrics.get('connection_failure_rate', 0.001)
        connection_threshold = self.breaking_point_indicators['connection_failures']['threshold']
        breaking_points['connection_failures'] = connection_failures / connection_threshold
        
        # Historical trend analysis
        if len(historical_data) >= 10:
            # Analyze historical breaking points
            historical_response_times = [d.get('response_time', 100) for d in historical_data]
            max_historical_response = max(historical_response_times)
            breaking_points['historical_response_peak'] = max_historical_response / response_time_threshold
            
            historical_error_rates = [d.get('error_rate', 0.001) for d in historical_data]
            max_historical_error = max(historical_error_rates)
            breaking_points['historical_error_peak'] = max_historical_error / error_rate_threshold
        
        return breaking_points
    
    def _analyze_recovery_metrics(self, historical_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """Analyze system recovery metrics"""
        recovery_metrics = {}
        
        if len(historical_data) < 5:
            # Default values for insufficient data
            return {
                'mean_time_to_recovery': 10.0,  # minutes
                'recovery_success_rate': 0.9,
                'recovery_consistency': 0.8
            }
        
        # Extract recovery times from historical data
        recovery_times = [d.get('recovery_time_minutes', 10) for d in historical_data if d.get('failure_occurred', False)]
        
        if recovery_times:
            recovery_metrics['mean_time_to_recovery'] = sum(recovery_times) / len(recovery_times)
            recovery_metrics['max_recovery_time'] = max(recovery_times)
            recovery_metrics['min_recovery_time'] = min(recovery_times)
            
            # Calculate recovery consistency (inverse of variance)
            if len(recovery_times) > 1:
                mean_recovery = recovery_metrics['mean_time_to_recovery']
                variance = sum((t - mean_recovery) ** 2 for t in recovery_times) / len(recovery_times)
                recovery_metrics['recovery_consistency'] = max(0, 1 - (variance / (mean_recovery ** 2)))
            else:
                recovery_metrics['recovery_consistency'] = 1.0
        else:
            recovery_metrics['mean_time_to_recovery'] = 5.0  # Optimistic default
            recovery_metrics['recovery_consistency'] = 0.9
        
        # Calculate recovery success rate
        failure_count = sum(1 for d in historical_data if d.get('failure_occurred', False))
        successful_recoveries = sum(1 for d in historical_data if d.get('recovery_successful', True))
        
        if failure_count > 0:
            recovery_metrics['recovery_success_rate'] = successful_recoveries / failure_count
        else:
            recovery_metrics['recovery_success_rate'] = 0.95  # Default high success rate
        
        return recovery_metrics
    
    async def _identify_failure_modes(
        self,
        system_state: Dict[str, Any],
        current_metrics: Dict[str, Any]
    ) -> List[str]:
        """Identify potential system failure modes"""
        failure_modes = []
        
        # Single points of failure
        if not system_state.get('load_balancer', False):
            failure_modes.append("Single web server instance creates availability risk")
        
        if not system_state.get('database_replication', False):
            failure_modes.append("Single database instance creates data availability risk")
        
        if not system_state.get('multi_az_deployment', False):
            failure_modes.append("Single availability zone creates regional failure risk")
        
        # Resource exhaustion failure modes
        cpu_usage = current_metrics.get('cpu_utilization', 0)
        if cpu_usage > 80:
            failure_modes.append("High CPU utilization may lead to performance degradation")
        
        memory_usage = current_metrics.get('memory_usage', 0)
        if memory_usage > 85:
            failure_modes.append("High memory usage may lead to out-of-memory failures")
        
        # Network failure modes
        if not system_state.get('network_redundancy', False):
            failure_modes.append("Single network path creates connectivity failure risk")
        
        # Dependency failure modes
        external_dependencies = system_state.get('external_dependencies', [])
        if len(external_dependencies) > 3:
            failure_modes.append("Multiple external dependencies create cascade failure risk")
        
        # Data integrity failure modes
        if not system_state.get('data_backup', False):
            failure_modes.append("Lack of data backup creates data loss risk")
        
        if not system_state.get('data_integrity_checks', False):
            failure_modes.append("No data integrity checks create corruption risk")
        
        # Security failure modes
        if not system_state.get('security_monitoring', False):
            failure_modes.append("Lack of security monitoring creates breach risk")
        
        return failure_modes
    
    def _check_resilience_patterns(self, system_state: Dict[str, Any]) -> Dict[ResiliencePattern, bool]:
        """Check which resilience patterns are implemented"""
        patterns = {}
        
        for pattern in ResiliencePattern:
            pattern_key = pattern.value
            patterns[pattern] = system_state.get(pattern_key, False)
        
        return patterns
    
    async def _identify_system_weaknesses(
        self,
        resilience_score: float,
        breaking_points: Dict[str, float],
        failure_modes: List[str]
    ) -> List[str]:
        """Identify system weaknesses for chaos testing focus"""
        weaknesses = []
        
        # Low resilience score indicates overall weakness
        if resilience_score < 0.6:
            weaknesses.append("Overall system resilience below acceptable threshold")
        
        # High breaking point ratios indicate stress vulnerabilities
        for metric, ratio in breaking_points.items():
            if ratio > 0.7:  # Close to breaking point
                weaknesses.append(f"System approaching breaking point for {metric}")
        
        # Failure modes are inherent weaknesses
        weaknesses.extend(failure_modes)
        
        # Additional weakness analysis
        high_risk_breaking_points = [k for k, v in breaking_points.items() if v > 0.8]
        if len(high_risk_breaking_points) > 2:
            weaknesses.append("Multiple metrics near critical thresholds")
        
        return weaknesses
    
    def _determine_priority(self, resilience_score: float, weakness_count: int) -> str:
        """Determine recommendation priority"""
        if resilience_score < 0.4 or weakness_count > 5:
            return "critical"
        elif resilience_score < 0.6 or weakness_count > 3:
            return "high"
        elif resilience_score < 0.8 or weakness_count > 1:
            return "medium"
        else:
            return "low"
    
    def _calculate_chaos_readiness_score(
        self,
        resilience_assessment: ResilienceAssessment,
        system_state: Dict[str, Any]
    ) -> float:
        """Calculate system readiness for chaos engineering"""
        readiness_factors = []
        
        # Base readiness on resilience score
        readiness_factors.append(resilience_assessment.resilience_score * 0.4)  # 40% weight
        
        # Monitoring and observability readiness
        monitoring_readiness = 0
        if system_state.get('monitoring_enabled', False):
            monitoring_readiness += 0.3
        if system_state.get('alerting_enabled', False):
            monitoring_readiness += 0.3
        if system_state.get('logging_enabled', False):
            monitoring_readiness += 0.2
        if system_state.get('tracing_enabled', False):
            monitoring_readiness += 0.2
        
        readiness_factors.append(monitoring_readiness * 0.25)  # 25% weight
        
        # Safety mechanism readiness
        safety_readiness = 0
        if system_state.get('auto_rollback', False):
            safety_readiness += 0.4
        if system_state.get('circuit_breakers', False):
            safety_readiness += 0.3
        if system_state.get('health_checks', False):
            safety_readiness += 0.3
        
        readiness_factors.append(safety_readiness * 0.2)  # 20% weight
        
        # Team readiness (assumed based on system maturity)
        team_readiness = 0.8 if resilience_assessment.resilience_score > 0.7 else 0.6
        readiness_factors.append(team_readiness * 0.15)  # 15% weight
        
        return sum(readiness_factors)
    
    def _determine_chaos_level(
        self,
        chaos_readiness_score: float,
        resilience_assessment: ResilienceAssessment
    ) -> ChaosLevel:
        """Determine appropriate chaos engineering level"""
        
        if chaos_readiness_score < 0.4:
            return ChaosLevel.MINIMAL
        elif chaos_readiness_score < 0.6:
            return ChaosLevel.MODERATE
        elif chaos_readiness_score < 0.8:
            return ChaosLevel.AGGRESSIVE
        else:
            # Only recommend extreme if system has proven resilience
            if (resilience_assessment.resilience_score > 0.8 and 
                len(resilience_assessment.system_weaknesses) < 2):
                return ChaosLevel.EXTREME
            else:
                return ChaosLevel.AGGRESSIVE
    
    async def _design_chaos_experiments(
        self,
        resilience_assessment: ResilienceAssessment,
        system_state: Dict[str, Any],
        chaos_level: ChaosLevel
    ) -> List[ChaosExperiment]:
        """Design chaos engineering experiments"""
        experiments = []
        
        # Base experiment intensity on chaos level
        intensity_map = {
            ChaosLevel.MINIMAL: 0.2,
            ChaosLevel.MODERATE: 0.4,
            ChaosLevel.AGGRESSIVE: 0.6,
            ChaosLevel.EXTREME: 0.8
        }
        base_intensity = intensity_map[chaos_level]
        
        # Design experiments based on system weaknesses
        for weakness in resilience_assessment.system_weaknesses:
            if "CPU" in weakness or "performance" in weakness:
                experiments.append(self._create_resource_exhaustion_experiment(base_intensity))
            elif "network" in weakness or "connectivity" in weakness:
                experiments.append(self._create_network_partition_experiment(base_intensity))
            elif "database" in weakness or "data" in weakness:
                experiments.append(self._create_service_crash_experiment(base_intensity, ["database"]))
            elif "dependency" in weakness:
                experiments.append(self._create_dependency_failure_experiment(base_intensity))
        
        # Add baseline experiments for comprehensive testing
        if chaos_level in [ChaosLevel.MODERATE, ChaosLevel.AGGRESSIVE, ChaosLevel.EXTREME]:
            experiments.extend([
                self._create_latency_injection_experiment(base_intensity * 0.8),
                self._create_error_injection_experiment(base_intensity * 0.6)
            ])
        
        # Add advanced experiments for higher chaos levels
        if chaos_level in [ChaosLevel.AGGRESSIVE, ChaosLevel.EXTREME]:
            experiments.append(self._create_traffic_surge_experiment(base_intensity))
        
        if chaos_level == ChaosLevel.EXTREME:
            experiments.append(self._create_data_corruption_experiment(base_intensity * 0.4))
        
        return experiments[:6]  # Limit to 6 experiments for manageability
    
    def _create_resource_exhaustion_experiment(self, intensity: float) -> ChaosExperiment:
        """Create resource exhaustion chaos experiment"""
        return ChaosExperiment(
            experiment_id=f"chaos-resource-{int(time.time())}",
            name="Resource Exhaustion Test",
            failure_type=FailureType.RESOURCE_EXHAUSTION,
            target_components=["application_server", "worker_processes"],
            duration_seconds=int(120 * (1 + intensity)),  # 2-4 minutes based on intensity
            intensity=intensity,
            expected_impact={
                'response_time_increase': intensity * 200,  # % increase
                'throughput_decrease': intensity * 30,  # % decrease
                'error_rate_increase': intensity * 5  # % increase
            },
            success_criteria=[
                "System remains available during resource pressure",
                "Auto-scaling triggers within 2 minutes",
                "No data loss or corruption occurs",
                "Recovery time less than 5 minutes after experiment ends"
            ],
            rollback_conditions=[
                "Error rate exceeds 10%",
                "Response time exceeds 10 seconds",
                "System becomes completely unavailable"
            ],
            safety_checks=[
                "Monitor resource utilization continuously",
                "Verify auto-scaling is enabled",
                "Ensure monitoring alerts are active"
            ]
        )
    
    def _create_network_partition_experiment(self, intensity: float) -> ChaosExperiment:
        """Create network partition chaos experiment"""
        return ChaosExperiment(
            experiment_id=f"chaos-network-{int(time.time())}",
            name="Network Partition Test",
            failure_type=FailureType.NETWORK_PARTITION,
            target_components=["network_infrastructure", "service_mesh"],
            duration_seconds=int(180 * (1 + intensity * 0.5)),  # 3-4.5 minutes
            intensity=intensity,
            expected_impact={
                'connectivity_loss': intensity * 50,  # % of connections affected
                'failover_time': 30,  # seconds
                'data_sync_delay': intensity * 60  # seconds
            },
            success_criteria=[
                "Services detect partition within 30 seconds",
                "Failover mechanisms activate successfully",
                "Data consistency maintained after partition heals",
                "All services reconnect automatically"
            ],
            rollback_conditions=[
                "Partition detection takes longer than 60 seconds",
                "Data inconsistency detected",
                "Manual intervention required for recovery"
            ],
            safety_checks=[
                "Monitor network connectivity continuously",
                "Verify partition detection mechanisms",
                "Ensure data consistency monitoring is active"
            ]
        )
    
    def _create_service_crash_experiment(self, intensity: float, target_services: List[str]) -> ChaosExperiment:
        """Create service crash chaos experiment"""
        return ChaosExperiment(
            experiment_id=f"chaos-crash-{int(time.time())}",
            name=f"Service Crash Test - {', '.join(target_services)}",
            failure_type=FailureType.SERVICE_CRASH,
            target_components=target_services,
            duration_seconds=int(60 * (1 + intensity)),  # 1-2 minutes
            intensity=intensity,
            expected_impact={
                'service_downtime': intensity * 60,  # seconds
                'load_redistribution': True,
                'failover_activation': True
            },
            success_criteria=[
                "Service restarts automatically within 30 seconds",
                "Load balancer removes failed instance from rotation",
                "No requests are lost during failover",
                "Service health checks detect failure quickly"
            ],
            rollback_conditions=[
                "Service fails to restart after 2 minutes",
                "Cascade failures to other services",
                "Data corruption detected"
            ],
            safety_checks=[
                "Monitor service health continuously",
                "Verify auto-restart mechanisms",
                "Ensure load balancer health checks are active"
            ]
        )
    
    def _create_latency_injection_experiment(self, intensity: float) -> ChaosExperiment:
        """Create latency injection chaos experiment"""
        return ChaosExperiment(
            experiment_id=f"chaos-latency-{int(time.time())}",
            name="Latency Injection Test",
            failure_type=FailureType.LATENCY_INJECTION,
            target_components=["api_gateway", "microservices"],
            duration_seconds=int(240 * (1 + intensity * 0.3)),  # 4-5 minutes
            intensity=intensity,
            expected_impact={
                'response_time_increase': intensity * 500,  # ms increase
                'timeout_rate_increase': intensity * 10,  # % increase
                'user_experience_degradation': intensity * 30  # % degradation
            },
            success_criteria=[
                "Timeout mechanisms activate appropriately",
                "Circuit breakers trigger when necessary",
                "User experience gracefully degrades",
                "System performance recovers after experiment"
            ],
            rollback_conditions=[
                "Response times exceed 5 seconds consistently",
                "Timeout rate exceeds 20%",
                "User abandonment rate spikes significantly"
            ],
            safety_checks=[
                "Monitor response times continuously",
                "Verify timeout configurations",
                "Ensure circuit breaker mechanisms are active"
            ]
        )
    
    def _create_error_injection_experiment(self, intensity: float) -> ChaosExperiment:
        """Create error injection chaos experiment"""
        return ChaosExperiment(
            experiment_id=f"chaos-error-{int(time.time())}",
            name="Error Injection Test",
            failure_type=FailureType.ERROR_INJECTION,
            target_components=["api_endpoints", "service_interfaces"],
            duration_seconds=int(200 * (1 + intensity * 0.5)),  # 3-4 minutes
            intensity=intensity,
            expected_impact={
                'error_rate_increase': intensity * 15,  # % increase
                'retry_activation': True,
                'fallback_mechanism_usage': intensity * 40  # % of requests
            },
            success_criteria=[
                "Retry mechanisms handle transient errors",
                "Fallback responses maintain service availability",
                "Error monitoring and alerting function correctly",
                "System maintains acceptable error rates"
            ],
            rollback_conditions=[
                "Error rate exceeds 25%",
                "Retry mechanisms fail to recover",
                "Critical business functions become unavailable"
            ],
            safety_checks=[
                "Monitor error rates continuously",
                "Verify retry and fallback mechanisms",
                "Ensure error alerting is configured"
            ]
        )
    
    def _create_dependency_failure_experiment(self, intensity: float) -> ChaosExperiment:
        """Create dependency failure chaos experiment"""
        return ChaosExperiment(
            experiment_id=f"chaos-dependency-{int(time.time())}",
            name="External Dependency Failure Test",
            failure_type=FailureType.DEPENDENCY_FAILURE,
            target_components=["external_apis", "third_party_services"],
            duration_seconds=int(300 * (1 + intensity * 0.2)),  # 5-6 minutes
            intensity=intensity,
            expected_impact={
                'dependency_availability': (1 - intensity) * 100,  # % availability
                'fallback_activation': True,
                'performance_degradation': intensity * 25  # % degradation
            },
            success_criteria=[
                "Circuit breakers protect against dependency failures",
                "Fallback mechanisms provide alternative responses",
                "System maintains core functionality",
                "Dependency health monitoring detects failures"
            ],
            rollback_conditions=[
                "Core system functionality becomes unavailable",
                "Cascade failures affect multiple services",
                "Data integrity compromised"
            ],
            safety_checks=[
                "Monitor dependency health continuously",
                "Verify circuit breaker configurations",
                "Ensure fallback mechanisms are tested"
            ]
        )
    
    def _create_traffic_surge_experiment(self, intensity: float) -> ChaosExperiment:
        """Create traffic surge chaos experiment"""
        return ChaosExperiment(
            experiment_id=f"chaos-traffic-{int(time.time())}",
            name="Traffic Surge Test",
            failure_type=FailureType.TRAFFIC_SURGE,
            target_components=["load_balancer", "application_tier"],
            duration_seconds=int(180 * (1 + intensity * 0.3)),  # 3-4 minutes
            intensity=intensity,
            expected_impact={
                'traffic_increase': intensity * 300,  # % increase
                'auto_scaling_activation': True,
                'response_time_degradation': intensity * 50  # % increase
            },
            success_criteria=[
                "Auto-scaling responds to increased load",
                "Load balancer distributes traffic effectively",
                "System maintains acceptable response times",
                "No requests are dropped during scaling"
            ],
            rollback_conditions=[
                "Auto-scaling fails to activate",
                "Response times exceed 3 seconds",
                "Error rate exceeds 5%"
            ],
            safety_checks=[
                "Monitor traffic patterns continuously",
                "Verify auto-scaling configurations",
                "Ensure rate limiting is configured"
            ]
        )
    
    def _create_data_corruption_experiment(self, intensity: float) -> ChaosExperiment:
        """Create data corruption chaos experiment"""
        return ChaosExperiment(
            experiment_id=f"chaos-corruption-{int(time.time())}",
            name="Data Corruption Test",
            failure_type=FailureType.DATA_CORRUPTION,
            target_components=["database", "data_storage"],
            duration_seconds=int(120 * (1 + intensity)),  # 2-3 minutes
            intensity=intensity,
            expected_impact={
                'data_integrity_impact': intensity * 1,  # % of test data
                'backup_activation': True,
                'corruption_detection_time': 60  # seconds
            },
            success_criteria=[
                "Data corruption is detected within 60 seconds",
                "Backup and recovery mechanisms activate",
                "System maintains data integrity for critical operations",
                "Corrupted data is isolated and quarantined"
            ],
            rollback_conditions=[
                "Corruption spreads to production data",
                "Backup systems fail to activate",
                "Critical data integrity compromised"
            ],
            safety_checks=[
                "Use isolated test data only",
                "Monitor data integrity continuously",
                "Verify backup and recovery procedures"
            ]
        )
    
    def _identify_safety_requirements(
        self,
        chaos_experiments: List[ChaosExperiment],
        system_state: Dict[str, Any]
    ) -> List[str]:
        """Identify safety requirements for chaos experiments"""
        requirements = []
        
        # General safety requirements
        requirements.extend([
            "Comprehensive monitoring and alerting must be active",
            "Automated rollback mechanisms must be configured",
            "Blast radius must be limited to non-critical components initially",
            "Emergency stop procedures must be documented and tested"
        ])
        
        # Experiment-specific requirements
        experiment_types = set(exp.failure_type for exp in chaos_experiments)
        
        if FailureType.DATA_CORRUPTION in experiment_types:
            requirements.extend([
                "Data backup and recovery procedures must be validated",
                "Test data isolation must be implemented",
                "Data integrity monitoring must be active"
            ])
        
        if FailureType.NETWORK_PARTITION in experiment_types:
            requirements.extend([
                "Network monitoring and partition detection must be active",
                "Alternative communication paths must be available"
            ])
        
        if FailureType.SERVICE_CRASH in experiment_types:
            requirements.extend([
                "Service health checks and auto-restart must be configured",
                "Load balancer health checks must be active"
            ])
        
        # System-specific requirements
        if not system_state.get('monitoring_enabled', False):
            requirements.append("Comprehensive monitoring must be implemented before chaos testing")
        
        if not system_state.get('backup_systems', False):
            requirements.append("Backup and recovery systems must be implemented")
        
        return requirements
    
    def _define_monitoring_requirements(
        self,
        chaos_experiments: List[ChaosExperiment],
        resilience_assessment: ResilienceAssessment
    ) -> List[str]:
        """Define monitoring requirements for chaos experiments"""
        requirements = []
        
        # Core monitoring requirements
        requirements.extend([
            "Real-time system health monitoring",
            "Application performance monitoring (APM)",
            "Infrastructure monitoring and alerting",
            "Business metrics monitoring"
        ])
        
        # Experiment-specific monitoring
        for experiment in chaos_experiments:
            strategy = self.failure_strategies.get(experiment.failure_type)
            if strategy:
                for metric in strategy['monitoring_metrics']:
                    requirement = f"Monitor {metric} during {experiment.failure_type.value} experiments"
                    if requirement not in requirements:
                        requirements.append(requirement)
        
        # Breaking point monitoring
        for breaking_point in resilience_assessment.breaking_points.keys():
            requirements.append(f"Continuous monitoring of {breaking_point} thresholds")
        
        # Recovery monitoring
        requirements.extend([
            "Recovery time measurement and tracking",
            "Success/failure rate monitoring for all experiments",
            "Blast radius impact assessment monitoring"
        ])
        
        return requirements
    
    def _calculate_expected_benefits(
        self,
        resilience_assessment: ResilienceAssessment,
        chaos_experiments: List[ChaosExperiment]
    ) -> Dict[str, float]:
        """Calculate expected benefits from chaos engineering"""
        benefits = {}
        
        # Resilience improvement based on current score
        current_resilience = resilience_assessment.resilience_score
        resilience_improvement = min(0.3, (1 - current_resilience) * 0.5)
        benefits['resilience_score_improvement'] = resilience_improvement
        
        # MTTR improvement
        current_mttr = resilience_assessment.recovery_metrics.get('mean_time_to_recovery', 10)
        mttr_improvement = min(0.4, max(0.1, (current_mttr - 5) / current_mttr))
        benefits['mttr_improvement'] = mttr_improvement
        
        # Incident reduction
        weakness_count = len(resilience_assessment.system_weaknesses)
        incident_reduction = min(0.5, weakness_count * 0.08)
        benefits['incident_reduction'] = incident_reduction
        
        # Confidence improvement
        experiment_count = len(chaos_experiments)
        confidence_improvement = min(0.4, experiment_count * 0.05)
        benefits['system_confidence_improvement'] = confidence_improvement
        
        # Cost savings (estimated based on incident reduction)
        cost_savings = incident_reduction * 0.6  # Proportional to incident reduction
        benefits['operational_cost_savings'] = cost_savings
        
        # Knowledge improvement
        benefits['team_knowledge_improvement'] = 0.3  # Consistent benefit
        
        return benefits
    
    async def _generate_chaos_strategy(
        self,
        analysis: ChaosAnalysis,
        objectives: List[str]
    ) -> Dict[str, Any]:
        """Generate chaos engineering strategy"""
        
        # Determine strategy based on chaos readiness and resilience
        readiness_score = analysis.chaos_readiness_score
        resilience_score = analysis.resilience_assessment.resilience_score
        
        if readiness_score < 0.4:
            strategy_name = "chaos_readiness_preparation"
            priority = "medium"
        elif readiness_score < 0.7 or resilience_score < 0.6:
            strategy_name = "gradual_chaos_introduction"
            priority = "medium"
        elif analysis.recommended_chaos_level in [ChaosLevel.AGGRESSIVE, ChaosLevel.EXTREME]:
            strategy_name = "comprehensive_chaos_engineering"
            priority = "high"
        else:
            strategy_name = "systematic_chaos_testing"
            priority = "medium"
        
        # Define strategy details
        strategy = {
            'name': strategy_name,
            'priority': priority,
            'chaos_level': analysis.recommended_chaos_level.value,
            'experiment_phases': self._plan_experiment_phases(analysis),
            'chaos_techniques': self._select_chaos_techniques(analysis),
            'expected_outcome': {
                'resilience_improvement': analysis.expected_benefits.get('resilience_score_improvement', 0.2),
                'mttr_improvement': analysis.expected_benefits.get('mttr_improvement', 0.3),
                'incident_reduction': analysis.expected_benefits.get('incident_reduction', 0.25),
                'confidence_improvement': analysis.expected_benefits.get('system_confidence_improvement', 0.2),
                'implementation_time': self._estimate_chaos_implementation_time(analysis),
                'success_probability': self._estimate_chaos_success_probability(analysis),
                'learning_outcomes': self._estimate_learning_outcomes(analysis)
            },
            'safety_strategy': {
                'blast_radius_control': True,
                'automated_rollback': True,
                'real_time_monitoring': True,
                'experiment_isolation': analysis.recommended_chaos_level != ChaosLevel.EXTREME
            }
        }
        
        return strategy
    
    def _plan_experiment_phases(self, analysis: ChaosAnalysis) -> List[str]:
        """Plan chaos experiment execution phases"""
        phases = []
        
        # Phase 1: Preparation
        phases.append("Phase 1: Chaos engineering preparation and safety setup")
        
        # Phase 2: Basic experiments
        if analysis.recommended_chaos_level != ChaosLevel.MINIMAL:
            phases.append("Phase 2: Basic failure injection experiments")
        
        # Phase 3: Service-level experiments
        phases.append("Phase 3: Service-level resilience testing")
        
        # Phase 4: System-level experiments
        if analysis.recommended_chaos_level in [ChaosLevel.AGGRESSIVE, ChaosLevel.EXTREME]:
            phases.append("Phase 4: System-level chaos experiments")
        
        # Phase 5: Advanced experiments
        if analysis.recommended_chaos_level == ChaosLevel.EXTREME:
            phases.append("Phase 5: Advanced chaos scenarios and game days")
        
        # Phase 6: Analysis and improvement
        phases.append("Phase 6: Results analysis and system hardening")
        
        return phases
    
    def _select_chaos_techniques(self, analysis: ChaosAnalysis) -> List[str]:
        """Select appropriate chaos engineering techniques"""
        techniques = []
        
        # Based on experiment types
        experiment_types = set(exp.failure_type for exp in analysis.chaos_experiments)
        
        for failure_type in experiment_types:
            if failure_type == FailureType.NETWORK_PARTITION:
                techniques.append("network_chaos")
            elif failure_type == FailureType.SERVICE_CRASH:
                techniques.append("service_killing")
            elif failure_type == FailureType.RESOURCE_EXHAUSTION:
                techniques.append("resource_stress_testing")
            elif failure_type == FailureType.LATENCY_INJECTION:
                techniques.append("latency_chaos")
            elif failure_type == FailureType.ERROR_INJECTION:
                techniques.append("error_injection")
        
        # Based on chaos level
        if analysis.recommended_chaos_level in [ChaosLevel.AGGRESSIVE, ChaosLevel.EXTREME]:
            techniques.extend([
                "dependency_chaos",
                "infrastructure_chaos",
                "game_day_exercises"
            ])
        
        # Based on system weaknesses
        for weakness in analysis.resilience_assessment.system_weaknesses:
            if "database" in weakness:
                techniques.append("database_chaos")
            elif "security" in weakness:
                techniques.append("security_chaos")
        
        return list(set(techniques))[:8]  # Limit and remove duplicates
    
    def _estimate_chaos_implementation_time(self, analysis: ChaosAnalysis) -> int:
        """Estimate implementation time in hours"""
        base_time = 32  # 32 hours base
        
        # Add time based on number of experiments
        experiment_time = len(analysis.chaos_experiments) * 8
        
        # Add time based on safety requirements
        safety_time = len(analysis.safety_requirements) * 4
        
        # Add time based on monitoring requirements
        monitoring_time = len(analysis.monitoring_requirements) * 2
        
        # Add time based on chaos level
        level_multiplier = {
            ChaosLevel.MINIMAL: 0.8,
            ChaosLevel.MODERATE: 1.0,
            ChaosLevel.AGGRESSIVE: 1.3,
            ChaosLevel.EXTREME: 1.6
        }
        
        total_time = (base_time + experiment_time + safety_time + monitoring_time)
        total_time *= level_multiplier[analysis.recommended_chaos_level]
        
        return min(160, int(total_time))  # Cap at 160 hours
    
    def _estimate_chaos_success_probability(self, analysis: ChaosAnalysis) -> float:
        """Estimate probability of successful chaos implementation"""
        base_probability = 0.8
        
        # Adjust based on chaos readiness
        readiness_factor = analysis.chaos_readiness_score
        base_probability *= (0.6 + readiness_factor * 0.4)
        
        # Adjust based on system resilience
        resilience_factor = analysis.resilience_assessment.resilience_score
        base_probability *= (0.7 + resilience_factor * 0.3)
        
        # Reduce probability for complex chaos levels
        if analysis.recommended_chaos_level == ChaosLevel.EXTREME:
            base_probability *= 0.7
        elif analysis.recommended_chaos_level == ChaosLevel.AGGRESSIVE:
            base_probability *= 0.85
        
        return max(0.5, base_probability)  # Minimum 50% probability
    
    def _estimate_learning_outcomes(self, analysis: ChaosAnalysis) -> Dict[str, float]:
        """Estimate learning outcomes from chaos engineering"""
        return {
            'system_behavior_understanding': 0.8,
            'failure_mode_identification': 0.7,
            'recovery_process_optimization': 0.6,
            'team_incident_response_skills': 0.5,
            'monitoring_and_alerting_improvements': 0.7
        }
    
    def _assess_chaos_risk(self, analysis: ChaosAnalysis) -> str:
        """Assess overall risk of chaos engineering implementation"""
        risk_score = 0
        
        # Risk based on chaos readiness
        if analysis.chaos_readiness_score < 0.4:
            risk_score += 3
        elif analysis.chaos_readiness_score < 0.7:
            risk_score += 1
        
        # Risk based on system resilience
        if analysis.resilience_assessment.resilience_score < 0.5:
            risk_score += 3
        elif analysis.resilience_assessment.resilience_score < 0.7:
            risk_score += 2
        
        # Risk based on chaos level
        level_risk = {
            ChaosLevel.MINIMAL: 0,
            ChaosLevel.MODERATE: 1,
            ChaosLevel.AGGRESSIVE: 2,
            ChaosLevel.EXTREME: 3
        }
        risk_score += level_risk[analysis.recommended_chaos_level]
        
        # Risk based on safety requirements
        if len(analysis.safety_requirements) > 8:
            risk_score += 2
        elif len(analysis.safety_requirements) > 5:
            risk_score += 1
        
        if risk_score >= 6:
            return "high"
        elif risk_score >= 3:
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence(
        self,
        current_metrics: Dict[str, Any],
        system_state: Dict[str, Any]
    ) -> float:
        """Calculate confidence in the recommendation"""
        base_confidence = 0.7
        
        # Increase confidence with better observability
        if system_state.get('monitoring_enabled', False):
            base_confidence += 0.1
        if system_state.get('alerting_enabled', False):
            base_confidence += 0.05
        if system_state.get('tracing_enabled', False):
            base_confidence += 0.05
        
        # Increase confidence with safety mechanisms
        if system_state.get('auto_rollback', False):
            base_confidence += 0.05
        if system_state.get('circuit_breakers', False):
            base_confidence += 0.05
        
        return min(0.9, base_confidence)
    
    def _generate_reasoning(
        self,
        analysis: ChaosAnalysis,
        strategy: Dict[str, Any]
    ) -> str:
        """Generate reasoning for the recommendation"""
        reasoning_parts = []
        
        # Analysis summary
        reasoning_parts.append(f"Chaos readiness score: {analysis.chaos_readiness_score:.2f}")
        reasoning_parts.append(f"System resilience score: {analysis.resilience_assessment.resilience_score:.2f}")
        reasoning_parts.append(f"Recommended chaos level: {analysis.recommended_chaos_level.value}")
        
        # Strategy justification
        reasoning_parts.append(f"Proposed {strategy['name']} approach")
        reasoning_parts.append(f"Expected {strategy['expected_outcome']['resilience_improvement']:.1%} resilience improvement")
        
        # Key benefits
        benefits = analysis.expected_benefits
        if benefits.get('incident_reduction', 0) > 0.2:
            reasoning_parts.append(f"Projected {benefits['incident_reduction']:.1%} incident reduction")
        
        return ". ".join(reasoning_parts)
    
    def _generate_implementation_steps(
        self,
        strategy: Dict[str, Any],
        analysis: ChaosAnalysis
    ) -> List[str]:
        """Generate detailed implementation steps"""
        steps = []
        
        # Always start with preparation
        steps.append("Establish chaos engineering team and responsibilities")
        steps.append("Implement comprehensive monitoring and safety mechanisms")
        
        # Add strategy-specific steps
        for technique in strategy.get('chaos_techniques', []):
            if technique == "network_chaos":
                steps.append("Design and implement network partition experiments")
            elif technique == "service_killing":
                steps.append("Implement controlled service termination experiments")
            elif technique == "resource_stress_testing":
                steps.append("Design resource exhaustion test scenarios")
            elif technique == "game_day_exercises":
                steps.append("Plan and execute comprehensive game day exercises")
        
        # Add phase-specific steps
        for phase in strategy.get('experiment_phases', []):
            steps.append(f"Execute {phase}")
        
        # Add safety and monitoring steps
        steps.extend([
            "Validate all safety mechanisms before experiments",
            "Execute chaos experiments with blast radius control",
            "Analyze results and identify system improvements",
            "Implement discovered improvements and re-test"
        ])
        
        return steps
    
    def _identify_monitoring_metrics(self, analysis: ChaosAnalysis) -> List[str]:
        """Identify key metrics to monitor during chaos experiments"""
        metrics = [
            'system_availability',
            'response_time',
            'error_rate',
            'recovery_time',
            'experiment_blast_radius',
            'safety_mechanism_activation'
        ]
        
        # Add experiment-specific metrics
        for experiment in analysis.chaos_experiments:
            strategy = self.failure_strategies.get(experiment.failure_type)
            if strategy:
                metrics.extend(strategy['monitoring_metrics'])
        
        return list(set(metrics))  # Remove duplicates
    
    def _experiment_to_dict(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Convert experiment to dictionary"""
        return {
            'experiment_id': experiment.experiment_id,
            'name': experiment.name,
            'failure_type': experiment.failure_type.value,
            'target_components': experiment.target_components,
            'duration_seconds': experiment.duration_seconds,
            'intensity': experiment.intensity,
            'expected_impact': experiment.expected_impact,
            'success_criteria': experiment.success_criteria,
            'rollback_conditions': experiment.rollback_conditions,
            'safety_checks': experiment.safety_checks
        }
    
    def _resilience_to_dict(self, resilience: ResilienceAssessment) -> Dict[str, Any]:
        """Convert resilience assessment to dictionary"""
        return {
            'resilience_score': resilience.resilience_score,
            'breaking_points': resilience.breaking_points,
            'recovery_metrics': resilience.recovery_metrics,
            'failure_modes': resilience.failure_modes,
            'resilience_patterns': {k.value: v for k, v in resilience.resilience_patterns.items()},
            'system_weaknesses': resilience.system_weaknesses,
            'recommendation_priority': resilience.recommendation_priority
        }
    
    def _store_analysis(self, analysis: ChaosAnalysis, recommendation: Dict[str, Any]):
        """Store analysis results for learning"""
        record = {
            'timestamp': time.time(),
            'chaos_readiness_score': analysis.chaos_readiness_score,
            'resilience_score': analysis.resilience_assessment.resilience_score,
            'recommended_chaos_level': analysis.recommended_chaos_level.value,
            'experiment_count': len(analysis.chaos_experiments),
            'strategy': recommendation['strategy'],
            'confidence': recommendation['confidence']
        }
        
        self.chaos_history.append(record)
        
        # Keep only last 50 records
        if len(self.chaos_history) > 50:
            self.chaos_history = self.chaos_history[-50:]
    
    def _generate_fallback_recommendation(self) -> Dict[str, Any]:
        """Generate fallback recommendation when analysis fails"""
        return {
            'strategy': 'basic_resilience_assessment',
            'confidence': 0.6,
            'reasoning': 'Chaos analysis failed, recommending basic resilience assessment',
            'expected_outcome': {
                'resilience_improvement': 0.15,
                'mttr_improvement': 0.2,
                'incident_reduction': 0.1,
                'confidence_improvement': 0.1,
                'implementation_time': 24,
                'success_probability': 0.8,
                'learning_outcomes': {'system_behavior_understanding': 0.5}
            },
            'risk_assessment': 'low',
            'implementation_steps': [
                'Assess current system monitoring capabilities',
                'Implement basic health checks and alerting',
                'Conduct simple failure scenario planning',
                'Establish incident response procedures'
            ],
            'metrics_to_monitor': ['system_availability', 'response_time', 'error_rate']
        }
    
    async def configure(self, config: Dict[str, Any]):
        """Configure expert parameters"""
        if 'chaos_principles' in config:
            self.chaos_principles.update(config['chaos_principles'])
        
        if 'failure_strategies' in config:
            self.failure_strategies.update(config['failure_strategies'])
        
        if 'resilience_patterns' in config:
            self.resilience_patterns.update(config['resilience_patterns'])
        
        self.logger.info(f"Chaos Expert configured with {len(config)} parameters")